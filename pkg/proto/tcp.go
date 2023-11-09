package proto

import (
	"fmt"
	"log/slog"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/socket"
	"netstack/pkg/util"
	"sync"

	"github.com/google/netstack/tcpip/header"
)

const (
	MAX_WND_SIZE       = 65535
	DEFAULT_DATAOFFSET = 20
)

type Segment struct {
	Packet *TCPPacket
	ACKed  chan bool
	RTT    float32
	Mu     sync.Mutex
}

type TCPPacket struct {
	LAddr     netip.Addr
	RAddr     netip.Addr
	TCPHeader *header.TCPFields
	Payload   []byte
}

type SendBufData struct {
	NumB uint32
	Flag uint8
}

type TCB struct {
	SID   int // Socket Id
	State int // Socket State

	Laddr netip.Addr // my ip addr
	Lport uint16     // my ip port

	Raddr netip.Addr // other ip addr
	Rport uint16     // other ip port

	// Communication between IP Stack and TCP Stack
	ReceiveChan chan *TCPPacket
	SendChan    chan *TCPPacket
	// Signal Our FIN is ACK'ed
	FinOK chan bool
	// Timer Reset (TIME_WAIT)
	TimeReset chan bool
	// Signal the Reaper for removeal
	ReapChan chan int
	// ACK signal
	ACKSignal chan bool
	// Data signal

	SBufDataSignal chan SendBufData
	SBufPutSignal  chan bool

	RBufDataSignal chan bool

	// Pointers to Buffers
	SendBuffer *socket.CircularBuffer
	RecvBuffer *socket.CircularBuffer
	// Early Arrival Queue
	EarlyArrivals []*TCPPacket
	// Retransmission Queue
	RetransmissionQ []*Segment

	// Initial Sequence Numbers
	ISS uint32
	IRS uint32

	// Connection State Variables
	SND_UNA uint32
	SND_NXT uint32
	SND_WND uint32
	SND_WL1 uint32
	SND_WL2 uint32
	RCV_NXT uint32
	RCV_WND uint32

	// Last Byte Read
	LBR uint32
	// Last Byte Written
	LBW uint32

	// Zero Window Probing
	ProbeStatus bool
}

type SocketTableKey struct {
	// The 4-tuple maps to a single socket
	Laddr netip.Addr
	Lport uint16
	Raddr netip.Addr
	Rport uint16
}

type TCPStackT struct {
	// counter used for clock-based ISN generation
	// (RFC 9293: 3.4.1)
	ISNCTR uint32
	// Next Available Socket ID
	NextSID int
	// Socket Id to Key into TCB for ease of access from REPL
	SIDToTableKey map[int]SocketTableKey
	// The Cannonical table
	SocketTable map[SocketTableKey]*TCB
	StMtx       sync.Mutex
	// Bounded Ports
	BoundPorts map[int]bool
	// Channel through which we communicate with the ipstack
	SendChan chan *TCPPacket
	// Reap Chan
	ReapChan chan int
}

// Global Socket Table
var TCPStack *TCPStackT

// Function that initializes our Socket Table for hosts
func InitializeTCPStack(sendChan chan *TCPPacket) {
	TCPStack = &TCPStackT{
		ISNCTR:        0,
		NextSID:       0,
		SIDToTableKey: make(map[int]SocketTableKey),
		SocketTable:   make(map[SocketTableKey]*TCB),
		BoundPorts:    make(map[int]bool),
		SendChan:      sendChan,
		ReapChan:      make(chan int, 100),
	}
	go util.KeepIncrement(&TCPStack.ISNCTR)
	go TCPStack.Reap()
}

// =================== Helper ===================
func (tcb *TCB) TrimSegment(tcpPacket *TCPPacket) ([]byte, uint32) {
	SEG_SEQ := tcpPacket.TCPHeader.SeqNum
	SEG_LEN := uint32(len(tcpPacket.Payload))
	SEG_DATA := tcpPacket.Payload
	available := tcb.GetAdvertisedWND()

	// Compute the offset to the first new byte
	start := tcb.RCV_NXT - SEG_SEQ
	// Compute the number of bytes we can receive
	end := min(available, SEG_LEN)
	SEG_DATA = SEG_DATA[start:end]
	SEG_LEN = uint32(len(SEG_DATA))
	return SEG_DATA, SEG_LEN
}

// Update RTO dynamically for segments that cannot be removed
// We DON't partially update tcp packet payload
func (tcb *TCB) RQManager() {
	// for {
	// 	// First Wait until we get a signal that SND.UNA has been updated
	// 	<-tcb.ACKSignal
	// 	newRQ := make([]*Segment, 0)
	// 	// For each segment check
	// 	// - Complete ACK -> (SEG.SEQ + SEG.LEN - 1 < SND.UNA)
	// 	//   - SEQ=3, LEN=3 -> (3,4,5) ok when SND.UNA >= 6
	// 	// - Else there is data not ACK'ed yet
	// 	for _, seg := range tcb.RetransmissionQ {
	// 		seg_seq := seg.Packet.TCPHeader.SeqNum
	// 		seg_len := uint32(len(seg.Packet.Payload))
	// 		seg_lb := seg_seq + seg_len - 1
	// 		if seg_lb < tcb.SND_UNA {
	// 			// This segment data ALL ACK'ed
	// 			seg.ACKed <- true
	// 		} else {
	// 			// The segment data is NOT FULLY ACK'ed
	// 			// TODO: update the RTO here
	// 			// Update Packet for RT
	// 			seg.Packet.TCPHeader.WindowSize = uint16(tcb.GetAdvertisedWND())
	// 			seg.Packet.TCPHeader.AckNum = tcb.RCV_NXT
	// 			newRQ = append(newRQ, seg)
	// 		}
	// 	}
	// 	tcb.RetransmissionQ = newRQ
	// }
}

// Insert so that Early Arrival Packets are in order of their sequence numbers
// Example:
// If you have EAQ of 1 4 5 6
// - You get packet with seq 3
// - Insert position is hence 1 (after 1)
// - Append a temp slice 1 4 5 6 temp
// - Copy (1 4 4 5 6) and update insert pos
// - Result is 1 3 4 5 6
func (tcb *TCB) InsertEAQ(packet *TCPPacket) {
	if len(tcb.EarlyArrivals) == 0 {
		tcb.EarlyArrivals = append(tcb.EarlyArrivals, packet)
		return
	}
	insertPos := 0
	found := false
	insertSeq := packet.TCPHeader.SeqNum
	for i, curr := range tcb.EarlyArrivals {
		if insertSeq == curr.TCPHeader.SeqNum {
			// We already have this in our early arrivals queue => nop
			return
		}
		if curr.TCPHeader.SeqNum > insertSeq {
			// We find our insert position
			insertPos = i
			found = true
			break
		}
	}
	var q []*TCPPacket
	if !found {
		// append at the end
		q = append(tcb.EarlyArrivals, packet)
	} else {
		// insert
		q := append(tcb.EarlyArrivals, &TCPPacket{})
		copy(q[insertPos+1:], q[insertPos:])
		q[insertPos] = packet
	}
	tcb.EarlyArrivals = q
}

// Given end sequence number (incl.) of current segment data
// Loop the EAQ and merge data
func (tcb *TCB) MergeEAQ(end uint32, currData []byte) ([]byte, uint32) {
	available := tcb.GetAdvertisedWND() - uint32(len(currData))
	if available == 0 {
		// No space available in recv buf
		return currData, uint32(len(currData))
	}
	for i, curr := range tcb.EarlyArrivals {
		currSEQ := curr.TCPHeader.SeqNum
		currEND := currSEQ + uint32(len(curr.Payload)) - 1
		if currEND <= end {
			// already received
			continue
		}
		if currSEQ > end+1 {
			// not contiguous -> cannot receive
			// - remove all the preceding segments
			tcb.EarlyArrivals = tcb.EarlyArrivals[i:]
			return currData, uint32(len(currData))
		}
		// Either currSEQ - 1 == end or
		// end lies in [currSEQ, currEND]
		mergeLen := min(int(available), len(curr.Payload))
		// Get the offset
		off := ((end + 1) - currSEQ)
		// Get the data
		mergeData := curr.Payload[off : off+uint32(mergeLen)]
		currData = append(currData, mergeData...)
		available -= uint32(mergeLen)
		if available == 0 {
			if mergeLen != len(curr.Payload) {
				// we have not completely merged this segment
				tcb.EarlyArrivals = tcb.EarlyArrivals[i:]
			} else {
				// we completely merged this segment
				if i == len(tcb.EarlyArrivals)-1 {
					// if this is the last segment
					// we know we are done with this queue
					tcb.EarlyArrivals = make([]*TCPPacket, 0)
				} else {
					// if not, remove self and go on
					tcb.EarlyArrivals = tcb.EarlyArrivals[i+1:]
				}
			}
			return currData, uint32(len(currData))
		}
		end += uint32(mergeLen)
	}

	// If we get here we have merged everything and available > 0
	tcb.EarlyArrivals = make([]*TCPPacket, 0)
	return currData, uint32(len(currData))
}

// Get the useable window given a TCB state
func (tcb *TCB) GetUseableWND() uint32 {
	return tcb.SND_UNA + tcb.SND_WND - tcb.SND_NXT
}

// Get the advertised window given a TCB state
// MAX_BUF - (NXT - 1 - LBR)
// Example: MAX_BUF = 10
//
// + = byte consumed
// * = byte not yet consumed
//
//	l       n
//
// [ + * * * + + + + + + ]
// 10 - (4 - 1 - 0) = 7
//
//	l       n
//
// [ + + + + * * * + + + ]
// 10 - (7 - 1 - 3) = 7
// l                     n
// [ * * * * * * * * * * ]
// 10 - (10 - 1 - (-1)) = 0
func (tcb *TCB) GetAdvertisedWND() uint32 {
	return MAX_WND_SIZE - ((tcb.RCV_NXT - 1) - tcb.LBR)
}

// Gets the number of unread bytes in the recv buffer
func (tcb *TCB) GetUnreadBytes() uint32 {
	return (tcb.RCV_NXT - 1) - tcb.LBR
}

// Gets the number of unsent bytes in the recv buffer
// - - - - -
func (tcb *TCB) GetSendableBytes() uint32 {
	return (tcb.LBW - tcb.SND_NXT) + 1
}

// Send is done if retransmission queue is empty
func (tcb *TCB) IsSendDone() bool {
	return len(tcb.RetransmissionQ) == 0
}

// Reap the sockets that expired
func (stack *TCPStackT) Reap() {
	// SID to remove
	for sid := range stack.ReapChan {
		stack.StMtx.Lock()
		key := stack.SIDToTableKey[sid]
		RemoveSocketFromTable(key)
		stack.StMtx.Unlock()
	}
}

// Given TCB state, create an ACK packet with the current variables and passed-in flags
func (tcb *TCB) SendACKPacket(flag uint8, data []byte) *TCPPacket {
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT,
		tcb.RCV_NXT, DEFAULT_DATAOFFSET, flag,
		uint16(tcb.GetAdvertisedWND()))
	tcpPacket := &TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   data,
	}
	tcb.SendChan <- tcpPacket
	return tcpPacket
}

// Helper to print out the different connection variables
func (tcb *TCB) PrintTCBState() {
	iss := tcb.ISS
	irs := tcb.IRS
	fmt.Println("----- TCB State -----")
	fmt.Println("SND_UNA", tcb.SND_UNA-iss)
	fmt.Println("SND_NXT", tcb.SND_NXT-iss)
	fmt.Println("SND_WND", tcb.SND_WND)
	fmt.Println("RCV_NXT", tcb.RCV_NXT-irs)
	fmt.Println("RCV_WND", tcb.RCV_WND)
	fmt.Println("LBR", tcb.LBR-irs)
	fmt.Println("LBW", tcb.LBW-iss)
	fmt.Println("---------------------")
}

func (tcb *TCB) PrintOutgoingSegment(seg *TCPPacket) {
	iss := tcb.ISS
	irs := tcb.IRS
	fmt.Println("----- SEGMENT -----")
	fmt.Println("SEG_SEQ", seg.TCPHeader.SeqNum-iss)
	fmt.Println("SEG_ACK", seg.TCPHeader.AckNum-irs)
	fmt.Println("SEG_LEN", len(seg.Payload))
	fmt.Println("SEG_WND", seg.TCPHeader.WindowSize)
	fmt.Println("-------------------")
}

func (tcb *TCB) PrintSegment(seg *TCPPacket) {
	iss := tcb.ISS
	irs := tcb.IRS
	fmt.Println("----- SEGMENT -----")
	fmt.Println("SEG_SEQ", seg.TCPHeader.SeqNum-irs)
	fmt.Println("SEG_ACK", seg.TCPHeader.AckNum-iss)
	fmt.Println("SEG_LEN", len(seg.Payload))
	fmt.Println("SEG_WND", seg.TCPHeader.WindowSize)
	fmt.Println("-------------------")
}

// Given TCB state, check if incoming segment is valid or not
func (tcb *TCB) IsSegmentValid(tcpPacket *TCPPacket) bool {
	SEG_LEN := len(tcpPacket.Payload)
	SEG_SEQ := tcpPacket.TCPHeader.SeqNum
	RCV_WND := tcb.GetAdvertisedWND()
	// Four CASES

	// Case 1: SEG_LEN = 0 && RECV_WND = 0
	// -> SEG_SEQ = RCV_NXT
	if SEG_LEN == 0 && RCV_WND == 0 {
		return SEG_SEQ == RCV_WND
	}

	// Case 2: SEG_LEN = 0 && RECV_WND > 0
	// -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
	if SEG_LEN == 0 && RCV_WND > 0 {
		return (tcb.RCV_NXT <= SEG_SEQ) && (SEG_SEQ <= tcb.RCV_NXT+RCV_WND)
	}

	// Case 3: SEG_LEN > 0 && RECV_WND = 0
	// -> Not acceptable
	if SEG_LEN > 0 && RCV_WND == 0 {
		return false
	}

	// Case 4: SEG_LEN > 0 && RECV_WND > 0
	// -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
	//               or
	// -> RCV.NXT <= SEG.SEQ+SEG_LEN-1 < RCV.NXT+RCV.WND

	// Does first part of the segment fall within the window
	cond1 := (tcb.RCV_NXT <= SEG_SEQ) && (SEG_SEQ <= tcb.RCV_NXT+RCV_WND)
	// Does last part of the segment fall within the window
	cond2 := (tcb.RCV_NXT <= SEG_SEQ+uint32(SEG_LEN)-1) && (SEG_SEQ+uint32(SEG_LEN)-1 <= tcb.RCV_NXT+RCV_WND)

	// If either is true, there is data
	return cond1 || cond2
}

// Look up on socket table
func SocketTableLookup(key SocketTableKey) (*TCB, bool) {
	tcb, ok := TCPStack.SocketTable[key]
	return tcb, ok
}

// Given a SID, return the TCB
func SIDToTCB(sid int) (*TCB, bool) {
	key, ok := TCPStack.SIDToTableKey[sid]
	if !ok {
		return nil, false
	}
	return SocketTableLookup(key)
}

// Create TCB for Listen Socket
func CreateTCBForListenSocket(sid int, port uint16) *TCB {
	return &TCB{
		SID:         sid,
		State:       socket.LISTEN,
		Laddr:       netip.MustParseAddr("0.0.0.0"),
		Lport:       port,
		Raddr:       netip.MustParseAddr("0.0.0.0"),
		Rport:       0,
		ReceiveChan: make(chan *TCPPacket, 100),
		ReapChan:    TCPStack.ReapChan,
		SendChan:    TCPStack.SendChan,
		TimeReset:   make(chan bool, 100),
		SND_WND:     MAX_WND_SIZE,
		RCV_WND:     MAX_WND_SIZE,
	}
}

// Create TCB for Normal Socket
func CreateTCBForNormalSocket(sid int, laddr netip.Addr, lport uint16,
	raddr netip.Addr, rport uint16) *TCB {
	return &TCB{
		// Basic Connection Information
		SID:   sid,
		State: socket.LISTEN,
		Laddr: laddr,
		Lport: lport,
		Raddr: raddr,
		Rport: rport,
		// IPStack <=> Socket(s)
		ReceiveChan: make(chan *TCPPacket, 100),
		SendChan:    TCPStack.SendChan,
		// Sent when our FIN packet was ACK'ed
		FinOK: make(chan bool, 100),
		// Reset chan for restarting TIME-WAIT timer
		TimeReset: make(chan bool, 100),
		// Signal the reaper to reap sent SID
		ReapChan: TCPStack.ReapChan,
		// ACK signal
		ACKSignal:      make(chan bool, 100),
		SBufDataSignal: make(chan SendBufData, 100),
		SBufPutSignal:  make(chan bool, 100),
		RBufDataSignal: make(chan bool, 100),
		// Buffers
		SendBuffer: socket.InitCircularBuffer(),
		RecvBuffer: socket.InitCircularBuffer(),
		// Early Arrival Queue
		EarlyArrivals: make([]*TCPPacket, 0),
		// Retransmission Queue
		RetransmissionQ: make([]*Segment, 0),
		// Receive Window is max initially
		RCV_WND: MAX_WND_SIZE,
		// Last Byte Read
		LBR: 0,
	}
}

// Add Key and Value to Socket Table
func AddSocketToTable(key SocketTableKey, value *TCB) {
	TCPStack.SocketTable[key] = value
	TCPStack.SIDToTableKey[value.SID] = key
}

// Remove Socket from Table
func RemoveSocketFromTable(key SocketTableKey) {
	tcb := TCPStack.SocketTable[key]
	// Remove from SID to Key map
	delete(TCPStack.SIDToTableKey, tcb.SID)
	// Remove from actual Socket Table
	delete(TCPStack.SocketTable, key)
	// If listen sock, un-bind
	if tcb.State == socket.LISTEN {
		unbind := tcb.Lport
		TCPStack.BoundPorts[int(unbind)] = false
	}
}

// Given a port, bind to that port
func BindPort(toBind int) bool {
	if val, ok := TCPStack.BoundPorts[toBind]; ok && val {
		return false
	}
	TCPStack.BoundPorts[toBind] = true
	return true
}

// Allocate a socket id for new socket
func AllocSID() int {
	toRet := TCPStack.NextSID
	TCPStack.NextSID++
	return toRet
}

// Create the 4-tuple
func CreateSocketTableKey(l bool, laddr netip.Addr, lport uint16,
	raddr netip.Addr, rport uint16) SocketTableKey {
	if l {
		// For listen socket
		return SocketTableKey{
			Laddr: netip.MustParseAddr("0.0.0.0"),
			Lport: lport,
			Raddr: netip.MustParseAddr("0.0.0.0"),
			Rport: 0,
		}
	}
	return SocketTableKey{
		Laddr: laddr,
		Lport: lport,
		Raddr: raddr,
		Rport: rport,
	}
}

// TCP Protocol (6)
func HandleTCPProtocol(packet *packet.Packet, l *slog.Logger) {
	// First get the payload and unmarshal
	tcpHdr := util.ParseTCPHeader(packet.Payload)
	// Assume for now, no options are used
	payload := packet.Payload[tcpHdr.DataOffset:]
	// Verify TCP Checksum
	fromHdr := tcpHdr.Checksum
	tcpHdr.Checksum = 0
	computedChecksum := util.ComputeTCPChecksum(&tcpHdr, packet.IPHeader.Src, packet.IPHeader.Dst, payload)
	if fromHdr != computedChecksum {
		l.Error(fmt.Sprintf("Checksum Incorrect: %d != %d", fromHdr, computedChecksum))
		return
	}
	// Construct TCP Packet
	tcpPacket := &TCPPacket{
		LAddr:     packet.IPHeader.Dst,
		RAddr:     packet.IPHeader.Src,
		TCPHeader: &tcpHdr,
		Payload:   payload,
	}
	// First look up normal conn
	key := CreateSocketTableKey(false, packet.IPHeader.Dst,
		tcpHdr.DstPort, packet.IPHeader.Src, tcpHdr.SrcPort)
	tcb, found := SocketTableLookup(key)
	// If normal socket is found, forward the packet to that socket
	if found {
		tcb.ReceiveChan <- tcpPacket
		return
	}
	// If not found, check for listen socket
	key = CreateSocketTableKey(true, netip.Addr{}, tcpHdr.DstPort,
		netip.Addr{}, 0)
	tcb, found = SocketTableLookup(key)
	if found {
		// Should be SYN packet
		tcb.ReceiveChan <- tcpPacket
		return
	}

	l.Info("Received TCP Packet destined to unknown application")
}
