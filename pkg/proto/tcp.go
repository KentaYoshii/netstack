package proto

import (
	"errors"
	"log/slog"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/socket"
	"netstack/pkg/util"
	"os"
	"sync"
	"time"

	"github.com/google/netstack/tcpip/header"
)

const (
	MAX_WND_SIZE       = 65535
	DEFAULT_DATAOFFSET = 20
	// Retransmission Related
	MAX_RTO   = 5000
	MIN_RTO   = 100
	RTT_ALPHA = 0.8
	RTT_BETA  = 1.5
)

type TCPPacket struct {
	// Struct that represents single TCPPacket

	LAddr     netip.Addr
	RAddr     netip.Addr
	TCPHeader *header.TCPFields
	Payload   []byte
}

type RQSegment struct {
	// Struct that gets put in the Retransmission Queue
	// Contains meta data about the packet

	Packet       *TCPPacket
	SentAt       time.Time
	IsRetransmit bool
}

type TCB struct {
	// Struct that represents Transmission Control Block (TCB)

	// Associated Socket Id
	SID int
	// TCB State
	State int

	// 4-tuple
	Laddr netip.Addr
	Lport uint16
	Raddr netip.Addr
	Rport uint16

	// Communication between IP Stack and TCP Stack
	ReceiveChan chan *TCPPacket
	SendChan    chan *TCPPacket

	// TIME_WAIT timer reset channel
	TimeReset chan bool
	// Signal the Reaper for TCB removeal
	// after entering CLOSED state
	ReapChan chan int
	// Update to ACK cond
	// - when you receive new ACK number
	ACKCond sync.Cond
	// Update to RQ cond
	// - when you receive new ACK number
	RQUpdateCond sync.Cond
	// Update the thread that sends out data in send buffer
	SBufDataCond sync.Cond
	// Update the thread that puts data into send buffer
	SBufPutCond sync.Cond
	// Update the thread that send buffre is empty
	// - when waiting to send out FIN packet
	SBufEmptyCond sync.Cond
	// Update the reader that there is data to read in receive buffer
	RBufDataCond sync.Cond

	// Circular Send Buffer
	SendBuffer *socket.CircularBuffer
	// Circular Receive Buffer
	RecvBuffer *socket.CircularBuffer
	// Early Arrivals Queue
	EarlyArrivals []*TCPPacket

	// Retransmission Queue
	RetransmissionQ []*RQSegment
	// Mutex for updating Retransmission Queue
	RQMu sync.Mutex
	// Ticker for Retransmitting oldest unACK'ed segment
	RQTicker *time.Ticker
	// Retransmission Timeout (in ms)
	RTO float64
	// True if RTO timer is running
	RTOStatus bool
	// Smooth Round Trip Time
	SRTT float64
	// True if updating RTO for the first time
	First bool

	// Initial Sequence Numbers
	ISS uint32
	IRS uint32

	// Connection State Variables

	// - Oldest un-ACK'ed sequence number
	SND_UNA uint32
	// - Next sequence number to send
	SND_NXT uint32
	// - Send Window
	SND_WND uint32
	// - Next sequence number we expect to receive
	RCV_NXT uint32
	// - Receive Window
	RCV_WND uint32

	// Last Byte Read in Receive Buffer
	LBR uint32
	// Last Byte Written in Send Buffer
	LBW uint32

	// True if Zero Window Probing
	ProbeStatus bool
	// Signal to stop Zero Window Probing
	ProbeStopSignal chan bool

	// Congestion Control

	// True if using Congestion Control
	CCEnabled bool
	// "Reno" or "Tahoe"
	CCAlgo string
	// Congestion Window
	// - Variable that limits the amount of data a TCP can send
	CWND uint16
	// Slow Start Threshold
	SSThresh uint16
	// Number of Bytes ACK'ed
	// - Use during Congestion Avoidance
	NumBytesACK uint16
	// Flag to see if we can increment CWND during CA
	CAIncrementFlag bool
}

type SocketTableKey struct {
	// The 4-tuple
	// - This maps to a single TCB

	Laddr netip.Addr
	Lport uint16
	Raddr netip.Addr
	Rport uint16
}

type TCPStackT struct {
	// Struct that represents TCPStack

	// Counter used for clock-based ISN generation
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
	// Logger
	Logger *slog.Logger
}

// Global Socket Table
var TCPStack *TCPStackT

// Log given string with given type
func Log(msg string, level util.LogLevel) {
	switch level {
	case util.DEBUG:
		TCPStack.Logger.Debug(msg)
	case util.INFO:
		TCPStack.Logger.Info(msg)
	case util.WARN:
		TCPStack.Logger.Warn(msg)
	case util.ERROR:
		TCPStack.Logger.Error(msg)
	}
}

// Function that initializes TCP stack
func InitializeTCPStack(sendChan chan *TCPPacket) {
	TCPStack = &TCPStackT{
		ISNCTR:        0,
		NextSID:       0,
		SIDToTableKey: make(map[int]SocketTableKey),
		SocketTable:   make(map[SocketTableKey]*TCB),
		BoundPorts:    make(map[int]bool),
		SendChan:      sendChan,
		ReapChan:      make(chan int, 100),
		Logger: slog.New(util.NewPrettyHandler(os.Stdout, util.PrettyHandlerOptions{
			SlogOpts: slog.HandlerOptions{
				Level: slog.LevelInfo,
			},
		})),
	}
	// Start the ISN generator
	go util.KeepIncrement(&TCPStack.ISNCTR)
	// Start the repear of SID
	go TCPStack.Reap()
}

// Function that trims the payload of the given tcpPacket
// based on the current state of TCB
// Returns the trimmed payload and the size of that payload
func (tcb *TCB) TrimSegment(tcpPacket *TCPPacket) ([]byte, uint16) {
	SEG_SEQ := tcpPacket.TCPHeader.SeqNum
	SEG_LEN := uint16(len(tcpPacket.Payload))
	SEG_DATA := tcpPacket.Payload
	available := tcb.GetAdvertisedWND()
	// Compute the offset to the first new byte
	start := tcb.RCV_NXT - SEG_SEQ
	if start != 0 {
		// If non-zero, trim the irrelevant beginning bytes
		SEG_DATA = SEG_DATA[start:]
		SEG_LEN = uint16(len(SEG_DATA))
	}
	// Compute the number of bytes we can receive
	end := min(available, SEG_LEN)
	SEG_DATA = SEG_DATA[start:end]
	SEG_LEN = uint16(len(SEG_DATA))
	return SEG_DATA, SEG_LEN
}

// Function that gets a current RTO in time.Duration
func (tcb *TCB) GetRTO() time.Duration {
	tcb.RTOStatus = true
	return time.Duration(tcb.RTO * float64(time.Millisecond))
}

// Function that computes the RTT based on RFC 793
// Takes in a measured RTT of a normal segment
// Sets SRTT and RTO
func (tcb *TCB) ComputeRTT(r float64) {
	if tcb.First {
		tcb.SRTT = r
		tcb.First = false
	} else {
		tcb.SRTT = (RTT_ALPHA * tcb.SRTT) + ((1 - RTT_ALPHA) * r)
	}
	// CLAMP [100, 5000]
	tcb.RTO = min(MAX_RTO, max(MIN_RTO, tcb.SRTT*RTT_BETA))
}

// Insert so that Early Arrival Packets are in order of their sequence numbers
// Example:
// If you have EAQ of 1 4 5 6
// - You get early arrival packet with seq 3
// - Result is 1 3 4 5 6
// Returns true if successfully inserted
func (tcb *TCB) InsertEAQ(packet *TCPPacket) bool {
	if len(tcb.EarlyArrivals) == 0 {
		// If length is zero, simply append
		tcb.EarlyArrivals = append(tcb.EarlyArrivals, packet)
		return true
	}
	// Find the insert position
	// Sequence number is strictly increasing
	insertPos := 0
	found := false
	insertSeq := packet.TCPHeader.SeqNum
	for i, curr := range tcb.EarlyArrivals {
		if insertSeq == curr.TCPHeader.SeqNum {
			// We already have this in our early arrivals queue
			return false
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
		// If not found, that means this packet has the largest
		// sequence number
		q = append(tcb.EarlyArrivals, packet)
	} else {
		// Insert
		// the ones before
		q = append(q, tcb.EarlyArrivals[:insertPos]...)
		// the newcomer
		q = append(q, packet)
		// the ones later
		q = append(q, tcb.EarlyArrivals[insertPos:]...)
	}
	tcb.EarlyArrivals = q
	return true
}

// Given the next sequence number, loop the EAQ and merge data
// until we merge all possible early arrival segments or run out of
// receive window
// Returns merged data and the size of that new merged data
func (tcb *TCB) MergeEAQ(start uint32, currData []byte) ([]byte, uint16) {
	// Get the Receive Window space
	available := tcb.GetAdvertisedWND() - uint16(len(currData))
	if available == 0 {
		// No space available in recv buf
		return currData, uint16(len(currData))
	}
	for i, curr := range tcb.EarlyArrivals {
		currSEQ := curr.TCPHeader.SeqNum
		currEND := currSEQ + uint32(len(curr.Payload)) - 1
		if currEND < start {
			// We already have this segment
			continue
		}
		if currSEQ > start {
			// Not contiguous, we cannot receive
			// - remove all the preceding segments
			tcb.EarlyArrivals = tcb.EarlyArrivals[i:]
			return currData, uint16(len(currData))
		}

		// Either
		// - currSEQ == start
		// - currSEQ < start <= currEND

		// Trim the data first
		d := curr.Payload[start-currSEQ:]
		// Check how many bytes we can merge
		mLen := min(int(available), len(d))
		// Append the data
		currData = append(currData, d[:mLen]...)
		// Reflect the update
		available -= uint16(mLen)
		// Update pointer to next byte to be merge
		start += uint32(mLen)
		// Check if we can merge more
		if available != 0 {
			continue
		}

		// If we cannot merge, then we trim the EAQs
		// Two cases:
		// - Complete merge
		// - Partial merge

		if currEND < start {
			// Complete merge
			// -> rm up until and including this current segment
			if i == len(tcb.EarlyArrivals)-1 {
				// If last element, simply reset the queue
				tcb.EarlyArrivals = make([]*TCPPacket, 0)
			} else {
				tcb.EarlyArrivals = tcb.EarlyArrivals[i+1:]
			}
			return currData, uint16(len(currData))
		}

		// Partial merge
		// -> rm up until and excluding this segment from the queue
		tcb.EarlyArrivals = tcb.EarlyArrivals[i:]
		return currData, uint16(len(currData))
	}

	// If we get here we have merged everything and available > 0
	tcb.EarlyArrivals = make([]*TCPPacket, 0)
	return currData, uint16(len(currData))
}

// Returns true if this socket is in the Slow Start mode
// Retruns false otherwise (e.g., it is in Congestion Avoidance mode)
func (tcb *TCB) IsSlowStart() bool {
	return tcb.CWND < tcb.SSThresh
}

// Returns the number of bytes available in the send window 
// If congestion control is enabled, then CWND is taken into consideration
func (tcb *TCB) GetNumFreeBytesInSNDWND() uint16 {
	sndWNDSZ := tcb.GetNumBytesInSNDWND()
	if !tcb.CCEnabled {
		// If no CC is used, we can just return the number of free bytes in SND_WND
		return sndWNDSZ
	}
	// At any given time, a TCP MUST NOT send data with a sequence number 
	// higher than the sum of the highest acknowledged sequence number and 
	// the minimum of cwnd and rwnd.
	//           una     nxt
	// [A A A A A U U U U - - - - ] (A = ACK'ed, U = unACK'ed, CWND = 6)
	return min(tcb.CWND-tcb.GetNumBytesInFlight(), sndWNDSZ)
}

// Get the bytes in send window given a TCB state
//
//	u     n    u+s
//
// [+ + + - - - -]
func (tcb *TCB) GetNumBytesInSNDWND() uint16 {
	return uint16(tcb.SND_UNA + tcb.SND_WND - tcb.SND_NXT)
}

// Get the number of in-flight bytes
//
//	u         n
//
// [+ + + + + - - -]
func (tcb *TCB) GetNumBytesInFlight() uint16 {
	return uint16(tcb.SND_NXT - tcb.SND_UNA)
}

// Gets the number of free bytes in the send buffer
//
//	n         l
//
// [+ + + + + + f f f f]
func (tcb *TCB) GetNumFreeBytesInSNDBUF() uint16 {
	return uint16(MAX_WND_SIZE - (tcb.LBW - tcb.SND_NXT + 1))
}

// Gets the number of unsent bytes in the send buffer
//
//	n       l
//
// [* * * * * f f f]
func (tcb *TCB) GetNumBytesInSNDBUF() uint16 {
	return uint16(tcb.LBW - tcb.SND_NXT + 1)
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
//
// l                     n
// [ * * * * * * * * * * ]
// 10 - (10 - 1 - (-1)) = 0
func (tcb *TCB) GetAdvertisedWND() uint16 {
	return uint16(MAX_WND_SIZE - ((tcb.RCV_NXT - 1) - tcb.LBR))
}

// Gets the number of unread bytes in the recv buffer
//
//	l          rn
//
// [r r r r nr nr nr +]
func (tcb *TCB) GetUnreadBytes() uint16 {
	return uint16((tcb.RCV_NXT - 1) - tcb.LBR)
}

// Reaps the sockets that expired
// SID is sent through the ReapChan
func (stack *TCPStackT) Reap() {
	// SID to remove
	for sid := range stack.ReapChan {
		stack.StMtx.Lock()
		key := stack.SIDToTableKey[sid]
		RemoveSocketFromTable(key)
		stack.StMtx.Unlock()
	}
}

// Given TCB state, create an ACK packet with the current
// variables and passed-in flags
// Return the sent out TCPPacket
func (tcb *TCB) SendACKPacket(flag uint8, data []byte) *TCPPacket {
	// TCP Header
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT,
		tcb.RCV_NXT, DEFAULT_DATAOFFSET, flag,
		uint16(tcb.GetAdvertisedWND()))
	// Create the Packet
	tcpPacket := &TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   data,
	}
	// Send out
	tcb.SendChan <- tcpPacket
	return tcpPacket
}

// Given TCB state, check if incoming segment is valid or not
// We do that by checking the sequence number, receiving window,
// and segment length
func (tcb *TCB) IsSegmentValid(tcpPacket *TCPPacket) bool {
	SEG_LEN := len(tcpPacket.Payload)
	SEG_SEQ := tcpPacket.TCPHeader.SeqNum
	RCV_WND := tcb.GetAdvertisedWND()

	// Four CASES

	// Case 1: SEG_LEN = 0 && RECV_WND = 0
	// -> SEG_SEQ = RCV_NXT
	if SEG_LEN == 0 && RCV_WND == 0 {
		return SEG_SEQ == uint32(RCV_WND)
	}

	// Case 2: SEG_LEN = 0 && RECV_WND > 0
	// -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
	if SEG_LEN == 0 && RCV_WND > 0 {
		return (tcb.RCV_NXT <= SEG_SEQ) && (SEG_SEQ <= tcb.RCV_NXT+uint32(RCV_WND))
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
	cond1 := (tcb.RCV_NXT <= SEG_SEQ) && (SEG_SEQ <= tcb.RCV_NXT+uint32(RCV_WND))
	// Does last part of the segment fall within the window
	cond2 := (tcb.RCV_NXT <= SEG_SEQ+uint32(SEG_LEN)-1) && (SEG_SEQ+uint32(SEG_LEN)-1 <= tcb.RCV_NXT+uint32(RCV_WND))

	// If either is true, there is data
	return cond1 || cond2
}

// Function that sets the congestion control state for the given socket
func (tcb *TCB) SetCongestionControl(cc string) error {
	if cc != "tahoe" && cc != "reno" && cc != "none" {
		return errors.New("Invalid Congestion Control algorithm provided")
	}
	if cc == "none" {
		tcb.CCEnabled = false
		tcb.CCAlgo = "N/A"
		return nil
	}
	tcb.CCEnabled = true
	tcb.CCAlgo = cc
	tcb.CWND = 3 * 1360
	tcb.SSThresh = MAX_WND_SIZE
	tcb.NumBytesACK = 0
	tcb.CAIncrementFlag = true
	go CongestionAvoidanceRTT(tcb)
	return nil
}

// Function that sets the flag for incrementing cwnd to true every RTT 
// This is to prevent CWND updates from happening too often 
// (more than once every RTT)
func CongestionAvoidanceRTT(tcb *TCB) {
	for {
		tick := time.NewTicker(tcb.GetRTO())
		select {
		case <-tick.C:
			{
				// Can Increment CWND every RTT in Congestion Avoidance mode
				tcb.CAIncrementFlag = true
				tick.Reset(tcb.GetRTO())
			}
		}
	}
}

// Look up on socket table given a 4-tuple
// Returns the TCB and true, if found
// Returns nil and false, if not found
func SocketTableLookup(key SocketTableKey) (*TCB, bool) {
	TCPStack.StMtx.Lock()
	defer TCPStack.StMtx.Unlock()
	tcb, ok := TCPStack.SocketTable[key]
	return tcb, ok
}

// Given a SID, return the TCB
// Returns the TCB and true, if found
// Returns nil and false, if not found
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
		SID:             sid,
		State:           socket.LISTEN,
		Laddr:           laddr,
		Lport:           lport,
		Raddr:           raddr,
		Rport:           rport,
		ReceiveChan:     make(chan *TCPPacket, 100),
		SendChan:        TCPStack.SendChan,
		TimeReset:       make(chan bool, 100),
		ReapChan:        TCPStack.ReapChan,
		ACKCond:         *sync.NewCond(&sync.Mutex{}),
		RQUpdateCond:    *sync.NewCond(&sync.Mutex{}),
		SBufDataCond:    *sync.NewCond(&sync.Mutex{}),
		SBufPutCond:     *sync.NewCond(&sync.Mutex{}),
		SBufEmptyCond:   *sync.NewCond(&sync.Mutex{}),
		RBufDataCond:    *sync.NewCond(&sync.Mutex{}),
		SendBuffer:      socket.InitCircularBuffer(),
		RecvBuffer:      socket.InitCircularBuffer(),
		EarlyArrivals:   make([]*TCPPacket, 0),
		RetransmissionQ: make([]*RQSegment, 0),
		RQTicker:        time.NewTicker(time.Duration(MIN_RTO * float64(time.Millisecond))),
		RTO:             100,
		RTOStatus:       false,
		First:           true,
		RCV_WND:         MAX_WND_SIZE,
		LBR:             0,
		LBW:             0,
		ProbeStatus:     false,
		ProbeStopSignal: make(chan bool, 10),
		CCEnabled:       false,
		CCAlgo:          "N/A",
	}
}

// Given "key" and "value", add the pair to the Socket Table
func AddSocketToTable(key SocketTableKey, value *TCB) {
	TCPStack.StMtx.Lock()
	defer TCPStack.StMtx.Unlock()
	TCPStack.SocketTable[key] = value
	TCPStack.SIDToTableKey[value.SID] = key
}

// Given 4-tuple key, remove the associated socket from Socket Table
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
// Returns false if port already bound
func BindPort(toBind int) bool {
	if val, ok := TCPStack.BoundPorts[toBind]; ok && val {
		return false
	}
	TCPStack.BoundPorts[toBind] = true
	return true
}

// Allocate a socket id for the new socket
func AllocSID() int {
	toRet := TCPStack.NextSID
	TCPStack.NextSID++
	return toRet
}

// Create the 4-tuple key based on network information
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
// - Parse the IP Packet
// - Compute TCP Checksum
// - Lookup which TCB to forward the packet to
// - Forward
//   - drop the packet if look up fails
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
		l.Error("Checksum Incorrect")
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
