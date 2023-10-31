package proto

import (
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

type TCPPacket struct {
	LAddr     netip.Addr
	RAddr     netip.Addr
	TCPHeader *header.TCPFields
	Payload   []byte
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

	// Pointers to Buffers
	SendBuffer *socket.CircularBuffer
	RecvBuffer *socket.CircularBuffer

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
}

type SocketTableKey struct {
	// The 4-tuple maps to a single socket
	Laddr netip.Addr
	Lport uint16
	Raddr netip.Addr
	Rport uint16
}

type SocketTableT struct {
	// Socket Id to Key into TCB for ease of access from REPL
	SIDToTableKey map[int]SocketTableKey
	// The Cannonical table
	Table map[SocketTableKey]*TCB
	StMtx sync.Mutex
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
func (tcb *TCB) SendACKPacket(flag uint8) {
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT, tcb.RCV_NXT, DEFAULT_DATAOFFSET, flag, uint16(tcb.RCV_WND))
	tcpPacket := &TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   []byte{},
	}
	tcb.SendChan <- tcpPacket
}

// Given TCB state, check if incoming segment is valid or not
func (tcb *TCB) IsSegmentValid(tcpPacket *TCPPacket) bool {
	SEG_LEN := len(tcpPacket.Payload)
	SEG_SEQ := tcpPacket.TCPHeader.SeqNum

	// Four CASES

	// Case 1: SEG_LEN = 0 && RECV_WND = 0
	// -> SEG_SEQ = RCV_NXT
	if SEG_LEN == 0 && tcb.RCV_WND == 0 {
		return SEG_SEQ == tcb.RCV_NXT
	}

	// Case 2: SEG_LEN = 0 && RECV_WND > 0
	// -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
	if SEG_LEN == 0 && tcb.RCV_WND > 0 {
		return (tcb.RCV_NXT <= SEG_SEQ) && (SEG_SEQ <= tcb.RCV_NXT+tcb.RCV_WND)
	}

	// Case 3: SEG_LEN > 0 && RECV_WND = 0
	// -> Not acceptable
	if SEG_LEN > 0 && tcb.RCV_WND == 0 {
		return false
	}

	// Case 4: SEG_LEN > 0 && RECV_WND > 0
	// -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
	//               or
	// -> RCV.NXT <= SEG.SEQ+SEG_LEN-1 < RCV.NXT+RCV.WND

	// Does first part of the segment fall within the window
	cond1 := (tcb.RCV_NXT <= SEG_SEQ) && (SEG_SEQ <= tcb.RCV_NXT+tcb.RCV_WND)
	// Does last part of the segment fall within the window
	cond2 := (tcb.RCV_NXT <= SEG_SEQ+uint32(SEG_LEN)-1) && (SEG_SEQ+uint32(SEG_LEN)-1 <= tcb.RCV_NXT+tcb.RCV_WND)

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
		RCV_WND:     MAX_WND_SIZE,
	}
}

// Create TCB for Normal Socket
func CreateTCBForNormalSocket(sid int, laddr netip.Addr, lport uint16,
	raddr netip.Addr, rport uint16) *TCB {
	return &TCB{
		SID:         sid,
		State:       socket.LISTEN,
		Laddr:       laddr,
		Lport:       lport,
		Raddr:       raddr,
		Rport:       rport,
		ReceiveChan: make(chan *TCPPacket, 100),
		SendChan:    TCPStack.SendChan,
		ReapChan:    TCPStack.ReapChan,
		FinOK:       make(chan bool, 100),
		TimeReset:   make(chan bool, 100),
		RCV_WND:     MAX_WND_SIZE,
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
		l.Error("TCP Checusum is wrong")
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
