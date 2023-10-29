package proto

import (
	"net/netip"
	"netstack/pkg/socket"
	"sync"
)

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
	Table map[SocketTableKey]*socket.TCB
	StMtx sync.Mutex
}

type TCPStackT struct {
    // Next Available Socket ID
    NextSID int
    // Socket Id to Key into TCB for ease of access from REPL
    SIDToTableKey map[int]SocketTableKey
    // The Cannonical table
	SocketTable map[SocketTableKey]*socket.TCB
    StMtx sync.Mutex
    // Bounded Ports
	BoundPorts  map[int]bool
}

// Global Socket Table
var TCPStack TCPStackT

// Function that initializes our Socket Table for hosts
func InitializeTCPStack() {
	TCPStack = TCPStackT{
        NextSID: 0,
        SIDToTableKey: make(map[int]SocketTableKey),
		SocketTable: make(map[SocketTableKey]*socket.TCB),
        BoundPorts: make(map[int]bool),
	}
}

// =================== Helper ===================

// Add Key and Value to Socket Table
func AddSocketToTable(key SocketTableKey, value *socket.TCB) {
    TCPStack.SocketTable[key] = value
    TCPStack.SIDToTableKey[value.SID] = key
}

// Given a port, bind to that port
func BindPort(toBind int) bool {
    if _, ok := TCPStack.BoundPorts[toBind]; ok {
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
func CreateSocketTableKey( l bool, laddr netip.Addr, lport uint16, 
    raddr netip.Addr, rport uint16,) SocketTableKey {
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