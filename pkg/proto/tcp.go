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

// Global Socket Table
var SocketTable SocketTableT

// Function that initializes our Socket Table for hosts
func InitializeSocketTable() {
    SocketTable  = SocketTableT{
        SIDToTableKey: make(map[int]SocketTableKey),
        Table: make(map[SocketTableKey]*socket.TCB),
    }
}