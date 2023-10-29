package socket

import (
    "net/netip"
)

type TCB struct {
	SID   int // Socket Id
	State SocketState // Socket State

    Laddr netip.Addr // my ip addr
    Lport uint16 // my ip port

    Raddr netip.Addr // other ip addr
    Rport uint16 // other ip port
}

type SocketState int

const (
	// Defines different state the TCP Socket can be in
	LISTEN SocketState = iota
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
	FIN_WAIT_1
	FIN_WAIT_2
	CLOSE_WAIT
	CLOSING
	LAST_ACK
	TIME_WAIT
	CLOSED
)

// ============= Helper ==============

// Create TCB for Listen Socket
func CreateTCBForListenSocket(sid int, port uint16) *TCB {
    return &TCB{
        SID: sid,
        State: LISTEN,
        Laddr: netip.MustParseAddr("0.0.0.0"),
        Lport: port,
        Raddr: netip.MustParseAddr("0.0.0.0"),
        Rport: 0,
    }
}

// Given Socket State in int, return the string representation of it
func ToSocketStateStr(state SocketState) string {
	switch state {
	case LISTEN:
		{
			return "LISTEN"
		}
	case SYN_SENT:
		{
			return "SYN_SENT"
		}
	case SYN_RECEIVED:
		{
			return "SYN_RECEIVED"
		}
	case ESTABLISHED:
		{
			return "ESTABLISHED"
		}
	case FIN_WAIT_1:
		{
			return "FIN_WAIT_1"
		}
	case FIN_WAIT_2:
		{
			return "FIN_WAIT_2"
		}
	case CLOSE_WAIT:
		{
			return "CLOSE_WAIT"
		}
	case CLOSING:
		{
			return "CLOSING"
		}
	case LAST_ACK:
		{
			return "LAST_ACK"
		}
	case TIME_WAIT:
		{
			return "TIME_WAIT"
		}
	case CLOSED:
		{
			return "CLOSED"
		}
	default:
		{
			return ""
		}
	}
}
