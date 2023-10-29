package socket_api

import (
	"errors"
	"net/netip"
	"netstack/pkg/proto"
	"netstack/pkg/socket"
)

type VTCPListener struct {
    SID   int
    Laddr netip.Addr // Addr we are listening at
    Lport uint16 // Port we are listening at 
}

type VTCPConn struct {

}

// ================= VTCPListener ====================

// VListen creates a new listening socket bound to the specified port
// After binding, the listening socket moves into LISTEN state
// Returns the listening socket or error 
func VListen(port uint16) (*VTCPListener, error) {
    if !proto.BindPort(int(port)) {
        // Port already bound
        return &VTCPListener{}, errors.New("Port already in use")
    }
    // Allocate new socket id
    sid := proto.AllocSID()
    // Create TCB for the Listen Socket
    tcb := socket.CreateTCBForListenSocket(sid, port)
    // Create Key for TCB
    key := proto.CreateSocketTableKey(true, netip.Addr{}, port, netip.Addr{}, 0)
    // Add to socket table
    proto.AddSocketToTable(key, tcb)
    // Return listen socket
	return &VTCPListener{
        SID: sid,
        Laddr: key.Laddr,
        Lport: port,
    }, nil
}

// VAccept waits for new TCP connections on the given listening socket
// BLOCK until new connection is established
// Returns the new normal socket represneting the connection or error
func (li *VTCPListener) VAccept() (*VTCPConn, error) {
    return &VTCPConn{}, nil
}

// Closes this listening socket, removing it from the socket table. 
// No new connection may be made on this socket. 
// Returns eror if closing fails
func (li *VTCPListener) VClose() error {
    return nil
}

// ================= VTCPConn =========================

// Creates a new socket that connects to the specified virtual IP address and port
// Up to util.NUM_RETRANS number of retransmission attemps are maded until aborting
// Returns the new normal socket representing the connection or error
func VConnect(addr netip.Addr, port int16) (*VTCPConn, error) {
    return &VTCPConn{}, nil
}

// Reads data from the TCP socket. Data is read into "buf"
// BLOCK when there is no available data to read. 
// Unless a failure or EOF occurs, this should return at least 1 byte
// Return number of bytes read into the buffer. 
// The returned error is nil on success, io.EOF if other side of connection has finished
// or another error describing other failure cases.
func (conn *VTCPConn) VRead(buf []byte) (int, error) {
    return -1, nil 
}

// Writes data to the TCP socket. Data to write is in "data"
// BLOCK until all data are in the send buffer of the socket
// Returns the number of bytes written to the connection. 
func (conn *VTCPConn) VWrite(data []byte) (int, error) {
    return -1, nil
}

// Initiates the connection termination process for this socket
// All subsequent calls to VRead and VWrite on this socket should return an error
// (NOTE)
// VClose only initiates the close process, hence it is non-blocking.
// VClose does not delete sockets
func (conn *VTCPConn) VClose() error {
    return nil
}