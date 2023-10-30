package socket_api

import (
	"errors"
	"fmt"
	"net/netip"
	"netstack/pkg/proto"
	"netstack/pkg/socket"
	"netstack/pkg/util"
)

type VTCPListener struct {
	InfoChan chan string
	TCB      *proto.TCB
}

type VTCPConn struct {
	TCB *proto.TCB
}

// Maps of SIDs to Conns
// Used in our REPL for easy access to sockets
var SIDToListenSock map[int]*VTCPListener = make(map[int]*VTCPListener)
var SIDToNormalSock map[int]*VTCPConn = make(map[int]*VTCPConn)

// ================= VTCPListener ====================

// PASSIVE_OPEN

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
	// Create TCB for the Passive Open Socket
	tcb := proto.CreateTCBForListenSocket(sid, port)
	// Create Key for TCB
	key := proto.CreateSocketTableKey(true, netip.Addr{}, port, netip.Addr{}, 0)
	// Add to socket table
	proto.AddSocketToTable(key, tcb)
	// Return listen socket
	return &VTCPListener{
		TCB: tcb,
	}, nil
}

// VAccept waits for new TCP connections on the given listening socket
// BLOCK until new connection is established
// Returns the new normal socket represneting the connection or error
func (li *VTCPListener) VAccept() {
	// We will have a for loop that keeps monitoring the
	// Receive Channel of listening socket
	for {

		tcpPacket, more := <-li.TCB.ReceiveChan

		if !more {
			// Channel closed
			return
		}
		if (tcpPacket.TCPHeader.Flags & util.SYN) == 0 {
			// Not SYN packet
			continue
		}

		// We get a SYN -> create TCB
		// 1. Allocate SID, ISN, and TCB
		// 2. Add the new socket to socket table
		// 3. Update the connection state variables of the new TCB
		// 4. Invoke the subroutine to proceed with the handshake
		// 5. Once the 3-way Handshake is done dispatch the socket
        //    - If fails, remove the alloc'ed TCB

		// 1
		sid := proto.AllocSID()
		isn := util.GetNewISN(proto.TCPStack.ISNCTR, tcpPacket.LAddr, tcpPacket.TCPHeader.DstPort, tcpPacket.RAddr, tcpPacket.TCPHeader.SrcPort)
		newTCB := proto.CreateTCBForNormalSocket(sid, tcpPacket.LAddr, tcpPacket.TCPHeader.DstPort, tcpPacket.RAddr, tcpPacket.TCPHeader.SrcPort)
		// 2
		key := proto.CreateSocketTableKey(false, tcpPacket.LAddr, tcpPacket.TCPHeader.DstPort, tcpPacket.RAddr, tcpPacket.TCPHeader.SrcPort)
		proto.AddSocketToTable(key, newTCB)
		// 3
		newTCB.State = socket.SYN_RECEIVED
		newTCB.ISS = isn
		newTCB.IRS = tcpPacket.TCPHeader.SeqNum
		newTCB.SND_UNA = newTCB.ISS
		newTCB.SND_NXT = newTCB.ISS + 1
		newTCB.RCV_NXT = tcpPacket.TCPHeader.SeqNum + 1
		// 4
		for i := 0; i < MAX_RETRANS; i++ {
			suc := _passiveHandshake(newTCB)
			if suc {
				// Connection is established!
				li.InfoChan <- fmt.Sprintf("New connection on SID=%d => Created new socket with SID=%d", li.TCB.SID, newTCB.SID)
				// Add to mapping
				SIDToNormalSock[newTCB.SID] = &VTCPConn{
					newTCB,
				}
				// 5 
				go _doSocket(newTCB)
				break
			}
		}
        // If failed, remove the TCB 
        proto.RemoveSocketFromTable(key)
	}
}

// Closes this listening socket, removing it from the socket table.
// No new connection may be made on this socket.
// Returns eror if closing fails
func (li *VTCPListener) VClose() error {
	// First close the receive chan so no new SYN packet is received
	close(li.TCB.ReceiveChan)
	// Remove
	key := proto.CreateSocketTableKey(true, netip.Addr{}, li.TCB.Lport, netip.Addr{}, 0)
	proto.RemoveSocketFromTable(key)
	return nil
}

// ================= VTCPConn =========================

// ACTIVE_OPEN

// Creates a new socket that connects to the specified virtual IP address and port
// Up to util.NUM_RETRANS number of retransmission attemps are made until aborting
// Returns the new normal socket representing the connection or error
func VConnect(laddr netip.Addr, raddr netip.Addr, rport uint16) (*VTCPConn, error) {

	// Active Open
	// 1. Allocate port, SID, ISN, and TCB
	// 2. Add the new socket to socket table
	//    - If key already exists, try another port
	// 3. Update the connection state variables of the new TCB
	// 4. Invoke the subroutine to proceed with the handshake
	// 5. Once the 3-way handshake is done, dispatch the socket

	// 1
	sid := proto.AllocSID()
retry:
	lport := util.GetPort()
	iss := util.GetNewISN(proto.TCPStack.ISNCTR, laddr, lport, raddr, rport)
	tcb := proto.CreateTCBForNormalSocket(sid, laddr, lport, raddr, rport)
	key := proto.CreateSocketTableKey(false, laddr, lport, raddr, rport)
	// 2
	_, found := proto.SocketTableLookup(key)
	if found {
		goto retry
	}
	proto.AddSocketToTable(key, tcb)
	// 3
	tcb.State = socket.SYN_SENT
	tcb.ISS = iss
	tcb.SND_UNA = iss
	tcb.SND_NXT = iss + 1
	// 4
	for i := 0; i < MAX_RETRANS; i++ {
		suc := _activeHandShake(tcb)
		if suc {
			// SYN was ACK'ed
			// Dispatch this socket
			go _doSocket(tcb)
			// Return the conn
			return &VTCPConn{
				TCB: tcb,
			}, nil
		}
	}

    // Remove TCB
    proto.RemoveSocketFromTable(key)
	return &VTCPConn{}, errors.New("VConnect(): Destionation port does not exist")
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
