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
            li.TCB.ReapChan <- li.TCB.SID
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
		for i := 1; i < MAX_RETRANS+1; i++ {
			suc := _passiveHandshake(newTCB, i)
			if suc {
				// Connection is established!
				li.InfoChan <- fmt.Sprintf("New connection on SID=%d => Created new socket with SID=%d", li.TCB.SID, newTCB.SID)
				// 5
				go _doSocket(newTCB)
				break
			}
			if i == MAX_RETRANS {
				// If failed, remove the TCB
				newTCB.ReapChan <- newTCB.SID
			}
		}
	}
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
	for i := 1; i < MAX_RETRANS+1; i++ {
		suc := _activeHandShake(tcb, i)
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
	tcb.ReapChan <- tcb.SID
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
func VClose(tcb *proto.TCB) error {

    // LISTEN STATE
    if tcb.State == socket.LISTEN {
        close(tcb.ReceiveChan)
        return nil
    }

	// SYN-SENT STATE
	// Delete the TCB and return "error: closing" responses to any queued SENDs, or RECEIVEs.
	// Currently, no way to test this as "c" command hangs
	if tcb.State == socket.SYN_SENT {
		// Close the Receive channel to signal CLOSE
		close(tcb.ReceiveChan)
		return nil
	}

	// SYN-RECEIVED STATE

	// If no SENDs have been issued and there is no pending data to send, then form a FIN segment and send it, and enter FIN-WAIT-1 state; otherwise, queue for processing after entering ESTABLISHED state.
	if tcb.State == socket.SYN_RECEIVED {
		// TODO: check
		go _doActiveClose(tcb)
		return nil
	}

	// ESTABLISHED STATE

	// Queue this until all preceding SENDs have been segmentized, then form a FIN segment and send it. In any case, enter FIN-WAIT-1 state.
	if tcb.State == socket.ESTABLISHED {
		// TODO: check
		go _doActiveClose(tcb)
		return nil
	}

	// CLOSE_WAIT
	if tcb.State == socket.CLOSE_WAIT {
		go _doActiveClose(tcb)
		return nil
	}

	// FIN_WAIT_1, FIN_WAIT_2, CLOSING, LAST_ACK, TIME_WAIT
	return errors.New("error: connection closing")
}
