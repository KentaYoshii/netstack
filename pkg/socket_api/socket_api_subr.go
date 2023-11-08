package socket_api

import (
	"fmt"
	"netstack/pkg/proto"
	"netstack/pkg/socket"
	"netstack/pkg/util"
	"time"
)

const (
	// Retransmission
	MAX_RETRANS  = 3
	RTO_LB       = 1
	MSL          = 5
	MAX_SEG_SIZE = 1400 - (util.HeaderLen - util.TcpHeaderLen)
)

// Function that handles a hadnshake for PASSIVE OPEN
// Specifically, send a SYN, ACK packet
// After sending SYN, ACK packet
// - Either timeouts and return false
// - Receive a packet
//   - Check if segment is acceptable or not
//   - Send ACK if not and drop the segment
//   - Check if ACK is set
//   - Drop if not
func _passiveHandshake(tcb *proto.TCB, i int) bool {
	// Send SYN, ACK
	// <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.ISS, tcb.RCV_NXT, proto.DEFAULT_DATAOFFSET, util.SYN|util.ACK, uint16(tcb.RCV_WND))
	tcpPacket := &proto.TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   []byte{},
	}
	tcb.SendChan <- tcpPacket
	// Expontential Backoff
	time := time.NewTimer(time.Duration((RTO_LB * i)) * time.Second)
	for {
		select {
		case <-time.C:
			{
				// Timeout, abort
				return false
			}
		case reply := <-tcb.ReceiveChan:
			{
				// If we see a SYN flag, return and send SYN, ACK
				if reply.TCPHeader.Flags&util.SYN != 0 {
					return false
				}

				// 3.10.7.4
				// First perform the Segment acceptability test
				if !tcb.IsSegmentValid(reply) {
					// If invalid send ACK in reply
					// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
					tcb.SendACKPacket(util.ACK, []byte{})
					continue
				}

				// Check if ACK is set
				if reply.TCPHeader.Flags&util.ACK == 0 {
					// not set
					continue
				}

				SEG_ACK := reply.TCPHeader.AckNum

				// Check if it is ACK for our SYN, ACK
				if !(tcb.SND_UNA < SEG_ACK && SEG_ACK <= tcb.SND_NXT) {
					// ACK not for our SYN, ACK packet
					continue
				}

				tcb.SND_UNA = SEG_ACK

				// Update state
				tcb.State = socket.ESTABLISHED

				// Set the connection state variables
				tcb.SND_WND = uint32(reply.TCPHeader.WindowSize)
				tcb.SND_WL1 = reply.TCPHeader.SeqNum
				tcb.SND_WL2 = reply.TCPHeader.AckNum

				return true
			}
		}

	}
}

// Function that handles a handshake for ACTIVE OPEN
// Specifically, send a single SYN packet.
// After sending SYN packet
// - Either timeouts and return false
// - Receive a packet and performs the following check
//   - Check if ACK bit and SYN bit is set
//   - If not, drop the segment
//   - Check if ACK falls in range
//   - If not drop the segment
//   - Update the connection variables
//   - Check SEG_ACK > ISS
//   - If not, not ACK for SYN
//   - SYN is ACK'ed
//   - Updatate state from SYN_SENT -> ESTABLISHED
//     Send ACK and return true
//
// - This function only errors when a user initiates the CLOSE
//   - This is a CLOSE on SYN_SENT state
func _activeHandShake(tcb *proto.TCB, i int) bool {
	// Send SYN
	// <SEQ=ISS><CTL=SYN>
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.ISS, 0, proto.DEFAULT_DATAOFFSET, util.SYN, uint16(tcb.RCV_WND))
	tcpPacket := &proto.TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   []byte{},
	}
	tcb.SendChan <- tcpPacket
	// Expontential Backoff
	time := time.NewTimer(time.Duration(RTO_LB*i) * time.Second)
	for {
		select {
		case <-time.C:
			{
				// Timeout, abort
				return false
			}
		case reply, more := <-tcb.ReceiveChan:
			{
				if !more {
					// CLOSE call
					tcb.ReapChan <- tcb.SID
					return false
				}
				// 3.10.7.3
				SEG_SEQ := reply.TCPHeader.SeqNum
				SEG_ACK := reply.TCPHeader.AckNum
				SEG_FLAG := reply.TCPHeader.Flags

				// We disregard RST for now
				// - So ACK and SYN bits MUST be set
				if SEG_FLAG&util.ACK == 0 || SEG_FLAG&util.SYN == 0 {
					continue
				}

				if !(tcb.SND_UNA < SEG_ACK && SEG_ACK <= tcb.SND_NXT) {
					// ACK is outside of valid range
					continue
				}

				// Set the connection state variables
				tcb.IRS = SEG_SEQ
				tcb.RCV_NXT = SEG_SEQ + 1
				tcb.LBR = SEG_SEQ
				tcb.SND_UNA = SEG_ACK
				if tcb.SND_UNA <= tcb.ISS {
					// - Not ACK for our SYN
					continue
				}

				// SYN is ACKed -> ESTABLISHED
				tcb.State = socket.ESTABLISHED

				// Set window variables
				tcb.SND_WND = uint32(tcpPacket.TCPHeader.WindowSize)
				tcb.SND_WL1 = SEG_SEQ
				tcb.SND_WL2 = SEG_ACK
				// Send ACK for SYN, ACK
				// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
				tcb.SendACKPacket(util.ACK, []byte{})
				// Handshake is complete
				return true
			}
		}
	}
}

func _doSend(tcb *proto.TCB, data []byte) {
	// First get the usable window
	U := tcb.GetUseableWND()
	D := uint32(len(data))
	for U < uint32(D) {
		// Block until we have space to send 1 MSS
		// Do it inside for-loop to be extra safe
		<-tcb.SendSignal
		U = tcb.GetUseableWND()
	}
	// We have space in the SND_WND to send the current data
	// Send the packet out
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT,
		tcb.RCV_NXT, proto.DEFAULT_DATAOFFSET, util.ACK,
		uint16(tcb.GetAdvertisedWND()))
	tcpPacket := &proto.TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   data,
	}
	// Construct Segment in case of retransmission
	seg := &proto.Segment{
		Packet: tcpPacket,
		ACKed:  make(chan bool, 1),
		RTT:    0.2, // TODO: hardcode for now
	}
	tcb.RetransmissionQ = append(tcb.RetransmissionQ, seg)

	tcb.SendChan <- tcpPacket
	// Update SND_NXT
	tcb.SND_NXT += D
	// Start the retransmissoin clock
	go _monitorSegment(tcb, seg)
}

// Function that keeps retransmitting segment "seg" until
// we get a signal that this segment is completely ACK'ed
func _monitorSegment(tcb *proto.TCB, seg *proto.Segment) {
	for {
		dur, _ := time.ParseDuration(fmt.Sprintf("%fs", seg.RTT))
		currRTO := time.NewTimer(dur)
		select {
		case <-currRTO.C:
			{
				// RTO -> Retransmit
				seg.Mu.Lock()
				fmt.Println("RETRANSMIT")
				tcb.SendChan <- seg.Packet
				seg.Mu.Unlock()
			}
		case <-seg.ACKed:
			{
				return
			}
		}
	}
}

// Function that do things socket is meant to do
// When entering this state, socket is in ESTABLISHED state
func _doSocket(tcb *proto.TCB) {
	for {
		select {
		case tcpPacket, more := <-tcb.ReceiveChan:
			{
				if !more {
					// RETRANS EXPIRE
					tcb.ReapChan <- tcb.SID
					return
				}

				// ---- SEGMENT TEST ----
				if !tcb.IsSegmentValid(tcpPacket) {
					tcb.SendACKPacket(util.ACK, []byte{})
					continue
				}

				SEG_SEQ := tcpPacket.TCPHeader.SeqNum
				SEG_ACK := tcpPacket.TCPHeader.AckNum
				SEG_LEN := uint32(len(tcpPacket.Payload))
				SEG_DATA := tcpPacket.Payload
				SEG_FLAG := tcpPacket.TCPHeader.Flags

				// ---- Early Arrivals Check ----
				if SEG_SEQ > tcb.RCV_NXT {
					fmt.Println("Early Arrival Packet, SEG_SEQ=", SEG_SEQ, "RCV_NXT=", tcb.RCV_NXT)
					tcb.InsertEAQ(tcpPacket)
					tcb.SendACKPacket(util.ACK, []byte{})
					continue
				}

				// ---- DATA Trimming ----
				if SEG_LEN != 0 {
					SEG_DATA, SEG_LEN = tcb.TrimSegment(tcpPacket)
				}

				// ---- MERGE EA (if possible) ----
				if len(tcb.EarlyArrivals) != 0 {
					SEG_DATA, SEG_LEN = tcb.MergeEAQ(tcb.RCV_NXT+SEG_LEN-1, SEG_DATA)
				}

				// ---- ACK ----
				proceed, forceQuit := _handleAckSeg(tcb, tcpPacket)
				if forceQuit {
					return
				}
				if !proceed {
					continue
				}

				// ---- DATA ----
				if SEG_LEN != 0 {
					_handleTextSeg(tcb, SEG_DATA, SEG_LEN)
				}

				// ---- FIN ----
				if SEG_FLAG&util.FIN != 0 {
					_handleFinSeg(tcb, tcpPacket)
				} else {
					// ACK for our FIN
					if (tcb.SND_NXT == SEG_ACK) &&
						tcb.State == socket.FIN_WAIT_1 {
						tcb.State = socket.FIN_WAIT_2
					}
				}
			}
		}
	}
}

// Handle Segment Data
// Here we know that whatever in SEG_DATA, we can receive them in full
// Additionally, segment should be "idealized segment"
// RCV.NXT == SEG_SEQ && SEG_LEN < RCV_WND_SZ
func _handleTextSeg(tcb *proto.TCB, data []byte, len uint32) {
	switch tcb.State {
	case socket.ESTABLISHED:
		fallthrough
	case socket.FIN_WAIT_1:
		fallthrough
	case socket.FIN_WAIT_2:
		// Put the data
		tcb.RecvBuffer.Put(data)
		// Increment RCV_NXT over the received data
		tcb.RCV_NXT += len
		// Send ACK for everything up until here
		tcb.SendACKPacket(util.ACK, []byte{})
		// Signal the reader
		tcb.DataSignal <- true
	default:
		// For other states ignore the segment
		break
	}
}

// Handle FIN segment
// Return false if dropping this segment
func _handleFinSeg(tcb *proto.TCB, tcpPacket *proto.TCPPacket) bool {

	SEG_ACK := tcpPacket.TCPHeader.AckNum

	var FIN_ACK_FLAG = (tcb.SND_NXT == SEG_ACK)

	if tcb.State == socket.LISTEN ||
		tcb.State == socket.CLOSED ||
		tcb.State == socket.SYN_SENT {
		// SEG_SEQ cannot be validated -> drop the segment
		return false
	}

	// Advance by 1 (FIN)
	tcb.RCV_NXT += 1
	// Send ACK
	tcb.SendACKPacket(util.ACK, []byte{})

	switch tcb.State {
	case socket.SYN_RECEIVED:
		fallthrough
	case socket.ESTABLISHED:
		tcb.State = socket.CLOSE_WAIT
		break
	case socket.FIN_WAIT_1:
		if FIN_ACK_FLAG {
			tcb.State = socket.TIME_WAIT
			// Start the timer
			go _doTimeWait(tcb)
		} else {
			tcb.State = socket.CLOSING
		}
		break
	case socket.FIN_WAIT_2:
		tcb.State = socket.TIME_WAIT
		// Start the timer
		go _doTimeWait(tcb)
	case socket.TIME_WAIT:
		// Restart the timer
		tcb.TimeReset <- true
	default:
		// Other states stay the same
		break
	}
	return true
}

// Handle ACK segment
// Return false if dropping this segment
// Return true in the second argument if socket closed
func _handleAckSeg(tcb *proto.TCB, tcpPacket *proto.TCPPacket) (bool, bool) {

	if tcpPacket.TCPHeader.Flags&util.ACK == 0 {
		return false, false
	}

	SEG_ACK := tcpPacket.TCPHeader.AckNum
	SEG_SEQ := tcpPacket.TCPHeader.SeqNum
	SEG_WND := tcpPacket.TCPHeader.WindowSize
	SEG_LEN := uint32(len(tcpPacket.Payload))

	var FIN_ACK_FLAG = (tcb.SND_NXT == SEG_ACK)

	if tcb.SND_UNA < SEG_ACK && SEG_ACK <= tcb.SND_NXT {
		// Update the SND.UNA
		tcb.SND_UNA = SEG_ACK
		// Signal the update to the manager
		tcb.ACKSignal <- true
	} else if tcb.SND_UNA >= SEG_ACK {
		// check for duplicate ACK
		// - three conds
		//   - SND_UNA == SEG_ACK ()
		//   - SEG_LEN == 0 (no data)
		//   - SND_UNA != SND_NXT (unacked data)
		if (tcb.SND_UNA == SEG_ACK) &&
			(SEG_LEN == 0) &&
			(tcb.SND_UNA != tcb.SND_NXT) {
			fmt.Println("Duplicate ACK", "SEG_ACK=", SEG_ACK)
		}
	} else if SEG_ACK > tcb.SND_NXT {
		// ACK for unsent stuff (ACK and drop)
		tcb.SendACKPacket(util.ACK, []byte{})
		fmt.Println("Unseen ACK", "SEG_ACK=", SEG_ACK, "SND_NXT=", tcb.SND_NXT)
		return false, false
	}

	// Update send window
	if tcb.SND_UNA <= SEG_ACK && SEG_ACK <= tcb.SND_NXT {
		if tcb.SND_WL1 < SEG_SEQ || (tcb.SND_WL1 == SEG_SEQ && tcb.SND_WL2 <= SEG_ACK) {
			tcb.SND_WL1 = SEG_SEQ
			tcb.SND_WL2 = SEG_ACK
		}
		// Update the SND_WND
		tcb.SND_WND = uint32(SEG_WND)
		// Signal the window change
		tcb.SendSignal <- true
	}

	// If we are FIN_WAIT_1 check if this ACK is for FIN
	if tcb.State == socket.FIN_WAIT_1 {
		if FIN_ACK_FLAG {
			// ACK for our FIN
			tcb.FinOK <- true
		}
	}

	// If we are CLOSING check if this ACK is for FIN
	if tcb.State == socket.CLOSING {
		if FIN_ACK_FLAG {
			// ACK for our FIN
			tcb.State = socket.TIME_WAIT
		} else {
			// O.W. ignore
			return false, false
		}
	}

	// If we are LAST_ACK, we just close
	if tcb.State == socket.LAST_ACK {
		if FIN_ACK_FLAG {
			// ACK for our FIN
			tcb.FinOK <- true
			// LAST_ACK -> CLOSED
			tcb.State = socket.CLOSED
			// Delete TCB
			tcb.ReapChan <- tcb.SID
			return false, true
		}
	}

	// Retransmission of the remote FIN
	if tcb.State == socket.TIME_WAIT {
		// ACK it
		tcb.SendACKPacket(util.ACK, []byte{})
		// restart the timer
		tcb.TimeReset <- true
	}

	return true, false
}

// Function that TIME_WAIT socket will be in
// Once the timer goes off, close the receive chan
// If you get reset signal, reset the timer
func _doTimeWait(tcb *proto.TCB) {
reset:
	timer := time.NewTimer(2 * MSL * time.Second)
	for {
		select {
		case <-timer.C:
			{
				// Time is up! Close the chan
				close(tcb.ReceiveChan)
				return
			}
		case <-tcb.TimeReset:
			{
				goto reset
			}
		}
	}
}

// Active Close
// Send a FIN packet to other side to let them know that
// you are done sending data and ready to close the connection
func _doActiveClose(tcb *proto.TCB) {
	i := 1
	if tcb.State == socket.CLOSE_WAIT {
		// The other side initiated the CLOSE
		tcb.State = socket.LAST_ACK
	} else {
		// We initiate the CLOSE
		tcb.State = socket.FIN_WAIT_1
	}
	FIN_SEQ := tcb.SND_NXT
sendFIN:
	// Send FIN
	// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK,FIN>
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, FIN_SEQ, tcb.RCV_NXT, proto.DEFAULT_DATAOFFSET, util.FIN|util.ACK, uint16(tcb.RCV_WND))
	tcpPacket := &proto.TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   []byte{},
	}
	tcb.SendChan <- tcpPacket
	tcb.SND_NXT = FIN_SEQ + 1
	// Expontential Backoff
	time := time.NewTimer(time.Duration(RTO_LB*i) * time.Second)
	for {
		select {
		case <-time.C:
			{
				if i == MAX_RETRANS {
					// RETRIES EXPIRE -> CLOSE
					close(tcb.ReceiveChan)
					return
				}
				i++
				goto sendFIN
			}
		case <-tcb.FinOK:
			{
				// FIN, ACK was ACK'ed
				return
			}
		}
	}
}
