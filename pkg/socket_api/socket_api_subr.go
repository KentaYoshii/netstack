package socket_api

import (
	"fmt"
	"io"
	"log/slog"
	"netstack/pkg/proto"
	"netstack/pkg/socket"
	"netstack/pkg/util"
	"os"
	"time"
)

const (
	// Retransmission
	MAX_RETRANS  = 3
	RTO_LB       = 1
	MSL          = 5
	MAX_SEG_SIZE = 1400 - 20 - 20
	ZWP_TO       = 100
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
				// Send ACK for SYN, ACK
				// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
				tcb.SendACKPacket(util.ACK, []byte{})
				// Handshake is complete
				return true
			}
		}
	}
}

// Function that sends out data in the send buffer
// Blocks if there is no data to send out
func monitorSendBuffer(tcb *proto.TCB) {
	for {
		// While there is nothing to send out, go to sleep
		d := <-tcb.SBufDataSignal
		// Then check if we have space in snd wnd
		U := tcb.GetNumBytesInSNDWND()
		for U < d.NumB {
			// Sleep until we are signalled that some of the in-flight
			// bytes have been ACK'ed
			<-tcb.ACKSignal
			U = tcb.GetNumBytesInSNDWND()
		}
		buf := make([]byte, d.NumB)
		// Get the bytes
		tcb.SendBuffer.Get(buf)
		// Send the packet out
		tcpPacket := tcb.SendACKPacket(d.Flag, buf)
		// Update SND_NXT
		tcb.SND_NXT += d.NumB

		if d.Flag&util.FIN != 0 {
			// If it is FIN then advance one more
			tcb.SND_NXT = tcb.SND_NXT + 1
		}

		// Add to RQ and start the retransmissoin clock
		// - RTT sample can only be taken for normal packet
		tcb.RQMu.Lock()
		tcb.RetransmissionQ = append(tcb.RetransmissionQ, &proto.RQSegment{
			Packet:       tcpPacket,
			SentAt:       time.Now(),
			IsRetransmit: false,
		})
		tcb.RQMu.Unlock()
		if !tcb.RTOStatus {
			// If timer is not running, start
			tcb.StartRTO()
		}
	}
}

// Function that puts data to buffer
// Blocks until send buffer has space
func _doSend(tcb *proto.TCB, data []byte) {
	// First get the usable space in the send buffer
	U := tcb.GetNumFreeBytesInSNDBUF()
	D := uint32(len(data))
	for U < uint32(D) {
		// Block until we have space to put 1 MSS in the send buf
		// Do it inside for-loop to be extra safe
		<-tcb.SBufPutSignal
		U = tcb.GetNumFreeBytesInSNDBUF()
	}
	// We have space in the send buffer to put current data
	tcb.SendBuffer.Put(data)
	// Update LBW
	tcb.LBW += D
	// Signal the monitoror about the new data
	tcb.SBufDataSignal <- proto.SendBufData{
		NumB: D,
		Flag: util.ACK,
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
					SEG_DATA, SEG_LEN = tcb.MergeEAQ(tcb.RCV_NXT+SEG_LEN, SEG_DATA)
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
func _handleTextSeg(tcb *proto.TCB, data []byte, dlen uint32) {
	switch tcb.State {
	case socket.ESTABLISHED:
		fallthrough
	case socket.FIN_WAIT_1:
		fallthrough
	case socket.FIN_WAIT_2:
		// Put the data
		tcb.RecvBuffer.Put(data)
		// Increment RCV_NXT over the received data
		tcb.RCV_NXT += dlen
		// Send ACK for everything up until here
		tcb.SendACKPacket(util.ACK, []byte{})
		// Signal the reader
		tcb.RBufDataSignal <- true
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
	// FIN is considered data
	tcb.RBufDataSignal <- true
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
	SEG_WND := tcpPacket.TCPHeader.WindowSize
	SEG_LEN := uint32(len(tcpPacket.Payload))

	var FIN_ACK_FLAG = (tcb.SND_NXT == SEG_ACK)

	if tcb.SND_UNA < SEG_ACK && SEG_ACK <= tcb.SND_NXT {
		// Update the SND.UNA
		tcb.SND_UNA = SEG_ACK
		// (5.3) When an ACK is received that acknowledges
		// new data, restart the retransmission timer so
		// that it will expire after RTO seconds
		tcb.StartRTO()
		tcb.RTOStatus = true
		// Signal the update to the manager
		tcb.RQUpdateSignal <- true
		// Signal the new space in send wnd
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
			fmt.Println("Duplicate ACK", "SEG_ACK=", SEG_ACK-tcb.ISS)
		}
	} else if SEG_ACK > tcb.SND_NXT {
		// ACK for unsent stuff (ACK and drop)
		tcb.SendACKPacket(util.ACK, []byte{})
		fmt.Println("Unseen ACK", "SEG_ACK=", SEG_ACK-tcb.ISS, "SND_NXT=", tcb.SND_NXT-tcb.ISS)
		return false, false
	}

	// Update send window
	if tcb.SND_UNA <= SEG_ACK && SEG_ACK <= tcb.SND_NXT {
		// If window size is 0, we probe
		if SEG_WND == 0 && !tcb.ProbeStatus {
			tcb.ProbeStatus = true
			go _doZWP(tcb)
		}
		if SEG_WND != 0 && tcb.ProbeStatus {
			tcb.ProbeStatus = false
			tcb.ProbeStopSignal <- true
		}
		// Update the SND_WND
		prevWND := tcb.SND_WND
		tcb.SND_WND = uint32(SEG_WND)
		// Signal the window change
		if tcb.SND_WND != prevWND {
			tcb.SBufPutSignal <- true
		}
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

// Function that does zero window probing
func _doZWP(tcb *proto.TCB) {
	// Get 1 byte data segment

	// If Send Buffer is empty, then we can return
	if tcb.GetNumFreeBytesInSNDBUF() == proto.MAX_WND_SIZE {
		return
	}
	zwp_payload := [1]byte{}
	tcb.SendBuffer.Peek(zwp_payload)

	zwpTicker := time.NewTicker(time.Duration(int64(time.Millisecond) * ZWP_TO))
	for {
		select {
		case <-tcb.ProbeStopSignal:
			{
				return
			}
		case <-zwpTicker.C:
			{
				tcb.SendACKPacket(util.ACK, []byte{zwp_payload[0]})
			}
		}
	}
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
	if tcb.State == socket.CLOSE_WAIT {
		// The other side initiated the CLOSE
		tcb.State = socket.LAST_ACK
	} else {
		// We initiate the CLOSE
		tcb.State = socket.FIN_WAIT_1
	}
	// Send FIN
	tcb.SBufDataSignal <- proto.SendBufData{
		NumB: 0,
		Flag: util.ACK | util.FIN,
	}
}

// Function that sends a file given by "filepath"
func SendFile(tcb *proto.TCB, filepath string, l *slog.Logger) {
	// Get the handle
	f, err := os.Open(filepath)
	if err != nil {
		// File open fails
		l.Error(err.Error())
		err = VClose(tcb)
		if err != nil {
			// VClose fails
			l.Error(err.Error())
		}
	}
	defer f.Close()
	buf := make([]byte, proto.MAX_WND_SIZE)
	total := 0
	l.Info("File opened, start sending file")
	for {
		// Read
		bRead, err := f.Read(buf)
		if err == io.EOF {
			l.Info(fmt.Sprintf("Sent File! Wrote %d bytes", total))
			break
		}
		if err != nil {
			l.Error(err.Error())
			break
		}
		bWritten, err := VWrite(tcb, buf[:bRead])
		total += bWritten
		if err != nil {
			break
		}
	}
	// Close the connection to let the other side know we are done sending
	err = VClose(tcb)
	if err != nil {
		l.Error(err.Error())
	}
}

// Function that receives a file
func ReceiveFile(tcb *proto.TCB, dest string, l *slog.Logger) {
	// Get the handle
	f, err := os.Create(dest)
	if err != nil {
		// File open fails
		l.Error(err.Error())
		err = VClose(tcb)
		if err != nil {
			// VClose fails
			l.Error(err.Error())
		}
	}
	defer f.Close()
	buf := make([]byte, proto.MAX_WND_SIZE)
	total := 0
	for {
		// Receive
		readBytes, err := VRead(tcb, buf)
		total += readBytes
		if err != nil {
			if err.Error() == "error: connection closing" {
				l.Info(fmt.Sprintf("Received File! Read %d bytes", total))
				break
			} else {
				l.Error(err.Error())
				break
			}
		}
		// Write to file
		_, err = f.Write(buf[:readBytes])
		if err != nil {
			l.Error(err.Error())
			break
		}
	}
	// Close the connection
	err = VClose(tcb)
	if err != nil {
		l.Error(err.Error())
	}
}
