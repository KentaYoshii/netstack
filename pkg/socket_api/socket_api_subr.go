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
	ZWP_TO       = 200
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
		// Wait for the signal
		d := <-tcb.SBufDataSignal
		// Get the unsent bytes
		bytesToSend := tcb.GetNumBytesInSNDBUF()
		// While we have bytes to send out or FIN bit is set
		for bytesToSend > 0 || (d.Flag&util.FIN) != 0 {
			// Then check if we have space in snd wnd
			sndWNDSZ := tcb.GetNumBytesInSNDWND()
			tcb.ACKCond.L.Lock()
			for sndWNDSZ == 0 {
				// Sleep until we are signalled that some of the in-flight
				// bytes have been ACK'ed
				tcb.ACKCond.Wait()
				sndWNDSZ = tcb.GetNumBytesInSNDWND()
			}
			tcb.ACKCond.L.Unlock()
			// We can send the entire bytesToSend or whatever we can fit into send window
			can_send := min(bytesToSend, sndWNDSZ, MAX_SEG_SIZE)
			fmt.Println(fmt.Sprintf("Sending %d bytes starting at %d! SND_WND is %d", can_send, tcb.SND_NXT-tcb.ISS, sndWNDSZ))
			buf := make([]byte, can_send)
			// Get the bytes
			tcb.SendBuffer.Get(buf)
			// Send the packet out
			tcpPacket := tcb.SendACKPacket(d.Flag, buf)
			// Update SND_NXT
			tcb.SND_NXT += can_send
			bytesToSend -= can_send

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

			if d.Flag&util.FIN != 0 {
				break
			}
		}
	}
}

// Funciton that manages the retransmission queue
func _doManageRQ(tcb *proto.TCB) {
	for {
		tcb.RBufDataCond.L.Lock()
		tcb.RBufDataCond.Wait()
		// Some of our in-flight bytes have been ACK'ed
		updateTime := time.Now()
		trimPos := 0
		found := false
		tcb.RQMu.Lock()
		for i := 0; i < len(tcb.RetransmissionQ); i++ {
			currSeg := tcb.RetransmissionQ[i]
			currPacket := currSeg.Packet
			currEND := currPacket.TCPHeader.SeqNum + uint32(len(currPacket.Payload)) - 1
			if tcb.SND_UNA > currEND {
				// Segment Fully ACK'ed

				// Segment is normal (not retransmission
				// that is a valid RTT sample
				if !currSeg.IsRetransmit {
					// compute and update RTT
					diff := float64(updateTime.Sub(currSeg.SentAt).Milliseconds())
					tcb.ComputeRTT(tcb.First, diff)
				}
				continue
			} else {
				// First Segment that is not fully ACK'ed yet
				trimPos = i
				found = true
				break
			}
		}
		if !found {
			// (5.2) When all outstanding data has been ACK'ed
			// stop the timer
			tcb.RetransmissionQ = make([]*proto.RQSegment, 0)
			tcb.RQTicker.Stop()
		} else {
			// Trim the queue
			// Remove all segments up until trimPos
			tcb.RetransmissionQ = tcb.RetransmissionQ[trimPos:]
			// (5.3) When an ACK is received that acknowledges new data, restart
			// the RTO
			tcb.StartRTO()
		}
		tcb.RQMu.Unlock()
		tcb.RBufDataCond.L.Unlock()
	}
}

// Function that keeps retransmitting the oldest packet
func _doRetransmit(tcb *proto.TCB) {
	for range tcb.RQTicker.C {
		if len(tcb.RetransmissionQ) == 0 {
			continue
		}
		// (RFC 6298)
		// (5.4) Retransmit the oldest unACK'ed segment
		tcb.RQMu.Lock()
		tcb.RetransmissionQ[0].IsRetransmit = true
		tcb.RetransmissionQ[0].Packet.TCPHeader.WindowSize = uint16(tcb.GetAdvertisedWND())
		tcb.RetransmissionQ[0].Packet.TCPHeader.AckNum = tcb.RCV_NXT
		tcb.RetransmissionQ[0].Packet.TCPHeader.Checksum = 0
		fmt.Println("Retransmitting SEG_SEQ=", tcb.RetransmissionQ[0].Packet.TCPHeader.SeqNum-tcb.ISS, "UNA=", tcb.SND_UNA-tcb.ISS, "RTO=", tcb.RTO)
		tcb.SendChan <- tcb.RetransmissionQ[0].Packet
		tcb.RQMu.Unlock()
		// (5.5) RTO <- 2 * RTO
		tcb.RTO = min(proto.MAX_RTO, 2*tcb.RTO)
		// (5.6) Restart the Retransmission Timer
		tcb.StartRTO()
	}
}

// Function that puts data to buffer
// Blocks until send buffer has space
func _doSend(tcb *proto.TCB, data []byte) {
	// First get the usable space in the send buffer
	U := tcb.GetNumFreeBytesInSNDBUF()
	remain := uint32(len(data))
	off := 0
	for remain > 0 {
		// While we have data to put
		tcb.SBufPutCond.L.Lock()
		for U == 0 {
			// Block until we have space to put in the send buf
			// Do it inside for-loop to be extra safe
			tcb.SBufPutCond.Wait()
			U = tcb.GetNumFreeBytesInSNDBUF()
		}
		tcb.SBufPutCond.L.Unlock()
		// We can put either everything that remains or up until the free space
		canPut := min(U, remain)
		// Put
		tcb.SendBuffer.Put(data[off : off+int(canPut)])
		// Update LBW
		tcb.LBW += canPut
		// Decrement D
		remain -= canPut
		// Update offset
		off += int(canPut)
		// Signal the monitoror about the new data
		tcb.SBufDataSignal <- proto.SendBufData{
			Flag: util.ACK,
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
	case socket.ESTABLISHED, socket.FIN_WAIT_1, socket.FIN_WAIT_2:
		// Put the data
		tcb.RecvBuffer.Put(data)
		// Increment RCV_NXT over the received data
		tcb.RCV_NXT += dlen
		// Send ACK for everything up until here
		tcb.SendACKPacket(util.ACK, []byte{})
		// Signal the reader
		tcb.RBufDataCond.Signal()
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
	tcb.RBufDataCond.Signal()
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

	// If we are currently ZWPing and
	if tcb.ProbeStatus && SEG_WND != 0 {
		if SEG_ACK == tcb.SND_NXT+1 {
			// If our probe byte is accepted
			tcb.SND_NXT = SEG_ACK
		}
		tcb.ProbeStopSignal <- true
		tcb.ProbeStatus = false
	}

	if tcb.SND_UNA < SEG_ACK && SEG_ACK <= tcb.SND_NXT {
		// Update the SND.UNA
		tcb.SND_UNA = SEG_ACK
		// (5.3) When an ACK is received that acknowledges
		// new data, restart the retransmission timer so
		// that it will expire after RTO seconds
		tcb.StartRTO()
		// Signal the update to the manager
		tcb.RQUpdateCond.Signal()
		// Signal the new space in send buffer
		tcb.SBufPutCond.Signal()
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
		prevWND := tcb.SND_WND
		tcb.SND_WND = uint32(SEG_WND)
		// If window size is 0, we probe
		if SEG_WND == 0 && !tcb.ProbeStatus {
			tcb.ProbeStatus = true
			go _doZWP(tcb)
			fmt.Println("Start ZWP")
		} else if prevWND != tcb.SND_WND {
			tcb.ACKCond.Signal()
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
	// If Send Buffer is empty, then we can return
	if tcb.GetNumFreeBytesInSNDBUF() == proto.MAX_WND_SIZE {
		return
	}

	// Else stop the RTO
	tcb.RQTicker.Stop()

	// Get 1 byte data segment
	zwp_payload := make([]byte, 1)
	zwp_seq := tcb.SND_NXT
	tcb.SendBuffer.Get(zwp_payload)
	// Create the zwp packet, reuse the same SEQ number

	// Constant Probe TO for now
	zwpTO := ZWP_TO
	zwpTicker := time.NewTicker(time.Duration(int(time.Millisecond) * zwpTO))
	for {
		select {
		case <-tcb.ProbeStopSignal:
			{
				// Restart the timer
				tcb.StartRTO()
				return
			}
		case <-zwpTicker.C:
			{
				hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, zwp_seq,
					tcb.RCV_NXT, proto.DEFAULT_DATAOFFSET, util.ACK,
					uint16(tcb.GetAdvertisedWND()))
				zwpPacket := &proto.TCPPacket{
					LAddr:     tcb.Laddr,
					RAddr:     tcb.Raddr,
					TCPHeader: hdr,
					Payload:   zwp_payload,
				}
				tcb.SendChan <- zwpPacket
				zwpTO = max(2*zwpTO, 3000)
				zwpTicker = time.NewTicker(time.Duration(int(time.Millisecond) * zwpTO))
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
