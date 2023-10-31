package socket_api

import (
	"netstack/pkg/proto"
	"netstack/pkg/socket"
	"netstack/pkg/util"
	"time"
)

const (
	// Retransmission
	MAX_RETRANS = 3
	RTO_LB      = 1
	MSL         = 5
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
					tcb.SendACKPacket(util.ACK)
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
				tcb.SND_UNA = SEG_ACK
				if tcb.SND_UNA <= tcb.ISS {
					// - Not ACK for our SYN
					continue
				}

				// SYN is ACKed -> ESTABLISHED
				tcb.State = socket.ESTABLISHED

				// Send ACK for SYN, ACK
				// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
				tcb.SendACKPacket(util.ACK)
				// Handshake is complete
				return true
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
					// CLOSED
					// - RETRANS EXPIRE
					// let the reaper reap
					tcb.ReapChan <- tcb.SID
					return
				}
				// First perform the Segment acceptability test
				if !tcb.IsSegmentValid(tcpPacket) {
					// If invalid send ACK in reply
					// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
					tcb.SendACKPacket(util.ACK)
					// and drop
					continue
				}

				// TODO: Make the segment "idealized segment"

				// * Check ACK

				// If ACK bit is off drop
				if tcpPacket.TCPHeader.Flags&util.ACK == 0 {
					continue
				}

				SEG_ACK := tcpPacket.TCPHeader.AckNum
				SEG_SEQ := tcpPacket.TCPHeader.SeqNum
				SEG_WND := tcpPacket.TCPHeader.WindowSize
				// SEG_LEN := len(tcpPacket.Payload)

				if SEG_ACK <= tcb.SND_UNA {
					// Duplicate ACK (ignore)
				} else if SEG_ACK > tcb.SND_NXT {
					// ACK for unsent stuff (ACK and drop)
					tcb.SendACKPacket(util.ACK)
					continue
				} else {
					// Update send window
					if tcb.SND_UNA <= SEG_ACK && SEG_ACK <= tcb.SND_NXT {
						if tcb.SND_WL1 < SEG_SEQ || (tcb.SND_WL1 == SEG_SEQ && tcb.SND_WL2 <= SEG_ACK) {
							tcb.SND_WND = uint32(SEG_WND)
							tcb.SND_WL1 = SEG_SEQ
							tcb.SND_WL2 = SEG_ACK
						}
					}
					// Update the SND.UNA
					tcb.SND_UNA = SEG_ACK
					// TODO: update retranmission queue

				}

				var FIN_ACK_FLAG = (tcb.SND_NXT == SEG_ACK)

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
						continue
					}
				}

				if tcb.State == socket.LAST_ACK {
					if FIN_ACK_FLAG {
						// ACK for our FIN
						tcb.FinOK <- true
						// LAST_ACK -> CLOSED
						tcb.State = socket.CLOSED
						// Delete TCB
						tcb.ReapChan <- tcb.SID
						return
					}
				}

				// Retransmission of the remote FIN
				if tcb.State == socket.TIME_WAIT {
					// ACK it
					tcb.SendACKPacket(util.ACK)
					// restart the timer
                    tcb.TimeReset <- true
				}

				// TODO: Process Segment Data
				// ESTABLISHED, FIN_WAIT_1, and FIN_WAIT_2 can recv data

				switch tcb.State {
				case socket.ESTABLISHED:
					fallthrough
				case socket.FIN_WAIT_1:
					fallthrough
				case socket.FIN_WAIT_2:
					// if tcpPacket.TCPHeader.Flags&util.FIN!=0{
					//     SEG_LEN++
					// }
					// tcb.RCV_NXT += uint32(SEG_LEN)
					// tcb.SendACKPacket(util.ACK)
					// TODO: Adjust window
				default:
					// For other states ignore the segment
					break
				}

				// * Check FIN

				if tcpPacket.TCPHeader.Flags&util.FIN == 0 {
					// ACK for our FIN
					if FIN_ACK_FLAG && tcb.State == socket.FIN_WAIT_1 {
						tcb.State = socket.FIN_WAIT_2
					}
					continue
				}

				if tcb.State == socket.LISTEN || tcb.State == socket.CLOSED || tcb.State == socket.SYN_SENT {
					// SEG_SEQ cannot be validated -> drop the segment
					continue
				}

				// Advance by 1 (FIN)
				tcb.RCV_NXT = SEG_SEQ + 1
				// Send ACK
				tcb.SendACKPacket(util.ACK)

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
			}
		}
	}
}

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
