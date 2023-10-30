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

	DEFAULT_DATAOFFSET = 20

	RTO_LB = 1
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
func _passiveHandshake(tcb *proto.TCB) bool {
	// Send SYN, ACK
	// <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.ISS, tcb.RCV_NXT, DEFAULT_DATAOFFSET, util.SYN|util.ACK, uint16(tcb.RCV_WND))
	tcpPacket := &proto.TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   []byte{},
	}
	tcb.SendChan <- tcpPacket
	time := time.NewTimer(RTO_LB * time.Second)
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
                    var flag = util.ACK
					// If invalid send ACK in reply
					// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
					hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT, tcb.RCV_NXT, DEFAULT_DATAOFFSET, uint8(flag), uint16(tcb.RCV_WND))
					tcpPacket := &proto.TCPPacket{
						LAddr:     tcb.Laddr,
						RAddr:     tcb.Raddr,
						TCPHeader: hdr,
						Payload:   []byte{},
					}
					tcb.SendChan <- tcpPacket
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

				// Update state
				tcb.State = socket.ESTABLISHED

				// Set the connection state variables
				tcb.SND_WND = uint32(reply.TCPHeader.WindowSize)
				tcb.SND_WL1 = reply.TCPHeader.SeqNum
				tcb.SND_WL2 = reply.TCPHeader.AckNum

				return true
				// TODO: Check if the FIN bit is set
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
func _activeHandShake(tcb *proto.TCB) bool {
	// Send SYN
	// <SEQ=ISS><CTL=SYN>
	hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.ISS, 0, DEFAULT_DATAOFFSET, util.SYN, uint16(tcb.RCV_WND))
	tcpPacket := &proto.TCPPacket{
		LAddr:     tcb.Laddr,
		RAddr:     tcb.Raddr,
		TCPHeader: hdr,
		Payload:   []byte{},
	}
	tcb.SendChan <- tcpPacket
	time := time.NewTimer(RTO_LB * time.Second)
	for {
		select {
		case <-time.C:
			{
				// Timeout, abort
				return false
			}
		case reply := <-tcb.ReceiveChan:
			{
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
				hdr = util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT, tcb.RCV_NXT, DEFAULT_DATAOFFSET, util.ACK, uint16(tcb.RCV_WND))
				tcpPacket := &proto.TCPPacket{
					LAddr:     tcb.Laddr,
					RAddr:     tcb.Raddr,
					TCPHeader: hdr,
					Payload:   []byte{},
				}
				// Send the packet out
				tcb.SendChan <- tcpPacket
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
		case tcpPacket := <-tcb.ReceiveChan:
			{
                // First perform the Segment acceptability test
				if !tcb.IsSegmentValid(tcpPacket) {
					// If invalid send ACK in reply
					// <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
					hdr := util.CreateTCPHeader(tcb.Lport, tcb.Rport, tcb.SND_NXT, tcb.RCV_NXT, DEFAULT_DATAOFFSET, util.ACK, uint16(tcb.RCV_WND))
					tcpPacket := &proto.TCPPacket{
						LAddr:     tcb.Laddr,
						RAddr:     tcb.Raddr,
						TCPHeader: hdr,
						Payload:   []byte{},
					}
					tcb.SendChan <- tcpPacket
					continue
				}
			}
		}
	}
}
