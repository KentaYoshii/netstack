package link

import (
	"net"
	"netstack/pkg/packet"
	"netstack/pkg/util"
)

// Function that keeps reading from an interface for IP packets
// For each packet
// - ...
// At any point during the processing of incoming packet, an error occurred,
// simply drop the packet
func ListenAtInterface(conn *net.UDPConn, packetChan chan *packet.Packet, errorChan chan string) { 
	for {
		buf := make([]byte, util.MAX_PACKET_SIZE)
		_, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			errorChan <- err.Error()
			continue
		}
		header, err := util.ParseHeader(buf)
		if err != nil {
			errorChan <- err.Error()
			continue
		}
		headerBytes := buf[:header.Len]
		// Compute the Checksum to make sure packet is in good shape
		originalCheckSum := uint16(header.Checksum)
		computedCheckSum := util.ValidateChecksum(headerBytes, originalCheckSum)
		if originalCheckSum != computedCheckSum {
			errorChan <- "Checksum is wrong! Dropping this packet!\n"
			continue
		}
		// Checksum ok so send the packet to the channel
		packetChan <- &packet.Packet{
			IPHeader: header,
			Payload: buf[header.Len:],
		}
	}
}