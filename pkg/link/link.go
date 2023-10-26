package link

import (
	"errors"
	"net"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/util"
)

type Link struct {
	// IP Address of this link
	IPAddr netip.Addr
	// UDP Address of this link
	ListenAddr netip.AddrPort
	// ARP Table
	ARPTable map[netip.Addr]netip.AddrPort
	// Listening Conn of this interface
	ListenConn *net.UDPConn
	// Name of this interface
	InterfaceName string
	// Status
	IsUp bool
	// Subnet Prefix that it is connected to
	Subnet netip.Prefix
}

func (li *Link) InitializeLink() error {
	udpAddr, err := net.ResolveUDPAddr("udp4", li.ListenAddr.String())
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return err
	}
	li.ListenConn = conn
	return nil
}

// Given one of the LOCAL destinatio IP address, use the ARP table to
// look up the corresponding MAC Address
func (li *Link) arpLookup(dst netip.Addr) (netip.AddrPort, bool) {
	res, ok := li.ARPTable[dst]
	return res, ok
}

// Given payload, destination IP address and IP Header, send the packet to the
// MAC Address corresponding to the passed in IP Address
func (li *Link) SendLocal(packet *packet.Packet, dst netip.Addr, f bool) error {
	// Check the state of the link
	if !li.IsUp {
		return errors.New("link is down\n")
	}
	// ARP look up
	dstMACAddr, found := li.arpLookup(dst)
	if !found {
		return errors.New("mac address not found\n")
	}
	// Decrement the Time To Live (SHOULD NOT reach 0) if for forward
	if f {
		packet.IPHeader.TTL -= 1
	}
	// Recompute Checksum
	packet.IPHeader.Checksum = 0
	headerBytes, err := packet.IPHeader.Marshal()
	if err != nil {
		return err
	}
	newCheckSum := util.ComputeChecksum(headerBytes)
	packet.IPHeader.Checksum = int(newCheckSum)

	// Resolve Address and Send
	resolvedUDPAddr, _ := net.ResolveUDPAddr("udp4", dstMACAddr.String())
	li.ListenConn.WriteToUDP(packet.Marshal(), resolvedUDPAddr)
	return nil
}

// Function that keeps reading from an interface for IP packets
// For each packet
// - Parse the header, check checksum, and, if everything looks good, send to ipstack
// At any point during the processing of incoming packet, an error occurred,
// simply drop the packet
func (li *Link) ListenAtInterface(packetChan chan *packet.Packet, errorChan chan string) {
	for {
		buf := make([]byte, util.MAX_PACKET_SIZE)
		_, _, err := li.ListenConn.ReadFromUDP(buf)
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
			Payload:  buf[header.Len:],
		}
	}
}
