package link

import (
	"errors"
	"net"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/proto"
	"netstack/pkg/util"
	"time"
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

	// Chan
	ErrorChan chan string
}

// Function that initializes the Link by start listening at the assigned UDP address
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
	li.ARPTable[li.IPAddr] = li.ListenAddr
	return nil
}

// Given IP address and corresponding MAC address,
// add the pair to the ARP table
func (li *Link) AddNeighbor(nIP netip.Addr, nMAC netip.AddrPort) {
	li.ARPTable[nIP] = nMAC
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
	if !li.IsUp {
		return errors.New("Packet cannot be sent from downed " + li.InterfaceName)
	}
	// ARP look up
	dstMACAddr, found := li.arpLookup(dst)
	if !found {
		return errors.New("MAC Address resolution failed for IP: " + dst.String())
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
		if !li.IsUp {
			// Don't recv
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
			errorChan <- "Checksum is wrong! Dropping this packet!"
			continue
		}
		// Checksum ok so send the packet to the channel
		packetChan <- &packet.Packet{
			IPHeader: header,
			Payload:  buf[header.Len:],
		}
	}
}

// Given ICMP Type "icType", Type code "icCode", and invalid packet "pac"
// Create and return an ICMP packet to be sent back to the source of the
// invalid IP packet
func (li *Link) CreateICMPPacketTo(icType uint8, icCode uint8, pac *packet.Packet) (*packet.Packet, error) {
	icmpPacket, err := proto.CreateICMPPacketFrom(pac, icType, icCode)
	if err != nil {
		return &packet.Packet{}, err
	}
	icmpBytes, err := icmpPacket.Marshal()
	if err != nil {
		return &packet.Packet{}, err
	}
	newPacket := packet.CreateNewPacket(icmpBytes, li.IPAddr, pac.IPHeader.Src, util.ICMP_PROTO, util.DEFAULT_TTL)
	return newPacket, nil
}

// Function to send a request for routes message to the "neighbor"
func (li *Link) RequestRouteFrom(neighbor netip.Addr) {
	// Create the Payload for RIP Request Message
	payload, err := proto.CreateRIPRequestPayload()
	if err != nil {
		li.ErrorChan <- err.Error()
		return
	}
	// Create the packet
	packet := packet.CreateNewPacket(payload, li.IPAddr, neighbor, util.RIP_PROTO, util.DEFAULT_TTL)
	// Send to the neighbor router
	err = li.SendLocal(packet, neighbor, false)
	if err != nil {
		li.ErrorChan <- err.Error()
		return
	}
}

// Function that handles a single trigger update to a neighbor "neighbor"
func (li *Link) TriggerUpdateTo(neighbor netip.Addr, newEntry proto.NextHop) {
	temp := make([]proto.NextHop, 0)
	temp = append(temp, newEntry)
	// Apply Poison Reverse
	ripEntries, err := proto.PoisonReverse(temp, neighbor)
	if err != nil {
		li.ErrorChan <- err.Error()
		return
	}
	// Marshal
	entBytes, err := proto.MarshalRIPEntries(ripEntries)
	if err != nil {
		li.ErrorChan <- err.Error()
		return
	}
	// Create the rip packet
	ripBytes, err := proto.CreateRIPPacketPayload(entBytes)
	if err != nil {
		li.ErrorChan <- err.Error()
		return
	}
	packet := packet.CreateNewPacket(ripBytes, li.IPAddr, neighbor, util.RIP_PROTO, util.DEFAULT_TTL)
	// Send to the neighbor router
	err = li.SendLocal(packet, neighbor, false)
	if err != nil {
		li.ErrorChan <- err.Error()
		return
	}
}

// Function that periodically updates the neighbor with its routes every 5 seconds
// If trigger update, then send the new entry
func (li *Link) SendUpdatesTo(neighbor netip.Addr, triggerChan chan proto.NextHop) {

	ticker := time.NewTicker(proto.PERIODIC_TO * time.Second)

	for {
		select {
		case <-ticker.C:
			{
				// Get Current Entries
				nextHopEntries := proto.GetAllEntries()
				// Apply Poison Reverse
				ripEntries, err := proto.PoisonReverse(nextHopEntries, neighbor)
				if err != nil {
					li.ErrorChan <- err.Error()
					continue
				}
				// Marshal
				entBytes, err := proto.MarshalRIPEntries(ripEntries)
				if err != nil {
					li.ErrorChan <- err.Error()
					continue
				}
				// Create the rip packet
				ripBytes, err := proto.CreateRIPPacketPayload(entBytes)
				if err != nil {
					li.ErrorChan <- err.Error()
					continue
				}
				packet := packet.CreateNewPacket(ripBytes, li.IPAddr, neighbor, util.RIP_PROTO, util.DEFAULT_TTL)
				// Send to the neighbor router
				err = li.SendLocal(packet, neighbor, false)
				if err != nil {
					li.ErrorChan <- err.Error()
					continue
				}
			}
		case update := <-triggerChan:
			{
				// Trigger Update!
				li.TriggerUpdateTo(neighbor, update)
			}
		}
	}
}
