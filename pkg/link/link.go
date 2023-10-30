package link

import (
	"encoding/binary"
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
	InfoChan  chan string
	ARPChan   chan ARPEntry

	// For ARP
	// - to simulate, we kinda need these
	BroadCastAddrs []netip.AddrPort
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

// Statically add ARP entries
func (li *Link) AddARPEntry(ip netip.Addr, mac netip.AddrPort) {
	li.ARPTable[ip] = mac
}

// Add the neighbor to our broadcast list to be used in arp
func (li *Link) AddNeighbor(nMAC netip.AddrPort) {
	li.BroadCastAddrs = append(li.BroadCastAddrs, nMAC)
}

// Given one of the LOCAL destinatio IP address, use the ARP table to
// look up the corresponding MAC Address
// If no such entry is found for "dst", broadcast an ARP request
func (li *Link) arpLookup(dst netip.Addr) (netip.AddrPort, bool) {
	res, ok := li.ARPTable[dst]
	if !ok {
		// Broadcast
		err := li.broadcast(dst)
		if err != nil {
			// ARP failed
			li.ErrorChan <- err.Error()
			return res, ok
		}
		// Success
		return li.ARPTable[dst], true
	}
	return res, ok
}

// If ARP miss, broadcast to LAN
// Create an ARP Request frame, and for each known hosts in the LAN, send
// Timeout or return nil if valid ARP Reply is received
func (li *Link) broadcast(dst netip.Addr) error {
	// We wish to find the MAC Addr for "dst"
	// First set stuff up
	spa := li.IPAddr.As4()
	tpa := dst.As4()
	sha_addr_as_4 := li.ListenAddr.Addr().As4()
	sha_port_as_2 := util.PortAs2(li.ListenAddr.Port())
	sha := [6]byte{
		sha_addr_as_4[0],
		sha_addr_as_4[1],
		sha_addr_as_4[2],
		sha_addr_as_4[3],
		sha_port_as_2[0],
		sha_port_as_2[1],
	}
	// tha is ignored in arp request
	arpBytes, err := CreateARPFrame(sha, spa, [6]byte{0}, tpa, ARP_REQUEST)
	if err != nil {
		return err
	}
	// broadcast
	for _, host := range li.BroadCastAddrs {
		// Resolve Address and Send
		resolvedUDPAddr, _ := net.ResolveUDPAddr("udp4", host.String())
		li.ListenConn.WriteToUDP(arpBytes, resolvedUDPAddr)
	}
	// wait or timeout
	timer := time.NewTimer(ARP_TO * time.Second)
	for {
		select {
		case <-timer.C:
			{
				return errors.New("ARP broadcast timeout")
			}
		case ent := <-li.ARPChan:
			{
				// Add to Cache
				li.InfoChan <- "Adding (" + ent.IPAddress.String() + ", " + ent.MACAddress.String() + ") to ARP Cache"
				li.ARPTable[ent.IPAddress] = ent.MACAddress
				// Check if this is the desired one
				if ent.IPAddress == dst {
					return nil
				}
			}
		}
	}
}

// Given ARP Message bytes check if we need to do anything with it
func (li *Link) HandleARPMessage(b []byte) {
	ARPMessage := UnMarshalARPFrame(b)
	// Check if I am the target IP or not
	if netip.AddrFrom4(ARPMessage.TPA) != li.IPAddr {
		return
	}
	// IF ARP Request
	if ARPMessage.Operation == ARP_REQUEST {
		// First set stuff up
		spa := li.IPAddr.As4()
		tpa := ARPMessage.SPA
		sha_addr_as_4 := li.ListenAddr.Addr().As4()
		sha_port_as_2 := util.PortAs2(li.ListenAddr.Port())
		sha := [6]byte{
			sha_addr_as_4[0],
			sha_addr_as_4[1],
			sha_addr_as_4[2],
			sha_addr_as_4[3],
			sha_port_as_2[0],
			sha_port_as_2[1],
		}
		tha := ARPMessage.SHA
		arpBytes, err := CreateARPFrame(sha, spa, tha, tpa, ARP_REPLY)
		if err != nil {
			return
		}
		// Resolve Address
		targetAddr := netip.AddrFrom4([4]byte{tha[0], tha[1], tha[2], tha[3]})
		targetPort := binary.BigEndian.Uint16([]byte{tha[4], tha[5]})
		targetMACAddr := netip.AddrPortFrom(targetAddr, targetPort)
		resolvedUDPAddr, _ := net.ResolveUDPAddr("udp4", targetMACAddr.String())
		li.ListenConn.WriteToUDP(arpBytes, resolvedUDPAddr)
		// Add to our cache
		li.ARPTable[netip.AddrFrom4(tpa)] = targetMACAddr
	} else if ARPMessage.Operation == ARP_REPLY {
		// If ARP Reply, send to the channel
		targetIPAddr := netip.AddrFrom4(ARPMessage.SPA)
		// Resolve Address
		targetAddr := netip.AddrFrom4([4]byte{
			ARPMessage.SHA[0],
			ARPMessage.SHA[1],
			ARPMessage.SHA[2],
			ARPMessage.SHA[3]})
		targetPort := binary.BigEndian.Uint16([]byte{ARPMessage.SHA[4], ARPMessage.SHA[5]})
		targetMACAddr := netip.AddrPortFrom(targetAddr, targetPort)
		li.ARPChan <- ARPEntry{
			IPAddress:  targetIPAddr,
			MACAddress: targetMACAddr,
		}
	}
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
		buf := make([]byte, util.MTU)
		b, _, err := li.ListenConn.ReadFromUDP(buf)
		if err != nil {
			errorChan <- err.Error()
			continue
		}
		if !li.IsUp {
			// Don't recv
			continue
		}
		if len(buf) > util.MTU {
			// Exceed MAX
			errorChan <- "Packet Bytes Exceed MTU"
			continue
		}
		// Before we proceed, we check if the received bytes are arp message or not
		if IsThisARPPacket(buf) {
			li.HandleARPMessage(buf)
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
			Payload:  buf[header.Len:b],
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
