package ipstack

import (
	"bufio"
	"net/netip"
	"netstack/pkg/link"
	"netstack/pkg/lnxconfig"
	"netstack/pkg/packet"
	"netstack/pkg/proto"
	"netstack/pkg/util"
	"netstack/pkg/vrouter"
	"os"
	"time"
)

type NextHop struct {
	// VIPAddress of our next hop
	NextHopVIPAddr netip.Addr
	// Cost (infinity = 16)
	HopCost uint32
	// Type
	EntryType util.HopType
	// Interface name
	InterfaceName string
}

type ProtocolHandler func(*packet.Packet)

type IpStack struct {

	// Writer
	Writer *bufio.Writer

	// RIP enabled?
	RipEnabled bool

	// Maps

	// Map from Subnet IP address to InterfaceInfo Struct
	Subnets map[netip.Prefix]*link.Link
	// Map for protocol number to higher layer handler function
	ProtocolHandlerMap map[uint8]ProtocolHandler
	// Forwarding Table (map from Network Prefix to NextHop IP)
	ForwardingTable map[netip.Prefix]*NextHop
	// Interface name to Prefix Address
	NameToPrefix map[string]netip.Prefix

	// Channels

	// Channel through whicn interfaces send IP packets to network layer
	IpPacketChan chan *packet.Packet
	// Channel for getting non-serious error messages
	errorChan chan string
	// Debugging
	InfoChan chan string

	// ----- ROUTERS specific -----
	// Map from neighbor router ip address udp conn
	RIPTo map[netip.Addr]*vrouter.NeighborRouterInfo
}

// Create new IP stack
func CreateIPStack() *IpStack {
	return &IpStack{
		Writer:             bufio.NewWriter(os.Stdout),
		RipEnabled:         false,
		Subnets:            make(map[netip.Prefix]*link.Link),
		ProtocolHandlerMap: make(map[uint8]ProtocolHandler),
		ForwardingTable:    make(map[netip.Prefix]*NextHop),
		NameToPrefix:       make(map[string]netip.Prefix),
		IpPacketChan:       make(chan *packet.Packet, 100),
		errorChan:          make(chan string, 100),
		InfoChan:           make(chan string, 100),
	}
}

// Given "config", initialize the ip struct and link structs
func (ip *IpStack) Initialize(config *lnxconfig.IPConfig) {
	// ============== Interface ==============
	for _, i := range config.Interfaces {
		ip.NameToPrefix[i.Name] = i.AssignedPrefix
		ip.Subnets[i.AssignedPrefix] = &link.Link{
			IPAddr:        i.AssignedIP,
			ListenAddr:    i.UDPAddr,
			ARPTable:      make(map[netip.Addr]netip.AddrPort, 0),
			InterfaceName: i.Name,
			IsUp:          true,
			Subnet:        i.AssignedPrefix,
		}
	}
	// =============== ARP Table ===============
	for _, n := range config.Neighbors {
		for prefix, intf := range ip.Subnets {
			if prefix.Contains(n.DestAddr) {
				intf.ARPTable[n.DestAddr] = n.UDPAddr
			}
		}
	}

	// Initialize the interfaces and start listening
	ip.InitializeInterfaces()
	// Let the port binding complete
	time.Sleep(time.Millisecond * util.INITIAL_SETUP_TO)

	// ================== RIP ==================
	if config.RoutingMode == lnxconfig.RoutingTypeRIP {
		ip.RipEnabled = true
	} else {
		ip.RipEnabled = false
	}
	if ip.RipEnabled {
		ip.RIPTo = make(map[netip.Addr]*vrouter.NeighborRouterInfo)
		for _, subnet := range ip.Subnets {
			for _, neighbor := range config.RipNeighbors {
				if !subnet.Subnet.Contains(neighbor) {
					continue
				}
				ip.RIPTo[neighbor] = &vrouter.NeighborRouterInfo{
					// OutgoingVIP:   subnet.VirtualIPAddr,
					OutgoingConn:  subnet.ListenConn,
					RouterUDPAddr: subnet.ARPTable[neighbor],
				}
			}
		}
	}
	// ============ Forwarding Table ============
	// Static Routes (default gateway)
	for k, v := range config.StaticRoutes {
		for prefix, intf := range ip.Subnets {
			if !prefix.Contains(v) {
				continue
			}
			ip.ForwardingTable[k] = &NextHop{
				NextHopVIPAddr: v,
				EntryType:      util.HOP_STATIC,
				HopCost:        0,
				InterfaceName:  intf.InterfaceName,
			}
		}
	}
	// Local Interfaces
	for k, v := range ip.Subnets {
		ip.ForwardingTable[k] = &NextHop{
			NextHopVIPAddr: v.IPAddr,
			EntryType:     util.HOP_LOCAL,
			HopCost:       0,
			InterfaceName: v.InterfaceName,
		}
	}

	// =========== Protocol Handlers ============
	// TEST PROTOCOL
	ip.ProtocolHandlerMap[util.TEST_PROTO] = proto.HandleTestProtocol
	// RIP PROTOCOL
	if ip.RipEnabled {
		ip.ProtocolHandlerMap[util.RIP_PROTO] = proto.HandleRIPProtocol
	}
	// ICMP PROTOCOL
	ip.ProtocolHandlerMap[util.ICMP_PROTO] = proto.HandleICMProtocol

	// Start processing incoming packets
	go ip.ProcessPackets()

	// Request routing information
	if ip.RipEnabled {
		// if err := vrouter.RequestRoutingInfo(ip.RIPTo); err != nil {
		// 	ip.errorChan <- err.Error()
		// }
	}
}

// Register a handler
func (ip *IpStack) RegisterHandler(proto uint8, handler ProtocolHandler) {
	ip.ProtocolHandlerMap[proto] = handler
}

// For each interface we have, initialize and start listening
func (ip *IpStack) InitializeInterfaces() {
	for _, li := range ip.Subnets {
		err := li.InitializeLink()
		if err != nil {
			panic(err)
		}
		go li.ListenAtInterface(ip.IpPacketChan, ip.errorChan)
	}
}

// Loop through the channels and listen for incoming packets
func (ip *IpStack) ProcessPackets() {
	for {
		select {
		// Packets sent from the Link Layer
		case packet := <-ip.IpPacketChan:
			// Check if I am the intended destination
			if ip.IsThisMyPacket(packet.IPHeader.Dst) {
				ip.ProtocolHandlerMap[uint8(packet.IPHeader.Protocol)](packet)
				continue
			}
			// Check TTL. Drop if cannot forward
			if packet.IPHeader.TTL <= 1 {
				ip.errorChan <- "TTL reached 0!\n"
				continue
			}
			// Get the next hop
			nextHop, found := ip.GetNextHop(packet.IPHeader.Dst)
			if !found {
				ip.errorChan <- "NextHop not found!\n"
				continue
			}
			// Get the link to send out from
			link := ip.Subnets[ip.NameToPrefix[nextHop.InterfaceName]]
			var err error
			if nextHop.EntryType == util.HOP_LOCAL {
				// LOCAL delivery
				err = link.SendLocal(packet, packet.IPHeader.Dst, true)
			} else {
				// FORWARD
				err = link.SendLocal(packet, nextHop.NextHopVIPAddr, true)
			}
			if err != nil {
				ip.errorChan <- err.Error()
			}
		case errStr := <-ip.errorChan:
			ip.Writer.WriteString("\nERROR: " + errStr)
			ip.Writer.Flush()
		case info := <-ip.InfoChan:
			ip.Writer.WriteString("\nInfo: " + info)
			ip.Writer.Flush()
		}
	}
}

// Helper to check if this packet is destined to one of my interfaces
// if so, dst should match to one of our links' assigned IPAddr
func (ip *IpStack) IsThisMyPacket(dst netip.Addr) bool {
	for _, i := range ip.Subnets {
		if dst.Compare(i.IPAddr) == 0 {
			return true
		}
	}
	return false
}

// Given a destination IP Address, consult the forwarding table to get next hop
// Performs a Longest Prefix Matching
func (ip *IpStack) GetNextHop(dst netip.Addr) (NextHop, bool) {
	// Check Forwarding Table
	longest := -1
	var niHop NextHop
	for prefix, nihop := range ip.ForwardingTable {
		if prefix.Contains(dst) {
			sharedBits := util.GetNumSharedPrefix(dst, prefix.Addr())
			if longest < sharedBits {
				longest = sharedBits
				niHop = *nihop
			}
		}
	}

	if longest == -1 {
		// Not found
		return NextHop{}, false
	}

	return niHop, true
}