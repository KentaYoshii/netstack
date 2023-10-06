package ipstack

import (
	"bufio"
	"net"
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
	// UDPAddress of our next hop
	NextHopUDPAddr netip.AddrPort
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

type InterfaceInfo struct {
	// VIP of the interface
	VirtualIPAddr netip.Addr
	// MAC of this interface
	MacAddr netip.AddrPort
	// Listening Conn of this interface
	ListenConn *net.UDPConn
	// Name of the interface
	InterfaceName string
	// Subnet
	Subnet netip.Prefix
	// State (up/down)
	IsUp bool
	// ARP Table
	ARPTable map[netip.Addr]netip.AddrPort
}

type IpStack struct {

	// Writer
	Writer *bufio.Writer

	// RIP enabled?
	RipEnabled bool

	// Maps

	// Map from Subnet IP address to InterfaceInfo Struct
	Subnets map[netip.Prefix]*InterfaceInfo
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
		Subnets:            make(map[netip.Prefix]*InterfaceInfo),
		ProtocolHandlerMap: make(map[uint8]ProtocolHandler),
		ForwardingTable:    make(map[netip.Prefix]*NextHop),
		NameToPrefix:       make(map[string]netip.Prefix),
		IpPacketChan:       make(chan *packet.Packet, 100),
		errorChan:          make(chan string, 100),
		InfoChan:           make(chan string, 100),
	}
}

// Given "config", initialize the ip struct
func (ip *IpStack) Initialize(config *lnxconfig.IPConfig) {
	// ============== Interface ==============
	for _, i := range config.Interfaces {
		ip.NameToPrefix[i.Name] = i.AssignedPrefix
		ip.Subnets[i.AssignedPrefix] = &InterfaceInfo{
			VirtualIPAddr: i.AssignedIP,
			MacAddr:       i.UDPAddr,
			InterfaceName: i.Name,
			Subnet:        i.AssignedPrefix,
			IsUp:          true,
			ARPTable:      make(map[netip.Addr]netip.AddrPort, 0),
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
					OutgoingVIP:   subnet.VirtualIPAddr,
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
				NextHopUDPAddr: intf.ARPTable[v],
				EntryType:      util.HOP_STATIC,
				HopCost:        0,
				InterfaceName:  intf.InterfaceName,
			}
		}
	}
	// Local Interfaces
	for k, v := range ip.Subnets {
		ip.ForwardingTable[k] = &NextHop{
			NextHopVIPAddr: v.VirtualIPAddr,
			NextHopUDPAddr: v.MacAddr,
			EntryType:      util.HOP_LOCAL,
			HopCost:        0,
			InterfaceName:  v.InterfaceName,
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

// For each interface, start listening at the UDP port
func (ip *IpStack) InitializeInterfaces() {
	for _, i := range ip.Subnets {
		udpAddr, err := net.ResolveUDPAddr("udp4", i.MacAddr.String())
		if err != nil {
			panic(err)
		}
		conn, err := net.ListenUDP("udp4", udpAddr)
		if err != nil {
			panic(err)
		}
		i.ListenConn = conn
		go link.ListenAtInterface(conn, ip.IpPacketChan, ip.errorChan)
	}
}

// Loop through the channels and listen for incoming packets
func (ip *IpStack) ProcessPackets() {
	for {
		select {
		case packet := <-ip.IpPacketChan:
			if ip.IsThisMyPacket(packet.IPHeader.Dst) {
				// Dst == one of our interfaces
				// - Invoke the handler
				ip.ProtocolHandlerMap[uint8(packet.IPHeader.Protocol)](packet)
				continue
			}
			nextHop, prefix := ip.GetNextHop(packet.IPHeader.Dst)
			nextUdpAddr := nextHop.NextHopUDPAddr
			nextUdpConn := ip.Subnets[ip.NameToPrefix[nextHop.InterfaceName]].ListenConn
			if _, ok := ip.Subnets[prefix]; ok {
				// If one of my subnets
				nextUdpAddr = ip.Subnets[prefix].ARPTable[packet.IPHeader.Dst]
			}
			ip.SendPacketTo(packet, nextUdpAddr, nextUdpConn, true)
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
func (ip *IpStack) IsThisMyPacket(dst netip.Addr) bool {
	for _, i := range ip.Subnets {
		if dst.Compare(i.VirtualIPAddr) == 0 {
			// This is for me
			return true
		}
	}
	return false
}

func (ip *IpStack) IsThisMySubnet(dst netip.Addr) (bool, string) {
	for prefix, i := range ip.Subnets {
		if prefix.Contains(dst) {
			return true, i.InterfaceName
		}
	}
	return false, ""
}

func (ip *IpStack) GetNextHop(dst netip.Addr) (NextHop, netip.Prefix) {
	// Check Forwarding Table
	longest := -1
	var niHop NextHop
	var rprefix netip.Prefix
	for prefix, nihop := range ip.ForwardingTable {
		if prefix.Contains(dst) {
			sharedBits := util.GetNumSharedPrefix(dst, prefix.Addr())
			if longest < sharedBits {
				longest = sharedBits
				niHop = *nihop
				rprefix = prefix
			}
		}
	}
	return niHop, rprefix
}

func (ip *IpStack) SendPacketTo(packet *packet.Packet, udpAddr netip.AddrPort, udpConn *net.UDPConn, forward bool) {
	var newTTL int = packet.IPHeader.TTL
	// First decrement the TTL
	if forward {
		newTTL := packet.IPHeader.TTL - 1
		if newTTL < 0 {
			ip.errorChan <- "TTL reached below 0. Dropping it!\n"
			return
		}
	}
	// Recompute Checksum for this packet
	packet.IPHeader.TTL = newTTL
	packet.IPHeader.Checksum = 0
	headerBytes, err := packet.IPHeader.Marshal()
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
	newCheckSum := util.ComputeChecksum(headerBytes)
	packet.IPHeader.Checksum = int(newCheckSum)
	// Forward
	packetBytes := packet.Marshal()
	resolvedUdpAddr, _ := net.ResolveUDPAddr("udp4", udpAddr.String())
	udpConn.WriteToUDP(packetBytes, resolvedUdpAddr)
}
