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
	"os"
)

type ProtocolHandler func(*packet.Packet)

type NeighborInfo struct {
	// VIP of neighbor node
	VirtualIPAddr netip.Addr
	// MAC of neighbor node
	MacAddr netip.AddrPort
	// UDP addr
	NeighborUDPAddr *net.UDPAddr
	// Interface to talk to this neighbor
	InterfaceAt string
}

type HopType int

const (
	HOP_RIP HopType = iota
	HOP_LOCAL
	HOP_STATIC
)

type NextHop struct {
	// Address of our next hop
	NextHopAddr netip.Addr
	// Cost
	HopCost int
	// Type
	EntryType HopType
}

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
}

type IpStack struct {

	// Writer
	Writer *bufio.Writer

	// RIP enabled?
	RipEnabled bool

	// Maps

	// Map from Neighbor IP address to NeighborInfo Struct
	Neighbors map[netip.Addr]*NeighborInfo
	// Map from Subnet IP address to InterfaceInfo Struct
	Subnets map[netip.Prefix]*InterfaceInfo
	// Map for protocol number to higher layer handler function
	ProtocolHandlerMap map[uint8]ProtocolHandler
	// Forwarding Table (map from Network Prefix to NextHop IP)
	ForwardingTable map[netip.Prefix]NextHop
	// Map from interface name to VIP
	InterfaceToVIP map[string]netip.Addr
	// Map from interface name to prefix
	InterfaceToPrefix map[string]netip.Prefix
	// Map from VIP to UDP
	VIPToUDP map[netip.Addr]netip.AddrPort
	// Channels

	// Channel through whicn interfaces send IP packets to network layer
	IpPacketChan chan *packet.Packet
	// Channel for getting non-serious error messages
	errorChan chan string

	// ----- ROUTERS specific -----
	RIPTo []netip.Addr
}

// Create new IP stack
func CreateIPStack() *IpStack {
	return &IpStack{
		Writer:             bufio.NewWriter(os.Stdout),
		RipEnabled:         false,
		Neighbors:          make(map[netip.Addr]*NeighborInfo),
		Subnets:            make(map[netip.Prefix]*InterfaceInfo),
		ProtocolHandlerMap: make(map[uint8]ProtocolHandler),
		ForwardingTable:    make(map[netip.Prefix]NextHop),
		InterfaceToVIP:     make(map[string]netip.Addr),
		InterfaceToPrefix: make(map[string]netip.Prefix),
		VIPToUDP: make(map[netip.Addr]netip.AddrPort),
		IpPacketChan:       make(chan *packet.Packet, 100),
		errorChan:          make(chan string, 100),
	}
}

// Given "config", initialize the ip struct
func (ip *IpStack) Initialize(config *lnxconfig.IPConfig) {
	// Load in the Interface Information
	for _, i := range config.Interfaces {
		ip.InterfaceToPrefix[i.Name] = i.AssignedPrefix
		ip.InterfaceToVIP[i.Name] = i.AssignedIP
		ip.VIPToUDP[i.AssignedIP] = i.UDPAddr
		ip.Subnets[i.AssignedPrefix] = &InterfaceInfo{
			VirtualIPAddr: i.AssignedIP,
			MacAddr:       i.UDPAddr,
			InterfaceName: i.Name,
			Subnet:        i.AssignedPrefix,
			IsUp:          true,
		}
	}
	// Load in the Neighbors Information
	for _, n := range config.Neighbors {
		neighborUDPAddr, err := net.ResolveUDPAddr("udp4", n.UDPAddr.String())
		if err != nil {
			panic(err)
		}
		ip.Neighbors[n.DestAddr] = &NeighborInfo{
			VirtualIPAddr:   n.DestAddr,
			MacAddr:         n.UDPAddr,
			NeighborUDPAddr: neighborUDPAddr,
			InterfaceAt:     n.InterfaceName,
		}
	}
	// Check if RIP is enabled
	if config.RoutingMode == lnxconfig.RoutingTypeRIP {
		ip.RipEnabled = true
	} else {
		ip.RipEnabled = false
	}
	// (ROUTER): set neighbors
	if ip.RipEnabled {
		ip.RIPTo = config.RipNeighbors
	}

	// Set up Forwarding table
	// Static Routes (default gateway)
	for k, v := range config.StaticRoutes {
		ip.ForwardingTable[k] = NextHop{
			NextHopAddr: v,
			EntryType: HOP_STATIC,
		}
	}

	// Setup protocol handlers
	// TEST PROTOCOL
	ip.ProtocolHandlerMap[0] = proto.HandleTestProtocol
	// TODO: Add RIP, ICMP handlers

	// Initialize the interfaces and start listening
	ip.InitializeInterfaces()
	// Start processing incoming packets
	go ip.ProcessPackets()
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
			var neighbor *NeighborInfo
			if check, _ := ip.IsThisMySubnet(packet.IPHeader.Dst); check {
				// Dst is in one of our direct subnets
				// - Just send to dst that directly through link
				neighbor = ip.Neighbors[packet.IPHeader.Dst]
			} else {
				// Dst is somewhere else
				// - Forward
				// Get next hop
				nextHop := ip.GetNextHop(packet.IPHeader.Dst)
				neighbor = ip.Neighbors[nextHop.NextHopAddr]
			}
			// Dispatch the packet
			ip.SendPacketTo(packet, neighbor, true)

		case errStr := <-ip.errorChan:
			ip.Writer.WriteString("\nERROR: " + errStr)
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
	for _, i := range ip.Subnets {
		if i.Subnet.Contains(dst) {
			return true, i.InterfaceName
		}
	}
	return false, ""
}

func (ip *IpStack) GetNextHop(dst netip.Addr) NextHop {
	// Check Forwarding Table
	for prefix, nihop := range ip.ForwardingTable {
		if prefix.Contains(dst) {
			return nihop
		}
	}
	panic("should not enter here")
}

func (ip *IpStack) SendPacketTo(packet *packet.Packet, to *NeighborInfo, forward bool) {
	var newTTL int = packet.IPHeader.TTL
	// First decrement the TTL
	if forward {
		newTTL := packet.IPHeader.TTL - 1
		if newTTL < 0 {
			ip.errorChan <- "TTL reached below 0. Dropping it!"
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
	// Get the conn
	prefix, _ := ip.InterfaceToPrefix[to.InterfaceAt]
	conn := ip.Subnets[prefix].ListenConn
	_, err = conn.WriteToUDP(packetBytes, to.NeighborUDPAddr)
}
