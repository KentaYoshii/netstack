package ipstack

import (
	"os"
	"bufio"
	"net"
	"net/netip"
	"netstack/pkg/lnxconfig"
	"netstack/pkg/packet"
	"netstack/pkg/link"
)

type ProtocolHandler func(*packet.Packet)

type NeighborInfo struct {
	// VIP of neighbor node
	VirtualIPAddr netip.Addr
	// MAC of neighbor node
	MacAddr netip.AddrPort
	// Interface to talk to this neighbor
	InterfaceAt string
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
	Subnet  netip.Prefix
	// State (up/down)
	IsUp bool
}

type IpStack struct {

	// Writer
	Writer *bufio.Writer

	// Maps

	// Map from Neighbor IP address to NeighborInfo Struct
	Neighbors map[netip.Addr]*NeighborInfo
	// Map from Subnet IP address to InterfaceInfo Struct
	Subnets map[netip.Prefix]*InterfaceInfo
	// Map for protocol number to higher layer handler function 
	ProtocolHandlerMap map[uint8]ProtocolHandler
	
	// Channels

	// Channel through whicn interfaces send IP packets to network layer
	ipPacketChan chan *packet.Packet
	// Channel for getting non-serious error messages
	errorChan chan string
}

// Create new IP stack
func CreateIPStack() *IpStack {
	return &IpStack{
		Writer: bufio.NewWriter(os.Stdout),
		Neighbors: make(map[netip.Addr]*NeighborInfo),
		Subnets: make(map[netip.Prefix]*InterfaceInfo),
		ProtocolHandlerMap: make(map[uint8]ProtocolHandler),
		ipPacketChan: make(chan *packet.Packet, 100),
		errorChan: make(chan string, 100),
	}
}

// Given "config", initialize the ip struct
func (ip *IpStack) Initialize(config *lnxconfig.IPConfig) {
	// Load in the Neighbors Information
	for _, n := range config.Neighbors {
		ip.Neighbors[n.DestAddr] = &NeighborInfo{
			VirtualIPAddr: n.DestAddr,
			MacAddr: n.UDPAddr,
			InterfaceAt: n.InterfaceName,
		}
	}
	// Load in the Interface Information
	for _, i := range config.Interfaces {
		ip.Subnets[i.AssignedPrefix] = &InterfaceInfo{
			VirtualIPAddr: i.AssignedIP,
			MacAddr: i.UDPAddr,
			InterfaceName: i.Name,
			Subnet: i.AssignedPrefix,
			IsUp: true,
		}
	}
	// TODO: RIP and Static Routes


	// Initialize the interfaces and start listening
	ip.InitializeInterfaces()
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
		go link.ListenAtInterface(conn, ip.ipPacketChan, ip.errorChan)
	}
}

// Loop through the channels and listen for incoming packets
func (ip *IpStack) ProcessPackets() {
	for {
		select {
		case packet := <- ip.ipPacketChan:
			if ip.IsThisMyPacket(packet) {
				// Dst == one of our ifs
				// - Invoke the handler
				ip.ProtocolHandlerMap[uint8(packet.IPHeader.Protocol)](packet)
				continue
			}
			// TODO: Forward the packet using the forwarding table
		
		case errStr := <- ip.errorChan:
			ip.Writer.WriteString("\nERROR: " + errStr)
			ip.Writer.Flush()
		}
	}
}

// Helper to check if this packet is destined to me
func (ip *IpStack) IsThisMyPacket(packet *packet.Packet) bool {
	dst := packet.IPHeader.Dst
	for _, i := range ip.Subnets {
		if dst.Compare(i.VirtualIPAddr) == 0 {
			// This is for me
			return true
		}
	}
	return false
}