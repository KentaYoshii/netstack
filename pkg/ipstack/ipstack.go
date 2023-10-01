package ipstack

import (
	"netstack/pkg/lnxconfig"
	"netstack/pkg/packet"
	"net/netip"
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
	// Name of the interface
	InterfaceName string
	// Subnet
	Subnet  netip.Prefix
	// State (up/down)
	IsUp bool
}

type IpStack struct {
	// Map from Neighbor IP address to NeighborInfo Struct
	Neighbors map[netip.Addr]*NeighborInfo
	// Map from Subnet IP address to InterfaceInfo Struct
	Subnets map[netip.Prefix]*InterfaceInfo
	// Map for protocol number to higher layer handler function 
	ProtocolHandlerMap map[uint8]ProtocolHandler
}

// Create new IP stack
func CreateIPStack() *IpStack {
	return &IpStack{
		Neighbors: make(map[netip.Addr]*NeighborInfo),
		Subnets: make(map[netip.Prefix]*InterfaceInfo),
		ProtocolHandlerMap: make(map[uint8]ProtocolHandler),
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
}

// Register a handler
func (ip *IpStack) RegisterHandler(proto uint8, handler ProtocolHandler) {
	ip.ProtocolHandlerMap[proto] = handler
}