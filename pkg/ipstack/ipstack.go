package ipstack

import (
	"bufio"
	"net/netip"
	"netstack/pkg/link"
	"netstack/pkg/lnxconfig"
	"netstack/pkg/packet"
	"netstack/pkg/proto"
	"netstack/pkg/util"
	"os"
	"sync"
	"time"
)

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
	ForwardingTable map[netip.Prefix]proto.NextHop
	// Interface name to Prefix Address
	NameToPrefix map[string]netip.Prefix

	// Channels

	// Channel through whicn interfaces send IP packets to network layer
	IpPacketChan chan *packet.Packet
	// ICMP chan which specializes in dealing with ICMP packet
	ICMPChan chan *packet.Packet
	// Channel through which new route entries are sent
	RouteChan chan proto.NextHop
	// Channels through which triggered updates are communicated
	TriggerChans []chan proto.NextHop
	// Channel for getting non-serious error messages
	errorChan chan string
	// Debugging
	InfoChan chan string

	// Concurrency
	ftMtx sync.Mutex
}

// Create new IP stack
func CreateIPStack() *IpStack {
	return &IpStack{
		Writer:             bufio.NewWriter(os.Stdout),
		RipEnabled:         false,
		Subnets:            make(map[netip.Prefix]*link.Link),
		ProtocolHandlerMap: make(map[uint8]ProtocolHandler),
		ForwardingTable:    make(map[netip.Prefix]proto.NextHop),
		NameToPrefix:       make(map[string]netip.Prefix),
		IpPacketChan:       make(chan *packet.Packet, 100),
		ICMPChan:           make(chan *packet.Packet, 100),
		RouteChan:          make(chan proto.NextHop, 100),
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
			ErrorChan:     ip.errorChan,
		}
	}
	// =============== ARP Table ===============
	for _, n := range config.Neighbors {
		for prefix, li := range ip.Subnets {
			if prefix.Contains(n.DestAddr) {
				li.AddNeighbor(n.DestAddr, n.UDPAddr)
			}
		}
	}

	// Initialize the interfaces and start listening
	ip.InitializeInterfaces()
	// Let the port binding complete
	time.Sleep(time.Millisecond * util.INITIAL_SETUP_TO)

	// ============ Forwarding Table ============
	// Static Routes (default gateway)
	for k, v := range config.StaticRoutes {
		for prefix, intf := range ip.Subnets {
			if !prefix.Contains(v) {
				continue
			}
			ip.ForwardingTable[k] = proto.NextHop{
				Prefix:         prefix,
				NextHopVIPAddr: v,
				EntryType:      util.HOP_STATIC,
				HopCost:        0,
				InterfaceName:  intf.InterfaceName,
				Expired:        false,
			}
		}
	}
	// Local Interfaces
	for k, v := range ip.Subnets {
		ip.ForwardingTable[k] = proto.NextHop{
			Prefix:         k,
			NextHopVIPAddr: v.IPAddr,
			EntryType:      util.HOP_LOCAL,
			HopCost:        0,
			InterfaceName:  v.InterfaceName,
			Expired:        false,
		}
	}

	// ================== RIP ==================
	if config.RoutingMode == lnxconfig.RoutingTypeRIP {
		ip.RipEnabled = true
		proto.InitializeRoutingTable(ip.ForwardingTable, ip.RouteChan)
	} else {
		ip.RipEnabled = false
	}
	if ip.RipEnabled {
		for _, neighbor := range config.RipNeighbors {
			for prefix, li := range ip.Subnets {
				if prefix.Contains(neighbor) {
					// Request Route
					li.RequestRouteFrom(neighbor)
					// Start Periodic Updates + monitor triggered updates
					triChan := make(chan proto.NextHop, 100)
					ip.TriggerChans = append(ip.TriggerChans, triChan)
					go li.SendUpdatesTo(neighbor, triChan)
					break
				}
			}
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
	ip.ProtocolHandlerMap[util.ICMP_PROTO] = proto.HandleICMPProtocol

	// =========== Routines =============
	// Start processing incoming packets
	go ip.ProcessPackets()
	// Start monitoring route updates
	go ip.CheckForRouteUpdates()
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

func (ip *IpStack) SendEchoReply(pac *packet.Packet, icmpPacket *proto.ICMPPacket) {
	rep, err := proto.CreateEchoReplyMessageFrom(icmpPacket)
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
	finalDst := pac.IPHeader.Src
	// Get the next hop to src ip
	nextHop, found := ip.GetNextHop(finalDst)
	if !found {
		ip.errorChan <- "no nexthop for icmp\n"
		return
	}
	link, ok := ip.Subnets[ip.NameToPrefix[nextHop.InterfaceName]]
	if !ok {
		ip.errorChan <- "if not found\n"
		return
	}
	if !link.IsUp {
		ip.errorChan <- "icmp cannot be sent from downed link\n"
		return
	}
	icmpBytes, err := rep.Marshal()
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
	// Create the packet
	newPacket := packet.CreateNewPacket(icmpBytes, link.IPAddr, finalDst, util.ICMP_PROTO, util.DEFAULT_TTL)
	if nextHop.EntryType == util.HOP_LOCAL {
		// LOCAL delivery
		err = link.SendLocal(newPacket, finalDst, false)
	} else {
		// FORWARD
		err = link.SendLocal(newPacket, nextHop.NextHopVIPAddr, false)
	}
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
}

func (ip *IpStack) SendICMP(packet *packet.Packet, t uint8, c uint8) {
	finalDst := packet.IPHeader.Src
	// Get the next hop to src ip
	nextHop, found := ip.GetNextHop(finalDst)
	if !found {
		ip.errorChan <- "no nexthop for icmp\n"
		return
	}
	link, ok := ip.Subnets[ip.NameToPrefix[nextHop.InterfaceName]]
	if !ok {
		ip.errorChan <- "if not found\n"
		return
	}
	if !link.IsUp {
		ip.errorChan <- "icmp cannot be sent from downed link\n"
		return
	}
	icmpPacket, err := link.CreateICMPPacketTo(t, c, packet)
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
	if nextHop.EntryType == util.HOP_LOCAL {
		// LOCAL delivery
		err = link.SendLocal(icmpPacket, finalDst, false)
	} else {
		// FORWARD
		err = link.SendLocal(icmpPacket, nextHop.NextHopVIPAddr, false)
	}
	if err != nil {
		ip.errorChan <- err.Error()
	}
}

// Loop through the channels and listen for incoming packets
func (ip *IpStack) ProcessPackets() {
	for {
		select {
		case packet := <-ip.IpPacketChan:
			// Check if I am the intended destination
			if ip.IsThisMyPacket(packet.IPHeader.Dst) {
				handler, ok := ip.ProtocolHandlerMap[uint8(packet.IPHeader.Protocol)]
				if !ok {
					// No such protocol
					ip.SendICMP(packet, proto.DST_UNREACHABLE, proto.DST_UNREACHABLE_PROTO)
				} else {
					// Send up
					handler(packet)
					if packet.IPHeader.Protocol == util.ICMP_PROTO {
						// Separately process ICMP
						icmpPacket := proto.UnMarshalICMPPacket(packet.Payload)
						// Needs to respond to echo request
						if icmpPacket.ICMPHeader.Type == proto.ECHO_REQUEST {
							ip.SendEchoReply(packet, icmpPacket)
						} else {
							ip.ICMPChan <- packet
						}
					}
				}
				continue
			}
			// Check TTL. Drop if cannot forward
			if packet.IPHeader.TTL <= 1 {
				ip.SendICMP(packet, proto.TIME_EXCEEDED, proto.TIME_EXCEEDED_TTL)
				continue
			}
			// Get the next hop
			nextHop, found := ip.GetNextHop(packet.IPHeader.Dst)
			if !found {
				ip.SendICMP(packet, proto.DST_UNREACHABLE, proto.DST_UNREACHABLE_NETWORK)
				continue
			}
			// Get the link to send out from
			link := ip.Subnets[ip.NameToPrefix[nextHop.InterfaceName]]
			if !link.IsUp {
				ip.SendICMP(packet, proto.DST_UNREACHABLE, proto.DST_UNREACHABLE_NETWORK)
				continue
			}
			var err error
			if nextHop.EntryType == util.HOP_LOCAL {
				// LOCAL delivery
				err = link.SendLocal(packet, packet.IPHeader.Dst, true)
			} else {
				// FORWARD
				err = link.SendLocal(packet, nextHop.NextHopVIPAddr, true)
			}
			if err != nil {
				if err.Error() == "ARP" {
					ip.SendICMP(packet, proto.DST_UNREACHABLE, proto.DST_UNREACHABLE_NETWORK)
				}
			}
		case errString := <-ip.errorChan:
			ip.Writer.WriteString("\nError: " + errString + "\n> ")
			ip.Writer.Flush()
		case info := <-ip.InfoChan:
			ip.Writer.WriteString("\nInfo: " + info + "\n> ")
			ip.Writer.Flush()
		}
	}
}

// A new/better route is sent to the "RouteChan" so keep monitoring
func (ip *IpStack) CheckForRouteUpdates() {
	for r := range ip.RouteChan {
		ip.ftMtx.Lock()
		if r.Expired {
			// This route update is for delete (expired)
			_, ok := ip.ForwardingTable[r.Prefix]
			if !ok {
				panic("trying to delete non-existent entry")
			}
			delete(ip.ForwardingTable, r.Prefix)
			r.HopCost = proto.INF // unreachability
		} else {
			// This route update is for upgrade
			// Add the new route
			nh, _ := ip.GetNextHop(r.NextHopVIPAddr)
			r.InterfaceName = nh.InterfaceName
			ip.ForwardingTable[r.Prefix] = r
		}
		ip.ftMtx.Unlock()

		// Trigger update to neighbors
		for _, triChan := range ip.TriggerChans {
			triChan <- r
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
func (ip *IpStack) GetNextHop(dst netip.Addr) (proto.NextHop, bool) {
	// Check Forwarding Table
	longest := -1
	var niHop proto.NextHop
	for prefix, nihop := range ip.ForwardingTable {
		if prefix.Contains(dst) {
			sharedBits := util.GetNumSharedPrefix(dst, prefix.Addr())
			if longest < sharedBits {
				longest = sharedBits
				niHop = nihop
			}
		}
	}

	if longest == -1 {
		// Not found
		return proto.NextHop{}, false
	}

	return niHop, true
}

// TraceRoute to IP Address given by "to"
func (ip *IpStack) TraceRoute(ttl int, to netip.Addr, res chan netip.Addr) {
	// Get the next hop
	nextHop, found := ip.GetNextHop(to)
	if !found {
		ip.errorChan <- "no nexthop for icmp\n"
		return
	}
	// Get the link to send out from
	link, ok := ip.Subnets[ip.NameToPrefix[nextHop.InterfaceName]]
	if !ok {
		ip.errorChan <- "if not found\n"
		return
	}
	// Check link status
	if !link.IsUp {
		ip.errorChan <- "icmp cannot be sent from downed link\n"
		return
	}
	echoRequestMessage, err, id, seq := proto.CreateEchoRequestMessageFrom([]byte("aaaa"))
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}

	icmpBytes, err := echoRequestMessage.Marshal()
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
	// Create the packet
	newPacket := packet.CreateNewPacket(icmpBytes, link.IPAddr, to, util.ICMP_PROTO, ttl)
	if nextHop.EntryType == util.HOP_LOCAL {
		// LOCAL delivery
		err = link.SendLocal(newPacket, to, false)
	} else {
		// FORWARD
		err = link.SendLocal(newPacket, nextHop.NextHopVIPAddr, false)
	}
	if err != nil {
		ip.errorChan <- err.Error()
		return
	}
	// Wait
	// - Successfully Reach the target == ECHO REPLY
	// - TTL MAX Reached == ICMP TTL EXCEEDED
	timer := time.NewTimer(5 * time.Second)
	for {
		select {
		case pac := <-ip.ICMPChan:
			{
				icmpPacket := proto.UnMarshalICMPPacket(pac.Payload)
				// Not Echo Reply
				if (icmpPacket.ICMPHeader.Type != proto.ECHO_REPLY) &&
					(icmpPacket.ICMPHeader.Type != proto.TIME_EXCEEDED) {
					continue
				}
				// If Time Exceeded
				if icmpPacket.ICMPHeader.Type == proto.TIME_EXCEEDED {
					// Check the payload
					matchID, matchSEQ := proto.ExtractIdSeq(icmpPacket.Payload[util.HeaderLen+4:util.HeaderLen+8])
					// Check if it is in response to our trace route packet
					if matchID != uint16(id) || matchSEQ != uint16(seq) {
						continue
					}
					res <- pac.IPHeader.Src
					return
				}
				// Match ID and SEQ
				matchID, matchSEQ := proto.ExtractIdSeq(icmpPacket.ICMPHeader.Data[:])
				if matchID != uint16(id) || matchSEQ != uint16(seq) {
					continue
				}
				// Valid Echo Reply
				res <- pac.IPHeader.Src
			}
		case <-timer.C:
			{
				// Time is up
				res <- netip.Addr{}
				return
			}
		}
	}
}
