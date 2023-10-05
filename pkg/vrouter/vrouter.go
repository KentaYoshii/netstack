package vrouter

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/util"
)

type HopType int

const (
	HOP_RIP HopType = iota
	HOP_LOCAL
	HOP_STATIC
)

type NextHop struct {
	// Address of our next hop
	NextHopAddr netip.Addr
	// Cost (infinity = 16)
	HopCost uint32
	// Type
	EntryType HopType
}

type NeighborRouterInfo struct {
	// Outgoing VIP
	OutgoingVIP netip.Addr
	// Outgoing Interface
	OutgoingConn *net.UDPConn
	// Neighbor Router UDP Addr
	RouterUDPAddr *net.UDPAddr
}

type RIPMessageEntry struct {
	// Network Address
	NetworkAddr uint32
	// Mask
	Mask uint32
	// Cost (infinity = 16)
	Cost uint32
}

type RIPMessage struct {
	// 1 (Request) or 2 (Response)
	Command uint16
	// 0 for Request
	NumEntries uint16
	Entries    []*RIPMessageEntry
}

func RequestRoutingInfo(ripTo map[netip.Addr]*NeighborRouterInfo) error {
	newRequestMessage := RIPMessage{
		Command:    1,
		NumEntries: 0,
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, newRequestMessage.Command)
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, newRequestMessage.NumEntries)
	if err != nil {
		return err
	}
	bytes := buf.Bytes()
	for dst, neighbor := range ripTo {
		newPacket := packet.CreateNewPacket(bytes, neighbor.OutgoingVIP, dst, util.RIP_PROTO)
		packet.SetCheckSumFor(newPacket)
		_, err := neighbor.OutgoingConn.WriteToUDP(newPacket.Marshal(), neighbor.RouterUDPAddr)
		if err != nil {
			return err
		}
	}
	return nil
}

// Entry function for rip protocol
func SendOutRIPMessages(ripTo map[netip.Addr]NeighborRouterInfo,
	ft map[netip.Prefix]*NextHop, mySubnets []netip.Prefix) error {
	// First get the entries we are announcing
	ripEntries, err := GetRIPEntriesFromTable(ft, mySubnets)
	if err != nil {
		return err
	}
	bytes, err := MarshalRIPEntries(ripEntries)
	// Send out
	for dst, neighbor := range ripTo {
		packet := packet.CreateNewPacket(bytes, neighbor.OutgoingVIP, dst, util.RIP_PROTO)
		neighbor.OutgoingConn.WriteToUDP(packet.Marshal(), neighbor.RouterUDPAddr)
	}
	return nil
}

// Recover RIPEntries from bytes
func RecoverRIPEntriesFromBytes(numEntries int, b []byte) []*RIPMessageEntry {
	entries := make([]*RIPMessageEntry, 0)
	for i := 0; i < numEntries; i++ {
		//Read network addr
		offset := 4
		networkAddr := binary.BigEndian.Uint32(b[(numEntries * i) : (numEntries*i)+offset])
		mask := binary.BigEndian.Uint32(b[(numEntries*i)+offset : (numEntries*i)+offset+4])
		offset += 4
		cost := binary.BigEndian.Uint32(b[(numEntries*i)+offset : (numEntries*i)+offset+4])
		entries = append(entries, &RIPMessageEntry{
			NetworkAddr: networkAddr,
			Mask:        mask,
			Cost:        cost,
		})
	}
	return entries
}

// Marshal RIPEntries into bytes
func MarshalRIPEntries(entries []*RIPMessageEntry) ([]byte, error) {
	buf := new(bytes.Buffer)
	var err error
	for _, entry := range entries {
		err = binary.Write(buf, binary.BigEndian, entry.NetworkAddr)
		if err != nil {
			return nil, err
		}
		binary.Write(buf, binary.BigEndian, entry.Mask)
		if err != nil {
			return nil, err
		}
		binary.Write(buf, binary.BigEndian, entry.Cost)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// Given my forwarding table, return all the RIP entries that can be potentially sent
func GetRIPEntriesFromTable(ft map[netip.Prefix]*NextHop, mySubnets []netip.Prefix) ([]*RIPMessageEntry, error) {
	entries := make([]*RIPMessageEntry, 0)
	// Add my subnets (these are in "up" state)
	for _, subnet := range mySubnets {
		// IPv4 in BigEndian
		networkAddr := binary.BigEndian.Uint32(subnet.Addr().AsSlice())
		// Get mask
		prefixString := subnet.String()
		_, ipnet, err := net.ParseCIDR(prefixString)
		if err != nil {
			return nil, err
		}
		mask := ipnet.Mask
		buf := bytes.NewReader(mask)
		var maskInt uint32
		err = binary.Read(buf, binary.BigEndian, &maskInt)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &RIPMessageEntry{
			NetworkAddr: networkAddr,
			Mask:        maskInt,
			Cost:        0,
		})
	}
	// Add the forwarding table entries
	for prefix, ent := range ft {
		// IPv4 in BigEndian
		networkAddr := binary.BigEndian.Uint32(prefix.Addr().AsSlice())
		// Get mask
		prefixString := prefix.String()
		_, ipnet, err := net.ParseCIDR(prefixString)
		if err != nil {
			return nil, err
		}
		mask := ipnet.Mask
		buf := bytes.NewReader(mask)
		var maskInt uint32
		err = binary.Read(buf, binary.BigEndian, &maskInt)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &RIPMessageEntry{
			NetworkAddr: networkAddr,
			Mask:        maskInt,
			Cost:        ent.HopCost,
		})
	}
	return entries, nil
}
