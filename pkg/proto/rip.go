package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/util"
	"strings"
	"sync"
)

const (
	REQUEST_CMD  = 1
	RESPONSE_CMD = 2
	INF          = 16
)

type RoutingTableT struct {
	entries map[netip.Prefix]NextHop
}

type NextHop struct {
	// For Prefix
	Prefix netip.Prefix
	// VIPAddress of our next hop
	NextHopVIPAddr netip.Addr
	// Cost (infinity = 16)
	HopCost uint32
	// Type
	EntryType util.HopType
	// Interface name
	InterfaceName string
}

type RIPMessage struct {
	// 1 (Request) or 2 (Response)
	Command uint16
	// 0 for Request
	NumEntries uint16
	Entries    []RIPMessageEntry
}

type RIPMessageEntry struct {
	// Network Address
	NetworkAddr uint32
	// Mask
	Mask uint32
	// Cost (infinity = 16)
	Cost uint32
}

// Global Routing Table
var RoutingTable RoutingTableT

// Mutex
var rtMtx sync.Mutex

// Initialize the routing table with immutable local&static routes
func InitializeRoutingTable(from map[netip.Prefix]*NextHop) {
	RoutingTable = RoutingTableT{
		entries: make(map[netip.Prefix]NextHop),
	}
	for prefix, nh := range from {
		RoutingTable.entries[prefix] = NextHop{
			Prefix:         nh.Prefix,
			NextHopVIPAddr: nh.NextHopVIPAddr,
			HopCost:        nh.HopCost,
			EntryType:      nh.EntryType,
			InterfaceName:  nh.InterfaceName,
		}
	}
}

// Create the payload for RIP Request message
func CreateRIPRequestPayload() ([]byte, error) {
	reqMsg := RIPMessage{
		Command:    REQUEST_CMD,
		NumEntries: 0,
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, reqMsg.Command)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, reqMsg.NumEntries)
	if err != nil {
		return nil, err
	}
	bytes := buf.Bytes()
	return bytes, nil
}

// Get all entries from the routing table
func GetAllEntries() []NextHop {
	rtMtx.Lock()
	defer rtMtx.Unlock()

	entries := make([]NextHop, 0)
	for _, ent := range RoutingTable.entries {
		entries = append(entries, ent)
	}
	return entries
}

// Convert our NextHop struct to single RIP entry
func NextHopToRIPEntry(entry NextHop) (RIPMessageEntry, error) {
	// IPv4 in BigEndian
	networkAddr := binary.BigEndian.Uint32(entry.Prefix.Addr().AsSlice())
	// Get Mask
	prefixString := entry.Prefix.String()
	_, ipnet, err := net.ParseCIDR(prefixString)
	if err != nil {
		return RIPMessageEntry{}, err
	}
	mask := ipnet.Mask
	buf := bytes.NewReader(mask)
	var maskInt uint32
	err = binary.Read(buf, binary.BigEndian, &maskInt)
	if err != nil {
		return RIPMessageEntry{}, err
	}
	return RIPMessageEntry{
		NetworkAddr: networkAddr,
		Mask: maskInt,
	}, nil
}

// Given rt entries and neighbor to announce to, apply poisoned reverse
// and convert to rip entries
func PoisonReverse(entries []NextHop, to netip.Addr) ([]RIPMessageEntry, error) {
	newEntries := make([]RIPMessageEntry, 0)
	for _, ent := range entries {
		newEnt, err := NextHopToRIPEntry(ent)
		if err != nil {
			return nil, err
		}
		if ent.NextHopVIPAddr == to {
			// If you learned about this entry from the neighbor
			// you are about to announce to, set cost to 16
			newEnt.Cost = INF
		} else {
			newEnt.Cost = ent.HopCost
		}
		newEntries = append(newEntries, newEnt)
	}
	return newEntries, nil
}

// Marshal RIP Entries
func MarshalRIPEntries(entries []RIPMessageEntry) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, ent := range entries {
		err := binary.Write(buf, binary.BigEndian, ent.Cost)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, ent.NetworkAddr)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, ent.Mask)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// Given entry bytes, create a rip packet out of it
func CreateRIPPacketPayload(entryBytes []byte) ([]byte, error) {
	reqMsg := RIPMessage{
		Command:    RESPONSE_CMD,
		NumEntries: uint16(len(entryBytes) / 12),
	}
	buf := new(bytes.Buffer)
	// CMD type
	err := binary.Write(buf, binary.BigEndian, reqMsg.Command)
	if err != nil {
		return nil, err
	}
	// Num Entries
	err = binary.Write(buf, binary.BigEndian, reqMsg.NumEntries)
	if err != nil {
		return nil, err
	}
	// Entry Bytes
	_, err = buf.Write(entryBytes)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RIP protocol (200)
func HandleRIPProtocol(packet *packet.Packet) {
	var b strings.Builder
	b.WriteString("Received rip packet\n")
	b.WriteString("--------------------\n")
	b.WriteString(fmt.Sprintf("Src: %s\n", packet.IPHeader.Src.String()))
	b.WriteString(fmt.Sprintf("Dst: %s\n", packet.IPHeader.Dst.String()))
	b.WriteString(fmt.Sprintf("TTL: %d\n", packet.IPHeader.TTL))
	// b.WriteString(fmt.Sprintf("Data: %s\n", string(packet.Payload)))
	b.WriteString("--------------------\n")
	fmt.Printf("\n%s> ", b.String())
}
