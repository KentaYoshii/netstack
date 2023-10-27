package proto

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"netstack/pkg/packet"
	"netstack/pkg/util"
	"sync"
	"time"
)

const (
	REQUEST_CMD  = 1
	RESPONSE_CMD = 2
	INF          = 16
)

type RoutingTableT struct {
	entries         map[netip.Prefix]NextHop
	RouteUpdateChan chan NextHop
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
	// Expired
	Expired bool
	// Last Update At
	UpdatedAt time.Time
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

// Update Channel
var updateChan chan NextHop

// Initialize the routing table with immutable local&static routes
func InitializeRoutingTable(from map[netip.Prefix]NextHop, uchan chan NextHop) {
	RoutingTable = RoutingTableT{
		entries:         make(map[netip.Prefix]NextHop),
		RouteUpdateChan: updateChan,
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
	updateChan = uchan
	// Start a routine that continually monitors the routing table
	go RefreshTable()
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
		Mask:        maskInt,
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

// UnMarshal RIP Packet
func UnMarshalRIPBytes(b []byte) RIPMessage {
	offset := 0
	// 2 bytes cmd type
	cmdT := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	// 2 bytes num entries
	numEntries := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	entries := make([]RIPMessageEntry, 0)
	for i := 0; i < int(numEntries); i++ {
		cost := binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
		networkAddr := binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
		mask := binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
		entries = append(entries, RIPMessageEntry{
			Cost:        cost,
			NetworkAddr: networkAddr,
			Mask:        mask,
		})
	}
	return RIPMessage{
		Command:    cmdT,
		NumEntries: numEntries,
		Entries:    entries,
	}
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

// Function that checks the routing table entries every 1 second to
// make sure they are all up-to-date
func RefreshTable() {

	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {
		rtMtx.Lock()
		for _, ent := range RoutingTable.entries {
			// Local or Static Routes are immutable
			if ent.EntryType == util.HOP_LOCAL || ent.EntryType == util.HOP_STATIC {
				continue
			}
			now := time.Now()
			diff := now.Sub(ent.UpdatedAt)
			if diff.Seconds() >= 12 {
				// entry expired! remove
				delete(RoutingTable.entries, ent.Prefix)
				// trigger the update
				ent.Expired = true
				updateChan <- ent
			}
		}
		rtMtx.Unlock()
	}
}

// Process a single RIP entry
// 3 cases
// - New Destination
//   - announcedPrefix is unknown -> ADD
//
// - Lower Cost
//   - annourcedPrefix is known but the announced cost is lower -> Update
//
// - NextHop Cost Increase
//   - announcedPrefix is known and it is from the nexthop -> Update
func ProcessRIPEntry(announcedPrefix netip.Prefix, cost uint32, from netip.Addr) {
	rtMtx.Lock()
	defer rtMtx.Unlock()
	// Check if we have this prefix
	ent, ok := RoutingTable.entries[announcedPrefix]

	if !ok {
		// Unknown prefix
		if cost == INF {
			// But if cost is INF, skip
			return
		}
		// OW, add
		newEnt := NextHop{
			Prefix:         announcedPrefix,
			NextHopVIPAddr: from,
			HopCost:        cost + 1,
			EntryType:      util.HOP_RIP,
			Expired:        false,
			UpdatedAt:      time.Now(),
		}
		RoutingTable.entries[announcedPrefix] = newEnt
		updateChan <- newEnt
	} else {
		newCost := cost + 1
		// Known prefix
		if ent.EntryType == util.HOP_LOCAL ||
			ent.EntryType == util.HOP_STATIC {
			// Local or Static Routes are Immutable
			return
		}
		if ent.NextHopVIPAddr == from {
			// If coming from same nexthop
			if newCost >= INF {
				// If cost is INF (link is down)
				delete(RoutingTable.entries, announcedPrefix)
				ent.Expired = true
				updateChan <- ent
				return
			}
			if newCost == ent.HopCost {
				// Same hop, same cost, just update
				ent.UpdatedAt = time.Now()
				return
			} else {
				// Update to whatever the advertised cost is
				ent.UpdatedAt = time.Now()
				ent.HopCost = newCost
				RoutingTable.entries[announcedPrefix] = ent
				updateChan <- ent
				return
			}
		} else {
			// If coming from different router
			if newCost >= ent.HopCost {
				// Not upgrade worthy
				return
			}
			// Lower cost
			ent.HopCost = newCost
			ent.NextHopVIPAddr = from
			ent.UpdatedAt = time.Now()
			RoutingTable.entries[announcedPrefix] = ent
			updateChan <- ent
			return 
		}
	}
}

// RIP protocol (200)
func HandleRIPProtocol(packet *packet.Packet) {
	ripMessage := UnMarshalRIPBytes(packet.Payload)
	for _, ent := range ripMessage.Entries {
		// Apply mask
		NetworkPrefixInt := ent.NetworkAddr & ent.Mask
		// Convert to netip.Addr
		NetworkAddr, _ := netip.AddrFromSlice(util.Int2ip(NetworkPrefixInt))
		numSet := util.NumOfSetBits(ent.Mask)
		// Convert to netip.Prefix
		announcedPrefix := netip.PrefixFrom(NetworkAddr, int(numSet))
		ProcessRIPEntry(announcedPrefix, ent.Cost, packet.IPHeader.Src)
	}
}
