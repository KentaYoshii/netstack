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
	REFRESH_RATE = 1
	RT_ENT_TO = 12
	RIP_ENTRY_SIZE = 12
	REQUEST_CMD  = 1
	RESPONSE_CMD = 2
	INF          = 16
)

type RoutingTableT struct {
	Entries         map[netip.Prefix]NextHop
	RouteUpdateChan chan NextHop
	RtMtx sync.Mutex
}

type NextHop struct {
	// Struct that represents our "Next Hop" node
	// It is contained in the Routing Table and Fowarding Table

	// For This Prefix
	Prefix netip.Prefix
	// IPv4 Address of our next hop
	NextHopVIPAddr netip.Addr
	// Cost (infinity = 16)
	HopCost uint32
	// Type (Local, Static, or RIP)
	EntryType util.HopType
	// Interface name through which we can reach this Next Hop
	InterfaceName string
	// Flag for expiration
	Expired bool
	// Last Updated time of this Next Hop
	UpdatedAt time.Time
}

type RIPMessage struct {
	// RIP Message that gets sent to neighboring routers for Routing Update

	// 1 (Request) or 2 (Response)
	Command uint16
	// 0 for Request
	NumEntries uint16
	Entries    []RIPMessageEntry
}

type RIPMessageEntry struct {
	// Struct that represents a single RIP Message Entry

	// Network Address
	NetworkAddr uint32
	// Mask
	Mask uint32
	// Cost (infinity = 16)
	Cost uint32
}

// Global Routing Table
var RoutingTable RoutingTableT

// Initialize the routing table with immutable local&static routes
func InitializeRoutingTable(from map[netip.Prefix]NextHop, uchan chan NextHop) {
	RoutingTable = RoutingTableT{
		Entries:         make(map[netip.Prefix]NextHop),
		RouteUpdateChan: uchan,
	}
	for prefix, nh := range from {
		RoutingTable.Entries[prefix] = NextHop{
			Prefix:         nh.Prefix,
			NextHopVIPAddr: nh.NextHopVIPAddr,
			HopCost:        nh.HopCost,
			EntryType:      nh.EntryType,
			InterfaceName:  nh.InterfaceName,
		}
	}
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
	RoutingTable.RtMtx.Lock()
	defer RoutingTable.RtMtx.Unlock()

	entries := make([]NextHop, 0)
	for _, ent := range RoutingTable.Entries {
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

// Given entry bytes, return the whole rip message bytes to be sent to other routes
func CreateRIPPacketPayload(entryBytes []byte) ([]byte, error) {
	reqMsg := RIPMessage{
		Command:    RESPONSE_CMD,
		NumEntries: uint16(len(entryBytes) / RIP_ENTRY_SIZE),
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

// Checks the routing table entries every REFRESH_RATE second to
// make sure they are all up-to-date. Delete if any of them are stale
func RefreshTable() {

	ticker := time.NewTicker(REFRESH_RATE * time.Second)

	for range ticker.C {
		RoutingTable.RtMtx.Lock()
		for _, ent := range RoutingTable.Entries {
			// Local or Static Routes are immutable
			if ent.EntryType == util.HOP_LOCAL || ent.EntryType == util.HOP_STATIC {
				continue
			}
			// Compute the time difference
			now := time.Now()
			diff := now.Sub(ent.UpdatedAt)
			if diff.Seconds() >= RT_ENT_TO {
				// entry expired! remove
				delete(RoutingTable.Entries, ent.Prefix)
				// trigger the update
				ent.Expired = true
				RoutingTable.RouteUpdateChan <- ent
			}
		}
		RoutingTable.RtMtx.Unlock()
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
// In either case, if we deem the new entry to be worthy of adding, let the ip stack know by sending
// to the "updateChan"
func ProcessRIPEntry(announcedPrefix netip.Prefix, cost uint32, from netip.Addr) {
	RoutingTable.RtMtx.Lock()
	defer RoutingTable.RtMtx.Unlock()
	// Check if we have this prefix
	ent, ok := RoutingTable.Entries[announcedPrefix]

	if !ok {
		// Unknown prefix
		if cost == INF {
			// But if cost is INF, skip
			return
		}
		// O.W., add
		newEnt := NextHop{
			Prefix:         announcedPrefix,
			NextHopVIPAddr: from,
			HopCost:        cost + 1,
			EntryType:      util.HOP_RIP,
			Expired:        false,
			UpdatedAt:      time.Now(),
		}
		RoutingTable.Entries[announcedPrefix] = newEnt
		RoutingTable.RouteUpdateChan <- newEnt
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
				delete(RoutingTable.Entries, announcedPrefix)
				ent.Expired = true
				RoutingTable.RouteUpdateChan <- ent
				return
			}
			if newCost == ent.HopCost {
				// Same hop, same cost, just update
				ent.UpdatedAt = time.Now()
				RoutingTable.Entries[announcedPrefix] = ent
				return
			} else {
				// Update to whatever the advertised cost is
				ent.UpdatedAt = time.Now()
				ent.HopCost = newCost
				RoutingTable.Entries[announcedPrefix] = ent
				RoutingTable.RouteUpdateChan <- ent
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
			RoutingTable.Entries[announcedPrefix] = ent
			RoutingTable.RouteUpdateChan <- ent
			return 
		}
	}
}

// RIP protocol 
// - Unmarshal the rip message
// - For each entry in the message
//   - Check if the entry deserves to be added to our routing table
//     - if yes -> let the ip stack know about the new route
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
