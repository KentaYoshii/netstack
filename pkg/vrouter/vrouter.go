package vrouter

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
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
func GetRIPEntriesFromTable(ft map[netip.Prefix]*NextHop) ([]*RIPMessageEntry, error) {
	entries := make([]*RIPMessageEntry, 0)
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
