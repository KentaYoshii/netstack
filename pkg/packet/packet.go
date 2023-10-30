package packet

import (
	"net/netip"
	"netstack/pkg/util"
	"bytes"
)

type Packet struct {
	// IPv4 Header
	IPHeader *util.IPv4Header
	// Payload bytes
	Payload []byte
}

// Marshal the packet struct
func (p *Packet) Marshal() []byte {
	buf := new(bytes.Buffer)
	headerBytes, _ := p.IPHeader.Marshal()
	buf.Write(headerBytes)
	buf.Write(p.Payload)
	return buf.Bytes()
}

// Create a new IP packet with the info passed in 
func CreateNewPacket(payload []byte, sender netip.Addr, dest netip.Addr, proto int, ttl int) *Packet {
	header := util.CreateHeaderFrom(payload, sender, dest, proto, ttl)
	return &Packet{
		IPHeader: header,
		Payload: payload,
	}
}