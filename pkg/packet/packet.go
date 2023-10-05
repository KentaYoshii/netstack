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

// Compute Checksum for a given packet
func SetCheckSumFor(packet *Packet) error {
	hBytes, err := packet.IPHeader.Marshal()
	if err != nil {
		return err
	}
	newCheckSum := util.ComputeChecksum(hBytes)
	packet.IPHeader.Checksum = int(newCheckSum)
	return nil
}

// Create a new IP packet with the info passed in 
func CreateNewPacket(payload []byte, sender netip.Addr, dest netip.Addr, proto int) *Packet {
	header := util.CreateHeaderFrom(payload, sender, dest, proto)
	return &Packet{
		IPHeader: header,
		Payload: payload,
	}
}