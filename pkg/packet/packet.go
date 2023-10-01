package packet

import (
	"netstack/pkg/util"
)


type Packet struct {
	// IPv4 Header
	IPHeader *util.IPv4Header
	// Payload bytes
	Payload []byte
}

func (p *Packet) Marshal() []byte {
	totalBytes := make([]byte, util.MAX_PACKET_SIZE)
	headerBytes, _ := p.IPHeader.Marshal()
	b := copy(totalBytes, headerBytes)
	copy(totalBytes[b:], p.Payload)
	return totalBytes
}
