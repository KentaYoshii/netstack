package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"netstack/pkg/packet"
	"netstack/pkg/util"
)

const (
	// ICMP TYPE
	ECHO_REPLY      = 0
	DST_UNREACHABLE = 3
	ECHO_REQUEST    = 8
	TIME_EXCEEDED   = 11
)

const (
	// Code for ECHO_REQUEST/ECHO_REPLY
	ECHO_CODE = 0
)

const (
	// Code for DESTINATION_UNREACHABLE
	DST_UNREACHABLE_NETWORK = 0
	DST_UNREACHABLE_HOST    = 1
	DST_UNREACHABLE_PROTO   = 2
	DST_UNREACHABLE_PORT    = 3
)

const (
	// Code for TIME_EXCEEDED
	TIME_EXCEEDED_TTL  = 0
	TIME_EXCEEDED_FRAG = 1
)

type ICMPPacket struct {
	// ICMP Message struct
	ICMPHeader *ICMPHeader
	Payload    []byte
}

type ICMPHeader struct {
	Type     uint8   // ICMP TYPE
	Code     uint8   // CODE
	Checksum uint16  // Checksum
	Data     [4]byte // Rest of the Header
}

// =================== ECHO ========================

// Given Echo Request, construct an Echo Reply Message for it
func CreateEchoReplyMessageFrom(icmpPacket *ICMPPacket) (*ICMPPacket, error) {
	hdr := CreateICMPHeaderFrom(ECHO_REPLY, ECHO_CODE, icmpPacket.ICMPHeader.Data)
	hdrBytes, err := hdr.Marshal()
	if err != nil {
		return &ICMPPacket{}, err
	}
	allbuf := new(bytes.Buffer)
	payloadbuf := new(bytes.Buffer)
	// Get checksum
	allbuf.Write(hdrBytes)
	allbuf.Write(icmpPacket.Payload)
	newCheckSum := util.ComputeChecksum(allbuf.Bytes())
	hdr.Checksum = newCheckSum
	// Just copy the payload from the request
	payloadbuf.Write(icmpPacket.Payload)
	return &ICMPPacket{
		ICMPHeader: hdr,
		Payload:    payloadbuf.Bytes(),
	}, nil
}

// Create ICMP Echo Request Message
// Returns icmp packet, error (if any), id, and sequence number
func CreateEchoRequestMessageFrom(payload []byte) (*ICMPPacket, error, int, int) {
	// Generate ID and SEQ (16-bit ints)
	id := rand.Intn(65535)
	seq := rand.Intn(65535)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint16(id))
	if err != nil {
		return &ICMPPacket{}, err, 0, 0
	}
	err = binary.Write(buf, binary.BigEndian, uint16(seq))
	if err != nil {
		return &ICMPPacket{}, err, 0, 0
	}
	// Create Header
	hdr := CreateICMPHeaderFrom(ECHO_REQUEST, ECHO_CODE, [4]byte(buf.Bytes()))
	hdrBytes, err := hdr.Marshal()
	if err != nil {
		return &ICMPPacket{}, err, 0, 0
	}
	allbuf := new(bytes.Buffer)
	payloadbuf := new(bytes.Buffer)
	// Get checksum
	allbuf.Write(hdrBytes)
	allbuf.Write(payload)
	newCheckSum := util.ComputeChecksum(allbuf.Bytes())
	hdr.Checksum = newCheckSum
	// Payload
	payloadbuf.Write(payload)
	return &ICMPPacket{
		ICMPHeader: hdr,
		Payload:    payloadbuf.Bytes(),
	}, nil, id, seq
}

// Given an invalid IP packet, create corresponding ICMP packet with type "t" and code "c"
// Returns the created ICMP Packet
func CreateICMPPacketFrom(packet *packet.Packet, t uint8, c uint8) (*ICMPPacket, error) {
	// Create ICMP Message Header
	hdr := CreateICMPHeaderFrom(int(t), int(c), [4]byte{0})
	hdrBytes, err := hdr.Marshal()
	if err != nil {
		return &ICMPPacket{}, err
	}
	allbuf := new(bytes.Buffer)
	payloadbuf := new(bytes.Buffer)
	iphdrBytes, err := packet.IPHeader.Marshal()
	if err != nil {
		return &ICMPPacket{}, err
	}
	// Checksum
	// Computed over 
	// - ICMP header,
	// - IP header, 
	// - First 8 bytes of original datagram data
	allbuf.Write(hdrBytes)
	allbuf.Write(iphdrBytes)
	allbuf.Write(packet.Payload[:8])
	newCheckSum := util.ComputeChecksum(allbuf.Bytes())
	hdr.Checksum = newCheckSum
	// Payload
	// - IP Header 
	// - First 8 bytes of original datagram data
	payloadbuf.Write(iphdrBytes)
	payloadbuf.Write(packet.Payload[:8])
	return &ICMPPacket{
		ICMPHeader: hdr,
		Payload:    payloadbuf.Bytes(),
	}, nil
}

// =================== ICMP Packet =========================

// Unmarshal ICMP packet
func UnMarshalICMPPacket(b []byte) *ICMPPacket {
	// hdr = 8 bytes
	hdr := UnmarshalICMPHeader(b[0:8])
	return &ICMPPacket{
		ICMPHeader: hdr,
		Payload:    b[8:],
	}
}

// Marshal ICMP packet
func (p *ICMPPacket) Marshal() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil header")
	}
	buf := new(bytes.Buffer)
	hdrBytes, err := p.ICMPHeader.Marshal()
	if err != nil {
		return nil, err
	}
	// Write Header
	_, err = buf.Write(hdrBytes)
	if err != nil {
		return nil, err
	}
	// Write Payload
	_, err = buf.Write(p.Payload)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// =================== ICMP Header =========================

// Create ICMP header
// "t" is the type of ICMP and "c" is the code within the type
func CreateICMPHeaderFrom(t int, c int, data [4]byte) *ICMPHeader {
	return &ICMPHeader{
		Type:     uint8(t),
		Code:     uint8(c),
		Checksum: 0,
		Data:     data,
	}
}

// Marshal ICMP header
func (h *ICMPHeader) Marshal() ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, h.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, h.Code)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, h.Checksum)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(h.Data[:])
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal ICMP header bytes
func UnmarshalICMPHeader(b []byte) *ICMPHeader {
	return &ICMPHeader{
		Type:     uint8(b[0]),
		Code:     uint8(b[1]),
		Checksum: binary.BigEndian.Uint16(b[2:4]),
		Data:     [4]byte{b[4], b[5], b[6], b[7]},
	}
}

func HandleICMPProtocol(packet *packet.Packet) {

}
