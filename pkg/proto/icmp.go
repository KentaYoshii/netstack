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
	ICMPHeader *ICMPHeader
	Payload    []byte
}

type ICMPHeader struct {
	Type     uint8   // 1 byte
	Code     uint8   // 1 byte
	Checksum uint16  // 2 bytes
	Data     [4]byte // Rest (4 bytes)
}

// Create ICMP header
func CreateICMPHeaderFrom(t int, c int, data [4]byte) *ICMPHeader {
	return &ICMPHeader{
		Type:     uint8(t),
		Code:     uint8(c),
		Checksum: 0,
		Data:     data,
	}
}

func ExtractIdSeq(from []byte) (uint16, uint16) {
	id := binary.BigEndian.Uint16(from[0:2])
	seq := binary.BigEndian.Uint16(from[2:4])
	return id, seq
}

func CreateEchoReplyMessageFrom(icmpPacket *ICMPPacket) (*ICMPPacket, error) {
	hdr := CreateICMPHeaderFrom(ECHO_REPLY, ECHO_CODE, icmpPacket.ICMPHeader.Data)
	hdrBytes, err := hdr.Marshal()
	if err != nil {
		return &ICMPPacket{}, err
	}
	// Payload
	// - copy from request
	allbuf := new(bytes.Buffer)
	payloadbuf := new(bytes.Buffer)
	// Get checksum
	allbuf.Write(hdrBytes)
	allbuf.Write(icmpPacket.Payload)
	newCheckSum := util.ComputeChecksum(allbuf.Bytes())
	hdr.Checksum = newCheckSum
	payloadbuf.Write(icmpPacket.Payload)
	return &ICMPPacket{
		ICMPHeader: hdr,
		Payload:    payloadbuf.Bytes(),
	}, nil
}

// Create ICMP Echo Request Message
func CreateEchoRequestMessageFrom(payload []byte) (*ICMPPacket, error, int, int) {
	// Generate ID and SEQ
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
	hdr := CreateICMPHeaderFrom(ECHO_REQUEST, ECHO_CODE, [4]byte(buf.Bytes()))
	hdrBytes, err := hdr.Marshal()
	if err != nil {
		return &ICMPPacket{}, err, 0, 0
	}
	// Payload
	// - random bytes
	allbuf := new(bytes.Buffer)
	payloadbuf := new(bytes.Buffer)
	// Get checksum
	allbuf.Write(hdrBytes)
	allbuf.Write(payload)
	newCheckSum := util.ComputeChecksum(allbuf.Bytes())
	hdr.Checksum = newCheckSum
	payloadbuf.Write(payload)
	return &ICMPPacket{
		ICMPHeader: hdr,
		Payload:    payloadbuf.Bytes(),
	}, nil, id, seq
}

// Create ICMP packet
func CreateICMPPacketFrom(packet *packet.Packet, t uint8, c uint8) (*ICMPPacket, error) {
	switch t {
	// Destination Unreachable
	case DST_UNREACHABLE:
		{
			// Data not used && NextHop MTU not used yet
			hdr := CreateICMPHeaderFrom(DST_UNREACHABLE, int(c), [4]byte{0})
			hdrBytes, err := hdr.Marshal()
			if err != nil {
				return &ICMPPacket{}, err
			}
			// Payload
			// - IP Header and first 8 bytes of data
			allbuf := new(bytes.Buffer)
			payloadbuf := new(bytes.Buffer)
			iphdrBytes, err := packet.IPHeader.Marshal()
			if err != nil {
				return &ICMPPacket{}, err
			}
			// Get checksum
			allbuf.Write(hdrBytes)
			allbuf.Write(iphdrBytes)
			allbuf.Write(packet.Payload[:8])
			newCheckSum := util.ComputeChecksum(allbuf.Bytes())
			hdr.Checksum = newCheckSum
			payloadbuf.Write(iphdrBytes)
			payloadbuf.Write(packet.Payload[:8])
			return &ICMPPacket{
				ICMPHeader: hdr,
				Payload:    payloadbuf.Bytes(),
			}, nil
		}
	case TIME_EXCEEDED:
		{
			// Data not used
			// Code
			// - 0 -> TTL
			// - 1 -> Fragment reassembly time exceeded
			hdr := CreateICMPHeaderFrom(TIME_EXCEEDED, int(c), [4]byte{0})
			hdrBytes, err := hdr.Marshal()
			if err != nil {
				return &ICMPPacket{}, err
			}
			// Payload
			// - IP Header and first 8 bytes of data
			allbuf := new(bytes.Buffer)
			payloadbuf := new(bytes.Buffer)
			iphdrBytes, err := packet.IPHeader.Marshal()
			if err != nil {
				return &ICMPPacket{}, err
			}
			// Get checksum
			allbuf.Write(hdrBytes)
			allbuf.Write(iphdrBytes)
			allbuf.Write(packet.Payload[:8])
			newCheckSum := util.ComputeChecksum(allbuf.Bytes())
			hdr.Checksum = newCheckSum
			payloadbuf.Write(iphdrBytes)
			payloadbuf.Write(packet.Payload[:8])
			return &ICMPPacket{
				ICMPHeader: hdr,
				Payload:    payloadbuf.Bytes(),
			}, nil
		}
	default:
		{
			return &ICMPPacket{}, nil
		}
	}
}

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
