package util

import (
	"encoding/binary"
	"net/netip"

	"github.com/google/netstack/tcpip/header"
)

const (
	TcpHeaderLen       = header.TCPMinimumSize
	TcpPseudoHeaderLen = 12
)

// Build a TCPFields struct from the TCP byte array
//
// NOTE: the netstack package might have other options for parsing the header
// that you may like better--this example is most similar to our other class
// examples.  Your mileage may vary!
func ParseTCPHeader(b []byte) header.TCPFields {
	td := header.TCP(b)
	return header.TCPFields{
		SrcPort:    td.SourcePort(),
		DstPort:    td.DestinationPort(),
		SeqNum:     td.SequenceNumber(),
		AckNum:     td.AckNumber(),
		DataOffset: td.DataOffset(),
		Flags:      td.Flags(),
		WindowSize: td.WindowSize(),
		Checksum:   td.Checksum(),
	}
}

// Compute TCP checksum based on a "pesudo-header" that
// combines the (virtual) IP source and destination address, protocol value,
// as well as the TCP header and payload
func ComputeTCPChecksum(tcpHdr *header.TCPFields,
	sourceIP netip.Addr, destIP netip.Addr, payload []byte) uint16 {

	// Fill in the pseudo header
	pseudoHeaderBytes := make([]byte, TcpPseudoHeaderLen)

	// First are the source and dest IPs.  This function only supports
	// IPv4, so make sure the IPs are IPv4 addresses
	copy(pseudoHeaderBytes[0:4], sourceIP.AsSlice())
	copy(pseudoHeaderBytes[4:8], destIP.AsSlice())

	// Next, add the protocol number and header length
	pseudoHeaderBytes[8] = uint8(0)
	pseudoHeaderBytes[9] = uint8(TCP_PROTO)

	totalLength := TcpHeaderLen + len(payload)
	binary.BigEndian.PutUint16(pseudoHeaderBytes[10:12], uint16(totalLength))

	// Turn the TcpFields struct into a byte array
	headerBytes := header.TCP(make([]byte, TcpHeaderLen))
	headerBytes.Encode(tcpHdr)

	// Compute the checksum for each individual part and combine To combine the
	// checksums, we leverage the "initial value" argument of the netstack's
	// checksum package to carry over the value from the previous part
	pseudoHeaderChecksum := header.Checksum(pseudoHeaderBytes, 0)
	headerChecksum := header.Checksum(headerBytes, pseudoHeaderChecksum)
	fullChecksum := header.Checksum(payload, headerChecksum)

	// Return the inverse of the computed value,
	// which seems to be the convention of the checksum algorithm
	// in the netstack package's implementation
	return fullChecksum ^ 0xffff
}

// Create a TCP Header
func CreateTCPHeader(srcP uint16, dstP uint16, seq uint32,
	ack uint32, dataOff uint8, flags uint8,
	windowSize uint16) *header.TCPFields {
	return &header.TCPFields{
		SrcPort:       srcP,
		DstPort:       dstP,
		SeqNum:        seq,
		AckNum:        ack,
		DataOffset:    dataOff,
		Flags:         flags,
		WindowSize:    windowSize,
		Checksum:      0,
		UrgentPointer: 0,
	}
}

// Copy a TCP Header
func CopyTCPHeader(hdr *header.TCPFields) *header.TCPFields {
	return &header.TCPFields{
		SrcPort:       hdr.SrcPort,
		DstPort:       hdr.DstPort,
		SeqNum:        hdr.SeqNum,
		AckNum:        hdr.AckNum,
		DataOffset:    hdr.DataOffset,
		Flags:         hdr.Flags,
		WindowSize:    hdr.WindowSize,
		Checksum:      hdr.Checksum,
		UrgentPointer: hdr.UrgentPointer,
	}
}

// Serialize TCPHeader
func MarshalTCPHeader(hdr *header.TCPFields) header.TCP {
	// Serialize the TCP header
	tcpHeaderBytes := make(header.TCP, TcpHeaderLen)
	tcpHeaderBytes.Encode(hdr)
	return tcpHeaderBytes
}
