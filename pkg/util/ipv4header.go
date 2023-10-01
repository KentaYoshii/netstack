package util 

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/netstack/tcpip/header"
)

const (
	Version   = 4  // protocol version
	HeaderLen = 20 // header length without extension headers
)

type HeaderFlags int

const (
	MoreFragments HeaderFlags = 1 << iota // more fragments flag
	DontFragment                          // don't fragment flag
)

var (
	errInvalidConn       = errors.New("invalid connection")
	errMissingAddress    = errors.New("missing address")
	errNilHeader         = errors.New("nil header")
	errHeaderTooShort    = errors.New("header too short")
	errExtHeaderTooShort = errors.New("extension header too short")
	errInvalidConnType   = errors.New("invalid conn type")
)

// A Header represents an IPv4 header.
type IPv4Header struct {
	Version  int         // protocol version
	Len      int         // header length
	TOS      int         // type-of-service
	TotalLen int         // packet total length
	ID       int         // identification
	Flags    HeaderFlags // flags
	FragOff  int         // fragment offset
	TTL      int         // time-to-live
	Protocol int         // next protocol
	Checksum int         // checksum
	Src      netip.Addr  // source address
	Dst      netip.Addr  // destination address
	Options  []byte      // options, extension headers
}

func (h *IPv4Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d hdrlen=%d tos=%#x totallen=%d id=%#x flags=%#x fragoff=%#x ttl=%d proto=%d cksum=%#x src=%s dst=%s", h.Version, h.Len, h.TOS, h.TotalLen, h.ID, h.Flags, h.FragOff, h.TTL, h.Protocol, h.Checksum, h.Src.String(), h.Dst.String())
}

// Marshal returns the binary encoding of h.
//
// The returned slice is in the format used by a raw IP socket on the
// local system.
// This may differ from the wire format, depending on the system.
func (h *IPv4Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, errNilHeader
	}
	if h.Len < HeaderLen {
		return nil, errHeaderTooShort
	}
	hdrlen := HeaderLen + len(h.Options)
	b := make([]byte, hdrlen)
	b[0] = byte(Version<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)
	flagsAndFragOff := (h.FragOff & 0x1fff) | int(h.Flags<<13)
	// **** OS-dependent behavior removed
	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))
	// **** end

	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))
	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)
	binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))
	if h.Src.Is4() {
		copy(b[12:16], h.Src.AsSlice())
	}
	if h.Dst.Is4() {
		copy(b[16:20], h.Dst.AsSlice())
	} else {
		return nil, errMissingAddress
	}
	// if ip := h.Src.To4(); ip != nil {
	// 	copy(b[12:16], ip[:net.IPv4len])
	// }
	// if ip := h.Dst.To4(); ip != nil {
	// 	copy(b[16:20], ip[:net.IPv4len])
	// } else {
	// 	return nil, errMissingAddress
	// }
	if len(h.Options) > 0 {
		copy(b[HeaderLen:], h.Options)
	}
	return b, nil
}

// Parse parses b as an IPv4 header and stores the result in h.
//
// The provided b must be in the format used by a raw IP socket on the
// local system.
// This may differ from the wire format, depending on the system.
func (h *IPv4Header) Parse(b []byte) error {
	if h == nil || b == nil {
		return errNilHeader
	}
	if len(b) < HeaderLen {
		return errHeaderTooShort
	}
	hdrlen := int(b[0]&0x0f) << 2
	if len(b) < hdrlen {
		return errExtHeaderTooShort
	}
	h.Version = int(b[0] >> 4)
	h.Len = hdrlen
	h.TOS = int(b[1])
	h.ID = int(binary.BigEndian.Uint16(b[4:6]))
	h.TTL = int(b[8])
	h.Protocol = int(b[9])
	h.Checksum = int(binary.BigEndian.Uint16(b[10:12]))

	h.Src, _ = netip.AddrFromSlice(b[12:16])
	h.Dst, _ = netip.AddrFromSlice(b[16:20])
	//h.Src = net.IPv4(b[12], b[13], b[14], b[15])
	//h.Dst = net.IPv4(b[16], b[17], b[18], b[19])

	// **** OS-dependent behavior removed
	h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	// **** end

	h.Flags = HeaderFlags(h.FragOff&0xe000) >> 13
	h.FragOff = h.FragOff & 0x1fff
	optlen := hdrlen - HeaderLen
	if optlen > 0 && len(b) >= hdrlen {
		if cap(h.Options) < optlen {
			h.Options = make([]byte, optlen)
		} else {
			h.Options = h.Options[:optlen]
		}
		copy(h.Options, b[HeaderLen:hdrlen])
	}
	return nil
}

// ParseHeader parses b as an IPv4 header.
//
// The provided b must be in the format used by a raw IP socket on the
// local system.
// This may differ from the wire format, depending on the system.
func ParseHeader(b []byte) (*IPv4Header, error) {
	h := new(IPv4Header)
	if err := h.Parse(b); err != nil {
		return nil, err
	}
	return h, nil
}

func ValidateChecksum(b []byte, fromHeader uint16) uint16 {
	checksum := header.Checksum(b, fromHeader)

	return checksum
}