package util

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/praserx/ipconv"
)

const (
	INITIAL_SETUP_TO = 500
	MAX_PACKET_SIZE  = 1400
	TEST_PROTO       = 0
	ICMP_PROTO       = 1
	RIP_PROTO        = 200
)

type HopType int

const (
	HOP_RIP HopType = iota
	HOP_LOCAL
	HOP_STATIC
)

func Int2ip(nn uint32) net.IP {
	return ipconv.IntToIPv4(nn)
}

// Given an int, convert to a binary string
func FromIntToBitString(v uint8) string {
	return fmt.Sprintf("%08b", v)
}

// Given an netip.Addr, convert to a 32 bytes string
func IPAddrToBitStrting(addr netip.Addr) string {
	var b strings.Builder
	ipBytes := addr.As4()
	for i := 0; i < len(ipBytes); i++ {
		b.WriteString(FromIntToBitString(ipBytes[i]))
	}
	return b.String()
}

// Count number of set bits
func NumOfSetBits(n uint32) uint32 {
	var count uint32 = 0
	for n != 0 {
		count += n & 1
		n >>= 1
	}
	return count
}

// Given two netip.Addrs, return the number of shared prefix between down time
func GetNumSharedPrefix(a1 netip.Addr, a2 netip.Addr) int {
	cnt := 0
	a1Str := IPAddrToBitStrting(a1)
	a2Str := IPAddrToBitStrting(a2)
	for i := 0; i < 32; i++ {
		if a1Str[i] != a2Str[i] {
			return cnt
		}
		cnt++
	}
	return cnt
}
