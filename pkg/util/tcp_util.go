package util

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"math"
	"math/rand"
	"net/netip"
	"time"

	"github.com/google/netstack/tcpip/header"
)


const (
	// key
	NOT_SO_SECRET_KEY = 1000

    // FLAGS
    ACK  = header.TCPFlagAck
    RST  = header.TCPFlagRst
    SYN  = header.TCPFlagSyn
    FIN  = header.TCPFlagFin
)

// Given a ctr variable, keep incrementing it every 4ms
// Used to generate ISN
func KeepIncrement(ctr *uint32) {
	tick := time.NewTicker(4 * time.Millisecond)
	<-tick.C
	if *ctr == math.MaxUint32 {
		*ctr = 0
	}
	*ctr += 1
}

// Given a ctr and 4-tuple, return the ISN to be used for the
// new connection. Secret Key is exposed is here but this is ok
// because of the POC nature of this project
// ISN = CTR + F(LADDR ++ LPORT ++ RADDR + RPORT ++ KEY)
func GetNewISN(ctr uint32, laddr netip.Addr, lport uint16, raddr netip.Addr, rport uint16) uint32 {
	hash := fnv.New32a()
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, ctr)
	buf.Write(laddr.AsSlice())
	binary.Write(buf, binary.BigEndian, lport)
	buf.Write(raddr.AsSlice())
	binary.Write(buf, binary.BigEndian, rport)
	binary.Write(buf, binary.BigEndian, NOT_SO_SECRET_KEY)
	hash.Write(buf.Bytes())
	return hash.Sum32()
}

// Generate a random port number that is sufficiently high
func GetPort() uint16 {
    p := rand.Intn(65535)
    // Port range [0, 1023] is protected
    for p < 1024 {
        p = rand.Intn(65535)
    }
    return uint16(p)
}
