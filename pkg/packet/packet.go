package packet

import (
	"netstack/pkg/util"
)


type Packet struct {
	IPHeader *util.IPv4Header
	Payload []byte
}