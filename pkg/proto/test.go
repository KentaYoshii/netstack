package proto

import (
	"fmt"
	"netstack/pkg/packet"
	"strings"
)

// TEST protocol (0)
func HandleTestProtocol(packet *packet.Packet) {
	var src string = packet.IPHeader.Src.String()
	if src == "invalid IP" {
		src = "LOCAL"
	}
	var b strings.Builder
	b.WriteString("Received test packet\n")
	b.WriteString("--------------------\n")
	b.WriteString(fmt.Sprintf("Src: %s\n", src))
	b.WriteString(fmt.Sprintf("Dst: %s\n", packet.IPHeader.Dst.String()))
	b.WriteString(fmt.Sprintf("TTL: %d\n", packet.IPHeader.TTL))
	b.WriteString(fmt.Sprintf("Data: %s\n", string(packet.Payload)))
	b.WriteString("--------------------\n")
	fmt.Printf("\n%s> ", b.String())
}