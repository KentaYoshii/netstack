package proto

import (
	"netstack/pkg/packet"
	"strings"
	"fmt"
)

// RIP protocol (200)
func HandleRIPProtocol(packet *packet.Packet) {
	var b strings.Builder
	b.WriteString("Received rip packet\n")
	b.WriteString("--------------------\n")
	b.WriteString(fmt.Sprintf("Src: %s\n", packet.IPHeader.Src.String()))
	b.WriteString(fmt.Sprintf("Dst: %s\n", packet.IPHeader.Dst.String()))
	b.WriteString(fmt.Sprintf("TTL: %d\n", packet.IPHeader.TTL))
	// b.WriteString(fmt.Sprintf("Data: %s\n", string(packet.Payload)))
	b.WriteString("--------------------\n")
	fmt.Printf("\n%s> ", b.String())
}