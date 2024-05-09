package proto

import (
	"fmt"
	"netstack/pkg/packet"
	"strings"
	"log/slog"
)

// TEST protocol (0)
func HandleTestProtocol(packet *packet.Packet, l *slog.Logger) {
	var src string = packet.IPHeader.Src.String()
	var b strings.Builder
	b.WriteString("Received test packet: ")
	b.WriteString(fmt.Sprintf("src: %s ", src))
	b.WriteString(fmt.Sprintf("ttl: %d ", packet.IPHeader.TTL))
	b.WriteString(fmt.Sprintf("data: %s", string(packet.Payload)))
	l.Info(b.String())
}