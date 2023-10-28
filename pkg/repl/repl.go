package repl

import (
	"bufio"
	"fmt"
	"net/netip"
	"netstack/pkg/ipstack"
	"netstack/pkg/packet"
	"netstack/pkg/proto"
	"netstack/pkg/util"
	"os"
	"strconv"
	"strings"
)

const (
	PROMPT = "> "
)

type ReplHandler = func(args []string) string

type Repl struct {
	// Map from Command to Command Handler
	CommandHandlerMap map[string]ReplHandler
	// Host Info
	HostInfo *ipstack.IpStack
	// Writer
	Writer *bufio.Writer
	// Scanner
	Scanner *bufio.Scanner
}

// Initialize our REPL
func CreateREPL(ipstack *ipstack.IpStack) *Repl {
	return &Repl{
		CommandHandlerMap: make(map[string]ReplHandler),
		HostInfo:          ipstack,
		Writer:            bufio.NewWriter(os.Stdout),
		Scanner:           bufio.NewScanner(os.Stdin),
	}
}

// Register a single command to the map
func (r *Repl) RegisterCommandHandler(command string, handler ReplHandler) {
	r.CommandHandlerMap[command] = handler
}

// Helper function to write a result
func (r *Repl) WriteOutput(output string, prompt bool) {
	r.Writer.WriteString(output + "\n")
	if prompt {
		r.Writer.WriteString(PROMPT)
	}
	r.Writer.Flush()
}

// Handle Command
func (r *Repl) StartREPL() {
	// Register Commands
	r.RegisterCommandHandler("li", r.handleListInterface)
	r.RegisterCommandHandler("ln", r.handleListNeighbors)
	r.RegisterCommandHandler("lr", r.handleListRoutes)
	r.RegisterCommandHandler("echo", r.handleEcho)
	r.RegisterCommandHandler("help", r.handleHelp)
	r.RegisterCommandHandler("send", r.handleSend)
	r.RegisterCommandHandler("info", r.handleInfo)
	r.RegisterCommandHandler("up", r.handleUp)
	r.RegisterCommandHandler("down", r.handleDown)
	r.RegisterCommandHandler("tracert", r.handleTraceRt)
	r.RegisterCommandHandler("ping", r.handlePing)

	for r.Scanner.Scan() {
		// Split
		tokens := strings.Fields(r.Scanner.Text())
		if len(tokens) == 0 {
			r.WriteOutput("", false)
			continue
		}
		if tokens[0] == "exit" {
			break
		}
		// Get handler
		handler, ok := r.CommandHandlerMap[tokens[0]]
		if !ok {
			// No handler
			r.WriteOutput("Command not supported. Type help to see the supported commands\n", false)
			continue
		}
		// Handle
		r.WriteOutput(handler(tokens), false)
	}
	if e := r.Scanner.Err(); e != nil {
		r.WriteOutput("Host REPL terminating...\n", false)
	}
}

// ---------- Handler Functions ----------

// Handle "info" command
func (r *Repl) handleInfo(args []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "----", "---", "---"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "INTF", "VIP", "UDP"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "----", "---", "---"))
	for _, i := range r.HostInfo.Subnets {
		b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", i.InterfaceName, i.IPAddr.String(), i.ListenAddr.String()))
	}
	return b.String()
}

// Handle "li" command
func (r *Repl) handleListInterface(args []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "----", "-----------", "-----"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "Name", "Addr/Prefix", "State"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "----", "-----------", "-----"))
	var stateString string
	for _, i := range r.HostInfo.Subnets {
		// Convert bool to string
		if i.IsUp {
			stateString = "up"
		} else {
			stateString = "down"
		}
		cidr := fmt.Sprintf("%s/%d", i.IPAddr, i.Subnet.Bits())
		b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", i.InterfaceName, cidr, stateString))
	}
	return b.String()
}

// Handle "ln" command
func (r *Repl) handleListNeighbors(args []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "-----", "---", "-------"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "Iface", "VIP", "UDPAddr"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "-----", "---", "-------"))
	for _, subnet := range r.HostInfo.Subnets {
		for k, v := range subnet.ARPTable {
			b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", subnet.InterfaceName, k, v))
		}
	}
	return b.String()
}

// Handle "lr" command
func (r *Repl) handleListRoutes(args []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-15s %-10s %s\n", "-", "------", "--------", "----"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %-10s %s\n", "T", "Prefix", "Next hop", "COST"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %-10s %s\n", "-", "------", "--------", "----"))
	// Loop our forwarding table
	for prefix, ent := range r.HostInfo.ForwardingTable {
		var cost, t, name string
		if ent.EntryType == util.HOP_STATIC {
			name = ent.NextHopVIPAddr.String()
			cost = "-"
			t = "S"
		} else if ent.EntryType == util.HOP_LOCAL {
			inf := r.HostInfo.Subnets[prefix]
			name = "LOCAL:" + inf.InterfaceName
			cost = "0"
			t = "L"
		} else {
			name = ent.NextHopVIPAddr.String()
			cost = fmt.Sprintf("%d", ent.HopCost)
			t = "R"
		}
		b.WriteString(fmt.Sprintf("%-6s %-15s %-10s %s\n", t, prefix, name, cost))
	}
	return b.String()
}

// Handle "echo" command
func (r *Repl) handleEcho(args []string) string {
	var b strings.Builder
	b.WriteString(strings.Join(args[1:], " ") + "\n")
	return b.String()
}

// Handle "help" command
func (r *Repl) handleHelp(args []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "-------", "-----------"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "Command", "Description"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "-------", "-----------"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "echo", "Command Test"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "info", "About me"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "exit", "Terminate this program"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "li", "List interfaces"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "lr", "List routes"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "ln", "List available neighbors"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "up", "Enable an interface"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "down", "Disable an interface"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "send", "Send test packet"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "tracert", "Traceroute to given ip"))
	b.WriteString(fmt.Sprintf("%-6s %-15s\n", "ping", "Ping the given ip"))

	return b.String()
}

// Handle "send" command
func (r *Repl) handleSend(args []string) string {
	var b strings.Builder
	if len(args) < 3 {
		b.WriteString("Usage:  send <dest ip> <message>\n")
		return b.String()
	}
	destAddr, err := netip.ParseAddr(args[1])
	if err != nil {
		b.WriteString(err.Error())
		return b.String()
	}
	// Get the payload
	payloadString := strings.Join(args[2:], " ")
	link, valid := r.HostInfo.GetOutgoingLink(destAddr)
	if !valid {
		return b.String()
	}
	newPacket := packet.CreateNewPacket([]byte(payloadString), link.IPAddr, destAddr, util.TEST_PROTO, util.DEFAULT_TTL)
	err = r.HostInfo.SendPacket(newPacket, false)
	if err != nil {
		b.WriteString(err.Error())
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Sent %d bytes!\n", len(payloadString)))
	return b.String()
}

// Handle "up" command
func (r *Repl) handleUp(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		b.WriteString("Usage:  up <if name>\n")
		return b.String()
	}
	target := args[1]
	for prefix, li := range r.HostInfo.Subnets {
		if li.InterfaceName == target {
			if li.IsUp {
				// no op
				b.WriteString("Interface is already up\n")
				return b.String()
			}
			li.IsUp = true

			// Add back and Trigger Updates about the up status
			newHop := proto.NextHop{
				Prefix:         prefix,
				NextHopVIPAddr: li.IPAddr,
				HopCost:        0,
				EntryType:      util.HOP_LOCAL,
				InterfaceName:  li.InterfaceName,
			}

			proto.RoutingTable.RtMtx.Lock()
			proto.RoutingTable.Entries[prefix] = newHop
			proto.RoutingTable.RtMtx.Unlock()

			for _, triChan := range r.HostInfo.TriggerChans {
				triChan <- newHop
			}
			return b.String()
		}
	}
	b.WriteString(target + " not found\n")
	return b.String()
}

// Handle "down" command
func (r *Repl) handleDown(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		b.WriteString("Usage:  down <if name>\n")
		return b.String()
	}
	target := args[1]
	for prefix, li := range r.HostInfo.Subnets {
		if li.InterfaceName == target {
			if !li.IsUp {
				// no op
				b.WriteString("Interface is already down\n")
				return b.String()
			}
			li.IsUp = false

			// Remove from the routing table
			proto.RoutingTable.RtMtx.Lock()
			delete(proto.RoutingTable.Entries, prefix)
			proto.RoutingTable.RtMtx.Unlock()

			// Trigger Updates about the down status
			newHop := proto.NextHop{
				Prefix:         prefix,
				NextHopVIPAddr: li.IPAddr,
				HopCost:        proto.INF,
				EntryType:      util.HOP_LOCAL,
				InterfaceName:  li.InterfaceName,
			}
			for _, triChan := range r.HostInfo.TriggerChans {
				triChan <- newHop
			}
			return b.String()
		}
	}
	b.WriteString(target + " not found\n")
	return b.String()
}

// Handle "tracert" command
func (r *Repl) handleTraceRt(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		b.WriteString("Usage: tracert <ip address>\n")
		return b.String()
	}
	destAddr, err := netip.ParseAddr(args[1])
	if err != nil {
		b.WriteString(err.Error())
		return b.String()
	}
	b.WriteString(fmt.Sprintf("traceroute to %s, %d hops max, 4 bytes packet\n", destAddr.String(), proto.INF))
	res := make(chan proto.TraceRouteInfo, 100)
	for i := 1; i < proto.INF; i++ {
		go r.HostInfo.TraceRoute(i, destAddr, res)
		trInfo := <-res
		if trInfo.IPAddr.IsValid() {
			b.WriteString(fmt.Sprintf("%d    %s   %d micro seconds\n",
				i, trInfo.IPAddr.String(), trInfo.RTT.Microseconds()))
			if trInfo.IPAddr == destAddr {
				return b.String()
			}
		} else {
			b.WriteString(fmt.Sprintf("%d    *\n", i))
		}
	}
	return b.String()
}

// Handle "ping" command
func (r *Repl) handlePing(args []string) string {
	var b strings.Builder
	if len(args) != 3 {
		b.WriteString("Usage: ping <count> <ip address>\n")
		return b.String()
	}
	cnt, _ := strconv.Atoi(args[1])
	destAddr, err := netip.ParseAddr(args[2])
	if err != nil {
		b.WriteString(err.Error())
		return b.String()
	}
	b.WriteString(fmt.Sprintf("PING %s: 4 data bytes\n", destAddr.String()))
	res := make(chan proto.PingInfo, 100)
	okCnt := 0
	var rttMin, rttMax, rttAvg int64
	rttMin = 1000000
	rttMax = 1
	for i := 0; i < cnt; i++ {
		go r.HostInfo.Ping(destAddr, res)
	}
	for i := 0; i < cnt; i++ {
		pingInfo := <-res
		if pingInfo.From.IsValid() {
			okCnt += 1
			// Stats
			rttMin = min(rttMin, pingInfo.RTT.Microseconds())
			rttMax = max(rttMax, pingInfo.RTT.Microseconds())
			rttAvg += pingInfo.RTT.Microseconds()

			b.WriteString(fmt.Sprintf("%d bytes from %s: icmp_seq=%d ttl=%d time=%d ms\n",
				pingInfo.NumBytes, pingInfo.From.String(), pingInfo.SEQ, pingInfo.TTL, pingInfo.RTT.Microseconds()))

		} else {
			b.WriteString("Request timed out. \n")
		}
	}
	b.WriteString(fmt.Sprintf("--- %s ping statistics ---\n", destAddr.String()))
	b.WriteString(fmt.Sprintf("%d packets transmitted, %d packets received, %f percent packet loss\n",
		cnt, okCnt, 100.0-float32(okCnt*100)/float32(cnt)))
	b.WriteString(fmt.Sprintf("round-trip min/avg/max = %d/%f/%d ms\n",
		rttMin, float32(rttAvg)/float32(okCnt), rttMax))
	return b.String()
}
