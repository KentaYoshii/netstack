package repl

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/netip"
	"netstack/pkg/ipstack"
	"netstack/pkg/packet"
	"netstack/pkg/proto"
	"netstack/pkg/socket"
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

	// IP
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
	r.RegisterCommandHandler("setlog", r.handleSetLog)

	// TCP (only hosts can do these)
	if !r.HostInfo.RipEnabled {
		r.RegisterCommandHandler("a", r.handleSocketListenAndAccept)
		r.RegisterCommandHandler("c", r.handleSocketConnect)
		r.RegisterCommandHandler("s", r.handleSocketSend)
		r.RegisterCommandHandler("r", r.handleSocketReceive)
		r.RegisterCommandHandler("cl", r.handleSocketClose)
		r.RegisterCommandHandler("ls", r.handleSocketList)
		r.RegisterCommandHandler("sf", r.handleSocketSendFile)
		r.RegisterCommandHandler("rf", r.handleSocketReceiveFile)
	}

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

// ============= Handler Functions (TCP) ============

// Handle "a" command (a <port>)
// - Start listening and accepting on a port
func (r *Repl) handleSocketListenAndAccept(args []string) string {
	var b strings.Builder

	if len(args) != 2 {
		b.WriteString("Usage: a <port>")
		return b.String()
	}

	return ""
}

// Handle "c" command (c <ip> <port>)
// - Connect to a socket
func (r *Repl) handleSocketConnect(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		b.WriteString("Usage: c <ip> <port>")
		return b.String()
	}

	return ""
}

// Handle "s" command (s <sid> <payload>)
// - Send data using a socket
func (r *Repl) handleSocketSend(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		b.WriteString("Usage: s <sid> <payload>")
		return b.String()
	}

	return ""
}

// Handle "r" command (r <sid> <numbytes>)
// - Recieve data using a socket
func (r *Repl) handleSocketReceive(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		b.WriteString("Usage: r <sid> <numbytes>")
		return b.String()
	}

	return ""
}

// Handle "cl" command (cl <sid>)
// - Close a socket
func (r *Repl) handleSocketClose(args []string) string {
	var b strings.Builder

	if len(args) != 2 {
		b.WriteString("Usage: cl <sid>")
		return b.String()
	}

	return ""
}

// Handle "ls" command (ls)
// - List all sockets in the socket table
func (r *Repl) handleSocketList(args []string) string {
	var b strings.Builder

	if len(args) != 1 {
		b.WriteString("Usage: ls")
		return b.String()
	}

	proto.SocketTable.StMtx.Lock()
	defer proto.SocketTable.StMtx.Unlock()

	b.WriteString(fmt.Sprintf("%-4s%-15s%-7s%-15s%-7s%-10s\n", "---", "-----", "-----", "-----", "-----", "------"))
	b.WriteString(fmt.Sprintf("%-4s%-15s%-7s%-15s%-7s%-10s\n", "SID", "LAddr", "LPort", "RAddr", "RPort", "Status"))
	b.WriteString(fmt.Sprintf("%-4s%-15s%-7s%-15s%-7s%-10s\n", "---", "-----", "-----", "-----", "-----", "------"))

	for _, tcb := range proto.SocketTable.Table {
		b.WriteString(fmt.Sprintf("%-4d%-15s%-7d%-15s%-7d%-10s\n",
			tcb.SID, tcb.Laddr.String(), tcb.Lport, tcb.Raddr.String(), tcb.Rport, socket.ToSocketStateStr(tcb.State)))
	}

	return b.String()
}

// Handle "sf" command (sf <file path> <ip addr> <port>)
// - Send a file using a socket
func (r *Repl) handleSocketSendFile(args []string) string {
	var b strings.Builder

	if len(args) != 4 {
		b.WriteString("Usage: sf <file path> <ip addr> <port>")
		return b.String()
	}
	return ""
}

// Handle "rf" command (rf <dest file path> <port>)
// - Receive a file using a socket
func (r *Repl) handleSocketReceiveFile(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		b.WriteString("Usage: rf <dest file path> <port>")
		return b.String()
	}
	return ""
}

// ============= Handler Functions (IP) ============

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
	// IP
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

	// TCP
	if !r.HostInfo.RipEnabled {
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "a", "Start listening and accepting on a port"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "c", "Connect to a listening socket at addr port"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "s", "Send to the socket"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "r", "Read from the socket"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "cl", "Close the socket"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "ls", "List socket table"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "sf", "Send a file to the socket"))
		b.WriteString(fmt.Sprintf("%-6s %-15s\n", "rf", "Read a file from the socket"))
	}
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
	cnt, err := strconv.Atoi(args[1])
	if err != nil {
		b.WriteString(err.Error())
		return b.String()
	}
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

// Set Log Level
func (r *Repl) handleSetLog(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		b.WriteString("Usage: setlog <debug|info|warn|error>\n")
		return b.String()
	}
	switch args[1] {
	case "debug":
		{
			r.HostInfo.Logger = slog.New(util.NewPrettyHandler(os.Stdout, util.PrettyHandlerOptions{
				SlogOpts: slog.HandlerOptions{
					Level: slog.LevelDebug,
				},
			}))
			break
		}
	case "info":
		{
			r.HostInfo.Logger = slog.New(util.NewPrettyHandler(os.Stdout, util.PrettyHandlerOptions{
				SlogOpts: slog.HandlerOptions{
					Level: slog.LevelInfo,
				},
			}))
			break
		}
	case "warn":
		{
			r.HostInfo.Logger = slog.New(util.NewPrettyHandler(os.Stdout, util.PrettyHandlerOptions{
				SlogOpts: slog.HandlerOptions{
					Level: slog.LevelWarn,
				},
			}))
			break
		}
	case "error":
		{
			r.HostInfo.Logger = slog.New(util.NewPrettyHandler(os.Stdout, util.PrettyHandlerOptions{
				SlogOpts: slog.HandlerOptions{
					Level: slog.LevelError,
				},
			}))
			break
		}
	default:
		{
			b.WriteString("Usage: setlog <debug|info|warn|error>\n")
			return b.String()
		}
	}
	return ""
}
