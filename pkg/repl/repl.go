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
	"netstack/pkg/socket_api"
	"netstack/pkg/util"
	"os"
	"sort"
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
	HostInfo *ipstack.IPStack
	// Writer
	Writer *bufio.Writer
	// Scanner
	Scanner *bufio.Scanner
}

// Initialize our REPL
func CreateREPL(ipstack *ipstack.IPStack) *Repl {
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

	// Testing only
	if r.HostInfo.RipEnabled {
		r.RegisterCommandHandler("lossy", r.handleLossy)
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
			r.HostInfo.Logger.Error("Command not supported. Type help to see the supported commands")
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
		r.HostInfo.Logger.Error("Usage: a <port>")
		return ""
	}

	port, err := strconv.Atoi(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	if port < 0 || port > 65535 {
		r.HostInfo.Logger.Error("Invalid range for port number")
		return ""
	}

	// Create Listen Socket (Passive Open)
	listenSock, err := socket_api.VListen(uint16(port))
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	// For announcing new connections
	listenSock.InfoChan = r.HostInfo.InfoChan

	// Start accepting
	go listenSock.VAccept()

	b.WriteString(fmt.Sprintf("Created listen socket with SID=%d\n", listenSock.TCB.SID))
	return b.String()
}

// Handle "c" command (c <ip> <port>)
// - Connect to a socket
func (r *Repl) handleSocketConnect(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		r.HostInfo.Logger.Error("Usage: c <ip> <port>")
		return ""
	}

	// Verify IP
	ipAddr, err := netip.ParseAddr(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	// Verify Port
	port, err := strconv.Atoi(args[2])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	if port < 0 || port > 65535 {
		r.HostInfo.Logger.Error("Invalid range for port number")
		return ""
	}

	// Get outgoing ip
	link, valid := r.HostInfo.GetOutgoingLink(ipAddr)
	if !valid {
		return ""
	}

	// Active Open
	conn, err := socket_api.VConnect(link.IPAddr, ipAddr, uint16(port))
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	b.WriteString(fmt.Sprintf("Created new socket with SID=%d", conn.TCB.SID))
	return b.String()
}

// Handle "s" command (s <sid> <payload>)
// - Send data using a socket
func (r *Repl) handleSocketSend(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		r.HostInfo.Logger.Error("Usage: s <sid> <payload>")
		return ""
	}

	sid, err := strconv.Atoi(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	// Get tcb
	tcb, found := proto.SIDToTCB(sid)

	if !found {
		// No socket with SID found, error out
		r.HostInfo.Logger.Error(fmt.Sprintf("Socket with SID=%d does not exist", sid))
		return ""
	}

	bytes_written, err := socket_api.VWrite(tcb, []byte(strings.Join(args[2:], " ")))
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	r.HostInfo.Logger.Info(fmt.Sprintf("%d bytes written to SID=%d", bytes_written, tcb.SID))

	return b.String()
}

// Handle "r" command (r <sid> <numbytes>)
// - Recieve data using a socket
func (r *Repl) handleSocketReceive(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		r.HostInfo.Logger.Error("Usage: r <sid> <numbytes>")
		return ""
	}

	sid, err := strconv.Atoi(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	numB, err := strconv.Atoi(args[2])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}
	if numB < 0 {
		r.HostInfo.Logger.Error("cannot read less than 0 bytes")
		return ""
	}

	// Get tcb
	tcb, found := proto.SIDToTCB(sid)

	if !found {
		// No socket with SID found, error out
		r.HostInfo.Logger.Error(fmt.Sprintf("Socket with SID=%d does not exist", sid))
		return ""
	}

	// read
	buf := make([]byte, proto.MAX_WND_SIZE)
	bytes_read, err := socket_api.VRead(tcb, buf)

	r.HostInfo.Logger.Info(fmt.Sprintf("%d bytes read from SID=%d, content=%s", 
	bytes_read, tcb.SID, string(buf[:bytes_read])))
	
	return b.String()
}

// Handle "cl" command (cl <sid>)
// - Close a socket
func (r *Repl) handleSocketClose(args []string) string {
	var b strings.Builder

	if len(args) != 2 {
		r.HostInfo.Logger.Error("Usage: cl <sid>")
		return ""
	}

	sid, err := strconv.Atoi(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	// Get tcb
	tcb, found := proto.SIDToTCB(sid)

	if !found {
		// No socket with SID found, error out
		r.HostInfo.Logger.Error(fmt.Sprintf("Socket with SID=%d does not exist", sid))
		return ""
	}

	if err = socket_api.VClose(tcb); err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}

	return b.String()
}

// Handle "ls" command (ls)
// - List all sockets in the socket table
func (r *Repl) handleSocketList(args []string) string {
	var b strings.Builder

	if len(args) != 1 {
		r.HostInfo.Logger.Error("Usage: ls")
		return ""
	}

	proto.TCPStack.StMtx.Lock()
	defer proto.TCPStack.StMtx.Unlock()

	sids := make([]int, 0)
	for k := range proto.TCPStack.SIDToTableKey {
		sids = append(sids, k)
	}

	sort.Ints(sids)

	b.WriteString(fmt.Sprintf("%-4s%-15s%-7s%-15s%-7s%-10s\n", "---", "-----", "-----", "-----", "-----", "------"))
	b.WriteString(fmt.Sprintf("%-4s%-15s%-7s%-15s%-7s%-10s\n", "SID", "LAddr", "LPort", "RAddr", "RPort", "Status"))
	b.WriteString(fmt.Sprintf("%-4s%-15s%-7s%-15s%-7s%-10s\n", "---", "-----", "-----", "-----", "-----", "------"))

	for _, sid := range sids {
		key := proto.TCPStack.SIDToTableKey[sid]
		tcb := proto.TCPStack.SocketTable[key]
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
		r.HostInfo.Logger.Error("Usage: sf <file path> <ip addr> <port>")
		return ""
	}
	return b.String()
}

// Handle "rf" command (rf <dest file path> <port>)
// - Receive a file using a socket
func (r *Repl) handleSocketReceiveFile(args []string) string {
	var b strings.Builder

	if len(args) != 3 {
		r.HostInfo.Logger.Error("Usage: rf <dest file path> <port>")
		return ""
	}
	return b.String()
}

// ============= Handler Functions (IP) ============

// Handle "lossy" command
func (r *Repl) handleLossy(args []string) string {

	if len(args) != 2 {
		r.HostInfo.Logger.Error("Usage: lossy <rate>")
		return ""
	}
	rate, err := strconv.ParseFloat(args[1], 32)
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}
	if rate > 1 || rate < 0 {
		r.HostInfo.Logger.Error("Rate should be within 0 and 1.0")
		return ""
	}
	r.HostInfo.LossRate = rate
	return ""
}

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
		r.HostInfo.Logger.Error("Usage:  send <dest ip> <message>")
		return ""
	}
	destAddr, err := netip.ParseAddr(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}
	// Get the payload
	payloadString := strings.Join(args[2:], " ")
	link, valid := r.HostInfo.GetOutgoingLink(destAddr)
	if !valid {
		return ""
	}
	newPacket := packet.CreateNewPacket([]byte(payloadString), link.IPAddr, destAddr, util.TEST_PROTO, util.DEFAULT_TTL)
	err = r.HostInfo.SendPacket(newPacket, false)
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}
	b.WriteString(fmt.Sprintf("Sent %d bytes!\n", len(payloadString)))
	return b.String()
}

// Handle "up" command
func (r *Repl) handleUp(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		r.HostInfo.Logger.Error("Usage: up <if name>")
		return ""
	}
	target := args[1]
	for prefix, li := range r.HostInfo.Subnets {
		if li.InterfaceName == target {
			if li.IsUp {
				// no op
				r.HostInfo.Logger.Error("Interface is already up")
				return ""
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
	r.HostInfo.Logger.Error(target + " not found")
	return ""
}

// Handle "down" command
func (r *Repl) handleDown(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		r.HostInfo.Logger.Error("Usage: down <if name>")
		return ""
	}
	target := args[1]
	for prefix, li := range r.HostInfo.Subnets {
		if li.InterfaceName == target {
			if !li.IsUp {
				// no op
				r.HostInfo.Logger.Error("Interface is already down")
				return ""
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
	r.HostInfo.Logger.Error(target + " not found")
	return ""
}

// Handle "tracert" command
func (r *Repl) handleTraceRt(args []string) string {
	var b strings.Builder
	if len(args) != 2 {
		r.HostInfo.Logger.Error("Usage: tracert <ip address>")
		return ""
	}
	destAddr, err := netip.ParseAddr(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
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
		r.HostInfo.Logger.Error("Usage: ping <count> <ip address>")
		return ""
	}
	cnt, err := strconv.Atoi(args[1])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
	}
	destAddr, err := netip.ParseAddr(args[2])
	if err != nil {
		r.HostInfo.Logger.Error(err.Error())
		return ""
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
		r.HostInfo.Logger.Error("Usage: setlog <debug|info|warn|error>")
		return ""
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
			r.HostInfo.Logger.Error("Usage: setlog <debug|info|warn|error>")
			return ""
		}
	}
	return b.String()
}
