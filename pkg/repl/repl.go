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
	r.Writer.WriteString(output)
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

	fmt.Printf("> ")
	for r.Scanner.Scan() {
		// Split
		tokens := strings.Fields(r.Scanner.Text())
		if len(tokens) == 0 {
			r.WriteOutput("", true)
			continue
		}
		if tokens[0] == "exit" {
			break
		}
		// Get handler
		handler, ok := r.CommandHandlerMap[tokens[0]]
		if !ok {
			// No handler
			r.WriteOutput("Command not supported. Type help to see the supported commands\n", true)
			continue
		}
		// Handle
		r.WriteOutput(handler(tokens), true)
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
	// Loop our routing table next
	proto.RtMtx.Lock()
	defer proto.RtMtx.Unlock()
	for prefix, ent := range proto.RoutingTable.Entries {
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
	if r.HostInfo.IsThisMyPacket(destAddr) {
		r.HostInfo.ProtocolHandlerMap[0](packet.CreateNewPacket([]byte(payloadString), netip.Addr{}, destAddr, util.TEST_PROTO))
		b.WriteString(fmt.Sprintf("Sent %d bytes!\n", len(payloadString)))
		return b.String()
	}

	nextHop, found := r.HostInfo.GetNextHop(destAddr)
	if !found {
		b.WriteString("Next Hop not found!\n")
		return b.String()
	}
	// Get the link to send out from
	link := r.HostInfo.Subnets[r.HostInfo.NameToPrefix[nextHop.InterfaceName]]
	newPacket := packet.CreateNewPacket([]byte(payloadString), link.IPAddr, destAddr, util.TEST_PROTO)

	if nextHop.EntryType == util.HOP_LOCAL {
		// LOCAL delivery
		err = link.SendLocal(newPacket, destAddr, false)
	} else {
		// FORWARD
		err = link.SendLocal(newPacket, nextHop.NextHopVIPAddr, false)
	}
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
			newHop := proto.NextHop {
				Prefix: prefix,
				NextHopVIPAddr: li.IPAddr,
				HopCost: 0,
				EntryType: util.HOP_LOCAL,
				InterfaceName: li.InterfaceName,
			}

			proto.RtMtx.Lock()
			proto.RoutingTable.Entries[prefix] = newHop
			proto.RtMtx.Unlock()

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
			proto.RtMtx.Lock()
			delete(proto.RoutingTable.Entries, prefix)
			proto.RtMtx.Unlock()

			// Trigger Updates about the down status
			newHop := proto.NextHop {
				Prefix: prefix,
				NextHopVIPAddr: li.IPAddr,
				HopCost: proto.INF,
				EntryType: util.HOP_LOCAL,
				InterfaceName: li.InterfaceName,
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
