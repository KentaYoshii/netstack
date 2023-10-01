package repl

import (
	"bufio"
	"fmt"
	"netstack/pkg/ipstack"
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
		HostInfo: ipstack,
		Writer: bufio.NewWriter(os.Stdout),
		Scanner: bufio.NewScanner(os.Stdin),
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
	
	fmt.Printf("> ")
	for r.Scanner.Scan() {
		// Split
		tokens := strings.Fields(r.Scanner.Text())
		// Get handler
		handler, ok := r.CommandHandlerMap[tokens[0]]
		if !ok {
			// No handler
			r.WriteOutput("Command not supported. Type h to see the supported commands\n", true)
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
		cidr := fmt.Sprintf("%s/%d", i.VirtualIPAddr, i.Subnet.Bits())
		b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", i.InterfaceName, cidr, stateString))
	}
	return b.String()
}

func (r *Repl) handleListNeighbors(args []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "-----", "---", "-------"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "Iface", "VIP", "UDPAddr"))
	b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", "-----", "---", "-------"))
	for _, nei := range r.HostInfo.Neighbors {
		b.WriteString(fmt.Sprintf("%-6s %-15s %s\n", nei.InterfaceAt, nei.VirtualIPAddr, nei.MacAddr))
	}
	return b.String()
}