package repl

import (
	"bufio"
	"fmt"
	"netstack/pkg/ipstack"
	"os"
	"strings"
)


type ReplHandler = func(args []string)

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

// Handle Command
func (r *Repl) StartREPL() {
	// Register Commands
	r.RegisterCommandHandler("li", r.handleListInterface)

	fmt.Printf("> ")
	for r.Scanner.Scan() {
		// Split
		tokens := strings.Fields(r.Scanner.Text())
		// Get handler
		handler, ok := r.CommandHandlerMap[tokens[0]]
		if !ok {
			// No handler
			r.Writer.WriteString("Command not supported. Type h to see the supported commands\n> ")
			r.Writer.Flush()
			
			continue
		}
		// Handle
		handler(tokens)
		r.Writer.Flush()
	}

	if e := r.Scanner.Err(); e != nil {
		r.Writer.WriteString("Host REPL terminating...\n")
		r.Writer.Flush()
	}
}

// ---------- Handler Functions ----------

// Handle "li" command
func (r *Repl) handleListInterface(args []string) {
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
	r.Writer.WriteString(b.String() + "\n" + "> ")
}
