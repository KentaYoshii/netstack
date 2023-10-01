package lnxconfig

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type RoutingMode int

const (
	RoutingTypeNone   RoutingMode = 0
	RoutingTypeStatic RoutingMode = 1
	RoutingTypeRIP    RoutingMode = 2
)

/*
 * NOTE: These data structures only represent structure of a
 * configuration file.  In your implementation, you will still need to
 * build your own data structures that store relevant information
 * about your links, interfaces, etc. at runtime.
 *
 * These structs only represent the things in the config file--you
 * will probably only parse these at startup in order to set up your own
 * data structures.
 *
 */
type IPConfig struct {
	Interfaces []InterfaceConfig
	Neighbors  []NeighborConfig

	OriginatingPrefixes []netip.Prefix // Unused in F23, ignore.

	RoutingMode RoutingMode

	// ROUTERS ONLY:  Neighbors to send RIP packets
	RipNeighbors []netip.Addr

	// Manually-added routes ("route" directive, usually just for default on hosts)
	StaticRoutes map[netip.Prefix]netip.Addr
}

type InterfaceConfig struct {
	Name           string
	AssignedIP     netip.Addr
	AssignedPrefix netip.Prefix

	UDPAddr netip.AddrPort
}

type NeighborConfig struct {
	DestAddr netip.Addr
	UDPAddr  netip.AddrPort

	InterfaceName string
}

// Static config for testing
var LnxConfig = IPConfig{
	Interfaces: []InterfaceConfig{
		{
			Name:           "if0",
			AssignedIP:     netip.MustParseAddr("10.1.0.1"),
			AssignedPrefix: netip.MustParsePrefix("10.1.0.1/24"),
			UDPAddr:        netip.MustParseAddrPort("127.0.0.1:5000"),
		},
		{
			Name:           "if1",
			AssignedIP:     netip.MustParseAddr("10.10.1.1"),
			AssignedPrefix: netip.MustParsePrefix("10.10.1.1/24"),
			UDPAddr:        netip.MustParseAddrPort("127.0.0.1:5001"),
		},
	},

	Neighbors: []NeighborConfig{
		{
			DestAddr:      netip.MustParseAddr("10.1.0.10"),
			UDPAddr:       netip.MustParseAddrPort("127.0.0.1:6001"),
			InterfaceName: "if0",
		},
		{
			DestAddr:      netip.MustParseAddr("10.10.1.2"),
			UDPAddr:       netip.MustParseAddrPort("127.0.0.1:5100"),
			InterfaceName: "if1",
		},
	},

	OriginatingPrefixes: []netip.Prefix{
		netip.MustParsePrefix("10.1.0.1/24"),
	},

	RoutingMode: RoutingTypeStatic,

	RipNeighbors: []netip.Addr{
		netip.MustParseAddr("10.10.1.2"),
	},
}

// ******************** END PUBLIC INTERFACE *********************************************
// (You shouldn't need to worry about what's below, unless you want to modify the parser.)

type ParseFunc func(int, string, *IPConfig) error

var parseCommands = map[string]ParseFunc{
	"interface": parseInterface,
	"neighbor":  parseNeighbor,
	"routing":   parseRouting,
	"route":     parseRoute,
	"rip":       parseRip,
}

func parseRip(ln int, line string, config *IPConfig) error {
	tokens := strings.Split(line, " ")

	if len(tokens) < 2 {
		return newErrString(ln, "Usage:  rip [cmd] ...")
	}
	cmd := tokens[1]
	ripTokens := tokens[2:]

	switch cmd {
	case "originate":
		if len(ripTokens) < 2 && ripTokens[0] != "prefix" {
			return newErrString(ln, "Usage:  rip originate prefix <prefix>")
		}
		ripPrefix, err := netip.ParsePrefix(ripTokens[1])
		if err != nil {
			return newErr(ln, err)
		}
		ripPrefix = ripPrefix.Masked()

		// Check if prefix is in config
		err = addOriginatingPrefix(config, ripPrefix)
		if err != nil {
			return err
		}
	case "advertise-to":
		if len(ripTokens) < 1 {
			return newErrString(ln, "Usage:  rip advertise-to <neighbor IP>")
		}
		addr, err := netip.ParseAddr(ripTokens[0])
		if err != nil {
			return newErr(ln, err)
		}
		err = addRipNeighbor(config, addr)
		if err != nil {
			return err
		}
	default:
		return newErrString(ln, "Unrecognized RIP command %s", cmd)
	}

	return nil
}

func addOriginatingPrefix(config *IPConfig, prefix netip.Prefix) error {
	for _, iface := range config.Interfaces {
		if iface.AssignedPrefix == prefix {
			config.OriginatingPrefixes = append(config.OriginatingPrefixes, prefix)
			return nil
		}
	}

	return errors.Errorf("No matching prefix %s in config", prefix.String())
}

func addRipNeighbor(config *IPConfig, neighbor netip.Addr) error {
	for _, iface := range config.Neighbors {
		if iface.DestAddr == neighbor {
			config.RipNeighbors = append(config.RipNeighbors, neighbor)
			return nil
		}
	}

	return errors.Errorf("RIP neighbor %s is not a neighbor IP", neighbor.String())
}

func parseRouting(ln int, line string, config *IPConfig) error {
	tokens := strings.Split(line, " ")

	if len(tokens) < 2 {
		return newErrString(ln, "routing directive must have format:  routing <type>")
	}
	rt := tokens[1]

	switch rt {
	case "static":
		config.RoutingMode = RoutingTypeStatic
	case "rip":
		config.RoutingMode = RoutingTypeRIP
	default:
		return newErrString(ln, "Invalid routing type:  %s", rt)
	}

	return nil
}

func parseRoute(ln int, line string, config *IPConfig) error {
	var sPrefix, sAddr string

	format := "route <prefix> via <addr>"
	r := strings.NewReader(line)
	n, err := fmt.Fscanf(r, "route %s via %s", &sPrefix, &sAddr)

	if err != nil {
		return err
	}

	if n != 2 {
		return newErrString(ln, "route directive must have format  %s", format)
	}

	prefix, err := netip.ParsePrefix(sPrefix)
	if err != nil {
		return err
	}

	addr, err := netip.ParseAddr(sAddr)
	if err != nil {
		return err
	}

	config.StaticRoutes[prefix] = addr
	return nil
}

func parseInterface(ln int, line string, config *IPConfig) error {
	var sName, sPrefix, sBindAddr string

	format := "interface <name> <prefix> <bindAddr>"

	r := strings.NewReader(line)
	n, err := fmt.Fscanf(r, "interface %s %s %s",
		&sName, &sPrefix, &sBindAddr)

	if err != nil {
		return err
	}

	if n != 3 {
		return newErrString(ln, "interface directive must have format:  %s", format)
	}

	// Check prefix format first
	prefix, err := netip.ParsePrefix(sPrefix)
	if err != nil {
		return err
	}

	addr := prefix.Addr()    // Get addr part
	prefix = prefix.Masked() // Clear add bits for prefix

	addrPort, err := netip.ParseAddrPort(sBindAddr)
	if err != nil {
		return err
	}

	iface := InterfaceConfig{
		Name:           sName,
		AssignedIP:     addr,
		AssignedPrefix: prefix,
		UDPAddr:        addrPort,
	}

	config.Interfaces = append(config.Interfaces, iface)
	return nil
}

func parseNeighbor(ln int, line string, config *IPConfig) error {
	var sDestAddr, sUDPAddr, sIfName string

	format := "neighbor <vip> at <bindAddr> via <interface name>"

	r := strings.NewReader(line)
	n, err := fmt.Fscanf(r, "neighbor %s at %s via %s",
		&sDestAddr, &sUDPAddr, &sIfName)

	if err != nil {
		return err
	}

	if n != 3 {
		newErrString(ln, "neighbor directive must have format:  %s", format)
	}

	destAddr, err := netip.ParseAddr(sDestAddr)
	if err != nil {
		return err
	}

	udpAddr, err := netip.ParseAddrPort(sUDPAddr)
	if err != nil {
		return err
	}

	neighbor := NeighborConfig{
		DestAddr:      destAddr,
		UDPAddr:       udpAddr,
		InterfaceName: sIfName,
	}

	config.Neighbors = append(config.Neighbors, neighbor)

	return nil
}

func newErrString(line int, msg string, args ...any) error {
	_msg := fmt.Sprintf(msg, args...)
	return errors.New(fmt.Sprintf("Parse error on line %d:  %s", line, _msg))
}

func newErr(line int, err error) error {
	return errors.New(fmt.Sprintf("Parse error on line %d:  %s", line, err.Error()))

}

// Parse a configuration file
func ParseConfig(configFile string) (*IPConfig, error) {
	fd, err := os.Open(configFile)
	if err != nil {
		return nil, errors.New("Unable to open file")
	}
	defer fd.Close()

	config := &IPConfig{
		Interfaces:          make([]InterfaceConfig, 0, 1),
		Neighbors:           make([]NeighborConfig, 0, 1),
		OriginatingPrefixes: make([]netip.Prefix, 0, 1),

		RipNeighbors: make([]netip.Addr, 0),
		StaticRoutes: make(map[netip.Prefix]netip.Addr, 0),
	}

	scanner := bufio.NewScanner(fd)
	ln := 0
	for scanner.Scan() {
		ln++

		line := scanner.Text()
		tokens := strings.Split(line, " ")

		if len(tokens) == 0 {
			continue
		}

		// Skip comments
		head := tokens[0]
		if len(head) == 0 || head == "#" || head[0] == '#' {
			continue
		}

		pf, found := parseCommands[head]
		if !found {
			return nil, newErrString(ln, "Unrecognized token %s", head)
		}
		err = pf(ln, line, config)
		if err != nil {
			return nil, newErr(ln, err)
		}
	}

	return config, nil
}