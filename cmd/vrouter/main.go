package main

import (
	"log"
	"os"
	"netstack/pkg/lnxconfig"
	"netstack/pkg/ipstack"
	"netstack/pkg/repl"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage:  %s --config <linksfile>\n", os.Args[0])
	}
	// Parse the file
	lnxConfig, err := lnxconfig.ParseConfig(os.Args[2])
	if err != nil {
		log.Fatalln(err)
	}
	// Create the ipstack
	ipStack := ipstack.CreateIPStack()
	// Initialize the ipstack
	ipStack.Initialize(lnxConfig)

	// Start the REPL
	r := repl.CreateREPL(ipStack)
	r.StartREPL()
}