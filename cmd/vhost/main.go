package main

import (
	"log"
	"os"
	"netstack/pkg/ipstack"
	"netstack/pkg/repl"
	"netstack/pkg/util"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage:  %s --config <linksfile>\n", os.Args[0])
	}
	// Parse the file
	lnxConfig, err := util.ParseConfig(os.Args[2])
	if err != nil {
		log.Fatalln(err)
	}
	// Create the stack
	ipStack := ipstack.CreateIPStack()
	// Initialize the stack
	ipStack.Initialize(lnxConfig)

	// Start the REPL
	r := repl.CreateREPL(ipStack)
	r.StartREPL()
}