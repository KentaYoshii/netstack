package main

import (
	"log"
	"os"
	"netstack/pkg/lnxconfig"
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
	log.Println(lnxConfig.Interfaces[0].AssignedIP.String())
	for {

	}
}