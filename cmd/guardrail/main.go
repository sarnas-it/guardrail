package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "scan" {
		fmt.Fprintln(os.Stderr, "guardrail scan --base <sha> --head <sha> [--config guardrail.yml]")
		return 2
	}
	fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
	return 2
}
