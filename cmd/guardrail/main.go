package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sarnas-it/guardrail/internal/app"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "guardrail scan --base <sha> --head <sha> [--config guardrail.yml] [--sarif out.sarif] [--json out.json]")
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		base       = fs.String("base", "", "base commit SHA")
		head       = fs.String("head", "", "head commit SHA")
		configPath = fs.String("config", "guardrail.yml", "path to guardrail.yml")
		sarifFile  = fs.String("sarif", "", "write SARIF report to file")
		jsonFile   = fs.String("json", "", "write JSON report to file")
		reveal     = fs.Bool("reveal", false, "print full values")
		repoDir    = fs.String("repo", ".", "path to git repository")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Поддержка container action: GitHub передаёт inputs как env INPUT_<NAME>.
	flagOrEnv := func(flagVal, envKey string) string {
		if flagVal != "" {
			return flagVal
		}
		return os.Getenv(envKey)
	}
	*base = flagOrEnv(*base, "INPUT_BASE")
	*head = flagOrEnv(*head, "INPUT_HEAD")
	*configPath = flagOrEnv(*configPath, "INPUT_CONFIG")
	*sarifFile = flagOrEnv(*sarifFile, "INPUT_SARIF_FILE")

	if os.Getenv("GUARDRAIL_REVEAL") == "1" {
		*reveal = true
	}

	code, err := app.Run(*repoDir, *base, *head, *configPath, *sarifFile, *jsonFile, *reveal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guardrail: %v\n", err)
		return code
	}
	return code
}
