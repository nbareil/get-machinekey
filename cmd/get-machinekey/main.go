package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nbareil/get-machinekey/internal/collector"
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("get-machinekey", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	pretty := flags.Bool("pretty", false, "indent JSON output")
	configPath := flags.String("application-host-config", "", "override applicationHost.config path")
	targetURL := flags.String("url", "", "captured request URL to resolve to an IIS application")
	site := flags.String("site", "", "IIS site override for ambiguous URL bindings")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "get-machinekey: expected at most one positional URL")
		return 2
	}
	if flags.NArg() == 1 {
		if *targetURL != "" {
			fmt.Fprintln(os.Stderr, "get-machinekey: URL supplied both positionally and with -url")
			return 2
		}
		*targetURL = flags.Arg(0)
	}

	report, err := collector.Collect(context.Background(), collector.Options{
		ApplicationHostConfig: *configPath,
		TargetURL:             *targetURL,
		Site:                  *site,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "get-machinekey:", err)
		return 1
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if *pretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "get-machinekey: encode JSON:", err)
		return 1
	}
	return 0
}
