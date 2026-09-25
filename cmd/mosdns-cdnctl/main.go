package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"mosdns-router/internal/config"
	"mosdns-router/internal/state"
	"mosdns-router/internal/status"
)

const (
	exitSuccess          = 0
	exitInvalidCLI       = 2
	exitStateUnavailable = 3
	exitLockHeld         = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command boundary used by both the executable and focused tests.
// It deliberately returns an exit code instead of terminating the process so
// callers can exercise every CLI outcome in-process.
func run(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 {
		writeCLIError(stderr, "a command is required")
		return exitInvalidCLI
	}

	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	default:
		writeCLIError(stderr, "unknown command %q", args[0])
		return exitInvalidCLI
	}
}

func runValidate(args []string, _ io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "path to the policy YAML file")
	if err := flags.Parse(args); err != nil {
		writeCLIError(stderr, "validate: %v", err)
		return exitInvalidCLI
	}
	if flags.NArg() != 0 {
		writeCLIError(stderr, "validate: unexpected arguments: %s", strings.Join(flags.Args(), " "))
		return exitInvalidCLI
	}
	if *policyPath == "" {
		writeCLIError(stderr, "validate: --policy PATH is required")
		return exitInvalidCLI
	}

	policy, err := config.Load(*policyPath)
	if err != nil {
		writeCLIError(stderr, "validate: %v", err)
		return exitInvalidCLI
	}
	if err := policy.Validate(); err != nil {
		writeCLIError(stderr, "validate: %s: %v", *policyPath, err)
		return exitInvalidCLI
	}
	return exitSuccess
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectorPath := flags.String("selector", "", "path to the selector state")
	dhcpPath := flags.String("dhcp", "", "path to the DHCP state")
	echPath := flags.String("ech", "", "path to the ECH state")
	if err := flags.Parse(args); err != nil {
		writeCLIError(stderr, "status: %v", err)
		return exitInvalidCLI
	}
	if flags.NArg() != 0 {
		writeCLIError(stderr, "status: unexpected arguments: %s", strings.Join(flags.Args(), " "))
		return exitInvalidCLI
	}

	selectorSet, dhcpSet, echSet := suppliedFlags(flags)
	if !selectorSet && !dhcpSet && !echSet {
		writeCLIError(stderr, "status: at least one state path is required")
		return exitInvalidCLI
	}
	if selectorSet && *selectorPath == "" {
		writeCLIError(stderr, "status: --selector PATH must not be empty")
		return exitInvalidCLI
	}
	if dhcpSet && *dhcpPath == "" {
		writeCLIError(stderr, "status: --dhcp PATH must not be empty")
		return exitInvalidCLI
	}
	if echSet && *echPath == "" {
		writeCLIError(stderr, "status: --ech PATH must not be empty")
		return exitInvalidCLI
	}

	// Read every requested state before writing anything. A missing or invalid
	// state therefore cannot leave a misleading partial status report.
	var selector state.Selector
	if selectorSet {
		if err := state.ReadJSON(*selectorPath, &selector); err != nil {
			writeCLIError(stderr, "status selector: %v", err)
			return exitStateUnavailable
		}
	}
	var dhcp state.DHCPState
	if dhcpSet {
		if err := state.ReadJSON(*dhcpPath, &dhcp); err != nil {
			writeCLIError(stderr, "status dhcp: %v", err)
			return exitStateUnavailable
		}
	}
	var ech state.ECHState
	if echSet {
		if err := state.ReadJSON(*echPath, &ech); err != nil {
			writeCLIError(stderr, "status ech: %v", err)
			return exitStateUnavailable
		}
	}

	var rendered bytes.Buffer
	if selectorSet {
		if err := renderNamespaced(&rendered, "selector", func(writer io.Writer) error {
			return status.RenderSelector(writer, selector)
		}); err != nil {
			writeCLIError(stderr, "status selector: render: %v", err)
			return exitStateUnavailable
		}
	}
	if dhcpSet {
		if err := renderNamespaced(&rendered, "dhcp", func(writer io.Writer) error {
			return status.RenderDHCP(writer, dhcp)
		}); err != nil {
			writeCLIError(stderr, "status dhcp: render: %v", err)
			return exitStateUnavailable
		}
	}
	if echSet {
		if err := renderNamespaced(&rendered, "ech", func(writer io.Writer) error {
			return status.RenderECH(writer, ech)
		}); err != nil {
			writeCLIError(stderr, "status ech: render: %v", err)
			return exitStateUnavailable
		}
	}
	if _, err := io.Copy(stdout, &rendered); err != nil {
		writeCLIError(stderr, "status: write output: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

func suppliedFlags(flags *flag.FlagSet) (selector, dhcp, ech bool) {
	flags.Visit(func(current *flag.Flag) {
		switch current.Name {
		case "selector":
			selector = true
		case "dhcp":
			dhcp = true
		case "ech":
			ech = true
		}
	})
	return selector, dhcp, ech
}

func renderNamespaced(output io.Writer, namespace string, render func(io.Writer) error) error {
	var rendered bytes.Buffer
	if err := render(&rendered); err != nil {
		return err
	}
	contents := rendered.String()
	if contents == "" {
		return nil
	}
	contents = strings.TrimSuffix(contents, "\n")
	for _, line := range strings.Split(contents, "\n") {
		if _, err := fmt.Fprintf(output, "%s.%s\n", namespace, line); err != nil {
			return err
		}
	}
	return nil
}

func writeCLIError(output io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(output, format+"\n", args...)
}
