// Command check runs a built mosdns-router binary's build-info subcommand and
// refuses to pass when the binary still carries the compiled-in placeholders.
// It is the build-side counterpart of the runtime command: a build that forgot
// to inject its metadata fails verification instead of shipping an
// unidentifiable binary.
//
// Usage:
//
//	go run ./internal/buildinfo/cmd/check BINARY
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"mosdns-router/internal/buildinfo"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: check BINARY")
	}

	command := exec.Command(args[0], "build-info")
	reported, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return fmt.Errorf("%s build-info: %w: %s", args[0], err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return fmt.Errorf("%s build-info: %w", args[0], err)
	}

	var info buildinfo.Info
	if err := json.Unmarshal(reported, &info); err != nil {
		return fmt.Errorf("%s build-info: decode: %w", args[0], err)
	}
	if err := buildinfo.Check(info); err != nil {
		return fmt.Errorf("%s build-info: %w", args[0], err)
	}
	_, err = fmt.Fprintf(output, "build-info ok: version=%s revision=%s build_time=%s\n", info.Version, info.Revision, info.BuildTime)
	return err
}
