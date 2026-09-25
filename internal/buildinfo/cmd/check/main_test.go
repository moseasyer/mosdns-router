package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checker is only useful if it exercises the real binary: it has to run the
// build-info subcommand, parse the JSON it prints, and refuse placeholder
// metadata. The stand-in below is a real executable, so the exec path, the exit
// status handling, and the JSON decoding are all covered without rebuilding the
// whole router for every case.
func TestRunAcceptsInjectedMetadataFromTheBinary(t *testing.T) {
	binary := writeStandIn(t, `{"version":"0.1.0","revision":"1c3a9b0d2f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b","build_time":"2026-09-25T21:15:00Z"}`)

	var output bytes.Buffer
	if err := run([]string{binary}, &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	want := "build-info ok: version=0.1.0 revision=1c3a9b0d2f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b build_time=2026-09-25T21:15:00Z\n"
	if got := output.String(); got != want {
		t.Fatalf("run() output = %q, want %q", got, want)
	}
}

func TestRunRejectsPlaceholderMetadata(t *testing.T) {
	binary := writeStandIn(t, `{"version":"dev","revision":"unknown","build_time":"unknown"}`)

	var output bytes.Buffer
	err := run([]string{binary}, &output)
	if err == nil {
		t.Fatal("expected the placeholder metadata to be refused")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("error %q does not name the offending field", err)
	}
	if output.Len() != 0 {
		t.Fatalf("refused build reported success output: %q", output.String())
	}
}

func TestRunRejectsUnparsableAndMissingOutput(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{name: "not JSON", script: `echo "build-info: not json"`},
		{name: "empty output", script: `exit 0`},
		{name: "failing command", script: `echo "unknown command" >&2; exit 2`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binary := writeStandIn(t, "")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+tt.script+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{binary}, &bytes.Buffer{}); err == nil {
				t.Fatalf("expected %s to be refused", tt.name)
			}
		})
	}
}

func TestRunRejectsMissingOrAmbiguousArguments(t *testing.T) {
	for _, args := range [][]string{nil, {}, {""}, {"a", "b"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("expected an usage error for %v", args)
		}
	}
}

func TestRunReportsAMissingBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent-binary")
	if err := run([]string{missing}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}

func writeStandIn(t *testing.T, output string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mosdns-router-stand-in")
	script := "#!/bin/sh\ncat <<'JSON'\n" + output + "\nJSON\n"
	if output == "" {
		script = "#!/bin/sh\nexit 0\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
