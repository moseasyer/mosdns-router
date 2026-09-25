package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mosdns-router/internal/state"
)

const validPolicyYAML = `schema_version: 1
schedule: "03:00"
foreign:
  default_provider: Quad9 Secure DNSCrypt v2
  ecs: false
cdn:
  ip_version: IPv4
  suppress_aaaa: true
  cloudflare:
    max_candidates: 512
  latency_candidate_count: 10
  combined:
    latency_top: 3
    bandwidth_top: 3
  switch_improvement_percent: 10
  health:
    interval: 120
    failure_threshold: 3
  bandwidth:
    daily_budget: 104857600
    per_candidate_limit: 10485760
    per_candidate_seconds: 3
ech:
  enabled: true
  failure_policy: strict
  stale_grace: 900
  sources:
    - cloudflare-ech.com
dhcp:
  failure_policy: disable-current
cache:
  persistent_dump: false
`

func TestRunValidateSucceedsWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(validPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"validate", "--policy", policyPath}, &stdout, &stderr); got != exitSuccess {
		t.Fatalf("validate exit = %d, want %d (stderr: %s)", got, exitSuccess, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("successful validate wrote output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	after, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("validate changed policy contents: got %q, want %q", after, before)
	}
	if !reflect.DeepEqual(entryNames(beforeEntries), entryNames(afterEntries)) {
		t.Fatalf("validate changed policy directory: got %v, want %v", entryNames(afterEntries), entryNames(beforeEntries))
	}
}

func TestRunValidateRejectsInvalidPolicyWithConfigExit(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	invalid := strings.Replace(validPolicyYAML, "failure_policy: strict", "failure_policy: permissive", 1)
	if err := os.WriteFile(policyPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"validate", "--policy", policyPath}, &stdout, &stderr); got != exitInvalidCLI {
		t.Fatalf("invalid policy exit = %d, want %d", got, exitInvalidCLI)
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid policy wrote stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), policyPath) || !strings.Contains(stderr.String(), "failure_policy") {
		t.Fatalf("invalid policy error lacks useful context: %q", stderr.String())
	}
}

func TestRunStatusRendersOnlyExplicitlySuppliedState(t *testing.T) {
	dir := t.TempDir()
	selectorPath := filepath.Join(dir, "selector.json")
	writeSelectorFixture(t, selectorPath, state.Selector{
		SchemaVersion: 1,
		Generation:    2,
		Mode:          "auto",
		Provider:      "cloudflare",
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"status", "--selector", selectorPath}, &stdout, &stderr); got != exitSuccess {
		t.Fatalf("status exit = %d, want %d (stderr: %s)", got, exitSuccess, stderr.String())
	}

	want := "selector.generation=2\nselector.mode=auto\nselector.provider=cloudflare\nselector.schema_version=1\n"
	if got := stdout.String(); got != want {
		t.Fatalf("status output = %q, want %q", got, want)
	}
	if strings.Contains(stdout.String(), "dhcp.") || strings.Contains(stdout.String(), "ech.") {
		t.Fatalf("status rendered an unsupplied state: %q", stdout.String())
	}
}

func TestRunStatusOrderIsIndependentOfOptionOrder(t *testing.T) {
	dir := t.TempDir()
	selectorPath := filepath.Join(dir, "selector.json")
	dhcpPath := filepath.Join(dir, "dhcp.json")
	echPath := filepath.Join(dir, "ech.json")
	writeSelectorFixture(t, selectorPath, state.Selector{SchemaVersion: 1, Generation: 2, Mode: "manual", Provider: "cloudflare", WinnerIP: "192.0.2.10"})
	writeDHCPFixture(t, dhcpPath, state.DHCPState{SchemaVersion: 1, Generation: 3, Interface: "enp3s0", ConnectionUUID: "uuid", Upstreams: []string{"192.0.2.53"}, ObservedAt: time.Date(2026, time.September, 25, 18, 0, 0, 0, time.UTC), Source: "dhcp4", LastGood: true})
	writeECHFixture(t, echPath, state.ECHState{SchemaVersion: 1, Generation: 4, Source: "cloudflare-ech.com", ExpiresAt: time.Date(2026, time.September, 25, 20, 0, 0, 0, time.UTC), ConfigSHA256: "hash", PublicName: "public.example", Status: "fresh"})

	var firstOut, firstErr, secondOut, secondErr bytes.Buffer
	first := run([]string{"status", "--ech", echPath, "--selector", selectorPath, "--dhcp", dhcpPath}, &firstOut, &firstErr)
	second := run([]string{"status", "--dhcp", dhcpPath, "--ech", echPath, "--selector", selectorPath}, &secondOut, &secondErr)
	if first != exitSuccess || second != exitSuccess {
		t.Fatalf("status exits = %d/%d, stderr = %q / %q", first, second, firstErr.String(), secondErr.String())
	}
	if firstOut.String() != secondOut.String() {
		t.Fatalf("option order changed status output:\nfirst:  %q\nsecond: %q", firstOut.String(), secondOut.String())
	}

	want := "selector.generation=2\nselector.mode=manual\nselector.provider=cloudflare\nselector.schema_version=1\nselector.winner_ip=192.0.2.10\n" +
		"dhcp.connection_uuid=uuid\ndhcp.generation=3\ndhcp.interface=enp3s0\ndhcp.last_good=true\ndhcp.observed_at=2026-09-25T18:00:00Z\ndhcp.schema_version=1\ndhcp.source=dhcp4\ndhcp.upstreams=192.0.2.53\n" +
		"ech.config_sha256=hash\n" +
		"ech.expires_at=2026-09-25T20:00:00Z\n" +
		"ech.generation=4\n" +
		"ech.public_name=public.example\n" +
		"ech.schema_version=1\n" +
		"ech.source=cloudflare-ech.com\n" +
		"ech.status=fresh\n"
	if got := firstOut.String(); got != want {
		t.Fatalf("combined status output:\n got: %q\nwant: %q", got, want)
	}
}

func TestRunStatusReturnsStateExitForMissingState(t *testing.T) {
	dir := t.TempDir()
	selectorPath := filepath.Join(dir, "selector.json")
	missingPath := filepath.Join(dir, "missing.json")
	writeSelectorFixture(t, selectorPath, state.Selector{SchemaVersion: 1, Generation: 1, Mode: "disabled", Provider: "cloudflare"})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"status", "--selector", selectorPath, "--dhcp", missingPath}, &stdout, &stderr); got != exitStateUnavailable {
		t.Fatalf("missing state exit = %d, want %d", got, exitStateUnavailable)
	}
	if stdout.Len() != 0 {
		t.Fatalf("missing state emitted partial stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), missingPath) {
		t.Fatalf("missing state error lacks path: %q", stderr.String())
	}
}

func TestRunStatusRejectsFutureStateFieldWithoutLeakingItsValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.json")
	const futureSecret = "future-private-value-must-not-leak"
	data := `{"schema_version":1,"generation":1,"mode":"auto","provider":"cloudflare","future_private":"` + futureSecret + `"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"status", "--selector", path}, &stdout, &stderr); got != exitStateUnavailable {
		t.Fatalf("future field exit = %d, want %d", got, exitStateUnavailable)
	}
	if stdout.Len() != 0 {
		t.Fatalf("future field emitted status output: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), futureSecret) || strings.Contains(stderr.String(), "future_private") {
		t.Fatalf("future field leaked through stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), path) {
		t.Fatalf("future field error lacks path: %q", stderr.String())
	}
}

func TestRunRejectsInvalidCLIWithExitTwo(t *testing.T) {
	tests := [][]string{
		nil,
		{"unknown"},
		{"validate"},
		{"validate", "--policy"},
		{"status"},
		{"status", "--unknown", "value"},
		{"status", "--selector", ""},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != exitInvalidCLI {
				t.Fatalf("args %v exit = %d, want %d", args, got, exitInvalidCLI)
			}
			if stdout.Len() != 0 {
				t.Fatalf("args %v wrote stdout: %q", args, stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatalf("args %v wrote no diagnostic", args)
			}
		})
	}
}

func TestExitCodeContract(t *testing.T) {
	if exitSuccess != 0 || exitInvalidCLI != 2 || exitStateUnavailable != 3 || exitLockHeld != 4 {
		t.Fatalf("unexpected exit code contract: success=%d invalid=%d state=%d lock=%d", exitSuccess, exitInvalidCLI, exitStateUnavailable, exitLockHeld)
	}
}

func writeSelectorFixture(t *testing.T, path string, value state.Selector) {
	t.Helper()
	writeJSONFixture(t, path, value)
}

func writeDHCPFixture(t *testing.T, path string, value state.DHCPState) {
	t.Helper()
	writeJSONFixture(t, path, value)
}

func writeECHFixture(t *testing.T, path string, value state.ECHState) {
	t.Helper()
	writeJSONFixture(t, path, value)
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
