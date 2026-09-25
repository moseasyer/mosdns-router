package status

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"mosdns-router/internal/state"
)

func TestRenderSelectorRedactsFieldsOutsideTheStatusContract(t *testing.T) {
	selector := state.Selector{
		SchemaVersion:    1,
		Generation:       7,
		Mode:             "manual",
		Provider:         "cloudflare",
		WinnerIP:         "192.0.2.10",
		WinnerProofUntil: time.Date(2026, time.September, 25, 15, 0, 0, 0, time.UTC),
		FallbackIP:       "198.51.100.20",
		CloudFront:       map[string]string{"private.example": "192.0.2.99"},
		LastSuccess:      time.Date(2026, time.September, 25, 14, 0, 0, 0, time.UTC),
		LastFailure:      "private-failure-must-not-render",
		ConfigSHA256:     "selector-hash-must-not-render",
	}

	var output bytes.Buffer
	if err := RenderSelector(&output, selector); err != nil {
		t.Fatalf("RenderSelector() error = %v", err)
	}

	want := strings.Join([]string{
		"fallback_ip=198.51.100.20",
		"generation=7",
		"last_success=2026-09-25T14:00:00Z",
		"mode=manual",
		"provider=cloudflare",
		"schema_version=1",
		"winner_ip=192.0.2.10",
		"winner_proof_until=2026-09-25T15:00:00Z",
		"",
	}, "\n")
	if got := output.String(); got != want {
		t.Fatalf("RenderSelector() output:\n got: %q\nwant: %q", got, want)
	}
	for _, forbidden := range []string{"cloudfront", "private.example", "last_failure", "selector-hash-must-not-render"} {
		if strings.Contains(output.String(), forbidden) {
			t.Errorf("selector output exposed forbidden value %q: %s", forbidden, output.String())
		}
	}
}

func TestRenderSelectorOmitsEmptyOptionalFieldsAndSortsKeys(t *testing.T) {
	selector := state.Selector{
		SchemaVersion: 1,
		Generation:    0,
		Mode:          "disabled",
		Provider:      "cloudflare",
		FallbackIP:    "",
	}

	var output bytes.Buffer
	if err := RenderSelector(&output, selector); err != nil {
		t.Fatalf("RenderSelector() error = %v", err)
	}

	want := "generation=0\nmode=disabled\nprovider=cloudflare\nschema_version=1\n"
	if got := output.String(); got != want {
		t.Fatalf("RenderSelector() output = %q, want %q", got, want)
	}
	for _, omitted := range []string{"fallback_ip=", "winner_ip=", "winner_proof_until=", "last_success="} {
		if strings.Contains(output.String(), omitted) {
			t.Errorf("empty selector field %q was rendered: %s", omitted, output.String())
		}
	}
}

func TestRenderSelectorNormalizesTimestampsToUTC(t *testing.T) {
	selector := state.Selector{
		SchemaVersion:    1,
		Generation:       1,
		Mode:             "auto",
		Provider:         "cloudflare",
		WinnerProofUntil: time.Date(2026, time.September, 25, 17, 0, 0, 123456789, time.FixedZone("offset", 2*60*60)),
		LastSuccess:      time.Date(2026, time.September, 25, 16, 0, 0, 987654321, time.FixedZone("offset", -3*60*60)),
	}

	var output bytes.Buffer
	if err := RenderSelector(&output, selector); err != nil {
		t.Fatalf("RenderSelector() error = %v", err)
	}

	wantLines := []string{
		"last_success=2026-09-25T19:00:00.987654321Z",
		"winner_proof_until=2026-09-25T15:00:00.123456789Z",
	}
	for _, line := range wantLines {
		if !strings.Contains(output.String(), line) {
			t.Errorf("normalized timestamp line %q missing from %q", line, output.String())
		}
	}
}

func TestRenderDHCPEmitsStableSafeFields(t *testing.T) {
	dhcp := state.DHCPState{
		SchemaVersion:  1,
		Generation:     3,
		Interface:      "enp3s0",
		ConnectionUUID: "connection-1",
		Upstreams:      []string{"192.0.2.53", "2001:db8::53"},
		ObservedAt:     time.Date(2026, time.September, 25, 18, 0, 0, 0, time.UTC),
		Source:         "dhcp4",
		LastGood:       true,
	}

	var output bytes.Buffer
	if err := RenderDHCP(&output, dhcp); err != nil {
		t.Fatalf("RenderDHCP() error = %v", err)
	}

	want := strings.Join([]string{
		"connection_uuid=connection-1",
		"generation=3",
		"interface=enp3s0",
		"last_good=true",
		"observed_at=2026-09-25T18:00:00Z",
		"schema_version=1",
		"source=dhcp4",
		"upstreams=192.0.2.53,2001:db8::53",
		"",
	}, "\n")
	if got := output.String(); got != want {
		t.Fatalf("RenderDHCP() output:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderECHOnlyEmitsTheApprovedRedactedFields(t *testing.T) {
	ech := state.ECHState{
		SchemaVersion: 1,
		Generation:    4,
		Source:        "cloudflare-ech.com",
		FetchedAt:     time.Date(2026, time.September, 25, 19, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, time.September, 25, 20, 0, 0, 0, time.UTC),
		StaleUntil:    time.Date(2026, time.September, 25, 21, 0, 0, 0, time.UTC),
		ConfigSHA256:  "ech-hash",
		PublicName:    "public.example",
		Status:        "fresh",
	}

	var output bytes.Buffer
	if err := RenderECH(&output, ech); err != nil {
		t.Fatalf("RenderECH() error = %v", err)
	}

	want := strings.Join([]string{
		"config_sha256=ech-hash",
		"expires_at=2026-09-25T20:00:00Z",
		"fetched_at=2026-09-25T19:00:00Z",
		"generation=4",
		"public_name=public.example",
		"schema_version=1",
		"source=cloudflare-ech.com",
		"stale_until=2026-09-25T21:00:00Z",
		"status=fresh",
		"",
	}, "\n")
	if got := output.String(); got != want {
		t.Fatalf("RenderECH() output:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderECHOmitsZeroTimestamps(t *testing.T) {
	ech := state.ECHState{SchemaVersion: 1, Generation: 1, Source: "source", Status: "invalid"}

	var output bytes.Buffer
	if err := RenderECH(&output, ech); err != nil {
		t.Fatalf("RenderECH() error = %v", err)
	}

	want := "config_sha256=\ngeneration=1\npublic_name=\nschema_version=1\nsource=source\nstatus=invalid\n"
	if got := output.String(); got != want {
		t.Fatalf("RenderECH() output = %q, want %q", got, want)
	}
}

func TestRenderersReturnWriterErrors(t *testing.T) {
	want := errWriter{}
	if err := RenderSelector(want, state.Selector{SchemaVersion: 1, Mode: "disabled", Provider: "cloudflare"}); err == nil {
		t.Fatal("RenderSelector() returned nil for a failing writer")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}

var errWriteFailed = &writeError{}

type writeError struct{}

func (*writeError) Error() string { return "write failed" }

func TestRenderedLinesAreUniqueAndSorted(t *testing.T) {
	selector := state.Selector{SchemaVersion: 1, Generation: 2, Mode: "auto", Provider: "cloudflare"}
	var output bytes.Buffer
	if err := RenderSelector(&output, selector); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if !reflect.DeepEqual(lines, []string{"generation=2", "mode=auto", "provider=cloudflare", "schema_version=1"}) {
		t.Fatalf("rendered lines are not sorted: %#v", lines)
	}
}
