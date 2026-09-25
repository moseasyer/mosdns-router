package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWriteJSONAtomicReplacesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.json")
	first := NewSelector(1, "auto", "cloudflare", time.Date(2026, time.September, 25, 1, 2, 3, 0, time.UTC))
	if err := WriteJSONAtomic(path, first); err != nil {
		t.Fatalf("write first state: %v", err)
	}
	second := NewSelector(2, "manual", "cloudfront", time.Date(2026, time.September, 25, 2, 3, 4, 0, time.UTC))
	second.WinnerIP = "192.0.2.10"
	second.FallbackIP = "198.51.100.10"
	if err := WriteJSONAtomic(path, second); err != nil {
		t.Fatalf("write replacement state: %v", err)
	}

	var got Selector
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("read replacement state: %v", err)
	}
	if got.Generation != 2 || got.Mode != "manual" || got.Provider != "cloudfront" || got.WinnerIP != "192.0.2.10" || got.FallbackIP != "198.51.100.10" {
		t.Fatalf("replacement state = %#v", got)
	}
	assertOnlyTargetEntry(t, filepath.Dir(path), filepath.Base(path))
}

func TestReadJSONRejectsTruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.json")
	valid := NewSelector(3, "auto", "cloudflare", time.Date(2026, time.September, 25, 3, 0, 0, 0, time.UTC))
	validBytes, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	truncated := validBytes[:len(validBytes)/2]
	if err := os.WriteFile(path, truncated, 0600); err != nil {
		t.Fatal(err)
	}
	var got Selector
	if err := ReadJSON(path, &got); err == nil {
		t.Fatal("expected truncated JSON to be rejected")
	} else if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not include path %q", err, path)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, truncated) {
		t.Fatalf("truncated file changed: got %q, want %q", after, truncated)
	}
}

func TestWriteJSONAtomicNeverLeavesTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	value := NewSelector(1, "disabled", "cloudflare", time.Date(2026, time.September, 25, 4, 0, 0, 0, time.UTC))
	if err := WriteJSONAtomic(path, value); err != nil {
		t.Fatal(err)
	}
	assertOnlyTargetEntry(t, dir, "state.json")

	invalidPath := filepath.Join(dir, "invalid.json")
	invalid := Selector{SchemaVersion: SchemaVersion, Mode: "invalid", Provider: "cloudflare"}
	if err := WriteJSONAtomic(invalidPath, invalid); err == nil {
		t.Fatal("expected invalid state write to fail")
	}
	if _, err := os.Stat(invalidPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid state target exists, stat error = %v", err)
	}
	assertNoTempEntries(t, dir)
}

func TestWriteJSONAtomicPreventsGenerationRollbackForSameType(t *testing.T) {
	t.Run("lower generation is rejected without overwrite", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "selector.json")
		current := NewSelector(7, "auto", "cloudflare", time.Date(2026, time.September, 25, 5, 0, 0, 0, time.UTC))
		if err := WriteJSONAtomic(path, current); err != nil {
			t.Fatal(err)
		}
		before := readFileBytes(t, path)
		rollback := current
		rollback.Generation = 6
		rollback.WinnerIP = "192.0.2.99"
		if err := WriteJSONAtomic(path, rollback); err == nil {
			t.Fatal("expected generation rollback to be rejected")
		}
		if after := readFileBytes(t, path); !bytes.Equal(after, before) {
			t.Fatalf("rollback changed target: got %q, want %q", after, before)
		}
		assertOnlyTargetEntry(t, dir, filepath.Base(path))
	})

	t.Run("equal generation is allowed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "selector.json")
		current := NewSelector(7, "auto", "cloudflare", time.Date(2026, time.September, 25, 5, 0, 0, 0, time.UTC))
		if err := WriteJSONAtomic(path, current); err != nil {
			t.Fatal(err)
		}
		current.WinnerIP = "192.0.2.1"
		if err := WriteJSONAtomic(path, current); err != nil {
			t.Fatalf("equal-generation replacement rejected: %v", err)
		}
	})

	t.Run("different existing type is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		existing := BandwidthBudgetState{SchemaVersion: SchemaVersion, LocalDate: "2026-09-25", LimitBytes: 10, UsedBytes: 2}
		if err := WriteJSONAtomic(path, existing); err != nil {
			t.Fatal(err)
		}
		before := readFileBytes(t, path)
		candidate := NewSelector(1, "auto", "cloudflare", time.Date(2026, time.September, 25, 6, 0, 0, 0, time.UTC))
		if err := WriteJSONAtomic(path, candidate); err == nil {
			t.Fatal("expected different existing type to be rejected")
		}
		if after := readFileBytes(t, path); !bytes.Equal(after, before) {
			t.Fatalf("different-type write changed target: got %q, want %q", after, before)
		}
	})

	t.Run("corrupt existing state is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		before := []byte("{ this is not valid JSON")
		if err := os.WriteFile(path, before, 0600); err != nil {
			t.Fatal(err)
		}
		candidate := NewSelector(1, "auto", "cloudflare", time.Date(2026, time.September, 25, 6, 0, 0, 0, time.UTC))
		if err := WriteJSONAtomic(path, candidate); err == nil {
			t.Fatal("expected corrupt existing state to be rejected")
		}
		if after := readFileBytes(t, path); !bytes.Equal(after, before) {
			t.Fatalf("corrupt-state write changed target: got %q, want %q", after, before)
		}
	})

	t.Run("absent file accepts any uint64 generation", func(t *testing.T) {
		for _, generation := range []uint64{0, 1, ^uint64(0)} {
			path := filepath.Join(t.TempDir(), "selector.json")
			candidate := NewSelector(generation, "auto", "cloudflare", time.Date(2026, time.September, 25, 7, 0, 0, 0, time.UTC))
			if err := WriteJSONAtomic(path, candidate); err != nil {
				t.Errorf("absent path rejected generation %d: %v", generation, err)
			}
		}
	})
}

func TestWriteJSONAtomicPreventsRollbackForEveryGenerationBearingType(t *testing.T) {
	tests := []struct {
		name    string
		current any
		lower   any
	}{
		{
			name:    "DHCP",
			current: NewDHCPState(5, "eth0", "uuid", []string{"192.0.2.1"}, testFetchedAt, "dhcp4", true),
			lower:   NewDHCPState(4, "eth0", "uuid", []string{"192.0.2.2"}, testFetchedAt, "dhcp4", true),
		},
		{
			name:    "selector",
			current: NewSelector(5, "auto", "cloudflare", time.Time{}),
			lower:   NewSelector(4, "auto", "cloudflare", time.Time{}),
		},
		{
			name:    "ECH",
			current: NewECHState(5, "cloudflare-ech.com", testFetchedAt, testFetchedAt.Add(time.Hour), testFetchedAt.Add(2*time.Hour), testSHA256, "public.example", "fresh"),
			lower:   NewECHState(4, "cloudflare-ech.com", testFetchedAt, testFetchedAt.Add(time.Hour), testFetchedAt.Add(2*time.Hour), testSHA256, "public.example", "fresh"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := WriteJSONAtomic(path, tt.current); err != nil {
				t.Fatal(err)
			}
			before := readFileBytes(t, path)
			if err := WriteJSONAtomic(path, tt.lower); err == nil {
				t.Fatal("expected generation rollback to be rejected")
			}
			if after := readFileBytes(t, path); !bytes.Equal(after, before) {
				t.Fatal("generation rollback changed target")
			}
		})
	}
}

func TestWriteJSONAtomicValidatesAllSupportedTypesBeforeCreatingTarget(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "DHCP", value: DHCPState{SchemaVersion: SchemaVersion, Upstreams: []string{"bad"}}},
		{name: "selector", value: Selector{SchemaVersion: SchemaVersion, Mode: "invalid", Provider: "cloudflare"}},
		{name: "ECH", value: ECHState{SchemaVersion: SchemaVersion, Status: "expired"}},
		{name: "budget", value: BandwidthBudgetState{SchemaVersion: SchemaVersion, LocalDate: "not-a-date", UsedBytes: -1}},
		{name: "health", value: HealthState{SchemaVersion: SchemaVersion, ConsecutiveFailures: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			if err := WriteJSONAtomic(path, tt.value); err == nil {
				t.Fatal("expected validation error")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid state target exists, stat error = %v", err)
			}
			assertNoTempEntries(t, dir)
		})
	}
}

func TestReadJSONRoundTripsAllStateTypes(t *testing.T) {
	dir := t.TempDir()
	observedAt := time.Date(2026, time.September, 25, 8, 0, 0, 123, time.FixedZone("offset", -7*60*60))
	wantDHCP := NewDHCPState(11, "eth0", "uuid-11", []string{"192.0.2.1", "2001:db8::1"}, observedAt, "dhcp6", true)
	wantSelector := NewSelector(12, "manual", "cloudfront", observedAt)
	wantSelector.WinnerIP = "192.0.2.12"
	wantSelector.FallbackIP = "198.51.100.12"
	wantECH := NewECHState(13, "cloudflare-ech.com", observedAt, observedAt.Add(time.Hour), observedAt.Add(2*time.Hour), testSHA256, "public.example", "stale")
	wantBudget := BandwidthBudgetState{SchemaVersion: SchemaVersion, LocalDate: "2026-09-25", LimitBytes: 1000, UsedBytes: 250}
	wantHealth := HealthState{SchemaVersion: SchemaVersion, Healthy: true, ConsecutiveFailures: 0, LastSuccess: observedAt}

	tests := []struct {
		name        string
		value       any
		destination func() any
		check       func(*testing.T, any)
	}{
		{name: "DHCP", value: wantDHCP, destination: func() any { return new(DHCPState) }, check: func(t *testing.T, value any) {
			got := value.(*DHCPState)
			if got.Generation != wantDHCP.Generation || got.Interface != wantDHCP.Interface || !reflect.DeepEqual(got.Upstreams, wantDHCP.Upstreams) || !got.ObservedAt.Equal(wantDHCP.ObservedAt) {
				t.Errorf("DHCP round trip = %#v", got)
			}
		}},
		{name: "selector", value: wantSelector, destination: func() any { return new(Selector) }, check: func(t *testing.T, value any) {
			got := value.(*Selector)
			if got.Generation != wantSelector.Generation || got.Mode != wantSelector.Mode || got.WinnerIP != wantSelector.WinnerIP || !got.LastSuccess.Equal(wantSelector.LastSuccess) {
				t.Errorf("selector round trip = %#v", got)
			}
		}},
		{name: "ECH", value: wantECH, destination: func() any { return new(ECHState) }, check: func(t *testing.T, value any) {
			got := value.(*ECHState)
			if got.Generation != wantECH.Generation || got.Status != wantECH.Status || !got.FetchedAt.Equal(wantECH.FetchedAt) || !got.ExpiresAt.Equal(wantECH.ExpiresAt) {
				t.Errorf("ECH round trip = %#v", got)
			}
		}},
		{name: "budget", value: wantBudget, destination: func() any { return new(BandwidthBudgetState) }, check: func(t *testing.T, value any) {
			got := value.(*BandwidthBudgetState)
			if *got != wantBudget {
				t.Errorf("budget round trip = %#v, want %#v", got, wantBudget)
			}
		}},
		{name: "health", value: wantHealth, destination: func() any { return new(HealthState) }, check: func(t *testing.T, value any) {
			got := value.(*HealthState)
			if got.Healthy != wantHealth.Healthy || got.ConsecutiveFailures != wantHealth.ConsecutiveFailures || !got.LastSuccess.Equal(wantHealth.LastSuccess) {
				t.Errorf("health round trip = %#v", got)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".json")
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			destination := tt.destination()
			if err := ReadJSON(path, destination); err != nil {
				t.Fatalf("read %s state: %v", tt.name, err)
			}
			tt.check(t, destination)
		})
	}
}

func TestReadJSONRejectsSchemaMismatchForEveryStateType(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		destination func() any
	}{
		{name: "DHCP", value: DHCPState{SchemaVersion: 2, Upstreams: []string{"192.0.2.1"}}, destination: func() any { return new(DHCPState) }},
		{name: "selector", value: Selector{SchemaVersion: 2, Mode: "auto", Provider: "cloudflare"}, destination: func() any { return new(Selector) }},
		{name: "ECH", value: ECHState{SchemaVersion: 2, Status: "fresh"}, destination: func() any { return new(ECHState) }},
		{name: "budget", value: BandwidthBudgetState{SchemaVersion: 2, LocalDate: "2026-09-25"}, destination: func() any { return new(BandwidthBudgetState) }},
		{name: "health", value: HealthState{SchemaVersion: 2}, destination: func() any { return new(HealthState) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := ReadJSON(path, tt.destination()); err == nil {
				t.Fatal("expected schema mismatch error")
			}
		})
	}
}

func TestReadJSONDoesNotLeakInvalidTimestampValue(t *testing.T) {
	secret := "timestamp-secret-must-not-appear"
	path := filepath.Join(t.TempDir(), "dhcp.json")
	data := `{"schema_version":1,"generation":1,"interface":"eth0","connection_uuid":"uuid","upstreams":["192.0.2.1"],"observed_at":"` + secret + `","source":"dhcp4","last_good":true}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var got DHCPState
	err := ReadJSON(path, &got)
	if err == nil {
		t.Fatal("expected invalid timestamp error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked timestamp contents: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not include path %q", err, path)
	}
}

func TestReadJSONLeavesDestinationUnchangedWhenValidationFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"generation":2,"mode":"invalid","provider":"cloudflare"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got := NewSelector(1, "auto", "cloudflare", time.Date(2026, time.September, 25, 13, 0, 0, 0, time.UTC))
	before := got
	if err := ReadJSON(path, &got); err == nil {
		t.Fatal("expected invalid state error")
	}
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("invalid read changed destination: got %#v, want %#v", got, before)
	}
}

func TestReadJSONLeavesDestinationUnchangedWhenCloseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	valid := NewSelector(2, "auto", "cloudflare", time.Date(2026, time.September, 25, 14, 0, 0, 0, time.UTC))
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got := NewSelector(1, "manual", "cloudflare", time.Date(2026, time.September, 25, 13, 0, 0, 0, time.UTC))
	before := got
	injected := errors.New("injected read close failure")
	ops := defaultReadFileOps()
	ops.open = func(openPath string) (io.ReadCloser, error) {
		file, openErr := os.Open(openPath)
		if openErr != nil {
			return nil, openErr
		}
		return &closeErrorReadCloser{ReadCloser: file, closeErr: injected}, nil
	}
	if err := readJSONWithOps(path, &got, ops); !errors.Is(err, injected) {
		t.Fatalf("read error = %v, want injected close error", err)
	}
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("close failure changed destination: got %#v, want %#v", got, before)
	}
}

func TestReadJSONRejectsUnknownFieldsTrailingDataAndInvalidState(t *testing.T) {
	base := `{"schema_version":1,"generation":4,"mode":"auto","provider":"cloudflare"}`
	tests := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"schema_version":1,"generation":4,"mode":"auto","provider":"cloudflare","sensitive":"state-content-must-not-be-logged"}`},
		{name: "trailing data", data: base + ` {"generation":5}`},
		{name: "truncated", data: base[:len(base)-2]},
		{name: "invalid state", data: `{"schema_version":1,"generation":4,"mode":"invalid","provider":"cloudflare"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			var got Selector
			err := ReadJSON(path, &got)
			if err == nil {
				t.Fatal("expected strict read error")
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("error %q does not include path %q", err, path)
			}
			if strings.Contains(err.Error(), "state-content-must-not-be-logged") {
				t.Fatalf("error leaked file contents: %v", err)
			}
		})
	}
}

// Every destination the strict reader accepts must be validated by the same
// rules the writer enforces, so a hand-edited or truncated-on-write state file
// cannot smuggle an unusable value into a fail-closed consumer.
func TestReadJSONValidatesEveryStateType(t *testing.T) {
	tests := []struct {
		name        string
		valid       string
		invalid     string
		destination func() any
	}{
		{
			name: "DHCP",
			valid: `{"schema_version":1,"generation":1,"interface":"enp3s0","connection_uuid":"connection-1",` +
				`"upstreams":["192.0.2.53"],"observed_at":"2026-09-25T10:00:00Z","source":"dhcp4","last_good":true}`,
			invalid: `{"schema_version":1,"generation":1,"interface":"enp3s0","connection_uuid":"connection-1",` +
				`"upstreams":["127.0.0.53"],"observed_at":"2026-09-25T10:00:00Z","source":"dhcp4","last_good":true}`,
			destination: func() any { return new(DHCPState) },
		},
		{
			name: "selector",
			valid: `{"schema_version":1,"generation":1,"mode":"auto","provider":"cloudfront",` +
				`"cloudfront":{"distribution.example":"1.2.3.4"},"last_success":"2026-09-25T10:00:00Z","config_sha256":"` + testSHA256 + `"}`,
			invalid: `{"schema_version":1,"generation":1,"mode":"auto","provider":"cloudfront",` +
				`"cloudfront":{"distribution.example":"10.1.2.3"},"last_success":"2026-09-25T10:00:00Z"}`,
			destination: func() any { return new(Selector) },
		},
		{
			name: "ECH",
			valid: `{"schema_version":1,"generation":1,"source":"cloudflare-ech.com","fetched_at":"2026-09-25T10:00:00Z",` +
				`"expires_at":"2026-09-25T11:00:00Z","stale_until":"2026-09-25T12:00:00Z","config_sha256":"` + testSHA256 + `",` +
				`"public_name":"public.example","status":"fresh"}`,
			invalid: `{"schema_version":1,"generation":1,"source":"cloudflare-ech.com","fetched_at":"2026-09-25T12:00:00Z",` +
				`"expires_at":"2026-09-25T11:00:00Z","stale_until":"2026-09-25T12:00:00Z","config_sha256":"` + testSHA256 + `",` +
				`"public_name":"public.example","status":"fresh"}`,
			destination: func() any { return new(ECHState) },
		},
		{
			name:        "budget",
			valid:       `{"schema_version":1,"local_date":"2026-09-25","limit_bytes":104857600,"used_bytes":250}`,
			invalid:     `{"schema_version":1,"local_date":"2026-09-25","limit_bytes":104857600,"used_bytes":-1}`,
			destination: func() any { return new(BandwidthBudgetState) },
		},
		{
			name:        "health",
			valid:       `{"schema_version":1,"healthy":true,"consecutive_failures":0,"last_success":"2026-09-25T10:00:00Z"}`,
			invalid:     `{"schema_version":1,"healthy":true,"consecutive_failures":-1}`,
			destination: func() any { return new(HealthState) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validPath := filepath.Join(t.TempDir(), "valid.json")
			if err := os.WriteFile(validPath, []byte(tt.valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ReadJSON(validPath, tt.destination()); err != nil {
				t.Fatalf("valid %s document rejected: %v", tt.name, err)
			}

			invalidPath := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(invalidPath, []byte(tt.invalid), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ReadJSON(invalidPath, tt.destination()); err == nil {
				t.Fatalf("invalid %s document accepted", tt.name)
			}
		})
	}
}

// `omitempty` has never applied to a struct, so a zero timestamp used to be
// encoded as the literal year 1. A consumer that treats any present timestamp as
// a real observation would then act on a value that never happened, so a zero
// time must be absent from the encoded document entirely.
func TestZeroTimestampsAreOmittedFromEncodedState(t *testing.T) {
	t.Run("selector", func(t *testing.T) {
		zero := Selector{SchemaVersion: SchemaVersion, Generation: 3, Mode: "disabled", Provider: "cloudflare"}
		data, err := json.Marshal(zero)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"winner_proof_until", "last_success"} {
			if strings.Contains(string(data), `"`+key+`"`) {
				t.Errorf("zero timestamp was encoded as %s: %s", key, data)
			}
		}
		if !strings.Contains(string(data), `"generation":3`) {
			t.Errorf("non-time fields are missing from %s", data)
		}

		set := zero
		set.WinnerProofUntil = time.Date(2026, time.September, 25, 13, 0, 0, 0, time.UTC)
		set.LastSuccess = time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
		data, err = json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"winner_proof_until":"2026-09-25T13:00:00Z"`, `"last_success":"2026-09-25T12:00:00Z"`} {
			if !strings.Contains(string(data), want) {
				t.Errorf("set timestamp %s is missing from %s", want, data)
			}
		}
	})

	t.Run("health", func(t *testing.T) {
		zero := HealthState{SchemaVersion: SchemaVersion, Healthy: true}
		data, err := json.Marshal(zero)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"last_success", "last_failure"} {
			if strings.Contains(string(data), `"`+key+`"`) {
				t.Errorf("zero timestamp was encoded as %s: %s", key, data)
			}
		}

		set := zero
		set.LastSuccess = time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
		set.LastFailure = time.Date(2026, time.September, 25, 12, 30, 0, 0, time.UTC)
		data, err = json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"last_success":"2026-09-25T12:00:00Z"`, `"last_failure":"2026-09-25T12:30:00Z"`} {
			if !strings.Contains(string(data), want) {
				t.Errorf("set timestamp %s is missing from %s", want, data)
			}
		}
	})
}

// A document written without the optional keys must still round-trip, so the
// omission changes the encoding and not the meaning.
func TestReadJSONAcceptsStateWithoutOptionalTimestampKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"generation":4,"mode":"auto","provider":"cloudflare"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var got Selector
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("read state without optional timestamps: %v", err)
	}
	if !got.LastSuccess.IsZero() || !got.WinnerProofUntil.IsZero() {
		t.Fatalf("omitted timestamps were not read as zero: %#v", got)
	}
}

func TestWriteJSONAtomicCreatesParentAndUsesRequiredModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "state.json")
	value := NewSelector(1, "disabled", "cloudflare", time.Date(2026, time.September, 25, 9, 0, 0, 0, time.UTC))
	if err := WriteJSONAtomic(path, value); err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := parentInfo.Mode().Perm(); got != 0750 {
		t.Fatalf("parent mode = %04o, want 0750", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0640 {
		t.Fatalf("file mode = %04o, want 0640", got)
	}
}

func TestWriteJSONAtomicPropagatesFileSyncFailureAndCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := NewSelector(5, "auto", "cloudflare", time.Date(2026, time.September, 25, 10, 0, 0, 0, time.UTC))
	if err := WriteJSONAtomic(path, old); err != nil {
		t.Fatal(err)
	}
	before := readFileBytes(t, path)
	injected := errors.New("injected file sync failure")
	ops := defaultAtomicFileOps()
	calls := 0
	ops.syncFile = func(*os.File) error {
		calls++
		return injected
	}
	newState := old
	newState.Generation = 6
	err := writeJSONAtomicWithOps(path, newState, ops)
	if !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected sync error", err)
	}
	if calls != 1 {
		t.Fatalf("file sync called %d times, want once", calls)
	}
	if after := readFileBytes(t, path); !bytes.Equal(after, before) {
		t.Fatalf("file-sync failure changed target")
	}
	assertOnlyTargetEntry(t, dir, filepath.Base(path))
}

func TestWriteJSONAtomicPropagatesDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	value := NewSelector(1, "auto", "cloudflare", time.Date(2026, time.September, 25, 11, 0, 0, 0, time.UTC))
	injected := errors.New("injected directory sync failure")
	ops := defaultAtomicFileOps()
	ops.syncDir = func(string) error { return injected }
	if err := writeJSONAtomicWithOps(path, value, ops); !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected directory sync error", err)
	}
	var got Selector
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("read state after directory-sync error: %v", err)
	}
	if got.Generation != 1 {
		t.Fatalf("read generation = %d, want 1", got.Generation)
	}
	assertOnlyTargetEntry(t, filepath.Dir(path), filepath.Base(path))
}

func TestWriteJSONAtomicRestoresExistingTargetWhenDirectorySyncFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := NewSelector(5, "auto", "cloudflare", time.Date(2026, time.September, 25, 15, 0, 0, 0, time.UTC))
	old.WinnerIP = "192.0.2.5"
	if err := WriteJSONAtomic(path, old); err != nil {
		t.Fatal(err)
	}
	before := readFileBytes(t, path)

	candidate := old
	candidate.Generation = 6
	candidate.WinnerIP = "192.0.2.6"
	injected := errors.New("injected replacement directory sync failure")
	candidateRenamed := false
	syncCalls := 0
	ops := defaultAtomicFileOps()
	ops.rename = func(oldPath, newPath string) error {
		err := os.Rename(oldPath, newPath)
		if err == nil && newPath == path {
			candidateRenamed = true
		}
		return err
	}
	ops.syncDir = func(string) error {
		if !candidateRenamed {
			return errors.New("directory sync ran before candidate rename")
		}
		syncCalls++
		if syncCalls == 1 {
			return injected
		}
		return nil
	}

	if err := writeJSONAtomicWithOps(path, candidate, ops); !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected directory sync error", err)
	}
	if !candidateRenamed {
		t.Fatal("test did not exercise post-rename directory sync")
	}
	if after := readFileBytes(t, path); !bytes.Equal(after, before) {
		t.Fatalf("directory-sync failure changed target: got %q, want %q", after, before)
	}
	var got Selector
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("read restored state: %v", err)
	}
	if got.Generation != old.Generation || got.WinnerIP != old.WinnerIP {
		t.Fatalf("restored state = %#v, want generation %d and winner %q", got, old.Generation, old.WinnerIP)
	}
	assertOnlyTargetEntry(t, dir, filepath.Base(path))
}

func TestWriteJSONAtomicPropagatesRenameFailureWithoutOverwriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := NewSelector(5, "auto", "cloudflare", time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC))
	if err := WriteJSONAtomic(path, old); err != nil {
		t.Fatal(err)
	}
	before := readFileBytes(t, path)
	injected := errors.New("injected rename failure")
	ops := defaultAtomicFileOps()
	ops.rename = func(string, string) error { return injected }
	newState := old
	newState.Generation = 6
	if err := writeJSONAtomicWithOps(path, newState, ops); !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected rename error", err)
	}
	if after := readFileBytes(t, path); !bytes.Equal(after, before) {
		t.Fatal("rename failure changed target")
	}
	assertOnlyTargetEntry(t, filepath.Dir(path), filepath.Base(path))
}

// A temporary file or a state backup that cannot be removed leaves a readable
// copy of runtime state behind in the state directory, so a removal failure has
// to reach the caller instead of being discarded by the cleanup path. The
// original failure must still be reported.
func TestWriteJSONAtomicReportsTemporaryFileRemovalFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	value := NewSelector(1, "auto", "cloudflare", testFetchedAt)
	injectedSync := errors.New("injected file sync failure")
	injectedRemove := errors.New("injected temporary removal failure")
	ops := defaultAtomicFileOps()
	ops.syncFile = func(*os.File) error { return injectedSync }
	ops.remove = func(string) error { return injectedRemove }

	err := writeJSONAtomicWithOps(path, value, ops)
	if !errors.Is(err, injectedSync) {
		t.Fatalf("write error = %v, want it to report the injected sync failure", err)
	}
	if !errors.Is(err, injectedRemove) {
		t.Fatalf("write error = %v, want it to report the temporary removal failure", err)
	}
}

func TestWriteJSONAtomicReportsBackupRemovalFailureAfterAFailedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := NewSelector(5, "auto", "cloudflare", testFetchedAt)
	if err := WriteJSONAtomic(path, old); err != nil {
		t.Fatal(err)
	}
	before := readFileBytes(t, path)

	candidate := old
	candidate.Generation = 6
	injectedRename := errors.New("injected rename failure")
	injectedRemove := errors.New("injected backup removal failure")
	ops := defaultAtomicFileOps()
	ops.rename = func(string, string) error { return injectedRename }
	ops.remove = func(name string) error {
		if strings.Contains(name, ".bak") {
			return injectedRemove
		}
		return os.Remove(name)
	}

	err := writeJSONAtomicWithOps(path, candidate, ops)
	if !errors.Is(err, injectedRename) {
		t.Fatalf("write error = %v, want it to report the injected rename failure", err)
	}
	if !errors.Is(err, injectedRemove) {
		t.Fatalf("write error = %v, want it to report the backup removal failure", err)
	}
	if after := readFileBytes(t, path); !bytes.Equal(after, before) {
		t.Fatal("failed write changed the target")
	}
}

func TestWriteJSONAtomicReportsBackupRemovalFailureAfterASuccessfulWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := NewSelector(5, "auto", "cloudflare", testFetchedAt)
	if err := WriteJSONAtomic(path, old); err != nil {
		t.Fatal(err)
	}

	candidate := old
	candidate.Generation = 6
	injectedRemove := errors.New("injected backup removal failure")
	ops := defaultAtomicFileOps()
	ops.remove = func(name string) error {
		if strings.Contains(name, ".bak") {
			return injectedRemove
		}
		return os.Remove(name)
	}

	if err := writeJSONAtomicWithOps(path, candidate, ops); !errors.Is(err, injectedRemove) {
		t.Fatalf("write error = %v, want it to report the backup removal failure", err)
	}
	var got Selector
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("read state after a committed write: %v", err)
	}
	if got.Generation != 6 {
		t.Fatalf("read generation = %d, want 6", got.Generation)
	}
}

func TestWriteJSONAtomicRejectsUnsupportedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := WriteJSONAtomic(path, struct{ Value string }{Value: "not state"}); err == nil {
		t.Fatal("expected unsupported value error")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported value created target, stat error = %v", err)
	}
	assertNoTempEntries(t, filepath.Dir(path))
}

func assertOnlyTargetEntry(t *testing.T, dir, target string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != target {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("directory entries = %#v, want only %q", names, target)
	}
}

func assertNoTempEntries(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") || strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("temporary entry left behind: %q", entry.Name())
		}
	}
}

type closeErrorReadCloser struct {
	io.ReadCloser
	closeErr error
}

func (file *closeErrorReadCloser) Close() error {
	if err := file.ReadCloser.Close(); err != nil {
		return err
	}
	return file.closeErr
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
