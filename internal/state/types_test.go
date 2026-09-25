package state

import (
	"reflect"
	"testing"
	"time"
)

func TestConstructorsSetSchemaAndNormalizeTimestamps(t *testing.T) {
	location := time.FixedZone("test", 2*60*60)
	observedAt := time.Date(2026, time.September, 25, 12, 34, 56, 789, location)
	now := time.Date(2026, time.September, 25, 13, 35, 57, 890, location)
	fetchedAt := time.Date(2026, time.September, 25, 14, 36, 58, 1, location)
	expiresAt := time.Date(2026, time.September, 26, 14, 36, 58, 2, location)
	staleUntil := time.Date(2026, time.September, 26, 15, 36, 58, 3, location)

	dhcp := NewDHCPState(7, "enp3s0", "connection-1", []string{"192.0.2.53", "2001:db8::53"}, observedAt, "dhcp4", true)
	if dhcp.SchemaVersion != SchemaVersion || dhcp.Generation != 7 || dhcp.Interface != "enp3s0" || dhcp.ConnectionUUID != "connection-1" || dhcp.Source != "dhcp4" || !dhcp.LastGood {
		t.Fatalf("unexpected DHCP constructor result: %#v", dhcp)
	}
	if !reflect.DeepEqual(dhcp.Upstreams, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Fatalf("DHCP upstreams = %#v", dhcp.Upstreams)
	}
	if !dhcp.ObservedAt.Equal(observedAt) || dhcp.ObservedAt.Location() != time.UTC {
		t.Fatalf("DHCP observed time = %v (%v), want UTC equivalent of %v", dhcp.ObservedAt, dhcp.ObservedAt.Location(), observedAt)
	}

	selector := NewSelector(8, "auto", "cloudflare", now)
	if selector.SchemaVersion != SchemaVersion || selector.Generation != 8 || selector.Mode != "auto" || selector.Provider != "cloudflare" {
		t.Fatalf("unexpected selector constructor result: %#v", selector)
	}
	if !selector.LastSuccess.Equal(now) || selector.LastSuccess.Location() != time.UTC {
		t.Fatalf("selector last success = %v (%v), want UTC equivalent of %v", selector.LastSuccess, selector.LastSuccess.Location(), now)
	}

	ech := NewECHState(9, "cloudflare-ech.com", fetchedAt, expiresAt, staleUntil, "config-hash", "public.example", "fresh")
	if ech.SchemaVersion != SchemaVersion || ech.Generation != 9 || ech.Source != "cloudflare-ech.com" || ech.ConfigSHA256 != "config-hash" || ech.PublicName != "public.example" || ech.Status != "fresh" {
		t.Fatalf("unexpected ECH constructor result: %#v", ech)
	}
	for name, got := range map[string]time.Time{
		"fetched_at":  ech.FetchedAt,
		"expires_at":  ech.ExpiresAt,
		"stale_until": ech.StaleUntil,
	} {
		if got.Location() != time.UTC {
			t.Errorf("ECH %s location = %v, want UTC", name, got.Location())
		}
	}
	if !ech.FetchedAt.Equal(fetchedAt) || !ech.ExpiresAt.Equal(expiresAt) || !ech.StaleUntil.Equal(staleUntil) {
		t.Fatalf("ECH timestamps = %v, %v, %v", ech.FetchedAt, ech.ExpiresAt, ech.StaleUntil)
	}
}

func TestNewDHCPStateCopiesUpstreams(t *testing.T) {
	upstreams := []string{"192.0.2.1"}
	got := NewDHCPState(1, "eth0", "uuid", upstreams, time.Time{}, "source", true)
	upstreams[0] = "198.51.100.1"
	if got.Upstreams[0] != "192.0.2.1" {
		t.Fatalf("constructor retained caller's slice: %#v", got.Upstreams)
	}
}

func TestSelectorValidationAcceptsSupportedModesAndIPv4Addresses(t *testing.T) {
	for _, mode := range []string{"auto", "manual", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			state := Selector{
				SchemaVersion: SchemaVersion,
				Generation:    1,
				Mode:          mode,
				Provider:      "cloudflare",
				WinnerIP:      "192.0.2.10",
				FallbackIP:    "198.51.100.20",
			}
			if err := state.Validate(); err != nil {
				t.Fatalf("valid selector mode %q rejected: %v", mode, err)
			}
		})
	}
}

func TestSelectorValidationRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Selector)
	}{
		{name: "schema version", mutate: func(s *Selector) { s.SchemaVersion = 2 }},
		{name: "unsupported mode", mutate: func(s *Selector) { s.Mode = "invalid" }},
		{name: "empty provider", mutate: func(s *Selector) { s.Provider = "" }},
		{name: "blank provider", mutate: func(s *Selector) { s.Provider = "  " }},
		{name: "invalid winner", mutate: func(s *Selector) { s.WinnerIP = "not-an-ip" }},
		{name: "IPv6 winner", mutate: func(s *Selector) { s.WinnerIP = "2001:db8::1" }},
		{name: "invalid fallback", mutate: func(s *Selector) { s.FallbackIP = "192.0.2.999" }},
		{name: "IPv6 fallback", mutate: func(s *Selector) { s.FallbackIP = "2001:db8::2" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := Selector{SchemaVersion: SchemaVersion, Generation: 1, Mode: "auto", Provider: "cloudflare"}
			tt.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("expected selector validation error")
			}
		})
	}
}

func TestDHCPStateValidationRequiresValidUpstreamAddresses(t *testing.T) {
	valid := []string{"192.0.2.1", "2001:db8::1"}
	for _, upstream := range valid {
		state := DHCPState{SchemaVersion: SchemaVersion, Generation: 1, Upstreams: []string{upstream}}
		if err := state.Validate(); err != nil {
			t.Errorf("valid upstream %q rejected: %v", upstream, err)
		}
	}
	for _, upstream := range []string{"", "not-an-ip", "192.0.2.999"} {
		state := DHCPState{SchemaVersion: SchemaVersion, Generation: 1, Upstreams: []string{upstream}}
		if err := state.Validate(); err == nil {
			t.Errorf("invalid upstream %q accepted", upstream)
		}
	}
}

func TestECHStateValidationRestrictsStatus(t *testing.T) {
	for _, status := range []string{"fresh", "stale", "invalid"} {
		state := ECHState{SchemaVersion: SchemaVersion, Generation: 1, Source: "source", Status: status}
		if err := state.Validate(); err != nil {
			t.Errorf("valid status %q rejected: %v", status, err)
		}
	}
	for _, status := range []string{"", "expired", "Fresh", "unknown"} {
		state := ECHState{SchemaVersion: SchemaVersion, Generation: 1, Source: "source", Status: status}
		if err := state.Validate(); err == nil {
			t.Errorf("invalid status %q accepted", status)
		}
	}
}

func TestBandwidthBudgetStateValidationUsesCalendarDate(t *testing.T) {
	valid := []string{"2026-09-25", "2024-02-29", "2000-02-29"}
	for _, date := range valid {
		state := BandwidthBudgetState{SchemaVersion: SchemaVersion, LocalDate: date, LimitBytes: 100, UsedBytes: 0}
		if err := state.Validate(); err != nil {
			t.Errorf("valid local date %q rejected: %v", date, err)
		}
	}
	invalid := []string{
		"2026-9-25",
		"2026-09-25T00:00:00Z",
		"2026-09-25Z",
		"2026-13-01",
		"2026-02-30",
		"2023-02-29",
		"2026/09/25",
		"",
	}
	for _, date := range invalid {
		state := BandwidthBudgetState{SchemaVersion: SchemaVersion, LocalDate: date, LimitBytes: 100, UsedBytes: 0}
		if err := state.Validate(); err == nil {
			t.Errorf("invalid local date %q accepted", date)
		}
	}
}

func TestBudgetAndHealthValidationRejectNegativeCounters(t *testing.T) {
	budgetTests := []BandwidthBudgetState{
		{SchemaVersion: SchemaVersion, LocalDate: "2026-09-25", LimitBytes: -1, UsedBytes: 0},
		{SchemaVersion: SchemaVersion, LocalDate: "2026-09-25", LimitBytes: 0, UsedBytes: -1},
	}
	for _, state := range budgetTests {
		if err := state.Validate(); err == nil {
			t.Errorf("negative budget state accepted: %#v", state)
		}
	}
	for _, failures := range []int{-1, -100} {
		state := HealthState{SchemaVersion: SchemaVersion, ConsecutiveFailures: failures}
		if err := state.Validate(); err == nil {
			t.Errorf("negative health failure count accepted: %#v", state)
		}
	}
	zero := HealthState{SchemaVersion: SchemaVersion, ConsecutiveFailures: 0}
	if err := zero.Validate(); err != nil {
		t.Fatalf("zero health failure count rejected: %v", err)
	}
}

func TestAllStateTypesRejectUnsupportedSchemaVersions(t *testing.T) {
	states := []any{
		DHCPState{SchemaVersion: 2, Upstreams: []string{"192.0.2.1"}},
		Selector{SchemaVersion: 2, Mode: "auto", Provider: "cloudflare"},
		ECHState{SchemaVersion: 2, Status: "fresh"},
		BandwidthBudgetState{SchemaVersion: 2, LocalDate: "2026-09-25"},
		HealthState{SchemaVersion: 2},
	}
	for _, value := range states {
		if err := validateState(value); err == nil {
			t.Errorf("unsupported schema accepted for %T", value)
		}
	}
}
