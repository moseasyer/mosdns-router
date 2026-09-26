package state

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
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
				LastSuccess:   time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC),
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
		state := validDHCPState(upstream)
		if err := state.Validate(); err != nil {
			t.Errorf("valid upstream %q rejected: %v", upstream, err)
		}
	}
	for _, upstream := range []string{"", "not-an-ip", "192.0.2.999"} {
		state := validDHCPState(upstream)
		if err := state.Validate(); err == nil {
			t.Errorf("invalid upstream %q accepted", upstream)
		}
	}
}

// A DHCP upstream has to be something the router can actually forward a query
// to. Loopback (including the resolved stubs 127.0.0.53 and 127.0.0.54),
// unspecified, multicast, IPv4 link-local and zoned addresses cannot. A bare
// IPv6 link-local, ULA or global address is usable because the interface is
// recorded in the same state record.
func TestDHCPStateValidationRejectsUnusableUpstreamAddresses(t *testing.T) {
	accepted := []string{
		"192.0.2.53",
		"198.51.100.53",
		"203.0.113.53",
		"2001:db8::53",
		"fc00::53",
		"fe80::53",
	}
	for _, upstream := range accepted {
		state := validDHCPState(upstream)
		if err := state.Validate(); err != nil {
			t.Errorf("usable upstream %q rejected: %v", upstream, err)
		}
	}

	rejected := []string{
		"127.0.0.1",
		"127.0.0.53",
		"127.0.0.54",
		"127.255.255.254",
		"::1",
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"239.255.255.250",
		"ff02::1",
		"169.254.1.1",
		"fe80::1%eth0",
		"::ffff:192.0.2.1",
	}
	for _, upstream := range rejected {
		state := validDHCPState(upstream)
		if err := state.Validate(); err == nil {
			t.Errorf("unusable upstream %q accepted", upstream)
		}
	}
}

func TestDHCPStateValidationEnforcesLastGoodInterfaceSourceAndObservation(t *testing.T) {
	base := validDHCPState("192.0.2.53")

	t.Run("a complete record is valid", func(t *testing.T) {
		if err := base.Validate(); err != nil {
			t.Fatalf("complete DHCP state rejected: %v", err)
		}
	})

	// A leading digit is a legal device name the bridge collects for, so the rule
	// that refuses a leading dot or underscore must not grow into "a letter".
	t.Run("an interface that starts with a digit is valid", func(t *testing.T) {
		numeric := base
		numeric.Interface = "2eth0"
		if err := numeric.Validate(); err != nil {
			t.Fatalf("the interface 2eth0 was rejected: %v", err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*DHCPState)
	}{
		{name: "empty interface", mutate: func(s *DHCPState) { s.Interface = "" }},
		{name: "interface with a space", mutate: func(s *DHCPState) { s.Interface = "enp3 s0" }},
		{name: "interface with a control character", mutate: func(s *DHCPState) { s.Interface = "enp3s0\n" }},
		{name: "interface with a slash", mutate: func(s *DHCPState) { s.Interface = "enp3s0/0" }},
		{name: "interface longer than the kernel limit", mutate: func(s *DHCPState) { s.Interface = "abcdefghijklmnop" }},
		// The bridge only ever publishes a name whose first character is a letter
		// or a digit, and it refuses to collect for a name that is not one, so a
		// state this reader accepts but the bridge cannot produce is a state no
		// writer of this project can have written.
		{name: "interface starting with a dot", mutate: func(s *DHCPState) { s.Interface = ".enp3s0" }},
		{name: "interface starting with an underscore", mutate: func(s *DHCPState) { s.Interface = "_enp3s0" }},
		{name: "interface starting with a dash", mutate: func(s *DHCPState) { s.Interface = "-enp3s0" }},
		{name: "empty source", mutate: func(s *DHCPState) { s.Source = "" }},
		{name: "source with a space", mutate: func(s *DHCPState) { s.Source = "dhcp 4" }},
		{name: "source with an uppercase letter", mutate: func(s *DHCPState) { s.Source = "DHCP4" }},
		{name: "missing observation time", mutate: func(s *DHCPState) { s.ObservedAt = time.Time{} }},
		{name: "last good without upstreams", mutate: func(s *DHCPState) { s.Upstreams = nil }},
		{name: "last good with an empty upstream list", mutate: func(s *DHCPState) { s.Upstreams = []string{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := base
			state.Upstreams = append([]string(nil), base.Upstreams...)
			tt.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", state)
			}
		})
	}

	t.Run("a stale state may be empty", func(t *testing.T) {
		state := base
		state.Upstreams = nil
		state.LastGood = false
		if err := state.Validate(); err != nil {
			t.Fatalf("empty non-last-good state rejected: %v", err)
		}
	})
}

// writerSourceTokens is every source token a writer in this project can put in a
// DHCP state: the six the bridge's collector reports, plus the one the bridge
// records for a down event, where no source answered. The list is spelled out
// here rather than derived from the code, because the point of the case below is
// that the reader's own diagnostic stays inside the writer's vocabulary, and a
// list that moved with the code could not say that.
//
// The reader's check is a shape check -- any lowercase hyphenated token passes --
// so the vocabulary is not something it can enforce. It lives in the writer, and
// a diagnostic offering a token outside it teaches an operator to hand-write a
// document no writer here can produce.
var writerSourceTokens = []string{
	"down",
	"dispatcher-env",
	"nm-dhcp",
	"nm-dhcp4",
	"nm-dhcp6",
	"nm-effective",
	"resolved",
}

// messageProse is the fixed English of the source diagnostic, so a word that is
// not an offered token is recognised as a word rather than mistaken for one.
var messageProse = map[string]bool{
	"a": true, "as": true, "at": true, "be": true, "by": true, "character": true,
	"lowercase": true, "most": true, "must": true, "of": true, "or": true,
	"record": true, "source": true, "such": true, "the": true, "token": true,
	"tokens": true, "writer": true,
}

// tokenWord matches every word in a diagnostic that could be a source token, so
// an offered token cannot hide behind punctuation or capitalization.
var tokenWord = regexp.MustCompile(`[a-z0-9]+(?:-[a-z0-9]+)*`)

// A refusal that names a token no writer produces is a refusal that teaches the
// wrong thing: an operator who follows it writes a state this project has no way
// to produce, and the reader cannot catch it, because the check it does is the
// shape. This is the one place the vocabulary can be kept honest.
func TestDHCPStateSourceRefusalNamesOnlyTokensAWriterCanProduce(t *testing.T) {
	state := validDHCPState("192.0.2.53")
	state.Source = "DHCP4"

	err := state.Validate()
	if err == nil {
		t.Fatal("a source that is not a lowercase token was accepted")
	}
	message := err.Error()

	offered := 0
	for _, word := range tokenWord.FindAllString(message, -1) {
		if messageProse[word] {
			continue
		}
		if !slices.Contains(writerSourceTokens, word) {
			t.Errorf("the refusal names %q, which no writer of this project can publish; the writer's tokens are %v", word, writerSourceTokens)
		}
		offered++
	}
	if offered == 0 {
		t.Errorf("the refusal offers no token a writer can publish, so it cannot be acted on: %q", message)
	}
}

func TestSelectorValidationEnforcesWinnerFallbackAndProofConsistency(t *testing.T) {
	valid := Selector{
		SchemaVersion:    SchemaVersion,
		Generation:       4,
		Mode:             "auto",
		Provider:         "cloudflare",
		WinnerIP:         "192.0.2.10",
		WinnerProofUntil: time.Date(2026, time.September, 25, 13, 0, 0, 0, time.UTC),
		FallbackIP:       "198.51.100.20",
		LastSuccess:      time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("consistent selector rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Selector)
	}{
		{name: "winner without a success time", mutate: func(s *Selector) { s.LastSuccess = time.Time{} }},
		{name: "proof without a winner", mutate: func(s *Selector) { s.WinnerIP = "" }},
		{name: "proof before the last success", mutate: func(s *Selector) {
			s.WinnerProofUntil = time.Date(2026, time.September, 25, 11, 0, 0, 0, time.UTC)
		}},
		{name: "proof equal to the last success", mutate: func(s *Selector) { s.WinnerProofUntil = s.LastSuccess }},
		{name: "fallback identical to the winner", mutate: func(s *Selector) { s.FallbackIP = s.WinnerIP }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := valid
			tt.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", state)
			}
		})
	}

	t.Run("a selector without a winner needs no proof", func(t *testing.T) {
		state := valid
		state.WinnerIP = ""
		state.WinnerProofUntil = time.Time{}
		if err := state.Validate(); err != nil {
			t.Fatalf("winnerless selector rejected: %v", err)
		}
	})
}

func TestSelectorValidationRejectsUnsafeProviderAndConfigHash(t *testing.T) {
	base := Selector{
		SchemaVersion: SchemaVersion,
		Generation:    1,
		Mode:          "auto",
		Provider:      "cloudflare",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("selector without a config hash rejected: %v", err)
	}
	base.ConfigSHA256 = testSHA256
	if err := base.Validate(); err != nil {
		t.Fatalf("selector with a SHA-256 config hash rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Selector)
	}{
		{name: "provider with a space", mutate: func(s *Selector) { s.Provider = "cloud front" }},
		{name: "provider with a slash", mutate: func(s *Selector) { s.Provider = "cloudflare/global" }},
		{name: "provider with a control character", mutate: func(s *Selector) { s.Provider = "cloud\nflare" }},
		{name: "short config hash", mutate: func(s *Selector) { s.ConfigSHA256 = "abc" }},
		{name: "config hash with a non-hex character", mutate: func(s *Selector) { s.ConfigSHA256 = testSHA256[:63] + "z" }},
		{name: "uppercase config hash", mutate: func(s *Selector) { s.ConfigSHA256 = strings.ToUpper(testSHA256) }},
		{name: "config hash that is too long", mutate: func(s *Selector) { s.ConfigSHA256 = testSHA256 + "0" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := base
			tt.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", state)
			}
		})
	}
}

func TestSelectorValidationRejectsUnsafeCloudFrontMappings(t *testing.T) {
	valid := Selector{
		SchemaVersion: SchemaVersion,
		Generation:    1,
		Mode:          "auto",
		Provider:      "cloudfront",
		CloudFront:    map[string]string{"distribution.example": "1.2.3.4"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid CloudFront mapping rejected: %v", err)
	}

	tests := []struct {
		name       string
		cloudfront map[string]string
	}{
		{name: "empty hostname", cloudfront: map[string]string{"": "1.2.3.4"}},
		{name: "hostname with a space", cloudfront: map[string]string{"distribution example": "1.2.3.4"}},
		{name: "hostname with a wildcard", cloudfront: map[string]string{"*.example": "1.2.3.4"}},
		{name: "hostname with a trailing dot", cloudfront: map[string]string{"distribution.example.": "1.2.3.4"}},
		{name: "hostname with a leading hyphen label", cloudfront: map[string]string{"-bad.example": "1.2.3.4"}},
		{name: "hostname that is an IPv4 literal", cloudfront: map[string]string{"1.2.3.4": "1.2.3.4"}},
		{name: "hostname with an empty label", cloudfront: map[string]string{"distribution..example": "1.2.3.4"}},
		{name: "hostname with a control character", cloudfront: map[string]string{"distribution.example\n": "1.2.3.4"}},
		{name: "value that is not an address", cloudfront: map[string]string{"distribution.example": "not-an-ip"}},
		{name: "IPv6 value", cloudfront: map[string]string{"distribution.example": "2001:db8::1"}},
		{name: "loopback value", cloudfront: map[string]string{"distribution.example": "127.0.0.1"}},
		{name: "link-local value", cloudfront: map[string]string{"distribution.example": "169.254.1.1"}},
		{name: "multicast value", cloudfront: map[string]string{"distribution.example": "224.0.0.1"}},
		{name: "unspecified value", cloudfront: map[string]string{"distribution.example": "0.0.0.0"}},
		{name: "private value", cloudfront: map[string]string{"distribution.example": "10.1.2.3"}},
		{name: "carrier NAT value", cloudfront: map[string]string{"distribution.example": "100.64.0.1"}},
		{name: "documentation value", cloudfront: map[string]string{"distribution.example": "192.0.2.10"}},
		{name: "broadcast value", cloudfront: map[string]string{"distribution.example": "255.255.255.255"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := valid
			state.CloudFront = tt.cloudfront
			if err := state.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", tt.cloudfront)
			}
		})
	}
}

func TestECHStateValidationRestrictsStatus(t *testing.T) {
	for _, status := range []string{"fresh", "stale", "invalid"} {
		state := validECHState(status)
		if err := state.Validate(); err != nil {
			t.Errorf("valid status %q rejected: %v", status, err)
		}
	}
	for _, status := range []string{"", "expired", "Fresh", "unknown"} {
		state := validECHState(status)
		if err := state.Validate(); err == nil {
			t.Errorf("invalid status %q accepted", status)
		}
	}
}

func TestECHStateValidationEnforcesMetadataAndTimestampOrdering(t *testing.T) {
	base := validECHState("fresh")
	if err := base.Validate(); err != nil {
		t.Fatalf("complete ECH state rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ECHState)
	}{
		{name: "missing fetch time", mutate: func(s *ECHState) { s.FetchedAt = time.Time{} }},
		{name: "missing expiry", mutate: func(s *ECHState) { s.ExpiresAt = time.Time{} }},
		{name: "missing stale grace", mutate: func(s *ECHState) { s.StaleUntil = time.Time{} }},
		{name: "expiry before the fetch time", mutate: func(s *ECHState) { s.ExpiresAt = s.FetchedAt.Add(-time.Second) }},
		{name: "expiry equal to the fetch time", mutate: func(s *ECHState) { s.ExpiresAt = s.FetchedAt }},
		{name: "stale grace before the expiry", mutate: func(s *ECHState) { s.StaleUntil = s.ExpiresAt.Add(-time.Second) }},
		{name: "source with a URL scheme", mutate: func(s *ECHState) { s.Source = "https://cloudflare-ech.com" }},
		{name: "source with a path", mutate: func(s *ECHState) { s.Source = "cloudflare-ech.com/hello" }},
		{name: "source that is an address", mutate: func(s *ECHState) { s.Source = "192.0.2.1" }},
		{name: "empty source", mutate: func(s *ECHState) { s.Source = "" }},
		{name: "missing config hash", mutate: func(s *ECHState) { s.ConfigSHA256 = "" }},
		{name: "short config hash", mutate: func(s *ECHState) { s.ConfigSHA256 = "abc" }},
		{name: "missing public name", mutate: func(s *ECHState) { s.PublicName = "" }},
		{name: "public name with a space", mutate: func(s *ECHState) { s.PublicName = "public name" }},
		{name: "public name that is an address", mutate: func(s *ECHState) { s.PublicName = "192.0.2.1" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := base
			tt.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", state)
			}
		})
	}

	t.Run("an invalid state may report no public name", func(t *testing.T) {
		state := validECHState("invalid")
		state.PublicName = ""
		if err := state.Validate(); err != nil {
			t.Fatalf("invalid ECH state without a public name rejected: %v", err)
		}
	})
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

// testSHA256 is the lowercase hex SHA-256 digest of "test". State validation
// requires config hashes in exactly this shape, so the fixture is a real
// digest instead of a placeholder.
const testSHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

var testFetchedAt = time.Date(2026, time.September, 25, 10, 0, 0, 0, time.UTC)

// validDHCPState returns a DHCP record that satisfies every invariant except
// the upstream address, so a test can vary one rule at a time.
func validDHCPState(upstream string) DHCPState {
	state := NewDHCPState(1, "enp3s0", "connection-1", []string{upstream}, testFetchedAt, "dhcp4", true)
	return state
}

// validECHState returns an ECH record that satisfies every invariant except
// the status value itself.
func validECHState(status string) ECHState {
	return NewECHState(1, "cloudflare-ech.com", testFetchedAt, testFetchedAt.Add(time.Hour), testFetchedAt.Add(2*time.Hour), testSHA256, "public.example", status)
}
