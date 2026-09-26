package state

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const SchemaVersion = 1

// maximumInterfaceNameLength is the longest interface name the kernel accepts
// (IFNAMSIZ - 1). A longer or malformed name can never be a real device, so a
// state file that claims one is rejected instead of published.
const maximumInterfaceNameLength = 15

// maximumSourceLength and maximumProviderLength bound the free-form token
// fields so a state file cannot carry an arbitrary payload through the status
// renderer.
const (
	maximumSourceLength   = 32
	maximumProviderLength = 64
)

// maximumHostnameLength is the longest DNS name in presentation format, and
// maximumLabelLength is the longest single label.
const (
	maximumHostnameLength = 253
	maximumLabelLength    = 63
)

type DHCPState struct {
	SchemaVersion  int       `json:"schema_version"`
	Generation     uint64    `json:"generation"`
	Interface      string    `json:"interface"`
	ConnectionUUID string    `json:"connection_uuid"`
	Upstreams      []string  `json:"upstreams"`
	ObservedAt     time.Time `json:"observed_at"`
	Source         string    `json:"source"`
	LastGood       bool      `json:"last_good"`
}

type Selector struct {
	SchemaVersion    int               `json:"schema_version"`
	Generation       uint64            `json:"generation"`
	Mode             string            `json:"mode"`
	Provider         string            `json:"provider"`
	WinnerIP         string            `json:"winner_ip,omitempty"`
	WinnerProofUntil time.Time         `json:"winner_proof_until,omitzero"`
	FallbackIP       string            `json:"fallback_ip,omitempty"`
	CloudFront       map[string]string `json:"cloudfront,omitempty"`
	LastSuccess      time.Time         `json:"last_success,omitzero"`
	LastFailure      string            `json:"last_failure,omitempty"`
	ConfigSHA256     string            `json:"config_sha256"`
}

type ECHState struct {
	SchemaVersion int       `json:"schema_version"`
	Generation    uint64    `json:"generation"`
	Source        string    `json:"source"`
	FetchedAt     time.Time `json:"fetched_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	StaleUntil    time.Time `json:"stale_until"`
	ConfigSHA256  string    `json:"config_sha256"`
	PublicName    string    `json:"public_name"`
	Status        string    `json:"status"`
}

type BandwidthBudgetState struct {
	SchemaVersion int    `json:"schema_version"`
	LocalDate     string `json:"local_date"`
	LimitBytes    int64  `json:"limit_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
}

type HealthState struct {
	SchemaVersion       int       `json:"schema_version"`
	Healthy             bool      `json:"healthy"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastSuccess         time.Time `json:"last_success,omitzero"`
	LastFailure         time.Time `json:"last_failure,omitzero"`
}

func NewDHCPState(generation uint64, interfaceName, connectionUUID string, upstreams []string, observedAt time.Time, source string, lastGood bool) DHCPState {
	return DHCPState{
		SchemaVersion:  SchemaVersion,
		Generation:     generation,
		Interface:      interfaceName,
		ConnectionUUID: connectionUUID,
		Upstreams:      cloneStrings(upstreams),
		ObservedAt:     observedAt.UTC(),
		Source:         source,
		LastGood:       lastGood,
	}
}

func NewSelector(generation uint64, mode, provider string, now time.Time) Selector {
	return Selector{
		SchemaVersion: SchemaVersion,
		Generation:    generation,
		Mode:          mode,
		Provider:      provider,
		LastSuccess:   now.UTC(),
	}
}

func NewECHState(generation uint64, source string, fetchedAt, expiresAt, staleUntil time.Time, configSHA256, publicName, status string) ECHState {
	return ECHState{
		SchemaVersion: SchemaVersion,
		Generation:    generation,
		Source:        source,
		FetchedAt:     fetchedAt.UTC(),
		ExpiresAt:     expiresAt.UTC(),
		StaleUntil:    staleUntil.UTC(),
		ConfigSHA256:  configSHA256,
		PublicName:    publicName,
		Status:        status,
	}
}

// Validate rejects every DHCP record a fail-closed domestic branch could not
// use: a missing interface or observation time, a source that is not a
// well-shaped token, upstreams that cannot receive a forwarded query, and a
// last-known-good marker with nothing behind it.
//
// The source rule is a shape check and not the vocabulary. Any lowercase
// hyphenated token within the length bound is accepted here, because which
// sources exist is the writers' business and this reader only has to refuse what
// it could not act on: the vocabulary is the bridge collector's tokens plus the
// one the bridge records for a down event, and the two this diagnostic offers
// come from it, so an operator reading the refusal is not sent to hand-write a
// state nothing in this project can produce.
func (s DHCPState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if !validInterfaceName(s.Interface) {
		return fmt.Errorf("interface must be a network interface name of at most %d characters", maximumInterfaceNameLength)
	}
	if !validSourceToken(s.Source) {
		return fmt.Errorf("source must be a lowercase token such as nm-dhcp4 or nm-effective")
	}
	if s.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at must record when the DHCP DNS was observed")
	}
	for index, upstream := range s.Upstreams {
		if !validDHCPUpstream(upstream) {
			return fmt.Errorf("upstreams[%d] must be a routable unicast address without a zone", index)
		}
	}
	if s.LastGood && len(s.Upstreams) == 0 {
		return fmt.Errorf("a last-known-good state must record at least one upstream")
	}
	return nil
}

func (s Selector) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if s.Mode != "auto" && s.Mode != "manual" && s.Mode != "disabled" {
		return fmt.Errorf("mode must be auto, manual, or disabled")
	}
	if !validProviderToken(s.Provider) {
		return fmt.Errorf("provider must be a lowercase token such as cloudflare or cloudfront")
	}
	if !validOptionalSHA256(s.ConfigSHA256) {
		return fmt.Errorf("config_sha256 must be empty or a lowercase SHA-256 digest")
	}
	if s.WinnerIP != "" && !validIPv4Address(s.WinnerIP) {
		return fmt.Errorf("winner_ip must be a valid IPv4 address")
	}
	if s.FallbackIP != "" && !validIPv4Address(s.FallbackIP) {
		return fmt.Errorf("fallback_ip must be a valid IPv4 address")
	}
	if s.WinnerIP != "" && s.FallbackIP == s.WinnerIP {
		return fmt.Errorf("fallback_ip must differ from winner_ip")
	}
	if err := validateSelectorProof(s.WinnerIP, s.WinnerProofUntil, s.LastSuccess); err != nil {
		return err
	}
	for hostname, address := range s.CloudFront {
		if !validHostname(hostname) {
			return fmt.Errorf("cloudfront keys must be DNS hostnames")
		}
		if !validPublicIPv4Address(address) {
			return fmt.Errorf("cloudfront values must be public IPv4 addresses")
		}
	}
	return nil
}

// validateSelectorProof keeps the winner, its proof expiry, and the last
// successful validation consistent: a winner cannot be published without the
// time it was proved, and a proof cannot outlive the success it was issued for.
func validateSelectorProof(winnerIP string, proofUntil, lastSuccess time.Time) error {
	if winnerIP == "" {
		if !proofUntil.IsZero() {
			return fmt.Errorf("winner_proof_until requires a winner_ip")
		}
		return nil
	}
	if lastSuccess.IsZero() {
		return fmt.Errorf("winner_ip requires a last_success validation time")
	}
	if !proofUntil.IsZero() && !proofUntil.After(lastSuccess) {
		return fmt.Errorf("winner_proof_until must be later than last_success")
	}
	return nil
}

// Validate rejects every ECH record whose timeline or metadata a strict
// consumer cannot trust: an unnamed source, a hash that is not a SHA-256, a
// missing public name for a usable config, and timestamps that do not run from
// fetch through expiry to the end of the stale grace.
func (s ECHState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if s.Status != "fresh" && s.Status != "stale" && s.Status != "invalid" {
		return fmt.Errorf("status must be fresh, stale, or invalid")
	}
	if !validHostname(s.Source) {
		return fmt.Errorf("source must be a DNS hostname without a scheme or path")
	}
	if !validSHA256(s.ConfigSHA256) {
		return fmt.Errorf("config_sha256 must be a lowercase SHA-256 digest")
	}
	if s.PublicName != "" && !validHostname(s.PublicName) {
		return fmt.Errorf("public_name must be a DNS hostname")
	}
	if s.PublicName == "" && s.Status != "invalid" {
		return fmt.Errorf("a usable ECH state must record its public_name")
	}
	if s.FetchedAt.IsZero() {
		return fmt.Errorf("fetched_at must record when the ECHConfig was fetched")
	}
	if s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.FetchedAt) {
		return fmt.Errorf("expires_at must be later than fetched_at")
	}
	if s.StaleUntil.IsZero() || s.StaleUntil.Before(s.ExpiresAt) {
		return fmt.Errorf("stale_until must not be earlier than expires_at")
	}
	return nil
}

func (s BandwidthBudgetState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if !validLocalDate(s.LocalDate) {
		return fmt.Errorf("local_date must be a valid YYYY-MM-DD calendar date")
	}
	if s.LimitBytes < 0 {
		return fmt.Errorf("limit_bytes must be non-negative")
	}
	if s.UsedBytes < 0 {
		return fmt.Errorf("used_bytes must be non-negative")
	}
	return nil
}

func (s HealthState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if s.ConsecutiveFailures < 0 {
		return fmt.Errorf("consecutive_failures must be non-negative")
	}
	return nil
}

func validateSchema(version int) error {
	if version != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	return nil
}

func validIPv4Address(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && !address.Is4In6() && address.Is4()
}

// validDHCPUpstream accepts only addresses a domestic query can be forwarded
// to. Loopback (including the systemd-resolved stubs), the unspecified address,
// multicast, and IPv4 link-local space are all unusable, and a zoned address
// would silently depend on an interface that is recorded separately. A bare
// IPv6 link-local, unique-local, or global address stays usable because the
// owning interface is stored next to it.
func validDHCPUpstream(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	if address.Zone() != "" || address.Is4In6() {
		return false
	}
	if address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if address.Is4() && address.IsLinkLocalUnicast() {
		return false
	}
	return true
}

// nonPublicIPv4Prefixes covers every IPv4 range that is not a routable public
// address, so a published rewrite target can never point at the host itself,
// the LAN, or a reserved range.
var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func validPublicIPv4Address(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || !validIPv4Address(value) {
		return false
	}
	if address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range nonPublicIPv4Prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// validHostname accepts a syntactically valid DNS name and nothing else, so a
// URL, a wildcard, an IP literal, or a value carrying control characters can
// never be published as an ECH source, a public name, or a CloudFront key.
func validHostname(value string) bool {
	if value == "" || len(value) > maximumHostnameLength || strings.HasSuffix(value, ".") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > maximumLabelLength {
		return false
	}
	for index := 0; index < len(label); index++ {
		character := label[index]
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
		case character == '-':
			if index == 0 || index == len(label)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validInterfaceName accepts exactly the device names the bridge can publish:
// an alphanumeric first character, then alphanumerics, a dot, an underscore, or a
// dash, up to the kernel's length limit. The first-character rule is the
// publisher's, not an extra one here: the bridge refuses to collect for a name
// that does not start with a letter or a digit, so a state carrying ".eth0" or
// "_eth0" describes a document no writer of this project can have produced, and
// a leading dot or underscore is a path element or a shell token the moment a
// name reaches an argument array.
func validInterfaceName(value string) bool {
	if value == "" || len(value) > maximumInterfaceNameLength {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
		case index > 0 && (character == '.' || character == '_' || character == '-'):
		default:
			return false
		}
	}
	return true
}

// validSourceToken accepts the lowercase, hyphen-separated tokens the DHCP
// bridge and installer record as the origin of an upstream set.
func validSourceToken(value string) bool {
	return validLowercaseToken(value, maximumSourceLength)
}

func validProviderToken(value string) bool {
	return validLowercaseToken(value, maximumProviderLength)
}

func validLowercaseToken(value string, maximumLength int) bool {
	if value == "" || len(value) > maximumLength {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			if character == '-' && index == 0 {
				return false
			}
			continue
		}
		return false
	}
	return true
}

// validSHA256 accepts a lowercase hex SHA-256 digest, so a truncated or
// re-encoded digest cannot be mistaken for a verified one.
func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

// validOptionalSHA256 also accepts an absent digest, for state that a later
// component fills in.
func validOptionalSHA256(value string) bool {
	return value == "" || validSHA256(value)
}

func validLocalDate(value string) bool {
	if len(value) != len("2006-01-02") || value[4] != '-' || value[7] != '-' {
		return false
	}
	date, err := time.Parse("2006-01-02", value)
	if err != nil || date.Year() < 1 || date.Format("2006-01-02") != value {
		return false
	}
	return true
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
