// Package candidate normalizes the addresses a CDN selector may probe into
// Candidate values, and nothing else: no measurement, no ranking, and no state.
//
// Every candidate is a plain public IPv4 address in one of two groups. A global
// Cloudflare candidate carries no hostname and competes with every other global
// candidate; a CloudFront candidate names exactly one profile hostname and is
// only ever compared with candidates of that same hostname. Keeping the two
// apart in the value itself is what stops a winner proved for one hostname from
// being published for another.
package candidate

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Provider names the group a candidate belongs to. The two values are the only
// providers this release selects, and each is a token the selector state
// already accepts as its provider.
type Provider string

const (
	// ProviderCloudflare is the global group: any address Cloudflare anycasts
	// can serve any host, so these candidates carry no hostname.
	ProviderCloudflare Provider = "cloudflare"
	// ProviderCloudFront is the per-hostname group: an address only means
	// anything behind the hostname of the profile that named it.
	ProviderCloudFront Provider = "cloudfront"
)

// The source of a candidate is a bounded lowercase token, because the field is
// published into the selector state and rendered by the status page. It records
// provenance, not ownership: an address a user pinned keeps the user label even
// where an official range names the same address.
const (
	// SourceUser is a candidate the user wrote in a list.
	SourceUser = "user"
	// SourceRetained is a candidate the selector is already using. The current
	// winner and the current fallback are re-added under this label on every
	// run, so a daily reseed of the official ranges can never leave the switch
	// gate comparing against an address it cannot re-prove.
	SourceRetained = "retained"
	// SourceCloudflare is a candidate sampled from the Cloudflare IP API.
	SourceCloudflare = "cloudflare"
	// SourceCloudFront is a candidate a CloudFront profile named itself.
	SourceCloudFront = "cloudfront"
)

const (
	// MaximumOfficialCandidates is the default cap on candidates taken from an
	// official range list, the same default the policy carries in
	// cdn.cloudflare.max_candidates. User and retained candidates are never
	// counted against it. It is published here so a caller that has no policy to
	// read still measures the documented number of addresses.
	MaximumOfficialCandidates = 512

	// MaximumUserCandidates bounds what one user list may produce, so a single
	// wide prefix cannot hand the prober an unbounded number of addresses.
	MaximumUserCandidates = 512

	// maximumSourceTokenLength bounds the source token the same way the state
	// package bounds the tokens it publishes.
	maximumSourceTokenLength = 32

	// maximumHostnameLength and maximumLabelLength are the DNS presentation
	// limits, repeated here because this package is independent of the state
	// and config packages and must reach the same verdict on the same name.
	maximumHostnameLength = 253
	maximumLabelLength    = 63
)

// Candidate is one address this selector may probe, in one group, with the
// provenance recorded by the channel that produced it.
type Candidate struct {
	// Provider is the group this candidate competes in.
	Provider Provider
	// IP is the address to probe. It is always a public IPv4 address in
	// canonical form: IPv4-mapped input is unmapped before it gets here, and a
	// zone can never be attached to an IPv4 address.
	IP netip.Addr
	// Source records which channel named the address. It is a bounded
	// lowercase token, not a free-form label.
	Source string
	// Hostname is the CloudFront profile hostname this candidate belongs to,
	// and is empty for a global Cloudflare candidate.
	Hostname string
}

// Validate refuses every candidate a later component could not publish: a
// provider that is not one of the two groups, a hostname that does not belong
// to the group, an address that is not a routable public IPv4 address, and a
// source token that is not bounded lowercase text.
func (c Candidate) Validate() error {
	switch c.Provider {
	case ProviderCloudflare:
		if c.Hostname != "" {
			return fmt.Errorf("a %s candidate must not carry a hostname, got %q", ProviderCloudflare, c.Hostname)
		}
	case ProviderCloudFront:
		// An empty hostname is refused here too: a CloudFront candidate without
		// one is not a per-hostname candidate at all.
		if !validHostname(c.Hostname) {
			return fmt.Errorf("hostname %q must be a DNS name without a scheme, a path, an address or a wildcard", c.Hostname)
		}
	default:
		return fmt.Errorf("provider must be %q or %q, got %q", ProviderCloudflare, ProviderCloudFront, c.Provider)
	}
	if !validPublicIPv4(c.IP) {
		return fmt.Errorf("ip must be a public IPv4 address, got %q", c.IP)
	}
	if !validSourceToken(c.Source) {
		return fmt.Errorf("source must be a lowercase token of at most %d characters, got %q", maximumSourceTokenLength, c.Source)
	}
	return nil
}

// Compare is the total order of candidates: provider, then hostname, then
// address bytes, then source. Two candidates that compare equal carry the same
// four values, so an ordering built on it is reproducible from one run to the
// next and independent of the order the sources happened to answer in.
func Compare(first, second Candidate) int {
	if result := strings.Compare(string(first.Provider), string(second.Provider)); result != 0 {
		return result
	}
	if result := strings.Compare(first.Hostname, second.Hostname); result != 0 {
		return result
	}
	if result := first.IP.Compare(second.IP); result != 0 {
		return result
	}
	return strings.Compare(first.Source, second.Source)
}

// Sort orders a candidate list in place. The sort is stable, so a list that
// holds two values with the same four keys keeps the order its sources produced
// rather than an arbitrary one.
func Sort(candidates []Candidate) {
	slices.SortStableFunc(candidates, Compare)
}

// Combine returns the list one run measures. Official candidates are capped at
// the policy limit; user and retained candidates are always included and are
// never counted against that limit, so a wide official sample can never push
// the current winner or a pinned address out of the run. The same address named
// by more than one channel becomes one candidate, labelled with the channel a
// later step has to find it by: the retained label for the address the switch
// gate must re-prove, then the user label, then the official one.
//
// The three slices are read, never written.
func Combine(official, user, retained []Candidate, limit int) ([]Candidate, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("the official candidate limit must be greater than zero, got %d", limit)
	}
	for _, channel := range []struct {
		name         string
		values       []Candidate
		retainedOnly bool
	}{
		{"official", official, false},
		{"user", user, false},
		{"retained", retained, true},
	} {
		if err := checkChannel(channel.values, channel.retainedOnly); err != nil {
			return nil, fmt.Errorf("%s candidate: %w", channel.name, err)
		}
	}
	if len(official) > limit {
		official = official[:limit]
	}

	// The channels are appended from the lowest provenance to the highest, so
	// the surviving entry for an address is always the last one written for it.
	merged := make([]Candidate, 0, len(official)+len(user)+len(retained))
	merged = append(merged, official...)
	merged = append(merged, user...)
	merged = append(merged, retained...)

	type key struct {
		provider Provider
		hostname string
		address  string
	}
	position := make(map[key]int, len(merged))
	unique := make([]Candidate, 0, len(merged))
	for _, candidate := range merged {
		identifier := key{provider: candidate.Provider, hostname: candidate.Hostname, address: candidate.IP.String()}
		if index, seen := position[identifier]; seen {
			unique[index] = candidate
			continue
		}
		position[identifier] = len(unique)
		unique = append(unique, candidate)
	}
	Sort(unique)
	return unique, nil
}

// checkChannel validates the candidates one channel offers, and refuses a
// retained candidate that was passed as something else: a retained candidate in
// the official slice would be dropped by the limit, and a candidate of any other
// channel in the retained slice would be dropped by whatever limit the caller
// passed.
func checkChannel(values []Candidate, retainedOnly bool) error {
	for _, candidate := range values {
		if err := candidate.Validate(); err != nil {
			return err
		}
		if retainedOnly && candidate.Source != SourceRetained {
			return fmt.Errorf("source must be %q, got %q", SourceRetained, candidate.Source)
		}
		if !retainedOnly && candidate.Source == SourceRetained {
			return fmt.Errorf("a %q candidate must be passed as a retained candidate", SourceRetained)
		}
	}
	return nil
}

// nonPublicIPv4Prefixes covers every IPv4 range that is not a routable public
// address. It is the same rule the state package applies to a published rewrite
// target, repeated here because this package must not depend on that one: a
// candidate list is the only channel a user controls, so a range accepted here
// but refused at publish time would fail a pinned address for no reason, and a
// range accepted at both would let a user point a rewrite at the LAN.
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

// validPublicIPv4 reports whether an address is a plain IPv4 address that a
// published rewrite target is allowed to name. An IPv4-mapped address is not
// plain: it is IPv6 notation for an IPv4 address, and the address value reaches
// the socket layer, the report and the state, so it is refused here and
// unmapped on the way in instead.
func validPublicIPv4(address netip.Addr) bool {
	if !address.Is4() {
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

// parsePublicIPv4 parses one address and returns it in the canonical form this
// package stores: an IPv4-mapped literal is unmapped, and anything that is not
// public IPv4 space is refused.
func parsePublicIPv4(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an address: %w", value, err)
	}
	address = address.Unmap()
	if !validPublicIPv4(address) {
		return netip.Addr{}, fmt.Errorf("%q is not a public IPv4 address", value)
	}
	return address, nil
}

// parseIPv4Prefix parses one prefix and returns it masked, unmapped from
// IPv4-mapped notation when it was written that way, and only when the prefix
// lies in public IPv4 space. Refusing a prefix whose network address is reserved
// refuses the prefix whole: a range that contains one unusable address cannot be
// sampled honestly.
func parseIPv4Prefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 prefix: %w", value, err)
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("%q does not cover a whole IPv4 mapping", value)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 prefix", value)
	}
	prefix = prefix.Masked()
	if !validPublicIPv4(prefix.Addr()) {
		return netip.Prefix{}, fmt.Errorf("%q is not a public IPv4 prefix", value)
	}
	return prefix, nil
}

// blockSize is the /24 this package samples one address from. It is the
// smallest block every documented CDN range is aligned to, so a sample taken
// per block spreads over the whole published space instead of clustering in the
// first few thousand addresses of it.
const blockSize = 24

// blockCount returns how many blocks a prefix wider than a block covers.
func blockCount(prefix netip.Prefix) int64 {
	if prefix.Bits() >= blockSize {
		return 1
	}
	return int64(1) << (blockSize - prefix.Bits())
}

// blockAt returns the index-th block of a prefix wider than a block, counting
// from its network address, without building the blocks in between: a prefix as
// wide as a /3 covers 131072 of them and only the sampled ones are ever needed.
func blockAt(prefix netip.Prefix, index int64) netip.Prefix {
	network := prefix.Masked().Addr().As4()
	value := binary.BigEndian.Uint32(network[:]) + uint32(index)*256
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.PrefixFrom(netip.AddrFrom4(raw), blockSize)
}

// firstHostAddress returns the lowest host address of a block. It is used to
// expand a prefix a user named, where every run must measure the same addresses.
func firstHostAddress(block netip.Prefix) netip.Addr {
	raw := block.Addr().As4()
	raw[3] = 1
	return netip.AddrFrom4(raw)
}

// validHostname accepts a syntactically valid DNS name and nothing else, so a
// URL, a path, a wildcard, an address literal, or a value carrying a control
// character can never become a profile key or a CloudFront state key.
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

// validSourceToken accepts the lowercase, hyphen-separated tokens the sources of
// this package record and the state file publishes. A hyphen is refused at
// either end: that is stricter than the state token rule, and a source this
// package can produce never carries one.
func validSourceToken(value string) bool {
	if value == "" || len(value) > maximumSourceTokenLength {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if character == '-' && index > 0 && index < len(value)-1 {
			continue
		}
		return false
	}
	return true
}
