package candidate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultCloudFrontBaseURL is the AWS published ranges document this release
	// reads. It is a parameter of every source so a test can point one at a local
	// server; an empty value means this endpoint.
	DefaultCloudFrontBaseURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

	// DefaultCloudFrontCachePath is where the production router keeps the
	// reference document it read. It is a parameter too, so a test never writes
	// here.
	DefaultCloudFrontCachePath = "/var/lib/mosdns/lists/aws-ip-ranges.json"

	// profileSchemaVersion is the shape of a profile document. A document of
	// another version is refused rather than interpreted.
	profileSchemaVersion = 1

	// cloudFrontService is the service name the published document gives the
	// ranges that are this project's reference data.
	cloudFrontService = "CLOUDFRONT"

	// httpsPort is the port a profile URL resolves to when it names none.
	httpsPort = 443
)

// ProbeProfile is what a prober has to check to decide that an address is really
// serving one hostname: the name to send, the URL to fetch, the method and port
// to use, the statuses that mean the content arrived, the headers that must be
// there, and the digest the body must have.
type ProbeProfile struct {
	// Hostname is the only name this profile may ever be used for. It is
	// mandatory, and it is the key of the per-hostname mapping.
	Hostname string `yaml:"hostname"`
	// URL is the request to make. Its host must be the hostname.
	URL string `yaml:"url"`
	// Method is GET or HEAD.
	Method string `yaml:"method"`
	// Port is the TCP port to connect to. It must be the port the URL resolves
	// to.
	Port uint16 `yaml:"port"`
	// ExpectedStatus lists the response statuses that mean the request was
	// answered. Anything else, including a redirect, is a failure.
	ExpectedStatus []int `yaml:"expected_status"`
	// RequiredHeader lists headers a response must carry, by canonical name.
	RequiredHeader map[string]string `yaml:"required_headers"`
	// BodySHA256 is the digest the body must have, or empty when the body is not
	// identity.
	BodySHA256 string `yaml:"body_sha256"`
}

// CloudFrontProfile is one hostname to measure, and the addresses a profile named
// for it. A candidate from this list is only ever compared with candidates of the
// same hostname: that is the whole point of a per-hostname group.
type CloudFrontProfile struct {
	Profile    ProbeProfile
	Candidates []netip.Addr
}

// CloudFrontSource is the CloudFront side of candidate collection. It takes no
// limit and no date: a CloudFront group is whatever the operator wrote down, one
// profile per hostname.
type CloudFrontSource interface {
	Profiles(context.Context) ([]CloudFrontProfile, error)
}

// profileDocument is the shape of a profile file: a version and a list of
// profiles. Unknown fields are refused, because a profile is an instruction to
// publish an address for a hostname and a field this build ignored would be an
// instruction silently dropped.
type profileDocument struct {
	SchemaVersion int            `yaml:"schema_version"`
	Profiles      []profileEntry `yaml:"profiles"`
}

// profileEntry is one profile as written, with the address the profile named for
// its hostname.
type profileEntry struct {
	ProbeProfile `yaml:",inline"`
	Address      string `yaml:"ip"`
}

// ParseCloudFrontProfiles reads a profile document and returns the profiles it
// names.
//
// Only the hostname is mandatory, because it is the key of the per-hostname
// mapping: a profile that leaves it out is refused rather than defaulted, because
// two profiles would then be free to share one implicit mapping and a winner
// proved for one hostname could be published for another. Two profiles may not
// name the same hostname, in any spelling, because the state file publishes one
// address per hostname. Everything else is checked against itself: the URL must be
// an https URL for that hostname, the port must be the one the URL resolves to,
// the method must be one this release can send, the statuses must be statuses, the
// required headers must be real header names with printable values, and the body
// digest must be a lowercase SHA-256.
func ParseCloudFrontProfiles(reader io.Reader) ([]CloudFrontProfile, error) {
	if reader == nil {
		return nil, errors.New("a reader is required to parse a profile document")
	}
	document := profileDocument{}
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the profile document is empty")
		}
		return nil, fmt.Errorf("decode profile document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("the profile document must contain exactly one YAML document")
	}
	if document.SchemaVersion != profileSchemaVersion {
		return nil, fmt.Errorf("the profile document is schema version %d, not the supported version %d", document.SchemaVersion, profileSchemaVersion)
	}

	profiles := make([]CloudFrontProfile, 0, len(document.Profiles))
	owner := make(map[string]int, len(document.Profiles))
	for index, entry := range document.Profiles {
		profile, err := entry.profile()
		if err != nil {
			return nil, fmt.Errorf("profiles[%d]: %w", index, err)
		}
		// DNS names are case insensitive, so two spellings are one key.
		key := strings.ToLower(profile.Profile.Hostname)
		if previous, seen := owner[key]; seen {
			return nil, fmt.Errorf("profiles[%d]: the hostname %q is already used by profiles[%d]", index, profile.Profile.Hostname, previous)
		}
		owner[key] = index
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// profile turns one entry into a profile, filling in what the URL already implies
// and then holding the result to the same verdict a hand-built profile gets.
func (e profileEntry) profile() (CloudFrontProfile, error) {
	profile := CloudFrontProfile{Profile: e.ProbeProfile}
	// The hostname is checked before the URL, because a URL is checked against it
	// and an empty one would turn a missing hostname into a confusing complaint
	// about the URL instead.
	if profile.Profile.Hostname == "" {
		return CloudFrontProfile{}, errors.New("hostname is required: it is the key of the per-hostname mapping and is never defaulted")
	}
	_, port, err := probeURL(profile.Profile.URL, profile.Profile.Hostname)
	if err != nil {
		return CloudFrontProfile{}, err
	}
	if profile.Profile.Port == 0 {
		profile.Profile.Port = uint16(port)
	}
	if profile.Profile.Method == "" {
		profile.Profile.Method = http.MethodGet
	}
	profile.Profile.RequiredHeader, err = canonicalHeaders(profile.Profile.RequiredHeader)
	if err != nil {
		return CloudFrontProfile{}, err
	}
	if e.Address != "" {
		address, err := parsePublicIPv4(e.Address)
		if err != nil {
			return CloudFrontProfile{}, fmt.Errorf("ip: %w", err)
		}
		profile.Candidates = []netip.Addr{address}
	}
	if err := profile.Validate(); err != nil {
		return CloudFrontProfile{}, err
	}
	return profile, nil
}

// Validate refuses a profile a prober could not hold to, whether it was parsed
// from a document or built by hand. The hostname must be a DNS name, the URL an
// https URL for that exact hostname, the port the one the URL resolves to, the
// method one this release sends, the statuses real statuses with no repeats, the
// required headers printable header names, and the body digest a lowercase
// SHA-256. Every address the profile names must be an address a published rewrite
// target may name.
func (p CloudFrontProfile) Validate() error {
	if !validHostname(p.Profile.Hostname) {
		return fmt.Errorf("hostname %q must be a DNS name without a scheme, a path, an address or a wildcard", p.Profile.Hostname)
	}
	_, port, err := probeURL(p.Profile.URL, p.Profile.Hostname)
	if err != nil {
		return err
	}
	if p.Profile.Port == 0 {
		return fmt.Errorf("port must name the port %s resolves to, got none", p.Profile.URL)
	}
	if int(p.Profile.Port) != port {
		return fmt.Errorf("port %d contradicts the port %d of %s", p.Profile.Port, port, p.Profile.URL)
	}
	if p.Profile.Method != http.MethodGet && p.Profile.Method != http.MethodHead {
		return fmt.Errorf("method must be %s or %s, got %q", http.MethodGet, http.MethodHead, p.Profile.Method)
	}
	if len(p.Profile.ExpectedStatus) == 0 {
		return errors.New("expected_status must name at least one status")
	}
	seen := make(map[int]struct{}, len(p.Profile.ExpectedStatus))
	for index, status := range p.Profile.ExpectedStatus {
		if status < 100 || status > 599 {
			return fmt.Errorf("expected_status[%d] %d is not an HTTP status", index, status)
		}
		if _, repeated := seen[status]; repeated {
			return fmt.Errorf("expected_status repeats %d", status)
		}
		seen[status] = struct{}{}
	}
	if _, err := canonicalHeaders(p.Profile.RequiredHeader); err != nil {
		return err
	}
	if p.Profile.BodySHA256 != "" && !isLowerHex(p.Profile.BodySHA256, 64) {
		return fmt.Errorf("body_sha256 %q must be empty or a 64 character lowercase hex SHA-256", p.Profile.BodySHA256)
	}
	for index, address := range p.Candidates {
		if !validPublicIPv4(address) {
			return fmt.Errorf("candidates[%d] %s is not a public IPv4 address", index, address)
		}
	}
	return nil
}

// probeURL checks a profile URL against the hostname it must serve, and returns
// the port the URL resolves to. A URL is the one place a prober is told where to
// connect, so it may not name another host, carry credentials, or downgrade the
// transport.
func probeURL(rawURL, hostname string) (*url.URL, int, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, fmt.Errorf("url %q: %w", rawURL, err)
	}
	switch {
	case parsed.Scheme != "https":
		return nil, 0, fmt.Errorf("url %q must be an https URL", rawURL)
	case parsed.User != nil:
		return nil, 0, fmt.Errorf("url %q must not carry user information", rawURL)
	case parsed.Hostname() == "":
		return nil, 0, fmt.Errorf("url %q names no host", rawURL)
	case !strings.EqualFold(parsed.Hostname(), hostname):
		return nil, 0, fmt.Errorf("url %q is for %q, not the profile hostname %q", rawURL, parsed.Hostname(), hostname)
	}
	port := httpsPort
	if explicit := parsed.Port(); explicit != "" {
		value, err := strconv.ParseUint(explicit, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("url %q names the port %q, which is outside the port range", rawURL, explicit)
		}
		port = int(value)
	}
	return parsed, port, nil
}

// canonicalHeaders checks the required headers and returns them by canonical
// name, so a prober looks one up the same way whatever spelling a document used.
// A value with a control character would let a document append a header of its
// own to every request, and a header name that is not a name would make the check
// impossible to satisfy.
func canonicalHeaders(headers map[string]string) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	canonical := make(map[string]string, len(headers))
	for name, value := range headers {
		if !validHeaderName(name) {
			return nil, fmt.Errorf("required_headers names %q, which is not a header name", name)
		}
		if value == "" {
			return nil, fmt.Errorf("required_headers[%q] is empty, so it asks for nothing", name)
		}
		for index := 0; index < len(value); index++ {
			if value[index] < ' ' || value[index] == 0x7f {
				return nil, fmt.Errorf("required_headers[%q] carries a control character", name)
			}
		}
		key := http.CanonicalHeaderKey(name)
		if _, clash := canonical[key]; clash {
			return nil, fmt.Errorf("required_headers names %q twice once the spelling is canonical", key)
		}
		canonical[key] = value
	}
	return canonical, nil
}

// validHeaderName accepts the RFC 7230 token characters, which is what a header
// name may be made of and nothing else.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character <= ' ' || character >= 0x7f {
			return false
		}
		switch character {
		case '(', ')', ',', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '{', '}', '"':
			return false
		}
	}
	return true
}

// isLowerHex reports whether a value is exactly length lower-case hex characters.
// A digest is compared as bytes, so a different spelling of the same value would
// silently never match.
func isLowerHex(value string, length int) bool {
	if len(value) != length {
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

// HTTPCloudFrontSource carries the operator's profiles and keeps the published
// AWS ranges beside them as reference data.
//
// The AWS ranges are fetched, parsed and validated on every call, so a document
// that has stopped being usable is reported rather than assumed, and they are
// exposed as prefixes for an operator or a report to read. They are never
// expanded into candidates in this release: a CloudFront address only means
// anything behind the hostname of the profile that named it, and this package has
// no profile for the thousands of addresses AWS announces. The candidates a
// profile measures are the ones the profile named itself.
type HTTPCloudFrontSource struct {
	client    *http.Client
	baseURL   string
	cachePath string
	profiles  []CloudFrontProfile

	mutex     sync.Mutex
	reference []netip.Prefix
}

var _ CloudFrontSource = (*HTTPCloudFrontSource)(nil)

// NewCloudFrontSource returns a source for the given profiles. An empty base URL
// means DefaultCloudFrontBaseURL and an empty cache path means
// DefaultCloudFrontCachePath; the client is required, so a caller cannot
// accidentally reach the network with a default transport it did not choose. Every
// profile is held to the same verdict a parsed one is, so a profile built by hand
// cannot carry an address or a hostname a parsed one would have been refused for.
func NewCloudFrontSource(client *http.Client, baseURL, cachePath string, profiles []CloudFrontProfile) (*HTTPCloudFrontSource, error) {
	if client == nil {
		return nil, errors.New("an HTTP client is required to read the published AWS IP ranges")
	}
	if baseURL == "" {
		baseURL = DefaultCloudFrontBaseURL
	}
	if cachePath == "" {
		cachePath = DefaultCloudFrontCachePath
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("cloudfront source %q: %w", baseURL, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("cloudfront source %q must be an https URL", baseURL)
	}
	for index, profile := range profiles {
		if err := profile.Validate(); err != nil {
			return nil, fmt.Errorf("profiles[%d]: %w", index, err)
		}
	}
	return &HTTPCloudFrontSource{client: client, baseURL: baseURL, cachePath: cachePath, profiles: profiles}, nil
}

// Profiles returns the profiles this source carries, after reading and validating
// the published ranges it holds as reference data. It is safe to call from more
// than one goroutine.
func (s *HTTPCloudFrontSource) Profiles(ctx context.Context) ([]CloudFrontProfile, error) {
	fetched, err := fetchDocument(ctx, s.client, s.baseURL, s.cachePath, validatorOptional)
	if err != nil {
		return nil, err
	}
	prefixes, err := parseReferenceRanges(s.baseURL, fetched.Body)
	if err != nil {
		return nil, err
	}
	// The document is only stored once it has been accepted, so the cache never
	// holds a body this run refused.
	if err := storeDocument(s.cachePath, fetched); err != nil {
		return nil, err
	}
	s.mutex.Lock()
	s.reference = prefixes
	s.mutex.Unlock()
	profiles := make([]CloudFrontProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		clone := CloudFrontProfile{Profile: profile.Profile}
		clone.Profile.ExpectedStatus = slices.Clone(profile.Profile.ExpectedStatus)
		clone.Profile.RequiredHeader = maps.Clone(profile.Profile.RequiredHeader)
		clone.Candidates = slices.Clone(profile.Candidates)
		profiles = append(profiles, clone)
	}
	return profiles, nil
}

// ReferencePrefixes returns the CloudFront ranges of the last published document
// this source read successfully, in order. They are reference data: nothing in
// this release turns one of them into a candidate.
func (s *HTTPCloudFrontSource) ReferencePrefixes() []netip.Prefix {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return slices.Clone(s.reference)
}

// referenceDocument is the shape AWS publishes. Only the fields this package
// reads are declared, and a document with more is read the same way the list
// updater reads GitHub's: the fields it does not know about are not this build's
// business, and every field it does read is held to the same verdict.
type referenceDocument struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix string `json:"ip_prefix"`
		Region   string `json:"region"`
		Service  string `json:"service"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Region     string `json:"region"`
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"`
}

// parseReferenceRanges decodes and validates one published ranges document, and
// returns the CloudFront IPv4 ranges it announces in order. The IPv6 list is
// parsed and not used, for the same reason the Cloudflare document's is: this
// release selects IPv4 only.
func parseReferenceRanges(sourceURL string, body []byte) ([]netip.Prefix, error) {
	document := referenceDocument{}
	decoder := json.NewDecoder(newLimitedReader(body, maximumDocumentBytes*2))
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%s: decode document: %w", sourceURL, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: the document carries trailing content", sourceURL)
	}
	for index, entry := range document.IPv6Prefixes {
		prefix, err := netip.ParsePrefix(entry.IPv6Prefix)
		if err != nil {
			return nil, fmt.Errorf("%s: ipv6_prefixes[%d] %q is not a prefix: %w", sourceURL, index, entry.IPv6Prefix, err)
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("%s: ipv6_prefixes[%d] %q is not an IPv6 prefix", sourceURL, index, entry.IPv6Prefix)
		}
	}
	prefixes := make([]netip.Prefix, 0, len(document.Prefixes))
	for index, entry := range document.Prefixes {
		prefix, err := parseIPv4Prefix(entry.IPPrefix)
		if err != nil {
			return nil, fmt.Errorf("%s: prefixes[%d] (%s): %w", sourceURL, index, entry.Service, err)
		}
		if entry.Service == cloudFrontService {
			prefixes = append(prefixes, prefix)
		}
	}
	slices.SortFunc(prefixes, func(first, second netip.Prefix) int { return first.Addr().Compare(second.Addr()) })
	return prefixes, nil
}
