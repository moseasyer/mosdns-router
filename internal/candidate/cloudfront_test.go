package candidate

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The profile document is an in-memory string and the reference ranges come from
// the same local httptest origin, so nothing here reads a real CloudFront
// distribution, a real AWS document, or a clock.

const (
	// fixtureHostname is a CloudFront distribution name of the shape the service
	// issues. It is never resolved or dialled.
	fixtureHostname = "d111111abcdef8.cloudfront.net"
	// fixtureBodySHA256 is a well-formed lowercase digest, made up but shaped
	// like the real one.
	fixtureBodySHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	// referenceETag is the validator the fake origin hands out for the AWS
	// document.
	referenceETag = `W/"c1a2b3d4e5f6"`
)

// completeProfileBody is a profile body with every field present.
func completeProfileBody() string {
	return profileBody(
		"hostname: "+fixtureHostname,
		"ip: 13.32.0.1",
		"url: https://"+fixtureHostname+"/index.html",
		"method: GET",
		"port: 443",
		"expected_status: [200]",
		"required_headers:\n      x-amz-cf-id: E1234567890",
		"body_sha256: "+fixtureBodySHA256,
	)
}

// completeProfile is a document that must be accepted, with every field present.
func completeProfile() string {
	return profileFile(completeProfileBody())
}

// profileFile renders a document with one profile body, so every case below
// differs from the accepted document in exactly one field.
func profileFile(entry string) string {
	return profileList(entry)
}

// profileList renders a document with several profile bodies.
func profileList(entries ...string) string {
	return "schema_version: 1\nprofiles:\n" + strings.Join(entries, "")
}

// profileBody renders one profile body, the first line as the list item and
// every line after it as one of its fields.
func profileBody(fields ...string) string {
	var body strings.Builder
	for index, field := range fields {
		if index == 0 {
			body.WriteString("  - " + field + "\n")
			continue
		}
		body.WriteString("    " + field + "\n")
	}
	return body.String()
}

// acceptedEntry is the profile body every inconsistent case starts from, with one
// field changed or left out.
func acceptedEntry(changed ...string) string {
	fields := []string{
		"hostname: " + fixtureHostname,
		"url: https://" + fixtureHostname + "/index.html",
		"expected_status: [200]",
	}
	fields = append(fields, changed...)
	return profileBody(fields...)
}

// oneProfile is a profile body with the optional fields a complete document
// carries.
func oneProfile(fields ...string) string {
	return profileFile(acceptedEntry(fields...))
}

func TestParseCloudFrontProfilesReadsACompleteProfile(t *testing.T) {
	profiles, err := ParseCloudFrontProfiles(strings.NewReader(completeProfile()))
	if err != nil {
		t.Fatalf("ParseCloudFrontProfiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("got %d profiles, want 1: %+v", len(profiles), profiles)
	}
	want := CloudFrontProfile{
		Profile: ProbeProfile{
			Hostname:       fixtureHostname,
			URL:            "https://" + fixtureHostname + "/index.html",
			Method:         http.MethodGet,
			Port:           443,
			ExpectedStatus: []int{200},
			RequiredHeader: map[string]string{"X-Amz-Cf-Id": "E1234567890"},
			BodySHA256:     fixtureBodySHA256,
		},
		Candidates: []netip.Addr{netip.MustParseAddr("13.32.0.1")},
	}
	if len(profiles[0].Candidates) != 1 || profiles[0].Candidates[0] != want.Candidates[0] {
		t.Fatalf("got candidates %v, want %v", profiles[0].Candidates, want.Candidates)
	}
	got := profiles[0].Profile
	if got.Hostname != want.Profile.Hostname || got.URL != want.Profile.URL || got.Method != want.Profile.Method ||
		got.Port != want.Profile.Port || got.BodySHA256 != want.Profile.BodySHA256 {
		t.Errorf("got profile %+v, want %+v", got, want.Profile)
	}
	if !slices.Equal(got.ExpectedStatus, want.Profile.ExpectedStatus) {
		t.Errorf("got expected status %v, want %v", got.ExpectedStatus, want.Profile.ExpectedStatus)
	}
	for name, value := range want.Profile.RequiredHeader {
		if got.RequiredHeader[name] != value {
			t.Errorf("got required header %q = %q, want %q", name, got.RequiredHeader[name], value)
		}
	}
	if len(got.RequiredHeader) != len(want.Profile.RequiredHeader) {
		t.Errorf("got %d required headers, want %d", len(got.RequiredHeader), len(want.Profile.RequiredHeader))
	}
}

func TestParseCloudFrontProfilesFillsThePortAndMethodAProfileOmitted(t *testing.T) {
	// Only the hostname is mandatory. A profile that leaves out the method or the
	// port is completed from the one URL it named, so the prober never has to
	// guess what an empty field meant.
	profiles, err := ParseCloudFrontProfiles(strings.NewReader(oneProfile()))
	if err != nil {
		t.Fatalf("ParseCloudFrontProfiles: %v", err)
	}
	if profiles[0].Profile.Method != http.MethodGet || profiles[0].Profile.Port != 443 {
		t.Errorf("got method %q on port %d, want GET on 443", profiles[0].Profile.Method, profiles[0].Profile.Port)
	}
	if profiles[0].Profile.BodySHA256 != "" {
		t.Errorf("got body hash %q, want it empty", profiles[0].Profile.BodySHA256)
	}
	if len(profiles[0].Candidates) != 0 {
		t.Errorf("got candidates %v, want none: the profile named no address", profiles[0].Candidates)
	}
}
func TestParseCloudFrontProfilesAcceptsAProfileWithNoProfiles(t *testing.T) {
	profiles, err := ParseCloudFrontProfiles(strings.NewReader("schema_version: 1\nprofiles: []\n"))
	if err != nil {
		t.Fatalf("ParseCloudFrontProfiles: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("got %+v, want no profiles", profiles)
	}
}

func TestParseCloudFrontProfilesRefusesADocumentItCannotFullyRead(t *testing.T) {
	for name, document := range map[string]string{
		"an empty document":            "",
		"a comment only":               "# nothing configured yet\n",
		"no schema version":            "profiles: []\n",
		"another schema version":       "schema_version: 2\nprofiles: []\n",
		"an unknown field":             "schema_version: 1\nprofiles: []\nretries: 3\n",
		"an unknown profile field":     profileFile("  - hostname: " + fixtureHostname + "\n    timeout: 5\n"),
		"a second document":            completeProfile() + "---\nschema_version: 1\nprofiles: []\n",
		"profiles that are not a list": "schema_version: 1\nprofiles:\n  hostname: " + fixtureHostname + "\n",
	} {
		if profiles, err := ParseCloudFrontProfiles(strings.NewReader(document)); err == nil {
			t.Errorf("ParseCloudFrontProfiles accepted a document that is %s and returned %+v", name, profiles)
		}
	}
}

func TestParseCloudFrontProfilesRefusesAProfileWithoutAHostname(t *testing.T) {
	// The hostname is the key of the per-hostname mapping, so a profile that
	// omits it is refused rather than defaulted: two profiles would otherwise be
	// free to share one implicit mapping and a winner proved for one hostname
	// could be published for another. Every case below is otherwise a complete
	// profile, so a missing hostname is the only thing wrong with it.
	for name, document := range map[string]string{
		"only a URL": profileFile(profileBody(
			"url: https://"+fixtureHostname+"/index.html",
			"expected_status: [200]")),
		"an empty hostname": profileFile(profileBody(
			"hostname: \"\"",
			"url: https://"+fixtureHostname+"/index.html",
			"expected_status: [200]")),
		"only an address": profileFile(profileBody(
			"ip: 13.32.0.1",
			"expected_status: [200]")),
	} {
		if profiles, err := ParseCloudFrontProfiles(strings.NewReader(document)); err == nil {
			t.Errorf("ParseCloudFrontProfiles accepted a profile that has %s and returned %+v", name, profiles)
		}
	}
}

func TestParseCloudFrontProfilesRefusesABareAddressAsAHostname(t *testing.T) {
	// A hostname that is an address literal would key the mapping by an address
	// that no certificate can carry, and it is how a profile ends up looking like
	// a global candidate with a hostname attached.
	for _, hostname := range []string{"1.2.3.4", "13.32.0.1", "2606:4700::1"} {
		document := profileFile(profileBody(
			"hostname: \""+hostname+"\"",
			"url: https://"+fixtureHostname+"/index.html",
			"expected_status: [200]"))
		if profiles, err := ParseCloudFrontProfiles(strings.NewReader(document)); err == nil {
			t.Errorf("ParseCloudFrontProfiles accepted the hostname %q and returned %+v", hostname, profiles)
		}
	}
}

func TestParseCloudFrontProfilesRefusesTwoProfilesForOneHostname(t *testing.T) {
	// Two profiles for one hostname would be two identities proved for the same
	// key, and the state file can only publish one address for it. The second
	// profile is otherwise complete, so the shared hostname is the only thing
	// wrong with the document.
	for name, hostname := range map[string]string{
		"the same spelling": fixtureHostname,
		"another spelling":  strings.ToUpper(fixtureHostname),
	} {
		second := profileBody(
			"hostname: "+hostname,
			"url: https://"+fixtureHostname+"/other.html",
			"expected_status: [200]")
		document := profileList(completeProfileBody(), second)
		if profiles, err := ParseCloudFrontProfiles(strings.NewReader(document)); err == nil {
			t.Errorf("ParseCloudFrontProfiles accepted two profiles for one hostname spelled %s and returned %+v", name, profiles)
		}
	}
}

func TestParseCloudFrontProfilesRefusesAProfileThatIsInconsistentWithItself(t *testing.T) {
	// Every case is a complete profile body that differs from the accepted one in
	// exactly one field, so the failure names the field and not the document. A
	// hostname that is present but is not a DNS name belongs here rather than with
	// the absent hostnames: it is present, and refusing it is the hostname rule
	// doing its job.
	for name, document := range map[string]string{
		"a hostname that is not a DNS name": profileFile(profileBody(
			"hostname: \"# any host\"",
			"url: https://"+fixtureHostname+"/index.html",
			"expected_status: [200]")),
		"an address that is not one": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"ip: not-an-address")),
		"a private address": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"ip: 10.0.0.1")),
		"a documentation address": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"ip: 203.0.113.5")),
		"an IPv6 address": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"ip: 2606:4700::1")),
		"a URL that is not a URL": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: \"not a url\"", "expected_status: [200]")),
		"a URL that is not https": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: http://"+fixtureHostname+"/index.html", "expected_status: [200]")),
		"a URL for another host": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://other.example/index.html", "expected_status: [200]")),
		"a URL with userinfo": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: \"https://user@"+fixtureHostname+"/index.html\"", "expected_status: [200]")),
		"a port the URL contradicts": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"port: 8443")),
		"a port outside the port range": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"port: 70000")),
		"a method that is not GET or HEAD": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"method: POST")),
		"a method in the wrong case": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"method: get")),
		"an expected status that is empty": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: []")),
		"an expected status that is not a status": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [99]")),
		"an expected status above the range": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [600]")),
		"a repeated expected status": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200, 200]")),
		"a required header with no name": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"required_headers:\n      \"\": value")),
		"a required header name with a space": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"required_headers:\n      \"x test\": value")),
		"a required header value with a newline": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"required_headers:\n      x-test: \"value\\r\\ninjected: yes\"")),
		"an empty required header value": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"required_headers:\n      x-test: \"\"")),
		"a body hash that is too short": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"body_sha256: 9f86d081")),
		"a body hash in upper case": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"body_sha256: 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08")),
		"a body hash that is not hex": profileFile(profileBody(
			"hostname: "+fixtureHostname, "url: https://"+fixtureHostname+"/index.html", "expected_status: [200]",
			"body_sha256: zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")),
	} {
		if profiles, err := ParseCloudFrontProfiles(strings.NewReader(document)); err == nil {
			t.Errorf("ParseCloudFrontProfiles accepted a profile with %s and returned %+v", name, profiles)
		}
	}
}

func TestParseCloudFrontProfilesKeepsThePortAProfileDeclaredOnBothSides(t *testing.T) {
	profiles, err := ParseCloudFrontProfiles(strings.NewReader(profileFile(profileBody(
		"hostname: "+fixtureHostname,
		"url: https://"+fixtureHostname+":8443/index.html",
		"expected_status: [200]",
		"port: 8443",
	))))
	if err != nil {
		t.Fatalf("ParseCloudFrontProfiles: %v", err)
	}
	if profiles[0].Profile.Port != 8443 {
		t.Errorf("got port %d, want 8443", profiles[0].Profile.Port)
	}
}

// awsRangesDocument is the AWS document shape, with the three services that
// matter: the CloudFront ranges, an unrelated service in the same space, and the
// origin-facing range, plus the separate IPv6 list.
func awsRangesDocument() string {
	return `{"syncToken":"1784000000","createDate":"2026-09-25T00-00-00Z","prefixes":[` +
		`{"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"},` +
		`{"ip_prefix":"13.34.0.0/15","region":"us-east-1","service":"AMAZON"},` +
		`{"ip_prefix":"13.35.0.0/16","region":"GLOBAL","service":"CLOUDFRONT_ORIGIN_FACING"}` +
		`],"ipv6_prefixes":[` +
		`{"ipv6_prefix":"2600:1f13::/36","region":"GLOBAL","service":"CLOUDFRONT"}]}`
}

// cloudFrontReferencePrefix is the only range in the fixture that names the
// CloudFront service itself.
var cloudFrontReferencePrefix = netip.MustParsePrefix("13.32.0.0/15")

func newTestCloudFrontSource(t *testing.T, origin *fakeOrigin, cachePath string, profiles []CloudFrontProfile) *HTTPCloudFrontSource {
	t.Helper()
	source, err := NewCloudFrontSource(origin.client, origin.server.URL, cachePath, profiles)
	if err != nil {
		t.Fatalf("NewCloudFrontSource: %v", err)
	}
	return source
}

func TestCloudFrontSourceReturnsTheProfilesItWasGiven(t *testing.T) {
	// The profiles are the operator's own document; the source carries them
	// through unchanged, so nothing a later task measures is invented here.
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	parsed, err := ParseCloudFrontProfiles(strings.NewReader(completeProfile()))
	if err != nil {
		t.Fatalf("ParseCloudFrontProfiles: %v", err)
	}
	source := newTestCloudFrontSource(t, origin, filepath.Join(t.TempDir(), "aws-ip-ranges.json"), parsed)

	got0, err := source.Profiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if len(got0) != 1 {
		t.Fatalf("got %d profiles, want 1: %+v", len(got0), got0)
	}
	got, want := got0[0].Profile, parsed[0].Profile
	if got.Hostname != want.Hostname || got.URL != want.URL || got.Method != want.Method ||
		got.Port != want.Port || got.BodySHA256 != want.BodySHA256 {
		t.Errorf("got profile %+v, want %+v", got, want)
	}
	if !slices.Equal(got.ExpectedStatus, want.ExpectedStatus) {
		t.Errorf("got expected status %v, want %v", got.ExpectedStatus, want.ExpectedStatus)
	}
	if !maps.Equal(got.RequiredHeader, want.RequiredHeader) {
		t.Errorf("got required headers %v, want %v", got.RequiredHeader, want.RequiredHeader)
	}
}

func TestCloudFrontSourceKeepsThePublishedRangesAsReferenceData(t *testing.T) {
	// The reference ranges are fetched, parsed and validated so an operator can
	// see them and so a broken document is caught, but they are the service's own
	// announcement rather than a measurement result: only the CloudFront service
	// entries are kept, sorted, and only as reference.
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	source := newTestCloudFrontSource(t, origin, filepath.Join(t.TempDir(), "aws-ip-ranges.json"), nil)
	if _, err := source.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	got := source.ReferencePrefixes()
	if !slices.Equal(got, []netip.Prefix{cloudFrontReferencePrefix}) {
		t.Errorf("got the reference ranges %v, want only %v", got, cloudFrontReferencePrefix)
	}
}

func TestCloudFrontReferenceRangesAreExposedAsPrefixesAndNeverAsCandidates(t *testing.T) {
	// AWS CloudFront ranges are reference data in this release. The guarantee has
	// two halves, and this test checks the half that can be checked mechanically:
	// the ranges leave this package as prefixes and by no other route, and the only
	// method that exposes them hands back prefixes. A CloudFront address only means
	// anything behind the hostname of a profile that named it, and a global
	// candidate is served for any host, so a method that turned one of these
	// prefixes into a candidate would be the leak the spec is about. The other half
	// is that no production code calls the accessor at all, which is a fact about
	// the tree rather than about a run.
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	source := newTestCloudFrontSource(t, origin, filepath.Join(t.TempDir(), "aws-ip-ranges.json"), nil)
	if _, err := source.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if !slices.Equal(source.ReferencePrefixes(), []netip.Prefix{cloudFrontReferencePrefix}) {
		t.Fatalf("got the reference ranges %v, want only %v", source.ReferencePrefixes(), cloudFrontReferencePrefix)
	}

	candidateList := reflect.TypeOf([]Candidate(nil))
	candidateSet := reflect.TypeOf(CandidateSet{})
	exposed := reflect.TypeOf(&HTTPCloudFrontSource{})
	for index := range exposed.NumMethod() {
		method := exposed.Method(index)
		if method.Type.NumOut() == 0 {
			continue
		}
		if method.Type.Out(0) == candidateList || method.Type.Out(0) == candidateSet {
			t.Errorf("%s.%s returns %v, so the CloudFront ranges could reach a candidate", exposed, method.Name, method.Type.Out(0))
		}
	}

	// And nothing the official source produces falls inside one of them either.
	cloudflareOrigin := newFakeOrigin(t, standardDocument(), fixtureETag)
	official := cloudflareCandidates(t, newTestSource(t, cloudflareOrigin, filepath.Join(t.TempDir(), "cloudflare-ips.json")), 512, testDate(2026, time.September, 25))
	got, err := Combine(official, nil, nil, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(got) != len(official) {
		t.Fatalf("got %d global candidates, want the %d of the Cloudflare sample", len(got), len(official))
	}
	for _, candidate := range got {
		if cloudFrontReferencePrefix.Contains(candidate.IP) {
			t.Errorf("the global candidate list holds %v, which is inside the CloudFront range %v", candidate.IP, cloudFrontReferencePrefix)
		}
	}
}

func TestCloudFrontSourceDoesNotStoreADocumentItCouldNeverRevalidate(t *testing.T) {
	// This origin documents no ETag. The ranges are still read and kept as
	// reference data, because this source has other work to do with them, but a
	// stored copy could never be revalidated and readCache would refuse it, so
	// nothing is written: a file that looks like a cache and is not one is worse
	// than no file.
	cachePath := filepath.Join(t.TempDir(), "aws-ip-ranges.json")
	origin := newFakeOrigin(t, awsRangesDocument(), "")
	source := newTestCloudFrontSource(t, origin, cachePath, nil)
	if _, err := source.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if !slices.Equal(source.ReferencePrefixes(), []netip.Prefix{cloudFrontReferencePrefix}) {
		t.Errorf("got the reference ranges %v, want %v", source.ReferencePrefixes(), cloudFrontReferencePrefix)
	}
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a document with no validator was written to %s (stat error %v)", cachePath, err)
	}
}

func TestCloudFrontSourceRefusesAReferenceRangeItCannotUse(t *testing.T) {
	// The reference document is validated as strictly as the Cloudflare one: a
	// range no rewrite target may name, a malformed entry, and a document that is
	// not a document are all refused.
	for name, document := range map[string]string{
		"not JSON":                       `not json at all`,
		"a private range":                `{"prefixes":[{"ip_prefix":"10.0.0.0/8","region":"GLOBAL","service":"CLOUDFRONT"}]}`,
		"a malformed range":              `{"prefixes":[{"ip_prefix":"13.32.0.0/99","region":"GLOBAL","service":"CLOUDFRONT"}]}`,
		"a range with no prefix":         `{"prefixes":[{"region":"GLOBAL","service":"CLOUDFRONT"}]}`,
		"an IPv4 range in the IPv6 list": `{"prefixes":[],"ipv6_prefixes":[{"ipv6_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"}]}`,
		"a malformed IPv6 range":         `{"prefixes":[],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f13::/129","region":"GLOBAL","service":"CLOUDFRONT"}]}`,
		"a second document":              awsRangesDocument() + `{"prefixes":[]}`,
	} {
		origin := newFakeOrigin(t, document, referenceETag)
		source := newTestCloudFrontSource(t, origin, filepath.Join(t.TempDir(), "aws-ip-ranges.json"), nil)
		if profiles, err := source.Profiles(context.Background()); err == nil {
			t.Errorf("Profiles accepted a reference document that is %s and returned %+v", name, profiles)
		}
		if len(source.ReferencePrefixes()) != 0 {
			t.Errorf("a refused document left %v behind as reference ranges", source.ReferencePrefixes())
		}
	}
}

func TestCloudFrontSourceRevalidatesTheReferenceDocument(t *testing.T) {
	// The reference document is cached under its own injected path and
	// revalidated with the stored validator, exactly like the Cloudflare one: two
	// runs of a day cost one body and one 304.
	cachePath := filepath.Join(t.TempDir(), "lists", "aws-ip-ranges.json")
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	first := newTestCloudFrontSource(t, origin, cachePath, nil)
	if _, err := first.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}

	origin.setNotModified(true)
	second := newTestCloudFrontSource(t, origin, cachePath, nil)
	if _, err := second.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles after the origin answered 304: %v", err)
	}
	if !slices.Equal(second.ReferencePrefixes(), []netip.Prefix{cloudFrontReferencePrefix}) {
		t.Errorf("the cached document gave the reference ranges %v", second.ReferencePrefixes())
	}

	requests := origin.requests()
	if len(requests) != 2 {
		t.Fatalf("got %d requests, want one per run", len(requests))
	}
	if requests[1].ifNoneMatch != referenceETag {
		t.Errorf("second request sent If-None-Match %q, want the stored %q", requests[1].ifNoneMatch, referenceETag)
	}
	if origin.bodiesServed() != 1 {
		t.Errorf("the origin served %d bodies, want only the first", origin.bodiesServed())
	}
}

func TestCloudFrontSourceCachesTheReferenceDocumentUnderTheInjectedPath(t *testing.T) {
	root := t.TempDir()
	cachePath := filepath.Join(root, "lists", "aws-ip-ranges.json")
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	if _, err := newTestCloudFrontSource(t, origin, cachePath, nil).Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	var written []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			written = append(written, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk the injected cache root: %v", err)
	}
	if len(written) != 1 || written[0] != cachePath {
		t.Errorf("the run wrote %v, want only %s", written, cachePath)
	}
	contents, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var document struct {
		ETag string          `json:"etag"`
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode cache: %v", err)
	}
	if document.ETag != referenceETag || string(document.Body) != awsRangesDocument() {
		t.Errorf("the cache holds the validator %q and the body %q", document.ETag, document.Body)
	}
}

func TestNewCloudFrontSourceRefusesAProfileItWouldNeverMeasure(t *testing.T) {
	// A caller that builds profiles by hand instead of parsing a document gets
	// the same verdict, so a reserved address cannot reach a probe through the
	// back door.
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	hosted := CloudFrontProfile{Profile: ProbeProfile{Hostname: fixtureHostname, URL: "https://" + fixtureHostname + "/", Method: http.MethodGet, Port: 443, ExpectedStatus: []int{200}}}
	for name, profile := range map[string]CloudFrontProfile{
		"a private candidate": {
			Profile:    hosted.Profile,
			Candidates: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
		"an IPv6 candidate": {
			Profile:    hosted.Profile,
			Candidates: []netip.Addr{netip.MustParseAddr("2606:4700::1")},
		},
		"a profile with no hostname": {Profile: ProbeProfile{URL: "https://cdn.example/", Method: http.MethodGet, Port: 443, ExpectedStatus: []int{200}}},
	} {
		if _, err := NewCloudFrontSource(origin.client, origin.server.URL, filepath.Join(t.TempDir(), "aws.json"), []CloudFrontProfile{profile}); err == nil {
			t.Errorf("NewCloudFrontSource accepted a profile with %s", name)
		}
	}
}

func TestNewCloudFrontSourceRefusesANilClient(t *testing.T) {
	if _, err := NewCloudFrontSource(nil, DefaultCloudFrontBaseURL, DefaultCloudFrontCachePath, nil); err == nil {
		t.Error("NewCloudFrontSource accepted a nil HTTP client")
	}
}

func TestCloudFrontSourceUsesTheProductionEndpointByDefault(t *testing.T) {
	origin := newFakeOrigin(t, awsRangesDocument(), referenceETag)
	source, err := NewCloudFrontSource(hostRewritingClient(t, origin), "", filepath.Join(t.TempDir(), "aws-ip-ranges.json"), nil)
	if err != nil {
		t.Fatalf("NewCloudFrontSource: %v", err)
	}
	if _, err := source.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	requests := origin.requests()
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if requests[0].path != "/ip-ranges.json" {
		t.Errorf("the default source requested %q, want the AWS IP ranges path", requests[0].path)
	}
}
