package candidate

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The profile document is an in-memory string, so nothing here reads a real
// CloudFront distribution, a real AWS document, or a clock. This release does not
// fetch the AWS document at all: a per-hostname address comes from a profile the
// operator wrote, so the range list has no consumer.

const (
	// fixtureHostname is a CloudFront distribution name of the shape the service
	// issues. It is never resolved or dialled.
	fixtureHostname = "d111111abcdef8.cloudfront.net"
	// fixtureBodySHA256 is a well-formed lowercase digest, made up but shaped
	// like the real one.
	fixtureBodySHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
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

