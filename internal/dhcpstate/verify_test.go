package dhcpstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"mosdns-router/internal/state"
)

// committedFixture is the state document the Python publisher generated for
// bridge/tests/fixtures. Go runs a package's tests with the package directory as
// the working directory, so it is resolved from here rather than from the
// repository root the task brief was written against.
func committedFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "bridge", "tests", "fixtures", "dhcp-upstreams.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the committed bridge fixture is missing at %s: %v", path, err)
	}
	return path
}

// writeState puts one document on disk and returns its path. Every case reads a
// real file, so nothing about the reader is assumed from how the test built it.
func writeState(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dhcp-upstreams.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write state document: %v", err)
	}
	return path
}

// decodeBody returns an arbitrary document as a mutable value, so a case can
// change exactly one field of bytes it was given -- a committed fixture's or a
// capture's -- without a second copy of the decoding.
func decodeBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("document is not a JSON object: %v", err)
	}
	return document
}

// decodeFixture returns the committed document as a mutable value, so a case can
// change exactly one field of a document already proven acceptable.
func decodeFixture(t *testing.T) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(committedFixture(t))
	if err != nil {
		t.Fatalf("read the committed bridge fixture: %v", err)
	}
	return decodeBody(t, payload)
}

// encodeDocument writes a document back out as JSON. Its field order is this
// function's, not the publisher's, so a case cannot pass merely because the
// reader happens to accept the order the bridge writes.
func encodeDocument(t *testing.T, document map[string]any) string {
	t.Helper()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode state document: %v", err)
	}
	return string(encoded)
}

// stringValues returns every string a document carries at any depth, so a
// rejection can be checked against the values the document really held. A body
// that is not JSON has no values to walk, and the caller decides what a
// diagnostic must not quote instead.
func stringValues(t *testing.T, body string) []string {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return nil
	}
	var values []string
	collectStrings(decoded, &values)
	return values
}

func collectStrings(value any, into *[]string) {
	switch typed := value.(type) {
	case string:
		*into = append(*into, typed)
	case map[string]any:
		for _, nested := range typed {
			collectStrings(nested, into)
		}
	case []any:
		for _, nested := range typed {
			collectStrings(nested, into)
		}
	}
}

// quotedValues returns the values message repeats, across every group it was
// given. A refusal is allowed to name the field it refused and nothing of the
// value, so every string a document carried is a string the message must not
// repeat back.
func quotedValues(message string, groups ...[]string) []string {
	var quoted []string
	for _, values := range groups {
		for _, value := range values {
			if strings.Contains(message, value) {
				quoted = append(quoted, value)
			}
		}
	}
	return quoted
}

// assertUsable requires that the document at path is a state the router can use,
// and that a refusal of it names the field it refused rather than any value the
// document carried. Both acceptance cases need the second half, because a rule that
// grew stricter than intended fails by refusing something usable, and that refusal
// reaches the same packaging logs as a correct one.
func assertUsable(t *testing.T, path, body string) {
	t.Helper()
	err := VerifyFixture(path)
	if err == nil {
		return
	}
	if quoted := quotedValues(err.Error(), stringValues(t, body)); len(quoted) > 0 {
		t.Fatalf("error quotes the document's own values %q: %v", quoted, err)
	}
	t.Fatalf("VerifyFixture refused a state the bridge publishes: %v", err)
}

// TestVerifyFixtureAcceptsTheCommittedBridgeState is the cross-language proof:
// the bytes the Python publisher wrote are a state the router's own reader
// accepts. A bridge that published a document this reader would refuse, or a
// reader that tightened past the schema, both fail here.
func TestVerifyFixtureAcceptsTheCommittedBridgeState(t *testing.T) {
	payload, err := os.ReadFile(committedFixture(t))
	if err != nil {
		t.Fatalf("read the committed bridge fixture: %v", err)
	}
	assertUsable(t, committedFixture(t), string(payload))
}

// TestVerifyFixtureAcceptsADisabledState pins the other side of the last-good
// rule. A readable lease that named no resolver, and a down event, both publish a
// state with no upstreams and last_good false: that is the documented way to
// disable the domestic branch, and the bridge emits it on ordinary events. The
// rule may therefore refuse only the states that name resolvers nobody vouched
// for. A rule that refused every not-last-known-good state would pass a suite with
// no such case, and would stop the router from serving anything the moment a lease
// carried no DNS.
func TestVerifyFixtureAcceptsADisabledState(t *testing.T) {
	// The committed document with its resolver list emptied and the marker that
	// says the list is not vouched for, which is exactly what the publisher writes
	// for a down event on an interface that had a lease.
	document := decodeFixture(t)
	document["upstreams"] = []any{}
	document["last_good"] = false
	body := encodeDocument(t, document)
	assertUsable(t, writeState(t, body), body)
}

// captureLease is the exact bytes a capture published when it read a dual-stack
// lease from NetworkManager's own raw DHCP fields on enp3s0 and then looked the
// connection up: a real `mosdns-dhcp-bridge --capture-current enp3s0 ...` run
// through cli.main with a fixed clock and this runner double.
//
//	answers := map[tuple][]string{
//	  ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", "enp3s0"): {"192.168.1.1\n"},
//	  ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", "enp3s0"): {"fd00::1\n"},
//	  ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", "enp3s0"):                 {"1111...1111\n"},
//	}
//	cli._observed_now = fixed at 2026-09-26T16:04:22Z
//
// It is a byte literal rather than a second committed file for two reasons. A
// committed file is a document a later commit could hand-edit until it describes
// a state no writer emits, which is the exact failure bridge/tests/test_fixture.py
// exists to prevent on the Python side. And these bytes carry what the committed
// fixture does not: both address families, a source only a capture records as
// nm-dhcp, and a connection the capture had to ask NetworkManager for. A bridge
// that wrote the right bytes for the wrong reason would still be caught here,
// because a writer that recorded a source it could not produce, or a state
// without the connection, would differ from this document.
var captureLease = []byte(`{
  "schema_version": 1,
  "generation": 1,
  "interface": "enp3s0",
  "connection_uuid": "11111111-1111-1111-1111-111111111111",
  "upstreams": [
    "192.168.1.1",
    "fd00::1"
  ],
  "observed_at": "2026-09-26T16:04:22Z",
  "source": "nm-dhcp",
  "last_good": true
}
`)

// captureEmpty is the same capture on a machine whose lease named no resolver:
// both raw fields answered and both were empty, so the collector's first readable
// source answered and published nothing. It is the case a first install hits when
// ignore-auto-dns has already emptied the lease, and it is why the capture looks
// the connection up even with no resolvers to publish: the document records which
// connection stopped answering, so the first dispatcher event after it is the
// same state rather than a second generation.
var captureEmpty = []byte(`{
  "schema_version": 1,
  "generation": 1,
  "interface": "enp3s0",
  "connection_uuid": "11111111-1111-1111-1111-111111111111",
  "upstreams": [],
  "observed_at": "2026-09-26T16:04:22Z",
  "source": "nm-dhcp",
  "last_good": false
}
`)

// captureFacts records what the capture put in the document, so a change to what
// the capture writes cannot leave this file agreeing with itself.
var captureFacts = map[string]state.DHCPState{
	"lease": {
		SchemaVersion:  1,
		Generation:     1,
		Interface:      "enp3s0",
		ConnectionUUID: "11111111-1111-1111-1111-111111111111",
		Upstreams:      []string{"192.168.1.1", "fd00::1"},
		ObservedAt:     time.Date(2026, time.September, 26, 16, 4, 22, 0, time.UTC),
		Source:         "nm-dhcp",
		LastGood:       true,
	},
	"empty": {
		SchemaVersion:  1,
		Generation:     1,
		Interface:      "enp3s0",
		ConnectionUUID: "11111111-1111-1111-1111-111111111111",
		Upstreams:      []string{},
		ObservedAt:     time.Date(2026, time.September, 26, 16, 4, 22, 0, time.UTC),
		Source:         "nm-dhcp",
		LastGood:       false,
	},
}

// TestCaptureBytesAreTheStateWriterEmits is what keeps the two literals above
// honest without a bridge between the two suites. Marshalling the recorded facts
// through the same state writer the runtime decodes has to reproduce the capture's
// bytes exactly, so a hand-edited literal, a reindented one, or one left behind by
// a serialisation change fails here rather than passing as a document this reader
// happens to like.
func TestCaptureBytesAreTheStateWriterEmits(t *testing.T) {
	for name, want := range captureFacts {
		emitted, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatalf("marshal the %s capture facts: %v", name, err)
		}
		if got := append(emitted, '\n'); string(got) != string(bytesFor(name)) {
			t.Errorf("the %s capture literal is not what the state writer emits:\n got: %s\nwant: %s", name, got, emitted)
		}
	}
}

// bytesFor returns the capture literal under test.
func bytesFor(name string) []byte {
	if name == "empty" {
		return captureEmpty
	}
	return captureLease
}

// TestVerifyFixtureAcceptsACapture is the requirement the packaging plan states:
// what an installation publishes through --capture-current has to pass the same
// verification the committed fixture passes, because the router will read it the
// same way. Both documents a capture can produce go through the same call.
func TestVerifyFixtureAcceptsACapture(t *testing.T) {
	for name, body := range map[string][]byte{"lease": captureLease, "empty": captureEmpty} {
		t.Run(name, func(t *testing.T) {
			assertUsable(t, writeState(t, string(body)), string(body))
		})
	}
}

// The capture is verified by the same decoder as any other document, so the
// rules it must not break are the same ones. Each case changes exactly one field
// of bytes a capture really published, which is what makes a refusal attributable
// to that change and not to a document that was wrong to begin with.
func TestVerifyFixtureRejectsACaptureTheRouterCannotUse(t *testing.T) {
	cases := []struct {
		name string
		body func(t *testing.T, base map[string]any) string
	}{
		{
			name: "a field the reader does not know",
			body: func(t *testing.T, base map[string]any) string {
				base["installer"] = "mosdns-installer"
				return encodeDocument(t, base)
			},
		},
		{
			name: "a schema version the reader does not speak",
			body: func(t *testing.T, base map[string]any) string {
				base["schema_version"] = 2
				return encodeDocument(t, base)
			},
		},
		{
			// A capture that recorded a resolvers stub instead of the lease's own
			// resolvers would be a document the router may not forward to.
			name: "an upstream that is this host",
			body: func(t *testing.T, base map[string]any) string {
				base["upstreams"] = []any{"127.0.0.53"}
				return encodeDocument(t, base)
			},
		},
		{
			name: "resolvers nobody vouched for",
			body: func(t *testing.T, base map[string]any) string {
				base["last_good"] = false
				return encodeDocument(t, base)
			},
		},
		{
			name: "an interface no device could own",
			body: func(t *testing.T, base map[string]any) string {
				base["interface"] = "enp3s0:1"
				return encodeDocument(t, base)
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := testCase.body(t, decodeBody(t, captureLease))
			path := writeState(t, body)

			err := VerifyFixture(path)
			if err == nil {
				t.Fatalf("VerifyFixture accepted a capture the router cannot use:\n%s", body)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the document it refused", err)
			}
		})
	}
}

// The reader does not require a connection: DHCPState.Validate has no such rule,
// and this reader adds only the last-known-good one. A capture of a lease that
// named resolvers always records the connection, so the document above has one,
// and a writer that stopped looking it up would be refused by the Python
// publisher rather than here. The case is here so that gap is asserted rather
// than assumed: if a future reader starts requiring the connection, this fails
// and the plan's Task 4 note about it has to be revisited with it.
func TestVerifyFixtureAcceptsACaptureWithoutItsConnection(t *testing.T) {
	document := decodeBody(t, captureLease)
	document["connection_uuid"] = ""
	body := encodeDocument(t, document)
	assertUsable(t, writeState(t, body), body)
}

// The source a capture records is the one the collector reported, and the tokens
// it can report are the writer's vocabulary. This holds the same list the Python
// writer's collector defines, so a document that names a source nothing produces
// is a shape the reader accepts but no writer emits.
func TestACaptureNamesOnlySourceTokensTheWriterProduces(t *testing.T) {
	writerTokens := []string{
		"down",
		"dispatcher-env",
		"nm-dhcp",
		"nm-dhcp4",
		"nm-dhcp6",
		"nm-effective",
		"resolved",
	}
	for name, body := range map[string][]byte{"lease": captureLease, "empty": captureEmpty} {
		document := decodeBody(t, body)
		source, ok := document["source"].(string)
		if !ok {
			t.Fatalf("the %s capture recorded no source: %v", name, document["source"])
		}
		if !slices.Contains(writerTokens, source) {
			t.Errorf("the %s capture recorded source %q, which no writer of this project produces; the writer's tokens are %v", name, source, writerTokens)
		}
	}
}

// TestVerifyFixtureRejectsADocumentTheRouterCannotUse covers every way the
// published document stops being usable. Each case changes exactly one thing in a
// document the previous test proved acceptable, so a refusal is attributable to
// that change and not to a document that was wrong to begin with.
func TestVerifyFixtureRejectsADocumentTheRouterCannotUse(t *testing.T) {
	carried := stringValues(t, encodeDocument(t, decodeFixture(t)))
	cases := []struct {
		name string
		// body returns the document under test, built from the committed one.
		body func(t *testing.T, base map[string]any) string
		// planted names values the case adds in a position stringValues cannot
		// reach, because the body is not JSON.
		planted []string
	}{
		{
			name: "a field the reader does not know",
			body: func(t *testing.T, base map[string]any) string {
				base["expiry"] = "2027-01-01T00:00:00Z"
				return encodeDocument(t, base)
			},
		},
		{
			name: "a schema version the reader does not speak",
			body: func(t *testing.T, base map[string]any) string {
				base["schema_version"] = 2
				return encodeDocument(t, base)
			},
		},
		{
			name: "an upstream that is this host",
			body: func(t *testing.T, base map[string]any) string {
				base["upstreams"] = []any{"127.0.0.53"}
				return encodeDocument(t, base)
			},
		},
		{
			// A rename is a whole document or nothing, so a reader that ignored the
			// end of the file would accept a state that was never completely written.
			name: "a document that was cut off",
			body: func(t *testing.T, base map[string]any) string {
				text := encodeDocument(t, base)
				return text[:strings.Index(text, "\n}")]
			},
		},
		{
			// A second document means something else claimed the file after the
			// state, and nothing says which half the router would have read.
			name: "another document after the state",
			body: func(t *testing.T, base map[string]any) string {
				return encodeDocument(t, base) + "\n{\"next_state\": \"192.168.1.99\"}\n"
			},
			planted: []string{"192.168.1.99"},
		},
		{
			// The state schema allows this, so it is the one rule the verifier adds
			// on top of the decoder: resolvers nobody vouched for are resolvers a
			// query must not be sent to.
			name: "a state that is not last known good but names upstreams",
			body: func(t *testing.T, base map[string]any) string {
				base["last_good"] = false
				return encodeDocument(t, base)
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := testCase.body(t, decodeFixture(t))
			path := writeState(t, body)

			err := VerifyFixture(path)
			if err == nil {
				t.Fatalf("VerifyFixture accepted a document the router cannot use:\n%s", body)
			}
			// The path is the one thing an operator can act on: it says which file
			// to replace, so it must survive every refusal.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the document it refused", err)
			}
			// A diagnostic reaches packaging and container logs, and the document
			// holds the resolver set, so a refusal names the field it refused and
			// not the value. A wrapper that quoted the decoder's own message, or
			// the document, would still pass the assertions above; this catches it.
			values := stringValues(t, body)
			if values == nil {
				// The body is not JSON at all, so the values to protect are the ones
				// the committed document carries, which is where these bodies come
				// from.
				values = carried
			}
			if quoted := quotedValues(err.Error(), values, testCase.planted); len(quoted) > 0 {
				t.Errorf("error quotes the document's own values %q: %v", quoted, err)
			}
		})
	}
}
