package dhcpstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// decodeFixture returns the committed document as a mutable value, so a case can
// change exactly one field of a document already proven acceptable.
func decodeFixture(t *testing.T) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(committedFixture(t))
	if err != nil {
		t.Fatalf("read the committed bridge fixture: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("the committed bridge fixture is not a JSON object: %v", err)
	}
	return document
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
