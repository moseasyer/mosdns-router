package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// committedPolicyPath is the policy this project ships. It is generated from
// Defaults() by Marshal, so an installation starts from the policy this code
// approves rather than from a copy somebody edited.
const committedPolicyPath = "../../configs/policy.yaml"

// TestCommittedPolicyIsExactlyTheMarshalledDefault holds the committed file to
// the code. The break it catches is hand-editing the file the router reads: an
// edited policy beside unchanged code would ship a document nothing in the
// repository can explain, and a policy that no longer matches the one the renderers
// were tested against would change what a generated configuration contains.
func TestCommittedPolicyIsExactlyTheMarshalledDefault(t *testing.T) {
	marshalled, err := Marshal(Defaults())
	if err != nil {
		t.Fatalf("Marshal(Defaults()): %v", err)
	}
	updateCommitted(t, committedPolicyPath, marshalled)

	committed, err := os.ReadFile(filepath.Clean(committedPolicyPath))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedPolicyPath, err)
	}
	if string(committed) != string(marshalled) {
		t.Errorf("%s is not the output of Marshal(Defaults())\n--- committed ---\n%s\n--- marshalled ---\n%s", committedPolicyPath, committed, marshalled)
	}
}

// TestTheMarshalledPolicyLoadsBackAsItself covers the one thing a byte
// comparison cannot: that the document this project writes is one its own strict
// loader accepts. A number encoded in a form the decoder reads as a string, or a
// key the loader does not know, would leave a file that is byte-for-byte the
// renderer's output and still unusable at startup.
func TestTheMarshalledPolicyLoadsBackAsItself(t *testing.T) {
	marshalled, err := Marshal(Defaults())
	if err != nil {
		t.Fatalf("Marshal(Defaults()): %v", err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, marshalled, 0o600); err != nil {
		t.Fatalf("write the marshalled policy: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("the marshalled policy does not load: %v\n%s", err, marshalled)
	}
	if !reflect.DeepEqual(loaded, Defaults()) {
		t.Fatalf("the loaded policy is\n%+v\nwant\n%+v", loaded, Defaults())
	}
}

// TestMarshalRefusesAPolicyItWouldNotAccept stops a broken policy from being
// written to disk in the first place. A committed file that the loader refuses is
// a router that cannot start, and a file is a much worse place to find that out
// than the generator.
func TestMarshalRefusesAPolicyItWouldNotAccept(t *testing.T) {
	unsupported := Defaults()
	unsupported.DHCP.FailurePolicy = "keep-forever"

	if document, err := Marshal(unsupported); err == nil {
		t.Fatalf("Marshal accepted a policy its own loader refuses and wrote:\n%s", document)
	}
}

// updateCommitted rewrites a committed file from the code that produces it, so
// the bytes in the repository are never hand-edited. Set MOSDNS_ROUTER_UPDATE=1
// to regenerate them; without it this does nothing and the comparison stands.
func updateCommitted(t *testing.T, path string, want []byte) {
	t.Helper()
	if os.Getenv("MOSDNS_ROUTER_UPDATE") == "" {
		return
	}
	if err := os.WriteFile(filepath.Clean(path), want, 0o644); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
	t.Logf("rewrote %s from Marshal", path)
}
