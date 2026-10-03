package config

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

// TestTheCommittedPolicyNamesNoMachineLocalAddress holds the committed document
// to the same rule the routing configuration is held to.
//
// **The foreign route is the exception, and the exception is the whole reason this
// test needs rewording rather than deleting.** `foreign.upstreams[].bootstrap` is
// a list of public resolver addresses by necessity: the machine's only resolver is
// the router itself, so a domain upstream has to be told where to look up its own
// name. Those are PUBLIC addresses -- Quad9's, published by Quad9 -- and shipping
// them leaks nothing about the machine.
//
// What must never appear is an address that identifies the machine or its network:
// a DHCP server the installer discovered, a router's LAN address, a name server on
// the local segment. So the rule is not "no address" but "no address that is not
// a well-known public resolver", and the list below is the closed set the shipped
// policy is allowed to name.
//
// A bootstrap pointing at a LAN resolver would fail this test, and it SHOULD: it
// would ship the operator's network topology to everyone who cloned the
// repository, and nothing in the policy's own schema would object.
func TestTheCommittedPolicyNamesNoMachineLocalAddress(t *testing.T) {
	committed, err := os.ReadFile(filepath.Clean(committedPolicyPath))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedPolicyPath, err)
	}
	published := map[string]bool{
		// Quad9's own plain-DNS resolvers, the same two the DNSCrypt document's
		// bootstrap already uses (internal/dnscrypt/config.go). Public, published,
		// and identical on every install of this package.
		"9.9.9.9":       true,
		"149.112.112.9": true,
	}
	found := ipv4Address.FindAllString(string(committed), -1)
	for _, address := range found {
		if !published[address] {
			t.Errorf("the committed %s names %s, which is not one of the published public "+
				"resolvers this package is allowed to ship. A bootstrap pointing at a LAN "+
				"resolver would put the operator's own network into a file every clone reads",
				committedPolicyPath, address)
		}
	}
}

// And the closed set is closed: a public resolver that is not in it cannot be
// added to the shipped policy without this test being made to say why. The DNSCrypt
// document is where a machine-specific bootstrap belongs, and that file is
// generated from a constant rather than shipped in the policy.
func TestOnlyQuad9sResolversAreInThePublishedSet(t *testing.T) {
	published := map[string]bool{"9.9.9.9": true, "149.112.112.9": true}
	for _, address := range defaultForeignUpstreams()[1].Bootstrap {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			t.Errorf("a shipped bootstrap %q is not an address and a port: %v", address, err)
			continue
		}
		if !published[host] {
			t.Errorf("the shipped route bootstraps through %s, which is not in the published "+
				"set the committed-policy gate allows", host)
		}
	}
}

// ipv4Address finds every dotted-quad in a generated document.
var ipv4Address = regexp.MustCompile(`[0-9]{1,3}(\.[0-9]{1,3}){3}`)

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
