package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mosdns-router/internal/mosdnsconfig"
)

// The render path is what gives a policy an effect: without it the two generated
// documents in the repository are the only ones that exist, and an operator who
// edits an installed policy changes nothing. Every case here runs the real
// command against a temporary directory, and no case writes anywhere near /etc.

const (
	// committedMosdnsDocument and committedDNSCryptDocument are the reviewed
	// output of the two renderers. A published pair that is not these bytes is
	// not what the project reviewed, so they are the expectation rather than a
	// second call to the renderer under test.
	committedMosdnsDocument   = "../../configs/mosdns.yaml"
	committedDNSCryptDocument = "../../configs/dnscrypt-proxy.toml"

	// productionPolicyPath is the policy path the committed routing document's
	// header names, and the one the installed layout uses.
	productionPolicyPath = "/etc/mosdns/policy.yaml"
)

// installed is a temporary stand-in for the installed layout: a document
// directory, the policy inside it, and the path set the routing document names.
// Only the paths that would be /etc or /var/lib on a real installation move; the
// China list, the state document and the two endpoints stay the production ones
// unless a case is about them.
type installed struct {
	dir       string
	policy    string
	documents documentPaths
}

func newInstalled(t *testing.T) installed {
	t.Helper()
	dir := t.TempDir()
	documents := productionDocumentPaths()
	documents.Dir = dir
	documents.Policy = filepath.Join(dir, "policy.yaml")
	return installed{dir: dir, policy: documents.Policy, documents: documents}
}

func (i installed) services() services {
	return services{documents: i.documents, documentOps: defaultDocumentOps()}
}

// withPolicy writes the default policy to the installed policy path and returns
// its bytes, so the command renders from a file that is the reviewed policy
// rather than from a hand-written fixture.
func (i installed) withPolicy(t *testing.T, edit func([]byte) []byte) []byte {
	t.Helper()
	policy, err := defaultPolicyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		policy = edit(policy)
	}
	if err := os.WriteFile(i.policy, policy, 0o600); err != nil {
		t.Fatalf("write %s: %v", i.policy, err)
	}
	return policy
}

func defaultPolicyBytes() ([]byte, error) {
	return os.ReadFile(filepath.Clean("../../configs/policy.yaml"))
}

func (i installed) path(name string) string {
	return filepath.Join(i.dir, name)
}

// contents reads one published document, so a case can say what the operator is
// left with after a failed render.
func (i installed) contents(t *testing.T, name string) []byte {
	t.Helper()
	published, err := os.ReadFile(i.path(name))
	if err != nil {
		t.Fatalf("read the published %s: %v", name, err)
	}
	return published
}

// entryNames is what the document directory holds, so a case can prove the
// command wrote the pair and nothing else.
func (i installed) entryNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(i.dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func runRenderCLI(t *testing.T, svc services, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{"render"}, args...), &stdout, &stderr, svc)
	return code, stdout.String(), stderr.String()
}

func runValidateCLI(t *testing.T, svc services, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{"validate"}, args...), &stdout, &stderr, svc)
	return code, stdout.String(), stderr.String()
}

// TestRenderPublishesTheReviewedDocumentPair is the promise the command exists
// for: the two files it publishes are the two files this project reviewed, byte
// for byte, with nothing else in the directory. The routing document records the
// policy path it was rendered from, so the expectation is the committed document
// with that one path replaced by the policy the command was given.
func TestRenderPublishesTheReviewedDocumentPair(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)

	code, stdout, stderr := runRenderCLI(t, instance.services())
	if code != exitSuccess {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if stderr != "" {
		t.Errorf("render wrote a diagnostic: %q", stderr)
	}

	if got, want := strings.Join(instance.entryNames(t), ","), "dnscrypt-proxy.toml,mosdns.yaml,policy.yaml"; !strings.HasPrefix(got, want) {
		t.Errorf("the document directory holds %q, want the pair and the policy it was rendered from", got)
	}

	committedResolver := readCommitted(t, committedDNSCryptDocument)
	if got := instance.contents(t, "dnscrypt-proxy.toml"); !bytes.Equal(got, committedResolver) {
		t.Errorf("the published resolver document differs from %s:\n%s", committedDNSCryptDocument, got)
	}

	committedRouting := readCommitted(t, committedMosdnsDocument)
	// The committed routing document names the policy path twice: once in the
	// generated header, and once as the document the response rewriter is configured
	// by. Both have to be the policy this render was given, so every occurrence is
	// replaced rather than the first -- and the count is asserted instead of assumed,
	// because a document naming the path once would mean the rewriter was configured
	// by a different file than the header claims produced it.
	occurrences := bytes.Count(committedRouting, []byte(productionPolicyPath))
	if occurrences != 2 {
		t.Fatalf("%s names %q %d times, want 2: the generated header and the rewriter's policy_file",
			committedMosdnsDocument, productionPolicyPath, occurrences)
	}
	want := bytes.ReplaceAll(committedRouting, []byte(productionPolicyPath), []byte(instance.policy))
	published := instance.contents(t, "mosdns.yaml")
	if !bytes.Equal(published, want) {
		t.Errorf("the published routing document is not %s rendered from %s:\n%s", committedMosdnsDocument, instance.policy, published)
	}
	// And the rewriter is configured by that same policy rather than by the installed
	// one, which a byte-for-byte comparison above cannot tell: it would pass on a
	// document whose header said one thing and whose plugin argument said another, as
	// long as both were the committed bytes.
	if !bytes.Contains(published, []byte("policy_file: "+instance.policy+"\n")) {
		t.Errorf("the published routing document does not give the rewriter %s as its policy:\n%s", instance.policy, published)
	}

	for _, want := range []string{
		"rendered-policy: " + instance.policy,
		"rendered-mosdns: " + instance.path("mosdns.yaml"),
		"rendered-dnscrypt: " + instance.path("dnscrypt-proxy.toml"),
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the render report does not name %q:\n%s", want, stdout)
		}
	}
}

func readCommitted(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read the committed %s: %v", path, err)
	}
	return contents
}

// TestRenderAcceptsExplicitPathsForASecondInstallation covers the overrides the
// command takes. The packaged post-install runs it with the installed paths, but
// a second installation, a test, and an operator rendering a candidate policy
// somewhere else all need to say where the documents go.
func TestRenderAcceptsExplicitPathsForASecondInstallation(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	elsewhere := t.TempDir()

	code, stdout, stderr := runRenderCLI(t, instance.services(), "--policy", instance.policy, "--out", elsewhere)
	if code != exitSuccess {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	for _, name := range []string{"mosdns.yaml", "dnscrypt-proxy.toml"} {
		if _, err := os.Stat(filepath.Join(elsewhere, name)); err != nil {
			t.Errorf("--out did not receive %s: %v", name, err)
		}
	}
	if _, err := os.Stat(instance.path("mosdns.yaml")); err == nil {
		t.Error("render published into the default document directory although --out named another one")
	}
	if !strings.Contains(stdout, "rendered-mosdns: "+filepath.Join(elsewhere, "mosdns.yaml")) {
		t.Errorf("the render report does not name the document it published:\n%s", stdout)
	}
}

// TestRenderRefusesAnInvalidPolicyWithTheConfigExit is the policy boundary. A
// policy that does not load or does not validate is a configuration error, so it
// keeps the exit code every other policy refusal in this command uses, and
// nothing is published.
func TestRenderRefusesAnInvalidPolicyWithTheConfigExit(t *testing.T) {
	for name, policy := range map[string]string{
		"a policy the decoder refuses": "schema_version: 1\n  not: a policy\n",
		"a policy that does not validate": strings.Replace(
			string(mustReadCommittedFile(t, committedPolicyFixture)), "failure_policy: strict", "failure_policy: permissive", 1),
		"an empty file": "",
	} {
		t.Run(name, func(t *testing.T) {
			instance := newInstalled(t)
			if err := os.WriteFile(instance.policy, []byte(policy), 0o600); err != nil {
				t.Fatal(err)
			}
			publishedPreviousPair(t, instance)

			code, stdout, stderr := runRenderCLI(t, instance.services())
			if code != exitInvalidCLI {
				t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitInvalidCLI, stderr)
			}
			if stdout != "" {
				t.Errorf("a refused render wrote a report: %q", stdout)
			}
			if stderr == "" {
				t.Error("a refused render wrote no diagnostic")
			}
			assertPreviousPairIntact(t, instance)
		})
	}
}

const committedPolicyFixture = "../../configs/policy.yaml"

func mustReadCommittedFile(t *testing.T, path string) []byte {
	t.Helper()
	return readCommitted(t, path)
}

// TestRenderRefusesAPolicyNoDocumentCanRender covers a policy the loader accepts
// and a renderer will not produce a document for: a persistent cache with no dump
// path, and ECS with no ECS-capable stamp set. Both are refusals rather than
// partial publications, so the pair an operator is running is left as it was and
// the exit code is the operational one, not the configuration one: the policy
// file is valid, the render is what could not be done.
func TestRenderRefusesAPolicyNoDocumentCanRender(t *testing.T) {
	for name, edit := range map[string]func([]byte) []byte{
		"a persistent cache with nowhere to dump": func(policy []byte) []byte {
			return bytes.Replace(policy, []byte("persistent_dump: false"), []byte("persistent_dump: true"), 1)
		},
		"ECS with no ECS-capable stamp set": func(policy []byte) []byte {
			return bytes.Replace(policy, []byte("ecs: false"), []byte("ecs: true"), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			instance := newInstalled(t)
			instance.withPolicy(t, edit)
			publishedPreviousPair(t, instance)

			code, stdout, stderr := runRenderCLI(t, instance.services())
			if code != exitStateUnavailable {
				t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
			}
			if strings.Contains(stdout, "rendered-mosdns") || strings.Contains(stdout, "rendered-dnscrypt") {
				t.Errorf("a refused render reported a publication:\n%s", stdout)
			}
			if stderr == "" {
				t.Error("a refused render wrote no diagnostic")
			}
			assertPreviousPairIntact(t, instance)
		})
	}
}

// TestRenderReportsAnUnwritableOutputDirectory covers the operational failure. A
// document directory that is not there, or that cannot be written, has to stop the
// command with the operational exit code and leave the previous pair alone; a
// render that reported success would leave the router on a document the operator
// never published.
func TestRenderReportsAnUnwritableOutputDirectory(t *testing.T) {
	for name, out := range map[string]func(t *testing.T, instance installed) string{
		"a directory that does not exist": func(_ *testing.T, instance installed) string {
			return filepath.Join(instance.dir, "not-installed", "documents")
		},
		"a path that is a file": func(t *testing.T, _ installed) string {
			blocker := filepath.Join(t.TempDir(), "blocker")
			if err := os.WriteFile(blocker, []byte("not a directory\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return blocker
		},
	} {
		t.Run(name, func(t *testing.T) {
			instance := newInstalled(t)
			instance.withPolicy(t, nil)
			publishedPreviousPair(t, instance)
			target := out(t, instance)

			code, stdout, stderr := runRenderCLI(t, instance.services(), "--out", target)
			if code != exitStateUnavailable {
				t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
			}
			if strings.Contains(stdout, "rendered-mosdns") {
				t.Errorf("a failed publication reported a document:\n%s", stdout)
			}
			if !strings.Contains(stderr, target) {
				t.Errorf("the refusal does not name the output directory %q: %q", target, stderr)
			}
			assertPreviousPairIntact(t, instance)
		})
	}
}

// publishedPreviousPair installs a pair that is recognisably not what the
// renderer produces, so a case can tell a restored pair from a published one.
func publishedPreviousPair(t *testing.T, instance installed) {
	t.Helper()
	for _, name := range []string{"mosdns.yaml", "dnscrypt-proxy.toml"} {
		if err := os.WriteFile(instance.path(name), []byte("the document a previous policy produced\n"), 0o644); err != nil {
			t.Fatalf("publish a previous %s: %v", name, err)
		}
	}
}

func assertPreviousPairIntact(t *testing.T, instance installed) {
	t.Helper()
	for _, name := range []string{"mosdns.yaml", "dnscrypt-proxy.toml"} {
		if got, want := string(instance.contents(t, name)), "the document a previous policy produced\n"; got != want {
			t.Errorf("%s after a refused render = %q, want the previous %q", name, got, want)
		}
	}
}

// TestRenderRestoresTheFirstDocumentWhenTheSecondCannotBePublished is the pair
// discipline. The two documents cannot be renamed into place as one operation, so
// a failure between the two renames has to put the first one back: a half-published
// pair is a router reading a routing document from one policy and a resolver
// document from another.
//
// The second rename is made to fail, because that is the only step where the first
// document has already been replaced and the second has not. Everything the
// failure could leave behind -- a staged file, a backup, a renamed document -- is
// part of the assertion.
func TestRenderRestoresTheFirstDocumentWhenTheSecondCannotBePublished(t *testing.T) {
	for name, breakIt := range map[string]func(*documentFileOps, *int){
		"the second document cannot be renamed": func(ops *documentFileOps, renames *int) {
			rename := ops.rename
			ops.rename = func(from, to string) error {
				*renames++
				if *renames == 2 {
					return errors.New("injected rename failure")
				}
				return rename(from, to)
			}
		},
		"the second document's directory cannot be flushed": func(ops *documentFileOps, renames *int) {
			syncDir := ops.syncDir
			ops.syncDir = func(path string) error {
				*renames++
				if *renames == 2 {
					return errors.New("injected directory sync failure")
				}
				return syncDir(path)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			instance := newInstalled(t)
			instance.withPolicy(t, nil)
			publishedPreviousPair(t, instance)
			before := snapshotWithout(t, instance.dir, "policy.yaml")

			renames := 0
			ops := defaultDocumentOps()
			breakIt(&ops, &renames)
			svc := instance.services()
			svc.documentOps = ops

			code, stdout, stderr := runRenderCLI(t, svc)
			if code != exitStateUnavailable {
				t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
			}
			if !strings.Contains(stderr, "injected") {
				t.Errorf("the refusal does not carry the injected failure: %q", stderr)
			}
			if strings.Contains(stdout, "rendered-mosdns") {
				t.Errorf("a failed publication reported a document:\n%s", stdout)
			}
			assertUnchanged(t, before, instance.dir, "policy.yaml")
		})
	}
}

// TestRenderPublishesNothingBeforeEitherDocumentIsStaged covers the other side of
// the discipline: a failure that happens before a rename owes no restore, and a
// rollback that ran anyway would be reporting a repair it never made. The first
// backup cannot be written, so nothing has been replaced when the command stops,
// and the pair has to come out untouched with no leftovers.
func TestRenderPublishesNothingBeforeEitherDocumentIsStaged(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	publishedPreviousPair(t, instance)
	before := snapshotWithout(t, instance.dir, "policy.yaml")

	renames := 0
	ops := defaultDocumentOps()
	rename := ops.rename
	ops.rename = func(from, to string) error {
		renames++
		return rename(from, to)
	}
	syncFile := ops.syncFile
	flushes := 0
	ops.syncFile = func(file *os.File) error {
		flushes++
		// The two staged files are flushed first, then the backups.
		if flushes == 3 {
			return errors.New("injected file flush failure")
		}
		return syncFile(file)
	}
	svc := instance.services()
	svc.documentOps = ops

	code, _, stderr := runRenderCLI(t, svc)
	if code != exitStateUnavailable {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if !strings.Contains(stderr, "sync backup") {
		t.Errorf("the refusal does not name the step that failed: %q", stderr)
	}
	if renames != 0 {
		t.Errorf("render attempted %d renames, want 0: a failure before a rename owes no restore", renames)
	}
	assertUnchanged(t, before, instance.dir, "policy.yaml")
}

// TestRenderKeepsTheOnlyCopyOfAPreviousDocumentWhenTheRestoreFailsItself covers
// the last obligation. A restore that fails leaves the backup as the only copy of
// what the router was running, so it is kept rather than cleaned up, and the
// failure names it: an operator who deleted the leftover would be deleting the
// last copy of their working configuration.
func TestRenderKeepsTheOnlyCopyOfAPreviousDocumentWhenTheRestoreFailsItself(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	publishedPreviousPair(t, instance)

	renames := 0
	ops := defaultDocumentOps()
	rename := ops.rename
	ops.rename = func(from, to string) error {
		renames++
		// The first rename publishes a document, the second restores the
		// previous one; everything else is refused.
		if renames != 1 {
			return errors.New("injected rename failure")
		}
		return rename(from, to)
	}
	svc := instance.services()
	svc.documentOps = ops

	code, _, stderr := runRenderCLI(t, svc)
	if code != exitStateUnavailable {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	// The restore was refused, so the renamed document is still in place and the
	// backup beside it is the previous one. The error has to say so, because the
	// file on the document's own path is no longer it.
	if !strings.Contains(stderr, "restore the previous mosdns.yaml") {
		t.Errorf("the failure does not name the restore it could not make: %q", stderr)
	}
	if !strings.Contains(stderr, "is kept at") {
		t.Errorf("the failure does not say where the previous document survives: %q", stderr)
	}
	entries, err := os.ReadDir(instance.dir)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bak") {
			kept = true
			contents, err := os.ReadFile(filepath.Join(instance.dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if want := "the document a previous policy produced\n"; string(contents) != want {
				t.Errorf("the kept backup holds %q, want the previous document %q", contents, want)
			}
		}
	}
	if !kept {
		t.Errorf("the only copy of the previous document was deleted: %v", entryNames(entries))
	}
}

// TestRenderNeverWritesTheChinaListOrTheDhcpState is the boundary between the
// documents this command generates and the state other components own. The
// routing document names the list and the state document; writing either of them
// here would publish a rule set or a DHCP generation that nothing reviewed.
func TestRenderNeverWritesTheChinaListOrTheDhcpState(t *testing.T) {
	instance := newInstalled(t)
	documents := instance.documents
	documents.Routing.CNDomains = filepath.Join(instance.dir, "cn-domains.txt")
	documents.Routing.DHCPState = filepath.Join(instance.dir, "dhcp-upstreams.json")
	instance.documents = documents
	instance.withPolicy(t, nil)

	code, _, stderr := runRenderCLI(t, instance.services())
	if code != exitSuccess {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	for _, name := range []string{"cn-domains.txt", "dhcp-upstreams.json"} {
		if _, err := os.Stat(instance.path(name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("render wrote the %s the routing document only names: %v", name, err)
		}
	}
	// The documents do name them, so the assertion above is about what this
	// command did and not about a document that avoided the paths.
	routing := string(instance.contents(t, "mosdns.yaml"))
	for _, name := range []string{"cn-domains.txt", "dhcp-upstreams.json"} {
		if !strings.Contains(routing, name) {
			t.Errorf("the published routing document does not name %s, so the test above proves nothing: %s", name, routing)
		}
	}
}

// TestRenderDefaultsAreTheInstalledPaths is what the packaged post-install relies
// on. It runs the command with no paths at all, so a default that pointed
// anywhere but the installed layout would render documents no service reads.
func TestRenderDefaultsAreTheInstalledPaths(t *testing.T) {
	documents := productionDocumentPaths()
	if documents.Dir != "/etc/mosdns" {
		t.Errorf("default document directory = %q, want the installed configuration directory", documents.Dir)
	}
	if documents.Policy != productionPolicyPath {
		t.Errorf("default policy = %q, want the installed policy", documents.Policy)
	}
	if documents.Mosdns != "mosdns.yaml" || documents.DNSCrypt != "dnscrypt-proxy.toml" {
		t.Errorf("default document names = %q and %q, want the committed names", documents.Mosdns, documents.DNSCrypt)
	}
	if documents.Routing != mosdnsconfig.ProductionPaths() {
		t.Errorf("default routing path set = %+v, want the installed one", documents.Routing)
	}
}

// TestValidateReportsAnInstalledDocumentThePolicyNoLongerDescribes is the reason
// the report exists. An operator who changes a policy an installed gateway runs
// gets a green validate and a router still running the old document; the policy is
// valid, so validate still exits zero, but the disagreement is reported by name so
// a script can act on it.
func TestValidateReportsAnInstalledDocumentThePolicyNoLongerDescribes(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	if code, _, stderr := runRenderCLI(t, instance.services()); code != exitSuccess {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	published := instance.contents(t, "mosdns.yaml")

	// The operator changes the safety switch and does not re-render.
	instance.withPolicy(t, func(policy []byte) []byte {
		return bytes.Replace(policy, []byte("failure_policy: disable-current"), []byte("failure_policy: use-last-good"), 1)
	})
	before := snapshotWithout(t, instance.dir, "policy.yaml")

	code, stdout, stderr := runValidateCLI(t, instance.services(), "--policy", instance.policy)
	if code != exitSuccess {
		t.Fatalf("validate exit = %d, want %d: the policy itself is valid (stderr: %s)", code, exitSuccess, stderr)
	}
	if stderr != "" {
		t.Errorf("validate wrote a diagnostic for a valid policy: %q", stderr)
	}
	if !strings.Contains(stdout, "rendered-mismatch: mosdns.yaml") {
		t.Errorf("validate did not report the stale routing document by name:\n%s", stdout)
	}
	if strings.Contains(stdout, "rendered-mismatch: dnscrypt-proxy.toml") {
		t.Errorf("validate reported the resolver document as stale although the policy change does not touch it:\n%s", stdout)
	}
	if !strings.Contains(stdout, "the policy is valid") || !strings.Contains(stdout, "stale") {
		t.Errorf("validate does not say plainly that the policy is valid and the document is stale:\n%s", stdout)
	}
	// A report that rewrote the document would turn a diagnostic into a change
	// nobody asked for.
	assertUnchanged(t, before, instance.dir, "policy.yaml")
	if got := instance.contents(t, "mosdns.yaml"); !bytes.Equal(got, published) {
		t.Error("validate rewrote the installed routing document")
	}
}

// TestValidateNamesEveryDocumentThatIsNotWhatThePolicyDescribes covers the whole
// report rather than its first line: one line per stale document, each naming what
// is wrong with it, and a line an operator can act on.
func TestValidateNamesEveryDocumentThatIsNotWhatThePolicyDescribes(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	// Only the resolver document is installed, and it is the wrong one.
	if err := os.WriteFile(instance.path("dnscrypt-proxy.toml"), []byte("[server_names]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := runValidateCLI(t, instance.services(), "--policy", instance.policy)
	if code != exitSuccess {
		t.Fatalf("validate exit = %d, want %d: the policy itself is valid", code, exitSuccess)
	}
	for _, want := range []string{
		"rendered-mismatch: mosdns.yaml",
		"reason: " + instance.path("mosdns.yaml") + " is not installed",
		"rendered-mismatch: dnscrypt-proxy.toml",
		"reason: " + instance.path("dnscrypt-proxy.toml") + " differs from a fresh render of " + instance.policy,
		"mosdns-cdnctl render",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the validate report does not contain %q:\n%s", want, stdout)
		}
	}
}

// TestValidateReportsADocumentItCannotRender covers a policy that loads and
// validates but that a renderer refuses. The installed document cannot be this
// policy's output either, so it is reported by name, and the refusal is the
// reason: a report that said only "differs" would send an operator to re-render a
// document the command cannot produce.
func TestValidateReportsADocumentItCannotRender(t *testing.T) {
	instance := newInstalled(t)
	// The installed pair comes from a policy that renders, so the disagreement
	// under test is the one an operator creates by editing it afterwards.
	instance.withPolicy(t, nil)
	if code, _, stderr := runRenderCLI(t, instance.services()); code != exitSuccess {
		t.Fatalf("the fixture render exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	instance.withPolicy(t, func(policy []byte) []byte {
		return bytes.Replace(policy, []byte("ecs: false"), []byte("ecs: true"), 1)
	})

	code, stdout, _ := runValidateCLI(t, instance.services(), "--policy", instance.policy)
	if code != exitSuccess {
		t.Fatalf("validate exit = %d, want %d: the policy itself is valid", code, exitSuccess)
	}
	if !strings.Contains(stdout, "rendered-mismatch: dnscrypt-proxy.toml") {
		t.Errorf("validate did not report the unrenderable document by name:\n%s", stdout)
	}
	if !strings.Contains(stdout, "cannot be rendered from "+instance.policy) {
		t.Errorf("validate did not say the document cannot be rendered at all:\n%s", stdout)
	}
}

// TestValidateSaysNothingWhenTheInstalledDocumentsAreWhatThePolicyDescribes is
// the other half: a report that fires on a matching pair would train its reader to
// ignore it.
func TestValidateSaysNothingWhenTheInstalledDocumentsAreWhatThePolicyDescribes(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	if code, _, stderr := runRenderCLI(t, instance.services()); code != exitSuccess {
		t.Fatalf("render exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}

	code, stdout, stderr := runValidateCLI(t, instance.services(), "--policy", instance.policy)
	if code != exitSuccess {
		t.Fatalf("validate exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if stdout != "" || stderr != "" {
		t.Errorf("validate reported a matching pair: stdout=%q stderr=%q", stdout, stderr)
	}
}

// TestValidateSaysNothingWhenThereIsNothingInstalled covers a first install. An
// operator who has not rendered yet has no stale document, and a validate that
// said "stale" would be reporting a fault against a directory that was never
// written.
func TestValidateSaysNothingWhenThereIsNothingInstalled(t *testing.T) {
	for name, arrange := range map[string]func(t *testing.T, instance installed){
		"no document directory at all": func(t *testing.T, instance installed) {
			instance.documents.Dir = filepath.Join(instance.dir, "not-installed")
		},
		"a document directory with no documents": func(t *testing.T, instance installed) {},
	} {
		t.Run(name, func(t *testing.T) {
			instance := newInstalled(t)
			instance.withPolicy(t, nil)
			arrange(t, instance)

			code, stdout, stderr := runValidateCLI(t, instance.services(), "--policy", instance.policy)
			if code != exitSuccess {
				t.Fatalf("validate exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
			}
			if stdout != "" || stderr != "" {
				t.Errorf("validate reported a fault where nothing is installed: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

// TestValidateReadsTheInstalledDirectoryItWasGiven is the override that keeps a
// test and a second installation away from /etc. The report has to come from the
// directory the caller named, not from the installed one.
func TestValidateReadsTheInstalledDirectoryItWasGiven(t *testing.T) {
	instance := newInstalled(t)
	instance.withPolicy(t, nil)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "mosdns.yaml"), []byte("from another policy\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := runValidateCLI(t, instance.services(), "--policy", instance.policy, "--documents", elsewhere)
	if code != exitSuccess {
		t.Fatalf("validate exit = %d, want %d", code, exitSuccess)
	}
	if !strings.Contains(stdout, "rendered-mismatch: mosdns.yaml") || !strings.Contains(stdout, elsewhere) {
		t.Errorf("validate did not report the stale document in the directory it was given:\n%s", stdout)
	}
	if strings.Contains(stdout, instance.path("mosdns.yaml")) {
		t.Errorf("validate reported the installed document directory although --documents named another one:\n%s", stdout)
	}
}
