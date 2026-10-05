package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"mosdns-router/internal/config"
	"mosdns-router/internal/dnscrypt"
	"mosdns-router/internal/mosdnsconfig"
	"mosdns-router/internal/unitfile"
)

// A policy is inert until something renders it. The router reads two generated
// documents -- the routing sequence and the resolver's own configuration -- and
// until this command existed the only ones in existence were the copies committed
// to the repository, so an operator who edited an installed policy changed a file
// nothing read. This file is that path: it loads a policy strictly, renders both
// documents through the same renderers that produce the committed files, and
// publishes them as one pair.
//
// It writes those two files and nothing else. The China list and the DHCP state
// are named by the routing document and owned by the list updater and the bridge;
// rendering them here would publish a rule set or a DHCP generation nobody
// reviewed. It also does not repair the pair on its own: an operator who wants a
// policy applied runs this, and validate then says whether what is installed is
// what the policy describes.

// documentFileMode is the exact mode a published document carries, whatever the
// caller's umask or the file's previous mode. The two documents are read by the
// service user and by the operator, so they are world-readable like any other
// file under /etc; nothing in them is secret, and the whole point of a generated
// configuration is that it can be read and checked.
const documentFileMode = 0644

// documentPaths is every path the render command and the validate mismatch report
// touch. The defaults are the installed layout, so the packaged post-install runs
// the command with no paths at all, and every one of them comes from the services
// boundary, so a test never writes to /etc or reads a real installation.
type documentPaths struct {
	// Dir is the directory the two generated documents are published into.
	Dir string
	// Policy is the policy both documents are rendered from. It is also the path
	// the routing document's generated header names, so a document always says
	// which policy produced it.
	Policy string
	// Mosdns and DNSCrypt are the file names the document directory holds. They
	// are the committed names, and they are what a mismatch is reported under.
	Mosdns   string
	DNSCrypt string
	// Routing is the rest of the path set the routing document names: the China
	// list, the DHCP state, the two endpoints. The command copies it, overwrites
	// its Policy field with the policy actually read, and never writes the two
	// files it names.
	// Unit and UnitDir are where the generated systemd unit is published. The unit is
	// NOT beside the documents because systemd does not read it from there: a policy
	// that renders a unit to the wrong directory produces a machine whose policy and
	// whose schedule disagree, and the disagreement is invisible until the timer fires
	// at the old time.
	Unit    string
	UnitDir string
	Routing mosdnsconfig.Paths
}

// productionDocumentPaths returns the installed layout: the spec's
// /etc/mosdns/policy.yaml with both generated documents beside it, and the
// production path set the routing document refers to.
func productionDocumentPaths() documentPaths {
	return documentPaths{
		Dir:      "/etc/mosdns",
		Policy:   mosdnsconfig.ProductionPaths().Policy,
		Mosdns:   "mosdns.yaml",
		DNSCrypt: "dnscrypt-proxy.toml",
		Unit:     unitfile.UnitName,
		UnitDir:  "/usr/lib/systemd/system",
		Routing:  mosdnsconfig.ProductionPaths(),
	}
}

// renderOptions is the parsed command line of render.
type renderOptions struct {
	policy  string
	out     string
	unitOut string
}

// parseRenderOptions parses and validates the command line. Both paths default to
// the installed ones, so the packaged post-install names neither, and an empty
// value is refused rather than resolved against a working directory: a path that
// means something different under systemd and under a shell is a path a generated
// document cannot carry.
func parseRenderOptions(args []string, documents documentPaths) (renderOptions, error) {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := flags.String("policy", documents.Policy, "path to the policy YAML file")
	out := flags.String("out", documents.Dir, "directory the generated documents are published into")
	unitOut := flags.String("unit-out", documents.UnitDir,
		"directory the generated systemd unit is published into; it is separate from "+
			"--out because systemd does not read units from the document directory")
	if err := flags.Parse(args); err != nil {
		return renderOptions{}, err
	}
	if flags.NArg() != 0 {
		return renderOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	for _, path := range []struct{ name, value string }{
		{"--policy", *policy},
		{"--out", *out},
		{"--unit-out", *unitOut},
	} {
		if strings.TrimSpace(path.value) == "" {
			return renderOptions{}, fmt.Errorf("%s must not be empty", path.name)
		}
	}
	return renderOptions{policy: *policy, out: *out, unitOut: *unitOut}, nil
}

func runRender(args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseRenderOptions(args, services.documents)
	if err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitInvalidCLI
	}
	// The policy is loaded and validated before anything is rendered, so a
	// configuration error is reported as one rather than as a publication that
	// could not be made.
	policy, err := config.Load(options.policy)
	if err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitInvalidCLI
	}

	documents := pair(policy, services.documents, options.policy)
	if err := refuseUnrenderable(documents); err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitStateUnavailable
	}
	if err := publishPairWithOps(options.out, documents[:2], services.documentOps); err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitStateUnavailable
	}

	// The unit goes through the same atomic publication as the documents -- staged
	// file, fsync, rename -- because a unit half-written is a timer systemd cannot
	// parse, and the one reader is systemd itself.
	//
	// The directory is created rather than assumed. --out is left alone: it has a
	// gate of its own about being unwritable, and a render that creates the
	// directory it was told to publish into would turn that gate into a mkdir with
	// extra steps. --unit-out is new, it is a path an operator names rather than one
	// this package installs, and "no such directory" from a renderer is an answer
	// that sends them to mkdir by hand.
	if err := os.MkdirAll(options.unitOut, 0o755); err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitStateUnavailable
	}
	unit := documentPair{documents[2]}
	unit[0].Name = filepath.Base(documents[2].Name)
	if err := publishPairWithOps(options.unitOut, unit, services.documentOps); err != nil {
		writeCLIError(stderr, "render: %v", err)
		return exitStateUnavailable
	}

	// Reloaded as part of writing it. A schedule the operator changed and did not get
	// is the symptom the policy field's deadness produced in the first place, so the
	// reload belongs to the operation rather than to a step somebody has to remember.
	//
	// Reported AFTER the documents were written rather than instead of them, and
	// without failing the run: everything on disk is correct, and exiting non-zero
	// would send an operator hunting a render failure that did not happen.
	if err := services.reloadSystemd(); err != nil {
		writeCLIError(stderr, "render: %s written; systemd was not reloaded, so it keeps the "+
			"previous schedule until this is fixed or the machine reboots: %v",
			filepath.Join(options.unitOut, unitfile.UnitName), err)
	}

	writeReportLine(stdout, "rendered-policy: %s\n", options.policy)
	for _, document := range documents[:2] {
		writeReportLine(stdout, "rendered-%s: %s\n", document.Report, filepath.Join(options.out, document.Name))
		writeReportLine(stdout, "rendered-%s-sha256: %s\n", document.Report, digestOf(document.Contents))
	}
	writeReportLine(stdout, "rendered-unit: %s\n", filepath.Join(options.unitOut, unitfile.UnitName))
	writeReportLine(stdout, "rendered-unit-sha256: %s\n", digestOf(documents[2].Contents))
	return exitSuccess
}

// documentPair is the two documents a policy describes, in publication order. It
// is a pair rather than a list because the two are not interchangeable: the
// routing document is published first, the resolver document second, and each
// carries the prefix its report and mismatch lines are written under. A document
// name is a file name the provider chooses; the report prefix says which of the
// two documents it is, so a rename of either file cannot relabel the report.
type documentPair []renderedDocument

// renderedDocument is one document of the pair: the name it is published and
// reported under, and either the bytes a fresh render produced or the refusal
// that produced none. Both are kept rather than stopping at the first refusal, so
// a caller can report everything that is wrong at once.
type renderedDocument struct {
	// Report is the prefix the document's report and mismatch lines carry.
	Report string
	// Name is the file name inside the document directory.
	Name string
	// Contents is what a fresh render produced, or nil when Err is set.
	Contents []byte
	// Err is the renderer's refusal, or nil when the document rendered.
	Err error
}

// pair renders both documents a policy describes.
//
// The routing document is rendered through internal/mosdnsconfig and the resolver
// document through internal/dnscrypt, so both go through the same refusals the
// committed files were reviewed under: a path that cannot be served, a persistent
// cache with nowhere to dump to, a listener that is the router's own endpoint, a
// stamp that does not decode, and the scan for a Chinese public resolver in the
// finished routing document.
//
// The resolver document is rendered from dnscrypt.Defaults(), the Quad9 set this
// project reviewed, because the policy schema carries no stamp field. An operator
// who wants a different provider edits the installed document, as the packaging
// plan says, or this gains a stamp field; neither is something this command
// decides on its own, and a custom stamp set is a separate change.
func pair(policy config.Policy, documents documentPaths, policyPath string) documentPair {
	// The routing document names the policy it was rendered from, so a document
	// an operator is reading says which file produced it. The remaining paths are
	// the installed ones; the command copies them so nothing here can change what
	// a caller's path set holds.
	routing := documents.Routing
	routing.Policy = policyPath

	rendered := documentPair{
		{Report: "mosdns", Name: documents.Mosdns},
		{Report: "dnscrypt", Name: documents.DNSCrypt},
		{Report: "unit", Name: documents.Unit},
	}
	if rendered[0].Contents, rendered[0].Err = mosdnsconfig.Render(policy, routing); rendered[0].Err != nil {
		rendered[0].Err = fmt.Errorf("%s: %w", documents.Mosdns, rendered[0].Err)
	}
	if rendered[1].Contents, rendered[1].Err = dnscrypt.Render(policy, dnscrypt.Defaults()); rendered[1].Err != nil {
		rendered[1].Err = fmt.Errorf("%s: %w", documents.DNSCrypt, rendered[1].Err)
	}
	if rendered[2].Contents, rendered[2].Err = unitfile.Render(policy); rendered[2].Err != nil {
		rendered[2].Err = fmt.Errorf("%s: %w", documents.Unit, rendered[2].Err)
	}
	return rendered
}

// refuseUnrenderable reports every document that has no bytes, so an operator
// changing a policy is told about all of it at once rather than fixing one field
// and being told about the next.
func refuseUnrenderable(documents documentPair) error {
	var refusals []error
	for _, document := range documents {
		if document.Err != nil {
			refusals = append(refusals, document.Err)
		}
	}
	return errors.Join(refusals...)
}

func digestOf(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

// --- validate's disagreement report ---

// validateOptions is the parsed command line of validate.
type validateOptions struct {
	policy    string
	documents string
}

// parseValidateOptions parses and validates the command line. The policy is
// required, as it always was: it is the file being validated. The document
// directory is optional and defaults to the installed one, so the report a plain
// `validate --policy ...` gives is the one about the gateway that policy
// describes.
func parseValidateOptions(args []string, documents documentPaths) (validateOptions, error) {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := flags.String("policy", "", "path to the policy YAML file")
	documentDir := flags.String("documents", documents.Dir, "directory the generated documents are published into")
	if err := flags.Parse(args); err != nil {
		return validateOptions{}, err
	}
	if flags.NArg() != 0 {
		return validateOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *policy == "" {
		return validateOptions{}, errors.New("--policy PATH is required")
	}
	if strings.TrimSpace(*documentDir) == "" {
		return validateOptions{}, errors.New("--documents DIR must not be empty")
	}
	return validateOptions{policy: *policy, documents: *documentDir}, nil
}

// reportMismatches says which of the documents a policy describes are not what
// the operator has installed, in the form a script can read and a sentence an
// operator can act on.
//
// The policy itself is valid -- that is what the caller has already established,
// and it is why the command still exits zero. What the report adds is the
// disagreement between a policy nobody applied and a document the router is
// running, which is the one thing a policy on disk cannot show by itself. Nothing
// is written: a diagnostic that repaired the pair would be a change nobody asked
// for, and the repair is one command away.
//
// A directory with no document in it is not a stale installation, it is an
// installation that has not rendered yet, and nothing is said about it: reporting
// "stale" there would fault a directory that was never written.
func reportMismatches(stdout io.Writer, policy config.Policy, documents documentPaths, options validateOptions) error {
	var report bytes.Buffer
	installedAnything := false
	// The two documents are compared in the document directory and the unit in the
	// systemd one, because that is where each is published. The unit is not in this
	// loop by accident: reading it out of the document directory reports it "not
	// installed" on every machine, and reading it out of the file it names reports
	// the directory as a file.
	//
	// The unit is checked at all because it is generated from the policy the same way
	// the documents are. A machine whose policy says 05:15 and whose timer says
	// 03:30 is exactly the state this change exists to end, and validate is where an
	// operator looks before running render.
	// where is the directory each generated file is published into. The two documents
	// go to the document directory and the unit to the systemd one, because that is
	// where each is written; reading either out of the other's directory reports it
	// "not installed" on every machine, or reports the directory as a file.
	//
	// The unit is checked at all because it is generated from the policy exactly as
	// the documents are. A machine whose policy says 05:15 and whose timer says 03:30
	// is the state this change exists to end, and validate is where an operator looks
	// before running render.
	type placed struct {
		document renderedDocument
		dir      string
	}
	rendered := pair(policy, documents, options.policy)
	checked := make([]placed, 0, len(rendered))
	for _, document := range rendered[:2] {
		checked = append(checked, placed{document, options.documents})
	}
	checked = append(checked, placed{rendered[2], documents.UnitDir})
	for _, entry := range checked {
		document, path := entry.document, filepath.Join(entry.dir, entry.document.Name)
		published, err := os.ReadFile(filepath.Clean(path))
		missing := errors.Is(err, os.ErrNotExist)
		if err != nil && !missing {
			return fmt.Errorf("read %s: %w", path, err)
		}
		installedAnything = installedAnything || !missing

		var reason string
		switch {
		case document.Err != nil:
			reason = fmt.Sprintf("%s cannot be rendered from %s: %v", path, options.policy, document.Err)
		case missing:
			reason = fmt.Sprintf("%s is not installed, and this policy describes one", path)
		case !bytes.Equal(published, document.Contents):
			reason = fmt.Sprintf("%s differs from a fresh render of %s", path, options.policy)
		default:
			continue
		}
		fmt.Fprintf(&report, "rendered-mismatch: %s\nreason: %s\n", document.Name, reason)
	}
	if !installedAnything || report.Len() == 0 {
		return nil
	}
	fmt.Fprintf(&report, "the policy is valid, but the installed document is stale: run `mosdns-cdnctl render --policy %s --out %s` to publish what this policy describes\n",
		options.policy, options.documents)
	if _, err := stdout.Write(report.Bytes()); err != nil {
		return fmt.Errorf("write the mismatch report: %w", err)
	}
	return nil
}

// reloadSystemd asks systemd to re-read its units.
//
// `systemctl` is invoked by absolute name and with an argv, never a shell string:
// this runs from the render verb, which an operator may run as root, and a path
// resolved through $PATH on a machine whose PATH an attacker can write is a way to
// run their program as root.
//
// A missing systemctl is a refusal rather than a silent success. A render that wrote
// a new schedule and could not tell systemd about it has left the machine describing
// one thing and running another, and that is exactly the state this whole change
// exists to end.
func reloadSystemd() error {
	const systemctl = "/usr/bin/systemctl"
	if _, err := os.Stat(systemctl); err != nil {
		return fmt.Errorf("%s is not there to reload systemd with: %w", systemctl, err)
	}
	completed := exec.Command(systemctl, "daemon-reload").Run()
	if completed == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(completed, &exit) {
		if message := strings.TrimSpace(string(exit.Stderr)); message != "" {
			return errors.New(message)
		}
		return fmt.Errorf("systemctl daemon-reload exited %d", exit.ExitCode())
	}
	return completed
}
