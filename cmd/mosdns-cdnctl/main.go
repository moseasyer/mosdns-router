package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/health"
	"mosdns-router/internal/measure"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/prober"
	"mosdns-router/internal/state"
	"mosdns-router/internal/status"
)

const (
	exitSuccess          = 0
	exitInvalidCLI       = 2
	exitStateUnavailable = 3
	exitLockHeld         = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command boundary used by both the executable and focused tests.
// It deliberately returns an exit code instead of terminating the process so
// callers can exercise every CLI outcome in-process.
func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, productionServices())
}

// runWith is run with an explicit services boundary, so a test can point the
// update-lists command at a local origin, or the render command at a temporary
// directory, while the lock, the publication, the renderers and the conversion
// stay the real ones.
func runWith(args []string, stdout, stderr io.Writer, services services) int {
	return runWithContext(context.Background(), args, stdout, stderr, services)
}

func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 {
		writeCLIError(stderr, "a command is required")
		return exitInvalidCLI
	}

	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr, services)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "update-lists":
		return runUpdateLists(ctx, args[1:], stdout, stderr, services)
	case "render":
		return runRender(args[1:], stdout, stderr, services)
	case "test":
		return runCDNTest(ctx, args[1:], stdout, stderr, services)
	case "apply":
		return runCDNApply(ctx, args[1:], stdout, stderr, services)
	case "pin":
		return runCDNPin(ctx, args[1:], stdout, stderr, services)
	case "unpin":
		return runCDNUnpin(args[1:], stdout, stderr, services)
	case "flush-cache":
		return runFlushCache(args[1:], stdout, stderr, services)
	case "check-upstream":
		return runCheckUpstream(args[1:], stdout, stderr, services)
	case "health-check":
		return runCDNHealthCheck(ctx, args[1:], stdout, stderr, services)
	case "emergency-rollback":
		return runEmergencyRollback(args[1:], stdout, stderr, services)
	default:
		writeCLIError(stderr, "unknown command %q", args[0])
		return exitInvalidCLI
	}
}

// installerScriptPath is where the package installs the installer, and it is a
// constant rather than a flag for the same reason the other paths are: a rollback
// an operator can point at a different script is a rollback that can be pointed
// somewhere else. The script is the thing that decides what a machine's DNS is
// put back to, and that decision is not this program's to delegate to a path.
const installerScriptPath = "/usr/lib/mosdns-router/mosdns_installer.py"

// rollbackCommand is the argument array, and a fresh one every call: two runs
// cannot share a slice, because a caller that changed one of them would then be
// changing what the next rollback executes.
//
// It has no flags and takes no input. The verb the installer runs is a constant
// here, so nothing a caller can supply reaches the array -- which is what makes
// "no shell interpolation" a property of the code rather than a claim about it.
func rollbackCommand() []string {
	return []string{installerScriptPath, "emergency-rollback"}
}

// runEmergencyRollback puts a machine's DNS back from the installer's own backup
// and reports what the installer said.
//
// It is a launcher and nothing else, which is the right division: the installer
// holds the record of what the connection was set to, and a second
// implementation of "put it back" in Go would be a second thing that can be wrong
// about a machine's resolver. So this decides three things and then gets out of
// the way:
//
//   - that the caller is root. The installer rewrites a NetworkManager profile
//     and stops units; a non-root run would fail somewhere less legible than here.
//   - that the array is an array. There is no shell between this program and the
//     script, so nothing in a connection UUID, a device name or a path is ever
//     interpreted.
//   - that the installer's own status survives. 0 is restored, 5 is "this
//     connection is not mine to change", 6 is "I started and did not finish", and
//     each of those is a different fact about a machine. A launcher that reported
//     them all as one failure would take away the only thing a script or an
//     operator can act on.
//
// The two statuses this launcher raises itself are 2 and 3, both before or instead
// of the installer running, and neither is one the installer uses to mean a
// refusal. Its standard streams are inherited by the child, so the manual recovery
// report -- which is the whole deliverable of a refusal -- reaches the terminal.
func runEmergencyRollback(args []string, stdout, stderr io.Writer, services services) int {
	if len(args) != 0 {
		writeCLIError(stderr, "emergency-rollback: takes no arguments: %s", strings.Join(args, " "))
		return exitInvalidCLI
	}
	if services.effectiveUID == nil || services.runInstaller == nil {
		writeCLIError(stderr, "emergency-rollback: this build has no installer boundary")
		return exitStateUnavailable
	}
	if uid := services.effectiveUID(); uid != 0 {
		writeCLIError(
			stderr,
			"emergency-rollback: uid %d, and this command rewrites a NetworkManager profile and "+
				"stops units, so it runs as root (uid 0) only",
			uid,
		)
		return exitInvalidCLI
	}
	if err := services.runInstaller(rollbackCommand()); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// The installer's own status, unchanged. Its messages went to the
			// terminal already, because the child's streams are this process's.
			return exitErr.ExitCode()
		}
		writeCLIError(stderr, "emergency-rollback: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

// runValidate checks a policy and reports whether the documents the operator has
// installed are what that policy describes.
//
// The exit code is the policy's: 0 when it loads and validates, 2 when it does
// not. That contract does not change. What is added to a successful run is a
// report, and only when there is something to report: a policy nobody applied
// beside a document the router is running is a disagreement the policy file
// cannot show by itself, and an operator who changed a safety switch needs to be
// told that the running document still says something else. Exit stays 0 because
// the policy is valid; the report is about the installation, not the file.
func runValidate(args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseValidateOptions(args, services.documents)
	if err != nil {
		writeCLIError(stderr, "validate: %v", err)
		return exitInvalidCLI
	}

	policy, err := config.Load(options.policy)
	if err != nil {
		writeCLIError(stderr, "validate: %v", err)
		return exitInvalidCLI
	}
	if err := policy.Validate(); err != nil {
		writeCLIError(stderr, "validate: %s: %v", options.policy, err)
		return exitInvalidCLI
	}
	if err := reportMismatches(stdout, policy, services.documents, options); err != nil {
		writeCLIError(stderr, "validate: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectorPath := flags.String("selector", "", "path to the selector state")
	dhcpPath := flags.String("dhcp", "", "path to the DHCP state")
	echPath := flags.String("ech", "", "path to the ECH state")
	if err := flags.Parse(args); err != nil {
		writeCLIError(stderr, "status: %v", err)
		return exitInvalidCLI
	}
	if flags.NArg() != 0 {
		writeCLIError(stderr, "status: unexpected arguments: %s", strings.Join(flags.Args(), " "))
		return exitInvalidCLI
	}

	selectorSet, dhcpSet, echSet := suppliedFlags(flags)
	if !selectorSet && !dhcpSet && !echSet {
		writeCLIError(stderr, "status: at least one state path is required")
		return exitInvalidCLI
	}
	if selectorSet && *selectorPath == "" {
		writeCLIError(stderr, "status: --selector PATH must not be empty")
		return exitInvalidCLI
	}
	if dhcpSet && *dhcpPath == "" {
		writeCLIError(stderr, "status: --dhcp PATH must not be empty")
		return exitInvalidCLI
	}
	if echSet && *echPath == "" {
		writeCLIError(stderr, "status: --ech PATH must not be empty")
		return exitInvalidCLI
	}

	// Read every requested state before writing anything. A missing or invalid
	// state therefore cannot leave a misleading partial status report.
	var selector state.Selector
	if selectorSet {
		if err := state.ReadJSON(*selectorPath, &selector); err != nil {
			writeCLIError(stderr, "status selector: %v", err)
			return exitStateUnavailable
		}
	}
	var dhcp state.DHCPState
	if dhcpSet {
		if err := state.ReadJSON(*dhcpPath, &dhcp); err != nil {
			writeCLIError(stderr, "status dhcp: %v", err)
			return exitStateUnavailable
		}
	}
	var ech state.ECHState
	if echSet {
		if err := state.ReadJSON(*echPath, &ech); err != nil {
			writeCLIError(stderr, "status ech: %v", err)
			return exitStateUnavailable
		}
	}

	var rendered bytes.Buffer
	if selectorSet {
		if err := renderNamespaced(&rendered, "selector", func(writer io.Writer) error {
			return status.RenderSelector(writer, selector)
		}); err != nil {
			writeCLIError(stderr, "status selector: render: %v", err)
			return exitStateUnavailable
		}
	}
	if dhcpSet {
		if err := renderNamespaced(&rendered, "dhcp", func(writer io.Writer) error {
			return status.RenderDHCP(writer, dhcp)
		}); err != nil {
			writeCLIError(stderr, "status dhcp: render: %v", err)
			return exitStateUnavailable
		}
	}
	if echSet {
		if err := renderNamespaced(&rendered, "ech", func(writer io.Writer) error {
			return status.RenderECH(writer, ech)
		}); err != nil {
			writeCLIError(stderr, "status ech: render: %v", err)
			return exitStateUnavailable
		}
	}
	if _, err := io.Copy(stdout, &rendered); err != nil {
		writeCLIError(stderr, "status: write output: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

func suppliedFlags(flags *flag.FlagSet) (selector, dhcp, ech bool) {
	flags.Visit(func(current *flag.Flag) {
		switch current.Name {
		case "selector":
			selector = true
		case "dhcp":
			dhcp = true
		case "ech":
			ech = true
		}
	})
	return selector, dhcp, ech
}

func renderNamespaced(output io.Writer, namespace string, render func(io.Writer) error) error {
	var rendered bytes.Buffer
	if err := render(&rendered); err != nil {
		return err
	}
	contents := rendered.String()
	if contents == "" {
		return nil
	}
	contents = strings.TrimSuffix(contents, "\n")
	for _, line := range strings.Split(contents, "\n") {
		if _, err := fmt.Fprintf(output, "%s.%s\n", namespace, line); err != nil {
			return err
		}
	}
	return nil
}

func writeCLIError(output io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(output, format+"\n", args...)
}

// ---------------------------------------------------------------------------
// test, apply, pin and unpin
// ---------------------------------------------------------------------------

// The paths the CDN commands read by default, which are the ones the packaged
// service installs. Every one is a flag so a test, a second installation or an
// operator with a different layout names its own, and so no command here can be
// pointed at /etc or /var/lib by accident.
const (
	defaultPolicyPath             = "/etc/mosdns/policy.yaml"
	defaultUserCandidatesPath     = "/etc/mosdns/cloudflare.txt"
	defaultCloudFrontProfilesPath = "/etc/mosdns/cloudfront-domains.yaml"
	defaultIdentityDomainsPath    = "/etc/mosdns/force-ech-domains.txt"
	defaultRepresentativeDomain   = "speed.cloudflare.com"
	defaultSelectorPath           = optimizer.DefaultSelectorPath
	defaultBandwidthBudgetPath    = optimizer.DefaultBudgetPath
	defaultHealthPath             = health.DefaultHealthPath
	defaultCloudflareRangesURL    = candidate.DefaultCloudflareBaseURL
	defaultCloudflareRangesCache  = "/var/lib/mosdns/lists/cloudflare-ips.json"
)

// identityPort and identityPath are what a global Cloudflare identity profile asks
// for: the HTTPS port every CDN serves on, and the root of the hostname.
//
// The expected status is 200 and no body digest is named, which is the whole of
// what can be claimed about a hostname this project did not choose: a chain
// verified for the name, the name in SNI and Host, and a 200 from it. A domain that
// answers something else is a domain to take out of the list rather than a reason
// to weaken the check, and the profile is held to that rule before it is used.
const (
	identityPort = 443
	identityPath = "/"
)

// cdnOptions is the parsed command line of test, apply, pin and unpin. They share
// one set of flags because they are one set of inputs: the same policy, the same
// selector, the same budget and the same identity profiles, read once each and
// used for whichever command the operator asked for.
type cdnOptions struct {
	policy         string
	selector       string
	budget         string
	health         string
	controlLock    string
	profiles       string
	identities     string
	candidates     string
	representative string
	rangesURL      string
	rangesCache    string
	report         string
	apply          bool
	// argument is the command's positional argument: the report to apply, or the
	// address to pin. It is empty for test and unpin.
	argument string
}

// parseCDNOptions parses and validates the shared flags. Every path is required to
// be non-empty rather than silently falling back, because a mistyped path here is
// an operator measuring the wrong thing or publishing to the wrong file, and a
// refusal at the command line is cheaper than either.
//
// The command's argument comes before its flags, as `apply REPORT.json` and
// `pin IPV4` are written, and the flag package stops parsing at the first argument
// that is not a flag - so the leading argument is taken off first and everything
// after it is parsed as flags. A second positional is still refused, because a
// command that took two paths would be taking one of them by accident.
func parseCDNOptions(name string, args []string, positional int) (cdnOptions, error) {
	var leading []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		leading, args = args[:1], args[1:]
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := cdnOptions{}
	flags.StringVar(&options.policy, "policy", defaultPolicyPath, "path to the policy document")
	flags.StringVar(&options.selector, "selector", defaultSelectorPath, "path to the selector state")
	flags.StringVar(&options.budget, "budget", defaultBandwidthBudgetPath, "path to the daily bandwidth budget")
	flags.StringVar(&options.health, "health", defaultHealthPath, "path to the winner health document")
	flags.StringVar(&options.controlLock, "control-lock", defaultControlLockPath, "path to the shared control lock")
	flags.StringVar(&options.profiles, "profiles", defaultCloudFrontProfilesPath, "path to the CloudFront profile document")
	flags.StringVar(&options.identities, "identity-domains", defaultIdentityDomainsPath, "path to the newline-separated hostnames a global address is proved against")
	flags.StringVar(&options.candidates, "candidates", defaultUserCandidatesPath, "path to the user's own candidate list")
	flags.StringVar(&options.representative, "representative-domain", defaultRepresentativeDomain, "the provider domain a global address is proved against")
	flags.StringVar(&options.rangesURL, "ranges-url", defaultCloudflareRangesURL, "the published Cloudflare range document")
	flags.StringVar(&options.rangesCache, "ranges-cache", defaultCloudflareRangesCache, "where the published range document is cached")
	flags.StringVar(&options.report, "report", "", "write the report document to this path; a report-only run spends the same daily bandwidth budget as one that applies")
	flags.BoolVar(&options.apply, "apply", false, "publish the winner once the final identity proof has passed; spends the same daily bandwidth budget as a report-only run")
	if err := flags.Parse(args); err != nil {
		return cdnOptions{}, err
	}
	rest := append(leading, flags.Args()...)
	switch {
	case len(rest) < positional:
		if positional == 1 {
			return cdnOptions{}, errors.New("a report path or an address is required")
		}
		return cdnOptions{}, errors.New("no arguments are accepted")
	case len(rest) > positional:
		return cdnOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(rest, " "))
	}
	if len(rest) == 1 {
		options.argument = rest[0]
	}
	for _, required := range []struct{ name, value string }{
		{"--policy", options.policy},
		{"--selector", options.selector},
		{"--budget", options.budget},
		{"--health", options.health},
		{"--control-lock", options.controlLock},
		{"--profiles", options.profiles},
		{"--identity-domains", options.identities},
		{"--candidates", options.candidates},
		{"--representative-domain", options.representative},
		{"--ranges-url", options.rangesURL},
		{"--ranges-cache", options.rangesCache},
	} {
		if strings.TrimSpace(required.value) == "" {
			return cdnOptions{}, fmt.Errorf("%s must not be empty", required.name)
		}
	}
	if err := refuseReportCollision(name, &options); err != nil {
		return cdnOptions{}, err
	}
	return options, nil
}

// refuseReportCollision refuses a --report that names a file the same invocation
// also uses.
//
// A report is written by the command, and every other path it names is either read
// or published: the policy the run is measured under, the selector it publishes
// into, the budget document it charges, the control lock it takes, the profile and
// candidate documents it reads, and the cache it keeps the published ranges in.
// Naming one of those as the report means a run overwrites the very document it
// just used, and the damage is silent - the next run reads a report where it
// expects a policy and says so much later.
//
// The paths are compared absolute, so a report written to "./cdn-selector.json" is
// recognised as the selector at its installed path rather than as a new file
// beside it.
func refuseReportCollision(name string, options *cdnOptions) error {
	if options.report == "" {
		return nil
	}
	report, err := filepath.Abs(options.report)
	if err != nil {
		return fmt.Errorf("--report %s: %w", options.report, err)
	}
	for _, other := range []struct{ flag, path string }{
		{"policy", options.policy},
		{"selector", options.selector},
		{"budget", options.budget},
		{"health", options.health},
		{"control-lock", options.controlLock},
		{"profiles", options.profiles},
		{"identity-domains", options.identities},
		{"candidates", options.candidates},
		{"ranges-cache", options.rangesCache},
	} {
		absolute, err := filepath.Abs(other.path)
		if err != nil {
			continue
		}
		if absolute == report {
			return fmt.Errorf("%s: --report %s is the same file as --%s (%s), which this run reads or writes",
				name, options.report, other.flag, other.path)
		}
	}
	return nil
}

// candidateSource is where a run's candidates come from. It is a value rather than
// four parameters because it is a services field, and a field with a signature
// nobody can read at the call site is a field nobody keeps right.
type candidateSource struct {
	// Client reaches the published range document.
	Client *http.Client
	// BaseURL and CachePath are the operator's, so a test never touches the real
	// endpoint and never writes to the production cache.
	BaseURL   string
	CachePath string
	// UserList is the operator's own candidate file.
	UserList string
	// Limit is cdn.cloudflare.max_candidates, and Moment is the local date the
	// daily sample is seeded from.
	Limit  int
	Moment time.Time
}

// cdnWorld is everything a CDN command works through: the policy and the digest of
// the document it came from, the runner, and the profiles a proof is held to.
type cdnWorld struct {
	policy config.Policy
	digest string
	runner *optimizer.Runner
	// prober is the prober this world measures and proves with, kept beside the
	// runner rather than built twice: the health check proves addresses over the
	// same identity path a measurement run uses, and two probers would be two
	// configurations of it. It is held as the optimizer's wider interface because
	// that is what the services boundary produces; the health check takes the
	// narrower one it needs out of the same value.
	prober optimizer.Prober
	// profiles keeps the two kinds of identity profile apart, because a proof is
	// held to one or the other and never to both: the global profiles are the
	// provider's representative domain and the forced-ECH domains, and each
	// CloudFront rule is the only profile its own hostname may be proved against.
	// A Cloudflare anycast address cannot present a chain for a CloudFront
	// hostname, and the CloudFront mapping is per-hostname, so a global address is
	// never published for one - which is the whole of why they are not mixed here.
	profiles optimizer.Profiles
	// cloudFrontRules are the operator's CloudFront profiles, which are also the
	// run's input: a rule names the addresses to measure for its own hostname.
	cloudFrontRules []candidate.CloudFrontProfile
}

// loadCDNConfig reads the policy, the identity profiles, the forced-ECH domains and
// the prober a command works through, and builds nothing that measures.
//
// This is buildCDNWorld without the runner, and it is its own function because one
// command does not want a runner: `health-check` proves the addresses a selector has
// published and never runs a measurement, and handing it a runner it would not use is
// a configuration of the prober and the budget paths that has nothing to do with the
// check it is about to make.
//
// The digest is taken from the document's own bytes and the policy is loaded from the
// same path. That is two reads of one file, and a policy edited between them would
// pair a digest with a parse of different content - which can only refuse the next
// apply, never let one through: an apply compares the report's digest against the
// digest of the file as it is then, so a stale pairing is a report that will not
// apply. The alternative, a loader this project would have to maintain beside the
// config package's own, is worse.
func loadCDNConfig(options cdnOptions, services services) (cdnWorld, error) {
	world := cdnWorld{}
	document, err := os.ReadFile(options.policy)
	if err != nil {
		return world, fmt.Errorf("read the policy: %w", err)
	}
	world.digest = optimizer.PolicyDigest(document)
	if world.policy, err = config.Load(options.policy); err != nil {
		return world, err
	}
	if world.cloudFrontRules, err = readCloudFrontProfiles(options.profiles); err != nil {
		return world, err
	}
	domains, err := readDomainList(options.identities)
	if err != nil {
		return world, err
	}
	// The provider's representative domain leads the list, so a refusal names it
	// first, and identityProfiles collapses it with a name the list also carries:
	// two spellings of one hostname are one profile, and proving the same thing
	// twice would double the final gate's hold of the control lock.
	profiles, err := identityProfiles(append([]string{options.representative}, domains...))
	if err != nil {
		return world, err
	}
	world.profiles = optimizer.Profiles{Global: profiles, ByHostname: profilesByHostname(world.cloudFrontRules)}
	world.prober = services.newProber()
	return world, nil
}

// buildCDNWorld is loadCDNConfig plus the runner the four measuring commands need.
func buildCDNWorld(options cdnOptions, services services) (cdnWorld, error) {
	world, err := loadCDNConfig(options, services)
	if err != nil {
		return world, err
	}
	if world.runner, err = optimizer.NewRunner(world.policy, world.prober, optimizer.Options{
		BudgetPath:      options.budget,
		SelectorPath:    options.selector,
		ControlLockPath: options.controlLock,
		ConfigSHA256:    world.digest,
		Now:             services.now,
	}); err != nil {
		return world, err
	}
	return world, nil
}

// readCloudFrontProfiles reads the operator's profile document. A document with no
// profiles in it is not an error: an installation that serves only global CDN
// addresses has no CloudFront hostnames, and refusing to measure because of that
// would leave the whole selector unusable.
func readCloudFrontProfiles(path string) ([]candidate.CloudFrontProfile, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the CloudFront profile document: %w", err)
	}
	defer func() { _ = file.Close() }()
	profiles, err := candidate.ParseCloudFrontProfiles(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return profiles, nil
}

// readDomainList reads the newline-separated hostnames a global address is proved
// against. The shape is the forced-ECH domain list's: one name per line, a line
// whose first non-space character is # is a comment, and a blank line is nothing.
// The forced-ECH domains are the names a Cloudflare address has to serve besides
// the provider's own, because a user on one of them would have every query
// rewritten to it.
func readDomainList(path string) ([]string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the identity domain list: %w", err)
	}
	var domains []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(contents), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// DNS names are case insensitive, so two spellings of one name are one
		// profile, and a duplicate would prove the same thing twice.
		name := strings.ToLower(trimmed)
		if seen[name] {
			continue
		}
		seen[name] = true
		domains = append(domains, name)
	}
	return domains, nil
}

// identityProfiles builds one global Cloudflare identity profile per hostname, and
// holds each to what a prober could check before a socket is opened. A hostname
// that cannot be a profile is a refusal here rather than a proof that would fail
// later against the network.
//
// Two names that differ only in case are one profile, because DNS names are case
// insensitive and the profile is keyed by the name: two would be the same proof run
// twice, and the final gate runs under the control lock.
func identityProfiles(domains []string) ([]candidate.ProbeProfile, error) {
	profiles := make([]candidate.ProbeProfile, 0, len(domains))
	seen := make(map[string]bool, len(domains))
	for _, domain := range domains {
		name := strings.ToLower(domain)
		if seen[name] {
			continue
		}
		seen[name] = true
		profile := candidate.ProbeProfile{
			Hostname:       name,
			URL:            "https://" + name + identityPath,
			Method:         http.MethodGet,
			Port:           identityPort,
			ExpectedStatus: []int{http.StatusOK},
		}
		if err := (candidate.CloudFrontProfile{Profile: profile}).Validate(); err != nil {
			return nil, fmt.Errorf("the identity domain %q is not usable: %w", domain, err)
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// profilesByHostname is the operator's CloudFront rules as the per-hostname half of
// the profile set. A hostname two rules share is already refused by the profile
// parser, so one rule is one hostname here.
func profilesByHostname(rules []candidate.CloudFrontProfile) map[string]candidate.ProbeProfile {
	if len(rules) == 0 {
		return nil
	}
	byHostname := make(map[string]candidate.ProbeProfile, len(rules))
	for _, rule := range rules {
		byHostname[strings.ToLower(rule.Profile.Hostname)] = rule.Profile
	}
	return byHostname
}

// networkProber is the composition of the prober package's prober with the
// optimizer's narrower interface.
//
// The two packages each declare their own budget interface, and an interface
// parameter's type is part of a method's signature, so the runner's Prober cannot
// be satisfied by the prober package's Prober directly: the optimizer may not
// import that package, because that package's own in-package tests use this one
// and Go forbids the cycle. This type is where the two meet, which is why it lives
// in the command that owns the composition rather than in either package.
//
// It forwards, and the only thing it changes is the budget: the run's settle-once
// budget reaches the prober through byteBudget, which forwards Reserve and Consume
// to the same value. A transfer therefore reserves and settles against the day's
// one budget exactly as it would without the adapter.
type networkProber struct {
	inner prober.Prober
}

var _ optimizer.Prober = networkProber{}

func (p networkProber) TCP(ctx context.Context, address netip.Addr, port uint16, samples int) (measure.TCPMetrics, error) {
	return p.inner.TCP(ctx, address, port, samples)
}

func (p networkProber) HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (measure.HTTPMetrics, error) {
	return p.inner.HTTPS(ctx, subject, profile)
}

func (p networkProber) Download(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile, maxBytes int64, maxDuration time.Duration, budget optimizer.ByteBudget) (measure.DownloadMetrics, error) {
	return p.inner.Download(ctx, subject, profile, maxBytes, maxDuration, byteBudget{inner: budget})
}

// byteBudget is the run's budget seen through the prober's own narrower
// interface. It is one value with two method calls and no state of its own.
type byteBudget struct {
	inner optimizer.ByteBudget
}

var _ prober.ByteBudget = byteBudget{}

func (b byteBudget) Reserve(requested int64) (int64, error) { return b.inner.Reserve(requested) }

func (b byteBudget) Consume(reserved, actual int64) { b.inner.Consume(reserved, actual) }

// runCDNTest measures the candidates and reports, and publishes nothing unless
// --apply was asked for.
//
// The two are one command on purpose. The design has the daily timer call
// `test --apply`, which is the whole measurement and the whole publication in one
// invocation, so the final identity proof runs inside it against what it just
// measured. A report written earlier is never what gets published, and the report
// file --report writes is an output for a person rather than an input to this
// command.
//
// **A report-only run spends the day's bandwidth exactly as an applying one does.**
// The transfers happen in the measurement phases, which both forms run, and
// publication is a proof and a write at the end. Nothing here is a dry run, and
// with the shipped policy the difference is not academic: a ten-candidate
// shortlist at 10 MiB each is exactly the 100 MiB day, so an exploratory `test`
// can leave the nightly `test --apply` with `budget-exhausted: true` and every
// group kept. The report therefore carries the day's limit and what remains of it
// - from the run's own budget document, so an operator who tightened the day sees
// the number their document enforces - and the output prints both.
func runCDNTest(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseCDNOptions("test", args, 0)
	if err != nil {
		writeCLIError(stderr, "test: %v", err)
		return exitInvalidCLI
	}
	world, err := buildCDNWorld(options, services)
	if err != nil {
		writeCLIError(stderr, "test: %v", err)
		return exitInvalidCLI
	}
	collected, err := services.readCandidates(ctx, candidateSource{
		Client:    services.newHTTPClient(),
		BaseURL:   options.rangesURL,
		CachePath: options.rangesCache,
		UserList:  options.candidates,
		Limit:     world.policy.CDN.Cloudflare.MaxCandidates,
		Moment:    services.now(),
	})
	if err != nil {
		writeCLIError(stderr, "test: %v", err)
		return exitStateUnavailable
	}
	input := optimizer.Input{
		Cloudflare:         collected.Candidates,
		CloudflareProfiles: world.profiles.Global,
		CloudFrontRules:    world.cloudFrontRules,
		Stale:              collected.Stale,
	}
	// The selector is read without the control lock, deliberately. A report-only
	// run has to be possible while a pin or a health check is publishing, so the
	// read is of a file that is replaced by a rename and never half written; and
	// every use this run makes of it - the retained candidates, the incumbent
	// score - is a measurement, not a decision. The apply that follows re-reads it
	// under the lock and decides there.
	input.LastGood = readSelectorForReport(options.selector)
	report, err := world.runner.Run(ctx, input)
	if err != nil {
		// A run that could not finish still reports what it measured, and publishes
		// nothing: the partial document is the operator's only record of how far it
		// got.
		writePartialReport(options, report, stdout, stderr)
		return exitStateUnavailable
	}
	if len(report.Groups) == 0 {
		// A report with no group is not a document this build will write or apply -
		// it measured nothing - so it is said here rather than handed to the writer
		// to refuse with a validation error about a field the operator never sees.
		writeCLIError(stderr, "test: no candidate was collected, so nothing was measured and nothing was published")
		return exitStateUnavailable
	}
	var published *state.Selector
	if options.apply {
		applied, selector, applyErr := world.runner.Apply(ctx, report, world.profiles)
		report = applied
		if applyErr != nil {
			_ = writeCDNReport(stdout, report, nil)
			writeCLIError(stderr, "test: %v", applyErr)
			return cdnExitCode(applyErr)
		}
		published = publishedSelector(report, selector)
	}
	if err := writeReportFile(options.report, report); err != nil {
		writeCLIError(stderr, "test: %v", err)
		return exitStateUnavailable
	}
	if err := writeCDNReport(stdout, report, published); err != nil {
		writeCLIError(stderr, "test: write report: %v", err)
		return exitStateUnavailable
	}
	if !reportHasWinner(report) {
		// A run that measured nothing publishable is not a successful run: nothing
		// was published, and a timer that saw this succeed would record a day the
		// router measured nothing as a day it was fine. The reason is in the report.
		writeCLIError(stderr, "test: no candidate qualified, so nothing was published; the report names the reason")
		return exitStateUnavailable
	}
	return exitSuccess
}

// reportHasWinner reports whether any group named a winner at all, which is not the
// same as any of them being allowed to publish: a report whose every switch was
// refused has a winner and publishes nothing either.
func reportHasWinner(report optimizer.Report) bool {
	for _, group := range report.Groups {
		if group.Winner != nil {
			return true
		}
	}
	return false
}

// runCDNApply publishes a report that was written earlier.
//
// Everything the report says about the network is up to two hours old, and
// everything it says about the configuration is checked against the digest of the
// policy as it is now. What the report cannot be trusted for is the address: the
// final identity proof runs here, under the control lock, against the profiles this
// configuration names - not the ones the report carries, which is the whole point.
func runCDNApply(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseCDNOptions("apply", args, 1)
	if err != nil {
		writeCLIError(stderr, "apply: %v", err)
		return exitInvalidCLI
	}
	report, err := optimizer.ReadReport(options.argument)
	if err != nil {
		writeCLIError(stderr, "apply: %v", err)
		return exitStateUnavailable
	}
	world, err := buildCDNWorld(options, services)
	if err != nil {
		writeCLIError(stderr, "apply: %v", err)
		return exitInvalidCLI
	}
	applied, published, err := world.runner.Apply(ctx, report, world.profiles)
	if err != nil {
		// The report is printed before the error, on the same grounds as `test
		// --apply`: it carries the decision the run reached and the outcome the
		// apply reached, and a reader who only ever sees the error line learns
		// nothing about which address was about to go into service or that nothing
		// did.
		_ = writeCDNReport(stdout, applied, nil)
		writeCLIError(stderr, "apply: %v", err)
		return cdnExitCode(err)
	}
	// The applied report is written out as well as the measurement it came from, so
	// an operator who applies a report keeps the record that includes the final
	// proof the report on disk did not have.
	if err := writeReportFile(options.report, applied); err != nil {
		writeCLIError(stderr, "apply: %v", err)
		return exitStateUnavailable
	}
	if err := writeCDNReport(stdout, applied, publishedSelector(applied, published)); err != nil {
		writeCLIError(stderr, "apply: write report: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

// publishedSelector is what an apply wrote, or nil when it wrote nothing.
//
// An apply in which every group kept its mapping succeeds, and the address in
// service is unchanged - which is an outcome and not a failure, so the exit code
// says success. It is not a publication, though, and the output has to say so: the
// selector it did not write still holds the address that was already there, and a
// timer or a script that read "applied: <ip>" off that output would record a
// publication on the one night nobody reads a report twice.
//
// The report's own outcome is what is asked, rather than the selector's fields,
// because the outcome is the documented statement of what the apply did. The zero
// selector Apply returns in that case is the same fact from the other side.
func publishedSelector(report optimizer.Report, written state.Selector) *state.Selector {
	if report.Outcome != optimizer.OutcomePublished {
		return nil
	}
	return &written
}

// runCDNPin stores an address as the manual winner, after a real identity proof
// against the profiles of the group that address would be published for. It accepts
// an address and nothing else: a manual pin is one operator, one address, and a
// decision this project will not extend to a host, a prefix or a hostname it did
// not measure.
func runCDNPin(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseCDNOptions("pin", args, 1)
	if err != nil {
		writeCLIError(stderr, "pin: %v", err)
		return exitInvalidCLI
	}
	if options.report != "" {
		// A pin measures nothing, so there is no report to write. Refusing the flag
		// is better than accepting it and producing no file, which an operator would
		// read as a report that says nothing is wrong.
		writeCLIError(stderr, "pin: --report is for test and apply, which measure something")
		return exitInvalidCLI
	}
	address, err := netip.ParseAddr(options.argument)
	if err != nil {
		writeCLIError(stderr, "pin: %q is not an address: %v", options.argument, err)
		return exitInvalidCLI
	}
	world, err := buildCDNWorld(options, services)
	if err != nil {
		writeCLIError(stderr, "pin: %v", err)
		return exitInvalidCLI
	}
	pinned, err := world.runner.Pin(ctx, address.Unmap(), world.profiles)
	// The uncharged identity bytes are printed before the error, on the same
	// grounds as `health-check`: a pin that is refused has still spent the
	// operator's data allowance proving the address, and nothing on disk accounts
	// for it.
	writeReportLine(stdout, "identity-body-bytes: %d\n", pinned.IdentityBytes)
	if err != nil {
		writeCLIError(stderr, "pin: %v", err)
		return cdnExitCode(err)
	}
	writeReportLine(stdout, "pinned: %s\n", address)
	if err := renderNamespaced(stdout, "selector", func(writer io.Writer) error {
		return status.RenderSelector(writer, pinned.Selector)
	}); err != nil {
		writeCLIError(stderr, "pin: write report: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

// runCDNUnpin restores automatic selection and keeps the pinned address as the
// fallback. It reads no policy value beyond the configuration digest it stamps into
// the document, and it opens no socket.
func runCDNUnpin(args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseCDNOptions("unpin", args, 0)
	if err != nil {
		writeCLIError(stderr, "unpin: %v", err)
		return exitInvalidCLI
	}
	if options.report != "" {
		writeCLIError(stderr, "unpin: --report is for test and apply, which measure something")
		return exitInvalidCLI
	}
	world, err := buildCDNWorld(options, services)
	if err != nil {
		writeCLIError(stderr, "unpin: %v", err)
		return exitInvalidCLI
	}
	published, err := world.runner.Unpin()
	if err != nil {
		writeCLIError(stderr, "unpin: %v", err)
		return cdnExitCode(err)
	}
	writeReportLine(stdout, "unpinned: fallback %s\n", published.FallbackIP)
	if err := renderNamespaced(stdout, "selector", func(writer io.Writer) error {
		return status.RenderSelector(writer, published)
	}); err != nil {
		writeCLIError(stderr, "unpin: write report: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}

// cdnExitCode maps a refusal to the exit code a caller can act on. A lock conflict
// gets its own code, because "the other one got there first" and "this one is
// broken" are different answers to a timer and to an operator.
func cdnExitCode(err error) int {
	if errors.Is(err, optimizer.ErrControlLocked) {
		return exitLockHeld
	}
	return exitStateUnavailable
}

// readSelectorForReport reads the selector for a report-only run. A document that
// cannot be read is not an error here: the run's decision does not depend on it -
// it decides from what it measures - and the apply that publishes will read it
// again under the control lock and refuse there if it is unreadable.
func readSelectorForReport(path string) state.Selector {
	selector := state.Selector{}
	if err := state.ReadJSON(path, &selector); err != nil {
		return state.Selector{}
	}
	return selector
}

func writeReportFile(path string, report optimizer.Report) error {
	if path == "" {
		return nil
	}
	return optimizer.WriteReport(path, report)
}

// writeCDNReport is what an operator reads. Every line is a fact with its number on
// it, because the report's job is to be acted on and a run that found a winner it
// could not publish has to say so here rather than only on stderr.
//
// A nil published means nothing was written, and there are three ways to get here
// with one: a report-only run that never applied anything, an apply in which every
// group kept its mapping, and an apply that was refused at one of its gates. The
// report's own outcome says which of the last two it was, and the two must never
// be allowed to read alike - an outcome line claiming a publication beside an
// "applied: nothing" line is the mislabel this function's callers are checked
// against in their tests.
func writeCDNReport(output io.Writer, report optimizer.Report, published *state.Selector) error {
	if published != nil {
		writeReportLine(output, "applied: %s\n", published.WinnerIP)
		writeReportLine(output, "generation: %d\n", published.Generation)
		writeReportLine(output, "fallback: %s\n", published.FallbackIP)
	} else {
		writeReportLine(output, "applied: nothing\n")
	}
	if report.Outcome != "" {
		// The overall outcome, and then each group's own, because the two are not the
		// same answer: one group publishing while another keeps its mapping is
		// "published" overall and "kept" for the group that did not.
		writeReportLine(output, "outcome: %s\n", report.Outcome)
	}
	writeReportLine(output, "generated-at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	writeReportLine(output, "config-sha256: %s\n", report.ConfigSHA256)
	writeReportLine(output, "stale-candidates: %t\n", report.Stale)
	writeReportLine(output, "identity-body-bytes: %d\n", report.IdentityBytes)
	writeReportLine(output, "budget-used-bytes: %d\n", report.BudgetUsed)
	// The limit and the room left, because a run that named only what it spent
	// would leave an operator finding out the day's budget by having the next run
	// refused. Both numbers come from the run's own budget document, so an
	// operator who tightened the day sees the number their own document enforces.
	writeReportLine(output, "budget-limit-bytes: %d\n", report.BudgetLimit)
	writeReportLine(output, "budget-remaining-bytes: %d\n", report.BudgetRemaining)
	writeReportLine(output, "budget-exhausted: %t\n", report.BudgetExhausted)
	if len(report.SettleRefusals) > 0 {
		for _, refusal := range report.SettleRefusals {
			writeReportLine(output, "settle-refused: %s\n", refusal)
		}
	}
	for _, skipped := range report.SkippedRetained {
		writeReportLine(output, "skipped-retained: %s\n", skipped)
	}
	for _, group := range report.Groups {
		writeReportLine(output, "group: %s\n", group.Group)
		writeReportLine(output, "candidates: %d\n", len(group.Candidates))
		writeReportLine(output, "p10-bytes-per-second: %g\n", group.P10BytesPerSecond)
		for _, entry := range group.Candidates {
			verdict := "excluded: " + entry.Reason
			if entry.Eligible {
				verdict = fmt.Sprintf("eligible, score %g", entry.Score)
			}
			writeReportLine(output, "  candidate: %s %s p50 %gms jitter %gms loss %g speed %gB/s %s\n",
				entry.IP, entry.Source, entry.P50MS, entry.JitterMS, entry.Loss, entry.BytesPerSecond, verdict)
			if entry.Detail != "" {
				writeReportLine(output, "    detail: %s\n", entry.Detail)
			}
		}
		switch {
		case group.Winner != nil:
			verdict := "switch refused: " + group.Winner.SwitchRefusal
			if group.Winner.SwitchAllowed {
				verdict = "switch allowed"
			}
			writeReportLine(output, "  winner: %s score %g %s\n", group.Winner.IP, group.Winner.Score, verdict)
		case group.NoWinner != "":
			writeReportLine(output, "  no-winner: %s\n", group.NoWinner)
		}
		if group.Outcome != "" {
			writeReportLine(output, "  outcome: %s\n", group.Outcome)
			if group.OutcomeReason != "" {
				writeReportLine(output, "    outcome-reason: %s\n", group.OutcomeReason)
			}
		}
	}
	// The final proof gets the answer it deserves, and there are three: it passed,
	// it ran and did not, or it never ran. A report-only run never proves the winner
	// again, so "not run" is the truth for it; a proof that ran and was refused is
	// the line that says the address stopped serving, and printing "not run" beside
	// it read as though nothing had been proved and nothing was at stake.
	switch {
	case report.FinalProofPassed:
		writeReportLine(output, "final-proof: passed at %s\n", report.ProofedAt.Format(time.RFC3339))
	case report.FinalProofRefused != "":
		writeReportLine(output, "final-proof: %s, this report publishes nothing\n", report.FinalProofRefused)
	default:
		writeReportLine(output, "final-proof: not run, this report publishes nothing\n")
	}
	return nil
}

// writePartialReport is what a cancelled or failed run leaves behind: the document
// it did produce, on stdout, and the error on stderr. Publishing is not on the
// table for a run that did not finish.
//
// A partial report is not written to --report, and the error says so in those terms
// rather than surfacing the writer's validation complaint: the phases that never ran
// have no boundaries, so the document is not one this build will write and not one an
// apply could read - which is the right refusal, and a bare "the identity phase has
// no recorded boundaries" tells an operator nothing about where the document they
// asked for went.
func writePartialReport(options cdnOptions, report optimizer.Report, stdout, stderr io.Writer) {
	if report.Groups == nil && report.Phases.Collect.StartedAt.IsZero() {
		return
	}
	if err := writeReportFile(options.report, report); err != nil {
		writeCLIError(stderr, "test: the run did not finish, so no report document was written to %s: %v; the partial report is on stdout", options.report, err)
	}
	_ = writeCDNReport(stdout, report, nil)
}

// ---------------------------------------------------------------------------
// health-check
// ---------------------------------------------------------------------------

// runCDNHealthCheck proves the addresses the selector has published and moves the
// resolver to the fallback when the published winner has failed at the policy's
// threshold. It is the two-minute timer's command and the only one whose job is to
// take an address out of service.
//
// It reads the same policy, selector, identity profiles and forced-ECH domains the
// other CDN commands read, and it charges no bandwidth: a check that decides whether
// the address in service may stay there must not be able to spend the day, and the
// uncharged body bytes it does read are reported on stdout because nothing on disk
// accounts for them.
//
// The exit code is the outcome an operator can act on. Zero is a check that did what
// it was asked, whether or not it found a problem - a failing winner below the
// threshold is a fact, not a failure. A refused transition is exitStateUnavailable,
// because the address in service is failing and this command could not move it, and so
// is a check that was cut short before it could decide one. A control lock held by an
// apply or a pin is exitLockHeld, because the answer is "somebody else is publishing
// right now", and the timer will ask again in two minutes.
func runCDNHealthCheck(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseCDNOptions("health-check", args, 0)
	if err != nil {
		writeCLIError(stderr, "health-check: %v", err)
		return exitInvalidCLI
	}
	// --report and --apply belong to the commands that measure something. Accepting
	// them here would produce a command that appears to have measured or applied and
	// did neither, which is the one impression a report line must never give.
	if options.report != "" {
		writeCLIError(stderr, "health-check: --report is for test and apply, which measure something")
		return exitInvalidCLI
	}
	if options.apply {
		writeCLIError(stderr, "health-check: --apply publishes a measurement; a health check transitions on its own")
		return exitInvalidCLI
	}
	// The configuration and the prober, and no runner: a health check measures one
	// address against the identity profiles, and a runner it never calls would only be
	// a second thing to configure.
	world, err := loadCDNConfig(options, services)
	if err != nil {
		writeCLIError(stderr, "health-check: %v", err)
		return exitInvalidCLI
	}
	checker, err := health.NewChecker(world.prober, health.Options{
		Profiles:         world.profiles,
		HealthPath:       options.health,
		SelectorPath:     options.selector,
		ControlLockPath:  options.controlLock,
		FailureThreshold: world.policy.CDN.Health.FailureThreshold,
		Now:              services.now,
	})
	if err != nil {
		writeCLIError(stderr, "health-check: %v", err)
		return exitInvalidCLI
	}
	result, err := checker.Check(ctx)
	// The report is printed before the error, on the same grounds as `apply`: a
	// reader who only ever sees the error line learns nothing about which address
	// was checked, what the failure was, or how much uncharged traffic the check
	// spent reaching that verdict.
	writeHealthReport(stdout, result)
	if err != nil {
		writeCLIError(stderr, "health-check: %v", err)
		return cdnExitCode(err)
	}
	return exitSuccess
}

// writeHealthReport is what an operator or a timer reads after a check.
//
// Every line is a fact this check established, and a line that would not be is left
// out rather than printed as a zero:
//
//   - the winner's address and verdict, with the refusal the proof gave. An address
//     the selector does not publish is reported as "none" rather than as a verdict
//     about nothing.
//   - one line per published per-hostname mapping, with its own verdict, because the
//     document below describes the winner and nothing else would say whether the
//     CloudFront mappings are still serving.
//   - the uncharged identity body bytes, always, including a check that proved
//     nothing: they are spent either way and no budget accounts for them.
//   - the health document, but only when this check wrote one. A counter it did not
//     write is not a fact about the router, and a cancellation prints no counter at
//     all.
//   - winner-proof, on every path, because the response rewriter gates on the
//     window and a report that said nothing about it would leave an operator unable
//     to tell an open window from an expired one. It names the instant the window
//     closes when this check refreshed it, and says it refreshed nothing when it did
//     not - which is what a failing or a cancelled check means.
//   - failed-closed, when the previous document could not be read, because the count
//     that follows starts at the policy's threshold and would otherwise look like a
//     fourth consecutive failure of its own accord.
//   - transition, and only ever for a selector this check actually wrote. The check
//     clears the field on every error path, so a refused transition cannot be
//     reported as a publication.
func writeHealthReport(output io.Writer, result health.Result) {
	if result.Winner.Address == "" {
		writeReportLine(output, "winner: none %s\n", result.Winner.Verdict)
	} else {
		writeReportLine(output, "winner: %s %s\n", result.Winner.Address, result.Winner.Verdict)
	}
	if result.Winner.Detail != "" {
		writeReportLine(output, "detail: %s\n", result.Winner.Detail)
	}
	for _, mapping := range result.CloudFront {
		writeReportLine(output, "cloudfront: %s %s %s\n", mapping.Hostname, mapping.Address, mapping.Verdict)
		if mapping.Detail != "" {
			writeReportLine(output, "  detail: %s\n", mapping.Detail)
		}
	}
	writeReportLine(output, "identity-body-bytes: %d\n", result.Bytes)
	if result.FailedClosed != "" {
		writeReportLine(output, "failed-closed: %s\n", result.FailedClosed)
	}
	if result.WroteHealth() {
		writeReportLine(output, "consecutive-failures: %d\n", result.Health.ConsecutiveFailures)
		writeReportLine(output, "healthy: %t\n", result.Health.Healthy)
	}
	// The window the rewriter gates on, and whether this check moved it. A
	// transition stamps the window of the address it moved to and is reported as the
	// transition it is, so the two lines are never read as one refresh of one
	// address.
	if result.RefreshedProof {
		writeReportLine(output, "winner-proof: refreshed, until %s\n", result.ProofUntil.Format(time.RFC3339))
	} else {
		writeReportLine(output, "winner-proof: not refreshed\n")
	}
	if result.Transition != nil {
		writeReportLine(output, "transition: %s at generation %d\n", result.Transition.WinnerIP, result.Transition.Generation)
	}
}
