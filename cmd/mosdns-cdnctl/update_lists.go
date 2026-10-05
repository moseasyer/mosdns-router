package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/mosdnsconfig"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/prober"
	"mosdns-router/internal/rules"
)

// The paths the packaged service installs its list into. They are the defaults
// so the daily check timer and an operator's pin both act on the list the router
// reads, and they are overridable so a test or a second installation can use its
// own directory.
const (
	defaultSourceLockPath  = "/var/lib/mosdns/lists/source-lock.json"
	defaultListFilePath    = "/var/lib/mosdns/lists/cn-domains.txt"
	defaultControlLockPath = "/var/lib/mosdns/runtime/control.lock"
)

// pinRef is the only ref `--pin-remote` accepts. The reviewed commit comes from
// the repository's default branch, so there is no ref for an operator to name.
const pinRef = "HEAD"

// updateListTimeout bounds one update, so a timer run or a pin cannot hang on a
// slow or unresponsive origin.
const updateListTimeout = 60 * time.Second

// services is the boundary the commands in this binary use for everything outside
// themselves: the HTTP client that reaches the source, the control lock that keeps
// a publication from colliding with the rest of the control operations, where the
// generated documents live, and the file operations a document publication is
// built from. Everything else, conversion, rendering and publication included, is
// the real implementation.
//
// The three fields the CDN commands need are here for the same reason. The prober
// is the only thing that opens a socket, the candidate source is the only thing
// that reaches the network for addresses, and the clock is what dates a report and
// measures the age of one an apply is reading - so a test that wants any of the
// three to be something else has to be able to say so here.
type services struct {
	newHTTPClient func() *http.Client
	acquireLock   func(path string) (release func() error, err error)
	// documents is where the generated documents are published and which policy
	// they are rendered from, so no test has to write to /etc.
	documents documentPaths
	// documentOps are the file operations a document publication is built from.
	// They are a field so a test can make one of them fail and observe what the
	// operator is left with; production uses the real ones.
	documentOps documentFileOps
	// newProber builds the prober a measurement run measures with.
	newProber func() optimizer.Prober
	// readCandidates reads the official range document and the user's own list, and
	// is the only thing that puts an address a run will measure into existence. It
	// takes the caller's context because it is the one part of a measurement that
	// fetches over the network, and a fetch that ignored the context would make the
	// collection phase of `test` uncancellable.
	readCandidates func(context.Context, candidateSource) (candidate.CandidateSet, error)
	// reloadSystemd makes systemd re-read its units. The render verb runs it after
	// it writes the generated timer, so a schedule the operator changed takes effect
	// in the same operation that changed it. It is a field so a test can say what a
	// refused reload leaves behind instead of needing a systemd.
	reloadSystemd func() error
	// now is the clock. Every timestamp a report and a selector carry comes from
	// it, so all of them are one reading in production.
	now func() time.Time
	// effectiveUID is who this process is, and emergency-rollback refuses to run
	// as anyone else. It is a field rather than a call to os.Geteuid() inside the
	// command so that a test can say "this is not root" without a container, and
	// so that the refusal is a branch rather than an assumption.
	effectiveUID func() int
	// runInstaller is the whole process boundary of the emergency-rollback verb:
	// it takes the argument array and runs it, or reports why it could not. It is
	// an argv and never a string, so there is no shell between this program and
	// the installer, and it is a field so a test can see the exact array instead
	// of running the installer on whatever machine the test runs on.
	runInstaller func(argv []string) error
	// loadPolicy reads the policy the route is configured in. It is a field so the
	// connectivity check can be handed a policy that is not the installed one,
	// which is the only way to ask "would an operator who added an entry see it?"
	// without writing to /etc on the machine the test runs on.
	loadPolicy func(path string) (config.Policy, error)
	// newUpstream builds a dialable upstream. It is a field so the connectivity
	// check can be handed an upstream that answers, refuses, or never answers,
	// without a network and without a DNS server.
	newUpstream func(addr string, opt upstream.Opt) (upstream.Upstream, error)
	// flushBaseURL is the router's own API address. It is a field so the flush can
	// be pointed at an httptest server; production derives it from the routing
	// document's api block, which is what makes the two unable to disagree.
	flushBaseURL string
}

// productionServicesWith is productionServices with the two boundaries the
// emergency-rollback verb uses replaced. It exists so the rollback's own test can
// name a UID and a fake runner while every other boundary stays the real one, and
// so there is exactly one production definition of both.
func productionServicesWith(effectiveUID func() int, runInstaller func(argv []string) error) services {
	value := productionServices()
	value.effectiveUID = effectiveUID
	value.runInstaller = runInstaller
	return value
}

// productionServices is what the executable runs with: a plain client that
// resolves names through the system resolver, the shared control lock, the
// installed document layout, the real file operations, the real prober, the real
// published range source and the real clock.
func productionServices() services {
	return services{
		newHTTPClient: func() *http.Client { return &http.Client{Timeout: updateListTimeout} },
		acquireLock: func(path string) (func() error, error) {
			lock, err := filelock.Acquire(path)
			if err != nil {
				return nil, err
			}
			return lock.Close, nil
		},
		documents:      productionDocumentPaths(),
		documentOps:    defaultDocumentOps(),
		reloadSystemd:  reloadSystemd,
		newProber:      func() optimizer.Prober { return networkProber{inner: prober.New(prober.Options{})} },
		readCandidates: readOfficialAndUserCandidates,
		now:            time.Now,
		effectiveUID:   os.Geteuid,
		runInstaller:   runInstallerScript,
		loadPolicy:     config.Load,
		newUpstream: func(addr string, opt upstream.Opt) (upstream.Upstream, error) {
			return upstream.NewUpstream(addr, opt)
		},
		flushBaseURL: "http://" + mosdnsconfig.APIListenAddress(),
	}
}

// runInstallerScript is the one place in this program that starts another
// program, and it is here rather than inside the command so that the command's
// only job is deciding whether to call it.
//
// Three properties, all of them the reason this is a five-line function rather
// than an exec.Command call at the point of use:
//
//   - the argument array is passed through as an array, so nothing a caller or a
//     machine can put in a connection UUID or a device name is ever interpreted;
//   - the standard streams are inherited, so the installer's own messages -- which
//     include a manual recovery report an operator has to be able to read -- reach
//     the terminal instead of being captured and re-printed;
//   - the child's status is not translated, because each of the installer's
//     statuses is a fact about the machine and flattening them would take away the
//     only thing a caller can act on.
func runInstallerScript(argv []string) error {
	if len(argv) == 0 {
		return errors.New("no command to run")
	}
	command := exec.Command(argv[0], argv[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

// readOfficialAndUserCandidates is where a run's addresses come from: the
// published Cloudflare ranges, sampled under the policy's cap, and the operator's
// own list, which is never capped.
//
// The two are returned as one set carrying the official set's stale marker, because
// that is the fact a report has to show: an operator reading "12 candidates" needs
// to know whether they are today's or the last ones this build accepted.
//
// The context is the caller's, and it is the whole of the cancellation story for
// this phase: the range fetch is the only network I/O a measurement run does
// outside the prober, so a `test` whose operator pressed Ctrl-C would otherwise
// wait out the HTTP client's own timeout before it noticed.
func readOfficialAndUserCandidates(ctx context.Context, source candidateSource) (candidate.CandidateSet, error) {
	if source.Client == nil {
		return candidate.CandidateSet{}, errors.New("a candidate source needs an HTTP client")
	}
	official, err := candidate.NewCloudflareSource(source.Client, source.BaseURL, source.CachePath)
	if err != nil {
		return candidate.CandidateSet{}, err
	}
	set, err := official.Candidates(ctx, source.Limit, source.Moment)
	if err != nil {
		return candidate.CandidateSet{}, err
	}
	user, err := readUserCandidates(source.UserList)
	if err != nil {
		return candidate.CandidateSet{}, err
	}
	set.Candidates = append(set.Candidates, user...)
	return set, nil
}

// readUserCandidates reads the operator's own list. A file that is not there is
// simply no candidates of its own, which is the state of a fresh installation.
func readUserCandidates(path string) ([]candidate.Candidate, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the candidate list: %w", err)
	}
	defer func() { _ = file.Close() }()
	listed, err := candidate.ParseUserList(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return listed, nil
}

// updateListOptions are the parsed command line of update-lists.
// defaultPreviousLockPath sits beside the lock it archives, because the two are one
// fact in two states. A previous pin stored anywhere else is a previous pin nobody
// finds, and this is the file an operator is told to look at after a bad refresh.
const defaultPreviousLockPath = "/var/lib/mosdns/lists/source-lock.previous.json"

type updateListOptions struct {
	check bool
	// automatic is the mode a scheduled run uses: report drift, then refresh what the
	// policy says to refresh. It is a mode rather than a flag on --check because the
	// two differ in what they may do -- one writes and one does not -- and a flag that
	// changed that would be a flag whose name understated it.
	automatic bool
	// policy is where --automatic reads what to refresh. It defaults to the installed
	// policy, which is the file the rest of this package renders from, so a scheduled
	// run and a hand-run render cannot disagree about what the machine is configured
	// to do.
	policy        string
	pinRemote     string
	refreshRanges bool
	sourceLock    string
	listFile      string
	// previousLock is where the outgoing pin is archived, before the new one replaces
	// it. It is a field rather than a constant used at the one place it is read,
	// because a test that exercises the archive has to be able to point it somewhere
	// that is not this project's installation.
	previousLock string
	controlLock  string
	rangesURL    string
	rangesCache  string
	// pinnedRanges and pinnedRangesLock are the snapshot a package ships and the
	// lock beside it. They are paths of this project's own installation for the
	// reason the other range paths are, and they are the two that make an
	// installation with no route to the internet possible: the origin cannot be
	// read there, nothing is published on a fresh machine, and without a pair to
	// stand in the install refuses and the router never starts.
	pinnedRanges     string
	pinnedRangesLock string
}

// parseUpdateListOptions parses and validates the command line. Exactly one of
// --check, --pin-remote HEAD and --refresh-ranges is required, they are mutually
// exclusive, and the only accepted ref is the literal HEAD: a pin names no branch,
// tag or commit, so the reviewed source is always the repository's default branch.
//
// --refresh-ranges is a mode of its own rather than a flag on either of the other
// two, and that shape is the point. The prefix list it publishes is what the
// response rewriter refuses to construct without, so an installation needs it
// before the router starts; the two modes it might have been folded into are the
// wrong carriers. `--check` is documented to write nothing and takes no lock, so
// it cannot publish, and `--pin-remote` re-pins the China list, which ruling 59
// forbids during an install.
//
// diagnostics is where the flag set's own messages go. It used to be io.Discard,
// which made `-h` and `--help` print the usage into nothing: an operator who asked
// for help got "flag: help requested" and no flags, and an unknown flag produced a
// diagnostic that did not say which flags existed. It is the command's own stderr
// rather than a fresh writer, so the usage lands where everything else this command
// says lands and a caller that captures stderr captures the usage with it.
func parseUpdateListOptions(diagnostics io.Writer, args []string) (updateListOptions, error) {
	flags := flag.NewFlagSet("update-lists", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	// The --check description has to say what the command now reports, not only
	// what it reported when the flag was written: the ranges half of the report is
	// the half that says whether the prefix list the rewriter refuses to start
	// without is actually on disk, and the man page inherits this string rather
	// than a second copy of it.
	automatic := flags.Bool("automatic", false, "act on the policy's lists.china.automatic and lists.cloudflare.automatic: always report drift, and then refresh what the policy says to refresh, which by default is nothing at all. The mode a scheduled run uses")
	policy := flags.String("policy", defaultPolicyPath, "path to the policy YAML file, read by --automatic to decide what to refresh")
	check := flags.Bool("check", false, "report whether the pinned source has changed, and report the published Cloudflare ranges read from disk without requesting them; writes nothing and takes no lock. It cannot publish a missing prefix list: that is what --refresh-ranges is for")
	pinRemote := flags.String("pin-remote", "", "publish the named commit: HEAD for the current reviewed default-branch commit, or a full 40-character commit to publish that one instead -- which is how a pin accepted by mistake is undone")
	refreshRanges := flags.Bool("refresh-ranges", false, "fetch the published Cloudflare ranges and publish their prefix list; measures nothing and spends no bandwidth budget, so it is the mode an installation runs before the router starts")
	sourceLock := flags.String("source-lock", defaultSourceLockPath, "path to the source lock")
	listFile := flags.String("list-file", defaultListFilePath, "path to the converted list")
	previousLock := flags.String("previous-lock", defaultPreviousLockPath, "path the outgoing pin is archived to before a new one replaces it, so a pin accepted by mistake can be published again")
	controlLock := flags.String("control-lock", defaultControlLockPath, "path to the shared control lock")
	rangesURL := flags.String("ranges-url", candidate.DefaultCloudflareBaseURL, "the published Cloudflare range document")
	rangesCache := flags.String("ranges-cache", candidate.DefaultCloudflareCachePath, "where the published range document is cached; its prefix list is written beside it")
	pinnedRanges := flags.String("pinned-ranges", candidate.DefaultPinnedSnapshotPath, "the range document snapshot this package ships, published when the origin cannot be read and this machine has published none of its own; a snapshot that does not verify is a refusal")
	pinnedRangesLock := flags.String("pinned-ranges-lock", candidate.DefaultPinnedSnapshotLockPath, "the lock that accounts for the pinned snapshot: its endpoint, its revision, when it was taken, and the two digests of it")
	if err := flags.Parse(args); err != nil {
		return updateListOptions{}, err
	}
	if flags.NArg() != 0 {
		return updateListOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	modes := 0
	for _, selected := range []bool{*automatic, *check, *pinRemote != "", *refreshRanges} {
		if selected {
			modes++
		}
	}
	switch {
	case modes == 0:
		return updateListOptions{}, errors.New("one of --automatic, --check, --pin-remote HEAD or --refresh-ranges is required")
	case modes > 1:
		return updateListOptions{}, errors.New("--automatic, --check, --pin-remote and --refresh-ranges are mutually exclusive")
	}
	// HEAD is normalized to the empty string here rather than carried, so there is
	// one question in the code -- "which commit did the caller name?" -- instead of a
	// literal compared in the parser and a different assumption in the runner.
	selectedPin := strings.TrimSpace(*pinRemote)
	if selectedPin == pinRef {
		selectedPin = ""
	}
	if selectedPin != "" && !isFullCommit(selectedPin) {
		return updateListOptions{}, fmt.Errorf("--pin-remote accepts %s or a full 40-character commit, not %q",
			pinRef, selectedPin)
	}
	for _, path := range []struct{ name, value string }{
		{"--policy", *policy},
		{"--source-lock", *sourceLock},
		{"--list-file", *listFile},
		{"--previous-lock", *previousLock},
		{"--control-lock", *controlLock},
		{"--ranges-url", *rangesURL},
		{"--ranges-cache", *rangesCache},
		{"--pinned-ranges", *pinnedRanges},
		{"--pinned-ranges-lock", *pinnedRangesLock},
	} {
		if strings.TrimSpace(path.value) == "" {
			return updateListOptions{}, fmt.Errorf("%s must not be empty", path.name)
		}
	}
	return updateListOptions{
		check:            *check,
		automatic:        *automatic,
		policy:           *policy,
		pinRemote:        selectedPin,
		refreshRanges:    *refreshRanges,
		sourceLock:       *sourceLock,
		listFile:         *listFile,
		previousLock:     *previousLock,
		controlLock:      *controlLock,
		rangesURL:        *rangesURL,
		rangesCache:      *rangesCache,
		pinnedRanges:     *pinnedRanges,
		pinnedRangesLock: *pinnedRangesLock,
	}, nil
}

// isFullCommit reports whether ref is a complete commit id: forty lower-case hex
// characters, nothing shorter and nothing longer.
//
// Lower case because that is what ParseSourceLock requires of a lock's commit and
// therefore what a lock carrying this string can be read back as. Accepting an
// abbreviation would mean accepting a string no lock in this package can hold.
func isFullCommit(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for index := 0; index < len(ref); index++ {
		if !strings.ContainsRune("0123456789abcdef", rune(ref[index])) {
			return false
		}
	}
	return true
}

func runUpdateLists(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
	// The flag set writes its own diagnostics to stderr rather than discarding
	// them, so `-h` reaches the operator. The usage goes to stderr and not stdout
	// because `-h` is a usage error here: it names no mode, and every mode in this
	// command either writes or reaches the network.
	options, err := parseUpdateListOptions(stderr, args)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitInvalidCLI
	}
	switch {
	case options.automatic:
		return runAutomaticLists(ctx, options, stdout, stderr, services)
	case options.check:
		return runCheckLists(ctx, options, stdout, stderr, services)
	case options.refreshRanges:
		return runRefreshRanges(ctx, options, stdout, stderr, services)
	default:
		return runPinRemote(ctx, options, stdout, stderr, services)
	}
}

// runCheckLists reports whether the source the gateway runs on is still the one
// the remote publishes. It writes nothing and takes no lock, so a daily check
// never disturbs a running gateway. The report is assembled first and written
// only once it is complete, so a check that fails half way through says so
// instead of leaving a partial report behind.
//
// The published pair is read without the control lock, deliberately. Holding the
// lock is what a pin does, and a pin on the same host is a handful of writes; a
// daily check that took the lock would have to either block that pin or be
// skipped whenever anything else was publishing, so it would stop being the
// check an operator can run at any time. The consequence of reading unlocked is
// that a check can observe a half-applied pair, and it is fail-closed about
// that: ReadPublishedPair refuses a pair whose list and lock do not describe each
// other, the check reports the refusal on stderr and exits 3, and it never
// concludes "up-to-date" from a pair it could not verify. A transient exit 3 is
// the correct answer for a check that caught a publication in flight.
func runCheckLists(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
	published, _, found, err := rules.ReadPublishedPair(options.sourceLock, options.listFile)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	if !found {
		writeCLIError(stderr, "update-lists: no pinned China domain list at %s, nothing to compare against; pin one with update-lists --pin-remote HEAD", options.sourceLock)
		return exitStateUnavailable
	}

	client := services.newHTTPClient()
	var report bytes.Buffer
	writeReportLine(&report, "repository: %s\n", published.Repository)
	writeReportLine(&report, "entry: %s\n", published.Entry)
	writeReportLine(&report, "locked-commit: %s\n", published.Commit)
	writeReportLine(&report, "locked-archive-sha256: %s\n", published.SHA256)
	writeReportLine(&report, "locked-list-sha256: %s\n", published.ListSHA256)

	// The Cloudflare ranges are reported here, in the same report, and they cost
	// no request: ReadPublished reads the two artifacts off the disk and says
	// whether they are there and whether they agree. The check already makes a
	// request for the China list's sake, and a report that reached a third origin
	// to say "the file is there" would be a request whose only effect is to be
	// able to fail -- and a daily timer acting on this report would then fail on
	// an API outage while the files it is reporting about are perfectly fine.
	reportRanges(&report, options, services.now())

	remote, err := rules.ResolveCommit(ctx, client, rules.Repository, "")
	if err != nil {
		// The half of this report that was read off the disk goes out on the
		// failure path, and this is why. It needed no request, and the machine
		// this project makes installable without a route to the internet is
		// precisely the machine on which the request above cannot be made: a daily
		// timer acting on this report would otherwise say only "the China source
		// could not be read" there, forever, and the one snapshot the package
		// ships would never be measured at all.
		//
		// It goes to STDERR and stdout stays empty, because the property this
		// command already holds -- stdout carries a complete answer or nothing --
		// is what stops a reader treating half a report as a verdict. The status is
		// the one it always was: the check could not do its job.
		_, _ = stderr.Write([]byte("update-lists: " + err.Error() + "\n" +
			"update-lists: what was read from the disk, which did not depend on that request:\n"))
		_, _ = stderr.Write(report.Bytes())
		return exitStateUnavailable
	}
	writeReportLine(&report, "remote-commit: %s\n", remote.Commit)

	if remote.Commit == published.Commit {
		// The remote still publishes the commit the list was converted from, so
		// the archive is not fetched at all.
		writeReportLine(&report, "up-to-date: true\n")
		return writeReport(stdout, stderr, report.Bytes())
	}
	// The remote has moved on. The archive is read in memory only to report the
	// digest the new pin would record; nothing is accepted here.
	drifted, err := rules.ResolveHEAD(ctx, client, rules.Repository)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	writeReportLine(&report, "remote-archive-sha256: %s\n", drifted.SHA256)
	writeReportLine(&report, "up-to-date: false\n")
	return writeReport(stdout, stderr, report.Bytes())
}

// reportRanges writes what the two published range artifacts currently hold into
// a check's report.
//
// It is deliberately separate from the China half and deliberately silent about
// the origin. The China half answers "has the source this gateway runs on moved",
// which is a question only the origin can answer; the ranges half answers "is the
// file the rewriter refuses to start without actually there, and does it still
// describe the envelope beside it", which is a question the disk answers. A check
// that fetched the ranges to compare them would publish nothing -- it is
// report-only -- so the request would buy a fresh number nobody stores and a new
// way for a daily timer to fail.
//
// The absence of a prefix list is reported rather than treated as a failure. It is
// a fact about the installation, not about the check's ability to do its job, and the
// check still exits 0 on drift per ruling 50; a reader that wants a refusal
// asks for one with `update-lists --refresh-ranges`, which is the only command
// here that writes.
//
// The pin the package ships is reported in the same breath, and it is the second
// half of what this report exists for. The published artifacts answer "is the
// file the rewriter refuses to start without actually there"; the pin answers
// "how old is the artefact this package was built with, and is what is published
// still the same document", which is a question with a silent wrong answer -- a
// machine that has been reinstalled from the same package for a year looks
// exactly like a healthy one.
func reportRanges(report *bytes.Buffer, options updateListOptions, now time.Time) {
	published, err := candidate.ReadPublished(options.rangesCache)
	if err != nil {
		// A path that cannot be read at all is a question this report cannot
		// answer, and it is stated as one rather than as an absence.
		writeReportLine(report, "ranges-unreadable: %v\n", err)
		reportPinDrift(report, options, now, candidate.PublishedRanges{})
		return
	}
	writeReportLine(report, "ranges-cache: %s\n", published.CachePath)
	writeReportLine(report, "ranges-prefix-list: %s\n", published.PrefixPath)
	writeReportLine(report, "ranges-published: %t\n", published.Present)
	if !published.Present {
		writeReportLine(report, "ranges-missing: %s\n", published.Missing)
		reportPinDrift(report, options, now, published)
		return
	}
	writeReportLine(report, "ranges-consistent: %t\n", published.Consistent)
	writeReportLine(report, "ranges-prefixes: %d\n", published.Prefixes)
	writeReportLine(report, "ranges-prefix-list-sha256: %s\n", published.SHA256)
	writeReportLine(report, "ranges-published-document-sha256: %s\n", published.DocumentSHA256)
	reportPinDrift(report, options, now, published)
}

// reportPinDrift states what the package's shipped snapshot holds, how old it is,
// and whether the document this machine published is the same one.
//
// The comparison is between the two documents' own digests rather than between
// the published prefix list and a rendered copy of the pin, because the published
// list is a rendering of the envelope beside it and the question is which
// document that envelope holds. A machine that refreshed its ranges online reports
// drift from the package's pin, and that is the healthy case: it has today's
// ranges and the package carries an older snapshot. Reporting it as the same
// would be the false claim that a re-pin had happened.
//
// An unusable pin gets no drift line at all rather than a `false` one. There is
// nothing to compare against, and a report that said "no drift" about a snapshot
// it could not read would be the one report an operator would act on by mistake.
func reportPinDrift(report *bytes.Buffer, options updateListOptions, now time.Time, published candidate.PublishedRanges) {
	paths := candidate.PinnedSnapshotPaths{Snapshot: options.pinnedRanges, Lock: options.pinnedRangesLock}
	writeReportLine(report, "ranges-pin: %s\n", paths.Snapshot)
	writeReportLine(report, "ranges-pin-lock: %s\n", paths.Lock)
	pin, err := candidate.ReadPinnedSnapshot(paths)
	if err != nil {
		writeReportLine(report, "ranges-pin-verified: false\n")
		writeReportLine(report, "ranges-pin-unusable: %v\n", err)
		return
	}
	writeReportLine(report, "ranges-pin-verified: true\n")
	writeReportLine(report, "ranges-pin-source: %s\n", pin.Source)
	writeReportLine(report, "ranges-pin-sha256: %s\n", pin.SHA256)
	writeReportLine(report, "ranges-pin-revision: %s\n", pin.Revision)
	writeReportLine(report, "ranges-pin-pinned-at: %s\n", pin.FetchedAt.UTC().Format(time.RFC3339))
	writeReportLine(report, "ranges-pin-age: %s\n", pinAge(now, pin.FetchedAt))
	writeReportLine(report, "ranges-pin-prefixes: %d\n", pin.Prefixes)
	writeReportLine(report, "ranges-pin-prefix-list-sha256: %s\n", pin.PrefixListSHA256)
	writeReportLine(report, "ranges-pin-document-sha256: %s\n", digestOfDocument(pin.Body))
	if !published.Present {
		// Nothing is published, so there is no drift to measure and no document
		// to drift from. The pin is still reported, because its age is the fact an
		// operator has to be able to see.
		return
	}
	if published.DocumentSHA256 == digestOfDocument(pin.Body) {
		writeReportLine(report, "ranges-pin-drift: none\n")
		return
	}
	writeReportLine(report, "ranges-pin-drift: published-differs\n")
}

// digestOfDocument is the digest of a range document's own bytes, which is what
// two documents are compared by. The two sides of a drift comparison have to be
// digested the same way or the comparison is a coin toss, and one of them is
// digested inside internal/candidate, so the function is named here rather than
// reached for: the alternative is a report comparing a body against a re-encoding
// of itself and calling the result no drift.
func digestOfDocument(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// runPinRemote accepts the current reviewed default-branch commit and publishes
// the list and the lock that describes it.
//
// The download and the conversion happen before the control lock is taken, so a
// slow origin never keeps the router's control operations out. Under the lock
// the published pair is read again, so a pair that changed or was broken while
// the download was in flight is refused rather than overwritten, and only then is
// the new pair written.
// runAutomaticLists is the mode a scheduled run uses. It is a mode of its own rather
// than a flag on --check because the two may do different things: this one writes,
// that one documents that it writes nothing.
//
// The order is the design. The drift report is produced first and unconditionally,
// because it is the only place this machine's answer about its own source is written
// down, and a machine that has turned unattended refreshing on must not thereby stop
// being told. Then exactly what the policy says to refresh is refreshed, which by
// default is nothing at all: with both switches off this function does precisely what
// --check did, so turning the feature on and off changes the configuration rather than
// the machine.
// ruleCount renders a rule count as the sentence an operator reads, with the plural
// right. It is here rather than inline because the refusal is quoted in a man page and
// a message that says "1 rules" is a message nobody believes.
func ruleCount(count int) string {
	if count == 1 {
		return "1 rule"
	}
	return fmt.Sprintf("%d rules", count)
}

func runAutomaticLists(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
	// Loaded before anything is fetched, and refused before anything is written. The
	// policy is what says whether to refresh, so a run that could not read it has no
	// business resolving a commit -- and a policy that does not parse is an operator
	// typo, not a condition to refresh anyway with the old settings.
	policy, err := config.Load(options.policy)
	if err != nil {
		writeCLIError(stderr, "update-lists --automatic: %v", err)
		return exitInvalidCLI
	}

	if code := runCheckLists(ctx, options, stdout, stderr, services); code != exitSuccess {
		return code
	}
	if policy.Lists.China.Automatic {
		if code := refreshChinaList(ctx, options, stdout, stderr, services); code != exitSuccess {
			return code
		}
	}
	if policy.Lists.Cloudflare.Automatic {
		refreshed := options
		refreshed.refreshRanges = true
		if code := runRefreshRanges(ctx, refreshed, stdout, stderr, services); code != exitSuccess {
			return code
		}
	}
	return exitSuccess
}

// refreshChinaList re-pins the China list unattended, and refuses a list that has
// collapsed.
//
// The digest cannot catch this. An upstream commit whose data/cn is a fraction of its
// former size verifies perfectly, because it really is the upstream document -- what
// it changes is how many names take the foreign branch, and nobody reviewed that. So a
// collapse is refused, loudly, with both counts in the message, and nothing is
// written: publishing that commit afterwards is then one deliberate command an
// operator runs having read the diff.
//
// The threshold is 95% retained. A hand-curated list does lose domains now and then,
// and a guard that trips on that is a guard that means never updating -- which is the
// same as leaving the switch off, with more machinery and a false promise.
//
// Everything that can fail happens before anything is written: the pair is read, the
// remote is resolved, the archive is fetched and converted, and only then is the size
// compared. A machine with no route out therefore fails without having touched the
// pin, the list, or the rollback archive.
func refreshChinaList(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
	// Retained as a fraction of the published rule count. It is a fraction and not a
	// difference because a list of 8000 rules and a list of 200 are not comparable by
	// subtraction, and a fixed count would refuse the second for the wrong reason.
	const minimumRetained = 0.95

	pinned, current, _, err := rules.ReadPublishedPair(options.sourceLock, options.listFile)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	published := countListRules(current)

	client := services.newHTTPClient()
	resolved, err := rules.ResolveHEAD(ctx, client, rules.Repository)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	if resolved.Commit == pinned.Commit {
		// Already there. Nothing to do and nothing to say beyond the fact, because
		// re-downloading and re-publishing an identical commit is how a daily job
		// turns a no-op into wear on the disk the machine is running from.
		writeReportLine(stdout, "china-list: already at %s\n", pinned.Commit)
		return exitSuccess
	}
	_, list, err := rules.Download(ctx, client, resolved)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}

	incoming := countListRules(list)
	if published > 0 && float64(incoming) < float64(published)*minimumRetained {
		writeCLIError(stderr,
			"update-lists: refusing %s: it has %s where the published list has %s -- "+
				"fewer rules than a curated list loses in one commit, which is a mistake "+
				"upstream made rather than a change anybody reviewed here. Nothing was changed. "+
				"Read the diff, then publish that commit deliberately with "+
				"`mosdns-cdnctl update-lists --pin-remote %s`.",
			resolved.Commit, ruleCount(incoming), ruleCount(published), resolved.Commit)
		return exitStateUnavailable
	}

	// Publish the commit that was MEASURED, not whatever HEAD has become since. This
	// is the whole reason the guard is not advisory: re-resolving here would mean the
	// size check applied to one commit and the publication applied to another, so
	// upstream moving during the run would publish an unmeasured list through the
	// mechanism built to prevent exactly that.
	pinned_ := options
	pinned_.pinRemote = resolved.Commit
	return runPinRemote(ctx, pinned_, stdout, stderr, services)
}

func runPinRemote(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
	client := services.newHTTPClient()
	// No option means HEAD, and HEAD means the repository's current default-branch
	// commit. A 40-character commit means that commit, which is how a pin accepted by
	// mistake is undone: the rollback has to be able to name where it is going back
	// to, and "whatever upstream says now" is not an answer to that question.
	resolved, err := rules.ResolvePinned(ctx, client, rules.Repository, options.pinRemote)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	pinned, list, err := rules.Download(ctx, client, resolved)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}

	release, err := services.acquireLock(options.controlLock)
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			writeCLIError(stderr, "update-lists: %s: the control lock is held, not publishing %s", options.controlLock, resolved.Commit)
			return exitLockHeld
		}
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	defer func() { _ = release() }()

	if _, _, _, err := rules.ReadPublishedPair(options.sourceLock, options.listFile); err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	// Archived before the publish and replaced by it, and the order is the mechanism:
	// once the new lock is renamed into place the old one no longer exists anywhere,
	// so an archive taken afterwards records the commit that was just accepted rather
	// than the one this machine was on. Taken before, a publish that fails leaves an
	// archive naming a commit that really was current -- the one an operator
	// recovering from a failed unattended refresh needs.
	//
	// A failure here stops the pin rather than being warned about. Publishing without
	// an archive is the one outcome this cannot be recovered from: the rollback target
	// is destroyed by the very operation that needed it.
	if err := rules.Archive(options.previousLock, options.sourceLock); err != nil {
		writeCLIError(stderr, "update-lists: archive the outgoing pin, so publishing would leave "+
			"no way back: %v", err)
		return exitStateUnavailable
	}
	if err := rules.Publish(options.sourceLock, options.listFile, pinned, list); err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}

	writeReportLine(stdout, "pinned-commit: %s\n", pinned.Commit)
	writeReportLine(stdout, "pinned-archive-sha256: %s\n", pinned.SHA256)
	writeReportLine(stdout, "pinned-list-sha256: %s\n", pinned.ListSHA256)
	writeReportLine(stdout, "pinned-rules: %d\n", countListRules(list))
	writeReportLine(stdout, "published-source-lock: %s\n", options.sourceLock)
	writeReportLine(stdout, "archived-previous-source-lock: %s\n", options.previousLock)
	writeReportLine(stdout, "published-list: %s\n", options.listFile)
	return exitSuccess
}

// runRefreshRanges publishes the response rewriter's prefix list, and nothing
// else. It is the mode a package installation runs before the router starts,
// because the rewriter refuses to construct without that list and the only
// producer it had was a measurement run that spends the day's bandwidth budget.
//
// What it does not do is the part that makes it safe to run at install time. It
// builds no prober, opens no socket to a candidate address, and never constructs
// an optimizer Runner, so there is no measurement and no budget charge: a fresh
// installation cannot starve the first nightly with a file it needs before the
// nightly exists. The single HTTP request it makes is the range document itself,
// and the two files it writes -- the cache envelope and the prefix list beside it
// -- are both rendered from that one in-memory document, so they cannot describe
// different days. internal/candidate holds that: Refresh is the fetch half of
// Candidates with the sampling removed, sharing the read and the publication.
//
// It takes no control lock. The two files are each replaced by a same-directory
// temporary and a rename, so a reader never sees half of one, and a lock held
// across a network request would keep the router's own control operations out
// while an origin is slow. It also touches nothing the China list owns: a
// separate mode rather than a flag is what keeps an install from re-pinning that
// list, which ruling 59 forbids.
//
// The snapshot the package ships is the fourth thing this mode consults, and it
// is the last: the origin, then the document this machine published before, then
// the pair `/usr/share/mosdns-router` carries. That order is the China list's, and
// it is why a `dpkg` upgrade on an offline machine keeps the ranges its selector
// was built against while a fresh one gets a working install instead of a
// refusal. A snapshot that does not verify is not published and is not warned
// about: it is a refusal, because the only alternative is a selector over ranges
// this project cannot account for.
func runRefreshRanges(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
	source, err := candidate.NewCloudflareSourceWithPin(
		services.newHTTPClient(), options.rangesURL, options.rangesCache,
		candidate.PinnedSnapshotPaths{Snapshot: options.pinnedRanges, Lock: options.pinnedRangesLock},
	)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitInvalidCLI
	}
	refreshed, err := source.Refresh(ctx)
	if err != nil {
		// Nothing is reported on failure, because nothing was published: a report
		// naming a file that is not there is how an installer concludes it has the
		// prefix list when the router will refuse to start without it.
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	writeReportLine(stdout, "ranges-url: %s\n", refreshed.URL)
	writeReportLine(stdout, "ranges-etag: %s\n", refreshed.ETag)
	writeReportLine(stdout, "ranges-prefixes: %d\n", refreshed.Prefixes)
	// The stale flag is what tells an operator the ranges are the last ones this
	// build accepted rather than the ones the origin publishes today, and a
	// router that starts on a stale list is a router classifying against
	// yesterday's space.
	writeReportLine(stdout, "ranges-stale: %t\n", refreshed.Stale)
	// Which of the three documents answered, because "stale" alone cannot tell a
	// machine three days old from a machine that has been installing from the same
	// package copy for a year. The two are different states with different
	// remedies: one is a timer that has not run, the other is a package whose pin
	// nobody has refreshed.
	writeReportLine(stdout, "ranges-source: %s\n", documentSource(refreshed))
	if refreshed.Pinned {
		reportPin(stdout, refreshed.Pin, services.now())
	}
	writeReportLine(stdout, "published-ranges-cache: %s\n", refreshed.CachePath)
	writeReportLine(stdout, "published-prefix-list: %s\n", refreshed.PrefixPath)
	return exitSuccess
}

// documentSource names which of the three places a published document came from.
func documentSource(refreshed candidate.RangeRefresh) string {
	switch {
	case refreshed.Pinned:
		return "pinned-snapshot"
	case refreshed.Stale:
		return "cache"
	default:
		return "origin"
	}
}

// reportPin states what a package's shipped snapshot holds and how old it is.
//
// The age is the whole reason this function exists. A three-month-old pin is a
// perfectly good input for a selector, and a pin nobody measures the age of is
// not: it is the difference between a stale artefact an operator can decide
// about and a stale artefact that is simply how the machine has always been. It
// is computed from the command's own clock rather than a wall clock read here, so
// every timestamp in one report is one reading.
func reportPin(output io.Writer, pin candidate.PinnedSnapshot, now time.Time) {
	writeReportLine(output, "ranges-pinned-snapshot: %s\n", pin.SnapshotPath)
	writeReportLine(output, "ranges-pinned-lock: %s\n", pin.LockPath)
	writeReportLine(output, "ranges-pinned-sha256: %s\n", pin.SHA256)
	writeReportLine(output, "ranges-pinned-revision: %s\n", pin.Revision)
	writeReportLine(output, "ranges-pinned-at: %s\n", pin.FetchedAt.UTC().Format(time.RFC3339))
	writeReportLine(output, "ranges-pinned-age: %s\n", pinAge(now, pin.FetchedAt))
	writeReportLine(output, "ranges-pinned-prefixes: %d\n", pin.Prefixes)
	writeReportLine(output, "ranges-pinned-prefix-list-sha256: %s\n", pin.PrefixListSHA256)
}

// pinAge is how long ago a pin was taken, and never negative: a pin whose
// recorded time is in the future is a lock with a wrong date in it, and reporting
// a negative age would be a way of saying so that reads like a measurement. The
// zero is the whole answer instead, and the date beside it is what an operator
// has to look at.
func pinAge(now, taken time.Time) time.Duration {
	if age := now.Sub(taken); age > 0 {
		return age
	}
	return 0
}

// countListRules counts the expressions of a published list, which is the number
// of rules a pin added to the router's China set.
func countListRules(list []byte) int {
	if len(list) == 0 {
		return 0
	}
	lines := strings.Split(strings.TrimSuffix(string(list), "\n"), "\n")
	return len(lines)
}

// writeReportLine appends one line of a report.
func writeReportLine(output io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(output, format, args...)
}

// writeReport hands a complete report to the caller's output.
func writeReport(stdout, stderr io.Writer, report []byte) int {
	if _, err := stdout.Write(report); err != nil {
		writeCLIError(stderr, "update-lists: write report: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}
