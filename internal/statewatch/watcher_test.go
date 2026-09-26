package statewatch

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"mosdns-router/internal/state"
)

// The tests in this file are about the router's ability to keep serving while
// the files it serves from are being replaced underneath it. Every document a
// producer publishes here is written by hand, field for field, and every
// expectation is a literal rather than a value the code under test produced, so
// a case that passes says the watcher handed back the document the producer
// published and not something it invented.
//
// Two properties run through every case:
//
//   - A file the watcher cannot read leaves the LAST VALID snapshot in place.
//     A router serving a stale selector is recoverable; a router serving a zero
//     selector, or one that has stopped, is not.
//   - A value handed to a caller shares no mutable reference with the watcher's
//     own copy, so a plugin that edits what it was given cannot change what the
//     next query reads.
//
// Every case that waits for a background reload injects its own poll interval,
// so none of them waits half a second. The shipped default is asserted once, in
// TestWatchersUseTheDocumentedPollIntervalWhenGivenNoOptions.

const (
	// fastPoll is the interval the cases below inject. It is short enough that a
	// reload lands inside a test and long enough that a case which writes twice
	// can still make both writes land between two ticks.
	fastPoll = 5 * time.Millisecond
	// idlePoll is long enough that a case which must observe exactly one read
	// will not see a second one while it runs.
	idlePoll = time.Hour
	// waitLimit bounds every wait for a background reload. It is generous
	// because a race-enabled run of this package is slow, not because any case
	// should take that long.
	waitLimit = 3 * time.Second
)

// observedAt is the moment the fixtures below were taken. Every timestamp in
// every fixture is written relative to it rather than to time.Now, so a
// document is byte-identical from one run to the next.
var observedAt = time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)

// fixtureDigest is a well-formed lowercase SHA-256 digest. state refuses a
// selector carrying anything else, so a fixture with a truncated one would be
// testing the schema rather than the watcher.
const fixtureDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// publishedSelector is the selector a producer publishes for a generation: one
// winner, one fallback, one CloudFront mapping, and a proof window ten minutes
// past the observation that earned it. The winner is an argument so a case can
// publish two generations that differ in more than their number.
func publishedSelector(generation uint64, winnerIP string) state.Selector {
	return state.Selector{
		SchemaVersion:    state.SchemaVersion,
		Generation:       generation,
		Mode:             "auto",
		Provider:         "cloudflare",
		WinnerIP:         winnerIP,
		WinnerProofUntil: observedAt.Add(10 * time.Minute),
		FallbackIP:       "198.51.100.9",
		CloudFront:       map[string]string{"d2abcdef.cloudfront.net": "13.32.99.10"},
		LastSuccess:      observedAt,
		ConfigSHA256:     fixtureDigest,
	}
}

// publishedDHCP is a last-known-good upstream set with two addresses in it,
// which is what makes the slice in it worth isolating.
func publishedDHCP(generation uint64) state.DHCPState {
	return state.DHCPState{
		SchemaVersion:  state.SchemaVersion,
		Generation:     generation,
		Interface:      "eth0",
		ConnectionUUID: "5f2b9c40-1d3e-4a7b-9c51-8e6d0a2b3c4d",
		Upstreams:      []string{"1.1.1.1", "8.8.8.8"},
		ObservedAt:     observedAt,
		Source:         "dhcp4",
		LastGood:       true,
	}
}

func publishedECH(generation uint64) state.ECHState {
	return state.ECHState{
		SchemaVersion: state.SchemaVersion,
		Generation:    generation,
		Source:        "cloudflare.com",
		FetchedAt:     observedAt,
		ExpiresAt:     observedAt.Add(24 * time.Hour),
		StaleUntil:    observedAt.Add(48 * time.Hour),
		ConfigSHA256:  fixtureDigest,
		PublicName:    "cloudflare-ech.com",
		Status:        "fresh",
	}
}

func publishedBudget() state.BandwidthBudgetState {
	return state.BandwidthBudgetState{
		SchemaVersion: state.SchemaVersion,
		LocalDate:     "2026-09-25",
		LimitBytes:    1 << 30,
		UsedBytes:     1 << 20,
	}
}

func publishedHealth() state.HealthState {
	return state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		Healthy:             true,
		ConsecutiveFailures: 0,
		LastSuccess:         observedAt,
	}
}

// selectorEqual reports whether two selectors are the same document, field for
// field. A struct carrying a map cannot be compared with == at all, so a caller
// that wants to know whether the document it was handed is the one it published
// has to walk the fields -- and so does this test.
func selectorEqual(got, want state.Selector) bool {
	if got.SchemaVersion != want.SchemaVersion ||
		got.Generation != want.Generation ||
		got.Mode != want.Mode ||
		got.Provider != want.Provider ||
		got.WinnerIP != want.WinnerIP ||
		!got.WinnerProofUntil.Equal(want.WinnerProofUntil) ||
		got.FallbackIP != want.FallbackIP ||
		!got.LastSuccess.Equal(want.LastSuccess) ||
		got.LastFailure != want.LastFailure ||
		got.ConfigSHA256 != want.ConfigSHA256 {
		return false
	}
	return maps.Equal(got.CloudFront, want.CloudFront)
}

// dhcpEqual is selectorEqual's counterpart for a record carrying a slice.
func dhcpEqual(got, want state.DHCPState) bool {
	return got.SchemaVersion == want.SchemaVersion &&
		got.Generation == want.Generation &&
		got.Interface == want.Interface &&
		got.ConnectionUUID == want.ConnectionUUID &&
		got.ObservedAt.Equal(want.ObservedAt) &&
		got.Source == want.Source &&
		got.LastGood == want.LastGood &&
		slices.Equal(got.Upstreams, want.Upstreams)
}

// documentBytes encodes a published document the way a producer's writer does:
// indented JSON with a trailing newline. It is a serialiser, not a fixture
// builder -- the fields came from the literals above -- so the bytes are a
// faithful copy of a document this file wrote by hand.
func documentBytes(t *testing.T, document any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode published document: %v", err)
	}
	return append(encoded, '\n')
}

// replaceFile publishes data at path the way every producer in this project
// does: a same-directory temporary file, then a rename over the target. A
// reader therefore never sees half a document, which is the assumption the
// watcher is allowed to make.
func replaceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := publish(path, data); err != nil {
		t.Fatalf("publish over %s: %v", path, err)
	}
}

// publish is replaceFile without a testing.T, for a producer running on its own
// goroutine. FailNow may only be called from the test's own goroutine, so the
// goroutine has to carry its failure out as an error.
func publish(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".fixture-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// statePath returns a path inside a temporary directory that nothing has
// written yet, so a case that needs a missing file has one.
func statePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// watch builds a JSON watcher that a case can Close, and fails the case if the
// construction itself was refused.
func watch[T Document](t *testing.T, path string, initial T, options ...Options) *Watcher[T] {
	t.Helper()
	watcher, err := NewJSON(path, nil, initial, options...)
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	return watcher
}

// watchText builds a text watcher that a case can Close.
func watchText(t *testing.T, path string, initial []string, options ...Options) *TextWatcher {
	t.Helper()
	watcher, err := NewTrimmedLines(path, initial, options...)
	if err != nil {
		t.Fatalf("NewTrimmedLines(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	return watcher
}

// waitFor blocks until a condition holds, and fails the case naming what it was
// waiting for rather than hanging until the package timeout.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waited %s for %s and it never happened", waitLimit, what)
}

// refusals collects what a watcher's error handler was told, so a case can ask
// both what was said and how often without racing the poll goroutine.
type refusals struct {
	mu   sync.Mutex
	seen []error
}

func (r *refusals) record(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, err)
}

func (r *refusals) all() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.seen...)
}

func (r *refusals) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

// reloadGate is a caller check that can hold one reload inside the watcher until
// the test releases it, so Close can be called while a poll is in flight, and so
// a second read can be made to finish first. It passes everything until it is
// armed, and after being armed it holds exactly one read: the one the test wants
// parked, leaving the reads that follow it to run.
type reloadGate struct {
	mu      sync.Mutex
	armed   bool
	held    bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newReloadGate() *reloadGate {
	return &reloadGate{
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
}

func (g *reloadGate) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = true
}

// pass holds the first read that reaches the gate after it is armed, and returns
// immediately for every other one.
func (g *reloadGate) pass(state.Selector) error {
	g.mu.Lock()
	hold := g.armed && !g.held
	if hold {
		g.held = true
	}
	g.mu.Unlock()
	if !hold {
		return nil
	}
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return nil
}

func (g *reloadGate) open() {
	g.once.Do(func() { close(g.release) })
}

// errCallerRefusal is the check a caller adds on top of the state's own
// validation. errors.Is finds it, so a case can prove WHICH door refused a
// document rather than only that something did.
var errCallerRefusal = errors.New("the caller refuses a cloudfront selector")

func refuseCloudfront(selector state.Selector) error {
	if selector.Provider == "cloudfront" {
		return errCallerRefusal
	}
	return nil
}

// corruptMode returns a published selector with one byte of its mode changed, so
// the result is the same length as the document it came from and no validator
// can accept it.
func corruptMode(t *testing.T, selector state.Selector) []byte {
	t.Helper()
	document := documentBytes(t, selector)
	index := strings.Index(string(document), `"auto"`)
	if index < 0 {
		t.Fatalf("the fixture does not contain a mode to corrupt: %s", document)
	}
	corrupted := append([]byte(nil), document...)
	copy(corrupted[index:], `"aut0"`)
	return corrupted
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// TestWatchersRefuseAPathNoFileCanEverLiveAt covers both constructors. A
// watcher with no path would poll nothing and serve its initial value for the
// life of the process, which is indistinguishable from a healthy router whose
// selector has simply never changed.
func TestWatchersRefuseAPathNoFileCanEverLiveAt(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		if _, err := NewJSON("", nil, publishedSelector(1, "198.51.100.7")); err == nil {
			t.Fatal("NewJSON accepted an empty path, so the watcher would poll nothing and serve its initial value forever")
		}
	})
	t.Run("text", func(t *testing.T) {
		if _, err := NewTrimmedLines("", nil); err == nil {
			t.Fatal("NewTrimmedLines accepted an empty path, so the watcher would poll nothing and serve its initial list forever")
		}
	})
}

// TestWatchersRefuseANegativePollInterval covers both constructors. A negative
// interval is not a slower poll: it is time.NewTicker's panic, and it would
// arrive inside the poll goroutine after the router had already started.
func TestWatchersRefuseANegativePollInterval(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		_, err := NewJSON(statePath(t, "selector.json"), nil, publishedSelector(1, "198.51.100.7"),
			Options{PollInterval: -time.Millisecond})
		if err == nil {
			t.Fatal("NewJSON accepted a negative poll interval, which reaches time.NewTicker as a panic")
		}
	})
	t.Run("text", func(t *testing.T) {
		_, err := NewTrimmedLines(statePath(t, "force-ech-domains.txt"), nil,
			Options{PollInterval: -time.Millisecond})
		if err == nil {
			t.Fatal("NewTrimmedLines accepted a negative poll interval, which reaches time.NewTicker as a panic")
		}
	})
}

// TestWatchersRefuseASecondOptionsValue covers both constructors. One Options
// is the whole of the optional argument, so a caller that passes two is a
// mistake -- and honouring the first or the last of them silently would leave a
// caller with a poll rate it did not ask for.
func TestWatchersRefuseASecondOptionsValue(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		_, err := NewJSON(statePath(t, "selector.json"), nil, publishedSelector(1, "198.51.100.7"),
			Options{PollInterval: fastPoll}, Options{PollInterval: idlePoll})
		if err == nil {
			t.Fatal("NewJSON accepted two Options values, so one of the two poll rates the caller asked for was quietly dropped")
		}
	})
	t.Run("text", func(t *testing.T) {
		_, err := NewTrimmedLines(statePath(t, "force-ech-domains.txt"), nil,
			Options{PollInterval: fastPoll}, Options{PollInterval: idlePoll})
		if err == nil {
			t.Fatal("NewTrimmedLines accepted two Options values, so one of the two poll rates the caller asked for was quietly dropped")
		}
	})
}

// TestACallerRepairClearsTheEpisodeSoTheNextBreakIsReported: an operator who
// fixes the file themselves and then breaks it again has to hear about the second
// time. The file is broken now and nothing else will say so, and the message the
// poll would send is byte for byte the one it already sent, so a repair that does
// not end the episode leaves the router reporting nothing for a file that is
// broken.
func TestACallerRepairClearsTheEpisodeSoTheNextBreakIsReported(t *testing.T) {
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, publishedSelector(1, "198.51.100.7")))
	refused := &refusals{}
	watcher, err := NewJSON(path, nil, state.Selector{},
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	corrupt := corruptMode(t, publishedSelector(2, "203.0.113.8"))
	replaceFile(t, path, corrupt)
	waitFor(t, "the first corruption to be reported", func() bool { return refused.count() == 1 })

	// The repair is the caller's, not the poll's: they wrote the file and asked
	// for it to be read straight away. ReloadNow hands the refusal back rather
	// than reporting it, so the episode has to end here or the next break of the
	// same file is silence.
	replaceFile(t, path, documentBytes(t, publishedSelector(3, "198.51.100.21")))
	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("the caller's own reload refused a valid selector: %v", err)
	}

	replaceFile(t, path, corrupt)
	waitFor(t, "the second corruption to be reported", func() bool { return refused.count() == 2 })
}

// TestWatchersUseTheDocumentedPollIntervalWhenGivenNoOptions pins the shipped
// poll rate, which no other case can reach because every other case injects its
// own. The break it catches is a default lowered to make a test fast, which
// would leave the shipped router decoding a whole document two hundred times a
// second.
func TestWatchersUseTheDocumentedPollIntervalWhenGivenNoOptions(t *testing.T) {
	if DefaultPollInterval != 500*time.Millisecond {
		t.Fatalf("the documented default poll interval is %s, want 500ms", DefaultPollInterval)
	}

	watcher := watch(t, statePath(t, "selector.json"), publishedSelector(1, "198.51.100.7"))
	if watcher.poller.interval != DefaultPollInterval {
		t.Fatalf("a watcher built without options polls every %s, want the documented %s",
			watcher.poller.interval, DefaultPollInterval)
	}

	fast := watch(t, statePath(t, "selector.json"), publishedSelector(1, "198.51.100.7"),
		Options{PollInterval: fastPoll})
	if fast.poller.interval != fastPoll {
		t.Fatalf("a watcher built with an explicit interval polls every %s, want the %s it was given",
			fast.poller.interval, fastPoll)
	}
}

// ---------------------------------------------------------------------------
// Serving the published document, and refusing to unpublish it
// ---------------------------------------------------------------------------

// TestJSONWatcherServesThePublishedDocumentFromTheStart is the startup case: a
// router that boots while the optimizer has already published a selector must
// serve that selector, not the placeholder it was constructed with.
func TestJSONWatcherServesThePublishedDocumentFromTheStart(t *testing.T) {
	published := publishedSelector(7, "198.51.100.7")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, published))

	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, published) {
		t.Fatalf("the watcher started serving %+v, want the published selector %+v", snapshot, published)
	}
}

// TestJSONWatcherKeepsTheInitialDocumentWhenTheFileIsUnreadable is the case
// where the plugin is configured with a selector path the installer never
// created. The safe answer is the document the caller handed in, which the
// plugin sets to a disabled selector; the unsafe answers are a zero selector
// and a stopped watcher.
func TestJSONWatcherKeepsTheInitialDocumentWhenTheFileIsUnreadable(t *testing.T) {
	initial := state.Selector{
		SchemaVersion: state.SchemaVersion,
		Generation:    3,
		Mode:          "disabled",
		Provider:      "cloudflare",
	}
	watcher := watch(t, statePath(t, "absent.json"), initial, Options{PollInterval: fastPoll})

	if err := watcher.ReloadNow(); err == nil {
		t.Fatal("ReloadNow reported success for a file that is not there, so a caller cannot tell a missing selector from a published one")
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, initial) {
		t.Fatalf("a failed read replaced the snapshot with %+v, want the caller's initial document %+v", snapshot, initial)
	}
}

// TestJSONWatcherAdoptsAValidReplacement is the ordinary case: the optimizer
// published a newer selector and the watcher is now serving it.
func TestJSONWatcherAdoptsAValidReplacement(t *testing.T) {
	first := publishedSelector(1, "198.51.100.7")
	second := publishedSelector(2, "203.0.113.8")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, first))
	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	replaceFile(t, path, documentBytes(t, second))
	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("ReloadNow refused a valid replacement: %v", err)
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, second) {
		t.Fatalf("after a valid replacement the watcher served %+v, want %+v", snapshot, second)
	}
}

// TestJSONWatcherKeepsTheLastValidDocumentAfterACorruptReplacement is the case
// the whole package exists for. A truncated or half-edited selector must leave
// the address the router is serving in place, because the alternative is a
// rewrite plugin with no address and no way for the operator to know the router
// is broken.
func TestJSONWatcherKeepsTheLastValidDocumentAfterACorruptReplacement(t *testing.T) {
	last := publishedSelector(1, "198.51.100.7")
	replacement := publishedSelector(2, "203.0.113.8")
	corrupt := corruptMode(t, replacement)
	if len(corrupt) != len(documentBytes(t, replacement)) {
		t.Fatalf("the corrupt document is %d bytes and the valid one %d, so this case would prove nothing about a same-size replacement",
			len(corrupt), len(documentBytes(t, replacement)))
	}

	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, last))
	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	replaceFile(t, path, corrupt)
	if err := watcher.ReloadNow(); err == nil {
		t.Fatal("ReloadNow accepted a selector whose mode is not one of auto, manual or disabled")
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, last) {
		t.Fatalf("a corrupt replacement cost the router its last valid selector: served %+v, want %+v", snapshot, last)
	}
}

// TestJSONWatcherAdoptsARepairThatLandsInTheSameMtimeAndSizeWindow is the way
// "keep the last valid snapshot" is easy to get wrong. A watcher that records
// which file it has already seen -- even one it refused -- stops looking at a
// repair that lands in the same modification time and the same size, which is
// exactly what a producer's retry looks like. Both premises are asserted rather
// than assumed, because a repair that happened to differ in size would prove
// nothing.
func TestJSONWatcherAdoptsARepairThatLandsInTheSameMtimeAndSizeWindow(t *testing.T) {
	first := publishedSelector(1, "198.51.100.7")
	repair := publishedSelector(2, "203.0.113.8")
	corrupt := corruptMode(t, repair)
	repairDocument := documentBytes(t, repair)
	if len(corrupt) != len(repairDocument) {
		t.Fatalf("the corrupt document is %d bytes and the repair %d, so the same-size premise is broken",
			len(corrupt), len(repairDocument))
	}

	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, first))
	refused := &refusals{}
	watcher, err := NewJSON(path, nil, state.Selector{},
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	// Both documents carry this one modification time, so anything that decides
	// whether to look by comparing it cannot tell them apart.
	published := time.Date(2026, time.September, 25, 9, 30, 0, 0, time.UTC)
	replaceFile(t, path, corrupt)
	if err := os.Chtimes(path, published, published); err != nil {
		t.Fatalf("set the corrupt document's modification time: %v", err)
	}
	corruptStat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the corrupt document: %v", err)
	}

	waitFor(t, "the corrupt replacement to be refused", func() bool { return refused.count() > 0 })
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, first) {
		t.Fatalf("the corrupt replacement was published: served %+v, want %+v", snapshot, first)
	}

	replaceFile(t, path, repairDocument)
	if err := os.Chtimes(path, corruptStat.ModTime(), corruptStat.ModTime()); err != nil {
		t.Fatalf("set the repair's modification time: %v", err)
	}
	repairStat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the repair: %v", err)
	}
	if !repairStat.ModTime().Equal(corruptStat.ModTime()) {
		t.Fatalf("the repair is stamped %s and the corrupt document %s, so the same-modification-time premise is broken",
			repairStat.ModTime(), corruptStat.ModTime())
	}
	if repairStat.Size() != corruptStat.Size() {
		t.Fatalf("the repair is %d bytes and the corrupt document %d, so the same-size premise is broken",
			repairStat.Size(), corruptStat.Size())
	}

	waitFor(t, "the repair to be adopted", func() bool {
		return watcher.Snapshot().Generation == 2
	})
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, repair) {
		t.Fatalf("after the repair the watcher served %+v, want %+v", snapshot, repair)
	}
}

// TestJSONWatcherAdoptsTheNewestOfTwoReplacementsMadeBetweenPolls is the busy
// optimizer: two selectors are published between two ticks. The watcher has one
// tick's worth of information, so the only correct answer is the newest
// document, and a watcher that gave up after the first refusal it saw would
// still be serving generation 1 here.
func TestJSONWatcherAdoptsTheNewestOfTwoReplacementsMadeBetweenPolls(t *testing.T) {
	first := publishedSelector(1, "198.51.100.7")
	second := publishedSelector(2, "203.0.113.8")
	third := publishedSelector(3, "198.51.100.21")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, first))
	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	replaceFile(t, path, documentBytes(t, second))
	replaceFile(t, path, documentBytes(t, third))

	waitFor(t, "the newest of the two replacements", func() bool {
		return watcher.Snapshot().Generation == 3
	})
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, third) {
		t.Fatalf("the watcher served %+v, want the newest published document %+v", snapshot, third)
	}
}

// TestJSONWatcherRefusesAHalfWrittenDocumentAndThenAdoptsItWhole covers a
// producer that does not rename: a file truncated in place and finished a
// moment later. The watcher opens what the path names and validates what it
// gets, so the truncated half is refused and the completed file is adopted
// afterwards. A watcher that assembled a document from a stat and a read taken
// at different times is the mutant this catches.
func TestJSONWatcherRefusesAHalfWrittenDocumentAndThenAdoptsItWhole(t *testing.T) {
	last := publishedSelector(1, "198.51.100.7")
	replacement := publishedSelector(2, "203.0.113.8")
	replacementDocument := documentBytes(t, replacement)
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, last))
	refused := &refusals{}
	watcher, err := NewJSON(path, nil, state.Selector{},
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	if err := os.WriteFile(path, replacementDocument[:len(replacementDocument)/2], 0o640); err != nil {
		t.Fatalf("truncate the selector in place: %v", err)
	}
	waitFor(t, "the truncated document to be refused", func() bool { return refused.count() > 0 })
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, last) {
		t.Fatalf("half a document was published: served %+v, want %+v", snapshot, last)
	}

	if err := os.WriteFile(path, replacementDocument, 0o640); err != nil {
		t.Fatalf("finish the selector in place: %v", err)
	}
	waitFor(t, "the completed document to be adopted", func() bool {
		return watcher.Snapshot().Generation == 2
	})
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, replacement) {
		t.Fatalf("after the completed write the watcher served %+v, want %+v", snapshot, replacement)
	}
}

// TestJSONWatcherAdoptsTheDocumentAConcurrentProducerEndsWith is the
// stat-then-open window, in the form a reader can be raced with: a producer
// renames a new document into place over and over while the case reloads. Every
// value the watcher serves must be one whole published document -- a generation
// and the winner that generation published together, never a mixture of the two
// -- and the last one read has to be the last one written, which is what a
// watcher that decided whether to look by comparing a modification time gets
// wrong.
func TestJSONWatcherAdoptsTheDocumentAConcurrentProducerEndsWith(t *testing.T) {
	documents := []state.Selector{
		publishedSelector(1, "198.51.100.7"),
		publishedSelector(2, "203.0.113.8"),
	}
	publishedBytes := [][]byte{documentBytes(t, documents[0]), documentBytes(t, documents[1])}
	path := statePath(t, "selector.json")
	replaceFile(t, path, publishedBytes[0])
	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	stop := make(chan struct{})
	produced := make(chan error, 1)
	go func() {
		index := 1
		for {
			select {
			case <-stop:
				produced <- nil
				return
			default:
			}
			index++
			if err := publish(path, publishedBytes[index%len(publishedBytes)]); err != nil {
				produced <- err
				return
			}
		}
	}()

	// ReloadNow is the reader half, deliberately unsynchronised with the
	// producer: the case is about what the watcher can be made to serve while a
	// file is being replaced under it.
	for attempt := 0; attempt < 200; attempt++ {
		_ = watcher.ReloadNow()
		snapshot := watcher.Snapshot()
		if !selectorEqual(snapshot, documents[0]) && !selectorEqual(snapshot, documents[1]) {
			t.Fatalf("after %d reloads the watcher served %+v, which is not one of the two published documents %+v and %+v",
				attempt, snapshot, documents[0], documents[1])
		}
	}
	close(stop)
	if err := <-produced; err != nil {
		t.Fatalf("the producer failed to publish: %v", err)
	}

	replaceFile(t, path, publishedBytes[1])
	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("ReloadNow after the producer stopped: %v", err)
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, documents[1]) {
		t.Fatalf("after the producer stopped the watcher served %+v, want the document published last %+v",
			snapshot, documents[1])
	}
}

// TestJSONWatcherRefusesWhatTheStatePackageRefuses is the delegation rule. The
// caller's check here accepts everything, so the only thing that can refuse a
// schema-2 selector is the state's own read. A watcher that decoded the file
// itself and consulted only the caller would publish a document the rest of the
// router would refuse to read.
func TestJSONWatcherRefusesWhatTheStatePackageRefuses(t *testing.T) {
	last := publishedSelector(1, "198.51.100.7")
	future := publishedSelector(2, "203.0.113.8")
	future.SchemaVersion = 2
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, last))

	// The poll is parked for the length of the case: at fastPoll the background
	// read would race the one ReloadNow below, and the case is about which door
	// refuses the document, not about who got there first.
	watcher, err := NewJSON(path, func(state.Selector) error { return nil }, state.Selector{},
		Options{PollInterval: idlePoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	replaceFile(t, path, documentBytes(t, future))
	if err := watcher.ReloadNow(); err == nil {
		t.Fatal("a selector declaring schema version 2 was published, though the caller's own check accepted it")
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, last) {
		t.Fatalf("the refused document replaced the live selector: served %+v, want %+v", snapshot, last)
	}
}

// TestJSONWatcherRefusesWhatTheCallersCheckRefuses is the other half of the
// delegation rule: a caller's check may add a refusal, and the added refusal
// must keep the last valid document in place exactly as the state's own does.
// The sentinel makes it provable that this door and not the other one refused.
func TestJSONWatcherRefusesWhatTheCallersCheckRefuses(t *testing.T) {
	first := publishedSelector(1, "198.51.100.7")
	cloudfront := publishedSelector(2, "203.0.113.8")
	cloudfront.Provider = "cloudfront"
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, first))

	watcher, err := NewJSON(path, refuseCloudfront, state.Selector{}, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	replaceFile(t, path, documentBytes(t, cloudfront))
	var readBack state.Selector
	if err := state.ReadJSON(path, &readBack); err != nil {
		t.Fatalf("the fixture is not a document the state package accepts, so this case would prove nothing about the caller's check: %v", err)
	}

	if err := watcher.ReloadNow(); !errors.Is(err, errCallerRefusal) {
		t.Fatalf("ReloadNow returned %v, want the caller's own refusal", err)
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, first) {
		t.Fatalf("a document the caller's check refused was published: served %+v, want %+v", snapshot, first)
	}
}

// ---------------------------------------------------------------------------
// Snapshot isolation
// ---------------------------------------------------------------------------

// TestJSONWatcherSnapshotSharesNoMapWithTheWatcher is the map case. A selector
// carries its CloudFront mappings in a map, and a plugin that added a hostname
// to the map it was handed would otherwise be editing the router's live state
// from inside a query.
func TestJSONWatcherSnapshotSharesNoMapWithTheWatcher(t *testing.T) {
	published := publishedSelector(1, "198.51.100.7")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, published))
	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	snapshot := watcher.Snapshot()
	if len(snapshot.CloudFront) != 1 {
		t.Fatalf("the published selector carried %d cloudfront mappings, want 1", len(snapshot.CloudFront))
	}
	delete(snapshot.CloudFront, "d2abcdef.cloudfront.net")
	snapshot.CloudFront["injected.example.com"] = "13.32.99.11"

	next := watcher.Snapshot()
	if got := len(next.CloudFront); got != 1 {
		t.Fatalf("the watcher now holds %d cloudfront mappings, want the one it published: the snapshot handed out its own map", got)
	}
	if _, injected := next.CloudFront["injected.example.com"]; injected {
		t.Fatal("a hostname the caller added to a returned snapshot reached the watcher's own map")
	}
	if next.CloudFront["d2abcdef.cloudfront.net"] != "13.32.99.10" {
		t.Fatalf("the watcher's own mapping is %v, want the one it published", next.CloudFront)
	}
}

// TestJSONWatcherSnapshotSharesNoSliceWithTheWatcher is the slice case: a DHCP
// record's upstream set. Re-slicing or sorting a snapshot in place is the sort
// of thing a caller does to a list it was given.
func TestJSONWatcherSnapshotSharesNoSliceWithTheWatcher(t *testing.T) {
	published := publishedDHCP(1)
	path := statePath(t, "dhcp.json")
	replaceFile(t, path, documentBytes(t, published))
	watcher := watch(t, path, state.DHCPState{}, Options{PollInterval: fastPoll})

	snapshot := watcher.Snapshot()
	if len(snapshot.Upstreams) != 2 {
		t.Fatalf("the published record carried %d upstreams, want 2", len(snapshot.Upstreams))
	}
	snapshot.Upstreams[0] = "9.9.9.9"
	snapshot.Upstreams = append(snapshot.Upstreams, "208.67.222.222")

	if next := watcher.Snapshot(); !dhcpEqual(next, published) {
		t.Fatalf("the watcher's record is now %+v, want %+v: the snapshot handed out its own slice", next, published)
	}
}

// TestJSONWatcherSnapshotIsIndependentOfEveryDocumentItCanHold runs the
// isolation case against every document the watcher admits. Each subtest
// mutates every field the returned value exposes -- including the contents of
// any map or slice -- and requires a second snapshot to be the document that
// was published, field for field.
func TestJSONWatcherSnapshotIsIndependentOfEveryDocumentItCanHold(t *testing.T) {
	selector := publishedSelector(4, "198.51.100.7")
	dhcp := publishedDHCP(4)
	ech := publishedECH(4)
	budget := publishedBudget()
	health := publishedHealth()

	documents := map[string]func(t *testing.T){
		"DHCPState": func(t *testing.T) {
			path := statePath(t, "dhcp.json")
			replaceFile(t, path, documentBytes(t, dhcp))
			watcher := watch(t, path, state.DHCPState{}, Options{PollInterval: fastPoll})

			snapshot := watcher.Snapshot()
			snapshot.SchemaVersion = 9
			snapshot.Generation = 9999
			snapshot.Interface = "spoofed0"
			snapshot.ConnectionUUID = "spoofed"
			snapshot.Upstreams[0] = "9.9.9.9"
			snapshot.Upstreams = snapshot.Upstreams[:1]
			snapshot.ObservedAt = observedAt.Add(time.Hour)
			snapshot.Source = "spoofed"
			snapshot.LastGood = false

			if got := watcher.Snapshot(); !dhcpEqual(got, dhcp) {
				t.Fatalf("the watcher was edited through a returned DHCP record: %+v, want %+v", got, dhcp)
			}
		},
		"Selector": func(t *testing.T) {
			path := statePath(t, "selector.json")
			replaceFile(t, path, documentBytes(t, selector))
			watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

			snapshot := watcher.Snapshot()
			snapshot.SchemaVersion = 9
			snapshot.Generation = 9999
			snapshot.Mode = "spoofed"
			snapshot.Provider = "spoofed"
			snapshot.WinnerIP = "203.0.113.99"
			snapshot.WinnerProofUntil = observedAt.Add(time.Hour)
			snapshot.FallbackIP = "203.0.113.98"
			snapshot.CloudFront["injected.example.com"] = "13.32.99.11"
			delete(snapshot.CloudFront, "d2abcdef.cloudfront.net")
			snapshot.LastSuccess = observedAt.Add(time.Hour)
			snapshot.LastFailure = "spoofed"
			snapshot.ConfigSHA256 = fixtureDigest

			if got := watcher.Snapshot(); !selectorEqual(got, selector) {
				t.Fatalf("the watcher was edited through a returned selector: %+v, want %+v", got, selector)
			}
		},
		"ECHState": func(t *testing.T) {
			path := statePath(t, "ech.json")
			replaceFile(t, path, documentBytes(t, ech))
			watcher := watch(t, path, state.ECHState{}, Options{PollInterval: fastPoll})

			snapshot := watcher.Snapshot()
			snapshot.SchemaVersion = 9
			snapshot.Generation = 9999
			snapshot.Source = "spoofed.example.com"
			snapshot.FetchedAt = observedAt.Add(time.Hour)
			snapshot.ExpiresAt = observedAt.Add(72 * time.Hour)
			snapshot.StaleUntil = observedAt.Add(96 * time.Hour)
			snapshot.ConfigSHA256 = fixtureDigest
			snapshot.PublicName = "spoofed.example.com"
			snapshot.Status = "invalid"

			if got := watcher.Snapshot(); got != ech {
				t.Fatalf("the watcher was edited through a returned ECH state: %+v, want %+v", got, ech)
			}
		},
		"BandwidthBudgetState": func(t *testing.T) {
			path := statePath(t, "budget.json")
			replaceFile(t, path, documentBytes(t, budget))
			watcher := watch(t, path, state.BandwidthBudgetState{}, Options{PollInterval: fastPoll})

			snapshot := watcher.Snapshot()
			snapshot.SchemaVersion = 9
			snapshot.LocalDate = "2026-09-26"
			snapshot.LimitBytes = 0
			snapshot.UsedBytes = 1 << 40

			if got := watcher.Snapshot(); got != budget {
				t.Fatalf("the watcher was edited through a returned budget: %+v, want %+v", got, budget)
			}
		},
		"HealthState": func(t *testing.T) {
			path := statePath(t, "health.json")
			replaceFile(t, path, documentBytes(t, health))
			watcher := watch(t, path, state.HealthState{}, Options{PollInterval: fastPoll})

			snapshot := watcher.Snapshot()
			snapshot.SchemaVersion = 9
			snapshot.Healthy = false
			snapshot.ConsecutiveFailures = 41
			snapshot.LastSuccess = observedAt.Add(time.Hour)
			snapshot.LastFailure = observedAt.Add(2 * time.Hour)

			if got := watcher.Snapshot(); got != health {
				t.Fatalf("the watcher was edited through a returned health state: %+v, want %+v", got, health)
			}
		},
	}

	// The union in the production type, the keys of documentCloners, and the map
	// above are three lists of the same thing, and Go cannot check that a type
	// switch over a type set is exhaustive -- so a sixth state document added to
	// Document would compile and nothing would fail. The two checks below are the
	// reminders the compiler cannot give.
	//
	// One: a document with no entry in documentCloners cannot be watched at all,
	// because documentCloner refuses to build a copy function for it. A document
	// that holds no map and no slice does not need an entry for correctness, so
	// it has to be named in the map below all the same.
	//
	// Two: every document the watcher can hold has a case in the table above, so
	// a document nobody thought about cannot sit in the union unwatched.
	if got, want := len(documentCloners), len(documents); got != want {
		t.Fatalf("a watcher can hold %d documents and this test covers %d, want one subtest each: a document added to Document needs a subtest here, and the compiler will not say so",
			got, want)
	}
	for name := range documents {
		if _, known := documentCloners[name]; !known {
			t.Fatalf("this test has a subtest for %q, which is not a document documentCloners can copy", name)
		}
	}

	for name, check := range documents {
		t.Run(name, check)
	}
}

// ---------------------------------------------------------------------------
// Closing
// ---------------------------------------------------------------------------

// TestJSONWatcherCloseIsIdempotent: a plugin whose Close runs twice, or a
// shutdown path that closes what it holds and then reaches a deferred close,
// must not get to close a closed channel.
func TestJSONWatcherCloseIsIdempotent(t *testing.T) {
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, publishedSelector(1, "198.51.100.7")))
	watcher, err := NewJSON(path, nil, state.Selector{}, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}

	if err := watcher.Close(); err != nil {
		t.Fatalf("the first Close reported %v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("the second Close reported %v, so Close is not idempotent", err)
	}
}

// TestJSONWatcherCloseIsSafeFromSeveralGoroutines is the same property under
// the race detector: a shutdown path that reaches one watcher from two
// goroutines at once must not close its stop channel twice.
func TestJSONWatcherCloseIsSafeFromSeveralGoroutines(t *testing.T) {
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, publishedSelector(1, "198.51.100.7")))
	watcher, err := NewJSON(path, nil, state.Selector{}, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}

	var group sync.WaitGroup
	for attempt := 0; attempt < 8; attempt++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := watcher.Close(); err != nil {
				t.Errorf("Close reported %v", err)
			}
		}()
	}
	group.Wait()
}

// TestJSONWatcherCloseWaitsForAReloadInFlight: a reload that is halfway through
// reading when Close is called has to finish. Returning early would hand the
// caller a watcher whose poll goroutine is still writing to it, and would let a
// shutdown continue while a read of the state directory is still open.
func TestJSONWatcherCloseWaitsForAReloadInFlight(t *testing.T) {
	gate := newReloadGate()
	t.Cleanup(gate.open)
	first := publishedSelector(1, "198.51.100.7")
	replacement := publishedSelector(2, "203.0.113.8")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, first))

	watcher, err := NewJSON(path, gate.pass, state.Selector{}, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}

	// The replacement is published before the gate is armed, so the reload the
	// gate parks is one that has already read the NEW document in hand. Parking a
	// reload that read the constructor's document would store a value the watcher
	// was already serving, and the assertion below could not fail.
	replaceFile(t, path, documentBytes(t, replacement))
	gate.arm()
	waitFor(t, "a reload to reach the caller's check holding the new document", func() bool {
		select {
		case <-gate.entered:
			return true
		default:
			return false
		}
	})
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, first) {
		t.Fatalf("the watcher already stored %+v, so the parked reload has nothing left to store", snapshot)
	}

	closed := make(chan error, 1)
	go func() { closed <- watcher.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v while a reload was still inside the watcher's read", err)
	case <-time.After(50 * time.Millisecond):
	}

	gate.open()
	if err := <-closed; err != nil {
		t.Fatalf("Close reported %v", err)
	}
	// Close returned, so the parked reload has finished, so the new document is
	// stored. A Close that returned while the reload was in flight would leave
	// this one short of the value the router is serving.
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, replacement) {
		t.Fatalf("Close returned before the in-flight reload stored its document: served %+v, want %+v",
			snapshot, replacement)
	}
}

// TestJSONWatcherKeepsACallerReloadThroughAPollReadInFlight is the ordering case,
// and it is the part of the ordering that is deterministic. A poll read that is
// still in flight when the caller publishes a newer document must not stop the
// caller's reload from being stored: the read cannot be holding the write lock,
// because it is still reading. And once that read finishes and stores what it
// read, the value is the caller's again, because the next tick reads the file as
// it now is.
//
// What is NOT pinned here is the window in between. Between the parked read
// storing its older document and the next tick restoring the newer one, the
// watcher serves the older one for up to one poll interval. Observing that
// intermediate state is a race against the very tick that ends it -- at the
// interval this test injects, the window is a few milliseconds wide -- so the
// window is reasoned about in the poller's comment rather than asserted here.
func TestJSONWatcherKeepsACallerReloadThroughAPollReadInFlight(t *testing.T) {
	gate := newReloadGate()
	t.Cleanup(gate.open)
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, publishedSelector(1, "198.51.100.7")))

	watcher, err := NewJSON(path, gate.pass, state.Selector{}, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	gate.arm()
	waitFor(t, "a poll read to be in flight", func() bool {
		select {
		case <-gate.entered:
			return true
		default:
			return false
		}
	})

	// The caller's reload runs to completion with the poll read still parked, so
	// whatever that read does when it resumes, the caller's document was stored
	// rather than lost.
	newer := publishedSelector(2, "203.0.113.8")
	replaceFile(t, path, documentBytes(t, newer))
	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("the caller's own reload refused a valid selector: %v", err)
	}
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, newer) {
		t.Fatalf("with a poll read in flight the caller's reload did not take effect: served %+v, want %+v",
			snapshot, newer)
	}

	// The parked read resumes and stores what it read, and the next tick puts the
	// caller's document back. Which of the two happens first is the window, and
	// this only requires that the caller's document is what the watcher ends up
	// serving.
	gate.open()
	waitFor(t, "the watcher to settle on the caller's document", func() bool {
		snapshot := watcher.Snapshot()
		return selectorEqual(snapshot, newer)
	})
	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, newer) {
		t.Fatalf("after the in-flight read finished the watcher settled on %+v, want %+v", snapshot, newer)
	}
}

// TestJSONWatcherCloseStopsThePollAndKeepsTheLastValidDocument: closing is how
// a plugin shuts down, and it must neither blank the value the router was
// serving while the shutdown is still unwinding nor keep reading afterwards.
func TestJSONWatcherCloseStopsThePollAndKeepsTheLastValidDocument(t *testing.T) {
	last := publishedSelector(1, "198.51.100.7")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, last))
	watcher, err := NewJSON(path, nil, state.Selector{}, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("Close reported %v", err)
	}

	replaceFile(t, path, documentBytes(t, publishedSelector(2, "203.0.113.8")))
	time.Sleep(20 * fastPoll)

	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, last) {
		t.Fatalf("after Close the watcher serves %+v, want the last valid document %+v: a poll outlived its Close", snapshot, last)
	}
}

// TestWatchersStillReadOnACallerReloadAfterClose pins what Close does and does
// not end. The background poll is gone, so a replacement nobody is watching for
// arrives late, but the caller's own read of the file it is still holding is not
// something a shutdown took away: a plugin that writes a file and wants it read
// before it answers the next query can ask for it.
func TestWatchersStillReadOnACallerReloadAfterClose(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		last := publishedSelector(1, "198.51.100.7")
		replacement := publishedSelector(2, "203.0.113.8")
		path := statePath(t, "selector.json")
		replaceFile(t, path, documentBytes(t, last))
		watcher, err := NewJSON(path, nil, state.Selector{}, Options{PollInterval: fastPoll})
		if err != nil {
			t.Fatalf("NewJSON(%s): %v", path, err)
		}
		if err := watcher.Close(); err != nil {
			t.Fatalf("Close reported %v", err)
		}

		replaceFile(t, path, documentBytes(t, replacement))
		if err := watcher.ReloadNow(); err != nil {
			t.Fatalf("ReloadNow after Close reported %v", err)
		}
		if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, replacement) {
			t.Fatalf("a caller's own reload after Close served %+v, want %+v", snapshot, replacement)
		}
	})

	t.Run("text", func(t *testing.T) {
		path := statePath(t, "force-ech-domains.txt")
		replaceFile(t, path, []byte("example.com\n"))
		watcher, err := NewTrimmedLines(path, nil, Options{PollInterval: fastPoll})
		if err != nil {
			t.Fatalf("NewTrimmedLines(%s): %v", path, err)
		}
		if err := watcher.Close(); err != nil {
			t.Fatalf("Close reported %v", err)
		}

		replaceFile(t, path, []byte("example.com\nexample.net\n"))
		if err := watcher.ReloadNow(); err != nil {
			t.Fatalf("ReloadNow after Close reported %v", err)
		}
		assertList(t, watcher.Snapshot(), []string{"example.com", "example.net"})
	})
}

// ---------------------------------------------------------------------------
// Reporting a refusal
// ---------------------------------------------------------------------------

// TestJSONWatcherIsUndisturbedByAFileNobodyIsChanging is the brief's unchanged
// content case, and the only one that exercises episode suppression on the
// success path. Nothing is written for many poll intervals, so the snapshot must
// stay the published document and the refusal channel must stay silent: a
// successful reload reports nothing, and a watcher that mistook a valid file for
// something to complain about would fill the router's log twice a second for as
// long as it runs.
func TestJSONWatcherIsUndisturbedByAFileNobodyIsChanging(t *testing.T) {
	published := publishedSelector(1, "198.51.100.7")
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, published))
	refused := &refusals{}
	watcher, err := NewJSON(path, nil, state.Selector{},
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	// Long enough for many ticks at the injected interval, and for the file's
	// own timestamp to be the same across all of them.
	time.Sleep(50 * fastPoll)

	if snapshot := watcher.Snapshot(); !selectorEqual(snapshot, published) {
		t.Fatalf("a file nobody changed was served as %+v, want the published %+v", snapshot, published)
	}
	if count := refused.count(); count != 0 {
		t.Fatalf("a valid file nobody changed was reported %d times, the first reading %v", count, refused.all()[0])
	}
}

// TestTextWatcherIsUndisturbedByAListNobodyIsChanging is the same case for the
// allowlist, where the silence matters as much: a report on every tick of a file
// that is fine would bury the one report an operator needs to read.
func TestTextWatcherIsUndisturbedByAListNobodyIsChanging(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\nexample.org\n"))
	refused := &refusals{}
	watcher, err := NewTrimmedLines(path, nil,
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewTrimmedLines(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	time.Sleep(50 * fastPoll)

	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org"})
	if count := refused.count(); count != 0 {
		t.Fatalf("a valid list nobody changed was reported %d times, the first reading %v", count, refused.all()[0])
	}
}

// TestJSONWatcherReportsARefusalOncePerEpisode: a selector that stays corrupt is
// one problem, not two hundred a second, and one that is repaired and breaks
// again is a new problem. A handler called on every tick would bury the log; a
// handler called only on a transition would let a permanently broken file go
// unreported after the first tick.
func TestJSONWatcherReportsARefusalOncePerEpisode(t *testing.T) {
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, publishedSelector(1, "198.51.100.7")))
	refused := &refusals{}
	watcher, err := NewJSON(path, nil, state.Selector{},
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewJSON(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	corrupt := corruptMode(t, publishedSelector(2, "203.0.113.8"))
	replaceFile(t, path, corrupt)
	waitFor(t, "the corrupt selector to be reported", func() bool { return refused.count() > 0 })
	time.Sleep(20 * fastPoll)
	if count := refused.count(); count != 1 {
		t.Fatalf("a corrupt selector that stayed corrupt was reported %d times, want once per episode", count)
	}
	if reported := refused.all()[0]; !strings.Contains(reported.Error(), path) {
		t.Fatalf("the report reads %q, which does not say which file is broken", reported)
	}

	replaceFile(t, path, documentBytes(t, publishedSelector(3, "198.51.100.21")))
	waitFor(t, "the repaired selector to be adopted", func() bool {
		return watcher.Snapshot().Generation == 3
	})
	if count := refused.count(); count != 1 {
		t.Fatalf("a successful reload reported %d failures in total, want the one before it", count)
	}

	replaceFile(t, path, corrupt)
	waitFor(t, "the second corruption to be reported", func() bool { return refused.count() > 1 })
}

// TestJSONWatcherIsSafeUnderConcurrentSnapshotAndReload is the race a rewritten
// answer actually runs under: the poll stores a new generation while queries
// read the old one, and the queries hold what they were given.
func TestJSONWatcherIsSafeUnderConcurrentSnapshotAndReload(t *testing.T) {
	path := statePath(t, "selector.json")
	replaceFile(t, path, documentBytes(t, publishedSelector(1, "198.51.100.7")))
	watcher := watch(t, path, state.Selector{}, Options{PollInterval: fastPoll})

	done := make(chan struct{})
	var readers sync.WaitGroup
	for attempt := 0; attempt < 4; attempt++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				snapshot := watcher.Snapshot()
				if len(snapshot.CloudFront) == 0 {
					t.Errorf("a snapshot taken while a reload was in flight carried no cloudfront mappings")
					return
				}
				snapshot.CloudFront["spoofed.example.com"] = "13.32.99.11"
			}
		}()
	}

	// The document for each generation is built up front, because encoding one
	// calls t.Fatalf and FailNow may only be called from the test's own
	// goroutine.
	generations := make([][]byte, 0, 38)
	for generation := uint64(2); generation < 40; generation++ {
		generations = append(generations, documentBytes(t, publishedSelector(generation, "203.0.113.8")))
	}
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for _, document := range generations {
			if err := publish(path, document); err != nil {
				t.Errorf("publish a replacement: %v", err)
				return
			}
			_ = watcher.ReloadNow()
		}
	}()
	writers.Wait()
	close(done)
	readers.Wait()

	if snapshot := watcher.Snapshot(); len(snapshot.CloudFront) != 1 {
		t.Fatalf("the live watcher holds %v after concurrent snapshots and reloads, want exactly the one mapping it was given",
			snapshot.CloudFront)
	}
}

// ---------------------------------------------------------------------------
// The force-ECH text list
// ---------------------------------------------------------------------------

// TestTextWatcherServesThePublishedListFromTheStart is the startup case for the
// allowlist: the file the operator wrote is the list the plugin starts with.
func TestTextWatcherServesThePublishedListFromTheStart(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\nexample.org\n"))

	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	snapshot := watcher.Snapshot()
	if len(snapshot) != 2 || snapshot[0] != "example.com" || snapshot[1] != "example.org" {
		t.Fatalf("the watcher started serving %v, want [example.com example.org]", snapshot)
	}
}

// TestTextWatcherKeepsTheInitialListWhenTheFileIsUnreadable: a router configured
// for strict ECH whose allowlist is missing must keep the list it was
// constructed with. Dropping it turns strict ECH off for every domain in it,
// which is the direction this package exists to prevent.
func TestTextWatcherKeepsTheInitialListWhenTheFileIsUnreadable(t *testing.T) {
	watcher := watchText(t, statePath(t, "absent.txt"), []string{"configured.example"},
		Options{PollInterval: fastPoll})

	if err := watcher.ReloadNow(); err == nil {
		t.Fatal("ReloadNow reported success for an allowlist that is not there")
	}
	if snapshot := watcher.Snapshot(); len(snapshot) != 1 || snapshot[0] != "configured.example" {
		t.Fatalf("a missing allowlist cost the router its configured list: serving %v", snapshot)
	}
}

// TestTextWatcherIgnoresCommentsAndBlankLines: the file is an operator's file,
// so it carries prose. A line that is not a domain still has to be a domain to
// be accepted, and a comment is a comment whether or not it is indented.
func TestTextWatcherIgnoresCommentsAndBlankLines(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte(strings.Join([]string{
		"# force ECH for these domains",
		"",
		"   ",
		"\texample.com",
		"  # indented comment",
		"example.org",
		"",
	}, "\n")))

	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	want := []string{"example.com", "example.org"}
	assertList(t, watcher.Snapshot(), want)
}

// TestTextWatcherTrimsWhitespaceAroundEachName covers the name the constructor
// carries: a line padded with spaces, and a file written with a carriage return
// on the end of every line, are the same line as far as the operator is
// concerned.
func TestTextWatcherTrimsWhitespaceAroundEachName(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("  example.com  \r\n\texample.org\t\r\n"))

	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org"})
}

// TestTextWatcherLowercasesEveryName: a browser sends the name it was given and
// DNS names are case-insensitive, so a query for Example.com has to match the
// list's example.com. Storing the name as written would make the match depend on
// the client's capitalisation.
func TestTextWatcherLowercasesEveryName(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("Example.COM\nXN--BCHER-KVA.example\n"))

	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	assertList(t, watcher.Snapshot(), []string{"example.com", "xn--bcher-kva.example"})
}

// TestTextWatcherKeepsOneEntryPerNameInFirstSeenOrder: two spellings of one name
// are one domain, and a list of domains is read by a human looking for their
// own, so the order it was written in is the order it is kept in.
func TestTextWatcherKeepsOneEntryPerNameInFirstSeenOrder(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("Example.com\nexample.org\nexample.com\nEXAMPLE.ORG\nbeta.example\n"))

	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org", "beta.example"})
}

// TestTextWatcherAcceptsAListOfOnlyComments: a list with nothing in it is a list
// the operator emptied on purpose, not a malformed file. Refusing it would keep
// forcing ECH for every domain they removed, which is a list nobody can get rid
// of.
func TestTextWatcherAcceptsAListOfOnlyComments(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("# nothing forces ECH here yet\n\n"))

	watcher := watchText(t, path, []string{"configured.example"}, Options{PollInterval: fastPoll})

	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("a list of only comments was refused: %v", err)
	}
	if snapshot := watcher.Snapshot(); snapshot == nil {
		t.Fatal("the emptied list reads as no list at all, so a caller cannot tell it from a watcher that never loaded one")
	}
	assertList(t, watcher.Snapshot(), []string{})
}

// TestTextWatcherRefusesAWholeListWithOneBadLineAndKeepsTheLastValidOne is the
// case the whole-file validation exists for. One line of prose left in the
// middle of a thousand-domain list would either force ECH for a name that
// cannot exist, or -- skipped silently -- leave the operator with a list they
// did not write and cannot see.
func TestTextWatcherRefusesAWholeListWithOneBadLineAndKeepsTheLastValidOne(t *testing.T) {
	last := []string{"example.com", "example.org"}
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\nexample.org\n"))
	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	replaceFile(t, path, []byte("example.com\nhttps://example.org/\nbeta.example\n"))
	if err := watcher.ReloadNow(); err == nil {
		t.Fatal("a list holding a URL was published, though one malformed line makes the whole list unusable")
	}
	assertList(t, watcher.Snapshot(), last)
}

// TestTextWatcherRefusesWhatIsNotADomain is the refusal matrix. Every line here
// is something an operator's editor, a wiki page or a paste buffer can leave
// behind. The line number and the text are asserted, because a refusal the
// operator cannot locate in a file of thousands of names is a refusal they
// cannot act on.
func TestTextWatcherRefusesWhatIsNotADomain(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".com"
	longName := strings.Repeat("abcd.", 60) + "com"
	cases := []struct {
		name string
		list string
		line int
		text string
	}{
		{name: "url", list: "example.com\nhttps://example.org/\n", line: 2, text: "https://example.org/"},
		{name: "trailing dot", list: "example.com.\n", line: 1, text: "example.com."},
		{name: "empty label", list: "example.com\nexample..org\n", line: 2, text: "example..org"},
		{name: "leading dash", list: "-example.com\n", line: 1, text: "-example.com"},
		{name: "trailing dash", list: "example-.com\n", line: 1, text: "example-.com"},
		{name: "space inside", list: "example .com\n", line: 1, text: "example .com"},
		{name: "wildcard", list: "*.example.com\n", line: 1, text: "*.example.com"},
		{name: "ip literal", list: "1.2.3.4\n", line: 1, text: "1.2.3.4"},
		{name: "bare word", list: "example\n", line: 1, text: "example"},
		{name: "long label", list: longLabel + "\n", line: 1, text: longLabel},
		{name: "long name", list: longName + "\n", line: 1, text: longName},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := statePath(t, "force-ech-domains.txt")
			replaceFile(t, path, []byte(testCase.list))
			watcher := watchText(t, path, []string{"configured.example"}, Options{PollInterval: fastPoll})

			err := watcher.ReloadNow()
			if err == nil {
				t.Fatalf("the watcher accepted %q as a domain", testCase.text)
			}
			var refusal LineError
			if !errors.As(err, &refusal) {
				t.Fatalf("ReloadNow returned %T (%v), want a LineError the operator can locate", err, err)
			}
			if refusal.Line != testCase.line {
				t.Fatalf("the refusal names line %d, want line %d", refusal.Line, testCase.line)
			}
			if refusal.Text != testCase.text {
				t.Fatalf("the refusal quotes %q, want %q", refusal.Text, testCase.text)
			}
			if refusal.Path != path {
				t.Fatalf("the refusal names %q as the file, want %q", refusal.Path, path)
			}
			if refusal.Reason == "" {
				t.Fatalf("the refusal for %q says which line it is and not what is wrong with it", testCase.text)
			}
			assertList(t, watcher.Snapshot(), []string{"configured.example"})
		})
	}
}

// TestTextWatcherRefusesAZeroByteFileAndKeepsTheLastValidList is the truncation
// case, and the one refusal the whole-file rule alone does not catch. An
// operator's in-place write -- a shell redirect, sed -i, an editor that truncates
// before it writes -- leaves a zero-byte file for as long as the write takes. A
// zero-byte file parses to no entries and no complaint, so the list would be
// dropped for the length of that window: every domain the operator had chosen to
// force ECH for stops being forced, with nothing in any log to say so. The last
// valid list has to survive it, loudly.
func TestTextWatcherRefusesAZeroByteFileAndKeepsTheLastValidList(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\nexample.org\n"))
	refused := &refusals{}
	watcher, err := NewTrimmedLines(path, nil,
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewTrimmedLines(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatalf("truncate the allowlist in place: %v", err)
	}
	if err := watcher.ReloadNow(); err == nil {
		t.Fatal("a zero-byte allowlist was accepted, so the router stopped forcing ECH for every domain in it")
	}
	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org"})

	// The refusal has to be as loud as a line refusal, and it has to name the
	// file: an operator reading the log is the only one who can tell a truncated
	// write from a file they emptied.
	waitFor(t, "the truncated allowlist to be reported", func() bool { return refused.count() > 0 })
	reported := refused.all()[0]
	if !strings.Contains(reported.Error(), path) {
		t.Fatalf("the report reads %q, which does not say which file is broken", reported)
	}
	if snapshot := watcher.Snapshot(); len(snapshot) != 2 {
		t.Fatalf("the poll published the truncated file: serving %v, want the two domains it published", snapshot)
	}
}

// TestTextWatcherAcceptsACommentsOnlyFileAsTheIntentionalEmpty is the other half
// of the ruling, and it is what the operator has instead: the router must be
// able to stop forcing ECH, and a file whose every line is a comment says so
// unambiguously. A file of blank lines says the same thing.
func TestTextWatcherAcceptsACommentsOnlyFileAsTheIntentionalEmpty(t *testing.T) {
	for _, testCase := range []struct {
		name string
		list string
	}{
		{name: "comments", list: "# forcing is off while the keys are fetched\n"},
		{name: "blank lines", list: "\n\n   \n\t\n"},
		{name: "comments and blank lines", list: "\n# off\n\n  # still off\n\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := statePath(t, "force-ech-domains.txt")
			replaceFile(t, path, []byte("example.com\n"))
			watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

			replaceFile(t, path, []byte(testCase.list))
			if err := watcher.ReloadNow(); err != nil {
				t.Fatalf("a list the operator emptied on purpose was refused: %v", err)
			}
			if snapshot := watcher.Snapshot(); snapshot == nil {
				t.Fatal("the emptied list reads as no list at all, so a caller cannot tell it from a watcher that never loaded one")
			}
			assertList(t, watcher.Snapshot(), []string{})
		})
	}
}

// TestTextWatcherAdoptsAFileRepairedFromZeroBytes is the retry the truncation
// refusal has to survive: the operator's write finishes, the file has content
// again, and the router has to be enforcing what they wrote. A refusal that
// outlived its cause would pin the router to the list it had before the
// truncating editor opened.
func TestTextWatcherAdoptsAFileRepairedFromZeroBytes(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\n"))
	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatalf("truncate the allowlist in place: %v", err)
	}
	waitFor(t, "the truncation to be refused", func() bool {
		return watcher.ReloadNow() != nil
	})
	assertList(t, watcher.Snapshot(), []string{"example.com"})

	replaceFile(t, path, []byte("example.com\nexample.net\n"))
	waitFor(t, "the finished write to be adopted", func() bool { return len(watcher.Snapshot()) == 2 })
	assertList(t, watcher.Snapshot(), []string{"example.com", "example.net"})
}

// TestTextWatcherAdoptsAValidReplacement: the operator fixes the file and the
// next poll publishes what they wrote. A refusal has to be temporary, or a
// router serves a list its owner can never change.
func TestTextWatcherAdoptsAValidReplacement(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\n"))
	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	replaceFile(t, path, []byte("example.com\nexample.org\nbeta.example\n"))
	waitFor(t, "the added domains to be adopted", func() bool {
		return len(watcher.Snapshot()) == 3
	})
	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org", "beta.example"})
}

// TestTextWatcherSnapshotIsIndependentOfTheWatchersList: the list a caller
// receives is a slice it could sort, shorten, or write to, and a plugin that
// edited the allowlist it was handed would be editing the operator's decision
// about which domains are forced.
func TestTextWatcherSnapshotIsIndependentOfTheWatchersList(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\nexample.org\n"))
	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	snapshot := watcher.Snapshot()
	snapshot[0] = "injected.example"
	_ = append(snapshot, "appended.example")

	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org"})
}

// TestTextWatcherIsIndependentOfTheInitialListTheCallerPassed covers the
// constructor's copy. The list a watcher is built with belongs to whoever built
// it, and a plugin that keeps using its own slice afterwards -- reordering it,
// trimming it, reusing the buffer for the next file it reads -- must not be
// editing the list the router is enforcing.
//
// Two things make this case about the constructor. The file is ABSENT when the
// watcher is built, because the constructor reads the file once and a readable
// file would replace the caller's list before the case began. And the mutation
// is applied to the CALLER's slice rather than to a snapshot, because the
// snapshot's own copy is what TestTextWatcherSnapshotIsIndependentOfTheWatchersList
// is about; only the caller's own slice reaches the constructor's copy.
func TestTextWatcherIsIndependentOfTheInitialListTheCallerPassed(t *testing.T) {
	initial := []string{"example.com", "example.org"}
	watcher := watchText(t, statePath(t, "absent.txt"), initial, Options{PollInterval: fastPoll})

	// The caller's list is the live one, or this case is not about it.
	assertList(t, watcher.Snapshot(), initial)

	initial[0] = "injected.example"
	initial = append(initial, "appended.example")

	assertList(t, watcher.Snapshot(), []string{"example.com", "example.org"})
}

// TestTextWatcherKeepsTheLastValidListWhenTheOperatorFixesTheBadLine is the
// retry a refusal has to survive, seen from the poll rather than from
// ReloadNow: the file goes from refused to valid with no change of watcher, and
// the list the operator fixed has to arrive -- with the refusal naming the line
// they have to edit.
func TestTextWatcherKeepsTheLastValidListWhenTheOperatorFixesTheBadLine(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\n"))
	refused := &refusals{}
	watcher, err := NewTrimmedLines(path, nil,
		Options{PollInterval: fastPoll, ReloadError: refused.record})
	if err != nil {
		t.Fatalf("NewTrimmedLines(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	replaceFile(t, path, []byte("example.com\nnot a domain\n"))
	waitFor(t, "the malformed list to be reported", func() bool { return refused.count() > 0 })
	assertList(t, watcher.Snapshot(), []string{"example.com"})

	var refusal LineError
	if !errors.As(refused.all()[0], &refusal) {
		t.Fatalf("the poll reported %v, want the LineError naming the line", refused.all()[0])
	}
	if refusal.Line != 2 {
		t.Fatalf("the poll reported line %d as the bad one, want 2", refusal.Line)
	}

	replaceFile(t, path, []byte("example.com\nexample.net\n"))
	waitFor(t, "the fixed list to be adopted", func() bool { return len(watcher.Snapshot()) == 2 })
	assertList(t, watcher.Snapshot(), []string{"example.com", "example.net"})
}

// TestTextWatcherCloseIsIdempotent: the same shutdown contract as the JSON
// watcher, on the list a strict-ECH router cannot afford to lose.
func TestTextWatcherCloseIsIdempotent(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\n"))
	watcher, err := NewTrimmedLines(path, nil, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewTrimmedLines(%s): %v", path, err)
	}

	if err := watcher.Close(); err != nil {
		t.Fatalf("the first Close reported %v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("the second Close reported %v, so Close is not idempotent", err)
	}
}

// TestTextWatcherCloseStopsThePollAndKeepsTheLastValidList: the poll stops, and
// the list the router was enforcing is still there after it.
func TestTextWatcherCloseStopsThePollAndKeepsTheLastValidList(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\n"))
	watcher, err := NewTrimmedLines(path, nil, Options{PollInterval: fastPoll})
	if err != nil {
		t.Fatalf("NewTrimmedLines(%s): %v", path, err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("Close reported %v", err)
	}

	replaceFile(t, path, []byte("example.com\nexample.net\n"))
	time.Sleep(20 * fastPoll)

	assertList(t, watcher.Snapshot(), []string{"example.com"})
}

// TestTextWatcherIsSafeUnderConcurrentSnapshotAndReload is the same race the
// JSON watcher runs, on the slice a query matches against while the poll
// publishes a new list.
func TestTextWatcherIsSafeUnderConcurrentSnapshotAndReload(t *testing.T) {
	path := statePath(t, "force-ech-domains.txt")
	replaceFile(t, path, []byte("example.com\n"))
	watcher := watchText(t, path, nil, Options{PollInterval: fastPoll})

	done := make(chan struct{})
	var readers sync.WaitGroup
	for attempt := 0; attempt < 4; attempt++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				snapshot := watcher.Snapshot()
				if len(snapshot) == 0 {
					t.Errorf("a snapshot taken while a reload was in flight carried no entries")
					return
				}
				snapshot[0] = "spoofed.example"
			}
		}()
	}

	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		// publish rather than replaceFile, which calls t.Fatalf: FailNow may only
		// be called from the test's own goroutine.
		for round := 0; round < 40; round++ {
			if err := publish(path, []byte("example.com\nexample.org\nexample.net\n")); err != nil {
				t.Errorf("publish a longer list: %v", err)
				return
			}
			_ = watcher.ReloadNow()
			if err := publish(path, []byte("example.com\n")); err != nil {
				t.Errorf("publish a shorter list: %v", err)
				return
			}
			_ = watcher.ReloadNow()
		}
	}()
	writers.Wait()
	close(done)
	readers.Wait()

	// The watcher is settled by waiting for the file's own content to be what it
	// serves, not by asserting on the last reload: a poll read that read the
	// three-name list can store it after the writer's last reload of the one-name
	// list, and the next tick restores it. That window is the one the poller's
	// comment describes, and a test that ignored it would be asserting an ordering
	// the watcher does not promise.
	waitFor(t, "the watcher to settle on the list the writer published last", func() bool {
		snapshot := watcher.Snapshot()
		return len(snapshot) == 1 && snapshot[0] == "example.com"
	})
	assertList(t, watcher.Snapshot(), []string{"example.com"})
}

// assertList compares a served list with a hand-written expectation, entry for
// entry, and distinguishes an emptied list from no list at all.
func assertList(t *testing.T, got, want []string) {
	t.Helper()
	if got == nil {
		t.Fatalf("the list is nil, want %v", want)
	}
	if len(got) != len(want) {
		t.Fatalf("the list is %v, want exactly %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d is %q, want %q (whole list %v)", index, got[index], want[index], got)
		}
	}
}
