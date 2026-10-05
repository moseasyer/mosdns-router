package cdn_rewrite

// The ECH provider's BACKGROUND refresh. The defect these cases exist for is
// measured, not hypothetical, and it is the reason forced ECH worked after an
// install and stopped working later:
//
//   - The key was fetched ONLY from inside a forced-ECH HTTPS query
//     (ech_provider.Config was the sole caller of fetchOnce). No ticker, no
//     systemd timer, no CLI verb.
//   - expires_at = fetched_at + echRotationInterval (5 minutes, fixed), and
//     stale_until = expires_at + stale_grace. So the entire tolerance budget was
//     15 minutes on a shipped policy and 20 on a machine whose policy said 900.
//   - Every second of that budget was spent only by query ARRIVALS. A machine
//     that is not being queried through a forced name never refreshed, so the key
//     simply aged out and failure_policy: strict answered SERVFAIL.
//
// Two further defects made the episode invisible, and both are held here because
// both are the reason an operator had nothing to read:
//
//   - A refresh that failed while a stale key was still being served logged
//     nothing at all. logFetchFailure is reached from ech_provider.go:311 (no key
//     was EVER held) and :328 (both attempts exhausted), and NOT from the
//     fetch-failed-but-serving-stale path. rewriteHTTPS sees err == nil there, so
//     its own "there is no usable ECH key to install" warning does not fire
//     either. The whole "the source went quiet and only the grace is holding this
//     up" episode was silent.
//   - ech-state.json stopped being written after every restart. The provider's
//     generation is a per-process counter starting at 0; state.WriteJSONAtomic
//     refuses a generation rollback; and the provider advanced its
//     "already published" memory BEFORE the write, so a refused write was not
//     retried for that (generation, status) pair. So `mosdns-cdnctl status --ech`
//     could report status=fresh with an expires_at in the past while the router
//     was failing closed -- which is precisely the document the shipped
//     force-ech-domains.txt tells an operator to read.
//
// The rotation shape is in here too, because it is what makes NINE sources
// possible at all. The rotation position advances once per ATTEMPT (ech_provider.go
// fetch), so a ticker that asked exactly one source per tick would walk nine
// sources in 45 minutes -- and with a 15-20 minute grace, the key would die
// before the rotation ever reached a source that answers. MEASURED: the nine
// shipped sources all publish the byte-identical ECHConfigList
// (sha256:336cc2eb9ee1f248…, public_name cloudflare-ech.com) across five distinct
// DNS zones, so redundancy against one zone dropping ECH is the property that
// matters and it is entirely a property of the SOURCE LIST.
//
// One tick therefore keeps asking successive sources until one of them answers,
// bounded, rather than asking one and waiting five minutes for the next.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"mosdns-router/internal/state"
)

// testRefreshInterval is the background refresh's period in these cases. It is
// the production cadence divided by a thousand, so a refresh lands inside a
// test's deadline rather than inside its timeout, and it is the one thing about
// these tests a deployment gets differently: nothing here asserts how OFTEN a
// refresh happens, only that a key is kept current without any query.
const testRefreshInterval = 5 * time.Millisecond

// refreshDeadline is how long a case waits for the background refresh to land. It
// is generous relative to testRefreshInterval on purpose: a case that failed on a
// slow machine would be a case that fails for a reason that has nothing to do
// with the behaviour under test.
const refreshDeadline = 10 * time.Second

// backgroundHarness is a provider built for the background cases: its own state
// path, its own log observer, and a ticker period a test can wait on. It is a
// separate constructor rather than a setting on buildHarness because every case
// here is about a provider that NO client ever queries -- buildHarness's plugin
// path is the one that queries.
func backgroundHarness(t *testing.T, sources []string, answer func(dns.Question) (*dns.Msg, error), grace time.Duration) (*echProvider, *observer.ObservedLogs, string) {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "ech-state.json")
	fake := &fakeECHUpstream{answer: answer}
	core, logs := observer.New(zapcore.DebugLevel)
	provider, err := newECHProvider(echProviderOptions{
		upstream:  "tcp://127.0.0.1:15353",
		statePath: statePath,
		sources:   sources,
		grace:     grace,
		timeout:   time.Second,
		logger:    zap.New(core),
		now:       time.Now,
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) { return fake, nil },
		// The ticker is injected rather than derived, so a case does not have to
		// wait five minutes to see a refresh and the production wiring stays the
		// only thing that knows what the production period is.
		refreshEvery: testRefreshInterval,
	})
	if err != nil {
		t.Fatalf("newECHProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	return provider, logs, statePath
}

// waitForRefresh blocks until the background refresh has asked the upstream at
// least `want` queries, or the deadline passes. Polling a real fact rather than
// sleeping is the same rule the rest of this project's timing cases follow.
func waitForRefresh(t *testing.T, fake *fakeECHUpstream, want int) {
	t.Helper()
	deadline := time.Now().Add(refreshDeadline)
	for {
		if len(fake.asked()) >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background refresh asked %d queries within %s, want %d: a key that is only "+
				"refreshed when a client queries expires on a machine that is not being queried, and every "+
				"forced-ECH name then fails closed for as long as the grace lasts",
				len(fake.asked()), refreshDeadline, want)
		}
		time.Sleep(testRefreshInterval)
	}
}

// TestTheKeyIsRefreshedWithNoClientQueryAtAll is the defect itself, as a case.
//
// No Exec, no Config, no client query of any kind: only the ticker. Before the
// refresher existed this fetched nothing at all, so on a machine with no
// forced-ECH traffic the key aged out and strict mode failed closed.
func TestTheKeyIsRefreshedWithNoClientQueryAtAll(t *testing.T) {
	provider, _, statePath := backgroundHarness(t, []string{echSourceFirst}, rotationAnswer(t, map[string][]byte{
		echSourceFirst: echFixture(t),
	}), 600*time.Second)
	provider.startRefreshing()

	fake := provider.client.(*fakeECHUpstream)
	waitForRefresh(t, fake, 2)

	// **Polled, not read once.** `fake.asked` records the query as it goes out, so
	// it goes one ahead of the answer coming back: a case that waits for the second
	// query and then reads the document is reading it while that second fetch is
	// still in flight, and would report a generation of 1 for a provider that has
	// stored 2. The fact being waited for is the document itself.
	document := waitForGeneration(t, statePath, 2)
	if document.Status != echStatusFresh {
		t.Fatalf("the published status is %q, want %q: a background refresh that does not publish "+
			"leaves an operator reading a document about a key nobody has refreshed",
			document.Status, echStatusFresh)
	}
}

// TestOneTickAsksSuccessiveSourcesUntilOneAnswers is what makes nine sources
// possible at all.
//
// The rotation position advances once per attempt, so a ticker that asked one
// source per tick would walk nine sources in 45 minutes -- and the grace is 15 to
// 20. With the first two sources answering nothing, the tick must reach the third
// WITHIN THE SAME TICK rather than at the next one.
func TestOneTickAsksSuccessiveSourcesUntilOneAnswers(t *testing.T) {
	sources := []string{echSourceFirst, echSourceSecond, echSourceThird}
	// The first two publish nothing this provider can use, which is what a source
	// that stops returning an ech parameter looks like: the record still arrives,
	// with everything except the key.
	fake := &fakeECHUpstream{answer: func(question dns.Question) (*dns.Msg, error) {
		name := trimDot(question.Name)
		if name == echSourceThird {
			return rotationAnswer(t, map[string][]byte{echSourceThird: echFixture(t)})(question)
		}
		return &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{question},
			Answer: []dns.RR{httpsRecord(question.Name, echSourceTTL, 1, ".",
				&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})},
		}, nil
	}}
	core, _ := observer.New(zapcore.DebugLevel)
	provider, err := newECHProvider(echProviderOptions{
		upstream:  "tcp://127.0.0.1:15353",
		statePath: filepath.Join(t.TempDir(), "ech-state.json"),
		sources:   sources,
		grace:     600 * time.Second,
		timeout:   time.Second,
		logger:    zap.New(core),
		now:       time.Now,
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) { return fake, nil },
		// **ONE tick and no more, and that is the whole point of the case.** The
		// first version ran a 5ms ticker and waited for three queries, which three
		// ticks supply perfectly well -- so it passed against a refresher that asks
		// exactly one source per tick, and the mutation check said so. A tick that
		// reaches a live source WITHIN ITSELF is the property that makes a source
		// list longer than the grace survivable, so the case gives the refresher
		// exactly one opportunity and no more.
		refreshEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("newECHProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	provider.refreshTick()

	// Every source before the third was asked INSIDE that one tick.
	if asked := len(fake.asked()); asked != len(sources) {
		t.Fatalf("one tick asked %d sources, want %d: a tick that asks one source and waits five "+
			"minutes for the next walks a nine-source list in 45 minutes, and the grace is fifteen to "+
			"twenty, so the key dies before the rotation reaches a source that answers",
			asked, len(sources))
	}
	key, err := provider.Config(t.Context())
	if err != nil {
		t.Fatalf("Config after the refresh: %v", err)
	}
	if key == nil {
		t.Fatal("Config returned no key after the background refresh stored one")
	}

	asked := askedNames(fake)
	third := indexOf(asked, echSourceThird)
	if third < 0 {
		t.Fatalf("the third source %q was never asked; the rotation asked %v", echSourceThird, asked)
	}
	for _, dead := range []string{echSourceFirst, echSourceSecond} {
		if indexOf(asked, dead) < 0 || indexOf(asked, dead) > third {
			t.Fatalf("%q was not asked before %q in the same tick; the rotation asked %v, so a list "+
				"of sources longer than the grace would starve the key", dead, echSourceThird, asked)
		}
	}
}

// TestAFailedRefreshInsideTheGraceIsReported is the observability hole, held as
// a case.
//
// A refresh that fails while a stale key is still being served produced NO log
// line: logFetchFailure was reached only when no key had ever been held and when
// both attempts were exhausted, never from the fetch-failed-but-serving-stale
// path, and the caller's error was nil so its own warning did not fire either. An
// operator reading the journal for the whole episode found nothing.
func TestAFailedRefreshInsideTheGraceIsReported(t *testing.T) {
	clock := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	fake := &fakeECHUpstream{}
	fake.answer = func(question dns.Question) (*dns.Msg, error) {
		return rotationAnswer(t, map[string][]byte{echSourceFirst: echFixture(t)})(question)
	}
	statePath := filepath.Join(t.TempDir(), "ech-state.json")
	core, logs := observer.New(zapcore.DebugLevel)
	provider, err := newECHProvider(echProviderOptions{
		upstream:  "tcp://127.0.0.1:15353",
		statePath: statePath,
		sources:   []string{echSourceFirst},
		grace:     600 * time.Second,
		timeout:   time.Second,
		logger:    zap.New(core),
		now:       func() time.Time { return clock },
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) { return fake, nil },
		// Long enough that no tick fires during the case: this is about what a
		// client's own query reports, not about the refresher.
		refreshEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("newECHProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	if _, err := provider.Config(t.Context()); err != nil {
		t.Fatalf("the first fetch: %v", err)
	}
	// The key is now stale: past expires_at, inside stale_until.
	clock = clock.Add(echRotationInterval + time.Second)

	// The source goes quiet.
	fake.mu.Lock()
	fake.answer = func(dns.Question) (*dns.Msg, error) {
		return nil, ErrECHUnusable
	}
	fake.mu.Unlock()

	if _, err := provider.Config(t.Context()); err != nil {
		t.Fatalf("Config inside the grace: %v, want the stale key served with no error", err)
	}

	reported := false
	for _, entry := range logs.All() {
		if entry.Level == zapcore.WarnLevel && containsAll(entry.Message, "ECH source", "grace") {
			reported = true
		}
	}
	if !reported {
		var seen []string
		for _, entry := range logs.All() {
			seen = append(seen, entry.Level.String()+": "+entry.Message)
		}
		t.Fatalf("a refresh that failed while a stale key was still being served logged nothing at "+
			"warn level, so the whole episode -- the source going quiet and only the grace holding the "+
			"feature up -- is invisible in the journal. What was logged: %v", seen)
	}
}

// TestARestartDoesNotFreezeTheStateDocument is the lying document, held as a
// case.
//
// The provider's generation is a per-process counter. The state writer refuses a
// generation rollback. So after every restart of the router the document's
// generation was HIGHER than anything the new process could produce, every
// publish was refused, and -- because the provider remembered the publish before
// attempting it -- none of them was retried. `mosdns-cdnctl status --ech` then
// reported a document about a key nobody was serving.
func TestARestartDoesNotFreezeTheStateDocument(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "ech-state.json")
	sources := []string{echSourceFirst}
	answer := rotationAnswer(t, map[string][]byte{echSourceFirst: echFixture(t)})

	// The first process runs long enough to publish a generation well above 1.
	//
	// **An injected, advanceable clock**, because a Config call on a FRESH key
	// returns the held one and asks nothing -- so three Config calls against the
	// real clock produce generation 1 and the case skips. The clock is what makes
	// each call a real fetch, and it is the same seam the freshness cases in
	// cdn_rewrite_test.go use.
	clock := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	first, err := newECHProvider(echProviderOptions{
		upstream: "tcp://127.0.0.1:15353", statePath: statePath, sources: sources,
		grace: 600 * time.Second, timeout: time.Second, logger: zap.NewNop(),
		now: func() time.Time { return clock },
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) {
			return &fakeECHUpstream{answer: answer}, nil
		},
		refreshEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("newECHProvider: %v", err)
	}
	for i := 0; i < 3; i++ {
		// Past expires_at, inside stale_until, so every call is a real fetch.
		clock = clock.Add(echRotationInterval + time.Second)
		if _, err := first.Config(t.Context()); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	_ = first.Close()
	before := readECHState(t, statePath)
	if before.Generation < 2 {
		t.Fatalf("the first process only reached generation %d, want at least 2, so this case "+
			"cannot show what a restart does to the document", before.Generation)
	}

	// The second process is a restart over the same document, which is what every
	// `systemctl restart mosdns-router` does.
	core, logs := observer.New(zapcore.DebugLevel)
	// The clock CONTINUES where the first process left it, which is what a restart
	// on a real machine looks like: the document's timestamps are in the past and
	// the new process reads them as such.
	second, err := newECHProvider(echProviderOptions{
		upstream: "tcp://127.0.0.1:15353", statePath: statePath, sources: sources,
		grace: 600 * time.Second, timeout: time.Second, logger: zap.New(core),
		now: func() time.Time { return clock },
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) {
			return &fakeECHUpstream{answer: answer}, nil
		},
		refreshEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("newECHProvider after the restart: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if _, err := second.Config(t.Context()); err != nil {
		t.Fatalf("the first fetch after the restart: %v", err)
	}

	after := readECHState(t, statePath)
	if after.Generation <= before.Generation {
		t.Fatalf("the published generation is %d after a restart, want more than the %d the previous "+
			"process left: the provider's counter starts at zero and the state writer refuses a rollback, "+
			"so every publish after a restart is refused and the document stops describing the key in "+
			"service. The journal said: %v", after.Generation, before.Generation, messagesOf(logs))
	}
}

// TestARefusedPublishIsRetriedRatherThanRemembered is the other half of the same
// defect, and it is what turns a refusal into a permanent one.
//
// The provider recorded the document it was about to publish BEFORE writing it, so
// a write the state writer refused was never attempted again for that
// (generation, status) pair. The refusal is logged once and then the file is
// simply wrong for the rest of the process's life.
func TestARefusedPublishIsRetriedRatherThanRemembered(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "ech-state.json")
	answer := rotationAnswer(t, map[string][]byte{echSourceFirst: echFixture(t)})
	core, logs := observer.New(zapcore.DebugLevel)
	clock := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	provider, err := newECHProvider(echProviderOptions{
		upstream: "tcp://127.0.0.1:15353", statePath: statePath,
		sources: []string{echSourceFirst}, grace: 600 * time.Second, timeout: time.Second,
		logger: zap.New(core), now: func() time.Time { return clock },
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) {
			return &fakeECHUpstream{answer: answer}, nil
		},
		refreshEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("newECHProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	if _, err := provider.Config(t.Context()); err != nil {
		t.Fatalf("the first fetch: %v", err)
	}
	written := readECHState(t, statePath)

	// A blocker that makes the WRITE fail while the key is unchanged, and it is the
	// DIRECTORY rather than the file: a read-only directory refuses the staging file
	// the writer creates, which is the same failure a momentarily read-only
	// filesystem produces.
	//
	// The first version planted a document with a higher generation and then REMOVED
	// it, and proved nothing: with the file gone the next write has nothing to roll
	// back against and succeeds whether or not the provider remembered the refusal.
	// It also could not reach the property, which is about publishing THE SAME
	// (generation, status) PAIR a second time.
	directory := filepath.Dir(statePath)
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatalf("make the state directory read-only: %v", err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatalf("restore the state directory: %v", err)
			}
		}
	}
	t.Cleanup(restore)

	// A second fetch of a NEW key, so the pair to publish moves. The clock has to
	// move with it: a Config call on a fresh key returns the held one and publishes
	// nothing, which is how the first version of this case passed for the wrong
	// reason.
	clock = clock.Add(echRotationInterval + time.Second)
	if _, err := provider.Config(t.Context()); err != nil {
		t.Fatalf("the second fetch: %v", err)
	}
	refused := readECHState(t, statePath)
	if refused.Generation != written.Generation {
		t.Fatalf("the document moved to generation %d, want the %d the refused write left behind, "+
			"so this case is not exercising a refused publish", refused.Generation, written.Generation)
	}

	// The blocker is gone and the SAME key is still in service, so the next publish
	// is the same (generation, status) pair as the one that was refused. Before the
	// fix the provider had already recorded that pair as published and would skip
	// every later attempt at it for the rest of its life -- which is how one refused
	// write became a permanently wrong document.
	restore()
	if _, err := provider.Config(t.Context()); err != nil {
		t.Fatalf("a publish after the blocker was removed: %v", err)
	}
	document := readECHState(t, statePath)
	if document.Generation <= refused.Generation {
		t.Fatalf("the document is still at generation %d after a refused publish and a retry, so the "+
			"refusal was remembered and the same (generation, status) pair was never written again. "+
			"The journal said: %v", document.Generation, messagesOf(logs))
	}
}

// TestThePluginStartsTheBackgroundRefresher is the wiring, and it is a separate
// case because every provider case above calls startRefreshing ITSELF.
//
// That is how the first version of this file passed against a build where the
// plugin never started the refresher: each provider case drove its own ticker, so
// removing the one line in newPlugin that starts it changed nothing they could see.
// The line that matters in production is that one, and a case about the provider is
// not a case about it.
func TestThePluginStartsTheBackgroundRefresher(t *testing.T) {
	h, err := buildHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = rotationSources
		c.echAnswer = rotationAnswer(t, map[string][]byte{echSourceFirst: echFixture(t)})
		c.echRefreshEvery = testRefreshInterval
	})
	if err != nil {
		t.Fatalf("buildHarness: %v", err)
	}
	t.Cleanup(func() { _ = h.plugin.Close() })

	// No Exec, no Config, no client query: only the tick the plugin started.
	waitForRefresh(t, h.upstream, 1)
}

// Close has to mean the refresher has STOPPED, not that it has been asked to.
//
// A tick in flight publishes -- it writes the state document -- so a Close that
// returns while one is running is a Close that says "you may move this directory"
// to a goroutine that is about to write into it. This case was added because of a
// test-teardown flake on a CI machine, where the testing framework removed a
// temporary directory while the refresher was still writing into it and the message
// ("directory not empty") named nothing about the cause.
func TestCloseWaitsForTheRefresherToStop(t *testing.T) {
	const slowFetch = 150 * time.Millisecond
	entered := make(chan struct{}, 1)
	answer := rotationAnswer(t, map[string][]byte{echSourceFirst: echFixture(t)})
	// A fetch that is slow but BOUNDED, which is what a real one is -- it carries its
	// own timeout. An unbounded one would make this case deadlock against a Close that
	// waits correctly: the tick cannot finish until something releases it, and the
	// only thing that releases it would be the Close that is waiting for it.
	var finished atomic.Int64
	blocking := func(question dns.Question) (*dns.Msg, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		time.Sleep(slowFetch)
		finished.Add(1)
		return answer(question)
	}
	provider, _, _ := backgroundHarness(t, []string{echSourceFirst}, blocking, time.Hour)
	// Started by hand, the way the plugin's Config does it. The harness deliberately
	// does not start it, so a case about the refresher has to say it wants one.
	provider.startRefreshing()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the refresher never reached the upstream, so there is no tick to wait for")
	}

	if err := provider.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The assertion is that the fetch had FINISHED by the time Close returned, not
	// that no further fetch happened. That is the property, and it is falsifiable in
	// both directions: a Close that waits returns after the tick, so the count is 1;
	// a Close that only signals returns in microseconds, the tick is still sleeping,
	// and the count is 0.
	if got := finished.Load(); got != 1 {
		t.Errorf("a fetch that was in flight when Close was called had finished %d times by the "+
			"time Close returned, want 1: Close has to WAIT for the refresher to stop, because a "+
			"tick publishes, and a caller that moves the state directory on a Close that has only "+
			"signalled races a write into a directory that is going away", got)
	}
}

// Close twice is still once: the second call must not panic on a closed channel,
// and it must still be a call that returns only when the refresher has stopped.
func TestCloseTwiceIsStillSafe(t *testing.T) {
	provider, _, _ := backgroundHarness(t, []string{echSourceFirst},
		rotationAnswer(t, map[string][]byte{echSourceFirst: echFixture(t)}), time.Hour)
	if err := provider.Close(); err != nil {
		t.Fatalf("the first Close: %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
}

// --- helpers these cases use that the harness above does not ---

func trimDot(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
}

func indexOf(names []string, want string) int {
	for i, name := range names {
		if name == want {
			return i
		}
	}
	return -1
}

func askedNames(fake *fakeECHUpstream) []string {
	asked := fake.asked()
	names := make([]string, 0, len(asked))
	for _, query := range asked {
		names = append(names, trimDot(query.question.Name))
	}
	return names
}

func containsAll(text string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(text, part) {
			return false
		}
	}
	return true
}

// marshalPlanted is here rather than reusing whatever the harness marshals with,
// because the document these cases plant has to be byte-identical in SHAPE to what
// the provider wrote -- a hand-built JSON string would let a field this project has
// since added go missing and the refusal under test would then be a refusal for a
// different reason.
func marshalPlanted(t *testing.T, value state.ECHState) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal the planted document: %v", err)
	}
	return payload
}

// waitForGeneration polls the published document until its generation reaches
// `want`, and returns it. The document on disk is the thing under test here, so
// waiting on the document is waiting on the behaviour rather than on a proxy for
// it -- a case that waited on the upstream instead would be reading the request
// rather than the answer.
func waitForGeneration(t *testing.T, statePath string, want uint64) state.ECHState {
	t.Helper()
	deadline := time.Now().Add(refreshDeadline)
	var last state.ECHState
	for {
		if err := state.ReadJSON(statePath, &last); err == nil && last.Generation >= want {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("the published document reached generation %d within %s, want %d: a background "+
				"refresh that fetched a key and published nothing leaves an operator reading a document "+
				"about a key nobody is serving", last.Generation, refreshDeadline, want)
		}
		time.Sleep(testRefreshInterval)
	}
}

func messagesOf(logs *observer.ObservedLogs) []string {
	var out []string
	for _, entry := range logs.All() {
		out = append(out, entry.Level.String()+": "+entry.Message)
	}
	return out
}
