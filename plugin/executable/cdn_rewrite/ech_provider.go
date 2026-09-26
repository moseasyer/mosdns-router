package cdn_rewrite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"mosdns-router/internal/echconfig"
	"mosdns-router/internal/state"
)

// echProvider holds the ECHConfigList a force-ECH answer is built from, and keeps
// it current without ever putting a client's query through this router's own
// sequence.
//
// Four decisions make it what it is, and each of them is a place where the
// obvious alternative costs a client its privacy rather than its speed.
//
// The first is the transport. The key is fetched with a client of this plugin's
// own, pointed at the same loopback DNSCrypt listener the foreign forward uses,
// over TCP. It is not fetched by calling ExecNext, and it is not fetched over
// mosdns's stock UDP upstream: re-entering the sequence would classify and
// possibly rewrite the key's own answer, and the UDP transport re-sends a query
// that has gone unanswered for a second and can drop an answer that arrived early.
// Neither fault is one this plugin could report, because in both cases the key
// simply does not arrive, and a strict name then fails closed for as long as the
// last key lasts.
//
// The second is that the bytes stay in memory. A public HPKE key is not a secret,
// but a document every process on the host can read is not the place for the one
// value this router must hand to exactly the clients it chose, so ech-state.json
// records the source, the times, the digest and the public name and never a byte
// of the list.
//
// The third is the lifetime. A key is good for as long as the upstream's TTL says
// and no longer, with a floor under that TTL so a source publishing thirty
// seconds is not fetched once per client query. After the TTL the last key keeps
// serving for the policy's stale grace, which is the difference between a source
// that was briefly unreachable and a source that is gone, and after the grace
// there is nothing and a strict name fails closed.
//
// The fourth is that every configured source has to agree. A list from one source
// beside a different public name from another leaves a client unable to say which
// name it is authenticating, so a disagreement is a refusal rather than a
// preference: strict mode does not use them. A source that cannot be reached at
// all fails the refresh as well, and the last key is what keeps serving until its
// grace ends, which is the direction that costs a refresh rather than a key.

// echFetchTimeout is the documented default bound on one exchange with the ECH
// source. The plugin's constructor may pass a shorter one; nothing may pass a
// longer one, because the fetch is on the path of a client's HTTPS query and a
// stalled listener has to cost that client its own timeout rather than the whole
// sequence's.
const echFetchTimeout = 3 * time.Second

// minimumECHRefresh is the floor under the upstream's TTL. A key fetched more
// often than this spends a query per client query, on the listener this router
// forwards every foreign query through.
const minimumECHRefresh = 60 * time.Second

// The three states a held key can be in, spelled as the state document spells
// them, so the file an operator reads and the answer a client gets come out of
// one decision rather than two that can disagree.
const (
	echStatusFresh   = "fresh"
	echStatusStale   = "stale"
	echStatusInvalid = "invalid"
)

// The refusals a fetch makes. They are this layer's own because this is the layer
// that knows whether there was anything to fetch: a caller that cannot tell "the
// source is unreachable" from "the source published nothing usable" cannot decide
// whether to keep serving the last key.
var (
	// ErrNoECHSource means the policy names no source, so there is nothing to
	// query and no key can ever arrive.
	ErrNoECHSource = errors.New(PluginType + ": the policy names no ECH source")
	// ErrECHUnusable means a source answered and this router will not forward
	// what it published: no ech parameter, more than one record, a list this
	// build will not parse, or a public name a client could not authenticate.
	ErrECHUnusable = errors.New(PluginType + ": the ECH source published nothing this router will forward")
	// ErrECHExpired means the last key is past its stale grace, so there is
	// nothing left to serve and a strict name has to fail closed.
	ErrECHExpired = errors.New(PluginType + ": the last usable ECH key is past its stale grace")
)

// echProviderOptions are the provider's dependencies. Every one of them is
// injected, so a test can name its own clock, hand it a client that records what
// it was asked, and read what it logged.
type echProviderOptions struct {
	upstream  string
	statePath string
	sources   []string
	grace     time.Duration
	timeout   time.Duration
	logger    *zap.Logger
	now       func() time.Time
	newClient func(addr string, opt upstream.Opt) (upstream.Upstream, error)
}

// echConfig is one key this router is holding and everything about it except the
// bytes: where they came from, when, how long they are good for, and the public
// name the sources agreed a client authenticates.
type echConfig struct {
	raw        []byte
	source     string
	publicName string
	digest     string
	fetchedAt  time.Time
	expiresAt  time.Time
	staleUntil time.Time
	generation uint64
}

// echProvider holds the current key and the state of the last fetch. Its own
// mutex serialises the freshness decision, and the fetch itself runs outside it,
// with one fetch at a time: a client's first HTTPS query after a boot arrives
// with the rest of its tab's queries, and each of them must not put its own key
// lookup on the listener.
type echProvider struct {
	addr      string
	client    upstream.Upstream
	statePath string
	sources   []string
	grace     time.Duration
	timeout   time.Duration
	logger    *zap.Logger
	now       func() time.Time
	// nextID numbers this provider's own queries. The id is never a client's: a
	// fetch is not a transaction anybody is waiting on, and a fixed zero would be
	// a fingerprint on every key this router fetches.
	nextID atomic.Uint32

	mu         sync.Mutex
	current    echConfig
	have       bool
	refreshing bool
	finished   chan struct{}
	// published is what the metadata document on disk was last written from, so a
	// document that would be byte-identical is not written again and an older
	// snapshot cannot replace a newer one.
	published publishedKey
	// bytes counts every payload this provider has read. No budget in this
	// project accounts for it -- the daily budget governs the optimizer's
	// measurement transfers and belongs to another process -- so it is counted
	// here and reported with each fetch, which is the honesty the health check's
	// identity-body-bytes line is for.
	bytes int64

	closeOnce sync.Once
	closed    chan struct{}
}

// newECHProvider builds the provider and its client. Every refusal it makes is a
// construction refusal, because a plugin's Init is the only place a mistake is
// reported to the operator who can fix it.
func newECHProvider(o echProviderOptions) (*echProvider, error) {
	if strings.TrimSpace(o.statePath) == "" {
		return nil, errors.New("the ECH state path must not be empty")
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.logger == nil {
		o.logger = zap.NewNop()
	}
	if o.timeout <= 0 {
		o.timeout = echFetchTimeout
	}
	if o.grace < 0 {
		return nil, fmt.Errorf("the ECH stale grace must not be negative, got %s", o.grace)
	}
	if len(o.sources) == 0 {
		return nil, ErrNoECHSource
	}
	if o.newClient == nil {
		o.newClient = func(addr string, opt upstream.Opt) (upstream.Upstream, error) { return upstream.NewUpstream(addr, opt) }
	}
	client, err := o.newClient(o.upstream, upstream.Opt{Logger: o.logger})
	if err != nil {
		return nil, fmt.Errorf("the ECH source client for %s: %w", o.upstream, err)
	}
	return &echProvider{
		addr:      o.upstream,
		client:    client,
		statePath: o.statePath,
		sources:   append([]string(nil), o.sources...),
		grace:     o.grace,
		timeout:   o.timeout,
		logger:    o.logger,
		now:       o.now,
		closed:    make(chan struct{}),
	}, nil
}

// Config returns the key a force-ECH answer should carry, or the refusal that says
// there is none. The two are separate returns because the caller has to act on the
// difference: a key that has never been fetched is a fetch worth making, and a key
// past its grace is not.
//
// Four states, and each is a different answer rather than a variation on one:
//
//   - nothing held yet: fetch, and a failure is a failure.
//   - held and fresh: the held key, with no query at all.
//   - held and past its lifetime but inside the grace: a refresh is attempted,
//     because that is what the grace is for, and a refresh that fails leaves the
//     held key in service. The failure is reported, so an operator sees that the
//     source has gone rather than only that a key is old.
//   - held and past the grace: the same refresh attempt, and a failure means there
//     is nothing left to serve, which is ErrECHExpired and a strict name failing
//     closed.
//
// A fifth case falls between them, and it is the reason the loop below runs twice
// rather than once: a caller that LOST a race with another caller. It must not
// answer from anything it read before the race -- on a cold start that snapshot is
// an empty key, and returning it means a strict force-ECH name gets SERVFAIL over a
// key that was fetched successfully a moment earlier. So a caller that waited
// re-reads the stored value and decides from that, and the sentinel surfaces only
// when there is genuinely still nothing.
//
// The bound is two attempts, and each is a real fetch rather than a spin -- but only
// when the wait actually bought something. What it bought is a generation: only a
// fetch that stored a key moves one, and a move is the only difference between the
// snapshot a caller read before the wait and the one it would read after. When the
// generation moved, the winner succeeded, the key this caller would re-read is not
// the empty one it started with, and the retry is what saves a strict name from
// answering SERVFAIL over a key that is sitting right there.
//
// When the generation did NOT move, the fetch this caller waited for stored nothing,
// so re-reading finds the same value the caller already had and a second fetch buys
// no information at all. It costs a whole exchange on the listener every foreign
// query in this router depends on, paid by one caller at a time because the single
// flight is still serialising them, and it reports a source fault to callers that
// never read the source -- which is the shape a dead ECH source turns eight
// concurrent force-ECH queries into. So that case falls through to the held-key
// decision below: the last key in service if there is one and its grace has not
// ended, ErrECHExpired if it has, and the failure itself if nothing was ever held.
func (e *echProvider) Config(ctx context.Context) ([]byte, error) {
	var lastFailure error
	for attempt := 0; attempt < 2; attempt++ {
		e.mu.Lock()
		held, have := e.current, e.have
		// The generation is read here, before the wait, because after the wait it is
		// the only thing that says whether the wait changed anything. Read it
		// afterwards and it is always the winner's.
		before := e.current.generation
		status := ""
		if have {
			status = e.statusLocked()
		}
		e.mu.Unlock()

		if have && status == echStatusFresh {
			// The document is written outside the lock, and once per transition, so
			// a query does not queue behind a file write and an unchanged key has
			// nothing new to say.
			e.publish(echStatusFresh, held)
			return held.raw, nil
		}

		fetched, err := e.fetchOnce(ctx)
		if err == nil {
			e.publish(echStatusFresh, fetched)
			return fetched.raw, nil
		}
		if errors.Is(err, errECHNotRefetched) && e.generationMoved(before) {
			// Another caller fetched the key and it was stored, so this caller
			// re-reads the stored value at the top of the loop instead of deciding
			// from anything it read before the wait, which is the only way a loser
			// gets the key just published.
			continue
		}
		lastFailure = err
		if !have {
			// Nothing was held and nothing could be fetched, so there is nothing to
			// fall back on and the failure is the answer.
			e.logFetchFailure(err)
			return nil, err
		}
		e.publish(status, held)
		if status == echStatusInvalid {
			return nil, fmt.Errorf("%w: it expired at %s and its grace ended at %s",
				ErrECHExpired,
				held.expiresAt.Format(time.RFC3339), held.staleUntil.Format(time.RFC3339))
		}
		return held.raw, nil
	}
	// Two attempts and no usable key. The failure this caller last saw is the one to
	// report; a caller that never saw one was only ever told to re-read, and the
	// value it found there is the one it had already read.
	if lastFailure == nil {
		lastFailure = errECHNotRefetched
	}
	e.logFetchFailure(lastFailure)
	return nil, lastFailure
}

// generationMoved reports whether any key has been stored since the caller's reading
// of the generation it was handed. It is the whole of what a wait can be worth: a
// stored key and no stored key are the two outcomes, and only a stored key moves the
// counter, so this is false exactly when the fetch this caller waited for failed.
func (e *echProvider) generationMoved(before uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current.generation != before
}

// logFetchFailure reports a refresh that did not happen. It is a separate function
// because a caller that waited on somebody else's fetch and then found nothing
// stored has not itself failed to read the source, and saying so would report a
// source fault that may never have happened.
func (e *echProvider) logFetchFailure(err error) {
	if errors.Is(err, errECHNotRefetched) {
		return
	}
	e.logger.Warn("cdn_rewrite: the ECH source could not be read; the last usable key stands until its grace ends",
		zap.String("upstream", e.addr), zap.Error(err))
}

// fetchOnce reads every source, with one fetch at a time. A caller that arrives
// while a fetch is running waits for it rather than starting its own: a client's
// first HTTPS query after a boot arrives with the rest of its tab's queries, and
// each of them would otherwise put its own key lookup on the listener this router
// forwards everything else through.
func (e *echProvider) fetchOnce(ctx context.Context) (echConfig, error) {
	e.mu.Lock()
	if e.refreshing {
		finished := e.finished
		e.mu.Unlock()
		select {
		case <-finished:
		case <-ctx.Done():
			return echConfig{}, context.Cause(ctx)
		case <-e.closed:
			return echConfig{}, errClosed
		}
		// The fetch that was running has stored its result or has not, and this
		// caller has to decide from the stored value rather than from the other
		// caller's error -- which is why the wait is a retry and not a return.
		return echConfig{}, errECHNotRefetched
	}
	e.refreshing = true
	e.finished = make(chan struct{})
	finished := e.finished
	e.mu.Unlock()

	fetched, err := e.fetch(ctx)

	e.mu.Lock()
	if err == nil {
		e.current = fetched
		e.have = true
	}
	e.refreshing = false
	close(finished)
	e.mu.Unlock()
	return fetched, err
}

// errECHNotRefetched says the fetch this call was waiting for has finished and
// this call did not do it. It never reaches a query: Config's loop reads the stored
// value again and decides from that.
var errECHNotRefetched = errors.New(PluginType + ": another caller fetched the key; read it again")

// statusLocked is the freshness decision, and the three answers are the three the
// state document has. It must be called with the lock held.
func (e *echProvider) statusLocked() string {
	now := e.now()
	switch {
	case now.Before(e.current.expiresAt):
		return echStatusFresh
	case now.Before(e.current.staleUntil):
		return echStatusStale
	default:
		return echStatusInvalid
	}
}

// fetch reads every configured source and returns the one list they agree on.
//
// Every source is queried, not just the first that answers, because the agreement
// is the point: a list from one source beside a different public name from another
// leaves a client unable to say which name it is authenticating, and picking one
// is a decision no component of this router is placed to make. A source that could
// not be read fails the refresh as a whole, so the last key is what keeps serving
// until its grace ends.
func (e *echProvider) fetch(ctx context.Context) (echConfig, error) {
	fetched := echConfig{fetchedAt: e.now()}
	agreed := true
	for _, source := range e.sources {
		list, ttl, err := e.fetchOne(ctx, source)
		if err != nil {
			return echConfig{}, err
		}
		name := list.Configs[0].PublicName
		if fetched.source == "" {
			fetched.source = source
			fetched.raw = list.Raw
			fetched.publicName = name
			fetched.expiresAt = fetched.fetchedAt.Add(refreshAfter(ttl))
			fetched.staleUntil = fetched.expiresAt.Add(e.grace)
			digest := sha256.Sum256(list.Raw)
			fetched.digest = hex.EncodeToString(digest[:])
			continue
		}
		if name != fetched.publicName {
			agreed = false
			e.logger.Error("cdn_rewrite: the ECH sources disagree about the public name, so no key is used",
				zap.String("source", source), zap.String("public_name", name),
				zap.String("kept_source", fetched.source), zap.String("kept_public_name", fetched.publicName))
		}
	}
	if !agreed {
		return echConfig{}, fmt.Errorf("%w: the configured sources name different public names", ErrECHUnusable)
	}

	e.mu.Lock()
	fetched.generation = e.current.generation + 1
	e.bytes += int64(len(fetched.raw))
	read := e.bytes
	e.mu.Unlock()
	e.logger.Info("cdn_rewrite: fetched an ECH key",
		zap.String("source", fetched.source),
		zap.String("public_name", fetched.publicName),
		zap.Int("sources", len(e.sources)),
		zap.Duration("refresh_after", fetched.expiresAt.Sub(fetched.fetchedAt)),
		zap.Int64("ech-fetch-bytes", read))
	return fetched, nil
}

// fetchOne reads one source's HTTPS record and returns the validated list with
// the TTL it was published under.
//
// The query is built here rather than taken from a client's context: it has its
// own id, because it is not a transaction any client is waiting on, and its own
// EDNS0 buffer, because a source publishing an ech parameter beside hints for
// every address it anycasts answers with a message that does not fit in the 512
// bytes a query without EDNS0 may ask for.
func (e *echProvider) fetchOne(ctx context.Context, source string) (*echconfig.List, uint32, error) {
	query := new(dns.Msg)
	query.Id = uint16(e.nextID.Add(1))
	query.RecursionDesired = true
	query.Question = []dns.Question{{Name: dns.Fqdn(source), Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET}}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	query.Extra = append(query.Extra, opt)

	payload, err := query.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("%s: build the ECH query: %w", source, err)
	}
	attempt, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	answer, err := e.client.ExchangeContext(attempt, payload)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: ask for its HTTPS record: %w", source, err)
	}
	defer pool.ReleaseBuf(answer)

	response := new(dns.Msg)
	if err := response.Unpack(*answer); err != nil {
		return nil, 0, fmt.Errorf("%s: read its answer: %w", source, err)
	}
	if !response.Response || response.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("%s: it answered %s, which publishes no key", source, dns.RcodeToString[response.Rcode])
	}
	return echListFrom(response, source)
}

// echListFrom takes the one validated list out of a source's answer, and refuses
// every shape this router will not forward.
//
// The record has to be the source's own name in the IN class, there has to be
// exactly one of it, and its ech parameter has to be there exactly once. One
// record is a requirement rather than a simplification: two HTTPS records for one
// name are two descriptions of a service and this router does not choose between
// them. The list is validated by the parser every other consumer of these bytes
// uses, so the bytes installed in an answer are the bytes that were checked, and a
// public name a client could not authenticate is refused rather than forwarded.
func echListFrom(response *dns.Msg, source string) (*echconfig.List, uint32, error) {
	records := make([]*dns.HTTPS, 0, 2)
	for _, rr := range response.Answer {
		record, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		if !strings.EqualFold(record.Hdr.Name, dns.Fqdn(source)) || record.Hdr.Class != dns.ClassINET {
			return nil, 0, fmt.Errorf("%w: %s published an HTTPS record at %q, which is not its own name in the IN class",
				ErrECHUnusable, source, record.Hdr.Name)
		}
		records = append(records, record)
	}
	if len(records) != 1 {
		return nil, 0, fmt.Errorf("%w: %s published %d HTTPS records, want exactly one", ErrECHUnusable, source, len(records))
	}
	record := records[0]
	if record.Priority == 0 {
		return nil, 0, fmt.Errorf("%w: %s published an alias, so its key is described under another name", ErrECHUnusable, source)
	}
	var (
		list *echconfig.List
		ttl  uint32
	)
	for _, pair := range record.Value {
		ech, ok := pair.(*dns.SVCBECHConfig)
		if !ok {
			continue
		}
		if list != nil {
			return nil, 0, fmt.Errorf("%w: %s published two ech parameters, which no client can read", ErrECHUnusable, source)
		}
		parsed, err := echconfig.Parse(ech.ECH)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %s: %w", ErrECHUnusable, source, err)
		}
		if err := consistentPublicName(parsed); err != nil {
			return nil, 0, fmt.Errorf("%w: %s: %w", ErrECHUnusable, source, err)
		}
		list, ttl = parsed, record.Hdr.Ttl
	}
	if list == nil {
		return nil, 0, fmt.Errorf("%w: %s published an HTTPS record with no ech parameter", ErrECHUnusable, source)
	}
	return list, ttl, nil
}

// consistentPublicName refuses a list whose configs do not all name the same
// client-facing server. RFC 9849 lets a list carry several configs and a client
// authenticates the public name inside the one it picked, so two names in one
// list is a client told two different things about who it is talking to.
func consistentPublicName(list *echconfig.List) error {
	name := list.Configs[0].PublicName
	for _, config := range list.Configs[1:] {
		if config.PublicName != name {
			return fmt.Errorf("the list names two public names, %q and %q, so a client cannot say which one it authenticates", name, config.PublicName)
		}
	}
	return nil
}

// refreshAfter is how long a fetched key is good for: the TTL the source
// published, with a floor under it.
func refreshAfter(ttl uint32) time.Duration {
	lifetime := time.Duration(ttl) * time.Second
	if lifetime < minimumECHRefresh {
		return minimumECHRefresh
	}
	return lifetime
}

// publish writes the metadata document for a key in a known state.
//
// What decides whether a write happens is the CONTENT of the document, not the
// status word. A status-only rule froze the file after the first fetch: every
// successful refresh publishes "fresh", so nothing after the first document was
// ever written, and the file went on describing the first key's expiry -- in the
// past -- and the first key's digest while the router served a newer one. An
// operator reading it, or `mosdns-cdnctl status`, was shown a document about a key
// no longer in service. So the comparison is against everything the document says
// about the key: its generation, which moves with the fetched, expiry and grace
// times and with the digest, and the status, which one key changes on its own as it
// ages.
//
// The generation settles the one race there is. Two callers can be inside publish
// with different snapshots -- the fetcher with the key it just stored, and a waiter
// with an older one it read before waiting -- and the older one must not be what is
// on disk. The rule is the highest generation wins, and it is exact rather than a
// heuristic: a generation comes from the provider's own counter under its lock, and
// only a fetch that stored a key has one, so two snapshots of different generations
// are two different keys and the newer one is the key in service. The strict state
// writer would refuse a rollback in any case, so the loser was safe -- but a
// refusal that logs a warning is not a mechanism.
//
// A write that fails is reported and swallowed: the document is what an operator
// reads, and a router that stopped serving force-ECH names because a state file
// could not be written would trade a client's privacy for a log line nobody asked
// for.
func (e *echProvider) publish(status string, current echConfig) {
	if current.source == "" {
		return
	}
	e.mu.Lock()
	switch {
	case current.generation < e.published.generation:
		// A newer key is already the document on disk, so this snapshot is some
		// caller's older reading of a key that has since been replaced.
		e.mu.Unlock()
		return
	case current.generation == e.published.generation && status == e.published.status:
		// The same key in the same state: the document would be byte-identical.
		e.mu.Unlock()
		return
	}
	e.published = publishedKey{generation: current.generation, status: status}
	e.mu.Unlock()

	document := state.NewECHState(
		current.generation,
		current.source,
		current.fetchedAt,
		current.expiresAt,
		current.staleUntil,
		current.digest,
		current.publicName,
		status,
	)
	if err := state.WriteJSONAtomic(e.statePath, document); err != nil {
		e.logger.Warn("cdn_rewrite: the ECH state document could not be written; the key itself is unaffected",
			zap.String("path", e.statePath), zap.Error(err))
	}
}

// publishedKey is what the document on disk was last written from. The generation
// is the whole of it: it changes with every fetch, and it carries the times and the
// digest because those are properties of the key it was assigned to. The status is
// beside it because one key changes status as it ages -- fresh, then stale, then
// invalid -- without its generation moving, and each of those is a different
// document.
type publishedKey struct {
	generation uint64
	status     string
}

// Close releases the client. It is idempotent, and a Config call that arrives
// after it is refused rather than dialling a client that is gone.
func (e *echProvider) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.closed)
		err = e.client.Close()
	})
	return err
}
