package dhcp_forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"mosdns-router/internal/state"
	"mosdns-router/internal/testdns"
)

// testInterface is the interface a published state names. It is only used to
// scope a bare IPv6 link-local upstream.
const testInterface = "enp3s0"

func TestForwardsToCurrentDHCPGeneration(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.10", 30))
	forward, published := newTestForwardForServer(t, Args{}, upstream)

	response := exec(t, forward, "www.example.com.", dns.TypeA)

	if got := answersOf(t, response); len(got) != 1 || got[0] != "192.0.2.10" {
		t.Fatalf("answers = %v, want [192.0.2.10]", got)
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
	if got := response.Question[0].Name; got != "www.example.com." {
		t.Fatalf("question = %q, want www.example.com.", got)
	}
	queries := upstream.Queries()
	if len(queries) != 1 {
		t.Fatalf("upstream received %d queries, want 1: %+v", len(queries), queries)
	}
	if queries[0].QName != "www.example.com." || queries[0].QType != dns.TypeA || queries[0].QClass != dns.ClassINET {
		t.Fatalf("upstream saw %+v, want an IN A question for www.example.com.", queries[0])
	}
	if queries[0].Protocol != testdns.ProtocolUDP {
		t.Fatalf("upstream saw %q, want the first attempt over udp", queries[0].Protocol)
	}
	if got := published.generation(); got != 1 {
		t.Fatalf("the plugin served generation %d, want 1", got)
	}
}

func TestCachesSuccessfulResponseWithinGeneration(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.11", 30))
	forward, published := newTestForwardForServer(t, Args{}, upstream)

	first := exec(t, forward, "cached.example.com.", dns.TypeA)
	second := exec(t, forward, "cached.example.com.", dns.TypeA)
	third := exec(t, forward, "another.example.com.", dns.TypeA)

	if got := answersOf(t, second); len(got) != 1 || got[0] != "192.0.2.11" {
		t.Fatalf("second answers = %v, want [192.0.2.11]", got)
	}
	if first.Answer[0].Header().Ttl != 30 || second.Answer[0].Header().Ttl != 30 {
		t.Fatalf("ttls = %d and %d, want 30 and 30", first.Answer[0].Header().Ttl, second.Answer[0].Header().Ttl)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "cached.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries, want 1: the second query must come from the cache", count)
	}
	if reads := published.readCount(); reads != 1 {
		t.Fatalf("the state file was read %d times, want 1: an unchanged file is not re-read for every query", reads)
	}
	if got := answersOf(t, third); len(got) != 1 || got[0] != "192.0.2.11" {
		t.Fatalf("third answers = %v, want [192.0.2.11]", got)
	}
}

func TestBoundedCacheEvictsWhenItIsFull(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.61", 300))
	forward, _ := newTestForward(t, Args{CacheEntries: 1}, []string{hostOf(t, upstream)}, portOf(t, upstream))

	first := exec(t, forward, "a.bounded.example.com.", dns.TypeA)
	exec(t, forward, "b.bounded.example.com.", dns.TypeA)
	again := exec(t, forward, "a.bounded.example.com.", dns.TypeA)

	for name, response := range map[string]*dns.Msg{"first": first, "repeated": again} {
		if got := answersOf(t, response); len(got) != 1 || got[0] != "192.0.2.61" {
			t.Fatalf("%s answers = %v, want [192.0.2.61]", name, got)
		}
	}
	if count := upstream.Count(testdns.ProtocolUDP, "a.bounded.example.com."); count != 2 {
		t.Fatalf("upstream received %d queries for the first name, want 2: the single cache slot had to be given up", count)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "b.bounded.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries for the second name, want 1", count)
	}
}

func TestRemovedStateFileKeepsTheCurrentGeneration(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.62", 300))
	forward, published := newTestForwardForServer(t, Args{}, upstream)

	exec(t, forward, "before-removal.example.com.", dns.TypeA)
	if err := os.Remove(published.path); err != nil {
		t.Fatalf("remove the state file: %v", err)
	}
	after := exec(t, forward, "after-removal.example.com.", dns.TypeA)

	if got := answersOf(t, after); len(got) != 1 || got[0] != "192.0.2.62" {
		t.Fatalf("answers = %v, want the last valid generation's answer", got)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "after-removal.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries, want 1", count)
	}
	if reads := published.readCount(); reads != 1 {
		t.Fatalf("the state file was read %d times, want 1: a file that is not there is not read again", reads)
	}
}

func TestStateFileSignatureTracksFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	document := []byte(`{"schema_version":1,"generation":1}`)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write the state document: %v", err)
	}
	before, err := statStateFile(path)
	if err != nil {
		t.Fatalf("stat the state file: %v", err)
	}

	// The same bytes published again at the same instant, the way a publisher
	// that renames a fresh temporary file over its target can do.
	replacement := path + ".next"
	if err := os.WriteFile(replacement, document, 0o600); err != nil {
		t.Fatalf("write the replacement document: %v", err)
	}
	if err := os.Chtimes(replacement, before.modTime, before.modTime); err != nil {
		t.Fatalf("set the replacement times: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("rename the replacement: %v", err)
	}

	after, err := statStateFile(path)
	if err != nil {
		t.Fatalf("stat the renamed state file: %v", err)
	}
	if after.size != before.size {
		t.Fatalf("the setup changed the size from %d to %d, want it unchanged", before.size, after.size)
	}
	if !after.modTime.Equal(before.modTime) {
		t.Fatalf("the setup changed the modification time from %s to %s, want it unchanged", before.modTime, after.modTime)
	}
	if before.sameAs(after) {
		t.Fatal("a renamed file with the same size and modification time looks like the file it replaced")
	}

	unchanged, err := statStateFile(path)
	if err != nil {
		t.Fatalf("stat the state file again: %v", err)
	}
	if !after.sameAs(unchanged) {
		t.Fatal("a file that was not touched looks changed, so every query would read it again")
	}

	// The other direction: a document rewritten in place keeps its identity, so
	// only its timestamp distinguishes it from the one it replaced.
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("rewrite the state document: %v", err)
	}
	if err := os.Chtimes(path, before.modTime.Add(time.Second), before.modTime.Add(time.Second)); err != nil {
		t.Fatalf("set the rewritten times: %v", err)
	}
	rewritten, err := statStateFile(path)
	if err != nil {
		t.Fatalf("stat the rewritten state file: %v", err)
	}
	if rewritten.sameAs(unchanged) {
		t.Fatal("a document rewritten in place with the same length looks unchanged")
	}
}

// TestCacheHitCarriesTheCurrentQueryIdentity pins the transaction identity of a
// cached answer. The entry is a response to whichever query fetched it, so the
// second client for one name has to be answered with its own id and its own
// question: a client that drops a response because the id is another
// transaction's, or because the question inside it is a different one, treats a
// correct answer as an error.
func TestCacheHitCarriesTheCurrentQueryIdentity(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.71", 30))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	first := exec(t, forward, "identity.example.com.", dns.TypeA, withID(0x1234))
	second := exec(t, forward, "identity.example.com.", dns.TypeA, withID(0x5678))

	if first.Id != 0x1234 {
		t.Fatalf("first response id = %#x, want the query's %#x", first.Id, 0x1234)
	}
	if second.Id != 0x5678 {
		t.Fatalf("cached response id = %#x, want the second query's %#x", second.Id, 0x5678)
	}
	if got := second.Question[0].Name; got != "identity.example.com." {
		t.Fatalf("cached question = %q, want the current query's question", got)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "identity.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries, want 1: the second must come from the cache", count)
	}
}

// TestCacheSeparatesTheQuestionCase pins 0x20: the case a client sent is part of
// the question, an upstream may answer the two cases differently, and the
// response echoes the case the client used. A key that lowercased the name would
// serve one client's case to the other.
func TestCacheSeparatesTheQuestionCase(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.72", 30))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	exec(t, forward, "Www.Example.com.", dns.TypeA, withID(0x0001))
	exec(t, forward, "www.example.com.", dns.TypeA, withID(0x0002))
	again := exec(t, forward, "Www.Example.com.", dns.TypeA, withID(0x0003))

	if count := upstream.Count(testdns.ProtocolUDP, ""); count != 2 {
		t.Fatalf("upstream received %d queries, want 2: the two cases are two questions", count)
	}
	if got := again.Question[0].Name; got != "Www.Example.com." {
		t.Fatalf("cached question = %q, want the case this client asked in", got)
	}
	if again.Id != 0x0003 {
		t.Fatalf("cached response id = %#x, want %#x", again.Id, 0x0003)
	}
}

// TestCacheSeparatesTheAuthenticatedDataBit pins the AD bit in the key. The
// upstream reports the identity of the request it answered, so an entry served to
// a client that did not ask for validated data shows up in the answer itself and
// not only in the query count.
func TestCacheSeparatesTheAuthenticatedDataBit(t *testing.T) {
	upstream := startServer(t, reportIdentity)
	forward, _ := newTestForward(t, Args{}, []string{hostOf(t, upstream)}, portOf(t, upstream))

	plain := exec(t, forward, "authenticated.example.com.", dns.TypeA)
	checked := exec(t, forward, "authenticated.example.com.", dns.TypeA, withAD(true))
	repeat := exec(t, forward, "authenticated.example.com.", dns.TypeA, withAD(true))

	for _, check := range []struct {
		what     string
		response *dns.Msg
		want     string
	}{
		{"plain", plain, "plain"},
		{"authenticated data", checked, "plain+ad"},
		{"repeated authenticated data", repeat, "plain+ad"},
	} {
		if got := reportedIdentities(t, check.response); len(got) != 1 || got[0] != check.want {
			t.Fatalf("%s answer = %v, want [%s]", check.what, got, check.want)
		}
	}
	if count := upstream.Count(testdns.ProtocolUDP, "authenticated.example.com."); count != 2 {
		t.Fatalf("upstream received %d queries, want 2: the ad bit is part of the cache key", count)
	}
}

// bufferLedger counts the pooled buffers the UDP client takes and gives back.
//
// pool.GetBuf and pool.ReleaseBuf are package variables, so the real allocator
// still does the real allocating and this only observes the two ends of the
// lifecycle. That is the whole invariant: a buffer that is never returned is a
// fresh 64 KiB allocation for every timed-out query, and a buffer returned twice
// is one buffer owned by two exchanges.
type bufferLedger struct {
	mu       sync.Mutex
	taken    int
	returned int
}

func (l *bufferLedger) install(t *testing.T) {
	t.Helper()
	realGet, realRelease := pool.GetBuf, pool.ReleaseBuf
	l.mu.Lock()
	l.taken, l.returned = 0, 0
	l.mu.Unlock()
	pool.GetBuf = func(size int) *[]byte {
		l.mu.Lock()
		l.taken++
		l.mu.Unlock()
		return realGet(size)
	}
	pool.ReleaseBuf = func(payload *[]byte) {
		l.mu.Lock()
		l.returned++
		l.mu.Unlock()
		realRelease(payload)
	}
	t.Cleanup(func() {
		pool.GetBuf, pool.ReleaseBuf = realGet, realRelease
	})
}

func (l *bufferLedger) counts() (taken, returned int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.taken, l.returned
}

// TestUDPExchangeReturnsEveryPooledBufferItTakes covers both ends of the one
// buffer a UDP exchange owns. The reader goroutine writes the answer into a
// 64 KiB pooled buffer, so a context that expires while the read is outstanding
// is the one path where the reader has produced nothing to hand over: the buffer
// has to go back to the pool from the goroutine that was writing into it, and a
// successful exchange has to return its buffer exactly once. A leak here is not a
// slow path, it is an allocation per query that timed out.
func TestUDPExchangeReturnsEveryPooledBufferItTakes(t *testing.T) {
	ledger := &bufferLedger{}
	ledger.install(t)

	// A socket that receives the query and never answers it, so the read stays
	// outstanding until the deadline fires.
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open the black hole socket: %v", err)
	}
	t.Cleanup(func() { _ = blackhole.Close() })

	query := new(dns.Msg)
	query.SetQuestion("pooled.example.com.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack the query: %v", err)
	}

	const abandoned = 20
	abandoning := &udpClient{target: blackhole.LocalAddr().(*net.UDPAddr)}
	for range abandoned {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		payload, err := abandoning.ExchangeContext(ctx, wire)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("exchange error = %v, want the context deadline: the abandoned read was not the path taken", err)
		}
		if payload != nil {
			t.Fatalf("a cancelled exchange returned %d bytes, want none", len(*payload))
		}
	}
	if taken, returned := ledger.counts(); taken == 0 || returned != taken {
		t.Fatalf("%d cancelled exchanges returned %d of the %d pooled buffers they took: "+
			"an abandoned read buffer is never given back", abandoned, returned, taken)
	}

	// The other end: a buffer that was handed over is the caller's, and the
	// caller gives it back once. A second release would put one buffer into the
	// pool twice, so the next exchange would read into memory another one owns.
	upstream := startServer(t, answerWith("192.0.2.73", 30))
	target, err := net.ResolveUDPAddr("udp", upstream.Address())
	if err != nil {
		t.Fatalf("resolve the answering server: %v", err)
	}
	answer, err := (&udpClient{target: target}).ExchangeContext(t.Context(), wire)
	if err != nil {
		t.Fatalf("exchange against the answering server: %v", err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(*answer); err != nil {
		t.Fatalf("the returned buffer does not hold a complete message: %v", err)
	}
	pool.ReleaseBuf(answer)
	if taken, returned := ledger.counts(); returned != taken {
		t.Fatalf("the exchanges so far returned %d of the %d pooled buffers they took: "+
			"a buffer is released twice or not at all", returned, taken)
	}
}

func TestGenerationReplacedByRenameWithTheSameSizeAndTimeIsObserved(t *testing.T) {
	replaced := startServer(t, answerWith("192.0.2.63", 300))
	replacement := samePortServer(t, replaced, "127.0.0.2", answerWith("198.51.100.63", 300))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, replaced)}, portOf(t, replaced))

	first := exec(t, forward, "renamed.example.com.", dns.TypeA)
	publishByRename(t, published, 2, true, hostOf(t, replacement))
	second := exec(t, forward, "renamed.example.com.", dns.TypeA)

	if got := answersOf(t, first); len(got) != 1 || got[0] != "192.0.2.63" {
		t.Fatalf("first answers = %v, want the generation 1 answer", got)
	}
	if got := answersOf(t, second); len(got) != 1 || got[0] != "198.51.100.63" {
		t.Fatalf("answers = %v, want the generation 2 answer, never the cached generation 1 answer", got)
	}
	if count := replaced.Count(testdns.ProtocolUDP, "renamed.example.com."); count != 1 {
		t.Fatalf("the replaced upstream received %d queries, want 1", count)
	}
}

func TestNotLastGoodStateWithUpstreamsIsRefused(t *testing.T) {
	current := startServer(t, answerWith("192.0.2.64", 300))
	refused := samePortServer(t, current, "127.0.0.2", answerWith("198.51.100.64", 300))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, current)}, portOf(t, current))

	exec(t, forward, "kept.example.com.", dns.TypeA)
	published.publishDocument(2, false, hostOf(t, refused))
	after := exec(t, forward, "after-refusal.example.com.", dns.TypeA)

	if got := answersOf(t, after); len(got) != 1 || got[0] != "192.0.2.64" {
		t.Fatalf("answers = %v, want the last valid generation's answer", got)
	}
	if count := refused.Count("", ""); count != 0 {
		t.Fatalf("the refused upstream received %d queries, want 0", count)
	}
	if count := current.Count(testdns.ProtocolUDP, "after-refusal.example.com."); count != 1 {
		t.Fatalf("the current upstream received %d queries, want 1", count)
	}
}

func TestNotLastGoodStateWithUpstreamsFailsClosedWithoutAPriorGeneration(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.65", 300))
	forward, published := newTestForwardForServer(t, Args{}, upstream)
	published.publishDocument(2, false, hostOf(t, upstream))

	qCtx := newQueryContext("refused.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error for a state that is not last known good")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}
	if count := len(upstream.Queries()); count != 0 {
		t.Fatalf("upstream received %d queries, want 0", count)
	}
}

func TestNotLastGoodEmptyStateDisablesTheBranch(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.66", 300))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, upstream)}, portOf(t, upstream))

	// An empty generation that is not last known good is the documented way to
	// disable the branch, so it has to become the current generation.
	published.publishDocument(2, false)
	first := newQueryContext("disabled.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), first); err == nil {
		t.Fatal("Exec returned no error for an empty generation")
	}
	if response := first.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}

	// A newer valid generation is served again.
	published.publishDocument(3, true, hostOf(t, upstream))
	if got := answersOf(t, exec(t, forward, "enabled.example.com.", dns.TypeA)); len(got) != 1 || got[0] != "192.0.2.66" {
		t.Fatalf("answers = %v, want [192.0.2.66]", got)
	}

	// Disabling it again takes effect, which only holds if the empty generation
	// was adopted as the current one.
	published.publishDocument(4, false)
	second := newQueryContext("disabled-again.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), second); err == nil {
		t.Fatal("Exec returned no error after the branch was disabled again")
	}
	if response := second.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}
	if count := upstream.Count("", "disabled-again.example.com."); count != 0 {
		t.Fatalf("upstream received %d queries for a disabled branch, want 0", count)
	}
}

func TestCacheHitAgesTTLByElapsedSeconds(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.12", 5))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	first := exec(t, forward, "aged.example.com.", dns.TypeA)
	time.Sleep(1100 * time.Millisecond)
	second := exec(t, forward, "aged.example.com.", dns.TypeA)

	if got := first.Answer[0].Header().Ttl; got != 5 {
		t.Fatalf("first ttl = %d, want the upstream ttl 5", got)
	}
	if got := second.Answer[0].Header().Ttl; got != 4 {
		t.Fatalf("cached ttl = %d, want 4 after a whole second of a 5s entry", got)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "aged.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries, want 1", count)
	}
}

func TestCacheHitWithExpiredTTLRefetches(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.13", 1))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	exec(t, forward, "expiring.example.com.", dns.TypeA)
	time.Sleep(1100 * time.Millisecond)
	again := exec(t, forward, "expiring.example.com.", dns.TypeA)

	if got := again.Answer[0].Header().Ttl; got != 1 {
		t.Fatalf("ttl = %d, want the refetched ttl 1", got)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "expiring.example.com."); count != 2 {
		t.Fatalf("upstream received %d queries, want 2: a zero remaining ttl is a miss, not an answer", count)
	}
}

func TestResponseWithZeroTTLIsNotCached(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.14", 0))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	exec(t, forward, "volatile.example.com.", dns.TypeA)
	exec(t, forward, "volatile.example.com.", dns.TypeA)

	if count := upstream.Count(testdns.ProtocolUDP, "volatile.example.com."); count != 2 {
		t.Fatalf("upstream received %d queries, want 2: only a positive ttl is cacheable", count)
	}
}

func TestZeroTTLResponseDoesNotEvictACachedAnswer(t *testing.T) {
	// One cache slot: a stored answer that is worthless on arrival would push the
	// usable one out of the cache.
	upstream := startServer(t, func(_ context.Context, request *dns.Msg) *dns.Msg {
		ttl := uint32(300)
		if request.Question[0].Qtype == dns.TypeAAAA {
			ttl = 0
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return withA(request, response, "192.0.2.15", ttl)
	})
	forward, _ := newTestForward(t, Args{CacheEntries: 1}, []string{hostOf(t, upstream)}, portOf(t, upstream))

	exec(t, forward, "keep.example.com.", dns.TypeA)
	exec(t, forward, "volatile.example.com.", dns.TypeAAAA)
	again := exec(t, forward, "keep.example.com.", dns.TypeA)

	if got := answersOf(t, again); len(got) != 1 || got[0] != "192.0.2.15" {
		t.Fatalf("answers = %v, want the cached answer", got)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "keep.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries for the cacheable name, want 1", count)
	}
}

func TestCacheSeparatesQClassAndEDNSIdentity(t *testing.T) {
	// The upstream reports the identity of the request it answered, so an entry
	// served to the wrong identity shows up in the answer and not only in the
	// query count.
	upstream := startServer(t, reportIdentity)
	forward, _ := newTestForward(t, Args{}, []string{hostOf(t, upstream)}, portOf(t, upstream))

	plain := exec(t, forward, "shared.example.com.", dns.TypeA)
	dnssec := exec(t, forward, "shared.example.com.", dns.TypeA, withDO(true))
	subnet := exec(t, forward, "shared.example.com.", dns.TypeA, withClientSubnet("192.0.2.0", 24))
	otherSubnet := exec(t, forward, "shared.example.com.", dns.TypeA, withClientSubnet("198.51.100.0", 24))
	chaos := exec(t, forward, "shared.example.com.", dns.TypeA, withClass(dns.ClassCHAOS))
	repeat := exec(t, forward, "shared.example.com.", dns.TypeA)

	for _, check := range []struct {
		what     string
		response *dns.Msg
		want     string
	}{
		{"plain", plain, "plain"},
		{"dnssec ok", dnssec, "dnssec"},
		{"client subnet", subnet, "plain+192.0.2.0/24"},
		{"other client subnet", otherSubnet, "plain+198.51.100.0/24"},
		{"chaos class", chaos, "class3"},
		{"repeated plain", repeat, "plain"},
	} {
		if got := reportedIdentities(t, check.response); len(got) != 1 || got[0] != check.want {
			t.Fatalf("%s answer = %v, want [%s]", check.what, got, check.want)
		}
	}
	if count := upstream.Count(testdns.ProtocolUDP, "shared.example.com."); count != 5 {
		t.Fatalf("upstream received %d queries, want 5: the qclass, the DO bit, and the client subnet are part of the cache key", count)
	}
}

func TestGenerationChangeClearsDomesticCacheBeforeLookup(t *testing.T) {
	replaced := startServer(t, answerWith("192.0.2.21", 300))
	replacement := samePortServer(t, replaced, "127.0.0.2", answerWith("198.51.100.7", 300))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, replaced)}, portOf(t, replaced))

	first := exec(t, forward, "swapped.example.com.", dns.TypeA)
	published.publish(2, hostOf(t, replacement))
	second := exec(t, forward, "swapped.example.com.", dns.TypeA)

	if got := answersOf(t, first); len(got) != 1 || got[0] != "192.0.2.21" {
		t.Fatalf("first answers = %v, want the generation 1 answer", got)
	}
	if got := answersOf(t, second); len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("second answers = %v, want the generation 2 answer, never the cached generation 1 answer", got)
	}
	if count := replaced.Count(testdns.ProtocolUDP, "swapped.example.com."); count != 1 {
		t.Fatalf("the replaced upstream received %d queries, want 1", count)
	}
}

func TestInFlightOldGenerationAnswerIsNotCachedInTheNewGeneration(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var blockFirst sync.Once
	replaced := startServer(t, func(ctx context.Context, request *dns.Msg) *dns.Msg {
		if testdns.Protocol(ctx) == testdns.ProtocolUDP {
			blockFirst.Do(func() {
				close(entered)
				<-release
			})
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return withA(request, response, "192.0.2.22", 300)
	})
	replacement := samePortServer(t, replaced, "127.0.0.2", answerWith("198.51.100.8", 300))
	forward, published := newTestForward(t, Args{RetireAfterSeconds: 30}, []string{hostOf(t, replaced)}, portOf(t, replaced))

	inFlight := execInBackground(forward, "inflight.example.com.")

	<-entered
	published.publish(2, hostOf(t, replacement))
	fresh := exec(t, forward, "inflight.example.com.", dns.TypeA)
	close(release)

	carried := <-inFlight
	if carried.err != nil {
		t.Fatalf("the in-flight query against the replaced generation failed: %v", carried.err)
	}
	if got := answersOf(t, carried.response); len(got) != 1 || got[0] != "192.0.2.22" {
		t.Fatalf("in-flight answers = %v, want the replaced generation's answer", got)
	}
	if got := answersOf(t, fresh); len(got) != 1 || got[0] != "198.51.100.8" {
		t.Fatalf("answers = %v, want the new generation's answer", got)
	}
	if count := replacement.Count(testdns.ProtocolUDP, "inflight.example.com."); count != 1 {
		t.Fatalf("the new upstream received %d queries, want 1", count)
	}
	// The answer that crossed the swap must not have been stored into the new
	// generation's cache, so the next query still comes from that cache.
	repeat := exec(t, forward, "inflight.example.com.", dns.TypeA)
	if got := answersOf(t, repeat); len(got) != 1 || got[0] != "198.51.100.8" {
		t.Fatalf("answers = %v, want the cached new generation answer", got)
	}
}

func TestDoesNotCacheSERVFAILOrEmptyState(t *testing.T) {
	failing := startServer(t, servfail)
	forward, _ := newTestForwardForServer(t, Args{}, failing)

	first := exec(t, forward, "broken.example.com.", dns.TypeA)
	second := exec(t, forward, "broken.example.com.", dns.TypeA)

	if first.Rcode != dns.RcodeServerFailure || second.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcodes = %s and %s, want SERVFAIL twice", dns.RcodeToString[first.Rcode], dns.RcodeToString[second.Rcode])
	}
	if count := failing.Count(testdns.ProtocolUDP, "broken.example.com."); count != 2 {
		t.Fatalf("upstream received %d queries, want 2: a SERVFAIL is never cached", count)
	}

	// A valid empty generation replaces the working one and fails closed, and
	// that verdict is not cached either.
	working := startServer(t, answerWith("192.0.2.23", 300))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, working)}, portOf(t, working))
	exec(t, forward, "disabled.example.com.", dns.TypeA)
	published.publish(2)

	for attempt := range 2 {
		qCtx := newQueryContext("disabled.example.com.", dns.TypeA)
		if err := forward.Exec(t.Context(), qCtx); err == nil {
			t.Fatalf("attempt %d: Exec returned no error for a disabled generation", attempt)
		}
		if response := qCtx.R(); response != nil {
			t.Fatalf("attempt %d: response = %v, want none for a disabled generation", attempt, response)
		}
	}
	if count := working.Count(testdns.ProtocolUDP, "disabled.example.com."); count != 1 {
		t.Fatalf("the replaced upstream received %d queries, want 1", count)
	}
}

func TestEmptyStateReturnsErrorWithoutResponse(t *testing.T) {
	forward, _ := newTestForward(t, Args{}, nil, 53)

	for attempt := range 2 {
		qCtx := newQueryContext("empty.example.com.", dns.TypeA)
		if err := forward.Exec(t.Context(), qCtx); err == nil {
			t.Fatalf("attempt %d: Exec returned no error for an empty state", attempt)
		}
		if response := qCtx.R(); response != nil {
			t.Fatalf("attempt %d: response = %v, want none", attempt, response)
		}
	}
}

func TestQueryWithoutAQuestionFailsClosed(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.43", 30))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	qCtx := query_context.NewContext(new(dns.Msg))
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error for a query without a question")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}
	if count := len(upstream.Queries()); count != 0 {
		t.Fatalf("upstream received %d queries, want 0", count)
	}
}

func TestMissingStateFileFailsClosedUntilItAppears(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.24", 30))
	published := &testState{t: t, path: filepath.Join(t.TempDir(), "dhcp-upstreams.json")}
	forward := newForward(t, Args{StateFile: published.path}, published.read, portOf(t, upstream))

	qCtx := newQueryContext("missing.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error while the state file was missing")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}
	if reads := published.readCount(); reads != 0 {
		t.Fatalf("the state file was read %d times while it did not exist, want 0", reads)
	}

	published.publish(1, hostOf(t, upstream))
	response := exec(t, forward, "appeared.example.com.", dns.TypeA)
	if got := answersOf(t, response); len(got) != 1 || got[0] != "192.0.2.24" {
		t.Fatalf("answers = %v, want [192.0.2.24] once the state file appeared", got)
	}
}

func TestCorruptReloadKeepsCurrentGeneration(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.25", 30))
	forward, published := newTestForwardForServer(t, Args{}, upstream)

	exec(t, forward, "before.example.com.", dns.TypeA)
	published.corrupt(2)
	after := exec(t, forward, "after.example.com.", dns.TypeA)

	if got := answersOf(t, after); len(got) != 1 || got[0] != "192.0.2.25" {
		t.Fatalf("answers = %v, want the last valid generation's answer", got)
	}
	if count := upstream.Count(testdns.ProtocolUDP, "after.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries, want 1", count)
	}
}

func TestEqualOrLowerGenerationIsIgnored(t *testing.T) {
	current := startServer(t, answerWith("192.0.2.26", 30))
	rolledBack := samePortServer(t, current, "127.0.0.2", answerWith("198.51.100.26", 30))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, current)}, portOf(t, current))

	published.publish(5, hostOf(t, current))
	exec(t, forward, "rolled.example.com.", dns.TypeA)
	published.publish(5, hostOf(t, rolledBack))
	equal := exec(t, forward, "equal.example.com.", dns.TypeA)
	published.publish(3, hostOf(t, rolledBack))
	lower := exec(t, forward, "lower.example.com.", dns.TypeA)

	if got := answersOf(t, equal); len(got) != 1 || got[0] != "192.0.2.26" {
		t.Fatalf("answers = %v, want the generation 5 answer after an equal generation was published", got)
	}
	if got := answersOf(t, lower); len(got) != 1 || got[0] != "192.0.2.26" {
		t.Fatalf("answers = %v, want the generation 5 answer after a rollback to generation 3", got)
	}
	if count := rolledBack.Count("", ""); count != 0 {
		t.Fatalf("the rolled back upstream received %d queries, want 0", count)
	}
}

func TestHotSwapDoesNotCloseOldGenerationBeforeRetirement(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var blockFirst sync.Once
	replaced := startServer(t, func(ctx context.Context, request *dns.Msg) *dns.Msg {
		if testdns.Protocol(ctx) == testdns.ProtocolUDP {
			blockFirst.Do(func() {
				close(entered)
				<-release
			})
		}
		response := new(dns.Msg)
		response.SetReply(request)
		withA(request, response, "192.0.2.27", 300)
		if testdns.Protocol(ctx) == testdns.ProtocolUDP {
			response.Truncated = true
			response.Answer = nil
		}
		return response
	})
	replacement := samePortServer(t, replaced, "127.0.0.2", answerWith("198.51.100.27", 30))
	forward, published := newTestForward(t, Args{}, []string{hostOf(t, replaced)}, portOf(t, replaced))

	inFlight := execInBackground(forward, "inflight.example.com.")

	<-entered
	published.publish(2, hostOf(t, replacement))
	swapped := exec(t, forward, "after-swap.example.com.", dns.TypeA)
	// One more query runs a reload after the swap, so a generation that was
	// released too early would be released here.
	exec(t, forward, "after-swap-again.example.com.", dns.TypeA)
	close(release)

	carried := <-inFlight
	if carried.err != nil {
		t.Fatalf("the in-flight query against the replaced generation failed: %v", carried.err)
	}
	if got := answersOf(t, carried.response); len(got) != 1 || got[0] != "192.0.2.27" {
		t.Fatalf("in-flight answers = %v, want the replaced generation's answer over tcp", got)
	}
	if got := answersOf(t, swapped); len(got) != 1 || got[0] != "198.51.100.27" {
		t.Fatalf("answers = %v, want the new generation's answer", got)
	}
	if opened, closed := replaced.TCPConns(); opened == 0 || closed != 0 {
		t.Fatalf("the replaced generation's tcp conns opened=%d closed=%d, want an open client connection", opened, closed)
	}
}

func TestRetiredGenerationClosesItsClientsAfterRetirement(t *testing.T) {
	replaced := startServer(t, truncatingThenAnswering("192.0.2.28", 30))
	replacement := samePortServer(t, replaced, "127.0.0.2", answerWith("198.51.100.28", 30))
	forward, published := newTestForward(t, Args{UpstreamTimeoutMS: 400, RetireAfterSeconds: 1}, []string{hostOf(t, replaced)}, portOf(t, replaced))

	exec(t, forward, "tcp.example.com.", dns.TypeA)
	if opened, closed := replaced.TCPConns(); opened != 1 || closed != 0 {
		t.Fatalf("tcp conns opened=%d closed=%d, want one open client connection", opened, closed)
	}

	published.publish(2, hostOf(t, replacement))
	exec(t, forward, "generation-two.example.com.", dns.TypeA)
	if _, closed := replaced.TCPConns(); closed != 0 {
		t.Fatalf("the retired generation's client was closed %d times before the retirement window elapsed", closed)
	}

	time.Sleep(1100 * time.Millisecond)
	exec(t, forward, "generation-two-again.example.com.", dns.TypeA)

	waitFor(t, "the retired generation's client to be closed", func() bool {
		opened, closed := replaced.TCPConns()
		return opened == 1 && closed == 1
	})
}

func TestPluginCloseClosesAllUDPAndTCPClients(t *testing.T) {
	replaced := startServer(t, truncatingThenAnswering("192.0.2.29", 30))
	current := samePortServer(t, replaced, "127.0.0.2", truncatingThenAnswering("198.51.100.29", 30))
	forward, published := newTestForward(t, Args{UpstreamTimeoutMS: 400, RetireAfterSeconds: 30}, []string{hostOf(t, replaced)}, portOf(t, replaced))

	exec(t, forward, "replaced.example.com.", dns.TypeA)
	published.publish(2, hostOf(t, current))
	exec(t, forward, "current.example.com.", dns.TypeA)

	if opened, closed := replaced.TCPConns(); opened != 1 || closed != 0 {
		t.Fatalf("the replaced generation's tcp conns opened=%d closed=%d, want 1 open", opened, closed)
	}
	if opened, closed := current.TCPConns(); opened != 1 || closed != 0 {
		t.Fatalf("the current generation's tcp conns opened=%d closed=%d, want 1 open", opened, closed)
	}

	if err := forward.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := forward.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	for name, server := range map[string]*testdns.Server{"replaced": replaced, "current": current} {
		waitFor(t, "the "+name+" generation's client connection to be closed", func() bool {
			opened, closed := server.TCPConns()
			return opened == 1 && closed == 1
		})
	}

	qCtx := newQueryContext("after-close.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error after Close")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none after Close", response)
	}
}

func TestRacesAtMostTwoDistinctUpstreams(t *testing.T) {
	first := startServer(t, answerWith("192.0.2.31", 0))
	second := samePortServer(t, first, "127.0.0.2", answerWith("192.0.2.32", 0))
	third := samePortServer(t, first, "127.0.0.3", answerWith("192.0.2.33", 0))
	servers := []*testdns.Server{first, second, third}
	forward, _ := newTestForward(t, Args{}, []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, portOf(t, first))

	names := []string{
		"a.race.example.com.", "b.race.example.com.", "c.race.example.com.",
		"d.race.example.com.", "e.race.example.com.", "f.race.example.com.",
	}
	observed := make(map[string]struct{})
	var firstPair string
	for index, name := range names {
		before := snapshotQueries(servers)
		exec(t, forward, name, dns.TypeA)
		// The query returns as soon as one upstream answers, so the second
		// racer is still on its way when the client is answered.
		waitFor(t, name+" to reach two upstreams", func() bool {
			return len(queriedSince(servers, before)) == 2
		})
		pair := strings.Join(queriedSince(servers, before), ",")
		observed[pair] = struct{}{}
		if index == 0 {
			firstPair = pair
		}
	}
	if len(observed) < 2 {
		t.Fatalf("every question chose the same upstreams (%v), want the rotation to spread them", observed)
	}

	// The rotation is derived from the qname, so the same question keeps
	// choosing the same upstreams.
	for range 3 {
		before := snapshotQueries(servers)
		exec(t, forward, names[0], dns.TypeA)
		waitFor(t, "both racers to reach an upstream again", func() bool {
			return len(queriedSince(servers, before)) == 2
		})
		if pair := strings.Join(queriedSince(servers, before), ","); pair != firstPair {
			t.Fatalf("a repeat of %s chose %s, want the same %s", names[0], pair, firstPair)
		}
	}
}

func TestDuplicateUpstreamIsNotRacedTwice(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.44", 0))
	// A state file that lists one resolver twice must still send that resolver
	// one query, so the duplicate cannot take both slots of one query.
	forward, _ := newTestForward(t, Args{}, []string{hostOf(t, upstream), hostOf(t, upstream)}, portOf(t, upstream))

	exec(t, forward, "duplicate.example.com.", dns.TypeA)
	// The query is answered as soon as one racer replies, so a second query sent
	// to the same address would still be on its way. Let it arrive before
	// counting what was sent.
	time.Sleep(100 * time.Millisecond)

	if count := upstream.Count("", "duplicate.example.com."); count != 1 {
		t.Fatalf("upstream received %d queries, want 1: a repeated address is one endpoint", count)
	}
}

func TestTruncatedUDPRetriesOverTCP(t *testing.T) {
	upstream := startServer(t, truncatingThenAnswering("192.0.2.34", 42))
	forward, _ := newTestForwardForServer(t, Args{}, upstream)

	response := exec(t, forward, "big.example.com.", dns.TypeA)

	if response.Truncated {
		t.Fatal("the response is truncated, want the complete answer from the tcp retry")
	}
	if got := answersOf(t, response); len(got) != 1 || got[0] != "192.0.2.34" {
		t.Fatalf("answers = %v, want [192.0.2.34]", got)
	}
	if got := response.Answer[0].Header().Ttl; got != 42 {
		t.Fatalf("ttl = %d, want the tcp answer's ttl 42", got)
	}
	queries := upstream.Queries()
	if len(queries) != 2 {
		t.Fatalf("upstream received %d queries, want one udp and one tcp: %+v", len(queries), queries)
	}
	if queries[0].Protocol != testdns.ProtocolUDP || queries[1].Protocol != testdns.ProtocolTCP {
		t.Fatalf("protocols = %q then %q, want udp then tcp", queries[0].Protocol, queries[1].Protocol)
	}
	if queries[0].QName != queries[1].QName || queries[0].ID != queries[1].ID || queries[0].QType != queries[1].QType {
		t.Fatalf("the tcp retry changed the question: %+v then %+v", queries[0], queries[1])
	}
}

func TestPrefersSuccessfulResponseOverFailure(t *testing.T) {
	// The failing upstream answers first, so returning the first answer to
	// arrive is distinguishable from preferring a successful one.
	failing := startServer(t, servfail)
	working := samePortServer(t, failing, "127.0.0.2", func(_ context.Context, request *dns.Msg) *dns.Msg {
		time.Sleep(60 * time.Millisecond)
		response := new(dns.Msg)
		response.SetReply(request)
		return withA(request, response, "198.51.100.36", 30)
	})
	forward, _ := newTestForward(t, Args{UpstreamTimeoutMS: 1000}, []string{"127.0.0.1", "127.0.0.2"}, portOf(t, failing))

	response := exec(t, forward, "preferred.example.com.", dns.TypeA)

	if got := answersOf(t, response); len(got) != 1 || got[0] != "198.51.100.36" {
		t.Fatalf("answers = %v, want the successful response, not the earlier servfail", got)
	}
	if count := failing.Count(testdns.ProtocolUDP, "preferred.example.com."); count != 1 {
		t.Fatalf("the failing upstream received %d queries, want 1", count)
	}
	_ = working
}

func TestReturnsErrorWhenNoUpstreamAnswers(t *testing.T) {
	// Nothing listens on the second loopback address, so the only endpoint
	// fails at the transport level.
	server := startServer(t, answerWith("192.0.2.37", 30))
	port := portOf(t, server)
	if err := server.Close(); err != nil {
		t.Fatalf("close the loopback server: %v", err)
	}
	forward, _ := newTestForward(t, Args{UpstreamTimeoutMS: 300}, []string{"127.0.0.2"}, port)

	qCtx := newQueryContext("unanswered.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error when the only upstream could not answer")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none when every upstream failed", response)
	}
}

func TestUnreadableStateIsRetriedUntilItIsUsable(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.44", 30))
	forward, published := newTestForwardForServer(t, Args{}, upstream)
	// The state file itself never changes again, so only a plugin that retries
	// the read can recover from the failure.
	published.failNextReads(1)

	qCtx := newQueryContext("first.example.com.", dns.TypeA)
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error while the state file could not be read")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}

	response := exec(t, forward, "second.example.com.", dns.TypeA)
	if got := answersOf(t, response); len(got) != 1 || got[0] != "192.0.2.44" {
		t.Fatalf("answers = %v, want [192.0.2.44] once the read succeeded", got)
	}
}

func TestReadDHCPStateValidatesPublishedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp-upstreams.json")

	writeStateDocument(t, path, state.NewDHCPState(7, testInterface, "uuid", []string{"192.0.2.53"}, time.Unix(0, 0).UTC(), "dhcp4", true))
	published, err := readDHCPState(path)
	if err != nil {
		t.Fatalf("read a valid published state: %v", err)
	}
	if published.Generation != 7 || published.Interface != testInterface {
		t.Fatalf("read %+v, want generation 7 on %s", published, testInterface)
	}
	if len(published.Upstreams) != 1 || published.Upstreams[0] != "192.0.2.53" {
		t.Fatalf("read upstreams %v, want [192.0.2.53]", published.Upstreams)
	}

	for name, upstreams := range map[string][]string{
		"loopback":         {"127.0.0.1"},
		"resolved stub":    {"127.0.0.53"},
		"link local IPv4":  {"169.254.1.1"},
		"zoned IPv6":       {"fe80::1%" + testInterface},
		"multicast":        {"224.0.0.1"},
		"not an address":   {"resolver.example.com"},
		"address and port": {"192.0.2.53:53"},
	} {
		writeStateDocument(t, path, state.NewDHCPState(8, testInterface, "uuid", upstreams, time.Unix(0, 0).UTC(), "dhcp4", true))
		if _, err := readDHCPState(path); err == nil {
			t.Fatalf("%s upstream %v was accepted, want it refused before it can redirect queries", name, upstreams)
		}
	}
}

func TestNewRejectsInvalidArgs(t *testing.T) {
	valid := Args{StateFile: filepath.Join(t.TempDir(), "state.json")}
	read := staticState(state.NewDHCPState(1, testInterface, "uuid", []string{"192.0.2.40"}, time.Unix(0, 0).UTC(), "dhcp4", true))
	if _, err := newForwardWithState(valid, zap.NewNop(), read, 53); err != nil {
		t.Fatalf("the minimal valid args were rejected: %v", err)
	}

	for name, args := range map[string]Args{
		"no state file":                             {StateFile: ""},
		"negative timeout":                          {StateFile: valid.StateFile, UpstreamTimeoutMS: -1},
		"negative concurrency":                      {StateFile: valid.StateFile, Concurrency: -1},
		"concurrency above the range":               {StateFile: valid.StateFile, Concurrency: 3},
		"negative retirement":                       {StateFile: valid.StateFile, RetireAfterSeconds: -1},
		"negative cache entries":                    {StateFile: valid.StateFile, CacheEntries: -1},
		"retirement below the timeout":              {StateFile: valid.StateFile, UpstreamTimeoutMS: 5000, RetireAfterSeconds: 4},
		"retirement below a partial second timeout": {StateFile: valid.StateFile, UpstreamTimeoutMS: 2100, RetireAfterSeconds: 2},
	} {
		if _, err := newForwardWithState(args, zap.NewNop(), read, 53); err == nil {
			t.Fatalf("%s was accepted, want it rejected", name)
		}
	}

	// Three seconds is the smallest window that holds a 2500ms exchange.
	exact := Args{StateFile: valid.StateFile, UpstreamTimeoutMS: 2500, RetireAfterSeconds: 3}
	if _, err := newForwardWithState(exact, zap.NewNop(), read, 53); err != nil {
		t.Fatalf("retire_after_seconds 3 for a 2500ms timeout was rejected: %v", err)
	}
}

func TestNewAppliesDocumentedDefaults(t *testing.T) {
	forward, _ := newTestForward(t, Args{}, []string{"192.0.2.41"}, 53)

	if forward.rt.timeout != 5*time.Second {
		t.Fatalf("upstream timeout = %v, want the documented 5s", forward.rt.timeout)
	}
	if forward.rt.concurrency != 2 {
		t.Fatalf("concurrency = %d, want the documented 2", forward.rt.concurrency)
	}
	if forward.rt.retireAfter != 60*time.Second {
		t.Fatalf("retirement = %v, want the documented 60s", forward.rt.retireAfter)
	}
	if forward.rt.cacheEntries != 4096 {
		t.Fatalf("cache entries = %d, want the documented 4096", forward.rt.cacheEntries)
	}
}

func TestPluginLoadsFromMosdnsConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp-upstreams.json")
	writeStateDocument(t, path, state.NewDHCPState(1, testInterface, "uuid", []string{"192.0.2.53"}, time.Unix(0, 0).UTC(), "dhcp4", true))

	// The type and the argument names are spelled the way a mosdns configuration
	// file spells them, not through the package's own constants.
	mosdns, err := coremain.NewMosdns(&coremain.Config{
		Log: mlog.LogConfig{Level: "error"},
		Plugins: []coremain.PluginConfig{{
			Tag:  "dhcp_forward",
			Type: "dhcp_forward",
			Args: map[string]any{"state_file": path},
		}},
	})
	if err != nil {
		t.Fatalf("mosdns refused the dhcp_forward plugin: %v", err)
	}
	t.Cleanup(func() {
		mosdns.CloseWithErr(nil)
		_ = mosdns.GetSafeClose().WaitClosed()
	})

	plugin := mosdns.GetPlugin("dhcp_forward")
	if _, ok := plugin.(sequence.Executable); !ok {
		t.Fatalf("plugin %T does not implement sequence.Executable", plugin)
	}
	closer, ok := plugin.(interface{ Close() error })
	if !ok {
		t.Fatalf("plugin %T is not closed on shutdown", plugin)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIPv6LinkLocalUpstreamIsScopedToTheStateInterface(t *testing.T) {
	endpoint, err := newEndpoint("fe80::1", testInterface, 53, zap.NewNop())
	if err != nil {
		t.Fatalf("newEndpoint: %v", err)
	}
	if endpoint.address != "[fe80::1%"+testInterface+"]:53" {
		t.Fatalf("endpoint address = %q, want [fe80::1%%enp3s0]:53", endpoint.address)
	}
	if _, err := net.ResolveUDPAddr("udp", endpoint.address); err != nil {
		t.Fatalf("the scoped address is not dialable: %v", err)
	}

	global, err := newEndpoint("2001:db8::53", testInterface, 53, zap.NewNop())
	if err != nil {
		t.Fatalf("newEndpoint: %v", err)
	}
	if global.address != "[2001:db8::53]:53" {
		t.Fatalf("endpoint address = %q, want [2001:db8::53]:53 with no interface zone", global.address)
	}

	if _, err := newEndpoint("fe80::1", "", 53, zap.NewNop()); err == nil {
		t.Fatal("a link-local upstream without an interface was accepted")
	}
	if _, err := newEndpoint("not-an-address", testInterface, 53, zap.NewNop()); err == nil {
		t.Fatal("a non-address upstream was accepted")
	}
	if _, err := newEndpoint("192.0.2.1:53", testInterface, 53, zap.NewNop()); err == nil {
		t.Fatal("an upstream carrying a port was accepted")
	}
}

func TestConcurrentQueriesReloadAndCacheSafely(t *testing.T) {
	upstream := startServer(t, answerWith("192.0.2.42", 30))
	forward, published := newTestForwardForServer(t, Args{UpstreamTimeoutMS: 400, RetireAfterSeconds: 1}, upstream)

	var failures sync.WaitGroup
	runConcurrently(t, &failures, 8, func(worker, round int) {
		qCtx := newQueryContext(fmt.Sprintf("worker-%d-round-%d.example.com.", worker, round), dns.TypeA)
		if err := forward.Exec(context.Background(), qCtx); err != nil {
			t.Errorf("Exec in the first generation: %v", err)
		}
	})
	failures.Wait()
	published.publish(2, hostOf(t, upstream))
	runConcurrently(t, &failures, 8, func(worker, round int) {
		qCtx := newQueryContext(fmt.Sprintf("after-%d-%d.example.com.", worker, round), dns.TypeA)
		if err := forward.Exec(context.Background(), qCtx); err != nil {
			t.Errorf("Exec in the second generation: %v", err)
		}
	})
	failures.Wait()
}

// --- the published state a test drives ---

// testState is the state file a test publishes through, together with the state
// reader the plugin uses. Production state validation correctly refuses the
// loopback addresses a test server listens on, so the reader is injected while
// the file itself still drives the reload decision.
type testState struct {
	t    *testing.T
	path string

	mu       sync.Mutex
	current  state.DHCPState
	reads    int
	writes   int
	failures int
}

// read decodes the published document the way the production reader does, minus
// the schema validation that refuses the loopback addresses a test server listens
// on. A corrupt document still has to fail here, because that is what keeps the
// last valid generation in place.
// failNextReads makes the next count reads fail, the way an unreadable file does.
func (s *testState) failNextReads(count int) {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = count
}

func (s *testState) read(path string) (state.DHCPState, error) {
	s.mu.Lock()
	s.reads++
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return state.DHCPState{}, fmt.Errorf("%s: injected read failure", path)
	}
	s.mu.Unlock()

	document, err := os.ReadFile(path)
	if err != nil {
		return state.DHCPState{}, err
	}
	var published state.DHCPState
	if err := json.Unmarshal(document, &published); err != nil {
		return state.DHCPState{}, fmt.Errorf("%s: %w", path, err)
	}
	return published, nil
}

func (s *testState) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *testState) generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current.Generation
}

func (s *testState) publish(generation uint64, upstreams ...string) {
	s.t.Helper()
	s.publishDocument(generation, len(upstreams) > 0, upstreams...)
}

// publishDocument writes a document and gives the file a modification time no
// earlier write used, so the plugin sees every publication as a new file.
func (s *testState) publishDocument(generation uint64, lastGood bool, upstreams ...string) {
	s.t.Helper()
	published := s.note(generation, lastGood, upstreams...)
	writeStateDocument(s.t, s.path, published)
	s.setModified()
}

// note records what the plugin should read next, without writing it.
func (s *testState) note(generation uint64, lastGood bool, upstreams ...string) state.DHCPState {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = state.NewDHCPState(generation, testInterface, "uuid", upstreams, time.Unix(0, 0).UTC(), "dhcp4", lastGood)
	return s.current
}

// corrupt replaces the document with truncated JSON, keeping the generation in
// the text so a reader that only looked at the file would still see it.
func (s *testState) corrupt(generation uint64) {
	s.t.Helper()
	document := fmt.Sprintf("{\"schema_version\":1,\"generation\":%d,\"upstreams\":[\"192.0.2.99\"", generation)
	if err := os.WriteFile(s.path, []byte(document), 0o600); err != nil {
		s.t.Fatalf("write a corrupt state file: %v", err)
	}
	s.setModified()
}

// setModified gives the file a modification time no earlier write used, so the
// plugin sees every publication as a new file even when the document is the same
// length and the generation is unchanged.
func (s *testState) setModified() {
	s.t.Helper()
	s.writes++
	when := time.Unix(int64(s.writes)+1, 0)
	if err := os.Chtimes(s.path, when, when); err != nil {
		s.t.Fatalf("set the state file times: %v", err)
	}
}

func writeStateDocument(t *testing.T, path string, published state.DHCPState) {
	t.Helper()
	document, err := json.Marshal(published)
	if err != nil {
		t.Fatalf("encode the state document: %v", err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write the state document: %v", err)
	}
}

// publishByRename writes the document the way the bridge does: a fresh file in
// the same directory, then a rename over the target. The replacement keeps the
// target's modification time, so only its identity is new.
func publishByRename(t *testing.T, published *testState, generation uint64, lastGood bool, upstreams ...string) {
	t.Helper()
	document := newDHCPStateDocument(t, published.note(generation, lastGood, upstreams...))

	before, err := os.Stat(published.path)
	if err != nil {
		t.Fatalf("stat the current state document: %v", err)
	}
	replacement := published.path + ".next"
	if err := os.WriteFile(replacement, document, 0o600); err != nil {
		t.Fatalf("write the replacement document: %v", err)
	}
	if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
		t.Fatalf("set the replacement times: %v", err)
	}
	if err := os.Rename(replacement, published.path); err != nil {
		t.Fatalf("rename the replacement document: %v", err)
	}

	after, err := os.Stat(published.path)
	if err != nil {
		t.Fatalf("stat the renamed document: %v", err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("the replacement is %d bytes, was %d: the test needs two documents of the same size", after.Size(), before.Size())
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the replacement has time %s, was %s: the test needs the same modification time", after.ModTime(), before.ModTime())
	}
	if os.SameFile(before, after) {
		t.Fatal("the replacement kept the identity of the file it replaced")
	}
}

func newDHCPStateDocument(t *testing.T, published state.DHCPState) []byte {
	t.Helper()
	document, err := json.Marshal(published)
	if err != nil {
		t.Fatalf("encode the state document: %v", err)
	}
	return document
}

func staticState(published state.DHCPState) readStateFunc {
	return func(string) (state.DHCPState, error) { return published, nil }
}

func newTestForwardForServer(t *testing.T, args Args, server *testdns.Server) (*Forward, *testState) {
	t.Helper()
	return newTestForward(t, args, []string{hostOf(t, server)}, portOf(t, server))
}

func newTestForward(t *testing.T, args Args, upstreams []string, port uint16) (*Forward, *testState) {
	t.Helper()
	if args.StateFile == "" {
		args.StateFile = filepath.Join(t.TempDir(), "dhcp-upstreams.json")
	}
	published := &testState{t: t, path: args.StateFile}
	published.publish(1, upstreams...)
	return newForward(t, args, published.read, port), published
}

func newForward(t *testing.T, args Args, read readStateFunc, port uint16) *Forward {
	t.Helper()
	forward, err := newForwardWithState(args, zap.NewNop(), read, port)
	if err != nil {
		t.Fatalf("build the plugin: %v", err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	return forward
}

func exec(t *testing.T, forward *Forward, name string, qtype uint16, options ...func(*query_context.Context)) *dns.Msg {
	t.Helper()
	qCtx := newQueryContext(name, qtype, options...)
	if err := forward.Exec(t.Context(), qCtx); err != nil {
		t.Fatalf("Exec %s: %v", name, err)
	}
	response := qCtx.R()
	if response == nil {
		t.Fatalf("Exec %s returned no response", name)
	}
	return response
}

// execResult is the outcome of one Exec, successful or not.
type execResult struct {
	response *dns.Msg
	err      error
}

// execInBackground starts a query that the test releases later, so the plugin
// can be observed while the query is still on the wire.
func execInBackground(forward *Forward, name string) <-chan execResult {
	results := make(chan execResult, 1)
	go func() {
		qCtx := newQueryContext(name, dns.TypeA)
		err := forward.Exec(context.Background(), qCtx)
		results <- execResult{response: qCtx.R(), err: err}
	}()
	return results
}

func newQueryContext(name string, qtype uint16, options ...func(*query_context.Context)) *query_context.Context {
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	query.RecursionDesired = true
	qCtx := query_context.NewContext(query)
	for _, option := range options {
		option(qCtx)
	}
	return qCtx
}

// withDO sets the DNSSEC OK bit on the query that goes upstream, the way an
// earlier plugin in the chain would.
// withID sets the transaction id a client chose. A response has to carry the id
// of the query it answers, and a cached answer is a response to whichever query
// fetched it.
func withID(id uint16) func(*query_context.Context) {
	return func(qCtx *query_context.Context) { qCtx.Q().Id = id }
}

// withAD sets the header's authenticated-data bit, which asks the upstream for
// answers it has validated itself.
func withAD(ad bool) func(*query_context.Context) {
	return func(qCtx *query_context.Context) { qCtx.Q().AuthenticatedData = ad }
}

func withDO(do bool) func(*query_context.Context) {
	return func(qCtx *query_context.Context) {
		opt := qCtx.Q().IsEdns0()
		if opt == nil {
			return
		}
		if do {
			opt.SetDo()
			return
		}
		opt.Hdr.Ttl &^= 1 << 15
	}
}

// withClientSubnet adds a client subnet to the query that goes upstream, the way
// the ecs_handler plugin would.
func withClientSubnet(address string, mask uint8) func(*query_context.Context) {
	return func(qCtx *query_context.Context) {
		opt := qCtx.Q().IsEdns0()
		if opt == nil {
			return
		}
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: mask,
			SourceScope:   0,
			Address:       net.ParseIP(address).To4(),
		})
	}
}

func withClass(class uint16) func(*query_context.Context) {
	return func(qCtx *query_context.Context) { qCtx.Q().Question[0].Qclass = class }
}

// identityOf is the text the reporting upstream answers with, so a test can see
// which identity its request carried.
func identityOf(query *dns.Msg) string {
	identity := "plain"
	if query.AuthenticatedData {
		identity += "+ad"
	}
	if opt := query.IsEdns0(); opt != nil {
		if opt.Do() {
			identity = "dnssec"
		}
		for _, option := range opt.Option {
			subnet, ok := option.(*dns.EDNS0_SUBNET)
			if !ok {
				continue
			}
			identity += "+" + subnet.Address.String() + "/" + strconv.Itoa(int(subnet.SourceNetmask))
		}
	}
	if query.Question[0].Qclass != dns.ClassINET {
		identity = "class" + strconv.Itoa(int(query.Question[0].Qclass))
	}
	return identity
}

// reportIdentity answers with the identity of the request it received.
func reportIdentity(_ context.Context, request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = append(response.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   request.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  request.Question[0].Qclass,
			Ttl:    30,
		},
		Txt: []string{identityOf(request)},
	})
	return response
}

func reportedIdentities(t *testing.T, response *dns.Msg) []string {
	t.Helper()
	identities := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		text, ok := record.(*dns.TXT)
		if !ok {
			t.Fatalf("answer %v is not a TXT record", record)
		}
		identities = append(identities, strings.Join(text.Txt, ""))
	}
	return identities
}

func answerWith(address string, ttl uint32) testdns.Handler {
	return func(_ context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		return withA(request, response, address, ttl)
	}
}

func servfail(_ context.Context, request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeServerFailure)
	response.Answer = append(response.Answer, &dns.SOA{
		Hdr:  dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:   "ns." + request.Question[0].Name,
		Mbox: "hostmaster." + request.Question[0].Name,
	})
	return response
}

func withA(request, response *dns.Msg, address string, ttl uint32) *dns.Msg {
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   request.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  request.Question[0].Qclass,
			Ttl:    ttl,
		},
		A: net.ParseIP(address).To4(),
	})
	return response
}

// truncatingThenAnswering answers a udp query with a truncated message, as a
// server does when the answer does not fit, and answers the tcp retry in full.
func truncatingThenAnswering(address string, ttl uint32) testdns.Handler {
	return func(ctx context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		withA(request, response, address, ttl)
		if testdns.Protocol(ctx) == testdns.ProtocolUDP {
			response.Truncated = true
			response.Answer = nil
		}
		return response
	}
}

func startServer(t *testing.T, handler testdns.Handler) *testdns.Server {
	t.Helper()
	server, err := testdns.Start(handler)
	if err != nil {
		t.Fatalf("start a test dns server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// samePortServer puts one more server on reference's port under another loopback
// address. A published state carries bare addresses and the port is implied, so
// several resolvers of one generation are told apart by their address alone.
func samePortServer(t *testing.T, reference *testdns.Server, host string, handler testdns.Handler) *testdns.Server {
	t.Helper()
	address := net.JoinHostPort(host, strconv.Itoa(int(portOf(t, reference))))
	server, err := testdns.StartOn(address, handler)
	if err != nil {
		t.Fatalf("start a test dns server on %s: %v", address, err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// hostOf is the bare address a DHCP state publishes for a test server. The port
// is not part of a published address, so it is supplied separately.
func hostOf(t *testing.T, server *testdns.Server) string {
	t.Helper()
	host, _, err := net.SplitHostPort(server.Address())
	if err != nil {
		t.Fatalf("split %q: %v", server.Address(), err)
	}
	return host
}

func portOf(t *testing.T, server *testdns.Server) uint16 {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Address())
	if err != nil {
		t.Fatalf("split %q: %v", server.Address(), err)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", port, err)
	}
	return uint16(number)
}

func answersOf(t *testing.T, response *dns.Msg) []string {
	t.Helper()
	answers := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		address, ok := record.(*dns.A)
		if !ok {
			t.Fatalf("answer %v is not an A record", record)
		}
		answers = append(answers, address.A.String())
	}
	return answers
}

// snapshotQueries records how many queries each server has received, so a test
// can tell which servers answered one particular question.
func snapshotQueries(servers []*testdns.Server) []int {
	counts := make([]int, len(servers))
	for index, server := range servers {
		counts[index] = len(server.Queries())
	}
	return counts
}

func queriedSince(servers []*testdns.Server, before []int) []string {
	hosts := make([]string, 0, len(servers))
	for index, server := range servers {
		if len(server.Queries()) <= before[index] {
			continue
		}
		host, _, err := net.SplitHostPort(server.Address())
		if err != nil {
			host = server.Address()
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func runConcurrently(t *testing.T, failures *sync.WaitGroup, workers int, query func(worker, round int)) {
	t.Helper()
	for worker := range workers {
		failures.Add(1)
		go func() {
			defer failures.Done()
			for round := range 5 {
				query(worker, round)
			}
		}()
	}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
