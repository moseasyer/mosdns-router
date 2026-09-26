package candidate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every origin in this file is a local httptest server and every cache path is a
// path inside t.TempDir(), so nothing here reaches api.cloudflare.com, writes
// under /var/lib, or reads a clock: the local date is passed in.

const (
	// fixtureETag is the validator the fake origin hands out, in the weak form
	// the real API uses.
	fixtureETag = `W/"8d1f0b3c2a1e"`
	// fixtureIPv4CIDRs is a two-range IPv4 list, 4 blocks and 8 blocks wide,
	// small enough that no limit applies and every block can be written down.
	fixtureIPv4CIDRs = "104.16.0.0/22,172.64.0.0/21"
	// fixtureIPv6CIDRs is the IPv6 half of the same document. This release
	// selects IPv4 only, so these are parsed and never expanded.
	fixtureIPv6CIDRs = "2606:4700::/32,2400:cb00::/32"
	// wideIPv4CIDRs is the whole of one of Cloudflare's real /13 ranges: 2048
	// blocks, so a limit of 512 has to choose.
	wideIPv4CIDRs = "104.16.0.0/13"
)

// standardDocument is the document the fake origin serves by default.
func standardDocument() string {
	return cloudflareDocument(fixtureIPv4CIDRs, fixtureIPv6CIDRs, fixtureETag)
}

// cloudflareDocument renders the shape the real IP API answers with: the
// envelope, the result object, and the three fields this package reads. The
// fields it does not read are present, so a decoder that reached for something
// else fails here rather than in production.
func cloudflareDocument(ipv4CIDRs, ipv6CIDRs, etag string) string {
	return fmt.Sprintf(`{"errors":[],"messages":[],"result":{"etag":%q,"ipv4_cidrs":%s,"ipv6_cidrs":%s},"success":true}`,
		etag, jsonList(ipv4CIDRs), jsonList(ipv6CIDRs))
}

func jsonList(commas string) string {
	values := strings.Split(commas, ",")
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

// testDate is a fixed instant in a fixed zone, so the date the sample is seeded
// with does not depend on the machine the test runs on.
func testDate(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 3, 4, 5, 0, time.FixedZone("candidate-test", 8*60*60))
}

// originRequest is one request the fake origin answered. The conditional
// validator is recorded as both a value and a presence, because a header sent
// with an empty value is a different thing from no header at all, and the origin
// cannot tell them apart from the value alone.
type originRequest struct {
	path         string
	ifNoneMatch  string
	hasValidator bool
	acceptHeader string
}

// fakeOrigin is a Cloudflare-shaped HTTP origin. Every request is recorded
// behind a mutex, because the handler runs on the server's own goroutine and the
// race detector is part of the gate.
type fakeOrigin struct {
	server *httptest.Server
	client *http.Client

	mutex        sync.Mutex
	document     string
	etag         string
	notModified  bool
	status       int
	streamBytes  int64
	hijack       bool
	seen         []originRequest
	servedBodies int
}

func newFakeOrigin(t *testing.T, document, etag string) *fakeOrigin {
	t.Helper()
	origin := &fakeOrigin{document: document, etag: etag, status: http.StatusOK}
	// A TLS server, because a source in production only accepts an https URL and
	// a test that needed a plaintext one would be testing a configuration the
	// router refuses. Its certificate is issued for 127.0.0.1 and for
	// example.com, and server.Client() trusts it, so verification is on
	// everywhere in this file.
	origin.server = httptest.NewTLSServer(http.HandlerFunc(origin.serve))
	t.Cleanup(origin.server.Close)
	origin.client = origin.server.Client()
	return origin
}

func (o *fakeOrigin) serve(writer http.ResponseWriter, request *http.Request) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	_, hasValidator := request.Header["If-None-Match"]
	o.seen = append(o.seen, originRequest{
		path:         request.URL.Path,
		ifNoneMatch:  request.Header.Get("If-None-Match"),
		hasValidator: hasValidator,
		acceptHeader: request.Header.Get("Accept"),
	})
	switch {
	case o.status != http.StatusOK:
		writer.WriteHeader(o.status)
	case o.hijack:
		// A real transport failure from a real server: the connection is taken
		// over and closed without a response, so the client sees an unexpected
		// EOF rather than a status any code could read.
		if connection, _, err := writer.(http.Hijacker).Hijack(); err == nil {
			_ = connection.Close()
		}
	case o.notModified:
		writer.WriteHeader(http.StatusNotModified)
	case o.streamBytes != 0:
		writer.Header().Set("ETag", o.etag)
		_, _ = io.CopyN(writer, zeroReader{}, o.streamBytes)
	default:
		writer.Header().Set("ETag", o.etag)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, o.document)
		o.servedBodies++
	}
}

func (o *fakeOrigin) setNotModified(notModified bool) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.notModified = notModified
}

func (o *fakeOrigin) setStatus(status int) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.status = status
}

// setHijack makes the next requests fail at the connection instead of answering.
func (o *fakeOrigin) setHijack(hijack bool) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.hijack = hijack
}

// setDocument replaces what the origin answers with a fresh body.
func (o *fakeOrigin) setDocument(document string) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.document = document
	o.status = http.StatusOK
	o.hijack = false
}

func (o *fakeOrigin) requests() []originRequest {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return slices.Clone(o.seen)
}

func (o *fakeOrigin) bodiesServed() int {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.servedBodies
}

// zeroReader is an endless source of zero bytes, so a test can make an origin
// declare a body larger than any limit without holding it in memory.
type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

// hostRewritingClient sends every request to the test server, so a source that
// was given no base URL still builds and uses its real production endpoint. The
// transport is the test server's own, with the server name its certificate is
// issued for declared, so certificate verification stays on for every request in
// this file: the test states which name it expects, and nothing is skipped.
func hostRewritingClient(t *testing.T, origin *fakeOrigin) *http.Client {
	t.Helper()
	target, err := url.Parse(origin.server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	transport, ok := origin.server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server transport is a %T, want an *http.Transport", origin.server.Client().Transport)
	}
	cloned := transport.Clone()
	cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
	cloned.TLSClientConfig.ServerName = "example.com"
	return &http.Client{Transport: rewriteHostTransport{base: target, inner: cloned}}
}

type rewriteHostTransport struct {
	base  *url.URL
	inner *http.Transport
}

func (r rewriteHostTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	next := request.Clone(request.Context())
	next.URL.Scheme = r.base.Scheme
	next.URL.Host = r.base.Host
	return r.inner.RoundTrip(next)
}

// newTestSource returns a source pointed at the fake origin with its cache
// inside the test's own temporary directory.
func newTestSource(t *testing.T, origin *fakeOrigin, cachePath string) *HTTPCloudflareSource {
	t.Helper()
	source, err := NewCloudflareSource(origin.client, origin.server.URL, cachePath)
	if err != nil {
		t.Fatalf("NewCloudflareSource: %v", err)
	}
	return source
}

func cloudflareCandidates(t *testing.T, source *HTTPCloudflareSource, limit int, date time.Time) []Candidate {
	t.Helper()
	return cloudflareSet(t, source, limit, date).Candidates
}

func cloudflareSet(t *testing.T, source *HTTPCloudflareSource, limit int, date time.Time) CandidateSet {
	t.Helper()
	set, err := source.Candidates(context.Background(), limit, date)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	return set
}

// blockOf returns the /24 a candidate was sampled from, which is the unit the
// sample is defined in terms of.
func blockOf(address netip.Addr) netip.Prefix {
	raw := address.As4()
	raw[3] = 0
	return netip.PrefixFrom(netip.AddrFrom4(raw), 24)
}

// fixtureBlocks is every block the standard fixture covers, in the order the
// sorted block list holds them: 4 from 104.16.0.0/22 and 8 from 172.64.0.0/21.
var fixtureBlocks = []netip.Prefix{
	netip.MustParsePrefix("104.16.0.0/24"),
	netip.MustParsePrefix("104.16.1.0/24"),
	netip.MustParsePrefix("104.16.2.0/24"),
	netip.MustParsePrefix("104.16.3.0/24"),
	netip.MustParsePrefix("172.64.0.0/24"),
	netip.MustParsePrefix("172.64.1.0/24"),
	netip.MustParsePrefix("172.64.2.0/24"),
	netip.MustParsePrefix("172.64.3.0/24"),
	netip.MustParsePrefix("172.64.4.0/24"),
	netip.MustParsePrefix("172.64.5.0/24"),
	netip.MustParsePrefix("172.64.6.0/24"),
	netip.MustParsePrefix("172.64.7.0/24"),
}

// writeCacheEntry writes a cache document by hand, so a test can put a state on
// disk that a well-behaved run would never produce: a foreign URL, a corrupt
// body, or an empty validator.
func writeCacheEntry(t *testing.T, cachePath, validator, body, sourceURL string) {
	t.Helper()
	entry, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"url":            sourceURL,
		"etag":           validator,
		"body":           json.RawMessage(body),
	})
	if err != nil {
		t.Fatalf("encode a cache entry: %v", err)
	}
	if err := os.WriteFile(cachePath, entry, 0o600); err != nil {
		t.Fatalf("write a cache entry: %v", err)
	}
}

// cachedValidator returns the validator a cache document holds.
func cachedValidator(t *testing.T, cachePath string) string {
	t.Helper()
	contents, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var document struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode cache: %v", err)
	}
	return document.ETag
}

func TestCloudflareCandidatesServeTheCacheWhenTheOriginIsUnavailable(t *testing.T) {
	// An outage, a 5xx or a renamed field must not shrink the candidate set to
	// nothing: a run that can still reach the addresses it reached yesterday
	// measures them, and says so. The cached document is the one this build
	// accepted, and the set carries the stale flag so the report can record that
	// it is not today's ranges.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	date := testDate(2026, time.September, 25)
	fresh := cloudflareSet(t, newTestSource(t, origin, cachePath), 512, date)
	if fresh.Stale {
		t.Fatal("the first run reported a stale set with no origin failure at all")
	}

	origin.setStatus(http.StatusServiceUnavailable)
	stale := cloudflareSet(t, newTestSource(t, origin, cachePath), 512, date)
	if !stale.Stale {
		t.Error("a set served from the cache after a 503 was not marked stale")
	}
	assertCandidates(t, stale.Candidates, fresh.Candidates)
}

func TestCloudflareCandidatesServeTheCacheWhenTheConnectionFails(t *testing.T) {
	// A transport failure is the same decision as a 5xx: the origin could not be
	// read, so the last validated document stands in for it.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	date := testDate(2026, time.September, 25)
	fresh := cloudflareSet(t, newTestSource(t, origin, cachePath), 512, date)

	origin.setHijack(true)
	stale := cloudflareSet(t, newTestSource(t, origin, cachePath), 512, date)
	if !stale.Stale {
		t.Error("a set served from the cache after a failed connection was not marked stale")
	}
	assertCandidates(t, stale.Candidates, fresh.Candidates)
}

func TestCloudflareCandidatesFailWithoutACacheWhenTheOriginCannotBeRead(t *testing.T) {
	// With nothing cached there is nothing to stand in, and an empty candidate set
	// that looks like a measurement would be worse than a failure. Both kinds of
	// unreadable origin are covered: a status and a connection.
	for name, breakOrigin := range map[string]func(*fakeOrigin){
		"a 503":               func(origin *fakeOrigin) { origin.setStatus(http.StatusServiceUnavailable) },
		"a 404":               func(origin *fakeOrigin) { origin.setStatus(http.StatusNotFound) },
		"a closed connection": func(origin *fakeOrigin) { origin.setHijack(true) },
	} {
		origin := newFakeOrigin(t, standardDocument(), fixtureETag)
		breakOrigin(origin)
		source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
		if set, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
			t.Errorf("Candidates answered with %d candidates and no error after %s", len(set.Candidates), name)
		}
	}
}

func TestCloudflareCandidatesRefuseAFreshDocumentItCannotUse(t *testing.T) {
	// A body that arrived and cannot be used is not an outage, it is a document
	// this build does not understand, and it is a hard error: the cache is not
	// quietly substituted for it, and it is not allowed to overwrite the last
	// document this build did accept either. Both stages are covered, because a
	// document can be refused by the envelope or by the ranges inside it.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))
	validatorBefore := cachedValidator(t, cachePath)

	for name, document := range map[string]string{
		"an envelope that reports a failed request": `{"errors":[{"code":1000,"message":"bad request"}],"messages":[],"result":{"ipv4_cidrs":["104.16.0.0/22"],"ipv6_cidrs":[],"etag":"x"},"success":false}`,
		"a range that is not a prefix":              cloudflareDocument("", fixtureIPv6CIDRs, fixtureETag),
		"a range no rewrite target may use":         cloudflareDocument("10.0.0.0/8", fixtureIPv6CIDRs, fixtureETag),
		"a document that is not JSON":               `not json at all`,
	} {
		origin.setDocument(document)
		source := newTestSource(t, origin, cachePath)
		if set, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
			t.Errorf("Candidates answered with %d candidates from %s", len(set.Candidates), name)
		}
		if got := cachedValidator(t, cachePath); got != validatorBefore {
			t.Errorf("the cache now holds the validator %q after %s, want the last document this build accepted (%q)", got, name, validatorBefore)
		}
	}
}

func TestCloudflareCandidatesRefuseACacheThatNoLongerParses(t *testing.T) {
	// Serve-stale only serves a document this build would still accept. A cache
	// entry that no longer parses is a hard error, because a run must not measure
	// ranges out of a document nobody can read.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))

	// Same source, same schema, a real validator, and a body that decodes but is
	// not a published range list.
	writeCacheEntry(t, cachePath, fixtureETag, `{"errors":[],"messages":[],"result":{"ipv4_cidrs":[],"ipv6_cidrs":[],"etag":"x"},"success":false}`, origin.server.URL)
	origin.setStatus(http.StatusServiceUnavailable)
	if set, err := newTestSource(t, origin, cachePath).Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Errorf("Candidates answered with %d candidates from a cache that no longer parses", len(set.Candidates))
	}
}

func TestCloudflareCandidatesExpandOnlyTheIPv4Ranges(t *testing.T) {
	// The document's IPv6 half is parsed and never expanded: this release
	// selects IPv4 only, and an IPv6 address could never become a rewrite
	// target here.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	got := cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25))
	if len(got) != len(fixtureBlocks) {
		t.Fatalf("got %d candidates %v, want one per IPv4 block (%d)", len(got), got, len(fixtureBlocks))
	}
	for index, candidate := range got {
		if !candidate.IP.Is4() {
			t.Errorf("candidate %d is %v, which is not IPv4", index, candidate.IP)
		}
		if block := blockOf(candidate.IP); block != fixtureBlocks[index] {
			t.Errorf("candidate %d is %v, which is not in the expected block %v", index, candidate.IP, fixtureBlocks[index])
		}
	}
}

func TestCloudflareCandidatesSampleOneAddressPerBlock(t *testing.T) {
	// One address per block: the sample never measures the same block twice, and
	// it never returns fewer blocks than the document covers.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	got := cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25))
	seen := make(map[netip.Prefix]netip.Addr, len(got))
	for index, candidate := range got {
		block := blockOf(candidate.IP)
		if previous, repeated := seen[block]; repeated {
			t.Errorf("block %v produced both %v and %v", block, previous, candidate.IP)
		}
		seen[block] = candidate.IP
		if block != fixtureBlocks[index] {
			t.Errorf("candidate %d is %v, which is not in the expected block %v", index, candidate.IP, fixtureBlocks[index])
		}
	}
	if len(seen) != len(fixtureBlocks) {
		t.Errorf("got %d blocks, want %d", len(seen), len(fixtureBlocks))
	}
}

func TestCloudflareCandidatesNeverSampleTheEdgeOfABlock(t *testing.T) {
	// The network and broadcast addresses of a block are never chosen: the sample
	// has to be an address something answers on. Sixteen days over 2048 blocks
	// is 8192 samples, so this is not a statement about one lucky draw.
	origin := newFakeOrigin(t, cloudflareDocument(wideIPv4CIDRs, fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	sampled := 0
	for day := range 16 {
		for _, candidate := range cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25+day)) {
			host := candidate.IP.As4()[3]
			if host < 1 || host > 254 {
				t.Fatalf("day %d sampled %v, whose host octet is %d", day, candidate.IP, host)
			}
			sampled++
		}
	}
	if sampled != 16*512 {
		t.Errorf("got %d samples, want %d", sampled, 16*512)
	}
}

func TestCloudflareCandidatesSpreadTheHostAddressOverTheBlock(t *testing.T) {
	// The seed decides which host address of a block is sampled, so the addresses
	// have to be spread: one host octet repeated through every block would measure
	// the same offset of every range, which is a pattern, not a sample. Half the
	// possible host addresses is a floor a hash clears and a constant cannot.
	origin := newFakeOrigin(t, cloudflareDocument(wideIPv4CIDRs, fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	hosts := map[byte]struct{}{}
	for _, candidate := range cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25)) {
		hosts[candidate.IP.As4()[3]] = struct{}{}
	}
	if len(hosts) < 128 {
		t.Errorf("512 samples used only %d distinct host addresses, want at least 128", len(hosts))
	}
}

func TestCloudflareCandidatesReproduceTheSampleForTheSameDate(t *testing.T) {
	// A run is reproducible: the same date and the same document give the same
	// addresses, whatever the cache does in between.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	first := newTestSource(t, origin, filepath.Join(t.TempDir(), "first.json"))
	second := newTestSource(t, origin, filepath.Join(t.TempDir(), "second.json"))

	date := testDate(2026, time.September, 25)
	assertCandidates(t, cloudflareCandidates(t, second, 512, date), cloudflareCandidates(t, first, 512, date))
}

func TestCloudflareCandidatesChangeTheSampleForAnotherDate(t *testing.T) {
	// The sample is seeded by the local date, so a new day explores a different
	// address in every block instead of re-probing yesterday's winners forever.
	origin := newFakeOrigin(t, cloudflareDocument(wideIPv4CIDRs, fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	sameDay := cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25))
	nextDay := cloudflareCandidates(t, source, 512, testDate(2026, time.September, 26))
	if slices.Equal(sameDay, nextDay) {
		t.Fatalf("the sample did not change with the date: %v", sameDay[:4])
	}
}

func TestCloudflareCandidatesNeverExceedTheLimit(t *testing.T) {
	// 2048 blocks, 512 candidates: the chosen blocks are spread across the whole
	// published range rather than taken from its start, so the cap does not turn
	// the sample into the same few thousand addresses every day.
	origin := newFakeOrigin(t, cloudflareDocument(wideIPv4CIDRs, fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	got := cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25))
	if len(got) != 512 {
		t.Fatalf("got %d candidates, want the limit of 512", len(got))
	}
	// The i-th of 512 blocks out of 2048 is the 4i-th, so the first two are the
	// first and fifth block of the range and the last is 2044 blocks in.
	for index, want := range map[int]string{0: "104.16.0.0/24", 1: "104.16.4.0/24", 511: "104.23.252.0/24"} {
		if block := blockOf(got[index].IP); block.String() != want {
			t.Errorf("candidate %d came from %v, want the block %s", index, block, want)
		}
	}
}

func TestCloudflareCandidatesChooseTheBlocksInSortedOrder(t *testing.T) {
	// The ranges are sorted before the blocks are chosen from them, so which
	// blocks a limit keeps cannot depend on the order the origin happened to list
	// them in. This document lists a 256 block range before a one block range, and
	// the sorted list is 257 long, so the i-th of 128 chosen blocks is the
	// floor(i*257/128)-th: 104.16.0.0/24, 172.64.1.0/24, and last 172.64.253.0/24.
	origin := newFakeOrigin(t, cloudflareDocument("172.64.0.0/16,104.16.0.0/24", fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	got := cloudflareCandidates(t, source, 128, testDate(2026, time.September, 25))
	if len(got) != 128 {
		t.Fatalf("got %d candidates, want the limit of 128", len(got))
	}
	for index, want := range map[int]string{0: "104.16.0.0/24", 1: "172.64.1.0/24", 127: "172.64.253.0/24"} {
		if block := blockOf(got[index].IP); block.String() != want {
			t.Errorf("candidate %d came from %v, want the block %s", index, block, want)
		}
	}
}

func TestCloudflareCandidatesSampleAnOverlappingRangeOnce(t *testing.T) {
	// Ranges that overlap cover the same block twice, and a block sampled twice is
	// one address measured twice: the probe budget and the report both count it.
	origin := newFakeOrigin(t, cloudflareDocument("104.16.0.0/22,104.16.1.0/24", fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))

	got := cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25))
	if len(got) != 4 {
		t.Fatalf("got %d candidates %v, want one for each of the four blocks of 104.16.0.0/22", len(got), got)
	}
	for index, candidate := range got {
		if block := blockOf(candidate.IP); block != fixtureBlocks[index] {
			t.Errorf("candidate %d is %v, which is not in %v", index, candidate.IP, fixtureBlocks[index])
		}
	}
}

func TestCloudflareCandidatesRefuseANonPositiveLimit(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	for _, limit := range []int{0, -1} {
		if _, err := source.Candidates(context.Background(), limit, testDate(2026, time.September, 25)); err == nil {
			t.Errorf("Candidates accepted the limit %d", limit)
		}
	}
}

func TestCloudflareCandidatesRefuseAnUnsetLocalDate(t *testing.T) {
	// A zero date would seed every run with the same constant, which is the
	// failure the injected date exists to catch.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if _, err := source.Candidates(context.Background(), 512, time.Time{}); err == nil {
		t.Error("Candidates accepted an unset local date")
	}
}

func TestCloudflareCandidatesRefuseARangeNoRewriteTargetMayUse(t *testing.T) {
	// A document that names reserved space is refused whole: a range that
	// contains one unusable address cannot be sampled honestly, and the limit
	// would drop most of it before anyone noticed.
	reserved := newFakeOrigin(t, cloudflareDocument("104.16.0.0/22,10.0.0.0/8", fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	if _, err := newTestSource(t, reserved, filepath.Join(t.TempDir(), "first.json")).Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a document naming 10.0.0.0/8")
	}
	// The harder case: 100.0.0.0/9 has a public network address and still covers
	// the 100.64.0.0/10 carrier-grade range, so it is a sampled address that has to
	// be refused, not a range that can be refused before sampling.
	overlapping := newFakeOrigin(t, cloudflareDocument("104.16.0.0/22,100.0.0.0/9", fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	if _, err := newTestSource(t, overlapping, filepath.Join(t.TempDir(), "second.json")).Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a document naming 100.0.0.0/9, which covers reserved space")
	}
}

func TestCloudflareCandidatesRefuseAMalformedDocument(t *testing.T) {
	for name, document := range map[string]string{
		"not JSON":                       `not json at all`,
		"a failed request":               `{"errors":[{"code":1000,"message":"bad request"}],"messages":[],"result":{"ipv4_cidrs":[],"ipv6_cidrs":[],"etag":"x"},"success":false}`,
		"no result":                      `{"errors":[],"messages":[],"success":true}`,
		"no IPv4 range":                  cloudflareDocument("", fixtureIPv6CIDRs, fixtureETag),
		"no etag":                        cloudflareDocument(fixtureIPv4CIDRs, fixtureIPv6CIDRs, ""),
		"a malformed IPv4 range":         cloudflareDocument("104.16.0.0/33", fixtureIPv6CIDRs, fixtureETag),
		"an IPv6 range in the IPv4 list": cloudflareDocument("2606:4700::/32", fixtureIPv6CIDRs, fixtureETag),
		"an IPv4 range in the IPv6 list": cloudflareDocument(fixtureIPv4CIDRs, "104.16.0.0/22", fixtureETag),
		"a malformed IPv6 range":         cloudflareDocument(fixtureIPv4CIDRs, "2606:4700::/129", fixtureETag),
		"a trailing document":            standardDocument() + `{"success":true}`,
	} {
		origin := newFakeOrigin(t, document, fixtureETag)
		source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
		if candidates, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
			t.Errorf("Candidates accepted a document that is %s and returned %v", name, candidates)
		}
	}
}

func TestCloudflareCandidatesRefuseADocumentCoveringTooManyBlocks(t *testing.T) {
	// A document is bounded so one wide range cannot make the sample walk
	// millions of blocks before the limit chooses from them. A single /3 covers
	// 2097152 of them, far past what any CDN publishes.
	origin := newFakeOrigin(t, cloudflareDocument("1.0.0.0/3,8.0.0.0/5", fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if _, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a document covering more blocks than the bound")
	}
}

func TestCloudflareCandidatesRefuseADocumentAboveTheByteBound(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	origin.streamBytes = 8 << 20
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if _, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a body larger than the document bound")
	}
}

func TestCloudflareCandidatesRefuseAnUnexpectedStatus(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	origin.setStatus(http.StatusServiceUnavailable)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if _, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a 503 response")
	}
}

func TestCloudflareCandidatesRefuseAResponseWithoutAValidator(t *testing.T) {
	// A body with no ETag could never be revalidated, so caching it would only
	// hide a changed document behind a stale one.
	origin := newFakeOrigin(t, standardDocument(), "")
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if _, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a response with no ETag")
	}
}

func TestCloudflareCandidatesReuseTheCachedBodyOnANotModifiedResponse(t *testing.T) {
	// The second run revalidates with the stored validator and takes its ranges
	// from the cache, so an unchanged document costs a 304 and no body.
	cachePath := filepath.Join(t.TempDir(), "lists", "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	first := newTestSource(t, origin, cachePath)
	date := testDate(2026, time.September, 25)
	want := cloudflareCandidates(t, first, 512, date)

	origin.setNotModified(true)
	second := newTestSource(t, origin, cachePath)
	got := cloudflareCandidates(t, second, 512, date)

	assertCandidates(t, got, want)
	requests := origin.requests()
	if len(requests) != 2 {
		t.Fatalf("got %d requests, want one per run", len(requests))
	}
	if requests[1].ifNoneMatch != fixtureETag {
		t.Errorf("second request sent If-None-Match %q, want the stored %q", requests[1].ifNoneMatch, fixtureETag)
	}
	if origin.bodiesServed() != 1 {
		t.Errorf("the origin served %d bodies, want only the first", origin.bodiesServed())
	}
}

func TestCloudflareCandidatesRefuseACacheWithNoValidator(t *testing.T) {
	// A cache entry with no validator is not evidence about anything: it cannot be
	// revalidated, and a conditional request carrying an empty validator is a
	// malformed request a strict origin may answer with 400. So the entry is not
	// used, which means no conditional header is sent at all, and the run refetches
	// and replaces it with a document that carries one.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	// Every other field is one a well-behaved run would write: the same source, a
	// document that parses, and a body this build would accept. The empty
	// validator is the only thing wrong, so the refusal cannot be another rule
	// answering for it.
	writeCacheEntry(t, cachePath, "", standardDocument(), origin.server.URL)
	want := cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))

	requests := origin.requests()
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if requests[0].hasValidator {
		t.Errorf("the request revalidated against a cache with no validator, sending If-None-Match %q", requests[0].ifNoneMatch)
	}
	if got := cachedValidator(t, cachePath); got != fixtureETag {
		t.Errorf("the cache now holds the validator %q, want the one the origin sent %q", got, fixtureETag)
	}
	if len(want) != len(fixtureBlocks) {
		t.Errorf("got %d candidates, want one per block", len(want))
	}
}

func TestCloudflareCandidatesDoNotStoreABodyTheyRefuse(t *testing.T) {
	// A body with no validator is refused, so it must never reach the cache: a
	// stored copy of a document this run would not use is a file a later run has
	// to distrust, and there is nothing to revalidate it with anyway.
	root := t.TempDir()
	cachePath := filepath.Join(root, "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), "")
	if _, err := newTestSource(t, origin, cachePath).Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Fatal("Candidates accepted a body with no validator")
	}
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused body was written to %s (stat error %v)", cachePath, err)
	}
}

// The same rule for a refusal that happens after the body has been read and
// understood, which is the case the no-validator case cannot reach: that one is
// refused before a byte of the body is read, so it says nothing about whether a
// body this build parsed and then rejected reaches the disk.
//
// This document is a well-formed response - success, a revision marker, a document
// this build could sample - that names no IPv4 range at all. Every earlier gate
// accepts it, and only the "names no IPv4 range" refusal stands between it and the
// cache. A stored copy would be worse than the no-validator one: this body could be
// revalidated, so a later run would read it and be told the origin's ranges were
// empty.
func TestCloudflareCandidatesDoNotStoreABodyTheyRefuseAfterReadingIt(t *testing.T) {
	empty := `{"success":true,"errors":[],"messages":[],` +
		`"result":{"etag":"empty-lists","ipv4_cidrs":[],"ipv6_cidrs":[]}}`
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, empty, "empty-lists")

	_, err := newTestSource(t, origin, cachePath).Candidates(context.Background(), 512, testDate(2026, time.September, 25))
	if err == nil {
		t.Fatal("Candidates accepted a document naming no IPv4 range")
	}
	if !strings.Contains(err.Error(), "no IPv4 range") {
		t.Errorf("the refusal %q does not name the empty range list, so this case may be testing another rule", err)
	}
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a body refused after it was read was written to %s (stat error %v): the cache is written only after the document is accepted", cachePath, err)
	}
}

func TestCloudflareCandidatesRefuseANotModifiedResponseWithNoCache(t *testing.T) {
	// A 304 with nothing cached is a broken validator, not a document.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	origin.setNotModified(true)
	source := newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if _, err := source.Candidates(context.Background(), 512, testDate(2026, time.September, 25)); err == nil {
		t.Error("Candidates accepted a 304 response with no cached document")
	}
}

func TestCloudflareCacheKeepsTheValidatorAndTheBodyVerbatim(t *testing.T) {
	// The cache holds the body as it arrived and the validator that describes it,
	// because the next run has to revalidate with one and read the other.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))

	contents, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var document struct {
		SchemaVersion int             `json:"schema_version"`
		URL           string          `json:"url"`
		ETag          string          `json:"etag"`
		Body          json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode cache: %v (%s)", err, contents)
	}
	if document.ETag != fixtureETag {
		t.Errorf("cache holds the validator %q, want %q", document.ETag, fixtureETag)
	}
	if string(document.Body) != standardDocument() {
		t.Errorf("cache holds the body %q, want the served document verbatim", document.Body)
	}
	if document.URL != origin.server.URL {
		t.Errorf("cache records the source %q, want %q", document.URL, origin.server.URL)
	}
}

func TestCloudflareCacheIsWrittenOnlyUnderTheInjectedPath(t *testing.T) {
	// The cache path is injected, so a test never writes the production path
	// under /var/lib and a run never writes anywhere else.
	root := t.TempDir()
	cachePath := filepath.Join(root, "lists", "cloudflare-ips.json")
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))

	var written []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			written = append(written, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk the injected cache root: %v", err)
	}
	if len(written) != 1 || written[0] != cachePath {
		t.Errorf("the run wrote %v, want only %s", written, cachePath)
	}
}

func TestCloudflareCandidatesReplaceACacheTheyCannotRead(t *testing.T) {
	// A cache this build cannot read is replaced, not trusted: the run refetches
	// and no validator is sent, because a corrupt cache has no validator to send.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	if err := os.WriteFile(cachePath, []byte("{not a cache document"), 0o600); err != nil {
		t.Fatalf("write a corrupt cache: %v", err)
	}
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))

	requests := origin.requests()
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if requests[0].ifNoneMatch != "" {
		t.Errorf("the request sent If-None-Match %q for a corrupt cache", requests[0].ifNoneMatch)
	}
	contents, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if strings.Contains(string(contents), "not a cache document") {
		t.Errorf("the corrupt cache was not replaced: %s", contents)
	}
}

func TestCloudflareCandidatesIgnoreACacheWrittenForAnotherSource(t *testing.T) {
	// A cache is only evidence about the document it was read from, so one that
	// names another source is not used to revalidate this one.
	cachePath := filepath.Join(t.TempDir(), "cloudflare-ips.json")
	foreign, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"url":            "https://example.invalid/other.json",
		"etag":           `W/"stale"`,
		"body":           json.RawMessage(standardDocument()),
	})
	if err != nil {
		t.Fatalf("encode a foreign cache: %v", err)
	}
	if err := os.WriteFile(cachePath, foreign, 0o600); err != nil {
		t.Fatalf("write a foreign cache: %v", err)
	}
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cloudflareCandidates(t, newTestSource(t, origin, cachePath), 512, testDate(2026, time.September, 25))

	requests := origin.requests()
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if requests[0].ifNoneMatch != "" {
		t.Errorf("the request revalidated against a cache written for another source: %q", requests[0].ifNoneMatch)
	}
}

func TestCloudflareCandidatesUseTheProductionEndpointByDefault(t *testing.T) {
	// The default endpoint is the real one; the host-rewriting transport is what
	// keeps this off the network, so the request path is still checked.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	source, err := NewCloudflareSource(hostRewritingClient(t, origin), "", filepath.Join(t.TempDir(), "cloudflare-ips.json"))
	if err != nil {
		t.Fatalf("NewCloudflareSource: %v", err)
	}
	cloudflareCandidates(t, source, 512, testDate(2026, time.September, 25))

	requests := origin.requests()
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if requests[0].path != "/client/v4/ips" {
		t.Errorf("the default source requested %q, want the Cloudflare IP endpoint path", requests[0].path)
	}
	if requests[0].acceptHeader != "application/json" {
		t.Errorf("the request sent Accept %q, want application/json", requests[0].acceptHeader)
	}
}

func TestNewCloudflareSourceRefusesANilClient(t *testing.T) {
	if _, err := NewCloudflareSource(nil, "https://example.invalid/ips", filepath.Join(t.TempDir(), "cache.json")); err == nil {
		t.Error("NewCloudflareSource accepted a nil HTTP client")
	}
}

func TestCloudflareCandidatesKeepTheUserLabelOnAnAddressTheSampleAlsoNames(t *testing.T) {
	// The source field is provenance, not ownership: an address the operator
	// pinned keeps the user label even where the official sample names the same
	// address, and it is measured once rather than twice.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	official := cloudflareCandidates(t, newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json")), 512, testDate(2026, time.September, 25))
	pinned := official[3].IP

	user, err := ParseUserList(strings.NewReader(pinned.String() + "\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	got, err := Combine(official, user, nil, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(got) != len(official) {
		t.Fatalf("got %d candidates, want the %d of the sample with the pinned address measured once", len(got), len(official))
	}
	labelled := 0
	for _, candidate := range got {
		if candidate.IP == pinned {
			labelled++
			if candidate.Source != SourceUser {
				t.Errorf("the pinned address %v is labelled %q, want %q", pinned, candidate.Source, SourceUser)
			}
		}
	}
	if labelled != 1 {
		t.Errorf("the pinned address appears %d times, want once", labelled)
	}
}

func TestCloudflareCandidatesKeepAAddressTheDailySampleDropped(t *testing.T) {
	// The official sample reseeds every day, so today's winner is often absent
	// from tomorrow's candidates. The retained candidate is what makes it
	// re-provable anyway, and it is never counted against the limit.
	origin := newFakeOrigin(t, cloudflareDocument(wideIPv4CIDRs, fixtureIPv6CIDRs, fixtureETag), fixtureETag)
	official := cloudflareCandidates(t, newTestSource(t, origin, filepath.Join(t.TempDir(), "cloudflare-ips.json")), 512, testDate(2026, time.September, 26))
	winner := publicCandidate(SourceRetained, "9.9.9.9")
	fallback := publicCandidate(SourceRetained, "8.8.8.8")
	if slices.Contains(official, winner) || slices.Contains(official, fallback) {
		t.Fatalf("the fixture no longer drops the retained addresses: %v", official)
	}

	got, err := Combine(official, nil, []Candidate{winner, fallback}, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(got) != 514 {
		t.Fatalf("got %d candidates, want the 512 capped official ones plus the winner and the fallback", len(got))
	}
	if !slices.Contains(got, winner) || !slices.Contains(got, fallback) {
		t.Errorf("the retained winner or fallback was dropped: %v", got[len(got)-2:])
	}
}
