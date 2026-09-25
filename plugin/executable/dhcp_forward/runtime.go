package dhcp_forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/concurrent_lru"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"mosdns-router/internal/state"
)

// dnsPort is the port a DHCP DNS server answers on.
const dnsPort uint16 = 53

// truncatedResponseBit is the TC flag in the second byte of a DNS header.
const truncatedResponseBit = 1 << 1

// minimumAnswerHeaderSize is the size of a DNS header, so a payload this short
// cannot be read for its flags.
const minimumAnswerHeaderSize = 12

var (
	errClosed       = errors.New("dhcp_forward: the plugin is closed")
	errNoGeneration = errors.New("dhcp_forward: no valid DHCP state is available")
	errDisabled     = errors.New("dhcp_forward: the current DHCP generation has no upstream")
	errNoQuestion   = errors.New("dhcp_forward: a forwarded query must carry exactly one question")
	errAllFailed    = errors.New("dhcp_forward: every DHCP upstream failed")
)

// readStateFunc loads one published state document and validates it.
type readStateFunc func(path string) (state.DHCPState, error)

// readDHCPState is the production reader. It goes through the strict state
// decoder, so a state file carrying a local, multicast, zoned, or otherwise
// unusable upstream is refused instead of redirecting domestic queries.
func readDHCPState(path string) (state.DHCPState, error) {
	var published state.DHCPState
	if err := state.ReadJSON(path, &published); err != nil {
		return state.DHCPState{}, err
	}
	return published, nil
}

// fileSignature is what the reload looks at before it reads the state file. The
// bridge publishes with a same-directory rename, so a new generation always
// arrives with a new modification time; an unchanged file is not read again on
// every query.
type fileSignature struct {
	exists  bool
	modTime time.Time
	size    int64
}

// runtime owns the published generations. One query at a time reloads the state
// file, so every query sees the current generation before it looks in a cache.
// Queries read the current generation through an atomic pointer and never wait
// for the reload lock.
type runtime struct {
	logger    *zap.Logger
	read      readStateFunc
	stateFile string
	port      uint16

	timeout      time.Duration
	concurrency  int
	retireAfter  time.Duration
	cacheEntries int

	reloadMu sync.Mutex
	current  atomic.Pointer[runtimeGeneration]
	retired  []*runtimeGeneration
	observed fileSignature
	// unreadable records that the last read of the current file failed, so the
	// file is read again on the next query and the failure is reported once.
	unreadable bool
	closed     bool
}

// runtimeGeneration is one published DHCP state: the upstream clients it needs,
// the cache its answers live in, and the instant its clients may be released.
type runtimeGeneration struct {
	generation uint64
	endpoints  []*endpoint
	cache      *responseCache

	// retireAt is zero while the generation is current.
	retireAt time.Time
	closed   bool
}

// endpoint is one upstream address with the client pair a query needs. The UDP
// client never falls back to TCP on its own, so a truncated answer is retried
// over the TCP client this plugin owns and can account for.
type endpoint struct {
	address string
	udp     upstream.Upstream
	tcp     upstream.Upstream
}

func (e *endpoint) close() error {
	return errors.Join(e.udp.Close(), e.tcp.Close())
}

// exchange answers one query from the current generation.
func (r *runtime) exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// A mosdns context always carries exactly one question, so anything else is
	// refused here instead of indexing into an empty slice.
	if len(query.Question) != 1 {
		return nil, errNoQuestion
	}
	generation, err := r.reload()
	if err != nil {
		return nil, err
	}
	if len(generation.endpoints) == 0 {
		return nil, errDisabled
	}

	key := newCacheKey(generation.generation, query)
	if answer, ok := generation.cache.get(key, time.Now()); ok {
		return answer, nil
	}

	response, err := r.race(ctx, generation, query)
	if err != nil {
		return nil, err
	}
	// Only the current generation may publish an answer. A generation that was
	// replaced while the query was in flight must not fill the new generation's
	// cache with an answer its upstreams never produced.
	if r.current.Load() == generation {
		generation.cache.put(key, response, time.Now())
	}
	return response, nil
}

// race asks up to the configured number of distinct upstreams and prefers a
// response that answers the question over one that reports a failure.
func (r *runtime) race(ctx context.Context, generation *runtimeGeneration, query *dns.Msg) (*dns.Msg, error) {
	wire, err := pool.PackBuffer(query)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(wire)

	picked := generation.pick(query.Question[0].Name, r.concurrency)

	type outcome struct {
		response *dns.Msg
		err      error
	}
	outcomes := make(chan outcome, len(picked))
	for _, candidate := range picked {
		payload := copyPayload(*wire)
		go func(candidate *endpoint) {
			response, err := r.ask(ctx, candidate, payload)
			select {
			case outcomes <- outcome{response: response, err: err}:
			case <-ctx.Done():
			}
		}(candidate)
	}

	var failure *dns.Msg
	var failureErr error
	for range picked {
		select {
		case result := <-outcomes:
			if result.err != nil {
				if failureErr == nil {
					failureErr = result.err
				}
				continue
			}
			if answerable(result.response) {
				return result.response, nil
			}
			if failure == nil {
				failure = result.response
			}
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	if failure != nil {
		return failure, nil
	}
	if failureErr != nil {
		return nil, failureErr
	}
	return nil, errAllFailed
}

// ask runs one upstream attempt. The UDP answer and its TCP retry share a single
// budget, which is what makes the upstream timeout a bound on any one exchange
// and lets the retirement window be trusted to outlive it.
func (r *runtime) ask(ctx context.Context, candidate *endpoint, payload []byte) (*dns.Msg, error) {
	attempt, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	response, err := candidate.udp.ExchangeContext(attempt, payload)
	if err != nil {
		return nil, err
	}
	if !truncated(response) {
		return unpack(response)
	}
	pool.ReleaseBuf(response)

	response, err = candidate.tcp.ExchangeContext(attempt, payload)
	if err != nil {
		return nil, fmt.Errorf("dhcp_forward: %s: truncated udp answer, tcp retry: %w", candidate.address, err)
	}
	return unpack(response)
}

// reload returns the current generation, replacing it when the state file
// publishes a strictly newer one. A missing, unreadable, invalid, or older file
// leaves the last valid generation in place.
func (r *runtime) reload() (*runtimeGeneration, error) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	if r.closed {
		return nil, errClosed
	}
	r.sweep(time.Now())

	generation, err := r.reloadGeneration()
	if err != nil {
		return nil, err
	}
	if generation == nil {
		return nil, errNoGeneration
	}
	return generation, nil
}

// reloadGeneration re-reads the state file if the file changed. It must be
// called with the reload lock held.
func (r *runtime) reloadGeneration() (*runtimeGeneration, error) {
	signature, err := statStateFile(r.stateFile)
	if err != nil {
		// Nothing to read yet. The file is not read until it exists, and the
		// current generation keeps serving.
		r.logger.Debug("no dhcp state file yet", zap.String("path", r.stateFile), zap.Error(err))
		return r.current.Load(), nil
	}
	if signature == r.observed && !r.unreadable {
		return r.current.Load(), nil
	}

	published, err := r.read(r.stateFile)
	if err != nil {
		// The signature is deliberately not remembered. A read that failed once
		// must not leave the router waiting for the next DHCP event, and the
		// failure is reported once per streak instead of once per query.
		if !r.unreadable {
			r.unreadable = true
			r.logger.Warn("keeping the current dhcp generation: the published state is unusable",
				zap.String("path", r.stateFile), zap.Error(err))
		}
		return r.current.Load(), nil
	}
	r.unreadable = false
	r.observed = signature

	current := r.current.Load()
	if current != nil && published.Generation <= current.generation {
		r.logger.Warn("keeping the current dhcp generation: the published state is not newer",
			zap.String("path", r.stateFile),
			zap.Uint64("published_generation", published.Generation),
			zap.Uint64("current_generation", current.generation))
		return current, nil
	}

	replacement, err := newRuntimeGeneration(published, r)
	if err != nil {
		r.logger.Warn("keeping the current dhcp generation: its upstreams are unusable",
			zap.String("path", r.stateFile), zap.Error(err))
		return current, nil
	}

	now := time.Now()
	if current != nil {
		current.retireAt = now.Add(r.retireAfter)
		r.retired = append(r.retired, current)
		r.logger.Info("dhcp upstream generation replaced",
			zap.Uint64("generation", replacement.generation),
			zap.Uint64("replaced_generation", current.generation),
			zap.Int("upstreams", len(replacement.endpoints)),
			zap.Duration("retire_after", r.retireAfter))
	}
	r.current.Store(replacement)
	return replacement, nil
}

// sweep releases the generations whose retirement window has passed. It must be
// called with the reload lock held.
func (r *runtime) sweep(now time.Time) {
	kept := r.retired[:0]
	for _, generation := range r.retired {
		if now.Before(generation.retireAt) {
			kept = append(kept, generation)
			continue
		}
		r.logger.Info("releasing a retired dhcp upstream generation", zap.Uint64("generation", generation.generation))
		_ = generation.close()
	}
	r.retired = kept
}

// close releases every client the runtime owns. It is safe to call more than
// once, and a query after it fails closed.
func (r *runtime) close() error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	var err error
	if generation := r.current.Swap(nil); generation != nil {
		err = errors.Join(err, generation.close())
	}
	for _, generation := range r.retired {
		err = errors.Join(err, generation.close())
	}
	r.retired = nil
	return err
}

// newRuntimeGeneration builds the clients and the cache of one published state.
// An empty upstream list is a valid, disabled generation.
func newRuntimeGeneration(published state.DHCPState, r *runtime) (*runtimeGeneration, error) {
	generation := &runtimeGeneration{
		generation: published.Generation,
		cache:      newResponseCache(r.cacheEntries),
	}
	for _, address := range published.Upstreams {
		candidate, err := newEndpoint(address, published.Interface, r.port, r.logger)
		if err != nil {
			_ = generation.close()
			return nil, err
		}
		if generation.hasEndpoint(candidate.address) {
			// A repeated address would make the rotation pick the same upstream
			// twice in one query.
			_ = candidate.close()
			continue
		}
		generation.endpoints = append(generation.endpoints, candidate)
	}
	return generation, nil
}

func (g *runtimeGeneration) hasEndpoint(address string) bool {
	for _, candidate := range g.endpoints {
		if candidate.address == address {
			return true
		}
	}
	return false
}

// close releases the clients of a generation that is never used again. Its cache
// entries go with it: no query reads a released generation's cache.
func (g *runtimeGeneration) close() error {
	if g.closed {
		return nil
	}
	g.closed = true
	var err error
	for _, candidate := range g.endpoints {
		err = errors.Join(err, candidate.close())
	}
	return err
}

// pick chooses the endpoints one query races. The rotation is a hash of the
// question name, so the same question always starts at the same upstream, with
// no global random source, while different questions spread over the whole set.
func (g *runtimeGeneration) pick(qname string, concurrency int) []*endpoint {
	count := min(concurrency, len(g.endpoints))
	if count <= 0 {
		return nil
	}
	total := uint64(len(g.endpoints))
	start := hashName(qname) % total
	picked := make([]*endpoint, count)
	for index := range picked {
		picked[index] = g.endpoints[(start+uint64(index))%total]
	}
	return picked
}

// hashName is FNV-1a over the question name, which is stable across processes
// and needs no seeding.
func hashName(name string) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	hash := uint64(offset)
	for index := range len(name) {
		hash ^= uint64(name[index])
		hash *= prime
	}
	return hash
}

// newEndpoint turns one published address into a dialable endpoint. A bare IPv6
// link-local address only routes through the interface that owns it, and the
// state records that interface instead of a zone in the address, so the zone is
// added here. The address is assembled from parsed parts only.
func newEndpoint(address, interfaceName string, port uint16, logger *zap.Logger) (*endpoint, error) {
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("dhcp_forward: upstream %q is not an IP address: %w", address, err)
	}
	if parsed.Zone() == "" && parsed.Is6() && parsed.IsLinkLocalUnicast() {
		if interfaceName == "" {
			return nil, fmt.Errorf("dhcp_forward: upstream %q is link-local and the state records no interface", address)
		}
		parsed = parsed.WithZone(interfaceName)
	}

	addrPort := netip.AddrPortFrom(parsed, port)
	candidate := &endpoint{address: addrPort.String()}
	candidate.udp = &udpClient{target: net.UDPAddrFromAddrPort(addrPort)}

	// The TCP client is built from a parsed host and port, so an address that
	// needs brackets or carries a zone cannot be mangled by concatenation.
	tcpURL := (&url.URL{Scheme: "tcp", Host: net.JoinHostPort(parsed.String(), strconv.Itoa(int(port)))}).String()
	tcpUpstream, err := upstream.NewUpstream(tcpURL, upstream.Opt{Logger: logger})
	if err != nil {
		_ = candidate.udp.Close()
		return nil, fmt.Errorf("dhcp_forward: upstream %q has no usable tcp client: %w", address, err)
	}
	candidate.tcp = tcpUpstream
	return candidate, nil
}

// udpClient exchanges a query over one connected UDP socket that lives exactly as
// long as the query.
//
// The plugin keeps this exchange itself on purpose. mosdns's pipelined UDP
// transport re-sends any query that has not been answered within a second, which
// would send a DHCP query to the upstream twice, and it can drop an answer that
// arrives before its exchange starts waiting for it, which costs a full timeout.
// One write and one read on one socket the caller owns can do neither.
type udpClient struct {
	target *net.UDPAddr
}

func (c *udpClient) ExchangeContext(ctx context.Context, query []byte) (*[]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", c.target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	payload := pool.GetBuf(dns.MaxMsgSize)
	type readResult struct {
		size int
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		size, err := conn.Read(*payload)
		read <- readResult{size: size, err: err}
	}()

	select {
	case result := <-read:
		if result.err != nil {
			pool.ReleaseBuf(payload)
			return nil, result.err
		}
		*payload = (*payload)[:result.size]
		return payload, nil
	case <-ctx.Done():
		// Closing the socket is what releases the read; the goroutine then
		// reports into a buffered channel and exits.
		_ = conn.Close()
		return nil, context.Cause(ctx)
	}
}

// Close releases the client. Every socket belongs to one exchange, so there is
// nothing left to hold.
func (c *udpClient) Close() error {
	return nil
}

// answerable reports whether a response answers the question. Only those are
// preferred over a failure, and only those are cacheable.
func answerable(response *dns.Msg) bool {
	return response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError
}

func truncated(payload *[]byte) bool {
	return len(*payload) >= minimumAnswerHeaderSize && (*payload)[2]&truncatedResponseBit != 0
}

func unpack(payload *[]byte) (*dns.Msg, error) {
	defer pool.ReleaseBuf(payload)
	response := new(dns.Msg)
	if err := response.Unpack(*payload); err != nil {
		return nil, err
	}
	return response, nil
}

func copyPayload(payload []byte) []byte {
	duplicate := make([]byte, len(payload))
	copy(duplicate, payload)
	return duplicate
}

func statStateFile(path string) (fileSignature, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileSignature{}, err
	}
	return fileSignature{exists: true, modTime: info.ModTime(), size: info.Size()}, nil
}

// --- the generation scoped cache ---

// cacheKey identifies one cached answer. Two questions share a key only when the
// upstream could not have answered them differently: the same name, type, and
// class, the same DNSSEC and checking-disabled flags, and the same client subnet.
// The generation is part of the key so an entry can never be attributed to
// another set of upstreams.
type cacheKey struct {
	generation uint64
	qname      string
	qtype      uint16
	qclass     uint16
	do         bool
	cd         bool
	clientNet  string
}

func newCacheKey(generation uint64, query *dns.Msg) cacheKey {
	question := query.Question[0]
	key := cacheKey{
		generation: generation,
		qname:      strings.ToLower(question.Name),
		qtype:      question.Qtype,
		qclass:     question.Qclass,
		cd:         query.CheckingDisabled,
	}
	if opt := query.IsEdns0(); opt != nil {
		key.do = opt.Do()
		key.clientNet = clientSubnetIdentity(opt)
	}
	return key
}

// clientSubnetIdentity describes the client subnet option, the only EDNS0 option
// this router forwards upstream that changes the answer.
func clientSubnetIdentity(opt *dns.OPT) string {
	for _, option := range opt.Option {
		subnet, ok := option.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		return strconv.Itoa(int(subnet.Family)) + "/" + subnet.Address.String() + "/" + strconv.Itoa(int(subnet.SourceNetmask))
	}
	return ""
}

type cacheEntry struct {
	message  *dns.Msg
	storedAt time.Time
	ttl      uint32
}

// responseCache is one generation's bounded cache. It holds copies only, so a
// caller can never change an entry another query will be served.
type responseCache struct {
	entries *concurrent_lru.ConcurrentLRU[cacheKey, cacheEntry]
}

func newResponseCache(maxEntries int) *responseCache {
	return &responseCache{entries: concurrent_lru.NewConecurrentLRU[cacheKey, cacheEntry](maxEntries, nil)}
}

// get returns a copy of the cached answer with the time it has been waiting
// subtracted from its TTLs. An entry with no time left is a miss, not an answer
// with a zero TTL.
func (c *responseCache) get(key cacheKey, now time.Time) (*dns.Msg, bool) {
	entry, ok := c.entries.Get(key)
	if !ok {
		return nil, false
	}
	waited := time.Duration(0)
	if now.After(entry.storedAt) {
		waited = now.Sub(entry.storedAt)
	}
	elapsed := uint32(waited / time.Second)
	if elapsed >= entry.ttl {
		c.entries.Del(key)
		return nil, false
	}
	remaining := entry.ttl - elapsed
	answer := entry.message.Copy()
	setTTL(answer, remaining)
	return answer, true
}

// put stores an answer that can be reused: a response that answers the question
// and carries a positive TTL. A SERVFAIL, a REFUSED, a bare NXDOMAIN without an
// SOA, and a zero TTL are all left uncached.
func (c *responseCache) put(key cacheKey, response *dns.Msg, now time.Time) {
	ttl, ok := cacheableTTL(response)
	if !ok {
		return
	}
	c.entries.Add(key, cacheEntry{message: response.Copy(), storedAt: now, ttl: ttl})
}

// cacheableTTL is the smallest TTL in the answer, which is how long every record
// in it stays valid.
func cacheableTTL(response *dns.Msg) (uint32, bool) {
	if !answerable(response) {
		return 0, false
	}
	minimum := uint32(0)
	found := false
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range section {
			if _, isOPT := record.(*dns.OPT); isOPT {
				continue
			}
			ttl := record.Header().Ttl
			if !found || ttl < minimum {
				minimum, found = ttl, true
			}
		}
	}
	if !found || minimum == 0 {
		return 0, false
	}
	return minimum, true
}

func setTTL(response *dns.Msg, ttl uint32) {
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range section {
			if _, isOPT := record.(*dns.OPT); isOPT {
				continue
			}
			record.Header().Ttl = ttl
		}
	}
}
