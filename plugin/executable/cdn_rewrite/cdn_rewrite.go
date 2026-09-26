// Package cdn_rewrite is the recursive plugin that decides whose network a
// client should reach, and forces ECH for the domains an operator listed.
//
// It is the first executable in the foreign path, so the cache and the forwarder
// are downstream of it and a rewrite is applied to a copy of a cache hit rather
// than to the object the cache owns. Every decision it makes is a claim about a
// third party's network, so each one is made from a document this build validated
// and each one is refused rather than guessed at:
//
//   - A rewrite installs the selector's winner, and only while the winner's proof
//     window is open. The window is refreshed by the health check every two
//     minutes, so an open window is a live certificate, Host and SNI proof of the
//     address in service rather than a nightly snapshot of one. An expired or zero
//     window means no rewrite and the upstream's own answer, and a strict
//     force-ECH domain fails closed instead.
//   - An address is installed only for a response every terminal address of which
//     is inside a published Cloudflare range, and never for a response serving
//     more than one network. A per-hostname CloudFront mapping is exact: it covers
//     the name it was proved for and neither its parent nor its siblings.
//   - ECH is forced only for a name on the operator's allowlist, and a strict
//     name's A and AAAA are answered with an empty answer that costs no upstream
//     lookup at all, because a client that resolved the name could connect in the
//     clear.
//
// Three rules are about the bytes rather than the decision, and each of them
// exists because the alternative is a wrong answer rather than a missing one. A
// response this plugin changes carries no DNSSEC record and does not claim to be
// validated, and the rule is applied by the helpers that make the change, so
// there is exactly one place it can be got wrong. A response it does not change
// keeps its records and its bytes, including the object a cache handed it: every
// mutation is made on a copy. And the ECH key is fetched on a client of this
// plugin's own, over the same TCP listener the foreign forward uses, with its own
// timeout and its own query id, and never by re-entering the sequence this plugin
// sits in -- a key fetched through this plugin would be classified and rewritten
// like any other answer, which is the recursion this file exists to avoid.
package cdn_rewrite

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/dnsclassify"
	"mosdns-router/internal/dnsrewrite"
	"mosdns-router/internal/state"
	"mosdns-router/internal/statewatch"
)

// PluginType is the tag a mosdns configuration uses for this plugin.
const PluginType = "cdn_rewrite"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Args is the plugin configuration. Every path is required and every one of them
// is a document or a list this plugin reads continuously, so a mistyped path is a
// plugin that silently classifies nothing rather than one that says so.
type Args struct {
	// PolicyFile is the one policy document the router is configured with. The
	// plugin reads three fields out of it -- cdn.suppress_aaaa, ech.enabled and
	// ech.failure_policy, with ech.stale_grace and ech.sources for the ECH fetch --
	// so the safety switches an operator edits are the ones this plugin obeys, and
	// there is no second place to set them.
	PolicyFile string `yaml:"policy_file"`
	// SelectorFile is the published selector: the address in service, the window
	// its proof is good for, and the per-hostname CloudFront mappings.
	SelectorFile string `yaml:"selector_file"`
	// ForceECHFile is the operator's list of domains to force ECH for. It is
	// written by hand, so a malformed line keeps the last valid list rather than
	// dropping every domain on it.
	ForceECHFile string `yaml:"force_ech_file"`
	// ECHStateFile is where this plugin records what it fetched: the source, the
	// times, the digest and the public name. The key itself stays in memory, and
	// the document an operator can read carries no bytes of it.
	ECHStateFile string `yaml:"ech_state_file"`
	// ForeignUpstream is the DNSCrypt listener the ECH key is fetched through, as
	// a URL. It must be a TCP URL: mosdns's stock UDP transport re-sends a query
	// that has gone unanswered for a second and can drop an answer that arrived
	// before its exchange waited for it, and the ECH fetch must not be the one
	// place in this router that can lose a query.
	ForeignUpstream string `yaml:"foreign_upstream"`
	// CloudflareCIDRFile is the published Cloudflare range list, one prefix per
	// line. It is the only argument the classifier has: a response is called
	// Cloudflare-served because these ranges say so, never because this package
	// knows an address.
	CloudflareCIDRFile string `yaml:"cloudflare_cidr_file"`
}

// Init builds the plugin from a decoded configuration.
func Init(bp *coremain.BP, args any) (any, error) {
	pluginArgs, ok := args.(*Args)
	if !ok {
		return nil, fmt.Errorf("%s: args must be *Args, got %T", PluginType, args)
	}
	return New(*pluginArgs, bp)
}

// New builds the plugin for a mosdns plugin base. The policy is read by
// newPlugin, from the same path the configuration names, so there is one reader of
// it rather than two that could disagree about which file was authoritative.
func New(args Args, bp *coremain.BP) (sequence.RecursiveExecutable, error) {
	if bp == nil {
		return nil, errors.New(PluginType + ": a plugin base is required")
	}
	return newPlugin(args, options{
		logger: bp.L(),
		now:    time.Now,
	})
}

// options are the dependencies this package does not own. Production passes the
// real clock, the real upstream constructor and the plugin base's logger; a test
// passes a clock it can move, an upstream that records what it was asked, and a
// logger it can read. Nothing here changes a decision: it only decides which
// clock a decision is measured against and whether a fetch opened a socket.
type options struct {
	logger     *zap.Logger
	now        func() time.Time
	newClient  func(addr string, opt upstream.Opt) (upstream.Upstream, error)
	pollEvery  time.Duration
	echTimeout time.Duration
}

// withDefaults fills in what a caller left out and refuses nothing, because every
// value here has a production answer: the real clock, the real upstream
// constructor, the watchers' own poll interval, and the fetch timeout below.
func (o options) withDefaults() options {
	if o.logger == nil {
		o.logger = zap.NewNop()
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.newClient == nil {
		o.newClient = func(addr string, opt upstream.Opt) (upstream.Upstream, error) { return upstream.NewUpstream(addr, opt) }
	}
	if o.pollEvery <= 0 {
		o.pollEvery = statewatch.DefaultPollInterval
	}
	if o.echTimeout <= 0 {
		o.echTimeout = echFetchTimeout
	}
	return o
}

// The refusals this plugin raises on its own account, as opposed to the ones the
// rewrite package raises about an answer. Each names the condition it is about, so
// the log line an operator reads says which door closed.
var (
	errClosed      = errors.New(PluginType + ": the plugin is closed")
	errNoQuestion  = errors.New(PluginType + ": a query must carry exactly one question")
	errNoResponse  = errors.New(PluginType + ": the sequence returned no response, so there is nothing to rewrite")
	errUnsafeRoute = errors.New(PluginType + ": the ECH fetch must use a tcp:// foreign upstream")
)

// Plugin is the executable a mosdns sequence runs.
type Plugin struct {
	logger *zap.Logger
	now    func() time.Time

	// policy is the validated policy document, and the three fields below are the
	// only ones this plugin reads. They are resolved once, at construction, so a
	// query never re-reads a file to find out whether ECH is enabled.
	policy config.Policy
	// echPolicy is the plugin's ech.failure_policy as the rewrite package's own
	// value: strict fails closed and fallback keeps what the upstream published.
	echPolicy dnsrewrite.FailurePolicy
	// suppressAAAA is cdn.suppress_aaaa, and it is the switch that lets an AAAA
	// answer be emptied for a name this plugin has a Cloudflare verdict for.
	suppressAAAA bool

	// selector, force and prefixes are the three documents this plugin reads, held
	// as the narrowest thing it needs from each. Production fills them with the
	// statewatch types, which satisfy all three by the methods they already have,
	// so the interface is not a layer: it is what lets a test present a document
	// the writer would never publish and watch the plugin refuse it anyway.
	selector selectorSource
	force    forceSource
	prefixes prefixSource
	// watchers are the same three as their concrete types, kept for Close and
	// because the poll interval and the reload callback belong to the construction
	// rather than to the read.
	selectorWatcher *statewatch.Watcher[state.Selector]
	forceWatcher    *statewatch.TextWatcher
	prefixWatcher   *prefixList
	ech             *echProvider
	// cdn is the set of names this plugin has classified as Cloudflare-served in
	// the selector's current generation. It is what lets an AAAA query be answered
	// for a name whose A answer earned the answer, and it is cleared whenever the
	// generation moves.
	cdn *cdnNames

	closed atomic.Bool
}

// selectorSource is the last valid selector document.
type selectorSource interface{ Snapshot() state.Selector }

// forceSource is the last valid force-ECH allowlist.
type forceSource interface{ Snapshot() []string }

// prefixSource is the last valid Cloudflare range list.
type prefixSource interface{ Prefixes() []netip.Prefix }

var _ sequence.RecursiveExecutable = (*Plugin)(nil)

// newPlugin builds the plugin over the files it was given. Every refusal it can
// make is made here rather than on the first query, because a plugin's Init is
// the only place a mistake is reported to the operator who can fix it: nothing in
// this repository or in the pinned mosdns recovers from a panic, and a plugin
// that started serving answers nobody about the policy, the paths or the ranges
// it could not use.
func newPlugin(args Args, o options) (*Plugin, error) {
	resolved := o.withDefaults()
	for _, required := range []struct{ field, value string }{
		{"policy_file", args.PolicyFile},
		{"selector_file", args.SelectorFile},
		{"force_ech_file", args.ForceECHFile},
		{"ech_state_file", args.ECHStateFile},
		{"foreign_upstream", args.ForeignUpstream},
		{"cloudflare_cidr_file", args.CloudflareCIDRFile},
	} {
		if strings.TrimSpace(required.value) == "" {
			return nil, fmt.Errorf("%s: %s must not be empty", PluginType, required.field)
		}
	}
	if err := refuseUnsafeUpstream(args.ForeignUpstream); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", PluginType, args.ForeignUpstream, err)
	}
	// A caller may ask for a shorter fetch than the documented bound; a longer one
	// is refused rather than clamped, because the bound is a property of the query
	// path and a caller that asked for longer wanted a client's HTTPS query to
	// wait on a listener this router also forwards everything else through.
	if resolved.echTimeout > echFetchTimeout {
		return nil, fmt.Errorf("%s: the ECH fetch timeout must not exceed %s, got %s", PluginType, echFetchTimeout, resolved.echTimeout)
	}

	policy, err := config.Load(args.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", PluginType, err)
	}
	plugin := &Plugin{
		logger:       resolved.logger,
		now:          resolved.now,
		policy:       policy,
		echPolicy:    failurePolicyOf(policy),
		suppressAAAA: policy.CDN.SuppressAAAA,
		cdn:          newCDNNames(),
	}

	// The prefix list first, because a plugin with no published ranges cannot
	// classify anything, and starting up to serve answers it will never rewrite
	// would hide the reason from the operator who has to fix it.
	plugin.prefixWatcher, err = newPrefixList(args.CloudflareCIDRFile, resolved.pollEvery, plugin.logReloadRefusal)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", PluginType, err)
	}
	plugin.prefixes = plugin.prefixWatcher
	plugin.selectorWatcher, err = statewatch.NewJSON[state.Selector](args.SelectorFile, nil, disabledSelector(), statewatch.Options{
		PollInterval: resolved.pollEvery,
		ReloadError:  plugin.logReloadRefusal,
	})
	if err != nil {
		_ = plugin.prefixWatcher.Close()
		return nil, fmt.Errorf("%s: selector: %w", PluginType, err)
	}
	plugin.selector = plugin.selectorWatcher
	plugin.forceWatcher, err = statewatch.NewTrimmedLines(args.ForceECHFile, nil, statewatch.Options{
		PollInterval: resolved.pollEvery,
		ReloadError:  plugin.logReloadRefusal,
	})
	if err != nil {
		_ = plugin.prefixWatcher.Close()
		_ = plugin.selectorWatcher.Close()
		return nil, fmt.Errorf("%s: force-ech list: %w", PluginType, err)
	}
	plugin.force = plugin.forceWatcher
	plugin.ech, err = newECHProvider(echProviderOptions{
		upstream:  args.ForeignUpstream,
		statePath: args.ECHStateFile,
		sources:   policy.ECH.Sources,
		grace:     time.Duration(policy.ECH.StaleGraceSeconds) * time.Second,
		timeout:   resolved.echTimeout,
		logger:    resolved.logger,
		now:       resolved.now,
		newClient: resolved.newClient,
	})
	if err != nil {
		_ = plugin.forceWatcher.Close()
		_ = plugin.selectorWatcher.Close()
		_ = plugin.prefixWatcher.Close()
		return nil, fmt.Errorf("%s: ECH provider: %w", PluginType, err)
	}
	return plugin, nil
}

// refuseUnsafeUpstream refuses a foreign upstream this plugin will not fetch an
// ECH key through. The measurement is this project's own: mosdns v5.3.4's stock
// UDP upstream re-sends a query that has gone unanswered for one second and can
// drop an answer that arrived before its exchange began waiting for it, which is
// why the foreign branch is given a TCP listener. An ECH fetch has no client
// watching it, so a lost query is a force-ECH name that fails closed for as long
// as the last key lasts, and a refusal at construction is the only place that can
// be said out loud.
func refuseUnsafeUpstream(addr string) error {
	scheme, _, found := strings.Cut(addr, "://")
	if !found {
		return fmt.Errorf("%w: it names no transport, so it would default to udp", errUnsafeRoute)
	}
	if scheme != "tcp" {
		return fmt.Errorf("%w: %q is not tcp", errUnsafeRoute, scheme)
	}
	return nil
}

// failurePolicyOf is the one place the policy's token becomes the rewrite
// package's value, so there is a single place that decides what "strict" and
// "fallback" mean to a query. The policy package has already refused any other
// token, and FailClosed is the zero value, so an unrecognised one could only
// arrive from a policy this build did not validate.
func failurePolicyOf(policy config.Policy) dnsrewrite.FailurePolicy {
	if policy.ECH.FailurePolicy == "fallback" {
		return dnsrewrite.FallbackToOriginal
	}
	return dnsrewrite.FailClosed
}

// disabledSelector is what the plugin serves before the optimizer has published
// anything: a document that validates, names no provider to rewrite for, and
// carries no winner, so the first query after a boot rewrites nothing rather than
// guessing at a selection.
func disabledSelector() state.Selector {
	return state.NewSelector(0, "disabled", string(candidate.ProviderCloudflare), time.Unix(0, 0).UTC())
}

// logReloadRefusal is where every refusal a background reload makes becomes a log
// line. The watchers keep the last valid document when a file cannot be read, so
// without this the router would keep serving yesterday's force-ECH list with
// nothing anywhere saying the file is broken -- and losing strict ECH is the one
// failure here that is invisible to the client it protects.
func (p *Plugin) logReloadRefusal(err error) {
	p.logger.Warn("cdn_rewrite: keeping the last valid document", zap.Error(err))
}

// Exec answers one query, and is the whole decision this plugin makes.
//
// The order is the design. The strict short circuit comes before anything else, so
// a strict force-ECH name's A and AAAA cost no upstream lookup at all. Every
// other question is asked downstream exactly once, and only the response that
// comes back is ever considered for a change: a plugin that answered from its own
// state would be a second resolver, and the answer it has is a selector, not a
// record set.
func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if p.closed.Load() {
		return errClosed
	}
	query := qCtx.Q()
	if query == nil || len(query.Question) != 1 {
		return errNoQuestion
	}
	question := query.Question[0]
	name := dnsclassify.CanonicalName(question.Name)
	forced := p.forcesECH(name)

	if forced && p.echPolicy == dnsrewrite.FailClosed {
		switch question.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			// Nothing is asked downstream, and the answer is this router's own: a
			// NOERROR with no records and no SOA. The SOA is the part that is easy
			// to get wrong, and it matters: an authority record is a negative
			// caching claim, and a negative TTL measured against a policy TTL this
			// router did not choose is a claim about a name that is not true. An
			// empty answer with nothing in the authority section is recomputed for
			// free, which is the honest price of refusing to say.
			qCtx.SetResponse(emptyAnswer(query))
			return nil
		}
	}

	if err := next.ExecNext(ctx, qCtx); err != nil {
		return err
	}
	response := qCtx.R()
	if response == nil {
		// The sequence ran and produced nothing. A plugin that returned nil here
		// would leave mosdns to answer REFUSED, which reads to a client as a
		// policy decision; saying the sequence produced nothing keeps the failure
		// where it happened and makes it SERVFAIL.
		return errNoResponse
	}
	switch question.Qtype {
	case dns.TypeA:
		return p.rewriteAddress(qCtx, response, name)
	case dns.TypeAAAA:
		return p.suppressIPv6(qCtx, response, name)
	case dns.TypeHTTPS:
		return p.rewriteHTTPS(ctx, qCtx, response, name, forced)
	default:
		// A question type this plugin does not own. The answer goes back exactly
		// as it arrived, and the sequence has already been asked exactly once.
		return nil
	}
}

// rewriteAddress is the A path: classify the response, and install the selected
// address only for a response the classifier and the selector both authorise.
//
// The order of the three checks is the order of how much they cost when they are
// wrong. The response's own rcode and question come first because a denial is not
// something to rewrite, and a message that does not answer the question being
// asked about is a cache or an upstream being misread. The provider switch comes
// next, so a selector that published a CloudFront selection is never treated as
// though it had published a global one. Only then is the address asked for, and
// the window it was proved under is checked before the classifier is consulted:
// there is no point deciding a response is Cloudflare-served when there is no
// address this router is allowed to install in it.
//
// Every refusal from here on leaves the response exactly as the sequence set it.
// The rewrite package returns the caller's own message when a call had nothing to
// change and a nil message beside an error when it refused, so both shapes are
// handled here: a message is set back only when one came back, and an error is
// logged rather than returned. Returning it would turn an answer the upstream had
// already given into a SERVFAIL, which is the loudest possible way to say "this
// router declined to rewrite this" and the one that costs a client its name.
func (p *Plugin) rewriteAddress(qCtx *query_context.Context, response *dns.Msg, name string) error {
	if response.Rcode != dns.RcodeSuccess || len(response.Question) != 1 || response.Question[0].Qtype != dns.TypeA {
		return nil
	}
	published := p.selector.Snapshot()
	if published.Mode == "disabled" {
		return nil
	}

	// The per-hostname mapping is authorised by the map itself: an address proved
	// for one distribution says nothing about any other name, and no published
	// range list can say otherwise, so the exact name is the whole of the check.
	//
	// The winner's proof window does not gate this arm, and the asymmetry is
	// forced rather than chosen. The window describes the GLOBAL winner: the
	// optimizer and the health check stamp it when they prove that one address,
	// and a CloudFront-only installation publishes no global winner at all, so it
	// has no window and a gate on it would switch the whole feature off there. A
	// per-hostname mapping carries its own authorisation -- the exact name it was
	// proved for -- and the health check proves every mapping on the same two-minute
	// interval, reporting a failing one; what it does not do is remove it, which
	// this plan already records as a named limitation rather than inheriting it
	// silently.
	if mapped, ok := mappedAddress(published, name); ok {
		return p.installAddress(qCtx, response, dnsrewrite.AddressInput{
			Response:     response,
			QType:        dns.TypeA,
			Provider:     candidate.ProviderCloudFront,
			TerminalName: terminalOf(response),
			Hostname:     name,
			Selected:     mapped,
			Prefixes:     p.prefixes.Prefixes(),
			SuppressAAAA: p.suppressAAAA,
		}, name, "the CloudFront mapping for "+name)
	}

	if published.Provider != string(candidate.ProviderCloudflare) {
		return nil
	}
	winner, live := liveWinner(published, p.now())
	if !live {
		return nil
	}
	verdict := dnsclassify.Cloudflare(response, p.prefixes.Prefixes())
	if !verdict.AllMatch {
		// A refusal carries nothing a rewrite could be built from, and reading its
		// Provider or TerminalName is exactly the mistake the classifier's shape is
		// designed to make inexpressible: both are empty here.
		return nil
	}
	if err := p.installAddress(qCtx, response, dnsrewrite.AddressInput{
		Response:     response,
		QType:        dns.TypeA,
		Provider:     verdict.Provider,
		TerminalName: verdict.TerminalName,
		Selected:     winner,
		Prefixes:     p.prefixes.Prefixes(),
		SuppressAAAA: p.suppressAAAA,
	}, name, "the Cloudflare classification of "+name); err != nil {
		return err
	}
	// The name is remembered so that an AAAA query for it can be answered, which
	// is the only way an IPv6 answer can be known to belong to a CDN name: the
	// published ranges are IPv4 and an AAAA answer carries no address to check.
	p.cdn.record(published.Generation, verdict.TerminalName)
	return nil
}

// installAddress applies one authorized address rewrite and sets the result.
//
// The response the sequence produced is handed to the rewrite package as it is,
// and that package never modifies it: a rewrite lands on a copy, and the fallback
// arm of the HTTPS path hands the original back so its bytes are provably the ones
// the cache still holds. The message that comes back is therefore either a new
// object carrying the rewrite or the caller's own, and setting it back is what
// makes the change visible to the client.
func (p *Plugin) installAddress(qCtx *query_context.Context, response *dns.Msg, in dnsrewrite.AddressInput, name, why string) error {
	rewritten, err := dnsrewrite.Address(in)
	if rewritten != nil {
		qCtx.SetResponse(rewritten)
	}
	if err != nil {
		// The refusal is reported and the upstream's answer stands. A nil message
		// with an error is the refusal shape, and treating it as a failure of the
		// query would throw away a working answer for the sake of a log line.
		p.logger.Warn("cdn_rewrite: the answer was left as the upstream published it",
			zap.String("name", name),
			zap.String("authorised_by", why),
			zap.Error(err))
	}
	return nil
}

// suppressIPv6 is the AAAA path, and it is the one path with no classification of
// its own to stand on.
//
// An AAAA answer carries no IPv4 address, so the published ranges have nothing to
// check it against and any verdict about it would be a guess. The only evidence
// this router can have that a name is served by a CDN is an A answer for that name
// which the classifier accepted, and the A path records exactly those names. So
// the AAAA path is entered only for a name that record holds, under the selector's
// current generation and only while the winner's proof window is open -- the same
// two conditions the A answer was rewritten under, so the two answers for one name
// always agree about whether this router is rewriting it.
func (p *Plugin) suppressIPv6(qCtx *query_context.Context, response *dns.Msg, name string) error {
	if !p.suppressAAAA {
		return nil
	}
	if response.Rcode != dns.RcodeSuccess || len(response.Question) != 1 || response.Question[0].Qtype != dns.TypeAAAA {
		return nil
	}
	published := p.selector.Snapshot()
	winner, live := liveWinner(published, p.now())
	if !live {
		return nil
	}
	owners, refusal := dnsclassify.Chain(response)
	if refusal != dnsclassify.RefusalNone {
		return nil
	}
	terminal := owners[len(owners)-1]
	if !p.cdn.holds(published.Generation, terminal) {
		return nil
	}
	return p.installAddress(qCtx, response, dnsrewrite.AddressInput{
		Response:     response,
		QType:        dns.TypeAAAA,
		Provider:     candidate.ProviderCloudflare,
		TerminalName: terminal,
		Selected:     winner,
		Prefixes:     p.prefixes.Prefixes(),
		SuppressAAAA: true,
	}, name, "the Cloudflare classification of "+terminal)
}

// rewriteHTTPS is the HTTPS path, and it runs for a name the operator asked to
// force ECH for and for nothing else.
//
// A name that is not on the list keeps its own service bindings: this plugin
// rewrites the addresses a client connects to, and a record describing a service
// is not one of them. An ECH key injected into a record for a domain the operator
// never listed would also be a claim nobody authorised, and the key would be the
// same one for every name in any case.
//
// The three shapes the rewrite package can answer with are all handled here, and
// the middle one is the one a caller gets wrong:
//
//   - a synthesis, with a message and no error: the answer the client gets.
//   - the upstream's own record WITH a refusal, which is the fallback policy
//     saying "I could not do this, here is what the upstream published". The
//     message is forwarded and the refusal is logged. A caller that returns as
//     soon as it sees an error takes a working fallback domain to SERVFAIL
//     through this router's own health gate, which is the opposite of what the
//     fallback policy is for.
//   - nothing and a refusal, which is the strict policy saying the same thing the
//     other way. There is no message to forward, so the refusal becomes this
//     plugin's error and mosdns answers SERVFAIL -- which for a force-ECH name is
//     the outcome, not a fault: a client that cannot be given an encrypted
//     service mode is not given an unencrypted one.
func (p *Plugin) rewriteHTTPS(ctx context.Context, qCtx *query_context.Context, response *dns.Msg, name string, forced bool) error {
	if !forced {
		return nil
	}
	published := p.selector.Snapshot()
	// The address is the selector's, and the key is the source's, and the two are
	// fetched independently of each other on purpose. Asking for the key only when
	// an address exists would make the refusal name the wrong thing -- the key is
	// not what failed -- and it would leave the metadata document and the held key
	// going stale for as long as the selector was down, so the first query after
	// the window reopened would pay for a fetch it could have had ready. The cost
	// is one query per source per key lifetime while no address is available, which
	// is the same query a healthy deployment makes anyway.
	winner, _ := liveWinner(published, p.now())
	key, err := p.ech.Config(ctx)
	if err != nil {
		// Reported, not fatal: whether a missing key is fatal is the policy's
		// decision and the rewrite package makes it. A caller that swallowed this
		// would be safe but blind to a source that has gone away.
		p.logger.Warn("cdn_rewrite: there is no usable ECH key to install",
			zap.String("name", name), zap.Error(err))
	}

	rewritten, err := dnsrewrite.HTTPS(dnsrewrite.HTTPSInput{
		Response: response,
		QName:    name,
		Selected: winner,
		ECH:      key,
		Policy:   p.echPolicy,
		Report:   p.logDroppedParameters(name),
	})
	if rewritten == nil {
		// The strict arm, and the only shape with nothing to forward. What the
		// sequence set is removed first, so the answer a client gets is the failure
		// rather than the upstream's own record: leaving it in place would answer a
		// force-ECH name with whatever the upstream published, which is the one
		// outcome strict mode exists to prevent, and it would do it silently.
		qCtx.SetResponse(nil)
		return fmt.Errorf("%s: %s: %w", PluginType, name, err)
	}
	qCtx.SetResponse(rewritten)
	if err != nil {
		p.logger.Warn("cdn_rewrite: the force-ECH answer was left as the upstream published it",
			zap.String("name", name), zap.Error(err))
	}
	return nil
}

// logDroppedParameters reports the parameters a synthesis left out, because a
// record missing a parameter the upstream published is a degraded answer and a
// plugin that cannot see the degradation cannot count it. The rewrite package
// calls this only when something was left out, so what is logged here is always a
// degradation and never a successful synthesis.
func (p *Plugin) logDroppedParameters(name string) func(dnsrewrite.Report) {
	return func(report dnsrewrite.Report) {
		dropped := make([]string, 0, len(report.Dropped))
		for _, parameter := range report.Dropped {
			dropped = append(dropped, fmt.Sprintf("%d: %s", parameter.Key, parameter.Reason))
		}
		p.logger.Info("cdn_rewrite: the synthesized HTTPS record is missing parameters the upstream published",
			zap.String("name", name),
			zap.Strings("dropped", dropped))
	}
}

// liveWinner is the address the selector's proof window currently authorises, and
// the two reasons there is none.
//
// The window is the whole gate. It is stamped by the health check every time it
// proves the address in service, and it closes five minutes later whether or not
// the check came back, so an open window means a certificate, Host and SNI proof
// of that address completed within the last few minutes rather than on some night
// the optimizer ran. The instant the window ends is not inside it: the boundary
// is exclusive, so an address is never installed for the nanosecond after its
// proof expired. And a winner with no successful validation time behind it is not
// an address anything has been proved for, whatever the window says.
func liveWinner(published state.Selector, now time.Time) (netip.Addr, bool) {
	if published.Mode == "disabled" || published.WinnerIP == "" {
		return netip.Addr{}, false
	}
	if published.Provider != string(candidate.ProviderCloudflare) {
		return netip.Addr{}, false
	}
	if published.LastSuccess.IsZero() {
		return netip.Addr{}, false
	}
	if !now.Before(published.WinnerProofUntil) {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(published.WinnerIP)
	if err != nil || !address.Is4() {
		// The state package refuses a winner that is not an IPv4 address, so this
		// is the plugin refusing for itself what a document it did not write might
		// carry. An address that is not a public IPv4 one is refused again by the
		// rewrite package, which is where the full rule lives.
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

// mappedAddress is the per-hostname CloudFront mapping for exactly this name, and
// the address it names.
//
// The comparison folds the two spellings of a name together for the reason the
// force-ECH list does: a query carries its name fully qualified and the selector's
// keys are the profile hostnames, which carry no trailing dot. A mapping is an
// authorisation for one name, so the fold is applied to the key being compared and
// never to the set: a suffix, a parent or a sibling match would be a mapping used
// for a distribution it was never proved for.
func mappedAddress(published state.Selector, canonical string) (netip.Addr, bool) {
	if len(published.CloudFront) == 0 {
		return netip.Addr{}, false
	}
	bare := strings.TrimSuffix(canonical, ".")
	for hostname, value := range published.CloudFront {
		if !strings.EqualFold(hostname, bare) {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Addr{}, false
		}
		return address.Unmap(), true
	}
	return netip.Addr{}, false
}

// terminalOf is the name a response's CNAME chain ends at, or the empty string
// when the chain cannot be followed. An empty terminal is a refusal in the rewrite
// package, which is the right door for it: a chain that loops or branches is not
// something this plugin resolves on its own.
func terminalOf(response *dns.Msg) string {
	owners, refusal := dnsclassify.Chain(response)
	if refusal != dnsclassify.RefusalNone || len(owners) == 0 {
		return ""
	}
	return owners[len(owners)-1]
}

// emptyAnswer is the answer a strict force-ECH name's A and AAAA queries get: the
// question echoed, NOERROR, and no records anywhere. The recursion and
// checking-disabled bits are the client's own and are copied, so a client that
// asked not to be checked is not answered as though it had been.
func emptyAnswer(query *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = nil
	response.Ns = nil
	return response
}

// forcesECH reports whether a name is one the operator asked to force ECH for.
//
// The answer is false whenever ECH is disabled in the policy, whatever the list
// says: a list is the operator's list of names to force ECH for, and there is no
// ECH to force when the policy has turned it off. A client asking about a name
// on that list then gets an ordinary answer from the ordinary path, which is what
// a policy with ECH disabled is describing.
//
// The two forms of a name are folded together here rather than compared as they
// arrive, and the fold is why a match is not a plain string equality: a query
// carries its name fully qualified and in whatever case the client typed, while
// the list is a document a person edits whose entries carry no trailing dot --
// the watcher refuses one, because a name written with a dot is a configuration
// mistake rather than a name. An entry is therefore compared with the query's
// name without its dot, case insensitively, which is the one comparison for which
// both spellings are the name they mean.
func (p *Plugin) forcesECH(canonical string) bool {
	if !p.policy.ECH.Enabled {
		return false
	}
	bare := strings.TrimSuffix(canonical, ".")
	for _, forced := range p.force.Snapshot() {
		if strings.EqualFold(forced, bare) {
			return true
		}
	}
	return false
}

// Close stops the three watchers and releases the ECH client. It is idempotent
// and safe to call more than once, and a query after it fails closed rather than
// reaching a half-closed plugin.
func (p *Plugin) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	var err error
	if p.forceWatcher != nil {
		err = errors.Join(err, p.forceWatcher.Close())
	}
	if p.selectorWatcher != nil {
		err = errors.Join(err, p.selectorWatcher.Close())
	}
	if p.prefixWatcher != nil {
		err = errors.Join(err, p.prefixWatcher.Close())
	}
	if p.ech != nil {
		err = errors.Join(err, p.ech.Close())
	}
	return err
}

// --- the published Cloudflare range list ---

// prefixList is the last valid Cloudflare range list, kept current by a poll of
// its own.
//
// It is not a statewatch watcher because it is neither a state document nor a
// list of domain names: the document a statewatch JSON watcher decodes is one of
// five named types, and its text watcher refuses everything that is not a domain
// name -- which a CIDR is not. The two rules it does share with them are written
// out below rather than inherited, because a second copy of a rule is the only
// way two copies of a rule come to disagree: a file that cannot be read changes
// nothing, and a file that can be read but holds no range is refused rather than
// served as an empty one, because an empty range list classifies every response as
// somebody else's and would stop every rewrite in the router while looking like a
// healthy start.
type prefixList struct {
	path     string
	interval time.Duration
	logger   *zap.Logger
	report   func(error)
	current  atomic.Pointer[[]netip.Prefix]

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// newPrefixList reads the list once, synchronously, and then begins polling it.
// The first read is synchronous for the reason it is in the watchers: a router
// that boots after the daily list updater has published its ranges serves them
// from its first query.
func newPrefixList(path string, interval time.Duration, report func(error)) (*prefixList, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("the Cloudflare range list path must not be empty")
	}
	if interval <= 0 {
		return nil, fmt.Errorf("the Cloudflare range list poll interval must be positive, got %s", interval)
	}
	list := &prefixList{
		path:     path,
		interval: interval,
		logger:   zap.NewNop(),
		report:   report,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if err := list.ReloadNow(); err != nil {
		// A list this build cannot use is a refusal at construction rather than a
		// plugin that starts up and rewrites nothing. An operator who installed
		// the router without the daily updater is told so here, where they can act
		// on it, rather than by a browser quietly reaching the unselected network.
		return nil, err
	}
	go list.run()
	return list, nil
}

// Prefixes returns the ranges the last successful read found. The slice is the
// one the watcher published and is never written to after that, so it is handed
// out as it is rather than copied per query.
func (l *prefixList) Prefixes() []netip.Prefix {
	published := l.current.Load()
	if published == nil {
		return nil
	}
	return *published
}

// ReloadNow reads the file, validates it whole, and publishes it. A refusal
// returns the refusal and changes nothing.
func (l *prefixList) ReloadNow() error {
	prefixes, err := readPrefixList(l.path)
	if err != nil {
		return err
	}
	l.current.Store(&prefixes)
	return nil
}

func (l *prefixList) run() {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	defer close(l.done)
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.report(l.ReloadNow())
		}
	}
}

// Close stops the poll and waits for it. It is idempotent.
func (l *prefixList) Close() error {
	l.once.Do(func() { close(l.stop) })
	<-l.done
	return nil
}

// readPrefixList reads and validates one range list. Comments and blank lines are
// dropped, every remaining line is a prefix in public IPv4 space, and a file with
// no range in it is refused: the ranges are the only argument the classifier has,
// and a list of none is a statement that nothing is Cloudflare-served.
func readPrefixList(path string) ([]netip.Prefix, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: read the Cloudflare range list: %w", path, err)
	}
	lines := strings.Split(string(contents), "\n")
	prefixes := make([]netip.Prefix, 0, len(lines))
	seen := make(map[netip.Prefix]struct{}, len(lines))
	for index, raw := range lines {
		text := strings.TrimSpace(raw)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("%s: line %d: %q is not a prefix: %w", path, index+1, text, err)
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("%s: line %d: %q is not an IPv4 prefix, and this release rewrites IPv4 answers only", path, index+1, text)
		}
		if !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
			return nil, fmt.Errorf("%s: line %d: %q is not public unicast space, so no published range can be in it", path, index+1, text)
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("%s: the Cloudflare range list names no prefix, so every response would be classified as somebody else's and no rewrite could happen", path)
	}
	return prefixes, nil
}

// --- the names this plugin has classified ---

// cdnNames is the set of terminal names this plugin has classified as
// Cloudflare-served under the selector's current generation.
//
// It exists for one question the classifier cannot answer twice. An AAAA answer
// carries no A record, so the published IPv4 ranges have nothing to check it
// against and a classification of it would be a guess; the only evidence that a
// name is Cloudflare-served is an A answer for it that said so. So the A path
// records the name it proved, and the AAAA path is entered only for a name this
// set already holds -- which is what keeps a plain domain's IPv6 answer intact.
//
// Three properties make the record safe rather than a second cache to reason
// about. It is scoped to one generation, so a new selection empties it and no
// answer is suppressed on the strength of a classification the current selector
// never made. It is read only while the winner's proof window is open, so an A
// answer and an AAAA answer for one name agree about whether the router is
// rewriting it. And it is bounded, with the oldest name dropped when it is full,
// so a flood of one-off names cannot make the router's memory grow with them.
type cdnNames struct {
	mu         sync.Mutex
	generation uint64
	names      map[string]struct{}
	order      []string
}

// maximumRememberedNames bounds the set. It is a bound on memory rather than on
// correctness: a name that falls out of it is a name whose AAAA answer keeps its
// records, which is the answer a non-Cloudflare name gets anyway.
const maximumRememberedNames = 1024

func newCDNNames() *cdnNames {
	return &cdnNames{names: map[string]struct{}{}}
}

// record notes that a name was classified as Cloudflare-served in this
// generation. A generation that is not the one in hand empties the set first, so
// a record can never outlive the selection that produced it.
func (c *cdnNames) record(generation uint64, terminal string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		c.generation = generation
		c.names = make(map[string]struct{}, maximumRememberedNames)
		c.order = c.order[:0]
	}
	if _, known := c.names[terminal]; known {
		return
	}
	if len(c.order) >= maximumRememberedNames {
		delete(c.names, c.order[0])
		c.order = c.order[1:]
	}
	c.names[terminal] = struct{}{}
	c.order = append(c.order, terminal)
}

// holds reports whether this generation's record names terminal. A record from
// another generation is not a record at all, which is why the generation is an
// argument rather than something read from inside.
func (c *cdnNames) holds(generation uint64, terminal string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		return false
	}
	_, known := c.names[terminal]
	return known
}

// prefixPathFor is where the parsed range list lives beside the document it was
// parsed from, and it is what the plugin's cloudflare_cidr_file names.
func prefixPathFor(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), defaultPrefixFileName)
}

// defaultPrefixFileName is the name of the parsed range list the cached document's
// own fetch publishes beside its envelope.
const defaultPrefixFileName = "cloudflare-prefixes.txt"
