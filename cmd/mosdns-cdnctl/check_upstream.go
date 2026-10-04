package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"mosdns-router/internal/config"
	"mosdns-router/internal/dnscrypt"
)

// checkUpstreamProbeName is the name every entry is asked about.
//
// **example.com, and that is a decision rather than a default.** It is IANA's
// reserved example domain and every recursive resolver is required to answer it, so
// a failure is the transport or the reachability and not one provider's filtering
// or one zone's policy. Asking a Cloudflare name or a Google name would put "this
// resolver refuses example.com" and "this network cannot reach it" on the same
// line, and an operator reading the report would have to guess which.
const checkUpstreamProbeName = "example.com"

// checkUpstreamTimeout bounds ONE entry's probe. It is a check an operator is
// watching, so it answers in seconds rather than in the router's own per-query
// budget plus retries.
const checkUpstreamTimeout = 5 * time.Second

// upstreamCheckResult is one entry's outcome, and it is a value rather than a
// string so the report line is assembled in one place and the exit count is
// computed from the same field the reader sees.
type upstreamCheckResult struct {
	Name    string
	Kind    config.UpstreamKind
	Target  string
	Rcode   string
	Elapsed time.Duration
	Err     error
}

// runCheckUpstream reports whether each enabled entry in the policy's foreign route
// can actually be dialled and can answer.
//
// It exists because "is my DNS working" has two very different answers -- the router
// is fine and one upstream is unreachable, or every upstream is unreachable -- and
// from the router's behaviour they look identical: foreign names simply do not
// resolve. This verb asks each entry directly and says which one.
//
// Exit status is about REACHABILITY and nothing else: 0 when every enabled entry
// answered, 3 when at least one did not. It never writes and never locks.
func runCheckUpstream(args []string, stdout, stderr io.Writer, services services) int {
	options, err := parseCheckUpstreamOptions(stderr, args, services.documents.Policy)
	if err != nil {
		writeCLIError(stderr, "check-upstream: %v", err)
		return exitInvalidCLI
	}

	policy, err := services.loadPolicy(options.policy)
	if err != nil {
		writeCLIError(stderr, "check-upstream: %v", err)
		return exitStateUnavailable
	}
	selected, missing := selectUpstreams(policy.Foreign.Upstreams, options.names)
	if len(missing) > 0 {
		// Refused BEFORE anything is dialled, and it names what was not found AND
		// what is there -- an operator who typed a name wrong should not have to run
		// the command again to find the right one.
		writeCLIError(stderr, "check-upstream: no enabled entry named %s. The enabled entries are: %s",
			strings.Join(missing, ", "), strings.Join(enabledUpstreamNames(policy.Foreign.Upstreams), ", "))
		return exitInvalidCLI
	}
	if len(selected) == 0 {
		writeCLIError(stderr, "check-upstream: the policy enables no upstream entry, so there is "+
			"nothing to check; that is a configuration fault rather than a route that is down")
		return exitStateUnavailable
	}

	// The dnscrypt entry carries no address of its own; the address it stands for
	// is the packaged resolver's listener, read from the package that renders it.
	listener := "tcp://" + dnscrypt.ListenAddress

	ctx, cancel := context.WithTimeout(context.Background(),
		checkUpstreamTimeout*time.Duration(len(selected)))
	defer cancel()

	unreachable := 0
	for _, entry := range selected {
		result := checkOneUpstream(ctx, entry, listener, services.newUpstream, services.now)
		writeReportLine(stdout, "%s\n", formatUpstreamCheck(result))
		if result.Err != nil {
			unreachable++
		}
	}
	if unreachable > 0 {
		writeCLIError(stderr, "check-upstream: %d of %d enabled entries did not answer %s",
			unreachable, len(selected), checkUpstreamProbeName)
		return exitStateUnavailable
	}
	return exitSuccess
}

// checkUpstreamOptions is the parsed command line. --all and a NAME are two
// different questions, and taking both is a usage error rather than a silent
// preference for one.
type checkUpstreamOptions struct {
	all    bool
	names  []string
	policy string
}

func parseCheckUpstreamOptions(stderr io.Writer, args []string, policy string) (checkUpstreamOptions, error) {
	flags := flag.NewFlagSet("check-upstream", flag.ContinueOnError)
	// The flag set writes its own diagnostics to stderr rather than discarding
	// them, so `-h` reaches the operator.
	flags.SetOutput(stderr)
	var options checkUpstreamOptions
	flags.BoolVar(&options.all, "all", false, "check every enabled entry")
	// **The installed policy's own path is the default, and that is not a
	// convenience.** An earlier version defaulted to the empty string and handed
	// that to config.Load, so `check-upstream --all` -- the invocation the manual
	// documents and the one a control centre's "is it up?" button would make --
	// answered `open policy: open : no such file or directory` and exited 3. Every
	// other verb defaults to the installed document (render/validate read
	// documents.Policy, the CDN verbs read defaultPolicyPath), and a verb whose
	// only documented invocation does not work is a verb nobody has run.
	policyPath := flags.String("policy", policy, "path to the policy the route is configured in")
	if err := flags.Parse(args); err != nil {
		return checkUpstreamOptions{}, err
	}
	options.names = append(options.names, flags.Args()...)
	options.policy = *policyPath
	if options.all && len(options.names) > 0 {
		return checkUpstreamOptions{}, errors.New("--all and a name are two different questions")
	}
	if !options.all && len(options.names) == 0 {
		return checkUpstreamOptions{}, errors.New("name at least one entry, or pass --all")
	}
	return options, nil
}

// selectUpstreams is the whole of "which entries", and it returns the MISSING names
// alongside what it found.
//
// **The missing list is returned rather than raised, and that is deliberate.** A
// first version raised here and the caller then iterated the selection without
// noticing the error -- so a typo produced a successful, shorter report and exit 0.
// Two functions each holding half of one decision is how that happened, so the whole
// decision is one return value.
func selectUpstreams(upstreams []config.ForeignUpstream, names []string) (selected []config.ForeignUpstream, missing []string) {
	if len(names) == 0 {
		for _, entry := range upstreams {
			if entry.IsEnabled() {
				selected = append(selected, entry)
			}
		}
		return selected, nil
	}
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	for _, entry := range upstreams {
		if entry.IsEnabled() && wanted[entry.Name] {
			selected = append(selected, entry)
			delete(wanted, entry.Name)
		}
	}
	for name := range wanted {
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return selected, missing
}

// enabledUpstreamNames is the list the "no entry named X" refusal prints, so the
// operator is handed the right name rather than a second attempt.
func enabledUpstreamNames(upstreams []config.ForeignUpstream) []string {
	var out []string
	for _, entry := range upstreams {
		if entry.IsEnabled() {
			out = append(out, entry.Name)
		}
	}
	return out
}

func checkOneUpstream(ctx context.Context, entry config.ForeignUpstream, dnscryptListener string,
	build func(string, upstream.Opt) (upstream.Upstream, error), now func() time.Time) upstreamCheckResult {

	target := entry.Addr
	if entry.Kind == config.UpstreamKindDNSCrypt {
		// The packaged listener, over TCP -- the SAME road the ECH key is fetched
		// through (cdn_rewrite.go:353 refuses every other transport). So this line
		// is also the answer to "can this machine still fetch an ECH key".
		target = dnscryptListener
	}
	result := upstreamCheckResult{Name: entry.Name, Kind: entry.Kind, Target: target}

	dialer, err := build(target, upstream.Opt{
		Logger: zap.NewNop(),
		// The bootstrap goes in as mosdns wants it, so a domain upstream with a
		// bad bootstrap fails HERE with the reason rather than hanging on a dial
		// that can never succeed.
		Bootstrap: joinBootstrap(entry.Bootstrap),
	})
	if err != nil {
		result.Err = err
		return result
	}
	defer func() { _ = dialer.Close() }()

	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(checkUpstreamProbeName), dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		result.Err = err
		return result
	}

	attempt, cancel := context.WithTimeout(ctx, checkUpstreamTimeout)
	defer cancel()

	started := now()
	answer, err := dialer.ExchangeContext(attempt, payload)
	result.Elapsed = now().Sub(started)
	if err != nil {
		result.Err = err
		return result
	}
	defer pool.ReleaseBuf(answer)

	response := new(dns.Msg)
	if err := response.Unpack(*answer); err != nil {
		result.Err = fmt.Errorf("read its answer: %w", err)
		return result
	}
	result.Rcode = dns.RcodeToString[response.Rcode]
	if response.Rcode != dns.RcodeSuccess {
		// A reachable resolver that REFUSES is not an unreachable one, and the two
		// need different operator answers, so the line says which it was.
		result.Err = fmt.Errorf("it answered %s", result.Rcode)
	}
	return result
}

// joinBootstrap renders the policy's bootstrap list into mosdns's single-string
// form. The list holds at most one entry (config.ValidateOneUpstream refuses two,
// because mosdns parses the whole string as one address), so this is a length check
// rather than a join that could produce something unparseable.
func joinBootstrap(bootstrap []string) string {
	if len(bootstrap) == 0 {
		return ""
	}
	return bootstrap[0]
}

func formatUpstreamCheck(r upstreamCheckResult) string {
	var out strings.Builder
	out.WriteString(r.Name)
	out.WriteString(": ")
	out.WriteString(string(r.Kind))
	out.WriteString(" ")
	out.WriteString(r.Target)
	out.WriteString(": ")
	if r.Err != nil {
		out.WriteString("UNREACHABLE after ")
		out.WriteString(r.Elapsed.Round(time.Millisecond).String())
		out.WriteString(" -- ")
		out.WriteString(r.Err.Error())
		return out.String()
	}
	out.WriteString(r.Rcode)
	out.WriteString(" in ")
	out.WriteString(r.Elapsed.Round(time.Millisecond).String())
	return out.String()
}
