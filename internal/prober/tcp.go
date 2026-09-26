package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// DefaultTCPTimeout bounds one connect sample. A sample that outlives it is
// counted as lost, because a handshake that has not finished in two seconds is
// not a handshake this router should route a query through. It is a default of
// Options rather than a constant the caller must know, so a caller with nothing
// to change passes Options{} and gets this.
const DefaultTCPTimeout = 2 * time.Second

// Dialer opens one TCP connection. It is a parameter so a test can hold a
// handshake open, or refuse one attempt out of four, without a host that has to
// cooperate; production leaves it nil and gets the standard dialer.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Options are the numbers one prober's measurements are bounded by. The zero
// value is the production configuration, so a caller with nothing to change
// passes Options{}.
//
// There is deliberately no option here for the trust anchors a certificate is
// verified against. That is what this type is for: everything a production caller
// may bound, and nothing a production caller may weaken. The anchors a proof is
// checked against are the host's own, and the only way to reach them is
// newProber, which is not exported.
type Options struct {
	// TCPTimeout bounds one connect sample.
	TCPTimeout time.Duration
	// TLSHandshakeTimeout bounds one TLS handshake, on its own, before a response
	// is even requested.
	TLSHandshakeTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for response headers, which is what
	// separates a serving host from a black hole that completed a handshake.
	ResponseHeaderTimeout time.Duration
	// ProbeTimeout bounds one whole identity probe: connect, handshake, headers,
	// and body.
	ProbeTimeout time.Duration
	// MaxIdentityBodyBytes bounds the body an identity probe reads for a digest.
	MaxIdentityBodyBytes int64
	// Dialer opens connections; nil means the standard dialer.
	Dialer Dialer
}

// withDefaults fills in the numbers a caller left at zero.
func (o Options) withDefaults() Options {
	if o.TCPTimeout <= 0 {
		o.TCPTimeout = DefaultTCPTimeout
	}
	if o.TLSHandshakeTimeout <= 0 {
		o.TLSHandshakeTimeout = DefaultTLSHandshakeTimeout
	}
	if o.ResponseHeaderTimeout <= 0 {
		o.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = DefaultProbeTimeout
	}
	if o.MaxIdentityBodyBytes <= 0 {
		o.MaxIdentityBodyBytes = DefaultMaxIdentityBodyBytes
	}
	return o
}

// reviewed: the prober's unexported identity trust anchors
//
// This is the one file in the module that may name the anchors a certificate is
// verified against, and the source scan says so by name. The field is unexported
// and the only way to set it is newProber, which is not exported, so a production
// caller cannot reach it at all: production identity proofs are verified against
// the host's own roots, and a test in this package can prove the difference
// between a chain those roots carry and one they do not. anchors() is the single
// place the value leaves this struct, so the whole of the trust decision is one
// reviewed file and one method.
type probeOptions struct {
	// RootCAs overrides the trust anchors, for a test that must verify a chain
	// the host's roots cannot know about. A nil value means the system roots.
	RootCAs *x509.CertPool
}

// anchors are the trust roots an identity proof is verified against.
func (o probeOptions) anchors() *x509.CertPool {
	return o.RootCAs
}

// clientConfig is the TLS configuration every identity proof is verified with.
//
// It is here, in the one file the source scan exempts, so that the whole trust
// decision is one reviewed place: the name a certificate is checked against, the
// roots it is checked against, and the floor version. A caller cannot reach any
// of it, and the only way to have a different set of roots is newProber, which is
// not exported.
func (o probeOptions) clientConfig(hostname string) *tls.Config {
	return &tls.Config{
		// The name in the handshake is the one the profile names, so the
		// certificate is checked against the name that will be published for the
		// address rather than against whatever the address resolves to.
		ServerName: hostname,
		// These are the host's own trust roots in production. A probe that trusts
		// an arbitrary anchor proves nothing about anything.
		RootCAs:    o.RootCAs,
		MinVersion: tls.VersionTLS12,
	}
}

// NetworkProber measures over real sockets. It holds no per-candidate state: a
// call that is refused leaves nothing behind for the next one to trust.
type NetworkProber struct {
	options   Options
	anchoring probeOptions
}

var _ Prober = (*NetworkProber)(nil)

// New returns a prober that measures with the standard dialer unless Options
// names one, and that verifies certificates against the host's own trust roots.
// There is no way to ask it for a different set.
func New(options Options) *NetworkProber {
	return newProber(options, probeOptions{})
}

// newProber is New with the identity anchors named, which only a test in this
// package can do.
func newProber(options Options, anchoring probeOptions) *NetworkProber {
	return &NetworkProber{options: options.withDefaults(), anchoring: anchoring}
}

// dial opens one connection with the configured dialer, falling back to the
// standard one. It is the only place this package opens a socket.
func (p *NetworkProber) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if p.options.Dialer != nil {
		return p.options.Dialer(ctx, network, address)
	}
	var standard net.Dialer
	return standard.DialContext(ctx, network, address)
}

// endpoint validates what a measurement is aimed at and names it as a dial
// target. It is shared by the connect measurement and the identity probe, so
// both refuse the same addresses before either opens a socket.
func endpoint(address netip.Addr, port uint16) (string, error) {
	if !address.IsValid() {
		return "", fmt.Errorf("an address to measure must be a valid address, got %q", address)
	}
	if port == 0 {
		return "", fmt.Errorf("an address to measure must name a port, got %d", port)
	}
	return net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)), nil
}

// TCP measures how long an address takes to complete samples connect handshakes.
//
// The address here is a transport endpoint and nothing more: it may be any
// address a caller wants to time, because a connect time cannot make anything
// eligible. Only HTTPS decides that, and it decides it from a verified
// certificate.
//
// Every attempt is made, whether or not the earlier ones succeeded, so Loss is
// the fraction of a fixed number of attempts. A refused or timed-out attempt is
// not an error: an address that is not listening is a measurement of an address
// that is not listening, and a run that aborted on the first one would never
// compare a healthy candidate with a dead one. The only error this returns is
// the caller's own context, which means the run is over.
func (p *NetworkProber) TCP(ctx context.Context, address netip.Addr, port uint16, samples int) (TCPMetrics, error) {
	if samples <= 0 {
		return TCPMetrics{}, fmt.Errorf("a connect measurement must take at least one sample, got %d", samples)
	}
	// The endpoint is checked before the first attempt, so a call that cannot be
	// made does not report a run of failures that never happened.
	target, err := endpoint(address, port)
	if err != nil {
		return TCPMetrics{}, err
	}
	latencies := make([]time.Duration, 0, samples)
	for attempt := 0; attempt < samples; attempt++ {
		started := time.Now()
		connection, err := p.connect(ctx, target)
		elapsed := time.Since(started)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return TCPMetrics{}, ctxErr
			}
			continue
		}
		_ = connection.Close()
		latencies = append(latencies, elapsed)
	}
	if err := ctx.Err(); err != nil {
		return TCPMetrics{}, err
	}
	return summarizeSamples(latencies, samples), nil
}

// connect opens one connection within the configured per-sample timeout, so a
// sample can never cost a run more than one timeout.
func (p *NetworkProber) connect(ctx context.Context, target string) (net.Conn, error) {
	attempt, cancel := context.WithTimeout(ctx, p.options.TCPTimeout)
	defer cancel()
	connection, err := p.dial(attempt, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	return connection, nil
}

// summarizeSamples turns measured handshakes into the metrics a caller ranks
// with. The samples are in the order they were measured, because jitter is a
// statement about that order; the percentiles sort a copy of them, because a
// percentile is a statement about their sizes.
//
// Every field is stated from the samples themselves. Nothing here guesses: an
// address with no successful sample reports no percentile, because a median of
// nothing is not a fast median, it is a missing one.
func summarizeSamples(latencies []time.Duration, attempts int) TCPMetrics {
	metrics := TCPMetrics{Samples: len(latencies)}
	if attempts > 0 {
		metrics.Loss = float64(attempts-len(latencies)) / float64(attempts)
	}
	if len(latencies) == 0 {
		return metrics
	}
	ascending := slices.Clone(latencies)
	slices.Sort(ascending)
	metrics.P50MS = milliseconds(percentile(ascending, 50))
	metrics.P95MS = milliseconds(percentile(ascending, 95))
	metrics.JitterMS = milliseconds(meanDifference(latencies))
	return metrics
}

// percentile returns the sample at the nearest rank of an ascending slice:
// hundredths of a rank in hundredths, so 50 is the median and 95 the 95th
// percentile, computed as ceil(hundredths*n/100) with integer arithmetic and no
// value interpolated between two samples.
//
// The count is what makes the rank exact. With ten samples the 95th percentile
// is the tenth and the median the fifth; with twenty the 95th is the nineteenth
// and the median the tenth, which is the lower of the two middle samples. A
// caller that compares two candidates on these numbers is comparing real
// measurements, not averages that belong to no sample at all.
func percentile(ascending []time.Duration, hundredths int) time.Duration {
	if len(ascending) == 0 {
		return 0
	}
	rank := (hundredths*len(ascending) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(ascending) {
		rank = len(ascending)
	}
	return ascending[rank-1]
}

// meanDifference returns the mean absolute difference between consecutive
// samples, in the order they were measured, and zero for a single sample. It is
// the variation a caller feels between two queries and the median deliberately
// hides: a candidate that alternates between 5ms and 50ms has a good median and
// terrible jitter.
func meanDifference(measured []time.Duration) time.Duration {
	if len(measured) < 2 {
		return 0
	}
	var total time.Duration
	for index := 1; index < len(measured); index++ {
		difference := measured[index] - measured[index-1]
		if difference < 0 {
			difference = -difference
		}
		total += difference
	}
	return total / time.Duration(len(measured)-1)
}

// milliseconds is the one place a duration becomes a metric number, so every
// metric in this package is in the same unit and truncated the same way.
func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
