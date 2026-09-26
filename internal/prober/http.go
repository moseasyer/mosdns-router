package prober

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strconv"
	"strings"
	"time"

	"mosdns-router/internal/candidate"
)

// The identity probe is where a candidate becomes eligible, and every number here
// exists to keep that from happening by accident. The chain it walks, in order,
// is: the candidate is a public address this package may publish; the profile
// names one hostname and can be held to; a per-hostname candidate belongs to
// that hostname and no other; the connection is made to the candidate's address
// and never to a name; the certificate is verified for the profile's hostname
// against real trust anchors; and only then is the response read, and read
// against the profile's status, headers, and digest. A candidate that cannot
// walk all of it is not slower than the others, it is not eligible.

const (
	// DefaultTLSHandshakeTimeout bounds one TLS handshake, on its own, before a
	// response is even requested. A handshake that needs longer is not serving
	// this router.
	DefaultTLSHandshakeTimeout = 3 * time.Second

	// DefaultResponseHeaderTimeout bounds how long a response's headers may take
	// to start arriving. It is what separates a serving host from a black hole
	// that completed a handshake.
	DefaultResponseHeaderTimeout = 5 * time.Second

	// DefaultProbeTimeout bounds one whole identity probe: connect, handshake,
	// headers, and body.
	DefaultProbeTimeout = 10 * time.Second

	// DefaultMaxIdentityBodyBytes bounds the body the identity probe reads for
	// its digest. An identity response is a small document; a body past this is
	// a host that is not answering the question, and reading further would be an
	// unbounded transfer on a path that charged the day's budget for nothing.
	DefaultMaxIdentityBodyBytes = 1 << 20
)

// The edge a response says it was served from. CloudFront names its location in
// x-amz-cf-pop and Cloudflare ends a ray with its own code, so the two headers
// together cover both of the CDNs this project measures. The value is a label
// for the report: it is written by the host under test, so it is never an input
// to whether that host is eligible.
const (
	cloudFrontPopHeader = "X-Amz-Cf-Pop"
	cloudflareRayHeader = "Cf-Ray"
)

// HTTPS proves that a candidate's address is really serving a profile's
// hostname, and reports what the proof cost.
//
// This is the only call in this package that can make an address eligible, and it
// answers no unless every check passes. There is no flag, option, or fallback
// that turns the certificate check off, and a candidate that fails here is not
// "unverified" and not "pending": it is refused. Nothing in TCP's metrics, and
// nothing in a fast handshake, reaches a caller that treats this error as
// disqualifying.
//
// The address is dialled directly while the profile's hostname stays in the TLS
// handshake and in the request, so the certificate is verified for the name the
// state file will publish rather than for the name the address would resolve to.
// That is the whole difference between measuring an address and trusting it.
func (p *NetworkProber) HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (HTTPMetrics, error) {
	if err := checkIdentityRequest(subject, profile); err != nil {
		return HTTPMetrics{}, err
	}
	probe, cancel := context.WithTimeout(ctx, p.options.ProbeTimeout)
	defer cancel()

	response, timings, err := p.roundTrip(probe, subject, profile, refuseRedirect)
	if err != nil {
		return HTTPMetrics{}, err
	}
	defer func() { _ = response.Body.Close() }()

	// The metrics are only built once every check has passed. A refused probe
	// reports no numbers at all, because a number beside a refusal is a number a
	// caller can mistake for a measurement.
	if err := checkProfileResponse(profile, response); err != nil {
		return HTTPMetrics{}, err
	}
	if err := checkProfileBody(profile, response, p.options.MaxIdentityBodyBytes); err != nil {
		return HTTPMetrics{}, err
	}
	return HTTPMetrics{
		Status:     response.StatusCode,
		TLSMS:      milliseconds(timings.tls),
		TTFBMS:     milliseconds(timings.firstByte.Sub(timings.written)),
		TotalMS:    milliseconds(time.Since(timings.started)),
		Colocation: colocation(response.Header),
	}, nil
}

// checkIdentityRequest refuses everything that could make the proof weaker than
// the profile claims, before a socket is opened: a candidate that could not be
// published, a profile that could not be held to, and a per-hostname candidate
// that belongs to a different hostname.
//
// The hostname check is the anti-leak rule. A CloudFront candidate is one
// hostname's answer, and a proof for another hostname says nothing about it, so
// the two names have to be the same name. A global Cloudflare candidate carries
// no hostname and is checked only against the profile it was given.
func checkIdentityRequest(subject candidate.Candidate, profile candidate.ProbeProfile) error {
	if err := subject.Validate(); err != nil {
		return fmt.Errorf("candidate: %w", err)
	}
	if err := (candidate.CloudFrontProfile{Profile: profile}).Validate(); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if subject.Hostname != "" && !strings.EqualFold(subject.Hostname, profile.Hostname) {
		return fmt.Errorf("candidate %s belongs to %q and cannot be proved for %q", subject.IP, subject.Hostname, profile.Hostname)
	}
	return nil
}

// checkProfileResponse holds a response to what the profile says a served
// response looks like: a status it expects, and every header it requires, by
// value.
func checkProfileResponse(profile candidate.ProbeProfile, response *http.Response) error {
	if !slices.Contains(profile.ExpectedStatus, response.StatusCode) {
		return fmt.Errorf("status %d is not one the profile for %s expects (%s)", response.StatusCode, profile.Hostname, joinStatuses(profile.ExpectedStatus))
	}
	for name, value := range profile.RequiredHeader {
		// Header lookup is by canonical name, so a profile that spells a header
		// in any case is held to the same value.
		if got := response.Header.Get(name); got != value {
			return fmt.Errorf("header %s of the response for %s is %q, want %q", name, profile.Hostname, got, value)
		}
	}
	return nil
}

// checkProfileBody holds the body to the profile's digest, and bounds how much of
// it is read to do so. A profile with no digest is making no claim about the body,
// and it is read no further than its headers: reading what this probe has no claim
// about would be a transfer it cannot account for.
func checkProfileBody(profile candidate.ProbeProfile, response *http.Response, maximum int64) error {
	if profile.BodySHA256 == "" {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return fmt.Errorf("read the body of the response for %s: %w", profile.Hostname, err)
	}
	if int64(len(body)) > maximum {
		return fmt.Errorf("the response for %s is larger than the %d bytes an identity probe reads", profile.Hostname, maximum)
	}
	digest := sha256.Sum256(body)
	if got := hex.EncodeToString(digest[:]); got != profile.BodySHA256 {
		return fmt.Errorf("the body of the response for %s hashes to %s, want the %s the profile names", profile.Hostname, got, profile.BodySHA256)
	}
	return nil
}

// roundTrip performs the one request of a probe and reports when each part of it
// happened. The client is built per call and thrown away with it, so two
// candidates can never share a connection and nothing here mutates the process
// wide http.DefaultTransport that the rest of this program uses.
func (p *NetworkProber) roundTrip(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile, redirects func(*http.Request, []*http.Request) error) (*http.Response, probeTimings, error) {
	timings := probeTimings{started: time.Now()}
	transport := &http.Transport{
		// The dialer is the whole point: it connects to the candidate's address
		// and completes the handshake for the profile's hostname, so the name in
		// the URL never has to resolve and never is consulted.
		DialTLSContext:         p.dialTLSFor(subject, profile, &timings),
		ResponseHeaderTimeout:  p.options.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: maximumResponseHeaderBytes,
		ForceAttemptHTTP2:      false,
		// No proxy: a candidate address is dialled, never handed to a proxy that
		// would resolve the name instead.
		Proxy: nil,
		// A probe is one request. Nothing is kept between calls, so there is no
		// idle connection to leak and no second candidate to inherit a verdict.
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	request, err := p.buildRequest(ctx, subject, profile)
	if err != nil {
		return nil, timings, err
	}
	trace := &httptrace.ClientTrace{
		WroteRequest:         func(httptrace.WroteRequestInfo) { timings.written = time.Now() },
		GotFirstResponseByte: func() { timings.firstByte = time.Now() },
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: redirects,
	}
	response, err := client.Do(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, timings, ctxErr
		}
		return nil, timings, fmt.Errorf("%s at %s: %w", profile.Hostname, subject.IP, err)
	}
	return response, timings, nil
}

// buildRequest builds the one request a probe makes: the profile's own method and
// URL, with the Host header the profile's hostname requires.
//
// The URL already names the hostname, and the profile check has refused a URL
// that names another one, so the Host header is stated rather than inherited:
// a request that has been rewritten somewhere between here and the socket would
// then be caught rather than answered.
func (p *NetworkProber) buildRequest(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (*http.Request, error) {
	method := profile.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, profile.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("build the request for %s: %w", profile.Hostname, err)
	}
	request.Host = profile.Hostname
	request.Header.Set("Accept", "*/*")
	request.Header.Set("User-Agent", userAgent)
	return request, nil
}

// dialTLSFor returns the transport dialer for one candidate: it connects to the
// candidate's address and port, never to a name, and completes the TLS handshake
// itself so the chain is verified for the profile's hostname and the handshake
// can be timed on its own.
//
// The handshake is done here rather than left to the transport for two reasons.
// The chain has to be verified against the trust anchors while the connection is
// still the one that was dialled, and the time the handshake took has to be
// separable from the connect in front of it, because a report that cannot tell
// them apart cannot say which of the two a candidate is bad at.
func (p *NetworkProber) dialTLSFor(subject candidate.Candidate, profile candidate.ProbeProfile, timings *probeTimings) func(ctx context.Context, _, _ string) (net.Conn, error) {
	target, err := endpoint(subject.IP, profile.Port)
	if err != nil {
		return func(context.Context, string, string) (net.Conn, error) { return nil, err }
	}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		handshake, cancel := context.WithTimeout(ctx, p.options.TLSHandshakeTimeout)
		defer cancel()
		connection, err := p.dial(handshake, "tcp", target)
		if err != nil {
			return nil, err
		}
		client := tls.Client(connection, &tls.Config{
			// The name in the handshake is the profile's, so the certificate is
			// checked against the name that will be published for this address.
			ServerName: profile.Hostname,
			// No RootCAs means the host's own trust anchors. That is the production
			// configuration and the only one this package can be built with: a
			// probe that trusts an arbitrary anchor proves nothing about anything.
			RootCAs:    p.options.RootCAs,
			MinVersion: tls.VersionTLS12,
		})
		began := time.Now()
		if err := client.HandshakeContext(handshake); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("%s at %s: %w", profile.Hostname, subject.IP, err)
		}
		// The handshake is timed on its own, from the first handshake byte to
		// the handshake completing, so a report can tell a slow connect from a
		// slow handshake instead of reporting one number for both.
		timings.tls = time.Since(began)
		return client, nil
	}
}

// probeTimings is when each part of one request happened. The three numbers a
// caller reads are all differences of these, and nothing is measured from a
// moment the caller has to guess.
type probeTimings struct {
	started   time.Time
	written   time.Time
	firstByte time.Time
	tls       time.Duration
}

// userAgent identifies this project to the hosts it measures. It is a name, not
// a fingerprint: a host that refuses the request is a measurement of a host that
// refuses this router.
const userAgent = "mosdns-router"

// maximumResponseHeaderBytes bounds the response headers an identity probe will
// read. A header block is kilobytes; this is an envelope a hostile origin cannot
// make the reader buffer past.
const maximumResponseHeaderBytes = 64 << 10

// colocation returns the edge the response named for itself, or an empty string
// when it named none. The CloudFront header is already a location code; the
// Cloudflare one is a request identifier whose last segment is the code.
func colocation(header http.Header) string {
	if pop := header.Get(cloudFrontPopHeader); pop != "" {
		return pop
	}
	if ray := header.Get(cloudflareRayHeader); ray != "" {
		if separator := strings.LastIndexByte(ray, '-'); separator >= 0 && separator+1 < len(ray) {
			return ray[separator+1:]
		}
	}
	return ""
}

// errRedirectRefused reports that a response pointed somewhere this probe will
// not go. It is a named error because the caller has to be able to tell "the
// host sent us elsewhere" from "the host did not answer", and the first means the
// address is serving a different site.
var errRedirectRefused = errors.New("the response is a redirect, which an identity probe does not follow")

// refuseRedirect is the redirect policy of the identity probe: none. A redirect
// is the address under test naming somewhere else, and following it would turn
// the proof into a statement about whatever is at the other end, which is exactly
// the substitution this package exists to refuse.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errRedirectRefused
}

// joinStatuses names the statuses a profile expects, so a refusal says what it
// was refused against rather than only what it refused.
func joinStatuses(statuses []int) string {
	names := make([]string, 0, len(statuses))
	for _, status := range statuses {
		names = append(names, strconv.Itoa(status))
	}
	return strings.Join(names, ", ")
}
