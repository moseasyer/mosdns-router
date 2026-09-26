package prober

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/state"
)

// The measurements below run against listeners on ephemeral loopback ports and
// against a dialer the test supplies when it needs a socket the host cannot
// provide, such as a handshake that never completes. No test here opens a
// connection to anything but this process, and none waits on a clock it did not
// set itself.

// TestTCPPercentilesUseNearestRankWithoutInterpolation pins the percentile rule
// with hand-checked values, because a percentile that interpolates reports a
// latency no sample ever had, and a rank that is off by one reports a different
// candidate's order. The samples below are milliseconds; each expected value is
// one of the samples, because the method returns an existing sample and never a
// value between two of them.
func TestTCPPercentilesUseNearestRankWithoutInterpolation(t *testing.T) {
	// The samples and the expected values below are whole milliseconds, stated as
	// the integers they are. Every expected value is one of the samples, because
	// the method returns an existing sample and never a value between two of them.
	for name, table := range map[string]struct {
		samples []int
		p50     float64
		p95     float64
	}{
		"one sample is both percentiles": {
			samples: []int{7},
			p50:     7,
			p95:     7,
		},
		// ceil(0.50*2) = 1, ceil(0.95*2) = 2: the lower of two is the median and
		// the higher of two is the 95th percentile.
		"two samples take the lower and the higher": {
			samples: []int{7, 3},
			p50:     3,
			p95:     7,
		},
		// ceil(0.50*3) = 2 and ceil(0.95*3) = 3: the middle of three, and the
		// largest of three.
		"three samples take the middle and the largest": {
			samples: []int{5, 1, 9},
			p50:     5,
			p95:     9,
		},
		// ceil(0.50*5) = 3 and ceil(0.95*5) = 5.
		"five samples take the third and the fifth": {
			samples: []int{10, 20, 30, 40, 50},
			p50:     30,
			p95:     50,
		},
		// ceil(0.50*10) = 5 and ceil(0.95*10) = 10.
		"ten samples take the fifth and the tenth": {
			samples: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			p50:     5,
			p95:     10,
		},
		// ceil(0.50*20) = 10 and ceil(0.95*20) = 19: an even count takes the
		// lower of the two middle samples and the nineteenth of twenty, so
		// neither percentile invents a value.
		"twenty samples take the tenth and the nineteenth": {
			samples: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			p50:     10,
			p95:     19,
		},
	} {
		t.Run(name, func(t *testing.T) {
			samples := wholeMilliseconds(table.samples)
			metrics := summarizeSamples(samples, len(samples))
			if metrics.P50MS != table.p50 {
				t.Errorf("P50MS = %v, want %v", metrics.P50MS, table.p50)
			}
			if metrics.P95MS != table.p95 {
				t.Errorf("P95MS = %v, want %v", metrics.P95MS, table.p95)
			}
		})
	}
}

// TestTCPJitterIsTheMeanAbsoluteDifferenceBetweenConsecutiveSamples pins the
// jitter rule, because a jitter of "standard deviation" and a jitter of "mean
// consecutive difference" rank candidates differently and the report would name
// neither. The samples are in the order they were measured, and the rule reads
// them in that order: the median and the 95th percentile sort first, jitter does
// not.
func TestTCPJitterIsTheMeanAbsoluteDifferenceBetweenConsecutiveSamples(t *testing.T) {
	// Samples are whole milliseconds and jitter is expected in nanoseconds,
	// because the mean of two differences ends in half a millisecond and of
	// three in a third of one.
	for name, table := range map[string]struct {
		samples []int
		jitter  time.Duration
	}{
		"a single sample cannot vary": {
			samples: []int{10},
			jitter:  0,
		},
		// |20-10| = 10, |15-20| = 5, and (10+5)/2 = 7.5.
		"two consecutive differences are averaged": {
			samples: []int{10, 20, 15},
			jitter:  7500 * time.Microsecond,
		},
		// The same three values measured in another order: |10-20| = 10 and
		// |15-10| = 5, so the mean is 7.5ms again. Sorted, the same three values
		// would be 10, 15, 20 and would jitter by 5ms instead, which is what
		// makes this a statement about the order the samples were measured in.
		"the order of measurement is the order of the differences": {
			samples: []int{20, 10, 15},
			jitter:  7500 * time.Microsecond,
		},
		// A steady line has no jitter at all: |4-4| = 0 twice.
		"a steady series has no jitter": {
			samples: []int{4, 4, 4},
			jitter:  0,
		},
		// |2-1| = 1, |4-2| = 2, |8-4| = 4: (1+2+4)/3 is 2.333333ms over the
		// three differences, not 3.5ms over the four samples, and the reported
		// value lands on whole nanoseconds.
		"the mean is over the differences, not over the samples": {
			samples: []int{1, 2, 4, 8},
			jitter:  2333333 * time.Nanosecond,
		},
	} {
		t.Run(name, func(t *testing.T) {
			samples := wholeMilliseconds(table.samples)
			metrics := summarizeSamples(samples, len(samples))
			if got := time.Duration(metrics.JitterMS * float64(time.Millisecond)); got != table.jitter {
				t.Errorf("JitterMS = %v, want %v", got, table.jitter)
			}
		})
	}
}

func TestTCPSummaryOfNoSuccessfulSample(t *testing.T) {
	// Nothing connected: there is no median, no 95th percentile and no jitter to
	// report, and the only number a caller may act on is that every attempt
	// failed.
	metrics := summarizeSamples(nil, 4)
	if metrics.Samples != 0 {
		t.Errorf("Samples = %d, want 0", metrics.Samples)
	}
	if metrics.Loss != 1 {
		t.Errorf("Loss = %v, want 1", metrics.Loss)
	}
	for name, value := range map[string]float64{"P50MS": metrics.P50MS, "P95MS": metrics.P95MS, "JitterMS": metrics.JitterMS} {
		if value != 0 {
			t.Errorf("%s = %v with no sample, want 0", name, value)
		}
	}
}

func TestTCPRecordsOneSamplePerHandshake(t *testing.T) {
	// The sample count is the number of connections that were actually made, so a
	// caller can tell "four handshakes in four milliseconds" from "one handshake
	// in four milliseconds".
	address, port, accepted := mustListen(t)
	measure := New(Options{TCPTimeout: 5 * time.Second})

	metrics, err := measure.TCP(t.Context(), address, port, 4)
	if err != nil {
		t.Fatalf("measure four handshakes: %v", err)
	}
	if metrics.Samples != 4 {
		t.Errorf("Samples = %d, want 4", metrics.Samples)
	}
	if metrics.Loss != 0 {
		t.Errorf("Loss = %v, want 0", metrics.Loss)
	}
	if got := accepted.Load(); got != 4 {
		// The listener accepts in the background, so the fourth accept can land
		// just after the measurement returned. The wait is bounded, and the
		// measurement itself is what the assertions above are about.
		if !waitFor(accepted, 4, 5*time.Second) {
			t.Errorf("the listener accepted %d connections, want 4", got)
		}
	}
	if metrics.P50MS <= 0 {
		t.Errorf("P50MS = %v, want a positive handshake time", metrics.P50MS)
	}
	if metrics.P95MS < metrics.P50MS {
		// Both come from the same four samples and the 95th percentile is the
		// higher rank, so it can never be below the median. A percentile
		// invented by interpolation could break this bound.
		t.Errorf("P95MS = %v, which is below P50MS = %v", metrics.P95MS, metrics.P50MS)
	}
}

func TestTCPCountsARefusedConnectionAsLoss(t *testing.T) {
	// A refused connect is a measurement, not a failure of the measurement: a
	// candidate that is not listening must come back as a full loss with no
	// samples, and not as an error the caller has to classify.
	address, port := mustClosedPort(t)
	measure := New(Options{TCPTimeout: 5 * time.Second})

	metrics, err := measure.TCP(t.Context(), address, port, 3)
	if err != nil {
		t.Fatalf("measure a refused connect: %v", err)
	}
	if metrics.Samples != 0 {
		t.Errorf("Samples = %d, want 0", metrics.Samples)
	}
	if metrics.Loss != 1 {
		t.Errorf("Loss = %v, want 1", metrics.Loss)
	}
	if metrics.P50MS != 0 || metrics.P95MS != 0 || metrics.JitterMS != 0 {
		t.Errorf("metrics = %+v, want no percentiles and no jitter", metrics)
	}
}

func TestTCPCountsATimedOutHandshakeAsLoss(t *testing.T) {
	// A handshake that never completes must cost the per-sample timeout and then
	// count as one lost attempt, not hang the run and not abort it.
	var attempts atomic.Int64
	measure := New(Options{
		TCPTimeout: 50 * time.Millisecond,
		Dialer: func(ctx context.Context, _, _ string) (net.Conn, error) {
			attempts.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})

	metrics, err := measure.TCP(t.Context(), netip.MustParseAddr("192.0.2.1"), 443, 2)
	if err != nil {
		t.Fatalf("measure two handshakes that never complete: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("the dialer was asked for %d connections, want one attempt per sample", got)
	}
	if metrics.Samples != 0 {
		t.Errorf("Samples = %d, want 0", metrics.Samples)
	}
	if metrics.Loss != 1 {
		t.Errorf("Loss = %v, want 1", metrics.Loss)
	}
}

func TestTCPCountsOnlyTheAttemptsThatFailed(t *testing.T) {
	// A partially reachable address is the normal case for a CDN sample, and the
	// metrics have to say how much of the measurement actually happened. Half the
	// attempts here are refused by the test, so half the samples exist and the
	// loss is exactly one half.
	var attempts atomic.Int64
	measure := New(Options{
		TCPTimeout: 5 * time.Second,
		Dialer: func(ctx context.Context, network, target string) (net.Conn, error) {
			if attempts.Add(1)%2 == 0 {
				return nil, errors.New("the test refused this connect")
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	})
	// A closed port is the only address a refused sample can use, so the
	// successful attempts are the ones the dialer lets through to the real dialer
	// and a listener is what they reach.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	mustAccept(t, listener)
	open := netip.MustParseAddrPort(listener.Addr().String())

	metrics, err := measure.TCP(t.Context(), open.Addr(), open.Port(), 4)
	if err != nil {
		t.Fatalf("measure four handshakes, half refused: %v", err)
	}
	if metrics.Samples != 2 {
		t.Errorf("Samples = %d, want 2", metrics.Samples)
	}
	if metrics.Loss != 0.5 {
		t.Errorf("Loss = %v, want 0.5", metrics.Loss)
	}
	if metrics.P50MS <= 0 {
		t.Errorf("P50MS = %v, want a positive handshake time", metrics.P50MS)
	}
}

func TestTCPStopsWhenTheCallerContextIsDone(t *testing.T) {
	// A run that is shutting down must stop measuring, and must be able to tell
	// that from a candidate that is merely slow: the context's own error is
	// returned rather than a line of metrics.
	ctx, cancel := context.WithCancel(t.Context())
	measure := New(Options{
		TCPTimeout: time.Hour,
		Dialer: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	go cancel()

	_, err := measure.TCP(ctx, netip.MustParseAddr("192.0.2.1"), 443, 3)
	if err == nil {
		t.Fatal("a cancelled run reported metrics instead of stopping")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled run failed with %v, want the context's own error", err)
	}
}

func TestTCPRefusesToMeasureNothing(t *testing.T) {
	// A run that asked for no samples has measured nothing, and reporting a
	// perfect zero for it would put an unmeasured candidate into a ranking. The
	// refusal also happens before any socket is opened.
	for name, call := range map[string]func(*NetworkProber) (TCPMetrics, error){
		"no samples": func(measure *NetworkProber) (TCPMetrics, error) {
			return measure.TCP(t.Context(), netip.MustParseAddr("127.0.0.1"), 443, 0)
		},
		"a negative sample count": func(measure *NetworkProber) (TCPMetrics, error) {
			return measure.TCP(t.Context(), netip.MustParseAddr("127.0.0.1"), 443, -1)
		},
		"no port": func(measure *NetworkProber) (TCPMetrics, error) {
			return measure.TCP(t.Context(), netip.MustParseAddr("127.0.0.1"), 0, 1)
		},
		"no address": func(measure *NetworkProber) (TCPMetrics, error) {
			return measure.TCP(t.Context(), netip.Addr{}, 443, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var dials atomic.Int64
			measure := New(Options{
				TCPTimeout: time.Second,
				Dialer: func(ctx context.Context, network, target string) (net.Conn, error) {
					dials.Add(1)
					return (&net.Dialer{}).DialContext(ctx, network, target)
				},
			})
			metrics, err := call(measure)
			if err == nil {
				t.Fatalf("a measurement of %s was accepted and returned %+v", name, metrics)
			}
			if metrics != (TCPMetrics{}) {
				t.Errorf("metrics = %+v after a refusal, want the zero value", metrics)
			}
			if got := dials.Load(); got != 0 {
				t.Errorf("the dialer was asked for %d connections, want none", got)
			}
		})
	}
}

// mustListen starts a listener on an ephemeral loopback port, accepts
// everything that arrives in the background, and returns the address to measure,
// the port, and the number of connections it has accepted.
func mustListen(t *testing.T) (netip.Addr, uint16, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := mustAccept(t, listener)
	address, port := mustAddressPort(t, listener.Addr().String())
	return address, port, accepted
}

// mustClosedPort returns an address and port on loopback that nothing is
// listening on, so a connect to it is refused.
func mustClosedPort(t *testing.T) (netip.Addr, uint16) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	address, port := mustAddressPort(t, listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatalf("close the listener: %v", err)
	}
	return address, port
}

func mustAccept(t *testing.T, listener net.Listener) *atomic.Int64 {
	t.Helper()
	accepted := new(atomic.Int64)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = connection.Close()
		}
	}()
	return accepted
}

func mustAddressPort(t *testing.T, address string) (netip.Addr, uint16) {
	t.Helper()
	parsed, err := netip.ParseAddrPort(address)
	if err != nil {
		t.Fatalf("parse the listener address %q: %v", address, err)
	}
	return parsed.Addr(), parsed.Port()
}

// waitFor polls a counter until it reaches want or the limit passes. It exists
// because a listener accepts in the background: the connection is already made
// when the client closes it, and the server's own bookkeeping lands whenever the
// scheduler says so.
func waitFor(counter *atomic.Int64, want int64, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if counter.Load() >= want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return counter.Load() >= want
}

// wholeMilliseconds turns whole-millisecond counts into durations, so the
// percentile and jitter tables above read as the numbers they are.
func wholeMilliseconds(values []int) []time.Duration {
	scaled := make([]time.Duration, 0, len(values))
	for _, value := range values {
		scaled = append(scaled, time.Duration(value)*time.Millisecond)
	}
	return scaled
}

// Every identity test below proves the same chain from the other end: the
// connection goes to the candidate's address, the name the certificate is
// checked against and the name the request carries is the profile's hostname,
// and the response is only accepted when it is the one the profile describes.
// The certificates are generated per test into that test's own temporary
// directory, so nothing here depends on a certificate that already existed on
// this host and nothing is added to the host's trust store.

const (
	// profileHostname is the name every identity test is written for.
	profileHostname = "example.test"
	// otherHostname is a name the tests use where a name is not allowed to
	// match, either in a certificate or in a candidate.
	otherHostname = "other.test"
	// candidateAddress is a real public literal, because the candidate rules
	// refuse loopback and the reserved documentation ranges on purpose. It is
	// never dialled: the test's dialer sends the connection to the local
	// listener, which is what lets a real public literal be measured at all.
	candidateAddress = "13.32.0.1"
	// profilePort is the port a production profile names. The test's dialer
	// redirects it, so the port in the profile is the real one.
	profilePort = uint16(443)
	// identityBody is what a verified host answers with.
	identityBody = "mosdns-router identity probe\n"
)

func TestHTTPSAcceptsACandidateThatProvesTheProfile(t *testing.T) {
	// The only path to eligibility: a verified chain for the profile's name, a
	// status the profile expects, the headers it requires, and the body it
	// names. Everything the caller learns came from the host under test.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, identityHandler)
	measure, dialled := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
	subject := identityCandidate(profileHostname)

	metrics, err := measure.HTTPS(t.Context(), subject, profile)
	if err != nil {
		t.Fatalf("a candidate that proved the profile was refused: %v", err)
	}
	if metrics.Status != http.StatusOK {
		t.Errorf("Status = %d, want %d", metrics.Status, http.StatusOK)
	}
	if metrics.TotalMS <= 0 {
		t.Errorf("TotalMS = %v, want a positive total", metrics.TotalMS)
	}
	if metrics.TTFBMS <= 0 {
		t.Errorf("TTFBMS = %v, want a positive time to first byte", metrics.TTFBMS)
	}
	if metrics.TotalMS < metrics.TTFBMS {
		t.Errorf("TotalMS = %v, which is below the TTFBMS = %v it must contain", metrics.TotalMS, metrics.TTFBMS)
	}
	if metrics.TLSMS < 0 {
		t.Errorf("TLSMS = %v, want a handshake time that is not negative", metrics.TLSMS)
	}
	// The request that answered carried the name the profile is for, and the
	// connection that carried it was made to the candidate's address.
	facts := requests.last(t)
	if facts.host != profileHostname {
		t.Errorf("the request went to Host %q, want %q", facts.host, profileHostname)
	}
	if facts.serverName != profileHostname {
		t.Errorf("the handshake offered SNI %q, want %q", facts.serverName, profileHostname)
	}
	if got := dialled.targets(); len(got) != 1 || got[0] != candidateAddress+":443" {
		t.Errorf("the dialer was asked for %v, want exactly [%s]", got, candidateAddress+":443")
	}
}

func TestHTTPSRefusesACertificateForAnotherName(t *testing.T) {
	// A chain this build trusts, for a name the profile is not: the certificate
	// is genuine and the address is still not allowed to serve this hostname.
	// This is the case a third-party "best IP" list cannot fake, and the reason
	// the connection is dialled by address while the name stays in the handshake.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, otherHostname, identityHandler)
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

	_, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err == nil {
		t.Fatal("a certificate for another name was accepted for this profile")
	}
	if !strings.Contains(err.Error(), profileHostname) {
		t.Errorf("the refusal does not name the hostname it was for: %v", err)
	}
}

func TestHTTPSRefusesAChainTheAnchorsDoNotCarry(t *testing.T) {
	// The right name on a certificate this build cannot trace to an anchor it
	// trusts. Trusting it would mean trusting whatever the address under test
	// signed, which is the identity proof in reverse.
	trusted := newTestAuthority(t)
	stranger := newTestAuthority(t)
	server, _ := mustIdentityServer(t, stranger, profileHostname, identityHandler)
	measure, _ := mustProberFor(t, trusted, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

	if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
		t.Fatal("a chain from an authority the trust anchors do not carry was accepted")
	}
}

func TestHTTPSRefusesAnEphemeralAuthorityWhenTheRootsAreTheSystemOnes(t *testing.T) {
	// The production configuration: the host's own roots. They know nothing about
	// a certificate this test generated, so a probe built the production way
	// refuses it, which is what proves the trust anchors in the other tests are
	// the reason they pass and not something looser.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, identityHandler)
	measure, _ := mustProberFor(t, nil, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

	if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
		t.Fatal("a generated authority was accepted with the system roots")
	}
}

func TestHTTPSRefusesAStatusOutsideTheProfile(t *testing.T) {
	// A host that answers at all is not a host that answered the question. 421
	// and 403 are what an interception or a wrong edge returns, and both are
	// refused unless the profile says they are the answer.
	for name, status := range map[string]int{
		"421 misdirected request":      http.StatusMisdirectedRequest,
		"403 forbidden":                http.StatusForbidden,
		"500 internal server error":    http.StatusInternalServerError,
		"a redirect to somewhere else": http.StatusFound,
	} {
		t.Run(name, func(t *testing.T) {
			authority := newTestAuthority(t)
			server, _ := mustIdentityServer(t, authority, profileHostname, statusHandler(status))
			measure, _ := mustProberFor(t, authority, server)
			profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

			metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
			if err == nil {
				t.Fatalf("status %d was accepted and reported as %+v", status, metrics)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(status)) {
				t.Errorf("the refusal does not name the status it refused: %v", err)
			}
		})
	}
}

func TestHTTPSAcceptsAStatusTheProfileExpects(t *testing.T) {
	// The other half of the rule above: a status the profile names is the answer
	// the profile asked for, and a host that returns it has proved nothing less
	// than one that returns 200.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, statusHandler(http.StatusMisdirectedRequest))
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusMisdirectedRequest})
	// This response has no body, so the profile claims nothing about one. A
	// profile that did claim a digest here is the body-mismatch case below.
	profile.BodySHA256 = ""

	metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err != nil {
		t.Fatalf("a status the profile expects was refused: %v", err)
	}
	if metrics.Status != http.StatusMisdirectedRequest {
		t.Errorf("Status = %d, want %d", metrics.Status, http.StatusMisdirectedRequest)
	}
}

func TestHTTPSRefusesAMissingRequiredHeader(t *testing.T) {
	// The headers a profile requires are the response's own claim about what is
	// in front of the user. A response without them, or with a different value,
	// is not the response the profile describes, and an absent header is exactly
	// what a captive portal or a bare 200 looks like.
	for name, handler := range map[string]http.HandlerFunc{
		"no edge header at all": func(writer http.ResponseWriter, _ *http.Request) {
			writeIdentityBody(writer)
		},
		"a different edge value": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("X-Amz-Cf-Id", "somewhere-else")
			writeIdentityBody(writer)
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority := newTestAuthority(t)
			server, _ := mustIdentityServer(t, authority, profileHostname, handler)
			measure, _ := mustProberFor(t, authority, server)
			profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

			if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
				t.Fatal("a response without the required header was accepted")
			}
		})
	}
}

func TestHTTPSRefusesABodyThatIsNotTheOne(t *testing.T) {
	// The digest is what says the bytes came from the site rather than from
	// something in front of it. A host that answers 200 with the right headers
	// and the wrong document is refused.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("mosdns-router identity probe!\n"))
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

	if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
		t.Fatal("a body whose digest is not the profile's was accepted")
	}
}

func TestHTTPSRefusesToFollowARedirect(t *testing.T) {
	// A redirect is the address under test pointing somewhere else. Following it
	// would make the proof a statement about whatever is at the other end, so the
	// identity probe never follows one and the second request is never made.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/final" {
			writeIdentityBody(writer)
			return
		}
		http.Redirect(writer, request, "https://"+profileHostname+"/final", http.StatusFound)
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

	if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
		t.Fatal("a redirect was accepted for an identity probe")
	}
	if got := requests.paths(); len(got) != 1 || got[0] != "/identity" {
		t.Errorf("the server was asked for %v, want only the profile's own path", got)
	}
}

func TestHTTPSRefusesACandidateThatBelongsToAnotherHostname(t *testing.T) {
	// A CloudFront candidate is one hostname's answer and nothing else. Probing
	// it with another hostname's profile is the leak this package exists to
	// prevent, so it is refused before a socket is opened.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, identityHandler)
	measure, dialled := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
	stranger := candidate.Candidate{
		Provider: candidate.ProviderCloudFront,
		IP:       netip.MustParseAddr(candidateAddress),
		Source:   candidate.SourceCloudFront,
		Hostname: otherHostname,
	}

	if _, err := measure.HTTPS(t.Context(), stranger, profile); err == nil {
		t.Fatal("a candidate of another hostname was proved for this profile")
	}
	if got := dialled.count(); got != 0 {
		t.Errorf("the dialer was asked for %d connections, want none", got)
	}
	if got := requests.count(); got != 0 {
		t.Errorf("the server was asked %d times, want none", got)
	}
}

func TestHTTPSRefusesACandidateThatIsNotAPublicAddress(t *testing.T) {
	// A candidate is published as a rewrite target, so it has to be routable
	// public IPv4 space. The prober holds the same line, because a probe that
	// would measure the router's own gateway is a probe whose result would be
	// published as a CDN address.
	for name, subject := range map[string]candidate.Candidate{
		"loopback": {
			Provider: candidate.ProviderCloudFront,
			IP:       netip.MustParseAddr("127.0.0.1"),
			Source:   candidate.SourceUser,
			Hostname: profileHostname,
		},
		"a reserved documentation address": {
			Provider: candidate.ProviderCloudFront,
			IP:       netip.MustParseAddr("198.51.100.7"),
			Source:   candidate.SourceUser,
			Hostname: profileHostname,
		},
		"a private address": {
			Provider: candidate.ProviderCloudflare,
			IP:       netip.MustParseAddr("192.168.1.1"),
			Source:   candidate.SourceUser,
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority := newTestAuthority(t)
			server, requests := mustIdentityServer(t, authority, profileHostname, identityHandler)
			measure, _ := mustProberFor(t, authority, server)
			profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

			if _, err := measure.HTTPS(t.Context(), subject, profile); err == nil {
				t.Fatalf("a candidate at %s was measured", subject.IP)
			}
			if got := requests.count(); got != 0 {
				t.Errorf("the server was asked %d times, want none", got)
			}
		})
	}
}

func TestHTTPSRefusesAProfileItCannotHoldTo(t *testing.T) {
	// A profile is an instruction about what a proof must show. One that cannot
	// be satisfied, or that names another host, is refused before any connection,
	// so a run cannot be pointed at a URL that would prove nothing about the
	// hostname the state file will publish.
	for name, mutate := range map[string]func(*candidate.ProbeProfile){
		"no expected status": func(profile *candidate.ProbeProfile) {
			profile.ExpectedStatus = nil
		},
		"a url for another host": func(profile *candidate.ProbeProfile) {
			profile.URL = "https://" + otherHostname + "/identity"
		},
		"a port the url does not name": func(profile *candidate.ProbeProfile) {
			profile.Port = 8443
		},
		"a method this release cannot send": func(profile *candidate.ProbeProfile) {
			profile.Method = http.MethodPost
		},
		"a body digest that is not a digest": func(profile *candidate.ProbeProfile) {
			profile.BodySHA256 = "not-a-digest"
		},
		"a port of zero": func(profile *candidate.ProbeProfile) {
			profile.Port = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority := newTestAuthority(t)
			server, requests := mustIdentityServer(t, authority, profileHostname, identityHandler)
			measure, _ := mustProberFor(t, authority, server)
			profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
			mutate(&profile)

			if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
				t.Fatalf("a profile with %s was accepted", name)
			}
			if got := requests.count(); got != 0 {
				t.Errorf("the server was asked %d times, want none", got)
			}
		})
	}
}

func TestHTTPSReadsTheEdgeTheResponseNamed(t *testing.T) {
	// Colocation is a label for the report and nothing else: the header it comes
	// from is written by the host under test, so it can never be an input to
	// whether that host is eligible. The rules are stated because "the edge" is
	// otherwise whatever the reader assumes.
	for name, table := range map[string]struct {
		headers map[string]string
		want    string
	}{
		"a CloudFront pop code": {
			headers: map[string]string{"X-Amz-Cf-Pop": "NRT9", "Cf-Ray": "8f2c1d3e4a5b6c7d-NRT"},
			want:    "NRT9",
		},
		"the Cloudflare suffix of a ray": {
			headers: map[string]string{"Cf-Ray": "8f2c1d3e4a5b6c7d-NRT"},
			want:    "NRT",
		},
		"a response that names no edge": {
			headers: map[string]string{},
			want:    "",
		},
		"a ray that names no location in it": {
			headers: map[string]string{"Cf-Ray": "8f2c1d3e4a5b6c7d"},
			want:    "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority := newTestAuthority(t)
			server, _ := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("X-Amz-Cf-Id", "probe")
				for key, value := range table.headers {
					writer.Header().Set(key, value)
				}
				writeIdentityBody(writer)
			})
			measure, _ := mustProberFor(t, authority, server)
			profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

			metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
			if err != nil {
				t.Fatalf("measure: %v", err)
			}
			if metrics.Colocation != table.want {
				t.Errorf("Colocation = %q, want %q", metrics.Colocation, table.want)
			}
		})
	}
}

func TestHTTPSRefusesABodyLargerThanTheIdentityProbeReads(t *testing.T) {
	// The identity body is bounded, because an address that has already passed
	// its handshake and its headers can still be an endless stream, and a probe
	// that reads it all is a transfer this package did not budget for.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		chunk := strings.Repeat("a", 4096)
		for written := 0; written < 64*1024; written += len(chunk) {
			if _, err := writer.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
	measure.options.MaxIdentityBodyBytes = 4096

	if _, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile); err == nil {
		t.Fatal("a body past the identity cap was read to the end")
	}
}

// TestPackageSourceNeverSkipsCertificateVerification is the standing check
// behind the identity probes: nothing in this module may turn certificate
// verification off. Every other test here proves that the verification this
// package does is strict, and this one proves there is no second, looser path
// waiting to be taken by a later change.
//
// The name it looks for is built from two halves so that this test file is not
// itself a match for it.
// TestAProberWithNoOptionsStillBoundsItsMeasurements is about the defaults. A
// bound left at zero is not an absent bound: a connect timeout of zero expires
// the attempt before it starts, and a body cap of zero refuses every digest, so a
// caller that passed the options it cared about and nothing else would measure
// nothing and be told it had measured a great deal of loss.
func TestAProberWithNoOptionsStillBoundsItsMeasurements(t *testing.T) {
	// The identity probe, whose handshake, header, and body bounds are all
	// separate numbers, and the transfer, whose body cap is the one the identity
	// probe reads its digest under.
	t.Run("an identity probe", func(t *testing.T) {
		authority := newTestAuthority(t)
		server, _ := mustIdentityServer(t, authority, profileHostname, identityHandler)
		measure := mustProberWithOnly(t, authority, server)

		metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), identityProfile(t, server, profileHostname, []int{http.StatusOK}))
		if err != nil {
			t.Fatalf("prove a profile with every bound left at its default: %v", err)
		}
		if metrics.Status != http.StatusOK {
			t.Errorf("Status = %d, want %d", metrics.Status, http.StatusOK)
		}
	})
	t.Run("a connect measurement", func(t *testing.T) {
		address, port, _ := mustListen(t)
		measure := New(Options{})

		metrics, err := measure.TCP(t.Context(), address, port, 1)
		if err != nil {
			t.Fatalf("measure one handshake with no options: %v", err)
		}
		if metrics.Samples != 1 {
			t.Errorf("Samples = %d with no options, want 1", metrics.Samples)
		}
	})
	t.Run("a transfer", func(t *testing.T) {
		authority := newTestAuthority(t)
		server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler("dd"))
		measure := mustProberWithOnly(t, authority, server)
		budget := mustBudget(t, dailyBudgetBytes)

		metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), downloadProfile(profileHostname), perCandidateBytes, 10*time.Second, budget)
		if err != nil {
			t.Fatalf("measure a transfer with every bound left at its default: %v", err)
		}
		if metrics.Bytes != 2 {
			t.Errorf("Bytes = %d, want the 2 the body carried", metrics.Bytes)
		}
	})
}

// TestHTTPSReportsTheIdentityBytesItRead is about the exposure the review found
// unmeasured. An identity probe is deliberately not charged to the daily budget,
// so the bytes it reads are bytes the budget does not know about. That is a
// deliberate trade (see DefaultMaxIdentityBodyBytes), not an oversight, and a
// trade nobody counts is a surprise waiting for the next run. Every body byte the
// probe reads is reported, so a run can add the probes up and show the operator
// what the identity checks cost.
func TestHTTPSReportsTheIdentityBytesItRead(t *testing.T) {
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, identityHandler)
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})

	metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err != nil {
		t.Fatalf("prove a profile: %v", err)
	}
	if metrics.BodyBytes != int64(len(identityBody)) {
		t.Errorf("BodyBytes = %d, want the %d the body carried", metrics.BodyBytes, len(identityBody))
	}
}

func TestHTTPSReadsNoBodyForAProfileThatClaimsNothing(t *testing.T) {
	// A profile with no digest makes no claim about the body, so the probe reads
	// no body at all. This is the mitigation that makes the exposure small: most
	// profiles need no digest, and the ones that do name a small document.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler(strings.Repeat("d", 4096)))
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
	profile.BodySHA256 = ""

	metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err != nil {
		t.Fatalf("prove a profile with no body claim: %v", err)
	}
	if metrics.BodyBytes != 0 {
		t.Errorf("BodyBytes = %d for a profile that claims nothing about the body, want 0", metrics.BodyBytes)
	}
}

func TestHTTPSReportsTheUnchargedBytesItRefusedToKeepReading(t *testing.T) {
	// A body past the cap is refused, and the refusal still has to say how much was
	// read: those bytes crossed the network, they are not on the budget, and
	// leaving them uncounted is the exact silence this metric exists to remove.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler(strings.Repeat("d", 8192)))
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
	const cap = 4096
	measure.options.MaxIdentityBodyBytes = cap

	metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err == nil {
		t.Fatalf("a body past the identity cap was accepted: %+v", metrics)
	}
	// The reader takes the cap and one more byte: one byte past the cap is how it
	// knows the body is too long to be the document the profile named.
	if metrics.BodyBytes != cap+1 {
		t.Errorf("BodyBytes = %d after refusing an 8192 byte body under a %d byte cap, want %d", metrics.BodyBytes, cap, cap+1)
	}
}

func TestHTTPSNeverReadsMoreThanTheIdentityCapAllows(t *testing.T) {
	// The cap is the whole bound, and it is the default a production prober gets.
	// The body here is four times the cap, so a reader that ignored the cap would
	// report four times as many bytes as the one that honours it: the fixture is
	// deliberately much larger than the cap rather than one byte over it, because a
	// body one byte over proves nothing about where the reader stops.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler(strings.Repeat("d", 4*DefaultMaxIdentityBodyBytes)))
	measure, _ := mustProberFor(t, authority, server)
	profile := identityProfile(t, server, profileHostname, []int{http.StatusOK})
	// The digest does not match on purpose: the point of the refused cases is how
	// much was read, not whether it matched.
	mismatch := strings.Repeat("a", 64)

	profile.BodySHA256 = mismatch
	metrics, err := measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err == nil {
		t.Fatalf("a body of %d bytes was accepted under a digest it does not match: %+v", 4*DefaultMaxIdentityBodyBytes, metrics)
	}
	// One byte past the cap is where the reader stops, and one byte past the cap is
	// all it reports: a reader that ignored the cap would have reported four times
	// this, which is the whole difference this bound makes to the exposure.
	if metrics.BodyBytes != DefaultMaxIdentityBodyBytes+1 {
		t.Errorf("BodyBytes = %d for a body of four times the cap, want the cap and the one byte that proves it: %d", metrics.BodyBytes, DefaultMaxIdentityBodyBytes+1)
	}

	// A body that fits is read whole and reported exactly, because a probe that
	// reported the cap for every body would be no use as an accounting figure.
	fits := strings.Repeat("d", 1024)
	server, _ = mustIdentityServer(t, authority, profileHostname, payloadHandler(fits))
	measure, _ = mustProberFor(t, authority, server)
	profile.BodySHA256 = digestOf(fits)
	metrics, err = measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err != nil {
		t.Fatalf("prove a profile whose body fits under the cap: %v", err)
	}
	if metrics.BodyBytes != int64(len(fits)) {
		t.Errorf("BodyBytes = %d for a %d byte body under the cap, want every byte of it", metrics.BodyBytes, len(fits))
	}

	// And the cap is a refusal in its own right, not only a way of noticing a
	// digest mismatch: a profile that names a document larger than the cap can
	// never be proved, and says so rather than reading the whole thing.
	overCap := strings.Repeat("d", DefaultMaxIdentityBodyBytes+1)
	server, _ = mustIdentityServer(t, authority, profileHostname, payloadHandler(overCap))
	measure, _ = mustProberFor(t, authority, server)
	profile.BodySHA256 = digestOf(overCap)
	metrics, err = measure.HTTPS(t.Context(), identityCandidate(profileHostname), profile)
	if err == nil {
		t.Fatalf("a profile naming a body over the cap was accepted: %+v", metrics)
	}
	if metrics.BodyBytes != DefaultMaxIdentityBodyBytes+1 {
		t.Errorf("BodyBytes = %d for a body one byte over the cap, want %d", metrics.BodyBytes, DefaultMaxIdentityBodyBytes+1)
	}
}

// TestTheSourceScanFailsOnForbiddenCode is the scan's own test, and it exists
// because a guard that cannot fail is not a guard. It runs the same scanner the
// module-wide test runs, over a tree it builds here, and requires each of the
// scanner's rules to fire on the file that breaks it and to stay quiet on the
// files that do not.
//
// The two forbidden names are built from halves so that this test file is not
// itself a match for either of them.
// TestTheExportedOptionsCannotCarryTrustAnchors closes the gap the source scan
// cannot. The scan lets exactly one file name the trust anchors, and that file is
// where an exported override would be the natural place to put one back, so the
// scan would not see it. This test is the rule the scan cannot express: the only
// thing a production caller can hand a prober is Options, and Options carries no
// pool of trust anchors. A prober is therefore verified against the host's own
// roots, always, and no policy document, profile, or line of Go in another
// package can change that.
func TestTheExportedOptionsCannotCarryTrustAnchors(t *testing.T) {
	anchors := reflect.TypeOf((*x509.CertPool)(nil))
	options := reflect.TypeOf(Options{})
	for field := 0; field < options.NumField(); field++ {
		if options.Field(field).Type == anchors {
			t.Errorf("Options.%s carries a trust anchor pool, so a production caller could have every identity proof verified against roots the router does not trust", options.Field(field).Name)
		}
	}
}

func TestTheSourceScanFailsOnForbiddenCode(t *testing.T) {
	forbiddenVerification := "InsecureSkip" + "Verify"
	forbiddenAnchors := "Root" + "CAs"
	const reviewedMarker = "// " + reviewMarker + "\n"
	// A file that names the anchors, one that skips verification, and one that does
	// neither, so each rule has something to tell apart from the others.
	namesAnchors := "package anchor\n\nvar identity = struct{ " + forbiddenAnchors + " *x509.CertPool }{}\n"
	skipsVerification := "package loose\n\nvar loose = tls.Config{" + forbiddenVerification + ": true}\n"

	for name, table := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"a file that skips certificate verification is reported": {
			files: map[string]string{
				"clean.go":      "package clean\n",
				"loose.go":      skipsVerification,
				"clean_test.go": "package clean\n",
			},
			want: []string{"loose.go"},
		},
		"a test file that skips certificate verification is reported too": {
			files: map[string]string{"loose_test.go": skipsVerification},
			want:  []string{"loose_test.go"},
		},
		"a production file that names the trust anchors is reported": {
			files: map[string]string{"anchor.go": namesAnchors},
			want:  []string{"anchor.go"},
		},
		"a test file may name the trust anchors, because that is how an identity proof is proved": {
			files: map[string]string{"anchor_test.go": namesAnchors},
		},
		"the one reviewed file may name the trust anchors": {
			files: map[string]string{"options.go": reviewedMarker + namesAnchors},
		},
		"the marker is a line of its own, not a word inside one": {
			files: map[string]string{
				"options.go": "package options // " + reviewMarker + "\n\nvar identity = struct{ " + forbiddenAnchors + " *x509.CertPool }{}\n",
			},
			want: []string{"options.go"},
		},
		"a reviewed file that skips certificate verification is still reported": {
			files: map[string]string{"options.go": reviewedMarker + skipsVerification},
			want:  []string{"options.go"},
		},
		"both rules fire in one tree": {
			files: map[string]string{
				"anchor.go":   namesAnchors,
				"loose.go":    skipsVerification,
				"reviewed.go": reviewedMarker + namesAnchors,
				"clean.go":    "package clean\n",
			},
			want: []string{"anchor.go", "loose.go"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for path, contents := range table.files {
				if err := os.WriteFile(filepath.Join(root, path), []byte(contents), 0o600); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
			}
			found, err := scanModuleSource(root, forbiddenVerification, forbiddenAnchors)
			if err != nil {
				t.Fatalf("scan the tree: %v", err)
			}
			reported := make([]string, 0, len(found))
			for _, path := range found {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					t.Fatalf("relativise %s: %v", path, relErr)
				}
				reported = append(reported, relative)
			}
			if !slices.Equal(reported, table.want) {
				t.Fatalf("the scan reported %v, want %v", reported, table.want)
			}
		})
	}
}

// TestPackageSourceNeverSkipsCertificateVerification is the standing check
// behind the identity probes: nothing in this module may turn certificate
// verification off, and nothing outside a test may name the trust anchors a
// verification is made against. Every other test here proves that the
// verification this package does is strict, and this one proves there is no
// second, looser path waiting to be taken by a later change.
//
// The two names it looks for are built from halves in the test below, so that
// this test file is not itself a match for either of them.
func TestPackageSourceNeverSkipsCertificateVerification(t *testing.T) {
	forbiddenVerification := "InsecureSkip" + "Verify"
	forbiddenAnchors := "Root" + "CAs"
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("locate the module root: %v", err)
	}
	found, err := scanModuleSource(root, forbiddenVerification, forbiddenAnchors)
	if err != nil {
		t.Fatalf("scan the module: %v", err)
	}
	if len(found) > 0 {
		t.Fatalf("these files weaken certificate verification: %v. A file may not turn verification off, and a file outside a test may not name the trust roots, except the one file carrying the %q marker", found, reviewMarker)
	}
}

// reviewMarker is the one exemption in the source scan, and it is a line of its
// own that exactly one file in this module carries: the prober's own identity
// anchors. It names where the trust anchors live so that the scan is what keeps
// them there, rather than a reviewer having to notice on their own.
const reviewMarker = "reviewed: the prober's unexported identity trust anchors"

// scanModuleSource returns every Go file under root that weakens certificate
// verification, sorted by path.
//
// The rule is deliberately blunt: any file, test or not, that sets the setting
// that disables verification is reported, because a test that skips
// verification proves nothing and a production file that does is the failure
// this whole project exists to prevent. Trust anchors are reported only outside
// tests, because naming them is how a test proves that a chain is checked and a
// chain that is not checked. The one production file allowed to name them must
// carry reviewMarker on a line of its own, so the exemption is a reviewed
// decision in that file rather than a package name in this one.
//
// The names are arguments rather than constants so that this test file, which
// contains them, is not a match for the scan it drives.
func scanModuleSource(root, forbiddenVerification, forbiddenAnchors string) ([]string, error) {
	var findings []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			// Only the module's own source is in scope. The build output and the
			// version control directory are not source, and the planning documents
			// name the forbidden settings in prose because they are prohibitions.
			if path != root && (name == ".git" || name == "build" || name == ".superpowers" || name == ".worktrees") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		isTest := strings.HasSuffix(name, "_test.go")
		weakensVerification := bytes.Contains(contents, []byte(forbiddenVerification))
		namesAnchors := !isTest && !carriesReviewMarker(contents) && bytes.Contains(contents, []byte(forbiddenAnchors))
		if weakensVerification || namesAnchors {
			findings = append(findings, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(findings)
	return findings, nil
}

// carriesReviewMarker reports whether a file claims the one exemption the anchor
// rule allows. The marker has to be a whole line: a comment that merely mentions
// it, or one that trails the end of a sentence, is not a reviewed decision in
// that file, and a scan that accepted either would be a scan anyone could talk
// past.
func carriesReviewMarker(contents []byte) bool {
	marker := "// " + reviewMarker
	for _, line := range bytes.Split(contents, []byte("\n")) {
		if string(bytes.TrimSpace(line)) == marker {
			return true
		}
	}
	return false
}

// The download measurements below run against a TLS server on a loopback port
// and charge a real persistent budget in a temporary directory, because the two
// things they have to prove are that the reader stops where it promised and that
// the budget is written before the first byte is read. Both are claims about
// order, and neither can be proved with a stand-in for the thing whose order
// matters.

const (
	// dailyBudgetBytes and perCandidateBytes are the policy defaults this
	// repository ships: cdn.bandwidth.daily_budget and
	// cdn.bandwidth.per_candidate_limit.
	dailyBudgetBytes  = 100 * mib
	perCandidateBytes = 10 * mib
	mib               = 1 << 20
)

func TestDownloadChargesOnlyTheBytesItTransferred(t *testing.T) {
	// A candidate that answers with three megabytes cost three megabytes. The
	// reservation is ten, the difference goes back, and what the day is charged
	// is what the user actually spent.
	body := strings.Repeat("d", 3*mib)
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler(body))
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget)
	if err != nil {
		t.Fatalf("measure a 3 MiB transfer: %v", err)
	}
	if metrics.Bytes != int64(len(body)) {
		t.Errorf("Bytes = %d, want the %d the body had", metrics.Bytes, len(body))
	}
	if used := budget.Used(); used != int64(len(body)) {
		t.Errorf("the budget is charged %d bytes, want the %d that were transferred", used, len(body))
	}
	if metrics.Elapsed <= 0 {
		t.Errorf("Elapsed = %v, want a positive transfer time", metrics.Elapsed)
	}
	// The rate is the transfer, not a number of its own: the bytes over the
	// seconds the transfer took.
	want := float64(metrics.Bytes) / metrics.Elapsed.Seconds()
	if difference := metrics.BytesPerSecond - want; difference > 1e-9*want || difference < -1e-9*want {
		t.Errorf("BytesPerSecond = %v, want %v for %d bytes over %v", metrics.BytesPerSecond, want, metrics.Bytes, metrics.Elapsed)
	}
}

func TestDownloadStopsAtTheReservation(t *testing.T) {
	// A body past the reservation stops at the reservation and not one byte
	// further, whatever the server was willing to send: a candidate that streams
	// without end must not be able to spend more than the day's per-candidate
	// limit.
	body := strings.Repeat("d", perCandidateBytes+4096)
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler(body))
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 30*time.Second, budget)
	if err != nil {
		t.Fatalf("measure a body past the reservation: %v", err)
	}
	if metrics.Bytes != perCandidateBytes {
		t.Errorf("Bytes = %d, want the %d reserved", metrics.Bytes, perCandidateBytes)
	}
	if used := budget.Used(); used != perCandidateBytes {
		t.Errorf("the budget is charged %d bytes, want the %d reserved", used, perCandidateBytes)
	}
	// The time limit was never reached, so this stopped on the byte limit.
	if metrics.Elapsed >= 30*time.Second {
		t.Errorf("Elapsed = %v, want a transfer that stopped on the byte limit", metrics.Elapsed)
	}
}

func TestCountingReaderNeverReadsPastItsLimit(t *testing.T) {
	// The reader is what the byte limit is enforced with, and a reader that asks
	// its source for one byte more than it may take is a reader that spends one
	// byte more than the budget reserved. The source below counts every byte it
	// hands over, so the bound is observable rather than inferred.
	for name, table := range map[string]struct {
		limit  int64
		buffer int
		want   int64
	}{
		"a limit smaller than the buffer": {limit: 10, buffer: 4096, want: 10},
		"a limit larger than the buffer":  {limit: 100, buffer: 8, want: 100},
		"a limit equal to the body":       {limit: 64, buffer: 64, want: 64},
		"no limit at all":                 {limit: 0, buffer: 4096, want: 0},
		"a negative limit":                {limit: -1, buffer: 4096, want: 0},
	} {
		t.Run(name, func(t *testing.T) {
			source := &countingSource{remaining: 1024}
			reader := newCountingReader(source, table.limit)

			read, err := io.Copy(io.Discard, reader)
			if err != nil {
				t.Fatalf("read to the end: %v", err)
			}
			if read != table.want {
				t.Errorf("read %d bytes, want %d", read, table.want)
			}
			if reader.count != table.want {
				t.Errorf("the reader counted %d bytes, want %d", reader.count, table.want)
			}
			// The source handed over no more than the limit, which is the whole
			// claim: io.LimitReader keeps the source from being asked for a byte
			// it is not allowed to give.
			if source.handed != table.want {
				t.Errorf("the source handed over %d bytes, want %d", source.handed, table.want)
			}
			// Asking again is the end of the reader, not another read of the source.
			buffer := make([]byte, 16)
			if count, err := reader.Read(buffer); count != 0 || !errors.Is(err, io.EOF) {
				t.Errorf("a read past the limit returned %d, %v, want 0, EOF", count, err)
			}
			if source.handed != table.want {
				t.Errorf("the source handed over %d bytes after the limit, want %d", source.handed, table.want)
			}
		})
	}
}

func TestDownloadStopsAtTheTimeLimit(t *testing.T) {
	// A body that trickles stops at the time limit instead, and what it delivered
	// by then is a measurement: the transfer is over as far as the day's budget
	// and the run are concerned, and the bytes that did arrive are what it cost.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, trickleHandler(32, 100*time.Millisecond))
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 250*time.Millisecond, budget)
	if err != nil {
		t.Fatalf("a transfer stopped by the time limit is a measurement, not a failure: %v", err)
	}
	if metrics.Bytes == 0 {
		t.Fatal("the transfer delivered nothing at all")
	}
	if metrics.Bytes >= perCandidateBytes {
		t.Errorf("Bytes = %d, want fewer than the %d the byte limit allows", metrics.Bytes, perCandidateBytes)
	}
	// The server sends 32 bytes every 100ms, so a 250ms limit can have delivered
	// at most three chunks of them, and what arrived is a whole number of chunks.
	if metrics.Bytes%32 != 0 {
		t.Errorf("Bytes = %d, which is not a whole number of 32 byte chunks", metrics.Bytes)
	}
	if metrics.Bytes > 3*32 {
		t.Errorf("Bytes = %d, want at most the three chunks a 250ms limit allows", metrics.Bytes)
	}
	if used := budget.Used(); used != metrics.Bytes {
		t.Errorf("the budget is charged %d bytes, want the %d that were transferred", used, metrics.Bytes)
	}
}

func TestDownloadReservesBeforeItOpensAConnection(t *testing.T) {
	// The reservation is on the books before the first request is made, so a run
	// that dies mid-transfer is still charged for it. The server reads the budget
	// document while it answers, which is the only way to see the order from the
	// other side of the socket.
	authority := newTestAuthority(t)
	budget := mustBudget(t, dailyBudgetBytes)
	seen := new(spentAtRequest)
	document := budget.Path()
	server, _ := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, _ *http.Request) {
		seen.record(t, document)
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		_, _ = writer.Write([]byte("d"))
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)

	if _, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget); err != nil {
		t.Fatalf("measure a transfer: %v", err)
	}
	if observed := seen.used(); observed < perCandidateBytes {
		t.Fatalf("the budget document held %d bytes when the first request arrived, want the %d reserved before it", observed, perCandidateBytes)
	}
}

func TestDownloadRefusesWhatTheDayCannotPayFor(t *testing.T) {
	// A budget with nothing left refuses the request, and the transfer never
	// starts: the reservation is the permission, and a transfer without one is
	// the exact thing the daily cap exists to prevent.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, payloadHandler("dd"))
	measure, dialled := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)
	if _, err := budget.Reserve(dailyBudgetBytes); err != nil {
		t.Fatalf("fill the day's budget: %v", err)
	}

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget)
	if err == nil {
		t.Fatalf("a transfer with no budget left was measured: %+v", metrics)
	}
	if !errors.Is(err, optimizer.ErrBudgetExhausted) {
		t.Errorf("the refusal is %v, want the budget's own exhausted error", err)
	}
	if metrics != (DownloadMetrics{}) {
		t.Errorf("metrics = %+v after a refusal, want the zero value", metrics)
	}
	if got := requests.count(); got != 0 {
		t.Errorf("the server was asked %d times, want none", got)
	}
	if got := dialled.count(); got != 0 {
		t.Errorf("the dialer was asked for %d connections, want none", got)
	}
	if used := budget.Used(); used != dailyBudgetBytes {
		t.Errorf("the budget is charged %d bytes, want the %d it already held", used, dailyBudgetBytes)
	}
}

func TestDownloadRefusesARedirectToAnotherHost(t *testing.T) {
	// A redirect to another host is the address under test naming somewhere else.
	// The transfer stops there rather than paying another site's bandwidth to
	// find out what a candidate can do, and the other host is never asked.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/final" {
			_, _ = writer.Write([]byte("dd"))
			return
		}
		http.Redirect(writer, request, "https://"+otherHostname+"/final", http.StatusFound)
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	if _, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget); err == nil {
		t.Fatal("a redirect to another host was followed")
	}
	if got := requests.paths(); len(got) != 1 || got[0] != "/payload" {
		t.Errorf("the server was asked for %v, want only the profile's own path", got)
	}
	if used := budget.Used(); used != 0 {
		t.Errorf("the budget is charged %d bytes, want nothing", used)
	}
}

func TestDownloadFollowsARedirectWithinTheProfileHost(t *testing.T) {
	// A redirect that stays on the profile's own host is not a different site, so
	// it is followed: the final host is still the host the profile names, and the
	// certificate is verified for that name on the way there.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/final" {
			writer.Header().Set("X-Amz-Cf-Id", "probe")
			_, _ = writer.Write([]byte("dddd"))
			return
		}
		http.Redirect(writer, request, "https://"+profileHostname+"/final", http.StatusFound)
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget)
	if err != nil {
		t.Fatalf("a redirect within the profile host was refused: %v", err)
	}
	if metrics.Bytes != 4 {
		t.Errorf("Bytes = %d, want the 4 the final response carried", metrics.Bytes)
	}
	if got := requests.paths(); len(got) != 2 || got[1] != "/final" {
		t.Errorf("the server was asked for %v, want the profile's path and then /final", got)
	}
	if used := budget.Used(); used != 4 {
		t.Errorf("the budget is charged %d bytes, want the 4 that were transferred", used)
	}
}

func TestDownloadRefusesAProfileThatCannotCarryABody(t *testing.T) {
	// A HEAD profile has no body to measure, and measuring nothing while looking
	// like a measurement is worse than refusing.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, payloadHandler("dd"))
	measure, dialled := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	profile.Method = http.MethodHead
	budget := mustBudget(t, dailyBudgetBytes)

	if _, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget); err == nil {
		t.Fatal("a HEAD profile was measured as a transfer")
	}
	if got := dialled.count(); got != 0 {
		t.Errorf("the dialer was asked for %d connections, want none", got)
	}
	if got := requests.count(); got != 0 {
		t.Errorf("the server was asked %d times, want none", got)
	}
	if used := budget.Used(); used != 0 {
		t.Errorf("the budget is charged %d bytes, want nothing", used)
	}
}

func TestDownloadRefusesAnIdentityItCannotProve(t *testing.T) {
	// A transfer only happens behind a proof, and the proof for a transfer is the
	// same one the identity probe makes: a chain for the profile's name, a status
	// the profile expects, and the headers it requires. A body this probe refuses
	// to read is a body this package does not pay for.
	for name, handler := range map[string]http.HandlerFunc{
		"a status the profile does not expect": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("X-Amz-Cf-Id", "probe")
			writer.WriteHeader(http.StatusForbidden)
			_, _ = writer.Write([]byte(strings.Repeat("d", 1024)))
		},
		"a response without the required header": func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(strings.Repeat("d", 1024)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority := newTestAuthority(t)
			server, _ := mustIdentityServer(t, authority, profileHostname, handler)
			measure, _ := mustProberFor(t, authority, server)
			profile := downloadProfile(profileHostname)
			budget := mustBudget(t, dailyBudgetBytes)

			if _, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget); err == nil {
				t.Fatalf("%s was measured as a transfer", name)
			}
			if used := budget.Used(); used != 0 {
				t.Errorf("the budget is charged %d bytes for a refused identity, want nothing", used)
			}
		})
	}
}

func TestDownloadRefusesACertificateForAnotherName(t *testing.T) {
	// The identity chain is the same chain a transfer goes through, so a
	// certificate for another name buys no bytes either.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, otherHostname, payloadHandler(strings.Repeat("d", 4096)))
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	if _, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget); err == nil {
		t.Fatal("a certificate for another name delivered a transfer")
	}
	if used := budget.Used(); used != 0 {
		t.Errorf("the budget is charged %d bytes, want nothing", used)
	}
}

func TestDownloadChargesWhatItReadBeforeTheConnectionFailed(t *testing.T) {
	// A transfer that dies part way through has cost what it delivered. Charging
	// nothing would be free bandwidth for anything that breaks a connection on
	// purpose, and charging the whole reservation would over-report a run the user
	// can see failed.
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		// A body that says it is longer than it is, and then stops: the client
		// takes what arrived and finds the connection ended.
		writer.Header().Set("Content-Length", "65536")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(strings.Repeat("d", 1024)))
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		panic(http.ErrAbortHandler)
	})
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	budget := mustBudget(t, dailyBudgetBytes)

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget)
	if err == nil {
		t.Fatalf("a transfer that ended early was reported as a measurement: %+v", metrics)
	}
	if metrics.Bytes == 0 {
		t.Fatal("nothing was charged, although 1024 bytes had been delivered")
	}
	if metrics.Bytes > 1024 {
		t.Errorf("Bytes = %d, want no more than the 1024 the server wrote", metrics.Bytes)
	}
	if used := budget.Used(); used != metrics.Bytes {
		t.Errorf("the budget is charged %d bytes, want the %d that were read", used, metrics.Bytes)
	}
}

// cappingBudget grants less than it is asked for, which the interface allows and
// the shipped budget never does. It exists because the reader's bound is the one
// thing standing between a grant and a transfer: a reader bounded by the request
// would take the 10 MiB it asked about from a budget that had promised 4 KiB, and
// settle 10 MiB against a 4 KiB grant.
type cappingBudget struct {
	granted int64
	// settled records what Consume was handed, which is what the day's charge
	// would be.
	settledActual int64
	settles       int
}

var _ ByteBudget = (*cappingBudget)(nil)

func (b *cappingBudget) Reserve(requested int64) (int64, error) {
	if requested > b.granted {
		return b.granted, nil
	}
	return requested, nil
}

func (b *cappingBudget) Consume(reserved, actual int64) {
	b.settles++
	b.settledActual = actual
}

// A budget that grants less than the transfer asked for bounds the transfer, and
// the settlement is never larger than the grant. The body is a full 10 MiB, so a
// reader bounded by the request would read all of it and settle all of it against
// a 4 KiB promise.
func TestDownloadIsBoundedByTheReservationAndNotTheRequest(t *testing.T) {
	body := strings.Repeat("d", perCandidateBytes)
	authority := newTestAuthority(t)
	server, _ := mustIdentityServer(t, authority, profileHostname, payloadHandler(body))
	measure, _ := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)
	const grant = 4096
	budget := &cappingBudget{granted: grant}

	metrics, err := measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, budget)
	if err != nil {
		t.Fatalf("measure a transfer against a budget that granted 4 KiB: %v", err)
	}
	if metrics.Bytes != grant {
		t.Errorf("Bytes = %d, want the %d the budget granted: the transfer may not read past what it paid for", metrics.Bytes, grant)
	}
	if budget.settles != 1 {
		t.Fatalf("the grant was settled %d times, want once", budget.settles)
	}
	if budget.settledActual != grant {
		t.Errorf("the grant was settled with %d bytes, want %d: the day may not be charged for more than it granted", budget.settledActual, grant)
	}
}

func TestDownloadRefusesATransferItCannotBound(t *testing.T) {
	// A transfer with no byte limit, no time limit, or no budget is not a
	// measurement: it is the unbounded thing this project exists to prevent, so it
	// is refused before the reservation is even asked for.
	authority := newTestAuthority(t)
	server, requests := mustIdentityServer(t, authority, profileHostname, payloadHandler("dd"))
	measure, dialled := mustProberFor(t, authority, server)
	profile := downloadProfile(profileHostname)

	for name, call := range map[string]func(ByteBudget) (DownloadMetrics, error){
		"no byte limit": func(ByteBudget) (DownloadMetrics, error) {
			return measure.Download(t.Context(), identityCandidate(profileHostname), profile, 0, 10*time.Second, mustBudget(t, dailyBudgetBytes))
		},
		"a negative byte limit": func(ByteBudget) (DownloadMetrics, error) {
			return measure.Download(t.Context(), identityCandidate(profileHostname), profile, -1, 10*time.Second, mustBudget(t, dailyBudgetBytes))
		},
		"no time limit": func(budget ByteBudget) (DownloadMetrics, error) {
			return measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 0, budget)
		},
		"no budget": func(ByteBudget) (DownloadMetrics, error) {
			return measure.Download(t.Context(), identityCandidate(profileHostname), profile, perCandidateBytes, 10*time.Second, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			metrics, err := call(nil)
			if err == nil {
				t.Fatalf("a transfer with %s was measured: %+v", name, metrics)
			}
			if metrics != (DownloadMetrics{}) {
				t.Errorf("metrics = %+v after a refusal, want the zero value", metrics)
			}
		})
	}
	if got := requests.count(); got != 0 {
		t.Errorf("the server was asked %d times, want none", got)
	}
	if got := dialled.count(); got != 0 {
		t.Errorf("the dialer was asked for %d connections, want none", got)
	}
}

// downloadProfile is the profile a transfer is measured with: the same name, URL,
// status, and header the identity probe insists on, and no claim about the body,
// because a transfer reads the body only as far as its limits allow.
func downloadProfile(hostname string) candidate.ProbeProfile {
	return candidate.ProbeProfile{
		Hostname:       hostname,
		URL:            "https://" + hostname + "/payload",
		Method:         http.MethodGet,
		Port:           profilePort,
		ExpectedStatus: []int{http.StatusOK},
		RequiredHeader: map[string]string{"X-Amz-Cf-Id": "probe"},
	}
}

// payloadHandler answers with a body of the given size, in as few writes as the
// server will make, which is how a candidate that delivers its whole allowance in
// under a second looks to the client.
func payloadHandler(body string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, body)
	}
}

// trickleHandler answers with a chunk of size bytes every interval, for as long
// as the client keeps reading, which is how a slow candidate looks.
func trickleHandler(size int, interval time.Duration) http.HandlerFunc {
	chunk := strings.Repeat("t", size)
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		writer.WriteHeader(http.StatusOK)
		flusher, canFlush := writer.(http.Flusher)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-request.Context().Done():
				return
			case <-ticker.C:
				if _, err := io.WriteString(writer, chunk); err != nil {
					return
				}
				if canFlush {
					flusher.Flush()
				}
			}
		}
	}
}

// spentAtRequest records what the budget document held at the moment a request
// arrived, which is how a test sees the order between the reservation and the
// first byte from the other side of the socket.
type spentAtRequest struct {
	mutex    sync.Mutex
	observed int64
}

func (s *spentAtRequest) record(t *testing.T, path string) {
	t.Helper()
	record := state.BandwidthBudgetState{}
	if err := state.ReadJSON(path, &record); err != nil {
		t.Errorf("the budget document is not readable while the request is in flight: %v", err)
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.observed = record.UsedBytes
}

func (s *spentAtRequest) used() int64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.observed
}

// mustBudget opens a real persistent budget in a temporary directory, because the
// claims these tests make are about what the budget document holds and about
// when.
func mustBudget(t *testing.T, limit int64) *optimizer.Budget {
	t.Helper()
	budget, err := optimizer.NewPersistentBudget(
		filepath.Join(t.TempDir(), optimizer.DefaultBudgetName), limit, time.UTC, time.Now())
	if err != nil {
		t.Fatalf("open the budget: %v", err)
	}
	return budget
}

// countingSource is a body that hands over a known number of bytes and counts
// every one of them, so a reader's limit can be observed from the source's side.
type countingSource struct {
	remaining int
	handed    int64
}

func (s *countingSource) Read(buffer []byte) (int, error) {
	if s.remaining == 0 {
		return 0, io.EOF
	}
	read := min(len(buffer), s.remaining)
	for index := range read {
		buffer[index] = 'x'
	}
	s.remaining -= read
	s.handed += int64(read)
	return read, nil
}

// identityHandler answers the way a verified host does: the required header, the
// expected status, and the body the profile names.
func identityHandler(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("X-Amz-Cf-Id", "probe")
	writeIdentityBody(writer)
}

func statusHandler(status int) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Amz-Cf-Id", "probe")
		writer.WriteHeader(status)
		if status == http.StatusOK {
			writeIdentityBody(writer)
		}
	}
}

func writeIdentityBody(writer http.ResponseWriter) {
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(identityBody))
}

// digestOf is the SHA-256 a profile would name for a body, written out here so a
// test that serves a body of its own can state the digest that body has.
func digestOf(body string) string {
	digest := sha256.Sum256([]byte(body))
	return hex.EncodeToString(digest[:])
}

// identityProfile is the profile a verified host answers: its own name, its own
// URL at the production port, the status and headers it must carry, and the
// digest of the body it must return.
func identityProfile(t *testing.T, _ *httptest.Server, hostname string, statuses []int) candidate.ProbeProfile {
	t.Helper()
	digest := sha256.Sum256([]byte(identityBody))
	return candidate.ProbeProfile{
		Hostname:       hostname,
		URL:            "https://" + hostname + "/identity",
		Method:         http.MethodGet,
		Port:           profilePort,
		ExpectedStatus: statuses,
		RequiredHeader: map[string]string{"X-Amz-Cf-Id": "probe"},
		BodySHA256:     hex.EncodeToString(digest[:]),
	}
}

// identityCandidate is a per-hostname candidate at the real public literal the
// tests measure through their own dialer.
func identityCandidate(hostname string) candidate.Candidate {
	return candidate.Candidate{
		Provider: candidate.ProviderCloudFront,
		IP:       netip.MustParseAddr(candidateAddress),
		Source:   candidate.SourceCloudFront,
		Hostname: hostname,
	}
}

// mustIdentityServer starts a TLS server on an ephemeral loopback port with a
// certificate this test generated, and records what each request looked like.
func mustIdentityServer(t *testing.T, authority *testAuthority, hostname string, handler http.HandlerFunc) (*httptest.Server, *requestLog) {
	t.Helper()
	certificate := authority.issue(t, hostname)
	requests := new(requestLog)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		serverName := ""
		if request.TLS != nil {
			serverName = request.TLS.ServerName
		}
		requests.add(requestFacts{host: request.Host, serverName: serverName, path: request.URL.Path})
		handler(writer, request)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	// The refusals below are made by aborting a handshake or a request, which this
	// server would otherwise log to the test's output. The log is not the
	// assertion; the returned error is.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, requests
}

// mustProberFor returns a prober that trusts the given authority's pool, or the
// host's own roots when the authority is nil, and a dialer that records what it
// was asked to connect to while sending the connection to the local server.
//
// The anchors go in through the unexported construction, because that is the only
// way in: no production caller can ask a prober to trust anything but the host's
// own roots, which is what TestHTTPSRefusesAnEphemeralAuthorityWhenTheSystemRootsAreTheOne
// shows and what the source scan keeps true.
func mustProberFor(t *testing.T, authority *testAuthority, server *httptest.Server) (*NetworkProber, *dialLog) {
	t.Helper()
	dialled := new(dialLog)
	local := server.Listener.Addr().String()
	measure := newProber(Options{
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ProbeTimeout:          10 * time.Second,
		MaxIdentityBodyBytes:  DefaultMaxIdentityBodyBytes,
		Dialer: func(ctx context.Context, network, target string) (net.Conn, error) {
			dialled.add(target)
			var standard net.Dialer
			return standard.DialContext(ctx, network, local)
		},
	}, probeOptions{RootCAs: authority.trust()})
	return measure, dialled
}

// mustProberWithOnly returns a prober that trusts the given authority and reaches
// the local server, and is configured with nothing else: every bound is left at
// whatever the prober's own defaults are.
func mustProberWithOnly(t *testing.T, authority *testAuthority, server *httptest.Server) *NetworkProber {
	t.Helper()
	local := server.Listener.Addr().String()
	return newProber(Options{
		Dialer: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var standard net.Dialer
			return standard.DialContext(ctx, network, local)
		},
	}, probeOptions{RootCAs: authority.trust()})
}

// requestFacts is what one request looked like from the server's side.
type requestFacts struct {
	host       string
	serverName string
	path       string
}

// requestLog records the requests a test server received, so a test can say how
// many there were and what they carried.
type requestLog struct {
	mutex sync.Mutex
	facts []requestFacts
}

func (l *requestLog) add(fact requestFacts) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.facts = append(l.facts, fact)
}

func (l *requestLog) count() int {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return len(l.facts)
}

func (l *requestLog) paths() []string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	paths := make([]string, 0, len(l.facts))
	for _, fact := range l.facts {
		paths = append(paths, fact.path)
	}
	return paths
}

func (l *requestLog) last(t *testing.T) requestFacts {
	t.Helper()
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if len(l.facts) != 1 {
		t.Fatalf("the server received %d requests, want exactly one", len(l.facts))
	}
	return l.facts[0]
}

// dialLog records the endpoints a prober asked its dialer for, which is how a
// test proves the connection was made to the candidate's address and not to a
// name that would have to be resolved first.
type dialLog struct {
	mutex   sync.Mutex
	records []string
}

func (l *dialLog) add(target string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.records = append(l.records, target)
}

func (l *dialLog) count() int {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return len(l.records)
}

func (l *dialLog) targets() []string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return append([]string(nil), l.records...)
}

// testAuthority is a certificate authority generated for one test, in that
// test's own temporary directory. Its private key never leaves the directory,
// and nothing it signs is added to the host's trust store: the prober is given
// this authority's pool explicitly, and the test that uses the system roots
// proves that a prober without it refuses everything this authority signs.
type testAuthority struct {
	directory   string
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pool        *x509.CertPool
}

// newTestAuthority generates a self-signed authority and writes it to the test's
// temporary directory.
func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the authority key: %v", err)
	}
	serial := new(big.Int).SetInt64(1)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mosdns-router test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the authority certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the authority certificate: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(directory, "authority.pem"), encoded, 0o600); err != nil {
		t.Fatalf("write the authority: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		t.Fatal("the authority certificate is not a certificate a pool can hold")
	}
	return &testAuthority{directory: directory, certificate: certificate, key: key, pool: pool}
}

// issue writes a leaf certificate for the given names into the test's directory
// and returns it as a key pair, exactly as a server would load one from disk.
func (a *testAuthority) issue(t *testing.T, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("create the leaf certificate: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("encode the leaf key: %v", err)
	}
	certificatePath := filepath.Join(a.directory, "leaf.pem")
	keyPath := filepath.Join(a.directory, "leaf.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write the leaf certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("write the leaf key: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load the leaf key pair: %v", err)
	}
	return pair
}

// trust is the pool a prober is given to verify this authority's leaves. A nil
// authority has no pool, and the prober falls back to the host's own roots.
func (a *testAuthority) trust() *x509.CertPool {
	if a == nil {
		return nil
	}
	return a.pool
}
