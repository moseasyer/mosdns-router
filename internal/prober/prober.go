// Package prober measures a candidate CDN address and decides whether it is
// really serving the hostname it was offered for.
//
// Nothing in here infers identity from a fast handshake. A TCP measurement says
// that something is listening; only the HTTPS measurement can make an address
// eligible, and it earns that by completing a certificate chain for the profile
// hostname, answering with a status the profile expects, carrying the headers
// the profile requires, and returning a body with the digest the profile names.
// Every measurement is bounded: samples, time, and bytes.
package prober

import (
	"context"
	"net/netip"
	"time"

	"mosdns-router/internal/candidate"
)

// ByteBudget is the daily allowance a transfer reserves from before it reads
// anything. Reserve persists the request, so the charge for a transfer that
// never finishes is already on the books; Consume settles it with what was
// really transferred.
//
// The interface is declared here, at the measurement boundary, because this is the
// side that must not be able to read first and ask later. It is deliberately
// narrow, and the narrowness has a cost a caller must know about: the guarantee
// that a reservation can be settled only once lives in the concrete budget, not
// here, because this interface has no way to report a refusal and therefore no way
// to know whether one happened. The only implementation of this contract is
// *optimizer.Budget, and another implementation would have to reimplement the
// one-shot rule to be as safe. Pass that type; if a caller finds itself writing
// another one, the settle semantics are being re-decided away from the budget
// that owns the day.
type ByteBudget interface {
	// Reserve charges up to requested bytes and returns the amount reserved, or
	// an error when the day cannot cover it.
	Reserve(requested int64) (int64, error)
	// Consume settles reserved with actual. It hands back the difference and
	// never more than the reservation.
	Consume(reserved, actual int64)
}

// TCPMetrics is what one address's connect latency looked like. It says that
// something was listening at a port, and nothing about who it was: no field here
// can make a candidate eligible.
type TCPMetrics struct {
	// Samples is the number of handshakes that completed. A sample is one
	// successful connect; the attempts that did not become samples are in Loss.
	Samples int
	// P50MS is the median of the successful samples by the nearest-rank method:
	// of n samples in ascending order, the one at index ceil(0.50*n)-1, with no
	// interpolation between neighbours.
	P50MS float64
	// P95MS is the 95th percentile of the successful samples by the same
	// nearest-rank method, at index ceil(0.95*n)-1.
	P95MS float64
	// JitterMS is the mean absolute difference between consecutive successful
	// samples in the order they were measured, which is the variation a caller
	// feels and the median hides. It is zero for a single sample.
	JitterMS float64
	// Loss is the fraction of attempts that did not complete, out of every
	// attempt this call made: refused, reset, or timed out.
	Loss float64
}

// HTTPMetrics is what one address proved about itself over a verified TLS
// connection. A caller may only treat the address as serving the profile's
// hostname when the call returned no error, because every one of these fields is
// reported by the very host that was under test.
type HTTPMetrics struct {
	// Status is the response status, which the profile had to expect.
	Status int
	// TLSMS is the TLS handshake on its own: from the first handshake byte to the
	// handshake completing, not counting the TCP connect in front of it.
	TLSMS float64
	// TTFBMS is the time to first response byte after the request was written,
	// which is what a page load calls time to first byte.
	TTFBMS float64
	// TotalMS is the whole probe: connect, handshake, request, and body.
	TotalMS float64
	// Colocation is the edge the response named for itself, from the first of
	// x-amz-cf-pop and cf-ray the response carried. It is a label for the report
	// and is never an input to eligibility, because the host under test writes it.
	Colocation string
	// BodyBytes is how many body bytes this probe read, and it is the one number
	// here that is not a measurement of the candidate.
	//
	// An identity probe is deliberately not charged to the daily budget, so
	// nothing on disk records the body bytes a run spent proving identity. This
	// field is that record: a caller sums it across the run's probes and shows the
	// operator what the uncharged identity traffic was, instead of leaving it as a
	// surprise in the operator's data allowance. It is reported even when the probe
	// is refused, because bytes that crossed the network are spent whether or not
	// the proof succeeded.
	//
	// So a caller must add it in before it looks at the error. The idiomatic
	// "metrics, err := HTTPS(...); if err != nil { continue }" throws away the only
	// accounting this field exists for, and a refused probe is the one case where
	// the bytes were spent and nothing was published in exchange.
	BodyBytes int64
}

// DownloadMetrics is what one address actually delivered, and what it cost.
type DownloadMetrics struct {
	// Bytes is what the body reader took, never more than the reservation.
	Bytes int64
	// Elapsed is the wall time the transfer took, to the byte limit, the time
	// limit, or the first read error.
	Elapsed time.Duration
	// BytesPerSecond is Bytes over Elapsed, and zero when no time passed.
	BytesPerSecond float64
}

// Prober measures candidates. TCP and HTTPS make no charge against the daily
// budget: they are small, bounded, and a run that cannot afford them has other
// problems. Only Download spends, because only Download transfers what the
// budget exists to bound.
type Prober interface {
	// TCP measures connect latency to an address and port.
	TCP(ctx context.Context, address netip.Addr, port uint16, samples int) (TCPMetrics, error)
	// HTTPS proves that an address is serving a profile's hostname.
	HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (HTTPMetrics, error)
	// Download measures how much an address delivers within a byte and a time
	// limit, reserving from budget before it opens a connection.
	Download(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile, maxBytes int64, maxDuration time.Duration, budget ByteBudget) (DownloadMetrics, error)
}
