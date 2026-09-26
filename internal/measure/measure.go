// Package measure holds the numbers a probe reports, and nothing else.
//
// These three types are data. A prober fills them in and a scorer reads them,
// and a scorer that had to import the prober to name a measurement would make
// the prober's own tests unable to use the scorer: an in-package test file
// cannot import a package that imports the one under test, so
// internal/prober's tests reach for internal/optimizer, and a type declared
// here rather than in the prober is what lets both hold at once.
//
// The prober keeps the names. prober.TCPMetrics, prober.HTTPMetrics and
// prober.DownloadMetrics are aliases for the types below, so the declaration a
// caller reads and writes is unchanged and the two spellings are the same type
// rather than two types that have to be converted. The definitions, including
// every field's meaning, are here; the prober's copies of the comments say only
// where the type now lives.
package measure

import "time"

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
