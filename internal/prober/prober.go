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
	"mosdns-router/internal/measure"
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

// The three metric types are declared in internal/measure, and named here as
// aliases, so the declaration a caller reads and writes is unchanged. They are
// data rather than prober behaviour, and a scorer has to be able to name them
// without importing this package: an in-package test file cannot import a
// package that imports the one under test, so these tests reach for
// internal/optimizer, and the optimizer scores what these types carry. An alias
// rather than a redefinition is what keeps the two spellings one type, so a
// value built as prober.TCPMetrics can be assigned to a field declared as
// measure.TCPMetrics with no conversion.
type (
	// TCPMetrics is what one address's connect latency looked like. See
	// measure.TCPMetrics for the fields and what each one means.
	TCPMetrics = measure.TCPMetrics
	// HTTPMetrics is what one address proved about itself over a verified TLS
	// connection. See measure.HTTPMetrics for the fields and what each one means.
	HTTPMetrics = measure.HTTPMetrics
	// DownloadMetrics is what one address actually delivered, and what it cost.
	// See measure.DownloadMetrics for the fields and what each one means.
	DownloadMetrics = measure.DownloadMetrics
)

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
