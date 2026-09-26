package prober

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mosdns-router/internal/candidate"
)

// A download is the only measurement in this package that spends the user's
// traffic, so it is the only one that reserves, and it is bounded three times
// over: by what the day's budget can pay for, by a byte limit, and by a time
// limit. The reader is the enforcement, not a hope about the server: it is asked
// for no more than the reservation allows and it is stopped at whichever of the
// two limits comes first.

const (
	// readBufferBytes is how much of a body is taken at a time. It is a
	// throughput compromise and nothing more: the byte limit is enforced by the
	// reader around it, and a smaller buffer would only cost syscalls.
	readBufferBytes = 64 << 10

	// maximumRedirects bounds a redirect chain inside the profile's own host. A
	// chain longer than this is not a CDN serving a client, it is a loop.
	maximumRedirects = 4
)

// Download measures how much a candidate's address delivers within a byte and a
// time limit, and charges the day's budget for what it really transferred.
//
// The order of the three things that matter here is fixed and each is load
// bearing. The reservation is persisted before a connection is opened, so a run
// that dies mid-transfer is still charged and the day's cap still holds. The body
// is read through a reader that cannot ask its source for a byte beyond what the
// reservation was granted, so a server that offers more does not get it and a
// budget that granted less than was asked for is not read past. And the transfer
// stops at whichever limit arrives first, so a slow candidate costs three seconds
// rather than the whole reservation.
//
// The identity is proved first, on the same terms the identity probe uses: a
// chain for the profile's hostname, a status the profile expects, and the headers
// it requires. What is deliberately not checked is the body digest, because a
// transfer reads the body only as far as its limits allow and a truncated body
// cannot have the digest of a whole one. The bytes are measured; the site they
// came from is proved by the handshake.
//
// What a failed call returns depends on how far it got. A refusal before the
// transfer started returns no metrics and charges nothing. A transfer that ended
// early returns the metrics for what it did read, and charges exactly that, so a
// caller can see what the failure cost.
func (p *NetworkProber) Download(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile, maxBytes int64, maxDuration time.Duration, budget ByteBudget) (DownloadMetrics, error) {
	if err := checkIdentityRequest(subject, profile); err != nil {
		return DownloadMetrics{}, err
	}
	// A transfer with no limit is the unbounded thing this project exists to
	// prevent, and a measurement of nothing while looking like a measurement is
	// worse than a refusal.
	switch {
	case maxBytes <= 0:
		return DownloadMetrics{}, fmt.Errorf("a transfer must be limited to at least one byte, got %d", maxBytes)
	case maxDuration <= 0:
		return DownloadMetrics{}, fmt.Errorf("a transfer must be limited to at least one moment, got %s", maxDuration)
	case budget == nil:
		return DownloadMetrics{}, errors.New("a transfer must reserve from a budget before it reads")
	}
	if profile.Method != "" && profile.Method != http.MethodGet {
		return DownloadMetrics{}, fmt.Errorf("a transfer measures a body, so it sends %s, not %s", http.MethodGet, profile.Method)
	}

	// From here the reservation is charged whatever happens. Everything below may
	// settle it with less, and nothing may settle it with more.
	reserved, err := budget.Reserve(maxBytes)
	if err != nil {
		return DownloadMetrics{}, err
	}

	probe, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()

	response, _, err := p.roundTrip(probe, subject, profile, redirectsWithin(profile))
	if err != nil {
		budget.Consume(reserved, 0)
		return DownloadMetrics{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if err := checkProfileResponse(profile, response); err != nil {
		// The identity was refused before a byte of the body was read, so nothing
		// was spent on the body and the whole reservation goes back.
		budget.Consume(reserved, 0)
		return DownloadMetrics{}, err
	}

	// Bounded by the reservation, not by the request. The two are the same number
	// for the shipped budget, which grants exactly what it is asked for, but the
	// interface does not promise that: a ByteBudget may hand back less than it was
	// asked for, and a reader bounded by the request would then transfer more than
	// the day paid for. The grant is what the budget will settle, so the grant is
	// what may be read.
	reader := newCountingReader(response.Body, reserved)
	started := time.Now()
	buffer := make([]byte, readBufferBytes)
	var readErr error
	for {
		_, err := reader.Read(buffer)
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		// The time limit is a measurement, not a failure: the transfer stopped
		// where the policy said it would, and what it delivered by then is a
		// result. The caller's own context is a different matter entirely.
		if ctxErr := ctx.Err(); ctxErr != nil {
			budget.Consume(reserved, reader.count)
			return DownloadMetrics{}, ctxErr
		}
		if probe.Err() != nil {
			break
		}
		readErr = err
		break
	}
	elapsed := time.Since(started)
	budget.Consume(reserved, reader.count)
	metrics := DownloadMetrics{Bytes: reader.count, Elapsed: elapsed, BytesPerSecond: bytesPerSecond(reader.count, elapsed)}
	if readErr != nil {
		return metrics, fmt.Errorf("the transfer from %s ended after %d bytes: %w", subject.IP, reader.count, readErr)
	}
	return metrics, nil
}

// countingReader reads at most a fixed number of bytes and counts what it took.
//
// The bound and the count are one thing here on purpose. A reader that limits and
// a counter that measures separately can disagree, and what they disagree about is
// exactly what the budget was asked to pay for. This one asks its source for no
// more than it may take, hands the source no more room than that either, and
// reports only what it actually received.
type countingReader struct {
	inner     io.Reader
	remaining int64
	count     int64
}

// newCountingReader returns a reader that will take at most limit bytes. A limit
// of zero or less is a reader that takes nothing, so a caller that computes a
// limit wrongly gets an empty transfer rather than an unlimited one.
func newCountingReader(inner io.Reader, limit int64) *countingReader {
	if limit < 0 {
		limit = 0
	}
	return &countingReader{inner: inner, remaining: limit}
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	// The buffer is shortened before the source is asked, so a source is never
	// given room to send a byte this reader may not keep.
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	read, err := r.inner.Read(buffer)
	r.remaining -= int64(read)
	r.count += int64(read)
	return read, err
}

// bytesPerSecond is the transfer's rate, and zero when no time passed: a rate
// built from a zero-length second is not a fast transfer, it is a division that
// was never defined.
func bytesPerSecond(count int64, elapsed time.Duration) float64 {
	if count <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
}

// redirectsWithin is the redirect policy of a transfer: a hop is followed only
// while it stays on the profile's own hostname, and only for a bounded number of
// hops.
//
// The reason is the same as for the identity probe, with one difference in what
// is allowed. A redirect to another host names a site this measurement is not
// about, and paying that site's bandwidth to find out what a candidate can do is
// exactly the spend the budget is for. A redirect that stays on the same name is
// the same site's own idea of where the payload is, so it is followed, and every
// hop of it completes its own certificate check for the same name.
func redirectsWithin(profile candidate.ProbeProfile) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= maximumRedirects {
			return fmt.Errorf("the response for %s redirects more than %d times", profile.Hostname, maximumRedirects)
		}
		if !strings.EqualFold(request.URL.Hostname(), profile.Hostname) {
			return fmt.Errorf("the response for %s redirects to %s, which is not the profile's host", profile.Hostname, request.URL.Host)
		}
		return nil
	}
}
