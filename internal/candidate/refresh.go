package candidate

// The response rewriter's prefix list is a hard start requirement: the plugin
// refuses to construct without it. It was produced only as a side effect of a
// measurement run's own fetch, which is the wrong shape for a requirement like
// that -- a fresh installation had to spend the day's bandwidth budget, and every
// candidate the run measured with, to obtain a file the router cannot start
// without. This file is the other half of that publication, taken out of the
// sampling path: `Refresh` publishes the same two artifacts from the same one
// document and does nothing else, and `ReadPublished` reports what is on disk
// without reaching the network, so a report-only mode can say whether the
// requirement is met.
//
// The two entry points share `read` and `publish`, so "one fetch, two artifacts,
// from one in-memory document" is a property of the code's shape rather than of
// two implementations agreeing by hand.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// RangeRefresh is what one refresh of the published ranges produced: the two
// files it wrote, the document they both came from, and how many prefixes the
// list holds.
//
// The fields are the report an operator reads after an install, so a run that
// published a stale document says so here rather than looking identical to one
// that reached the origin. Stale is that flag.
type RangeRefresh struct {
	// URL is the endpoint the document came from, and ETag the validator that
	// describes it. Both are the fetch's own, not a re-read of the cache file.
	URL  string
	ETag string
	// Prefixes is how many prefixes the published list holds, after the
	// deduplication and masking the render does.
	Prefixes int
	// Stale reports that the origin could not be read and the last document this
	// build accepted stands in for it.
	Stale bool
	// CachePath and PrefixPath are the two files this refresh wrote.
	CachePath  string
	PrefixPath string
}

// Refresh reads the published Cloudflare range document and publishes the two
// artifacts a run of this router needs: the cache envelope beside the injected
// cache path, and the plain prefix list the response rewriter reads.
//
// It is deliberately the fetch half of Candidates with the sampling removed. No
// socket is opened to any candidate address, no prober is built, and no
// bandwidth budget is touched, so it can run at install time without spending the
// day an optimiser run needs. What it does share with Candidates is everything
// that decides *which* document gets published: the same revalidation against the
// same cache, the same parse, the same refusals, and the same render -- see read
// and publish. A refresh therefore publishes byte-for-byte what a measurement run
// of the same document would have published, which is the property that makes it
// substitutable for one.
//
// When the origin cannot be read at all, the last document this build accepted
// stands in for it and Stale reports that, exactly as it does for a sample. A
// refresh that failed would leave the rewriter with no list, and the plugin's
// refusal to construct without one turns that into a router that will not start.
func (s *HTTPCloudflareSource) Refresh(ctx context.Context) (RangeRefresh, error) {
	document, fetched, err := s.read(ctx)
	if err != nil {
		return RangeRefresh{}, err
	}
	prefixes, err := s.publish(document, fetched)
	if err != nil {
		return RangeRefresh{}, err
	}
	return RangeRefresh{
		URL:        fetched.URL,
		ETag:       fetched.Validator,
		Prefixes:   prefixes,
		Stale:      fetched.Stale,
		CachePath:  s.cachePath,
		PrefixPath: prefixPathFor(s.cachePath),
	}, nil
}

// read fetches the range document and validates it, writing nothing.
//
// It is the half of both entry points that decides which document they will
// publish, so it is also the half that has to be shared: a refresh that parsed
// more loosely than a sample would publish a list a measurement run would have
// refused, and a router classifying against ranges this build does not understand
// is worse than one that classifies against nothing.
func (s *HTTPCloudflareSource) read(ctx context.Context) (cloudflareRanges, fetchedDocument, error) {
	fetched, err := fetchDocument(ctx, s.client, s.baseURL, s.cachePath, validatorRequired)
	if err != nil {
		return cloudflareRanges{}, fetchedDocument{}, err
	}
	document, err := parseCloudflareDocument(s.baseURL, fetched.Body)
	if err != nil {
		// A body that arrived and does not parse is a hard error, stale or not:
		// the cache is not quietly substituted for a document this build does not
		// understand.
		return cloudflareRanges{}, fetchedDocument{}, err
	}
	return document, fetched, nil
}

// publish writes both artifacts of one accepted document and reports how many
// prefixes the list holds.
//
// The two files are one publication, so the order is chosen so a refusal leaves
// neither half behind: the list is rendered first, and only a document that
// renders is stored and written. Storing first would leave an envelope in the
// cache describing a document the render then refused, and the next run would
// revalidate against it and be told the origin published ranges this build
// cannot use.
//
// The envelope is stored only because the document was accepted, so the cache
// never holds a body a caller refused, and a stale document is already stored. The
// list is rendered from the document in memory rather than read back from the
// envelope, so the two files can never describe different documents, and it costs
// no second request.
//
// The count is the list's own, after deduplication and masking, because that is
// what a reader of the file will find in it.
func (s *HTTPCloudflareSource) publish(document cloudflareRanges, fetched fetchedDocument) (int, error) {
	contents, err := renderPrefixList(document)
	if err != nil {
		return 0, err
	}
	if err := storeDocument(s.cachePath, fetched); err != nil {
		return 0, err
	}
	return countPrefixLines(contents), writeTextFile(prefixPathFor(s.cachePath), contents)
}

// PublishedRanges is what the two published range artifacts on disk hold.
//
// It is a report of a filesystem, not a claim about an origin: nothing here
// reaches the network, so a daily check can state the requirement's status
// without a request it would have nothing to do with.
type PublishedRanges struct {
	// Present reports that both artifacts are there and readable. It says
	// nothing about whether they agree.
	Present bool
	// Consistent reports that the prefix list is exactly what this build would
	// publish from the document the envelope records. The two files are each
	// replaced by a rename and are never half-written, so they cannot disagree
	// because of a crash -- they can only disagree because something else wrote
	// one of them, and a rewriter classifying against a list its neighbour does
	// not describe is exactly the state this flag exists to make visible.
	Consistent bool
	// URL and ETag are the envelope's own record of where the document came from.
	URL  string
	ETag string
	// Prefixes and SHA256 describe the published prefix list as it is, not as the
	// envelope would render it, because the list is the file a running router
	// reads and the envelope is a cache beside it.
	Prefixes int
	SHA256   string
	// CachePath and PrefixPath are the two files this report is about.
	CachePath  string
	PrefixPath string
	// Missing names the artifact that is not there, and is empty when both are.
	// The prefix list is named first: it is the one the plugin refuses to start
	// without, so a report that had to choose should name the load-bearing one.
	Missing string
}

// ReadPublished reports the two artifacts a refresh publishes, reading only the
// filesystem.
//
// It refuses on a path it cannot read at all, which is a different thing from a
// path holding nothing: an unreadable path is a question this report cannot
// answer, while an absent or unusable artifact is an answer, and a report-only
// mode has to be able to state the answer without failing.
func ReadPublished(cachePath string) (PublishedRanges, error) {
	published := PublishedRanges{
		CachePath:  cachePath,
		PrefixPath: prefixPathFor(cachePath),
	}
	list, err := os.ReadFile(published.PrefixPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return PublishedRanges{}, fmt.Errorf("%s: read the published prefix list: %w", published.PrefixPath, err)
		}
		published.Missing = published.PrefixPath
		return published, nil
	}
	cached, ok := readAnyCache(cachePath)
	if !ok {
		published.Missing = cachePath
		return published, nil
	}
	published.Present = true
	published.URL = cached.URL
	published.ETag = cached.ETag
	published.SHA256 = digestOf(list)
	published.Prefixes = countPrefixLines(list)
	// A body this build cannot parse leaves the consistency question open rather
	// than answered either way: the envelope is a cache, and a cache holding a
	// document of another shape says nothing about what the list beside it
	// describes. Reporting it as consistent would be a claim nobody checked.
	document, err := parseCloudflareDocument(cached.URL, cached.Body)
	if err != nil {
		return published, nil
	}
	rendered, err := renderPrefixList(document)
	if err != nil {
		return published, nil
	}
	published.Consistent = string(rendered) == string(list)
	return published, nil
}

// countPrefixLines is how many prefixes a list holds.
//
// Every line the renderer writes ends in a newline, so counting them is exact; a
// file somebody edited by hand may not end in one, and a last line without its
// newline is still a line. An empty file is zero prefixes rather than one empty
// one, which is what makes "the document names no IPv4 range" and "the list is
// empty" the same reportable state.
func countPrefixLines(contents []byte) int {
	if len(contents) == 0 {
		return 0
	}
	lines := bytes.Count(contents, []byte{'\n'})
	if contents[len(contents)-1] != '\n' {
		lines++
	}
	return lines
}

func digestOf(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
