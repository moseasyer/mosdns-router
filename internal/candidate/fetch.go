package candidate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	// cacheSchemaVersion is the shape of a written cache. A cache carrying any
	// other version is not read, because this build cannot know what a document
	// of another version holds.
	cacheSchemaVersion = 1

	// maximumDocumentBytes bounds one official document. The Cloudflare and AWS
	// documents are tens of kilobytes; this is an envelope a hostile origin
	// cannot make the reader buffer past.
	maximumDocumentBytes = 1 << 20

	// userAgent identifies this project to the origins it reads, the same
	// string the list updater sends.
	userAgent = "mosdns-router"
)

// cacheDocument is what an official source writes under its injected cache path:
// the URL the bytes were read from, the validator that describes them, and the
// bytes themselves verbatim. The body is kept exactly as it arrived rather than
// re-encoded, so a revalidation compares the document the origin still has with
// the one that is stored.
type cacheDocument struct {
	SchemaVersion int             `json:"schema_version"`
	URL           string          `json:"url"`
	ETag          string          `json:"etag"`
	Body          json.RawMessage `json:"body"`
}

// fetchedDocument is one document a source read: the bytes, the URL they came
// from, the validator that describes them, and whether they came from the cache
// rather than from the origin.
//
// Pinned and Pin are the third source, which is neither: a document read from
// the snapshot a package ships. It is carried here rather than beside the reader
// so that the publication below can tell the three apart without being told,
// because the difference is a side effect -- a document standing in for the cache
// is already stored, and one standing in for a package's snapshot has to be
// written or the next offline run has nothing to stand in with.
type fetchedDocument struct {
	Body      []byte
	URL       string
	Validator string
	Stale     bool
	Pinned    bool
	Pin       PinnedSnapshot
}

// validatorPolicy is what a source expects of the origin it reads. There is one
// expectation left in this release: a document with no validator is refused before
// the body is read or stored. An API that documents a validator and sends none is
// not an API this build knows how to revalidate, and a stored copy of such a
// response could never be used again.
//
// It is a type rather than a boolean because a second source with a second
// expectation is a decision, not an accident, and until one exists the only
// honest shape is one value.
type validatorPolicy uint8

const (
	// validatorRequired refuses a response with no ETag before the body is read
	// or stored.
	validatorRequired validatorPolicy = iota
)

// fetchDocument returns the body of an official source document, revalidating
// against the cached copy when there is one.
//
// The cache path and the URL are both parameters: production passes its own, and
// a test passes a temporary directory, so nothing in this package can write
// outside the path it was handed. A cache that is missing, unreadable, of another
// version, written for another URL, or stored without a validator is simply not
// used: it is evidence about the document it was read from and about nothing else,
// and the run refetches.
//
// A transport failure or a status that is neither 200 nor 304 means the origin
// could not be read. That is not a document this build does not understand, it is
// no document at all, and the last one this build accepted stands in for it,
// marked stale. With nothing cached there is nothing to stand in and the failure
// is returned: a run that silently measured nothing is worse than a run that says
// it could not collect. A 304 that cannot be satisfied, for the same reason, is an
// error rather than an empty body, because a validator that revalidates nothing
// can only mean the cache was lost.
//
// Nothing is written here. A document is stored by storeDocument, once the caller
// has accepted it, so a body this build refuses never reaches the disk.
func fetchDocument(ctx context.Context, client *http.Client, sourceURL, cachePath string, policy validatorPolicy) (fetchedDocument, error) {
	cached, cachedOK := readCache(cachePath, sourceURL)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%s: build request: %w", sourceURL, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	if cachedOK {
		// readCache only accepts a document that carries a validator, so this is
		// never a bare conditional request. A request with an empty
		// If-None-Match is malformed, and a strict origin may answer 400.
		request.Header.Set("If-None-Match", cached.ETag)
	}

	response, err := client.Do(request)
	if err != nil {
		return staleInsteadOf(cached, cachedOK, sourceURL, fmt.Errorf("%s: %w", sourceURL, err))
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		if !cachedOK {
			return fetchedDocument{}, fmt.Errorf("%s: the origin answered 304 and no cached document is available", sourceURL)
		}
		return fetchedDocument{Body: cached.Body, URL: sourceURL, Validator: cached.ETag}, nil
	default:
		return staleInsteadOf(cached, cachedOK, sourceURL, fmt.Errorf("%s: unexpected status %d", sourceURL, response.StatusCode))
	}

	validator := response.Header.Get("ETag")
	if policy == validatorRequired && validator == "" {
		return fetchedDocument{}, fmt.Errorf("%s: the response carries no ETag to revalidate with", sourceURL)
	}
	if response.ContentLength > maximumDocumentBytes {
		return fetchedDocument{}, fmt.Errorf("%s: the document declares %d bytes, larger than the %d byte bound", sourceURL, response.ContentLength, maximumDocumentBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumDocumentBytes+1))
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%s: read document: %w", sourceURL, err)
	}
	if len(body) > maximumDocumentBytes {
		return fetchedDocument{}, fmt.Errorf("%s: the document is larger than the %d byte bound", sourceURL, maximumDocumentBytes)
	}
	return fetchedDocument{Body: body, URL: sourceURL, Validator: validator}, nil
}

// staleInsteadOf turns a failure to read the origin into the cached document
// marked stale, when there is one to use. With no cache the cause is returned
// unchanged, so the caller still learns why the run could not collect.
func staleInsteadOf(cached cacheDocument, cachedOK bool, sourceURL string, cause error) (fetchedDocument, error) {
	if !cachedOK {
		return fetchedDocument{}, cause
	}
	return fetchedDocument{Body: cached.Body, URL: sourceURL, Validator: cached.ETag, Stale: true}, nil
}

// storeDocument records a freshly read document under the injected path, once the
// caller has accepted it. A stale document is already stored, and a document with
// no validator is not stored at all: readCache would refuse it on the next run, so
// the file could never be used for anything and would only be there to be
// distrusted.
//
// A document read from a package's pinned snapshot is stored even though it is
// stale, and that is the one exception here with a reason rather than a
// workaround. "Stale" normally means "this is the document that was already in the
// cache, and the cache is where it lives", so there is nothing to write; a pin's
// document has never been stored anywhere on this machine, and the publication
// this call belongs to exists precisely so that it is. Writing it is also what
// makes the next offline run a cache stand-in rather than a second read of the
// package's own copy, so a pin is consulted once per machine rather than once per
// install.
func storeDocument(cachePath string, fetched fetchedDocument) error {
	if (fetched.Stale && !fetched.Pinned) || fetched.Validator == "" {
		return nil
	}
	return writeCache(cachePath, cacheDocument{
		SchemaVersion: cacheSchemaVersion,
		URL:           fetched.URL,
		ETag:          fetched.Validator,
		Body:          fetched.Body,
	})
}

// readCache returns the cached document for exactly this source URL, and reports
// false for anything it cannot use. A document stored without a validator is one
// of those: there would be nothing to revalidate with, and a conditional request
// carrying an empty validator is malformed. A cache this build cannot read is
// replaced by the next run rather than trusted, and a read failure is not fatal:
// the run that follows writes to the same path and reports the write error if the
// path really is unusable.
func readCache(cachePath, sourceURL string) (cacheDocument, bool) {
	document, ok := readAnyCache(cachePath)
	if !ok || document.URL != sourceURL {
		return cacheDocument{}, false
	}
	return document, true
}

// readAnyCache returns the cached document at a path for whatever endpoint it
// records, and reports false for anything it cannot use. It is readCache without
// the endpoint check, and it exists so the report that names the two published
// artifacts applies the same gates this build applies to a cache it is about to
// revalidate against: a second set of weaker rules here would report a document
// as published that the next fetch would refuse to use, which is the one thing a
// report about a start requirement must not do.
func readAnyCache(cachePath string) (cacheDocument, bool) {
	document, err := readEnvelopeFile(cachePath)
	if err != nil {
		return cacheDocument{}, false
	}
	return document, true
}

// readEnvelopeFile reads one envelope and reports why it cannot be used, so the
// reader that has to explain a refusal and the reader that only wants to know
// whether to revalidate apply one set of gates to one set of bytes.
//
// The gates are exactly readAnyCache's, which is why this is the function the
// boolean is built from rather than a second implementation beside it: a snapshot
// a package ships is a cache document, and a reader that held it to weaker rules
// than a cache would accept a pinned file that the very next revalidation
// discarded.
func readEnvelopeFile(path string) (cacheDocument, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return cacheDocument{}, fmt.Errorf("%s: read: %w", path, err)
	}
	document := cacheDocument{}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return cacheDocument{}, fmt.Errorf("%s: decode: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cacheDocument{}, fmt.Errorf("%s: the document carries trailing content", path)
	}
	if document.SchemaVersion != cacheSchemaVersion {
		return cacheDocument{}, fmt.Errorf("%s: the cache is schema version %d, and this build reads version %d",
			path, document.SchemaVersion, cacheSchemaVersion)
	}
	if document.ETag == "" {
		return cacheDocument{}, fmt.Errorf("%s: the cache records no validator, so there would be nothing to revalidate with", path)
	}
	if len(document.Body) == 0 || !json.Valid(document.Body) {
		return cacheDocument{}, fmt.Errorf("%s: the cache records no document", path)
	}
	return document, nil
}

// writeCache stores one document under the injected path, creating the directory
// when it is missing and replacing the file through a temporary name in the same
// directory, so a reader never sees a half-written document and a crash never
// leaves a stray one behind.
func writeCache(cachePath string, document cacheDocument) error {
	contents, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("%s: encode cache: %w", cachePath, err)
	}
	contents = append(contents, '\n')
	directory := filepath.Dir(cachePath)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("%s: create %s: %w", cachePath, directory, err)
	}
	handle, err := os.CreateTemp(directory, filepath.Base(cachePath)+".*")
	if err != nil {
		return fmt.Errorf("%s: create a temporary file in %s: %w", cachePath, directory, err)
	}
	temporary := handle.Name()
	if err := storeCacheFile(handle, temporary, cachePath, contents); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, cachePath); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("%s: replace the cache: %w", cachePath, err)
	}
	return nil
}

func storeCacheFile(handle *os.File, temporary, cachePath string, contents []byte) error {
	if _, err := handle.Write(contents); err != nil {
		_ = handle.Close()
		return fmt.Errorf("%s: write %s: %w", cachePath, temporary, err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("%s: sync %s: %w", cachePath, temporary, err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("%s: close %s: %w", cachePath, temporary, err)
	}
	// The cached document is published reference data, not a secret, and the
	// reader in the other half of this project runs as an unprivileged user.
	if err := os.Chmod(temporary, 0o644); err != nil {
		return fmt.Errorf("%s: set the mode of %s: %w", cachePath, temporary, err)
	}
	return nil
}
