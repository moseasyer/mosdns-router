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

// fetchedDocument is one document a source read, with the validator that
// describes it. An origin that offers no validator yields an empty one: the
// document is still stored, so a later run can read it, but there is nothing to
// revalidate with and nothing is sent.
type fetchedDocument struct {
	Body      []byte
	Validator string
}

// fetchDocument returns the body of an official source document, revalidating
// against the cached copy when there is one.
//
// The cache path and the URL are both parameters: production passes its own, and
// a test passes a temporary directory, so nothing in this package can write
// outside the path it was handed. A cache that is missing, unreadable, of another
// version, or written for another URL is simply not used: it is evidence about
// the document it was read from and about nothing else, and the run refetches.
//
// A 304 with no usable cache is an error rather than an empty body, because a
// validator that revalidates nothing can only mean the cache was lost.
func fetchDocument(ctx context.Context, client *http.Client, sourceURL, cachePath string) (fetchedDocument, error) {
	cached, cachedOK := readCache(cachePath, sourceURL)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%s: build request: %w", sourceURL, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	if cachedOK {
		request.Header.Set("If-None-Match", cached.ETag)
	}

	response, err := client.Do(request)
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%s: %w", sourceURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		if !cachedOK {
			return fetchedDocument{}, fmt.Errorf("%s: the origin answered 304 and no cached document is available", sourceURL)
		}
		return fetchedDocument{Body: cached.Body, Validator: cached.ETag}, nil
	default:
		return fetchedDocument{}, fmt.Errorf("%s: unexpected status %d", sourceURL, response.StatusCode)
	}

	validator := response.Header.Get("ETag")
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
	if err := writeCache(cachePath, cacheDocument{SchemaVersion: cacheSchemaVersion, URL: sourceURL, ETag: validator, Body: body}); err != nil {
		return fetchedDocument{}, err
	}
	return fetchedDocument{Body: body, Validator: validator}, nil
}

// readCache returns the cached document for exactly this source URL, and reports
// false for anything it cannot use, including a document cached with no
// validator: there would be nothing to revalidate with. A cache this build cannot
// read is replaced by the next run rather than trusted, and a read failure is not
// fatal: the run that follows writes to the same path and reports the write error
// if the path really is unusable.
func readCache(cachePath, sourceURL string) (cacheDocument, bool) {
	contents, err := os.ReadFile(cachePath)
	if err != nil {
		return cacheDocument{}, false
	}
	document := cacheDocument{}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return cacheDocument{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cacheDocument{}, false
	}
	if document.SchemaVersion != cacheSchemaVersion || document.URL != sourceURL {
		return cacheDocument{}, false
	}
	if len(document.Body) == 0 || !json.Valid(document.Body) {
		return cacheDocument{}, false
	}
	return document, true
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
