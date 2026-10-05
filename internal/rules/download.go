package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	// Repository is the only source this gateway converts. It is not a
	// parameter: a caller cannot redirect a pin at another repository, and the
	// archive URL is derived from this value and the pinned commit.
	Repository = "v2fly/domain-list-community"

	// Entry is the list inside that repository this gateway publishes: the
	// China domain set.
	Entry = "data/cn"

	// schemaVersion is the shape of a written lock. A lock carrying any other
	// version is refused rather than interpreted.
	schemaVersion = 1

	// apiBaseURL and archiveBaseURL are fixed GitHub endpoints. Neither the
	// repository nor the host is caller-controlled.
	apiBaseURL     = "https://api.github.com"
	archiveBaseURL = "https://codeload.github.com"

	// maxArchiveFileBytes bounds one file inside a source archive, and
	// maxArchiveBytes bounds the archive body and its total uncompressed
	// content. A reviewed source archive is a few hundred kilobytes; these are
	// envelopes a hostile origin cannot make the pin buffer past.
	maxArchiveFileBytes = 4 << 20
	maxArchiveBytes     = 64 << 20

	// maxArchiveFiles bounds the entries of a source archive, so an archive of
	// tiny entries cannot make extraction do unbounded work.
	maxArchiveFiles = 32768

	// maxCommitDocumentBytes bounds the commit document this package reads one
	// field out of. A commit with a long file list is a few kilobytes.
	maxCommitDocumentBytes = 1 << 20
)

// SourceLock records the reviewed upstream source of a published list, so a
// later update can be compared against it and a reader can tell exactly which
// bytes produced the list it is running.
type SourceLock struct {
	// SchemaVersion is the shape of this document.
	SchemaVersion int `json:"schema_version"`
	// Repository is the only source this gateway accepts, recorded so a lock is
	// self-describing.
	Repository string `json:"repository"`
	// Commit is the reviewed 40-hex commit id.
	Commit string `json:"commit"`
	// SHA256 is the digest of the source archive for that commit.
	SHA256 string `json:"sha256"`
	// ListSHA256 is the digest of the published list bytes this lock describes.
	ListSHA256 string `json:"list_sha256"`
	// Entry is the list inside the repository that was converted.
	Entry string `json:"entry"`
}

// Encode renders the lock as the exact bytes a lock file holds. The field order
// is the struct's, so the same lock always renders the same document.
func (l SourceLock) Encode() ([]byte, error) {
	var rendered bytes.Buffer
	encoder := json.NewEncoder(&rendered)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(l); err != nil {
		return nil, fmt.Errorf("encode source lock: %w", err)
	}
	return rendered.Bytes(), nil
}

// ParseSourceLock decodes a lock document. An unknown field, a second document
// and any malformed JSON are refused: a lock is the record of what was reviewed,
// so a field this build does not understand must not be quietly dropped while
// the document still reads as a complete pin.
func ParseSourceLock(data []byte) (SourceLock, error) {
	lock := SourceLock{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return SourceLock{}, fmt.Errorf("decode source lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SourceLock{}, errors.New("decode source lock: trailing data after the document")
	}
	return lock, nil
}

// Validate reports whether a published lock is complete. It is used when a lock
// on disk is about to be replaced or compared, never as an input filter.
func (l SourceLock) Validate() error {
	if err := l.validatePinnedSource(); err != nil {
		return err
	}
	if !isLowerHex(l.ListSHA256, 64) {
		return fmt.Errorf("list_sha256 %q is not a 64 character lower-case hex digest", l.ListSHA256)
	}
	return nil
}

// validatePinnedSource checks everything a download needs to trust an archive
// except the list digest: a lock that has not been converted yet has no list
// digest, and the download is what produces it.
func (l SourceLock) validatePinnedSource() error {
	if l.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema_version %d is not the supported version %d", l.SchemaVersion, schemaVersion)
	}
	if l.Repository != Repository {
		return fmt.Errorf("repository %q is not the reviewed source %q", l.Repository, Repository)
	}
	if !isLowerHex(l.Commit, 40) {
		return fmt.Errorf("commit %q is not a 40 character lower-case hex commit id", l.Commit)
	}
	if !isLowerHex(l.SHA256, 64) {
		return fmt.Errorf("sha256 %q is not a 64 character lower-case hex digest", l.SHA256)
	}
	if l.Entry != Entry {
		return fmt.Errorf("entry %q is not the reviewed list %q", l.Entry, Entry)
	}
	return nil
}

// ResolveCommit resolves the commit the repository publishes for ref, and returns a
// lock pinned to it with no digests: it has read a commit, not an archive.
//
// An empty ref or the literal HEAD is the repository's current default-branch commit,
// read through the fixed GitHub API endpoint -- one request, so a check that finds the
// locked commit unchanged never downloads an archive at all.
//
// A full 40-character commit is that commit, and costs NO request. That is not only
// cheaper: it is what makes a rollback possible on a machine that can reach the archive
// host but not the API, which is a machine that cannot answer "what is HEAD today" and
// so cannot be told where to go back to. The commit names itself, and the archive
// fetch that follows is what refuses it if the repository has never published it.
//
// Anything else -- a branch, a tag, an abbreviated commit, HEAD~1 -- is refused here.
// A ref names a moving target or a form this package does not verify, and the lock
// records a commit: accepting one would put something in the lock that is not the
// thing the lock says it is.
func ResolveCommit(ctx context.Context, client *http.Client, repository, ref string) (SourceLock, error) {
	if repository != Repository {
		return SourceLock{}, fmt.Errorf("repository %q is not the reviewed source %q", repository, Repository)
	}
	if client == nil {
		return SourceLock{}, errors.New("an HTTP client is required to resolve the remote commit")
	}
	if named, ok := normalizeCommitRef(ref); ok {
		return SourceLock{
			SchemaVersion: schemaVersion,
			Repository:    Repository,
			Commit:        named,
			Entry:         Entry,
		}, nil
	}
	endpoint := apiBaseURL + "/repos/" + Repository + "/commits/HEAD"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SourceLock{}, fmt.Errorf("%s: build request: %w", endpoint, err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "mosdns-router")

	response, err := client.Do(request)
	if err != nil {
		return SourceLock{}, fmt.Errorf("%s: %w", endpoint, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return SourceLock{}, fmt.Errorf("%s: unexpected status %d", endpoint, response.StatusCode)
	}
	if response.ContentLength > maxCommitDocumentBytes {
		return SourceLock{}, fmt.Errorf("%s: commit document declares %d bytes, which is larger than the %d byte limit", endpoint, response.ContentLength, maxCommitDocumentBytes)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maxCommitDocumentBytes+1))
	if err != nil {
		return SourceLock{}, fmt.Errorf("%s: read commit document: %w", endpoint, err)
	}
	if len(document) > maxCommitDocumentBytes {
		return SourceLock{}, fmt.Errorf("%s: commit document is larger than the %d byte limit", endpoint, maxCommitDocumentBytes)
	}

	// The document carries the whole commit; only the sha is read from it.
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(document, &commit); err != nil {
		return SourceLock{}, fmt.Errorf("%s: decode commit document: %w", endpoint, err)
	}
	if !isLowerHex(commit.SHA, 40) {
		return SourceLock{}, fmt.Errorf("%s: commit document has no 40 character lower-case hex sha, got %q", endpoint, commit.SHA)
	}
	return SourceLock{
		SchemaVersion: schemaVersion,
		Repository:    Repository,
		Commit:        commit.SHA,
		Entry:         Entry,
	}, nil
}

// ResolvePinned resolves ref and downloads that commit's source archive to compute
// the archive digest, which is what a lock has to record before the archive can be
// verified. The returned lock has no list digest: nothing has been converted yet.
//
// The digest is recorded HERE rather than left to Download so that it is the digest of
// the archive this run read, not of one a later run reads. A lock whose digest is
// computed during the download it is verifying is a lock that verifies nothing: the
// archive it is checked against is whatever arrived.
func ResolvePinned(ctx context.Context, client *http.Client, repository, ref string) (SourceLock, error) {
	resolved, err := ResolveCommit(ctx, client, repository, ref)
	if err != nil {
		return SourceLock{}, err
	}
	archive, err := fetchArchive(ctx, client, resolved)
	if err != nil {
		return SourceLock{}, err
	}
	resolved.SHA256 = digestHex(archive)
	return resolved, nil
}

// ResolveHEAD resolves the repository's current default-branch commit and its archive
// digest. It is ResolvePinned with no ref, and it is named separately because the two
// callers mean different things by it: the drift check is asking "has upstream moved
// on from what this machine pinned", and a pin naming a commit is asking for that
// commit. Only the first is a question about now.
func ResolveHEAD(ctx context.Context, client *http.Client, repository string) (SourceLock, error) {
	return ResolvePinned(ctx, client, repository, "")
}

// normalizeCommitRef reports the commit ref names, and whether it named one at all.
//
// It repeats the shape ParseSourceLock requires of a commit rather than exporting that
// check, because that one answers a different question -- "is this string usable as a
// commit in a lock" -- and a ref that has passed it has not been validated as a ref.
func normalizeCommitRef(ref string) (string, bool) {
	trimmed := strings.TrimSpace(ref)
	if len(trimmed) != 40 {
		return "", false
	}
	for index := 0; index < len(trimmed); index++ {
		if !strings.ContainsRune("0123456789abcdef", rune(trimmed[index])) {
			return "", false
		}
	}
	return trimmed, true
}

// Download fetches the source archive of a fully pinned lock, verifies its
// digest before a byte of it is extracted, converts the pinned entry, and
// returns the lock extended with the digest of the exact list bytes it
// produced. A failure at any step returns no lock and no list, so a caller
// cannot mistake a partial update for a pin.
func Download(ctx context.Context, client *http.Client, lock SourceLock) (SourceLock, []byte, error) {
	if err := lock.validatePinnedSource(); err != nil {
		return SourceLock{}, nil, fmt.Errorf("source lock: %w", err)
	}
	if client == nil {
		return SourceLock{}, nil, errors.New("an HTTP client is required to download the source archive")
	}
	archive, err := fetchArchive(ctx, client, lock)
	if err != nil {
		return SourceLock{}, nil, err
	}
	if actual := digestHex(archive); actual != lock.SHA256 {
		return SourceLock{}, nil, fmt.Errorf("archive sha256 %s does not match the pinned %s", actual, lock.SHA256)
	}
	fsys, err := extractArchive(archive, lock.Commit)
	if err != nil {
		return SourceLock{}, nil, err
	}
	expressions, err := ConvertFS(fsys, lock.Entry)
	if err != nil {
		return SourceLock{}, nil, fmt.Errorf("convert %s at %s: %w", Repository, lock.Commit, err)
	}
	list := renderList(expressions)
	pinned := lock
	pinned.ListSHA256 = digestHex(list)
	return pinned, list, nil
}

// renderList renders converted expressions as the exact bytes a list file
// holds: one expression per line, each line terminated.
func renderList(expressions []string) []byte {
	var rendered bytes.Buffer
	for _, expression := range expressions {
		rendered.WriteString(expression)
		rendered.WriteByte('\n')
	}
	return rendered.Bytes()
}

// fetchArchive downloads the source archive of a lock's commit from the fixed
// codeload endpoint, enforcing the download bound before and while reading.
func fetchArchive(ctx context.Context, client *http.Client, lock SourceLock) ([]byte, error) {
	endpoint := archiveBaseURL + "/" + Repository + "/tar.gz/" + lock.Commit
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", endpoint, err)
	}
	request.Header.Set("Accept", "application/gzip")
	request.Header.Set("User-Agent", "mosdns-router")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %d", endpoint, response.StatusCode)
	}
	if response.ContentLength > maxArchiveBytes {
		return nil, fmt.Errorf("%s: archive declares %d bytes, which is larger than the %d byte limit", endpoint, response.ContentLength, maxArchiveBytes)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read archive: %w", endpoint, err)
	}
	if len(archive) > maxArchiveBytes {
		return nil, fmt.Errorf("%s: archive is larger than the %d byte limit", endpoint, maxArchiveBytes)
	}
	return archive, nil
}

// extractArchive unpacks a source archive into a read-only in-memory
// filesystem rooted at the archive's single top-level directory, which is the
// one named after the repository and the pinned commit. Anything that is not a
// regular file, any path that could reach outside the archive, and any archive
// above the size or entry bounds are refused: an archive is untrusted input.
func extractArchive(archive []byte, commit string) (fs.FS, error) {
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open source archive: %w", err)
	}
	defer func() { _ = reader.Close() }()

	files := make(map[string][]byte)
	tarReader := tar.NewReader(reader)
	root := archiveRoot(commit)
	prefix := root + "/"
	var total int64
	for entries := 0; ; entries++ {
		if entries >= maxArchiveFiles {
			return nil, fmt.Errorf("source archive holds more than %d entries", maxArchiveFiles)
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read source archive: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			// A GitHub source archive opens with a PAX global header that names
			// itself and carries no file of the repository.
			continue
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
			if name == "" {
				continue
			}
		}
		if !fs.ValidPath(name) || name != path.Clean(name) {
			return nil, fmt.Errorf("unsafe archive path %q", header.Name)
		}
		if name == root {
			// The archive's own top-level directory, which holds the repository.
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			return nil, fmt.Errorf("archive entry %q is not inside the %q top-level directory", header.Name, root)
		}
		relative := strings.TrimPrefix(name, prefix)
		if relative == "" {
			continue
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			if header.Size > maxArchiveFileBytes {
				return nil, fmt.Errorf("archive entry %q is %d bytes, larger than the %d byte limit", header.Name, header.Size, maxArchiveFileBytes)
			}
			total += header.Size
			if total > maxArchiveBytes {
				return nil, fmt.Errorf("archive holds more than the %d bytes of uncompressed content limit", maxArchiveBytes)
			}
			contents, err := io.ReadAll(io.LimitReader(tarReader, header.Size))
			if err != nil {
				return nil, fmt.Errorf("read archive entry %q: %w", header.Name, err)
			}
			files[relative] = contents
		default:
			return nil, fmt.Errorf("unsupported archive entry type %d for %q", header.Typeflag, header.Name)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("source archive holds no files under the %q top-level directory", root)
	}
	return &archiveFS{files: files}, nil
}

// archiveRoot is the single top-level directory a GitHub source archive for a
// commit is named after. Requiring it proves the archive is the repository at
// the pinned commit, so a substituted or repacked archive is refused.
func archiveRoot(commit string) string {
	return "domain-list-community-" + commit
}

// archiveFS is a read-only filesystem over the files a source archive held.
type archiveFS struct {
	files map[string][]byte
}

func (a *archiveFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	contents, ok := a.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &archiveFile{name: name, Reader: bytes.NewReader(contents)}, nil
}

// archiveFile is one file of an archiveFS.
type archiveFile struct {
	name string
	*bytes.Reader
}

func (f *archiveFile) Stat() (fs.FileInfo, error) {
	return archiveFileInfo{name: f.name, size: f.Size()}, nil
}

func (f *archiveFile) Close() error { return nil }

// archiveFileInfo describes an archiveFile to a caller that stats it.
type archiveFileInfo struct {
	name string
	size int64
}

func (i archiveFileInfo) Name() string       { return path.Base(i.name) }
func (i archiveFileInfo) Size() int64        { return i.size }
func (i archiveFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i archiveFileInfo) ModTime() time.Time { return time.Time{} }
func (i archiveFileInfo) IsDir() bool        { return false }
func (i archiveFileInfo) Sys() any           { return nil }

// digestHex returns the lowercase hex SHA-256 of b, which is the shape a lock
// records and a pinned download requires.
func digestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isLowerHex reports whether value is exactly length lower-case hex characters.
// Upper case, short, long and non-hex values are all refused: a digest or commit
// id is compared as bytes, so a different spelling of the same value would
// silently never match.
func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
