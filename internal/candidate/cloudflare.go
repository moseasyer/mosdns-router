package candidate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"
)

const (
	// DefaultCloudflareBaseURL is the Cloudflare IP API this release reads. It
	// is a parameter of every source so a test can point one at a local server;
	// an empty value means this endpoint.
	DefaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4/ips"

	// DefaultCloudflareCachePath is where the production router keeps the
	// document it read. It is a parameter too, so a test never writes here.
	DefaultCloudflareCachePath = "/var/lib/mosdns/lists/cloudflare-ips.json"

	// maximumDocumentBlocks bounds how many /24 blocks one document may cover.
	// The published Cloudflare space is about six thousand blocks; this is a
	// generous envelope that still stops one wide range from making the sample
	// walk millions of blocks before the limit chooses from them.
	maximumDocumentBlocks = 1 << 18

	// localDateLayout is the calendar date the daily sample is seeded with, in
	// the location the caller injected the date in.
	localDateLayout = "2006-01-02"

	// sampleHostAddresses is how many host addresses of a block a sample may
	// choose from: everything except the network and broadcast addresses.
	sampleHostAddresses = 254
)

// CloudflareSource is the global candidate source. It takes the limit to honour
// and the local date to seed the sample with, both from the caller, so a run is
// reproducible and no clock is read here.
type CloudflareSource interface {
	Candidates(ctx context.Context, limit int, localDate time.Time) ([]Candidate, error)
}

// HTTPCloudflareSource reads the Cloudflare IP API over HTTP and keeps the
// document it read under an injected cache path.
type HTTPCloudflareSource struct {
	client    *http.Client
	baseURL   string
	cachePath string
}

var _ CloudflareSource = (*HTTPCloudflareSource)(nil)

// NewCloudflareSource returns a source for the Cloudflare IP ranges. An empty
// base URL means DefaultCloudflareBaseURL and an empty cache path means
// DefaultCloudflareCachePath; the client is required, so a caller cannot
// accidentally reach the network with a default transport it did not choose.
func NewCloudflareSource(client *http.Client, baseURL, cachePath string) (*HTTPCloudflareSource, error) {
	if client == nil {
		return nil, errors.New("an HTTP client is required to read the Cloudflare IP ranges")
	}
	if baseURL == "" {
		baseURL = DefaultCloudflareBaseURL
	}
	if cachePath == "" {
		cachePath = DefaultCloudflareCachePath
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("cloudflare source %q: %w", baseURL, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("cloudflare source %q must be an https URL", baseURL)
	}
	return &HTTPCloudflareSource{client: client, baseURL: baseURL, cachePath: cachePath}, nil
}

// Candidates samples the published IPv4 ranges into at most limit candidates.
//
// One address is sampled from every /24 block the document covers, because that
// is the unit every documented range is aligned to: a sample taken per block
// spreads over the whole published space, while a sample taken per address would
// be dominated by the few largest ranges. The address each block contributes is
// chosen by a seed derived from the local date, so a day explores a different
// address in every block and the same date always produces the same sample.
//
// The IPv6 half of the document is parsed and validated but never expanded: this
// release selects IPv4 only, and an IPv6 address could not become a rewrite
// target. When the document covers more blocks than the limit, the blocks are
// spread across the whole range rather than taken from its start, so the cap does
// not turn the sample into the same few blocks every day.
func (s *HTTPCloudflareSource) Candidates(ctx context.Context, limit int, localDate time.Time) ([]Candidate, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("the official candidate limit must be greater than zero, got %d", limit)
	}
	seed, err := newDailySeed(localDate)
	if err != nil {
		return nil, err
	}
	fetched, err := fetchDocument(ctx, s.client, s.baseURL, s.cachePath, validatorRequired)
	if err != nil {
		return nil, err
	}
	document, err := parseCloudflareDocument(s.baseURL, fetched.Body)
	if err != nil {
		return nil, err
	}
	blocks, err := document.blocks()
	if err != nil {
		return nil, err
	}
	// The document is only stored once it has been accepted, so the cache never
	// holds a body this run refused.
	if err := storeDocument(s.cachePath, fetched); err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%s: the document covers no /24 block", s.baseURL)
	}
	chosen := min(len(blocks), limit)
	candidates := make([]Candidate, 0, chosen)
	for index := range chosen {
		// The i-th of k chosen blocks out of n is the (i*n)/k-th, which is
		// exactly k distinct blocks spread over the whole range.
		address := seed.addressIn(blocks[(int64(index)*int64(len(blocks)))/int64(chosen)])
		if !validPublicIPv4(address) {
			return nil, fmt.Errorf("%s: sampled address %s is not public IPv4 space", s.baseURL, address)
		}
		candidates = append(candidates, Candidate{Provider: ProviderCloudflare, IP: address, Source: SourceCloudflare})
	}
	Sort(candidates)
	return candidates, nil
}

// cloudflareRanges is the shape the IP API answers with. The fields this
// package does not read are declared, so a decoder that reached for something
// else would fail here rather than in production.
type cloudflareRanges struct {
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Messages []any `json:"messages"`
	Result   struct {
		ETag      string   `json:"etag"`
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
	} `json:"result"`
	Success bool `json:"success"`
}

// parseCloudflareDocument decodes and validates one IP API document. A failed
// request, a missing result, an empty IPv4 list, a missing revision marker, a
// trailing second document, and any malformed or reserved entry are all refused:
// every one of them means the document is not the published range list. Fields
// this build does not know about are not refused, because the document is the
// origin's own and not a document an operator wrote; every field this build does
// read is held to the verdict above.
func parseCloudflareDocument(sourceURL string, body []byte) (cloudflareRanges, error) {
	document := cloudflareRanges{}
	decoder := json.NewDecoder(newLimitedReader(body, maximumDocumentBytes*2))
	if err := decoder.Decode(&document); err != nil {
		return cloudflareRanges{}, fmt.Errorf("%s: decode document: %w", sourceURL, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cloudflareRanges{}, fmt.Errorf("%s: the document carries trailing content", sourceURL)
	}
	if !document.Success {
		if len(document.Errors) > 0 {
			return cloudflareRanges{}, fmt.Errorf("%s: the origin reported error %d: %s", sourceURL, document.Errors[0].Code, document.Errors[0].Message)
		}
		return cloudflareRanges{}, fmt.Errorf("%s: the origin reported a failed request", sourceURL)
	}
	if document.Result.ETag == "" {
		return cloudflareRanges{}, fmt.Errorf("%s: the document records no revision marker", sourceURL)
	}
	if len(document.Result.IPv4CIDRs) == 0 {
		return cloudflareRanges{}, fmt.Errorf("%s: the document names no IPv4 range", sourceURL)
	}
	for index, cidr := range document.Result.IPv6CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return cloudflareRanges{}, fmt.Errorf("%s: ipv6_cidrs[%d] %q is not a prefix: %w", sourceURL, index, cidr, err)
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return cloudflareRanges{}, fmt.Errorf("%s: ipv6_cidrs[%d] %q is not an IPv6 prefix", sourceURL, index, cidr)
		}
	}
	return document, nil
}

// blocks returns the deduplicated /24 blocks the document's IPv4 ranges cover, in
// order. The blocks are sorted before the sample chooses from them, so neither a
// map's iteration order nor the order the origin happened to list its ranges in
// can reach the sample, and ranges that overlap contribute each block once.
func (d cloudflareRanges) blocks() ([]netip.Prefix, error) {
	ranges := make([]netip.Prefix, 0, len(d.Result.IPv4CIDRs))
	total := int64(0)
	for index, cidr := range d.Result.IPv4CIDRs {
		prefix, err := parseIPv4Prefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("ipv4_cidrs[%d]: %w", index, err)
		}
		ranges = append(ranges, prefix)
		total += blockCount(prefix)
	}
	if total > maximumDocumentBlocks {
		return nil, fmt.Errorf("the document covers %d blocks, more than the %d block bound", total, maximumDocumentBlocks)
	}

	blocks := make([]netip.Prefix, 0, total)
	for _, prefix := range ranges {
		for index := int64(0); index < blockCount(prefix); index++ {
			blocks = append(blocks, blockAt(prefix, index))
		}
	}
	// Overlapping ranges expand to the same block twice. One pass over the sorted
	// blocks collapses them, so the sample counts each block once.
	slices.SortFunc(blocks, compareBlocks)
	unique := blocks[:0]
	for _, block := range blocks {
		if len(unique) > 0 && unique[len(unique)-1] == block {
			continue
		}
		unique = append(unique, block)
	}
	return unique, nil
}

// compareBlocks orders blocks by network address. Every block is a /24, so the
// address is the whole key.
func compareBlocks(first, second netip.Prefix) int {
	return first.Addr().Compare(second.Addr())
}

// dailySeed is the seed of the daily sample, derived from the local date the
// caller injected. Nothing in this package reads a clock, so the same date always
// produces the same sample and two runs on one day cannot disagree about it.
type dailySeed [sha256.Size]byte

func newDailySeed(localDate time.Time) (dailySeed, error) {
	if localDate.IsZero() {
		return dailySeed{}, errors.New("a local date is required to seed the daily sample")
	}
	return sha256.Sum256([]byte(localDate.Format(localDateLayout))), nil
}

// addressIn returns the address a block contributes to the sample. The block's
// own address and the date are hashed together, so the choice is spread over the
// block, is stable for one date, and changes with the date. The network and
// broadcast addresses are never chosen: the sample has to be an address something
// answers on.
func (s dailySeed) addressIn(block netip.Prefix) netip.Addr {
	digest := sha256.New()
	_, _ = digest.Write(s[:])
	_, _ = digest.Write(block.Addr().AsSlice())
	sum := digest.Sum(nil)
	raw := block.Addr().As4()
	raw[3] = 1 + byte(binary.BigEndian.Uint32(sum[:4])%sampleHostAddresses)
	return netip.AddrFrom4(raw)
}

// newLimitedReader returns a reader over at most limit bytes of body. The body
// comes from a reader that is already bounded, so this is the parse-time guard
// against a document whose nesting expands past what the read bound implies.
func newLimitedReader(body []byte, limit int64) io.Reader {
	return io.LimitReader(bytes.NewReader(body), limit)
}
