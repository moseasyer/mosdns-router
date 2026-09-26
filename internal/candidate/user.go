package candidate

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// maximumUserLineLength bounds one line of a user list. A candidate entry is an
// address or a prefix of at most twenty characters, so a longer line is a
// document this build cannot have been asked to accept, and it is refused
// instead of being buffered to find out.
const maximumUserLineLength = 256

// ParseUserList reads a user candidate list and returns the candidates it names,
// in the package order.
//
// A line is a comment when it starts with a # once it has been trimmed, and a
// # anywhere else ends the entry, so an address may carry a trailing comment. An
// empty line is ignored. Everything else must be one public IPv4 address or one
// public IPv4 prefix: this is the only channel a user controls, so a line that
// names two entries, an address this release does not select, a reserved range,
// or a value that is neither an address nor a prefix is refused rather than
// skipped, and the whole list is refused with it.
//
// A prefix a block wide or narrower names addresses, and every one of them
// becomes a candidate. A wider prefix cannot be expanded address by address
// without producing millions of probes, so it contributes the first host address
// of every block it covers. Either way the list as a whole is bounded by
// MaximumUserCandidates, so one line cannot hand the prober an unbounded list.
func ParseUserList(reader io.Reader) ([]Candidate, error) {
	if reader == nil {
		return nil, errors.New("a reader is required to parse a user candidate list")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, maximumUserLineLength), maximumUserLineLength)

	unique := make(map[Candidate]struct{})
	candidates := make([]Candidate, 0, 16)
	line := 0
	for scanner.Scan() {
		line++
		entry := strings.TrimSpace(scanner.Text())
		if before, _, found := strings.Cut(entry, "#"); found {
			entry = strings.TrimSpace(before)
		}
		if entry == "" {
			continue
		}
		addresses, err := expandUserEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		for _, address := range addresses {
			candidate := Candidate{Provider: ProviderCloudflare, IP: address, Source: SourceUser}
			if _, seen := unique[candidate]; seen {
				continue
			}
			if len(candidates) >= MaximumUserCandidates {
				return nil, fmt.Errorf("a user list may name at most %d candidates", MaximumUserCandidates)
			}
			unique[candidate] = struct{}{}
			candidates = append(candidates, candidate)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read user candidate list: %w", err)
	}
	Sort(candidates)
	return candidates, nil
}

// expandUserEntry returns the addresses one list entry names. An entry is one
// value: a value carrying whitespace names two entries, and neither parser below
// accepts it, so such a line is refused rather than half-read.
func expandUserEntry(entry string) ([]netip.Addr, error) {
	if !strings.Contains(entry, "/") {
		address, err := parsePublicIPv4(entry)
		if err != nil {
			return nil, err
		}
		return []netip.Addr{address}, nil
	}
	prefix, err := parseIPv4Prefix(entry)
	if err != nil {
		return nil, err
	}
	return expandUserPrefix(prefix)
}

// expandUserPrefix returns the addresses one list prefix names, and stops with
// an error as soon as it would pass the list bound, so a very wide prefix costs
// the work of the bound and not the work of the prefix.
func expandUserPrefix(prefix netip.Prefix) ([]netip.Addr, error) {
	if prefix.Bits() >= blockSize {
		// A block or narrower names addresses, and there are at most 256 of
		// them.
		addresses := make([]netip.Addr, 0, 256)
		for address := prefix.Addr(); prefix.Contains(address); address = address.Next() {
			addresses = append(addresses, address)
		}
		return addresses, nil
	}
	// A wider prefix contributes one address per block. The sample is not
	// seeded by the date: a user list is an instruction, so the addresses it
	// names are the same ones on every run.
	count := blockCount(prefix)
	addresses := make([]netip.Addr, 0, min(count, MaximumUserCandidates))
	for index := int64(0); index < count; index++ {
		if len(addresses) >= MaximumUserCandidates {
			return nil, fmt.Errorf("%s covers more than the %d candidates a user list may name", prefix, MaximumUserCandidates)
		}
		address := firstHostAddress(blockAt(prefix, index))
		if !validPublicIPv4(address) {
			return nil, fmt.Errorf("%s: block %d is %s, which is not public IPv4 space", prefix, index, address)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}
