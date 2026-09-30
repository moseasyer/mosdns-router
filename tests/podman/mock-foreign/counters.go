package main

// What the foreign listener was asked, and the one number the routing scenario
// reads.
//
// **Why this file is the product and not a log line.** Task 4 Step 6 asks the
// matrix to "assert query counters at mock domestic and foreign listeners", and
// the reason it says counters rather than answers is that an answer proves
// somebody answered and not *which branch asked*. A router that sent every name
// down the foreign branch would satisfy "the China name resolved" and fail
// everything this package exists to show, so the thing being measured is a count
// per name at one listener, and a second count per name at another, and the two
// have to disagree.
//
// **Keyed by name and by transport, never summed.** A single total is satisfied
// by a cell that sent all four of its queries over UDP, and a per-name count is
// satisfied by a cell that sent the China name to the foreign listener *and* the
// foreign name to the domestic one -- which is a different and more interesting
// failure, and it needs the name in the key to be visible at all.
//
// The stamp travels in the same document. The harness has to write a stamp it
// did not invent into the override before the install runs, and it reads that
// stamp off this file; keeping the two together is what makes "the counter the
// scenario read and the resolver it was talking to are the same one" a fact
// rather than a coincidence of two reads.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Counters is safe for the concurrent use two listeners make of it, and every
// mutation writes the whole document so a reader outside the process -- the
// harness, over `podman exec` -- sees a complete one rather than half of one.
type Counters struct {
	mutex   sync.Mutex
	stamp   string
	address string
	byName  map[string]map[string]uint64
	// certSeen counts the certificate requests, and it is separate from the
	// queries rather than folded into them: a count that included the client's own
	// certificate fetch would not be a count of the foreign branch's traffic.
	certSeen uint64
	probes   uint64
	dropped  uint64
}

// document is the shape written out. `queries` is sorted by name and each name's
// transports are sorted too, so two runs of the same cell produce byte-identical
// documents and a diff of two evidence files is readable.
type document struct {
	Stamp              string                       `json:"stamp"`
	Provider           string                       `json:"provider"`
	Address            string                       `json:"address"`
	Total              uint64                       `json:"total"`
	CertificateFetches uint64                       `json:"certificate_fetches"`
	PlaintextProbes    uint64                       `json:"plaintext_probes"`
	Dropped            uint64                       `json:"dropped"`
	Queries            map[string]map[string]uint64 `json:"queries"`
}

func newCounters() *Counters {
	return &Counters{byName: map[string]map[string]uint64{}}
}

// canonicalName lowercases a DNS name and drops the root label's dot, so that
// `CN-Routing.Example.`, `cn-routing.example` and `cn-routing.example.` are one
// name. DNS names are case-insensitive and the trailing dot is not part of the
// name, so a counter keyed on the wire spelling reads zero for a name asked in
// another case -- which is a counter that fails for a reason that has nothing to
// do with routing.
func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func (c *Counters) record(name, transport string) {
	key := canonicalName(name)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.byName[key] == nil {
		c.byName[key] = map[string]uint64{}
	}
	c.byName[key][transport]++
}

func (c *Counters) countCertificateFetch() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.certSeen++
}

func (c *Counters) countPlaintextProbe() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.probes++
}

func (c *Counters) countDropped() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.dropped++
}

func (c *Counters) setStamp(stamp string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.stamp = stamp
}

func (c *Counters) setAddress(address string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.address = address
}

func (c *Counters) transport(name, transport string) uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.byName[canonicalName(name)][transport]
}

func (c *Counters) total() uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	sum := uint64(0)
	for _, transports := range c.byName {
		for _, count := range transports {
			sum += count
		}
	}
	return sum
}

func (c *Counters) snapshot() document {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	queries := map[string]map[string]uint64{}
	sum := uint64(0)
	for name, transports := range c.byName {
		copied := map[string]uint64{}
		for transport, count := range transports {
			copied[transport] = count
			sum += count
		}
		queries[name] = copied
	}
	return document{
		Stamp: c.stamp, Provider: providerName, Address: c.address, Total: sum,
		CertificateFetches: c.certSeen, PlaintextProbes: c.probes, Dropped: c.dropped,
		Queries: queries,
	}
}

// marshal renders the snapshot with sorted keys, which `encoding/json` does for
// maps by itself and which is why the document type is a struct of maps rather
// than something assembled by hand: two runs of one cell then differ only where
// the cell differed.
func (c *Counters) marshal() []byte {
	rendered, err := json.MarshalIndent(c.snapshot(), "", "  ")
	if err != nil {
		// A counters document that cannot be written is not worth crashing over:
		// the listener is still answering, and the cell's real failure will be
		// the scenario's own refusal on a count it could not read.
		return []byte("{}\n")
	}
	return append(rendered, '\n')
}

// write publishes the snapshot where the harness reads it, atomically. The write
// goes to a neighbouring temporary file and is renamed over the target, because
// the reader is another process polling this path and a partially written
// document would read as a count of nothing.
func (c *Counters) write(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, c.marshal(), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Names is every name this resolver has been asked about, sorted. It is not on
// the wire to anything; it exists so a failing case can say what the mock *did*
// see rather than only what it did not.
func (c *Counters) Names() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	names := make([]string, 0, len(c.byName))
	for name := range c.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
