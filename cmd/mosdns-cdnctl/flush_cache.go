package main

import (
	"io"
	"net/http"
	"strings"
	"time"

	"mosdns-router/internal/mosdnsconfig"
)

// flushCachePluginTag is the tag the routing document gives the foreign cache, and
// it is part of the mounted path: coremain/mosdns.go:164-165 mounts a plugin's own
// mux under /plugins/<tag>, and plugin/executable/cache/cache.go:320-324 registers
// GET /flush on it. cache.go:108 mounts it unconditionally, so the endpoint has
// existed in every document this package has shipped -- and been unreachable,
// because the renderer emitted no api.http block until Task 2 added one.
const flushCachePluginTag = "foreign_cache"

// flushTimeout bounds the request. It is short because the endpoint is on loopback
// and answers or does not immediately; a slow answer means the thing answering is
// not the router this verb thinks it is.
const flushTimeout = 10 * time.Second

// flushCachePath is where the cache plugin's own endpoint is mounted.
func flushCachePath() string { return "/plugins/" + flushCachePluginTag + "/flush" }

// runFlushCache empties the router's foreign answer cache.
//
// **It is the router's OWN endpoint, not a mechanism this project built.** There is
// no second flush path that could disagree with the router's, and no cache to
// restart: nothing here writes a file, takes the control lock, or signals a unit. An
// operator clearing a cache should not be refused because a measurement happened to
// be publishing at that moment, which is what taking the lock would mean.
func runFlushCache(args []string, stdout, stderr io.Writer, services services) int {
	if len(args) != 0 {
		writeCLIError(stderr, "flush-cache: takes no arguments, got %q", strings.Join(args, " "))
		return exitInvalidCLI
	}
	base := strings.TrimRight(services.flushBaseURL, "/")
	request, err := http.NewRequest(http.MethodGet, base+flushCachePath(), nil)
	if err != nil {
		writeCLIError(stderr, "flush-cache: %v", err)
		return exitStateUnavailable
	}
	client := &http.Client{Timeout: flushTimeout}
	response, err := client.Do(request)
	if err != nil {
		writeCLIError(stderr, "flush-cache: the router did not answer on %s: %v", base, err)
		return exitStateUnavailable
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		// The router's own words, verbatim. A 404 here means the router is not
		// listening on its api address, which is a different fault from "the router
		// is down", and an operator needs to be able to tell them apart without
		// reading this source.
		writeCLIError(stderr, "flush-cache: the router answered %s: %s",
			response.Status, strings.TrimSpace(string(body)))
		return exitStateUnavailable
	}
	writeReportLine(stdout, "flushed: %s%s\n", base, flushCachePath())
	return exitSuccess
}

// mosdnsAPIListenAddress is the loopback address the routing document's api block
// binds. It comes from the package that renders the document rather than being
// written here, so the address this verb asks and the address the document binds
// cannot be two copies of a string that happened to agree when they were written.
func mosdnsAPIListenAddress() string { return mosdnsconfig.APIListenAddress() }
