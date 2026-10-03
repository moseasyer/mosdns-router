package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The path is the cache plugin's OWN endpoint, not one this project invented:
// coremain/mosdns.go:164-165 mounts a plugin's mux at /plugins/<tag> and
// plugin/executable/cache/cache.go:320-324 registers GET /flush on it. Getting this
// wrong produces a 404 that looks exactly like "the router has no cache".
func TestTheFlushPathIsTheCachePluginsOwnMountPoint(t *testing.T) {
	want := "/plugins/foreign_cache/flush"
	if flushCachePath() != want {
		t.Fatalf("flushCachePath() = %q, want %q", flushCachePath(), want)
	}
}

func TestFlushAsksTheRouterOverLoopbackAndReportsWhatItSaid(t *testing.T) {
	var asked, method string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked, method = r.URL.Path, r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	services := productionServices()
	services.flushBaseURL = server.URL
	var stdout, stderr bytes.Buffer
	if code := runFlushCache(nil, &stdout, &stderr, services); code != exitSuccess {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if asked != flushCachePath() {
		t.Fatalf("the router was asked for %q, want %q", asked, flushCachePath())
	}
	if method != http.MethodGet {
		t.Fatalf("the flush was a %s, want GET: mosdns registers the handler for GET only "+
			"(cache.go:320-324), so a POST would 405", method)
	}
	if !strings.Contains(stdout.String(), "flushed") {
		t.Fatalf("nothing said what happened:\n%s", stdout.String())
	}
}

// A 404 here means the router is not listening on its api address, which is a
// DIFFERENT fault from "the router is down", and an operator needs to tell them
// apart. So the router's own words are carried through rather than replaced by ours.
func TestAFlushTheRouterRefusesIsAnErrorWithTheRoutersOwnWords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "the router is not listening on its api address", http.StatusNotFound)
	}))
	defer server.Close()

	services := productionServices()
	services.flushBaseURL = server.URL
	var stdout, stderr bytes.Buffer
	if code := runFlushCache(nil, &stdout, &stderr, services); code != exitStateUnavailable {
		t.Fatalf("exit %d, want %d", code, exitStateUnavailable)
	}
	if !strings.Contains(stderr.String(), "not listening") {
		t.Fatalf("the router's own words were dropped, so an operator cannot tell a "+
			"refusal from a router that is down: %s", stderr.String())
	}
}

// The router being DOWN is its own fault and says so itself; the point is that the
// verb does not claim the router refused when nothing answered at all.
func TestARouterThatIsNotThereIsNamedAsUnreachable(t *testing.T) {
	services := productionServices()
	// A port nothing is listening on: the listener is closed before the request.
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	services.flushBaseURL = server.URL
	server.Close()

	var stdout, stderr bytes.Buffer
	if code := runFlushCache(nil, &stdout, &stderr, services); code != exitStateUnavailable {
		t.Fatalf("exit %d, want %d", code, exitStateUnavailable)
	}
	if !strings.Contains(stderr.String(), "did not answer") {
		t.Fatalf("an unreachable router is not reported as one: %s", stderr.String())
	}
}

// flush-cache takes no arguments. A verb that ignored them would silently do the
// thing while the operator believed they had asked for something else.
func TestFlushTakesNoArguments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the router was asked despite a usage error")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	services := productionServices()
	services.flushBaseURL = server.URL
	var stdout, stderr bytes.Buffer
	if code := runFlushCache([]string{"--all"}, &stdout, &stderr, services); code != exitInvalidCLI {
		t.Fatalf("exit %d, want %d", code, exitInvalidCLI)
	}
}

// The address the verb asks is the one the routing document writes, and that is
// asserted rather than assumed: two copies of a loopback address are how a flush
// that talks to nothing reports success forever.
func TestTheFlushAsksTheAddressTheDocumentWrites(t *testing.T) {
	services := productionServices()
	if services.flushBaseURL != "http://"+mosdnsAPIListenAddress() {
		t.Fatalf("the flush asks %q, want the routing document's own api address %q",
			services.flushBaseURL, "http://"+mosdnsAPIListenAddress())
	}
	if !strings.HasPrefix(mosdnsAPIListenAddress(), "127.0.0.1:") {
		t.Fatalf("the api address is %q, which is not loopback; this package's promise is "+
			"that every listener it configures is loopback-only", mosdnsAPIListenAddress())
	}
}
