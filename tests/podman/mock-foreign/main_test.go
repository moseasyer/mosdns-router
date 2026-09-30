package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// The address the stamp names is NOT the address this program binds, and the
// difference is the whole of the defect this file's cases exist for.
//
// A DNSCrypt stamp carries the address a client dials, and the client is
// `dnscrypt-proxy` in a *different container* on the run's private network. The
// container is told to listen on `0.0.0.0:443`, so it can be reached on whatever
// address the private network gave it -- and a stamp built from that bind address
// names `0.0.0.0:443`, which a client resolves to *itself*. So the target dialed
// its own port 443, got nothing, and the install transaction refused at its own
// barrier with:
//
//	install: dnscrypt-proxy.service was started but nothing answered a DNS
//	query at 127.0.0.1:15353 within 60s
//
// on all three releases, and the evidence document named the address the stamp
// carried, which is how it was found. `assertedAddress` is what stops it
// happening twice, and `TestAnUnspecifiedAddressIsRefused` is the half that stops
// the default from being the wrong thing silently.
func TestTheAddressIsTheOneTheStampNames(t *testing.T) {
	got, err := assertedAddress("0.0.0.0:443", "10.89.0.40:443")
	if err != nil {
		t.Fatalf("naming the address the client dials was refused: %v", err)
	}
	if got != "10.89.0.40:443" {
		t.Fatalf("the address is %q, not the one the flag named", got)
	}
}

func TestAnUnspecifiedAddressIsRefused(t *testing.T) {
	// The failure the first version of this image had, as a refusal. A stamp
	// naming an unspecified address is a resolver nothing can dial, and the cell
	// that installed it would report the transaction's foreign-resolver barrier
	// rather than the address that caused it -- which is what happened.
	//
	// The **bare** `0.0.0.0` and `::` are in the no-port case below rather than
	// here, and that is the order the checks run in: an address cannot be split
	// into a host and a port at all until it has a port, so the port refusal is
	// the true one for them, and saying "unspecified" would be a sentence about a
	// property the program never got far enough to look at.
	for _, address := range []string{"0.0.0.0:443", "[::]:443", "0.0.0.0:5353"} {
		t.Run(address, func(t *testing.T) {
			_, err := assertedAddress(address, "")
			if err == nil {
				t.Fatalf("an unspecified address was accepted as the one a client dials: %q", address)
			}
			if !strings.Contains(err.Error(), "unspecified") {
				t.Fatalf("the refusal does not say what is wrong with the address: %v", err)
			}
		})
	}
}

func TestTheDefaultIsTheBindAddress(t *testing.T) {
	// So that a caller who binds a specific address and names no other still gets
	// a stamp that works -- which is the case a single-host run is.
	got, err := assertedAddress("10.89.0.40:443", "")
	if err != nil {
		t.Fatalf("a specific bind address was refused as the address to name: %v", err)
	}
	if got != "10.89.0.40:443" {
		t.Fatalf("the default is %q rather than the bind address", got)
	}
}

func TestAnAddressThatIsNotAnIPLiteralIsRefused(t *testing.T) {
	// A name in a stamp is resolved by the client, and a DNSCrypt client resolves
	// it with its own bootstrap resolvers -- which in this cell are Quad9's, on a
	// machine with no route. So a stamp naming a name is a stamp that cannot be
	// used, and it is refused here rather than by the cell.
	if _, err := assertedAddress("0.0.0.0:443", "mock-foreign:443"); err == nil {
		t.Fatal("a name was accepted as the address a client dials")
	}
}

func TestAnAddressWithoutAPortIsRefused(t *testing.T) {
	// Every DNSCrypt stamp in the wild carries a port and dnscrypt-proxy reads it
	// as one, so an address without a port is a stamp this program cannot be
	// serving. The error has to say so, because the port is the difference between
	// "the override changed the address" and "the override changed the address and
	// the port", and the plan's Step 5 asks for the first.
	//
	// The bare unspecified forms are here rather than in the case above, because
	// this is the refusal that actually fires for them.
	for _, address := range []string{"10.89.0.40", "0.0.0.0", "::", "10.89.0.40:0"} {
		t.Run(address, func(t *testing.T) {
			_, err := assertedAddress("0.0.0.0:443", address)
			if err == nil {
				t.Fatalf("an address with no usable port was accepted: %q", address)
			}
			if !strings.Contains(err.Error(), "port") {
				t.Fatalf("the refusal does not mention the port: %v", err)
			}
		})
	}
}

func TestThePortTheAddressCarriesIsReachableByTheClient(t *testing.T) {
	// The shape the plan fixes, asserted here so a flag default of 5353 or a
	// `net.JoinHostPort` slip is a failing case rather than a cell that waits out
	// the transaction's whole budget.
	got, err := assertedAddress("0.0.0.0:443", "10.89.0.40:443")
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatal(err)
	}
	if host != "10.89.0.40" || port != "443" {
		t.Fatalf("the address is %s:%s", host, port)
	}
}

func TestTheCertificateThisStartPublishesDoesNotMoveWithTheClock(t *testing.T) {
	// **A second boundary is the whole of this case, and it is why it sleeps.**
	//
	// The certificate's validity window used to be read from the clock every time
	// one was built, and the window is *inside* the certificate, so two requests a
	// second apart got two different certificates -- a different signature over
	// the whole tail, not merely different timestamps. Nothing in a cell can see
	// it: the mock is asked once per client and the client verifies what it got.
	// But a TEST that builds one certificate and compares it with what the
	// response carries compares two documents that differ whenever the second
	// ticked between the two `time.Now()` calls -- measured at **9 failures in 20
	// package runs** of `TestTheCertificateSurvivesTheTextRecordItTravelsIn`, at
	// rounds 266 to 3829, each one a defect report about TXT escaping that was
	// about the clock.
	//
	// The mock's own wording is "the certificate this start of this resolver
	// publishes", so the window belongs to the start. Pinned, the case below is a
	// second boundary and a comparison rather than a coin flip, and the 256-round
	// case becomes a test of escaping.
	provider := newTestProvider(t)
	first := provider.validCertificate()
	time.Sleep(1100 * time.Millisecond)
	second := provider.validCertificate()
	if !bytes.Equal(first, second) {
		t.Fatalf("this start published two certificates:\n%x\n%x\n"+
			"so the validity window is read per request, and any comparison that builds one "+
			"certificate and asks the response for another compares two documents that differ "+
			"whenever the second ticks", first, second)
	}
}
