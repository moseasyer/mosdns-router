// The mock foreign resolver: a DNSCrypt server, on the private network, counting
// what it is asked.
//
// This is the "test-only foreign DNS listener" the Podman matrix plan's Task 4
// interfaces name, and it exists because of what the packaged resolver requires
// rather than because a mock is convenient. `configs/dnscrypt-proxy.toml` ships
// three Quad9 DNSCrypt stamps, and dnscrypt-proxy 2.1.18 will only talk to a
// DNSCrypt, DoH or ODoH server -- `fetchServerInfo` returns "Unsupported
// protocol" for anything else, and a `[static.*]` entry in its config carries a
// `Stamp` and nothing else, so it cannot name a plain address at all. A cell
// with no route to the internet therefore cannot make the install transaction
// complete with a plain DNS listener behind the stamps: it needs a resolver that
// speaks the protocol the shipped document is written for.
//
// **The three things it does, and none of them is configurable in a way that
// could matter.** It answers every query with one address, and it counts every
// query by name and by transport. It never forwards, never resolves anything and
// has no upstream -- a mock that could reach a real resolver would make "the
// foreign branch answered" indistinguishable from "something else answered",
// which is the whole property Task 4 Step 6 measures.
//
// **The stamp is generated, not configured.** The keys are made per start, so
// the stamp that authenticates them is too, and the harness reads it off the
// counters document. A stamp written down in the repository would have to mean a
// fixed private key, and a fixed private key in a repository is a
// credential-shaped thing to review for no benefit.

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/nacl/box"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:443",
		"the address to serve DNSCrypt on, over UDP and TCP, and the address the stamp names")
	countersPath := flag.String("counters", "/run/mosdns-mock-foreign/counters.json",
		"where the counters and the stamp are written; the harness polls this path")
	answer := flag.String("answer", "198.51.100.7",
		"the single address every answer carries. A documentation address (RFC 5737), "+
			"so nothing but this harness can reach whatever this mock says")
	flag.Parse()

	if err := run(*listen, *countersPath, *answer); err != nil {
		fmt.Fprintf(os.Stderr, "mosdns-mock-foreign: %v\n", err)
		os.Exit(1)
	}
}

// resolver is the whole program: an identity, a place to record what it was
// asked, and where to write that down. One struct so the two listeners and the
// counters share them without a package-level variable.
type resolver struct {
	provider *provider
	counters *Counters
	path     string
	answer   string
}

func run(listen, countersPath, answer string) error {
	keys, err := newProvider()
	if err != nil {
		return err
	}
	stamp, err := keys.stamp(listen)
	if err != nil {
		return err
	}
	counters := newCounters()
	counters.setStamp(stamp)
	counters.setAddress(listen)
	// Written before the sockets are bound. The harness polls this path for the
	// stamp, and a file that only appeared once something had been asked for
	// would be a file the install might start without.
	if err := counters.write(countersPath); err != nil {
		return fmt.Errorf("writing the counters document: %w", err)
	}
	mine := &resolver{provider: keys, counters: counters, path: countersPath, answer: answer}

	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	log.Printf("mosdns-mock-foreign: listening on %s, provider %s, stamp %s", listen, providerName, stamp)
	// One line per answer, on the container's log. The counters file is what the
	// harness asserts on and this is what a person reads when a count does not
	// move: it names the name and the transport, which is the pair a routing
	// assertion is about.

	udp, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("binding UDP %s: %w", listen, err)
	}
	defer udp.Close()
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("binding TCP %s: %w", listen, err)
	}
	defer listener.Close()

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		// The last write on the way out, so a cell that ends with a query in
		// flight has its count on disk rather than in a buffer.
		_ = counters.write(countersPath)
		udp.Close()
		listener.Close()
	}()

	var waiting sync.WaitGroup
	waiting.Add(2)
	go func() { defer waiting.Done(); mine.serveUDP(udp) }()
	go func() { defer waiting.Done(); mine.serveTCP(listener) }()
	waiting.Wait()
	return nil
}

// maxDatagram is the largest DNSCrypt response a client accepts, plus the
// framing around it: a 4096-byte DNS message (`MaxDNSPacketSize`) inside
// `ServerMagic(8) + nonce(24) + Poly1305 tag(16)`. A buffer smaller than this
// would truncate a large answer, and a truncated answer is one the client cannot
// read -- which the cell would report as a query that went unanswered.
const maxDatagram = 4096 + 8 + 24 + 16

func (r *resolver) serveUDP(packet net.PacketConn) {
	buffer := make([]byte, maxDatagram)
	for {
		read, from, err := packet.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		response, name, kind := r.respond(buffer[:read], "udp")
		if kind == notHandled {
			continue
		}
		if name != "" {
			r.counters.record(name, "udp")
			log.Printf("mosdns-mock-foreign: answered %s over udp with %s", name, r.answer)
		}
		r.publish()
		if response != nil {
			_, _ = packet.WriteTo(response, from)
		}
	}
}

// serveTCP reads the two-byte length prefix dnscrypt-proxy puts in front of
// every DNSCrypt exchange over TCP (`PrefixWithSize` on the way out,
// `ReadPrefixed` on the way in) and answers with the same framing. The prefix is
// read as a length and not as two more payload bytes, because a client that
// framed its query as DNS would be answered with a frame it cannot parse and the
// cell would look like a transport problem rather than a framing one.
func (r *resolver) serveTCP(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go r.serveConnection(connection)
	}
}

func (r *resolver) serveConnection(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		r.counters.countDropped()
		return
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length <= 0 || length > maxDatagram {
		r.counters.countDropped()
		return
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(connection, payload); err != nil {
		r.counters.countDropped()
		return
	}
	response, name, kind := r.respond(payload, "tcp")
	if kind == notHandled {
		return
	}
	if name != "" {
		r.counters.record(name, "tcp")
		log.Printf("mosdns-mock-foreign: answered %s over tcp with %s", name, r.answer)
	}
	r.publish()
	if response == nil {
		return
	}
	framed := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(response)))
	copy(framed[2:], response)
	_, _ = connection.Write(framed)
}

// publish writes the counters document. On the query path rather than on a timer
// so a count is on disk as soon as it exists; the harness polls, and a count that
// appears a second later is a count the harness can read but a slow cell waits
// for.
func (r *resolver) publish() {
	_ = r.counters.write(r.path)
}

// kind is what a packet turned out to be, which decides whether it is counted
// and whether anything is sent back.
type kind int

const (
	notHandled kind = iota
	// an encrypted query, or a certificate request: the two that are this
	// resolver's actual business.
	forwarded
	// dnscrypt-proxy's plaintext probe, which is answered NXDOMAIN and is
	// counted apart from the queries so a count is not inflated by the client's
	// own health check.
	probe
)

// respond is the decision tree. The order matters: the client magic is eight
// 0xFF bytes, which no DNS message can begin with (the first two bytes are the
// transaction ID and the next two are the flags, with QR set for a response), so
// the encrypted case is tested first and costs nothing. The two plaintext cases
// are then told apart by the question, and the certificate one is a TXT query
// for this provider's own name.
func (r *resolver) respond(packet []byte, transport string) (response []byte, name string, seen kind) {
	if len(packet) >= 8 && string(packet[:8]) == clientMagic {
		decrypted, err := r.provider.open(packet)
		if err != nil {
			r.counters.countDropped()
			return nil, "", notHandled
		}
		answer, err := answerFor(decrypted, r.answer)
		if err != nil {
			r.counters.countDropped()
			return nil, "", notHandled
		}
		sealed, err := r.provider.sealFor(decrypted, answer, packet)
		if err != nil {
			r.counters.countDropped()
			return nil, "", notHandled
		}
		return sealed, questionName(decrypted), forwarded
	}

	var request dns.Msg
	if err := request.Unpack(packet); err != nil || len(request.Question) == 0 {
		r.counters.countDropped()
		return nil, "", notHandled
	}
	question := request.Question[0]
	if question.Qtype == dns.TypeTXT && canonicalName(question.Name) == canonicalName(providerName) {
		r.counters.countCertificateFetch()
		return r.provider.certificateResponse(&request), "", forwarded
	}
	// Everything else in the clear is NXDOMAIN with an empty additional section,
	// and it is counted as a probe. dnscrypt-proxy sends
	// `<random>.test.dnscrypt. NS` in the clear after fetching a certificate, to
	// decide whether the resolver is "lying" (`serversInfo.go`:
	// fetchDNSCryptServerInfo), and refuses the server outright if the answer
	// carries an A or AAAA record or a TXT record in the additional section. A
	// mock that answered it from its own address table would be refused as a
	// lying resolver and the cell would report that as an unreachable chain.
	refusal := new(dns.Msg)
	refusal.SetRcode(&request, dns.RcodeNameError)
	packed, err := refusal.Pack()
	if err != nil {
		return nil, "", notHandled
	}
	r.counters.countPlaintextProbe()
	return packed, "", probe
}

func questionName(query []byte) string {
	var request dns.Msg
	if err := request.Unpack(query); err != nil || len(request.Question) == 0 {
		return ""
	}
	return canonicalName(request.Question[0].Name)
}

// sealFor wraps a built answer for the client that asked, recovering the shared
// key and the client's nonce from the query that is still in hand. The client's
// public key and nonce are in the clear at offsets 8..64, so no session state is
// needed and one server answers every client in the cell.
func (p *provider) sealFor(_, answer, query []byte) ([]byte, error) {
	var clientPublic [32]byte
	copy(clientPublic[:], query[8:40])
	clientNonce := readHalfNonce(query[8+32 : 8+32+halfNonceSize])
	var shared [32]byte
	box.Precompute(&shared, &clientPublic, &p.exchange)
	return p.seal(answer, clientNonce[:], &shared)
}
