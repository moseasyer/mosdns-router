// A DNSCrypt resolver, sized for one test and answering nothing it was not asked.
//
// **Why this program exists at all.** Task 4 Step 5 of the Podman matrix plan
// needs a "foreign answer reachable" in a cell with no route to the internet, and
// the shipped resolver document is the constraint rather than the obstacle. Read
// `configs/dnscrypt-proxy.toml`: it names three Quad9 stamps, `require_dnssec =
// true` and `require_nolog = true`, and its unit reads that one document
// (`packaging/systemd/dnscrypt-proxy.service`, `ExecStart=… -config
// /etc/mosdns/dnscrypt-proxy.toml`). So the only thing a cell may change about
// the foreign branch is *which resolver the stamps name*, and the thing that has
// to answer is a real DNSCrypt server, not a plain DNS one -- dnscrypt-proxy
// 2.1.18's `fetchServerInfo` accepts DNSCrypt, DoH and ODoH and nothing else, and
// `StaticConfig` in its config.go has one field, `Stamp`, so a `[static.*]`
// entry cannot name a plain address at all. A mock that answered plain DNS would
// be a mock the real resolver cannot talk to.
//
// **So this speaks DNSCrypt, and only as much of it as a client needs.** The
// certificate is published in a TXT record under `2.dnscrypt-cert.…` and the
// queries after that are XSalsa20-Poly1305 over Curve25519, with the client's
// 12-byte nonce echoed in the front of the server's 24-byte nonce. Every offset
// is dnscrypt-proxy's own and is asserted in `dnscrypt_test.go`; this file's
// comments say which function each one was read out of, because a mock that is
// subtly wrong does not fail -- it is a resolver that never becomes usable, and
// the install transaction's foreign-resolver barrier reports that as if it were
// an installer defect.
//
// **What it answers, and what it counts.** Every query it decrypts is answered
// with one fixed address, and every one of them is counted by name and by
// transport. The count is the product: Task 4 Step 6 asks the matrix to assert
// that a China-set name and a foreign name reach *different* listeners, and an
// assertion that only checked an answer came back would be satisfied by a router
// that sent everything to one of them. The counters are per name and per
// transport rather than a total, because a total is satisfied by a cell that sent
// every query over UDP.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// providerName is where the certificate is published, and it is part of the
	// address dnscrypt-proxy dials: `FetchCurrentDNSCryptCert` builds its TXT
	// query from the stamp's provider name, so a certificate served under any
	// other name is never fetched. The `2.dnscrypt-cert.` prefix is the
	// convention for a cert provider, and `FetchCurrentDNSCryptCert` drops the
	// relay for anything that does not carry it.
	providerName = "2.dnscrypt-cert.mosdns-mock-foreign"

	// The four-byte magic a certificate opens with, and the eight-byte magic a
	// client prefixes to a query. Both from dnscrypt-proxy 2.1.18's `common.go`,
	// and the client magic is *ours to choose* because the client copies it out
	// of the certificate: dnscrypt-proxy sends `serverInfo.MagicQuery` in front
	// of every query, and that is `binCert[104:112]`. It is eight 0xFF bytes
	// because no DNS message can begin with them -- the first two bytes are the
	// transaction ID and the next two are the flags with QR set for a response --
	// so a DNSCrypt query and a plaintext DNS query are told apart by the first
	// eight bytes rather than by a guess.
	certMagic = "DNSC"
	// BACKSLASH is the one byte both escaping schemes agree to escape first, and
	// naming it keeps the two switch statements below from spelling it twice.
	BACKSLASH   = '\\'
	clientMagic = "\xff\xff\xff\xff\xff\xff\xff\xff"

	// esVersionXSalsa20 is `dnscrypt_certs.go`'s `0x0001`. The alternative is
	// 0x0002, XChaCha20-Poly1305, which dnscrypt-proxy prefers and which needs
	// `github.com/jedisct1/xsecretbox` -- a module this repository does not
	// depend on and would not otherwise have a reason to. dnscrypt-proxy accepts
	// 0x0001 and logs one line about it; see dnscrypt_test.go for the trade.
	esVersionXSalsa20 = 0x0001

	// requiredProps are the two properties the shipped document insists on. They
	// are declared here rather than being left at their zero value because a
	// certificate that does not declare them is one dnscrypt-proxy refuses, and
	// the refusal is silent from the outside: the resolver binds its listener and
	// answers nothing.
	requiredProps = stamps.ServerInformalPropertyDNSSEC | stamps.ServerInformalPropertyNoLog

	// **A query carries HALF the nonce, and a response carries all of it.** That
	// asymmetry is `HalfNonceSize` in `crypto.go`, and getting it wrong is
	// invisible: the client prefixes its query with
	//
	//	MagicQuery(8) + publicKey(32) + nonce[:12]
	//
	// and the nonce it used for the secretbox is those twelve bytes followed by
	// twelve zeroes -- `copy(nonce, clientNonce)` into a 24-byte slice. So a server
	// that reads 24 bytes off the wire reads twelve bytes of ciphertext as if
	// they were nonce, and every query fails its authentication check with
	// nothing to tell a reader why. The sizes are therefore named separately and
	// the nonce is rebuilt from the twelve, not read.
	nonceSize     = 24
	halfNonceSize = nonceSize / 2
	// MagicQuery(8) + publicKey(32) + nonce[:12].
	queryHeader   = 8 + 32 + halfNonceSize
	responseMagic = "\x72\x36\x66\x6e\x76\x57\x6a\x38"

	// The validity window the certificate is issued for, and why it is computed
	// at every start rather than baked in. `cert_ignore_timestamp` is false in
	// the shipped document, so dnscrypt-proxy compares the window against the
	// clock and skips a certificate that does not contain it. A window written
	// into a fixture would work on the machine that made it and stop working in
	// a cell hours later -- a resolver that is fine until it is not.
	certificateBackdate = time.Hour
	certificateLifetime = 3 * 24 * time.Hour

	// The smallest and largest padded payloads. dnscrypt-proxy pads a query to
	// at least `InitialMinQuestionSize` and refuses a response outside
	// `MinDNSPacketSize`..`MaxDNSPacketSize`, so both bounds here are the
	// client's rather than this program's taste.
	minPaddedSize = 512
	maxDNSPacket  = 4096

	// answerTTL and certificateTTL are 60 seconds. Long enough that a client's
	// two lookups in one cell share an answer, short enough that nothing in the
	// cell is still holding a mock's address or a mock's certificate afterwards.
	answerTTL      = 60
	certificateTTL = 60
)

// provider is one resolver's identity and the two keys it answers with.
//
// Two different keys, and the difference is the whole of DNSCrypt's trust story:
// `signing` is Ed25519 and signs the *certificate*, so a client can tell whether
// the certificate came from the provider the stamp named; `exchange` is the
// Curve25519 SECRET this resolver derives its shared key from, and a party on
// the path can read nothing because it never sees this half.
//
// **The certificate carries the PUBLIC half and publishing the secret would
// break every query with a symptom that says nothing about the cause.** The
// client's `FetchCurrentDNSCryptCert` reads `binCert[72:104]` as the server's
// public key and computes `box.Precompute(&sharedKey, serverPk, itsOwnSecret)`,
// so publishing a secret there makes the two sides derive different shared keys
// and every query fails its authentication check. This is why `publicExchange()`
// exists and why `TestTheCertificateCarriesThePublicKeyAndNotTheSecret` holds it.
type provider struct {
	signing  ed25519.PrivateKey
	exchange [32]byte
	// **The validity window, read once.** It is inside the certificate and the
	// certificate is signed over the window, so a window read per request is a
	// different document per request -- not merely a different pair of timestamps
	// but a different signature over the whole tail. `TestTheCertificateThisStart
	// PublishesDoesNotMoveWithTheClock` is the case, and the failure it replaced
	// was 9 runs in 20 of a TXT-escaping case that was about the clock.
	from, until uint32
}

// publicExchange is the public half of `exchange`, and it is what goes into the
// certificate. Derived, never stored, so the two cannot drift apart: a stored
// copy of a public key is a second thing that can be wrong about the first.
func (p *provider) publicExchange() [32]byte {
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &p.exchange)
	return public
}

// newProvider generates a fresh identity. Nothing here is deterministic, and
// that is correct: the stamp the harness writes into the override names whatever
// key this start produced, and the harness reads that stamp back off the
// container rather than assuming one.
func newProvider() (*provider, error) {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the provider's signing key: %w", err)
	}
	var exchange [32]byte
	if _, err := rand.Read(exchange[:]); err != nil {
		return nil, fmt.Errorf("generating the provider's exchange key: %w", err)
	}
	// Curve25519 clamps its own scalar in `curve25519.ScalarBaseMult` but not in
	// `box.Precompute`, and the client uses `box.Precompute` -- so the server has
	// to clamp, or the two sides derive different shared keys and every answer
	// fails its tag check with no other symptom.
	exchange[0] &= 248
	exchange[31] &= 127
	exchange[31] |= 64
	// **The clock is read here and nowhere else.** A mock's certificate is "the
	// one this start publishes", and a window that moved per request would make
	// that a different document every time a client asked -- which no cell can
	// see and a test cannot stop tripping over.
	now := uint32(time.Now().Unix())
	return &provider{
		signing:  signing,
		exchange: exchange,
		from:     now - uint32(certificateBackdate/time.Second),
		until:    now + uint32(certificateLifetime/time.Second),
	}, nil
}

// certificate is the signed document dnscrypt-proxy fetches before it will send
// this resolver a single query. The layout is `dnscrypt_certs.go`'s, field for
// field, and the offsets are asserted in the test:
//
//	[0:4]    magic "DNSC"
//	[4:6]    esVersion, 0x0001 for XSalsa20-Poly1305
//	[6:8]    signature length, 64
//	[8:72]   Ed25519 signature over everything from [72] on
//	[72:104] Curve25519 public key -- the server's, and the only key material
//	         here that is not signed by a key of its own
//	[104:112] the magic the client prefixes to every query
//	[112:116] serial
//	[116:120] validity start, big endian
//	[120:124] validity end, big endian
//	[124:126] the signature length again, as the reference layout has it
//	[126:134] properties, little endian
func (p *provider) certificate(serial, from, until uint32) []byte {
	certificate := make([]byte, 134)
	copy(certificate[0:4], certMagic)
	binary.BigEndian.PutUint16(certificate[4:6], esVersionXSalsa20)
	binary.BigEndian.PutUint16(certificate[6:8], ed25519.SignatureSize)
	public := p.publicExchange()
	copy(certificate[72:104], public[:])
	copy(certificate[104:112], clientMagic)
	binary.BigEndian.PutUint32(certificate[112:116], serial)
	binary.BigEndian.PutUint32(certificate[116:120], from)
	binary.BigEndian.PutUint32(certificate[120:124], until)
	binary.BigEndian.PutUint16(certificate[124:126], ed25519.SignatureSize)
	binary.LittleEndian.PutUint64(certificate[126:134], uint64(requiredProps))
	signature := ed25519.Sign(p.signing, certificate[72:])
	copy(certificate[8:72], signature)
	return certificate
}

// validCertificate is the certificate this start of this resolver publishes, with
// a window around now -- read at the start, so it is the same document every time
// it is asked for.
func (p *provider) validCertificate() []byte {
	return p.certificate(1, p.from, p.until)
}

// stamp is the one line of the override document: a DNSCrypt stamp naming this
// resolver's address and its provider key. Built with go-dnsstamps rather than
// assembled by hand, because the encoding is base64 over a binary layout and a
// hand-built one would be a stamp only this program could read.
func (p *provider) stamp(address string) (string, error) {
	// The constructor is the library's, and its three arguments are the three
	// things the stamp has to carry: where the resolver is, which key signed its
	// certificate, and under which name that certificate is published. Handed the
	// provider key as hex because that is the spelling this version takes, and
	// the check inside it -- 32 bytes after the colons are stripped -- is a
	// refusal worth having rather than a stamp that fails to verify later.
	stamp, err := stamps.NewDNSCryptServerStampFromLegacy(
		address,
		hex.EncodeToString(p.signing.Public().(ed25519.PublicKey)),
		providerName,
		requiredProps,
	)
	if err != nil {
		return "", fmt.Errorf("building a stamp for %s: %w", address, err)
	}
	return stamp.String(), nil
}

// certificateQuestion is the TXT name the certificate is published under, in the
// form a query arrives: the provider name with a trailing dot.
func certificateQuestion() string {
	return providerName + "."
}

// open decrypts a DNSCrypt query, and reports the name in it.
//
// `transport` is this caller's own label and comes from the listener the packet
// arrived on, because "which transport reached the foreign branch" is one of the
// two things the routing scenario has to be able to tell apart.
func (p *provider) open(packet []byte) (query []byte, err error) {
	if len(packet) < queryHeader+secretbox.Overhead {
		return nil, fmt.Errorf("a %d-byte packet is too short to be a DNSCrypt query", len(packet))
	}
	if !bytes.Equal(packet[:8], []byte(clientMagic)) {
		return nil, errors.New("the packet does not start with this resolver's client magic")
	}
	var clientPublic [32]byte
	copy(clientPublic[:], packet[8:40])
	clientNonce := readHalfNonce(packet[8+32 : 8+32+halfNonceSize])

	// `box.Precompute(shared, peerPublic, mySecret)`: the client computes it the
	// other way round in `crypto.go: ComputeSharedKey`, and X25519 is symmetric,
	// so the two agree. The client's public key travels in every query, which is
	// what makes one server able to answer many clients without a session.
	var shared [32]byte
	box.Precompute(&shared, &clientPublic, &p.exchange)

	plain, ok := secretbox.Open(nil, packet[queryHeader:], &clientNonce, &shared)
	if !ok {
		return nil, fmt.Errorf("the %d-byte query did not authenticate under the shared key "+
			"(client nonce %x)", len(packet), clientNonce[:12])
	}
	unpadded, err := unpad(plain)
	if err != nil {
		return nil, fmt.Errorf("the query authenticated but did not unpad: %w", err)
	}
	return unpadded, nil
}

// readHalfNonce rebuilds the 24-byte nonce from the twelve bytes a query carried.
// The rest is zeroes, because that is what the client left there: it copies its
// twelve random bytes into the front of a 24-byte slice and encrypts with the
// whole thing.
func readHalfNonce(half []byte) [nonceSize]byte {
	var nonce [nonceSize]byte
	copy(nonce[:halfNonceSize], half)
	return nonce
}

// certificateResponse is the TXT answer dnscrypt-proxy fetches before it will use
// this resolver. One TXT record carrying the certificate, escaped by
// `escapeForTXT`; the client joins the character-strings back together and
// unescapes it with `PackTXTRR`.
//
// Nothing is delegated and `RecursionAvailable` is set. A certificate answered
// out of a cache is not a certificate whose signature anybody checked, and the
// check is the entire point of the exchange.
func (p *provider) certificateResponse(request *dns.Msg) []byte {
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	response.Answer = append(response.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name: request.Question[0].Name, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: certificateTTL,
		},
		Txt: []string{escapeForTXT(p.validCertificate())},
	})
	packed, err := response.Pack()
	if err != nil {
		// A certificate that will not pack is a resolver that will not start, so
		// this is worth saying out loud rather than answering something else.
		log.Printf("mosdns-mock-foreign: the certificate did not pack: %v", err)
		return nil
	}
	return packed
}

// answerFor builds the DNS response for one decrypted query.
//
// A single fixed address for every name, deliberately: the point of the mock is
// that an answer came back *from the foreign branch*, and an address nobody
// hosts cannot be reached by anything except the harness. The default,
// `198.51.100.7`, is TEST-NET-2 (RFC 5737) and `2001:db8::7` is the
// documentation prefix (RFC 3849), so neither is routable -- and neither is
// inside a Cloudflare range, which matters because the response rewriter the
// foreign branch runs *first* would otherwise have a Cloudflare address to
// rewrite, and the cell would be measuring the rewriter rather than the branch.
// An A query for a mock configured with an IPv6 address is answered with no
// records and NOERROR, which is what a resolver with nothing for that type says.
func answerFor(query []byte, address string) ([]byte, error) {
	var request dns.Msg
	if err := request.Unpack(query); err != nil {
		return nil, fmt.Errorf("the decrypted query is not a DNS message: %w", err)
	}
	response := new(dns.Msg)
	response.SetReply(&request)
	response.RecursionAvailable = true
	if len(request.Question) > 0 {
		switch request.Question[0].Qtype {
		case dns.TypeA:
			if parsed := net.ParseIP(address); parsed != nil && parsed.To4() != nil {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name: request.Question[0].Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: answerTTL,
					},
					A: parsed.To4(),
				})
			}
		case dns.TypeAAAA:
			if parsed := net.ParseIP(address); parsed != nil && parsed.To4() == nil {
				response.Answer = append(response.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name: request.Question[0].Name, Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET, Ttl: answerTTL,
					},
					AAAA: parsed.To16(),
				})
			}
		}
	}
	packed, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing the answer: %w", err)
	}
	if len(packed) > maxDNSPacket {
		return nil, fmt.Errorf("the answer is %d bytes, over the %d this client accepts", len(packed), maxDNSPacket)
	}
	return packed, nil
}

// seal wraps an answer the way `crypto.go: Decrypt` expects to find it:
//
//	ServerMagic(8) || serverNonce(24) || secretbox(pad(answer))
//
// and the nonce's first twelve bytes are the client's, because that is the check
// `Decrypt` makes before it decrypts anything:
//
//	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) { ... }
//
// The client builds a 24-byte nonce by copying its 12 random bytes into the front
// and leaving the rest zero, so the effective nonce is those twelve. A server
// that sealed under a nonce of its own would produce a response the client
// discards with "Unexpected nonce", which is indistinguishable from an
// unreachable resolver from the outside.
func (p *provider) seal(answer, clientNonce []byte, shared *[32]byte) ([]byte, error) {
	if len(clientNonce) != nonceSize {
		return nil, fmt.Errorf("the client nonce is %d bytes, want %d: `Decrypt` compares "+
			"`nonce[:HalfNonceSize]` against `serverNonce[:HalfNonceSize]`, so it is those "+
			"twelve bytes that have to come back and no fewer", len(clientNonce), nonceSize)
	}
	var serverNonce [nonceSize]byte
	copy(serverNonce[:halfNonceSize], clientNonce[:halfNonceSize])
	if _, err := rand.Read(serverNonce[12:]); err != nil {
		return nil, fmt.Errorf("generating a server nonce: %w", err)
	}
	frame := append([]byte(responseMagic), serverNonce[:]...)
	return secretbox.Seal(frame, pad(answer, minPaddedSize), &serverNonce, shared), nil
}

// pad and unpad are `crypto.go`'s, byte for byte: a 0x80 delimiter followed by
// zeroes to a minimum length, and the reverse scan on the way back. The
// delimiter is what makes "the answer ended here" unambiguous, because the
// payload before it is arbitrary bytes that may end in a zero.
func pad(packet []byte, size int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < size {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("the padding delimiter is not there")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		}
		if packet[i] != 0x00 {
			return nil, errors.New("the padding is not zeroes after the delimiter")
		}
	}
}

// escapeForTXT is the escaping a TXT character-string carries, and it is not
// decoration: a certificate is arbitrary binary, and a single 0x5C in it is
// enough to swallow whatever comes after it.
//
// **Three pieces of software are involved and they have to agree.** The
// certificate is written into a `dns.TXT` by this program; `github.com/miekg/dns`
// then *unescapes* it on the way into the wire -- `packTxtString` reads a
// backslash as the start of an escape -- and *escapes* it again on the way out,
// in `unpackString`; and dnscrypt-proxy reads the result with its own
// `PackTXTRR`, which is not that library's function. So:
//
//   - what goes into `Txt` is the escaped form, because `packTxtString` would
//     otherwise eat the first backslash in the certificate together with the
//     byte after it;
//   - what comes out of `unpackString` is the same escaped form, because that is
//     what `unpackString` produces for those same bytes; and
//   - `PackTXTRR` inverts exactly this form: a backslash and three digits is a
//     byte, a doubled backslash is a backslash, an escaped quote is a quote.
//
// So the rule below is `unpackString`'s, byte for byte: a double quote and a
// backslash are doubled, and anything outside printable ASCII becomes a backslash
// and three digits. `TestTheCertificateSurvivesTheTextRecordItTravelsIn` asserts
// the whole path over 256 certificates, which is the only way to be sure every
// byte value survives it.
func escapeForTXT(certificate []byte) string {
	var out strings.Builder
	out.Grow(len(certificate) * 2)
	for _, b := range certificate {
		switch {
		case b == '"' || b == BACKSLASH:
			out.WriteByte(BACKSLASH)
			out.WriteByte(b)
		case b < ' ' || b > '~':
			out.WriteByte(BACKSLASH)
			out.WriteByte('0' + b/100)
			out.WriteByte('0' + (b/10)%10)
			out.WriteByte('0' + b%10)
		default:
			out.WriteByte(b)
		}
	}
	return out.String()
}

// unescapeTXT is dnscrypt-proxy's `PackTXTRR`, mirrored: it is how the client
// reads a certificate out of the TXT record the answer carried. It is here, and
// not only in the test, because it is the definition of what this resolver has to
// produce -- a certificate that survives *that* parser -- and a mock that wrote
// its own escaping and checked it against itself would agree with itself and
// with nothing else.
//
// A backslash and three digits is a byte, `\t`, `\r` and `\n` are the three
// control characters the DNSCrypt tooling names, a doubled backslash is a
// backslash, and anything else after a backslash is itself. The last clause is
// what makes a double-escaped certificate decode to nothing sensible rather than
// to something plausible.
func unescapeTXT(escaped string) []byte {
	out := make([]byte, 0, len(escaped))
	for i := 0; i < len(escaped); i++ {
		if escaped[i] != BACKSLASH {
			out = append(out, escaped[i])
			continue
		}
		i++
		if i >= len(escaped) {
			break
		}
		if isDigit(escaped[i]) && i+2 < len(escaped) &&
			isDigit(escaped[i+1]) && isDigit(escaped[i+2]) {
			out = append(out, byte((int(escaped[i]-'0'))*100+
				(int(escaped[i+1]-'0'))*10+int(escaped[i+2]-'0')))
			i += 2
			continue
		}
		switch escaped[i] {
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		default:
			out = append(out, escaped[i])
		}
	}
	return out
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
