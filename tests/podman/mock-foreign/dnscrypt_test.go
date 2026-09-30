package main

// The DNSCrypt wire format, asserted against the client that has to read it.
//
// **These cases exist because the consumer is a binary nobody here can change.**
// `packaging/debian/dnscrypt-proxy.sha256` pins dnscrypt-proxy 2.1.18 and
// `scripts/build-deb.sh` builds it from that archive, so a byte layout this mock
// gets wrong is a cell whose foreign resolver silently never comes up: dnscrypt-proxy
// finds no usable certificate, answers nothing at all on 127.0.0.1:15353
// (`proxy.go: processIncomingQuery` returns an empty response when no server is
// registered), and the install transaction stops at its own foreign-resolver
// barrier looking for an installer defect. Every layout below is therefore read
// back out of `dnscrypt_certs.go` and `crypto.go` at 2.1.18 rather than written
// down from memory, and `TestTheLayoutIsTheOneDnscryptProxyReads` states where
// each field comes from.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// The three constants below are NOT re-declared here. They are read from
// `dnscrypt.go`, which is where they are written down once, with the comment
// saying which function of dnscrypt-proxy's each was read out of. A test that
// repeated them would assert the mock against itself: a wrong value in the
// implementation and the same wrong value in the test is a green run and a
// resolver that never starts. `TestTheConstantsAreDnscryptProxys` below pins them
// to the literals at 2.1.18.

func TestTheCertificateIsTheShapeDnscryptProxyReads(t *testing.T) {
	provider := newTestProvider(t)
	now := uint32(1_700_000_000)
	certificate := provider.certificate(7, now-3600, now+3*86400)

	if len(certificate) < 124 {
		t.Fatalf("the certificate is %d bytes; dnscrypt_certs.go refuses anything under 124", len(certificate))
	}
	if got := string(certificate[0:4]); got != certMagic {
		t.Errorf("the certificate does not open with the magic: got %q, want %q", got, certMagic)
	}
	if got := binary.BigEndian.Uint16(certificate[4:6]); got != esVersionXSalsa20 {
		t.Errorf("esVersion is 0x%04x; dnscrypt_certs.go reads 0x0001 as XSalsa20Poly1305", got)
	}
	if got := binary.BigEndian.Uint16(certificate[6:8]); got != ed25519.SignatureSize {
		t.Errorf("the signature length field says %d, want %d", got, ed25519.SignatureSize)
	}

	// The offsets below are the client's, verbatim from dnscrypt_certs.go:
	//
	//	signature := binCert[8:72]
	//	signed    := binCert[72:]
	//	serverPk  = binCert[72:104]
	//	magic     = binCert[104:112]
	//	serial    = binCert[112:116]
	//	tsBegin   = binCert[116:120]
	//	tsEnd     = binCert[120:124]
	//	props     = binCert[126:134]
	if !ed25519.Verify(provider.signing.Public().(ed25519.PublicKey), certificate[72:], certificate[8:72]) {
		t.Error("the signature does not verify over everything after it, which is what " +
			"dnscrypt_certs.go does with `ed25519.Verify(pk, signed, signature)`")
	}
	publishedKey := provider.publicExchange()
	if !bytes.Equal(certificate[72:104], publishedKey[:]) {
		t.Error("the server public key is not where dnscrypt_certs.go reads it from ([72:104])")
	}
	if !bytes.Equal(certificate[104:112], []byte(clientMagic)) {
		t.Error("the client magic is not where dnscrypt_certs.go reads it from ([104:112]), so " +
			"every query this mock is sent would fail the check the client does before it " +
			"decrypts anything")
	}
	if got := binary.BigEndian.Uint32(certificate[112:116]); got != 7 {
		t.Errorf("the serial at [112:116] is %d, want 7", got)
	}
	if got := binary.BigEndian.Uint32(certificate[116:120]); got != now-3600 {
		t.Errorf("the validity start at [116:120] is %d, want %d", got, now-3600)
	}
	if got := binary.BigEndian.Uint32(certificate[120:124]); got != now+3*86400 {
		t.Errorf("the validity end at [120:124] is %d, want %d", got, now+3*86400)
	}
	if got := stamps.ServerInformalProperties(binary.LittleEndian.Uint64(certificate[126:134])); got != requiredProps {
		t.Errorf("the properties at [126:134] are %#x, want %#x. The shipped resolver document "+
			"sets require_dnssec and require_nolog, and a certificate that does not declare both "+
			"is a resolver dnscrypt-proxy refuses to use", got, requiredProps)
	}
}

func TestTheCertificateCarriesThePublicKeyAndNotTheSecret(t *testing.T) {
	// **This is the one field where publishing the wrong half of a key produces
	// no error at all.** The client reads `binCert[72:104]` as the server's
	// *public* key and derives `box.Precompute(shared, thatKey, itsOwnSecret)`.
	// A certificate carrying the secret here still verifies -- the Ed25519
	// signature is over the whole field, so the field is authentic -- and still
	// passes every check the client makes, and then every single query fails to
	// authenticate. The failure a reader sees is "the resolver is unreachable",
	// which is what a network fault looks like.
	provider := newTestProvider(t)
	certificate := provider.certificate(1, 1, 2)
	published := certificate[72:104]
	secret := provider.exchange[:]
	if bytes.Equal(published, secret) {
		t.Fatal("the certificate carries the server's secret key. The client would derive a " +
			"different shared key from it and every query would fail to authenticate")
	}
	// And the published key really is the public half of the secret: a client
	// holding the secret can compute the public key, and that is what it compares
	// against what it was told.
	var derived [32]byte
	curve25519.ScalarBaseMult(&derived, &provider.exchange)
	if !bytes.Equal(published, derived[:]) {
		t.Error("the published key is not the public half of the secret this resolver " +
			"derives its shared key from, so no client could ever open a query from it")
	}
}

func TestACertificateThatExpiredIsRefusedByTheClient(t *testing.T) {
	// The other half of the timestamp: `cert_ignore_timestamp` is false in the
	// shipped document, so a certificate whose window does not contain "now" is
	// skipped and the resolver never becomes usable. A mock that generated its
	// window once and cached it would work on the machine that built it and fail
	// in a cell hours later, so the window is computed per start.
	provider := newTestProvider(t)
	if window := provider.certificate(1, 1, 2); binary.BigEndian.Uint32(window[116:120]) != 1 {
		t.Error("the validity start is not the one the caller asked for")
	}
	if window := provider.certificate(1, 3, 4); binary.BigEndian.Uint32(window[120:124]) != 4 {
		t.Error("the validity end is not the one the caller asked for")
	}
}

func TestTheCertificateSurvivesTheTextRecordItTravelsIn(t *testing.T) {
	// `dnscrypt_certs.go` reads the certificate out of a TXT record through
	// `PackTXTRR`, which unescapes a backslash and three digits, `\t`, `\r`,
	// `\n` and a doubled backslash. A binary certificate is mostly bytes that
	// escaping has to survive, and one that does not is a resolver that never
	// starts -- so the round trip is asserted rather than assumed, and over enough
	// certificates that an unescapable byte value shows up.
	//
	// **The escaping is the DNS library's and the mock must not do its own.**
	// `github.com/miekg/dns` escapes a TXT character-string on the way into the
	// wire and re-escapes it on the way out, so a mock that escaped the string
	// before handing it over produces a certificate that has been escaped twice --
	// which decodes to something that is not a certificate, and to a resolver that
	// answers nothing. The whole path is therefore exercised here, and the bytes
	// compared are the ones the CLIENT would read.
	for round := 0; round < 256; round++ {
		provider := newTestProvider(t)
		// The SAME document the response carries. `certificateResponse` publishes
		// `validCertificate()` -- a window around now, because that is what a
		// resolver has to serve -- and comparing against a differently-windowed
		// certificate would fail for a reason that has nothing to do with
		// escaping.
		certificate := provider.validCertificate()
		request := new(dns.Msg)
		request.SetQuestion(certificateQuestion(), dns.TypeTXT)
		packed := provider.certificateResponse(request)
		if packed == nil {
			t.Fatalf("round %d: the certificate response is empty", round)
		}
		var response dns.Msg
		if err := response.Unpack(packed); err != nil {
			t.Fatalf("round %d: the certificate response did not unpack: %v", round, err)
		}
		if len(response.Answer) != 1 {
			t.Fatalf("round %d: the response carries %d answers, want 1", round, len(response.Answer))
		}
		txt, ok := response.Answer[0].(*dns.TXT)
		if !ok {
			t.Fatalf("round %d: the answer is a %T, want a TXT record", round, response.Answer[0])
		}
		if got := unescapeTXT(strings.Join(txt.Txt, "")); !bytes.Equal(got, certificate) {
			t.Fatalf("round %d: what the client would read is %d bytes and is not the %d-byte "+
				"certificate that went in -- so the certificate does not survive the TXT "+
				"escaping, and this resolver would never become usable",
				round, len(got), len(certificate))
		}
	}
}

func TestTheStampNamesThisResolverAndNothingElse(t *testing.T) {
	// The stamp is the one thing the override writes, and it is what carries the
	// address the foreign branch is pointed at *and* the provider key that
	// authenticates whoever answers there. A stamp that named the wrong key would
	// be a certificate that fails to verify, so both halves are read back out of
	// go-dnsstamps -- the same parser dnscrypt-proxy uses.
	provider := newTestProvider(t)
	stamp, err := provider.stamp("10.89.0.40:443")
	if err != nil {
		t.Fatalf("building the stamp: %v", err)
	}
	parsed, err := stamps.NewServerStampFromString(stamp)
	if err != nil {
		t.Fatalf("the stamp this mock built is not one dnscrypt-proxy can read: %v", err)
	}
	if parsed.Proto != stamps.StampProtoTypeDNSCrypt {
		t.Errorf("the stamp is %v; the shipped resolver document sets dnscrypt_servers = true "+
			"and doh_servers = false, so anything but DNSCrypt is refused", parsed.Proto)
	}
	if parsed.ServerAddrStr != "10.89.0.40:443" {
		t.Errorf("the stamp names %q, want the private listener's address", parsed.ServerAddrStr)
	}
	if parsed.ProviderName != providerName {
		t.Errorf("the stamp names provider %q, want %q -- the name the certificate is "+
			"published under is part of the address a client dials", parsed.ProviderName, providerName)
	}
	// `ServerPk` is go-dnsstamps' name for the *provider* key on a DNSCrypt stamp
	// (dnsstamps.go: `ServerPk []uint8` between the address and the provider
	// name), which is not the server's X25519 key and is easy to mistake for it.
	if !bytes.Equal(parsed.ServerPk, provider.signing.Public().(ed25519.PublicKey)) {
		t.Error("the stamp carries a different provider key from the one that signed the " +
			"certificate, so every certificate this mock publishes would be refused")
	}
}

func TestAnEncryptedQueryIsOpenedAndTheAnswerIsSealedBack(t *testing.T) {
	// The shape of a DNSCrypt exchange, built here with the client's own code so
	// the offsets are the client's:
	//
	//	encrypted = MagicQuery || publicKey || nonce || secretbox(pad(query))
	//	(crypto.go: Encrypt)
	//	response = ServerMagic || serverNonce || secretbox(pad(answer))
	//	(crypto.go: Decrypt)
	//
	// and the one thing that is easy to get wrong and impossible to see: the
	// client's nonce is 12 bytes copied into the front of a 24-byte nonce, and
	// `Decrypt` refuses a response whose server nonce does not start with those
	// same 12 bytes. A mock that sealed its answer under a fresh 24-byte nonce
	// produces a response the client throws away with "Unexpected nonce", which
	// reads as an unreachable resolver.
	provider := newTestProvider(t)
	query := paddedMessage("a query", 512)

	clientPublic, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a client key: %v", err)
	}
	shared := [32]byte{}
	box.Precompute(&shared, clientPublic, &provider.exchange)

	// The client builds a 24-byte nonce, copies twelve random bytes into the front
	// and leaves the rest zero, and puts ONLY THOSE TWELVE on the wire
	// (`crypto.go: Encrypt` appends `nonce[:HalfNonceSize]`). The server has to
	// rebuild the other twelve as zeroes or every query fails to authenticate,
	// and there is nothing in the symptom to say so.
	var clientNonce [24]byte
	if _, err := rand.Read(clientNonce[:halfNonceSize]); err != nil {
		t.Fatalf("generating a client nonce: %v", err)
	}
	sealed := secretbox.Seal(nil, query, &clientNonce, &shared)
	frame := append([]byte{}, []byte(clientMagic)...)
	frame = append(frame, clientPublic[:]...)
	frame = append(frame, clientNonce[:halfNonceSize]...)
	frame = append(frame, sealed...)

	opened, err := provider.open(frame)
	if err != nil {
		t.Fatalf("the query the client would send is not one this mock can open: %v", err)
	}
	if !bytes.Equal(opened, query[:len(opened)]) {
		t.Error("the opened query is not the query that was sealed")
	}

	// Now the response, decrypted with the client's own Decrypt shape.
	var serverNonce [nonceSize]byte
	copy(serverNonce[:halfNonceSize], clientNonce[:halfNonceSize])
	if _, err := rand.Read(serverNonce[12:]); err != nil {
		t.Fatalf("generating a server nonce: %v", err)
	}
	answer := []byte("a response long enough to be a DNS message")
	frame = append([]byte(responseMagic), serverNonce[:]...)
	frame = secretbox.Seal(frame, paddedMessage(string(answer), 512), &serverNonce, &shared)

	if !bytes.Equal(frame[:8], []byte(responseMagic)) {
		t.Fatalf("the response does not open with the server magic: %q", frame[:8])
	}
	if !bytes.Equal(frame[8:8+halfNonceSize], clientNonce[:halfNonceSize]) {
		t.Error("the response's first 12 nonce bytes are not the client's nonce, which is " +
			"what crypto.go's Decrypt checks before it decrypts anything")
	}
	plain, ok := secretbox.Open(nil, frame[8+24:], &serverNonce, &shared)
	if !ok {
		t.Fatal("the sealed answer does not open under the shared key")
	}
	got, err := unpad(plain)
	if err != nil {
		t.Fatalf("the answer did not unpad: %v", err)
	}
	if want := []byte(answer); !bytes.Equal(got, want) {
		t.Errorf("the answer came back as %q, want %q", got, want)
	}
}

func TestAPacketThatIsNotADnscryptQueryIsNotOne(t *testing.T) {
	// The mock has to tell an encrypted query from the two plaintext ones
	// dnscrypt-proxy sends at the same address: the certificate TXT query and, for
	// an XSalsa20 certificate, a plaintext NXDOMAIN probe it uses to decide
	// whether the resolver is "lying". Getting that wrong means the probe is
	// answered as if it were a query, or the certificate is never published.
	provider := newTestProvider(t)
	for _, packet := range [][]byte{
		[]byte("not a query at all"),
		append([]byte{}, []byte(clientMagic)[:7]...),
	} {
		if _, err := provider.open(packet); err == nil {
			t.Errorf("a %d-byte packet was taken for a DNSCrypt query", len(packet))
		}
	}
}

func TestTheCountersRecordEveryNameOnEveryTransport(t *testing.T) {
	// The whole of what the routing scenario reads, so it is the part that has to
	// be a measurement rather than a shape. Counted per name AND per transport,
	// because a counter that only summed would be satisfied by a cell that sent
	// every query over UDP.
	counters := newCounters()
	counters.record("cn-routing.example", "udp")
	counters.record("cn-routing.example", "tcp")
	counters.record("foreign-routing.example", "udp")

	if got := counters.transport("cn-routing.example", "udp"); got != 1 {
		t.Errorf("cn-routing.example over udp is counted %d times, want 1", got)
	}
	if got := counters.transport("cn-routing.example", "tcp"); got != 1 {
		t.Errorf("cn-routing.example over tcp is counted %d times, want 1", got)
	}
	if got := counters.transport("foreign-routing.example", "udp"); got != 1 {
		t.Errorf("foreign-routing.example over udp is counted %d times, want 1", got)
	}
	if got := counters.transport("foreign-routing.example", "tcp"); got != 0 {
		t.Errorf("foreign-routing.example over tcp is counted %d times, want 0 -- a name that "+
			"was only asked over UDP must not read as asked over both", got)
	}
	if got := counters.transport("never-asked.example", "udp"); got != 0 {
		t.Errorf("a name that was never asked reads %d, want 0", got)
	}
	if got := counters.total(); got != 3 {
		t.Errorf("the total is %d, want 3", got)
	}
	// Names are compared case-insensitively and without a trailing dot, because
	// DNS names are neither and a counter keyed on the wire spelling would read
	// zero for a name asked in a different case.
	counters.record("CN-Routing.Example.", "udp")
	if got := counters.transport("cn-routing.example", "udp"); got != 2 {
		t.Errorf("the same name in another case and with a trailing dot counted %d, want 2: "+
			"a DNS name is case-insensitive and the trailing dot is not part of it", got)
	}
}

func TestTheCountersFileCarriesTheStampAndTheCounts(t *testing.T) {
	// The harness reads one file to learn both the stamp it has to write into the
	// override and the counters it asserts on, so a reader cannot get the stamp
	// from one place and the counts from another and compare a resolver that is
	// not the one that answered.
	counters := newCounters()
	counters.setStamp("sdns://AQcAAAAAAAAA")
	counters.setAddress("10.89.0.40:443")
	counters.record("foreign-routing.example", "tcp")
	document := counters.marshal()
	if !bytes.Contains(document, []byte(`"stamp": "sdns://AQcAAAAAAAAA"`)) {
		t.Errorf("the counters document does not carry the stamp:\n%s", document)
	}
	if !bytes.Contains(document, []byte(`"foreign-routing.example"`)) {
		t.Errorf("the counters document does not carry the name:\n%s", document)
	}
	if !bytes.Contains(document, []byte(`"tcp": 1`)) {
		t.Errorf("the counters document does not carry the transport:\n%s", document)
	}
	// And the address, because a stamp with an address and a document with a
	// different one is a reader comparing counts from a resolver it never named.
	if !bytes.Contains(document, []byte(`"address": "10.89.0.40:443"`)) {
		t.Errorf("the counters document does not carry the address:\n%s", document)
	}
}

// newTestProvider is a provider with fixed keys, so a failing case is about the
// layout rather than about which random bytes came out this time.
func newTestProvider(t *testing.T) *provider {
	t.Helper()
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	var exchange [32]byte
	if _, err := rand.Read(exchange[:]); err != nil {
		t.Fatalf("generating a server key: %v", err)
	}
	// A Curve25519 secret key has to be clamped; `box.Precompute` will not do it
	// for us, and an unclamped scalar makes the shared key wrong rather than an
	// error, which is the harder failure to read.
	exchange[0] &= 248
	exchange[31] &= 127
	exchange[31] |= 64
	return &provider{signing: signing, exchange: exchange}
}

func paddedMessage(text string, size int) []byte {
	return pad([]byte(text), size)
}

// The constants, pinned to the literals in dnscrypt-proxy 2.1.18 so that "the
// mock and the client agree" is checked against something outside both of them.
// `common.go` for the magics; `dnscrypt_certs.go`'s switch on `esVersion` for the
// construction.
func TestTheConstantsAreDnscryptProxys(t *testing.T) {
	if certMagic != "DNSC" {
		t.Errorf("the certificate magic is %q; dnscrypt_certs.go compares binCert[:4] against "+
			"CertMagic, which is 0x44 0x4e 0x53 0x43", certMagic)
	}
	if responseMagic != "\x72\x36\x66\x6e\x76\x57\x6a\x38" {
		t.Errorf("the server magic is %q; common.go's ServerMagic is r6fnvWj8", responseMagic)
	}
	if esVersionXSalsa20 != 0x0001 {
		t.Errorf("the esVersion is 0x%04x; dnscrypt_certs.go reads 0x0001 as XSalsa20Poly1305",
			esVersionXSalsa20)
	}
	if queryHeader != 8+32+halfNonceSize {
		t.Errorf("the query header is %d bytes; crypto.go builds MagicQuery(8) + public key(32) "+
			"+ nonce[:HalfNonceSize](%d), and the other half of the nonce is the zero padding "+
			"the client left in its own 24-byte slice", queryHeader, halfNonceSize)
	}
	if halfNonceSize != nonceSize/2 || nonceSize != 24 {
		t.Errorf("the nonce is %d bytes and its half is %d; crypto.go's NonceSize is 24 and "+
			"HalfNonceSize is 12", nonceSize, halfNonceSize)
	}
}
