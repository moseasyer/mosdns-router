// Package echconfig parses and validates the ECHConfigList that a DNS HTTPS RR
// carries in its ech SvcParam, and hands back the exact bytes to forward.
//
// This is a trust boundary with a one-sided failure mode. The bytes Parse
// accepts are put verbatim into an SvcParamValue, and a browser then encrypts its
// ClientHello to the HPKE public key inside them. A misparse is therefore not a
// cosmetic fault: forwarding bytes the browser reads as a different key, a
// different public name, or a different maximum_name_length than the one this
// router checked is handing a client a guarantee nobody verified, and forwarding
// a version this router never read is worse than forwarding nothing. So every
// rule below refuses rather than repairs, and a refusal is always an error with
// no result beside it, because a caller in strict mode has to be able to fail
// closed on a signal it cannot mistake for "nothing to do here".
//
// The wire layout is RFC 9849 Section 4, and it is pinned byte for byte by
// TestFixtureFieldOffsets rather than described here, because a layout change
// has to be a failing test. Three points in it are worth stating outright,
// because each is a place where reading it differently is silent:
//
//   - The SvcParamValue is the ECHConfigList *including* the outer uint16 length.
//     RFC 9848 Section 3 says so explicitly ("including the redundant length
//     prefix"), and List.Raw keeps those two bytes. miekg/dns states the same
//     thing on dns.SVCBECHConfig.ECH and copies the slice verbatim, so stripping
//     the prefix here, or adding a second one, would corrupt the RR.
//   - The public name carries a one-byte length. RFC 9849 Section 4 writes it as
//     `opaque public_name<1..255>`, and that range is a uint8 count that may not
//     be zero: the field runs to the extensions vector's own length. A parser
//     that reads it as an implicit-length run of bytes takes the length byte
//     itself as the first character of the name.
//   - A cipher suite is a kdf_id and an aead_id, four bytes, so the suite vector
//     is a two-byte byte count followed by whole suites and nothing else.
//
// The AEADs recognized here are the three HPKE AEADs in RFC 9180 Section 7.3 that
// current clients implement: AES-128-GCM (0x0001), AES-256-GCM (0x0002) and
// ChaCha20Poly1305 (0x0003). That is the same set Go 1.25's crypto/tls accepts
// and the set BoringSSL and Firefox offer, and it is the whole of what a browser
// can encrypt with today. Anything else is refused, including the export-only
// 0x0010 and the unassigned 0x0000, because a list whose only suites nobody
// implements is a list that silently disables ECH for the client that receives
// it. The single KDF recognized is HKDF-SHA256 (0x0001), the only one in RFC 9180
// Section 7.2 in wide use, and a suite counts as usable only when both halves of
// the pair are recognized.
package echconfig

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

const (
	// versionFe0d is the ECH version whose contents layout this package reads.
	// RFC 9849 Section 4 selects the layout on the version, so a config
	// announcing anything else is a config whose bytes mean something else.
	versionFe0d = 0xfe0d

	// kemDHKEMX25519HKDFSHA256 is HPKE KEM 0x0020 from RFC 9180 Section 7.1, the
	// KEM every deployed ECH config uses. RFC 9180 fixes its public key at 32
	// bytes, so a key of any other size is a key no client can deserialize.
	kemDHKEMX25519HKDFSHA256 = 0x0020
	x25519PublicKeyLen       = 32

	// The HPKE algorithm identifiers this router recognizes. The AEADs are the
	// three in RFC 9180 Section 7.3 that browsers implement; the KDF is the only
	// one in RFC 9180 Section 7.2 in use. See the package comment.
	kdfHKDFSHA256        = 0x0001
	aeadAES128GCM        = 0x0001
	aeadAES256GCM        = 0x0002
	aeadChaCha20Poly1305 = 0x0003

	// hpkeSuiteLen is the size of a HpkeSymmetricCipherSuite: a kdf_id and an
	// aead_id, with no padding.
	hpkeSuiteLen = 4

	// RFC 9849 Section 4 bounds the cipher-suite vector at 4..2^16-4, so it holds
	// at least one whole suite and never more than the vector can carry.
	minCipherSuitesLength = hpkeSuiteLen
	maxCipherSuitesLength = 0xfffc

	// RFC 9849 Section 4 bounds the public name at 1..255 octets, of which the
	// one-byte length already enforces the upper half. The name also has to be a
	// DNS name in preferred name syntax (RFC 9849 Section 6.1.7), which caps a
	// label at 63 octets (RFC 1035) and the name at 253.
	maxDNSNameLength = 253
	maxLabelLength   = 63

	// A public name identifies the client-facing server by certificate, so a
	// single label is not a name anything can be issued for.
	minLabelCount = 2

	// mandatoryExtensionBit is the high order bit of an extension type, which
	// RFC 9849 Section 4.2 uses to mark an extension a client cannot ignore.
	mandatoryExtensionBit = 0x8000

	// configHeaderLen is an ECHConfig's version and length, in front of its
	// contents.
	configHeaderLen = 4
)

// CipherSuite is one HPKE symmetric cipher suite from an ECHConfig: the key
// derivation function and the AEAD a client may use to seal the ClientHelloInner.
type CipherSuite struct {
	KDFID  uint16
	AEADID uint16
}

// Config is one validated ECHConfig: the HPKE key a client encrypts to, and the
// metadata that goes with it. Every field is read from the config's own declared
// length, and a config is only in a List if every one of them passed the checks
// the package comment describes.
type Config struct {
	// Version is the ECH version. Only 0xfe0d is ever in a List, because a
	// version whose contents layout this package has not read is refused.
	Version uint16
	// ConfigID names this key configuration to the client-facing server, which
	// Section 4.1 of RFC 9849 keeps distinct across a server's own keys.
	ConfigID uint8
	// KEMID is the HPKE KEM the public key belongs to. Only 0x0020
	// (DHKEM(X25519, HKDF-SHA256)) is ever in a List.
	KEMID uint16
	// PublicKey is the HPKE public key, always 32 bytes in a List. It is a copy,
	// not a view of the caller's buffer.
	PublicKey []byte
	// CipherSuites are the suite pairs the config advertises, in the order they
	// were on the wire. At least one is usable by a current client, and a List
	// holds no config whose config_id another config in the same list claims.
	CipherSuites []CipherSuite
	// MaximumNameLength is the longest backend server name if the config knows
	// it, and zero when it does not. It feeds a client's padding and constrains
	// nothing.
	MaximumNameLength uint8
	// PublicName is the client-facing server's own DNS name, which is what a
	// client authenticates when the ECH attempt is rejected.
	PublicName string
}

// List is a validated ECHConfigList: one or more usable configs, in the
// preference order the server published, together with the bytes to forward.
type List struct {
	// Raw is the whole input, byte for byte, outer uint16 list length included.
	// It is what belongs in a dns.SVCBECHConfig, and it is a copy rather than a
	// view of the caller's buffer. Nothing here rewrites it: the bytes a browser
	// reads have to be the bytes that were checked, so an extension this router
	// does not interpret still reaches the client that does.
	Raw []byte
	// Configs are the configs in the order they appeared, which RFC 9849
	// Section 4 defines as decreasing preference.
	Configs []Config
}

// Parse reads an ECHConfigList and refuses anything it cannot vouch for. The
// input is the SvcParamValue of an ech SvcParam, outer length prefix included.
//
// Every length is compared with the bytes actually left before anything is read
// or allocated, so a declared length beyond the buffer is a refusal rather than a
// truncation, a read past the end, or an allocation of a size an attacker chose.
// On any refusal the result is nil, so a caller cannot read an empty list as a
// list with nothing wrong in it.
func Parse(b []byte) (*List, error) {
	list := &reader{buf: b}
	declaredListLength, err := list.uint16("list length")
	if err != nil {
		return nil, err
	}
	// The list length counts every byte after itself, so it has to account for
	// exactly the rest of the input. This is also what makes Raw the whole
	// SvcParamValue: a list that did not fill its own declared length would
	// carry bytes no length accounts for.
	if got := len(b) - 2; int(declaredListLength) != got {
		return nil, fmt.Errorf("the list length declares %d bytes but the list carries %d", declaredListLength, got)
	}

	// A list with no config in it offers a browser no ECH at all, which is not a
	// success: the caller has to see an error to fail closed on it.
	var configs []Config
	seen := make(map[uint8]struct{})
	for list.remaining() > 0 {
		// Each config starts with a four-byte header, so fewer than four bytes
		// left is a list whose declared length does not divide into configs.
		if list.remaining() < configHeaderLen {
			return nil, fmt.Errorf("too few bytes left in the list (%d) for the %d-byte ECHConfig header",
				list.remaining(), configHeaderLen)
		}
		config, err := parseConfig(list)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[config.ConfigID]; duplicate {
			return nil, fmt.Errorf("two ECHConfigs in the list claim config_id %#02x, which leaves a client unable to say which key it encrypted to", config.ConfigID)
		}
		seen[config.ConfigID] = struct{}{}
		configs = append(configs, config)
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("the list carries no ECHConfig, so there is nothing to offer a client")
	}

	// Copied, not viewed: the bytes a browser is about to encrypt to must not be
	// reachable through a buffer the caller still holds.
	return &List{Raw: slices.Clone(b), Configs: configs}, nil
}

// parseConfig reads one ECHConfig from the front of list, validating it as it
// goes. Every read is bounded by the config's own declared length, and the
// config's fields have to fill that length exactly, because a config whose length
// and fields disagree is one whose fields this parser located by accident.
func parseConfig(list *reader) (Config, error) {
	var config Config

	version, err := list.uint16("version")
	if err != nil {
		return Config{}, err
	}
	contentsLength, err := list.uint16("config length")
	if err != nil {
		return Config{}, err
	}
	if version != versionFe0d {
		// Refused rather than skipped. RFC 9849 Section 4 has a client ignore a
		// config it cannot parse, but this router forwards the whole list as one
		// opaque value, so it cannot drop one config out of it and still be
		// forwarding what it read. Handing a browser a list it will partly
		// discard is a weaker guarantee than handing it none.
		return Config{}, fmt.Errorf("ECHConfig has version %#04x, want the implemented %#04x", version, versionFe0d)
	}
	// There is deliberately no separate check that the config length is at least
	// as large as the layout needs. The contents are taken against the bytes
	// actually left, and every field below is read against the contents, so a
	// length too small for the fields fails on the first one that does not fit
	// and a check that only restated that arithmetic would be a second place for
	// the same bound to be wrong.
	contents, err := list.take(int(contentsLength), "config length")
	if err != nil {
		return Config{}, err
	}

	// Every read below is against the config's own contents, never the rest of
	// the list, so a config that lies about its length cannot reach into its
	// neighbour. The wrap names the config the failure belongs to, because a read
	// that runs out here is either a length that does not cover its fields or a
	// field carrying a length that does not fit, and the inner error says which.
	fields := &reader{buf: contents}
	if err := parseConfigContents(fields, &config); err != nil {
		return Config{}, fmt.Errorf("ECHConfig: config length %d: %w", contentsLength, err)
	}
	if left := fields.remaining(); left != 0 {
		return Config{}, fmt.Errorf("the config length %d covers %d bytes at the end of the config that no field claims", contentsLength, left)
	}
	return config, nil
}

// parseConfigContents reads an ECHConfigContents and checks every field against
// the rules the package comment describes.
func parseConfigContents(r *reader, config *Config) error {
	configID, err := r.uint8("config_id")
	if err != nil {
		return err
	}
	kemID, err := r.uint16("kem_id")
	if err != nil {
		return err
	}
	// The key length is read before the key, and compared with what is left
	// before the key is taken, so nothing here is sized by a declared value.
	keyLength, err := r.uint16("public key length")
	if err != nil {
		return err
	}
	key, err := r.take(int(keyLength), "public key")
	if err != nil {
		return err
	}
	suitesLength, err := r.uint16("cipher suite vector length")
	if err != nil {
		return err
	}
	suiteBytes, err := r.take(int(suitesLength), "cipher suite vector")
	if err != nil {
		return err
	}
	// The vector is read into its pairs here, before the fields after it, so a
	// count that is not a whole number of suites is refused as a suite fault
	// rather than shifting every later field by the remainder and getting a
	// perfectly well formed field blamed for it.
	suites, usable, err := parseCipherSuites(suiteBytes)
	if err != nil {
		return err
	}
	maximumNameLength, err := r.uint8("maximum_name_length")
	if err != nil {
		return err
	}
	nameLength, err := r.uint8("public name length")
	if err != nil {
		return err
	}
	name, err := r.take(int(nameLength), "public name")
	if err != nil {
		return err
	}
	extensionsLength, err := r.uint16("extensions length")
	if err != nil {
		return err
	}
	extensionBytes, err := r.take(int(extensionsLength), "extensions block")
	if err != nil {
		return err
	}

	// Lengths are all read and checked now. The checks below are on values, and
	// they cannot reach outside the bytes already taken.
	if kemID != kemDHKEMX25519HKDFSHA256 {
		return fmt.Errorf("the KEM ID is %#04x, want the one implemented, %#04x (DHKEM(X25519, HKDF-SHA256))", kemID, kemDHKEMX25519HKDFSHA256)
	}
	if len(key) != x25519PublicKeyLen {
		return fmt.Errorf("the public key is %d bytes, want the %d RFC 9180 fixes for DHKEM(X25519, HKDF-SHA256)", len(key), x25519PublicKeyLen)
	}
	if err := parseExtensions(extensionBytes); err != nil {
		return err
	}

	if !usable {
		return fmt.Errorf("the config offers no cipher suite a current client implements, so it would silently disable ECH for the browser that received it")
	}
	if !validPublicName(string(name)) {
		return fmt.Errorf("the public name %q is not a name a client can authenticate, so the config is ignored", name)
	}

	config.Version = versionFe0d
	config.ConfigID = configID
	config.KEMID = kemDHKEMX25519HKDFSHA256
	config.PublicKey = slices.Clone(key)
	config.CipherSuites = suites
	config.MaximumNameLength = maximumNameLength
	config.PublicName = string(name)
	return nil
}

// parseCipherSuites reads the suite vector into its pairs and reports whether at
// least one of them is a pair a current client implements.
//
// The size rules are enforced here rather than left to the caller, so the walk
// below is total on its own terms: the vector is known to be a whole number of
// four-byte suites by the time the loop runs, and no caller can hand this
// something that would read past the end. Nothing is allocated from a declared
// value either; the slice is grown as suites are read.
func parseCipherSuites(suiteBytes []byte) ([]CipherSuite, bool, error) {
	if len(suiteBytes) < minCipherSuitesLength || len(suiteBytes) > maxCipherSuitesLength {
		return nil, false, fmt.Errorf("the cipher suite vector is %d bytes, want between %d and %d", len(suiteBytes), minCipherSuitesLength, maxCipherSuitesLength)
	}
	if len(suiteBytes)%hpkeSuiteLen != 0 {
		return nil, false, fmt.Errorf("the cipher suite vector is %d bytes, which is not a whole number of %d-byte suites", len(suiteBytes), hpkeSuiteLen)
	}
	var suites []CipherSuite
	usable := false
	for len(suiteBytes) > 0 {
		var suite CipherSuite
		suite.KDFID = binary.BigEndian.Uint16(suiteBytes)
		suite.AEADID = binary.BigEndian.Uint16(suiteBytes[2:])
		suiteBytes = suiteBytes[hpkeSuiteLen:]
		if usableCipherSuite(suite) {
			usable = true
		}
		suites = append(suites, suite)
	}
	return suites, usable, nil
}

// usableCipherSuite reports whether a client can build an HPKE context from this
// pair. Both halves have to be recognized: a known AEAD behind an unknown KDF is
// no more buildable than the other way round.
func usableCipherSuite(suite CipherSuite) bool {
	if suite.KDFID != kdfHKDFSHA256 {
		return false
	}
	switch suite.AEADID {
	case aeadAES128GCM, aeadAES256GCM, aeadChaCha20Poly1305:
		return true
	default:
		return false
	}
}

// parseExtensions walks an ECHConfig's extensions block. The bytes are carried to
// the client inside Raw whatever this finds; what it decides is whether the
// config itself is safe to forward, because RFC 9849 Section 4.2 has a client
// ignore a config carrying an extension it cannot honour.
func parseExtensions(extensionBytes []byte) error {
	r := &reader{buf: extensionBytes}
	seen := make(map[uint16]struct{})
	for r.remaining() > 0 {
		extensionType, err := r.uint16("extension type")
		if err != nil {
			return fmt.Errorf("the extensions block: %w", err)
		}
		if extensionType&mandatoryExtensionBit != 0 {
			// The high order bit marks the extension mandatory, and a client
			// that cannot honour it has to ignore the config. Forwarding one
			// would hand a browser a config it must drop, which is a downgrade
			// dressed as a success.
			return fmt.Errorf("the extensions block carries the mandatory extension type %#04x, which this router cannot honour", extensionType)
		}
		if _, duplicate := seen[extensionType]; duplicate {
			// RFC 9849 Section 4.2 allows extensions in any order but forbids
			// more than one of a type, so two peers could disagree about which
			// data belongs to the extension.
			return fmt.Errorf("the extensions block carries extension type %#04x more than once", extensionType)
		}
		seen[extensionType] = struct{}{}

		dataLength, err := r.uint16(fmt.Sprintf("data length of extension %#04x", extensionType))
		if err != nil {
			return fmt.Errorf("the extensions block: %w", err)
		}
		if _, err := r.take(int(dataLength), fmt.Sprintf("data of extension %#04x", extensionType)); err != nil {
			return fmt.Errorf("the extensions block: %w", err)
		}
	}
	return nil
}

// validPublicName reports whether name is a public name RFC 9849 Section 6.1.7
// has a client accept: a dot-separated sequence of LDH labels that neither begins
// nor ends with a dot, every label at most 63 octets, the name at most 253, and a
// final label that cannot be read as an IPv4 literal.
func validPublicName(name string) bool {
	if len(name) == 0 || len(name) > maxDNSNameLength {
		return false
	}
	labels := strings.Split(name, ".")
	// A leading or a trailing dot is an empty label, which the count below
	// rejects, so this is only the whole-name length and the label count.
	if len(labels) < minLabelCount {
		return false
	}
	for _, label := range labels {
		if !validLDHLabel(label) {
			return false
		}
	}
	return !readsAsIPv4Literal(labels[len(labels)-1])
}

// validLDHLabel reports whether label is a letter-digit-hyphen label of at most 63
// octets that neither begins nor ends with a hyphen, which is the preferred name
// syntax RFC 5890 Section 2.3.1 defines and RFC 9849 Section 6.1.7 requires.
func validLDHLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelLength {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(label)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// readsAsIPv4Literal reports whether the final label of a public name would be
// read as an IPv4 address. RFC 9849 Section 6.1.7 has a client ignore such a name
// because the reference identity it authenticates would not be the hostname the
// operator intended. WHATWG URL parsing and RFC 3986 Section 7.4 accept both an
// all-digit label and a "0x" or "0X" label of hex digits here, which is why both
// are refused.
func readsAsIPv4Literal(label string) bool {
	if label == "" {
		return false
	}
	allDigits := true
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	if len(label) < 2 || label[0] != '0' || (label[1] != 'x' && label[1] != 'X') {
		return false
	}
	// The hex digits may be empty: RFC 9849 Section 6.1.7 writes "possibly
	// empty" on purpose, so "0x" on its own is refused too.
	for i := 2; i < len(label); i++ {
		c := label[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// reader walks a byte slice from the front. Every read is compared with the bytes
// actually left before it happens, so a length read off the wire is a bound to
// check rather than a size to trust.
type reader struct {
	buf []byte
	off int
}

// remaining is how many bytes are left to read.
func (r *reader) remaining() int {
	return len(r.buf) - r.off
}

// take returns the next n bytes as a view of the underlying buffer, or an error
// naming field if fewer than n are left. It does not allocate, and n is never
// negative: every caller derives it from a uint8 or uint16 it has just read.
func (r *reader) take(n int, field string) ([]byte, error) {
	if n > r.remaining() {
		return nil, fmt.Errorf("the %s declares %d bytes but only %d are left", field, n, r.remaining())
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

// uint8 reads one byte as the named field.
func (r *reader) uint8(field string) (uint8, error) {
	b, err := r.take(1, field)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// uint16 reads two bytes as a big-endian uint16, the named field.
func (r *reader) uint16(field string) (uint16, error) {
	b, err := r.take(2, field)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}
