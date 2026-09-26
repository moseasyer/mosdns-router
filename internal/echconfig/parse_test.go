package echconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The fixture is the public ECHConfigList Cloudflare serves for its ECH
// deployment. It is public, non-secret material: an ECHConfigList travels in
// cleartext inside an HTTPS RR, and the HPKE public key in it encrypts towards
// the server rather than from it, so committing it discloses nothing. Every test
// reads this one file rather than a copy pasted below, so a corrected fixture
// cannot leave a second stale copy behind for a test to keep passing against.
//
// The decoded list is 71 bytes and RFC 9849 Section 4 lays them out as the table
// below. The offsets were counted by hand from those 71 bytes, and the arithmetic
// that fixes them is:
//
//   - 0x0045 at offset 0 is 69, which is 71 minus this length field's own two
//     bytes, so the list length covers every byte after offset 1.
//   - 0xfe0d at offset 2 is the ECH version.
//   - 0x0041 at offset 4 is 65, which is the 65 bytes from offset 6 to offset
//     70, so one config fills the list exactly.
//   - 0xb8 at offset 6 is the config_id. 0x0020 at offset 7 is kem_id 0x0020,
//     DHKEM(X25519, HKDF-SHA256) from RFC 9180 Section 7.1.
//   - 0x0020 at offset 9 is 32, so the HPKE public key occupies offsets 11 to
//     42 and the cipher-suite vector length sits at offset 43.
//   - 0x0004 at offset 43 is a byte count of 4, and a HpkeSymmetricCipherSuite is
//     a kdf_id and an aead_id, so it holds exactly one suite: 0x0001
//     (HKDF-SHA256) and 0x0001 (AES-128-GCM).
//   - 0x00 at offset 49 is maximum_name_length. RFC 9849 Section 4 allows zero
//     here for "not known", and Cloudflare publishes zero.
//   - 0x12 at offset 50 is 18, which is the length of "cloudflare-ech.com", so
//     the name occupies offsets 51 to 68. The count is one byte wide, which is
//     what `opaque public_name<1..255>` in RFC 9849 Section 4 describes: a uint8
//     that may not be zero.
//   - 0x0000 at offset 69 is the extensions byte count, which leaves the list at
//     exactly 71 bytes.
//
// Every one of the 71 bytes is claimed by exactly one row, so a field read from
// the wrong offset cannot still parse: it lands on another row's value, and
// TestFixtureFieldOffsets fails.
const (
	offListLength         = 0  // uint16, counts every byte after itself
	offVersion            = 2  // uint16
	offConfigLength       = 4  // uint16, counts every byte after itself
	offConfigID           = 6  // uint8
	offKEMID              = 7  // uint16
	offPublicKeyLength    = 9  // uint16
	offPublicKey          = 11 // 32 bytes
	offCipherSuitesLength = 43 // uint16, a byte count for the suite vector
	offSuiteKDFID         = 45 // uint16
	offSuiteAEADID        = 47 // uint16
	offMaximumNameLength  = 49 // uint8
	offPublicNameLength   = 50 // uint8
	offPublicName         = 51 // 18 bytes
	offExtensionsLength   = 69 // uint16

	// The list holds exactly one config, so these are the two lengths the
	// fixture's own bytes declare.
	fixtureTotalLen     = 71
	fixtureListLength   = 0x0045
	fixtureConfigLength = 0x0041

	// The fixture's public name, in the two forms the tests need it.
	fixturePublicName    = "cloudflare-ech.com"
	fixturePublicNameLen = 18

	// The fixture's public key, written out so the offset table and the parsed
	// value can each be checked against something other than the other.
	fixturePublicKeyHex  = "5e59f2f2774f0caebc50833dced30b3587f8faca1807d7ee234df150e58eaa6b"
	fixturePublicNameHex = "636c6f7564666c6172652d6563682e636f6d"
)

// loadFixture decodes the committed list.
func loadFixture(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile("testdata/cloudflare-ech-base64.txt")
	if err != nil {
		t.Fatalf("read the ECHConfigList fixture: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("the ECHConfigList fixture is not standard base64: %v", err)
	}
	return raw
}

// buildList assembles a one-config ECHConfigList from body, which is everything
// from the config's version field to the end of the list, and fills in the two
// length fields: the outer list length counts every byte after itself, and the
// config length counts every byte after itself inside the config.
//
// The caller states the total size and both lengths as literals and this helper
// has them checked, so the helper's arithmetic is verified by every case that
// uses it instead of being trusted. A miscount fails as a length mismatch rather
// than quietly exercising a different list than the one named.
func buildList(t *testing.T, body []byte, wantTotal, wantListLength, wantConfigLength int) []byte {
	t.Helper()
	list := make([]byte, 0, 2+len(body))
	list = append(list, 0x00, 0x00)
	list = append(list, body...)
	if len(list) != wantTotal {
		t.Fatalf("built a %d-byte list, want %d", len(list), wantTotal)
	}
	binary.BigEndian.PutUint16(list[offListLength:], uint16(len(list)-2))
	binary.BigEndian.PutUint16(list[offConfigLength:], uint16(len(list)-6))
	if got := int(binary.BigEndian.Uint16(list[offListLength:])); got != wantListLength {
		t.Fatalf("built a list declaring a %d-byte list length, want %d", got, wantListLength)
	}
	if got := int(binary.BigEndian.Uint16(list[offConfigLength:])); got != wantConfigLength {
		t.Fatalf("built a list declaring a %d-byte config length, want %d", got, wantConfigLength)
	}
	return list
}

// configHead is the fixture's version field through the end of its public key:
// everything a structural variant keeps and the field under test follows.
func configHead(t *testing.T) []byte {
	t.Helper()
	raw := loadFixture(t)
	return append([]byte(nil), raw[offVersion:offPublicKey+32]...)
}

// suitesVector assembles a cipher-suite vector: the two-byte byte count, then
// each suite's kdf_id and aead_id. RFC 9849 Section 4 defines a
// HpkeSymmetricCipherSuite as those two uint16s and nothing else, so a suite is
// four bytes and this length is always a multiple of four.
func suitesVector(suites ...[]byte) []byte {
	vector := make([]byte, 0, 2+4*len(suites))
	vector = binary.BigEndian.AppendUint16(vector, uint16(4*len(suites)))
	for _, suite := range suites {
		vector = append(vector, suite...)
	}
	return vector
}

// oneSuite is the suite the fixture itself advertises: HKDF-SHA256 with
// AES-128-GCM.
var oneSuite = []byte{0x00, 0x01, 0x00, 0x01}

// configTail assembles the bytes after a config's cipher-suite vector:
// maximum_name_length, the one-byte public name length, the name, and the
// extensions block behind its two-byte byte count.
func configTail(maximumNameLength byte, publicName, extensions []byte) []byte {
	tail := []byte{maximumNameLength, byte(len(publicName))}
	tail = append(tail, publicName...)
	tail = binary.BigEndian.AppendUint16(tail, uint16(len(extensions)))
	return append(tail, extensions...)
}

// withPublicName rebuilds the fixture around a different public name, leaving
// every other field exactly as Cloudflare published it. The one-byte name length
// and both enclosing lengths are recomputed, and the caller states the name
// length it expects so a miscount fails as a length mismatch.
func withPublicName(t *testing.T, publicName string) []byte {
	t.Helper()
	raw := loadFixture(t)
	if len(publicName) > 255 {
		t.Fatalf("a public name of %d bytes cannot be expressed in the one-byte length field", len(publicName))
	}
	list := make([]byte, 0, fixtureTotalLen)
	list = append(list, raw[:offPublicNameLength]...)
	list = append(list, byte(len(publicName)))
	list = append(list, publicName...)
	list = append(list, 0x00, 0x00) // the fixture's empty extensions block
	binary.BigEndian.PutUint16(list[offConfigLength:], uint16(len(list)-6))
	binary.BigEndian.PutUint16(list[offListLength:], uint16(len(list)-2))
	if got := int(list[offPublicNameLength]); got != len(publicName) {
		t.Fatalf("built a name length of %d, want %d", got, len(publicName))
	}
	return list
}

// assertRefused checks the fail-closed contract: a list the parser refuses must
// come back as an error and no result at all. Returning an empty List beside an
// error is the shape that would let a caller in strict mode read "no configs" as
// "nothing wrong here" and carry on with a stripped RR.
func assertRefused(t *testing.T, name string, list []byte, wantRefusal string) {
	t.Helper()
	got, err := Parse(list)
	if err == nil && got == nil {
		t.Fatalf("Parse accepted a list with %s and returned no result at all", name)
	}
	if err == nil {
		t.Fatalf("Parse accepted a list with %s and returned %d configs from %d bytes", name, len(got.Configs), len(list))
	}
	if got != nil {
		t.Fatalf("Parse refused a list with %s but also returned %+v; a refused list must yield no result at all", name, got)
	}
	if !strings.Contains(err.Error(), wantRefusal) {
		t.Fatalf("Parse refused a list with %s as %q, want a refusal naming %q", name, err, wantRefusal)
	}
}

// TestFixtureFieldOffsets pins each field of the fixture to the byte offset and
// the value RFC 9849 Section 4 puts there, and then checks that the rows tile the
// 71 bytes exactly. The break it catches is a parser that reads a field one or
// more bytes off: that misparse still returns plausible values, and a browser
// would encrypt its ClientHello to whatever key the misparse produced. A layout
// change has to be a failing test here, not a silent change of meaning.
func TestFixtureFieldOffsets(t *testing.T) {
	raw := loadFixture(t)
	if len(raw) != fixtureTotalLen {
		t.Fatalf("the fixture decodes to %d bytes, want %d", len(raw), fixtureTotalLen)
	}

	claimed := make([]bool, fixtureTotalLen)
	for _, field := range []struct {
		name   string
		offset int
		length int
		want   string
	}{
		{"ECHConfigList length", offListLength, 2, "0045"},
		{"ECH version", offVersion, 2, "fe0d"},
		{"ECHConfig length", offConfigLength, 2, "0041"},
		{"config_id", offConfigID, 1, "b8"},
		{"kem_id", offKEMID, 2, "0020"},
		{"public key length", offPublicKeyLength, 2, "0020"},
		{"public key", offPublicKey, 32, fixturePublicKeyHex},
		{"cipher suite vector length", offCipherSuitesLength, 2, "0004"},
		{"cipher suite kdf_id", offSuiteKDFID, 2, "0001"},
		{"cipher suite aead_id", offSuiteAEADID, 2, "0001"},
		{"maximum_name_length", offMaximumNameLength, 1, "00"},
		{"public name length", offPublicNameLength, 1, "12"},
		{"public name", offPublicName, fixturePublicNameLen, fixturePublicNameHex},
		{"extensions length", offExtensionsLength, 2, "0000"},
	} {
		if got := hex.EncodeToString(raw[field.offset : field.offset+field.length]); got != field.want {
			t.Errorf("%s at offset %d is %s, want %s", field.name, field.offset, got, field.want)
		}
		// A gap is a field the parser would skip without noticing; an overlap is
		// two rows claiming one field's bytes.
		for i := field.offset; i < field.offset+field.length; i++ {
			if claimed[i] {
				t.Errorf("offset %d is claimed by more than one field", i)
			}
			claimed[i] = true
		}
	}
	for i, isClaimed := range claimed {
		if !isClaimed {
			t.Errorf("offset %d of the fixture belongs to no field in the layout above", i)
		}
	}
}

// TestParseReadsEveryFixtureField proves each parsed value is the one the bytes
// at that offset carry, written here as literals from the layout above rather
// than taken from the parser. The break it catches is a parser that reports a
// field it did not read from the wire, or reports the wrong field under a right
// field's name.
func TestParseReadsEveryFixtureField(t *testing.T) {
	list, err := Parse(loadFixture(t))
	if err != nil {
		t.Fatalf("Parse refused the committed Cloudflare list: %v", err)
	}
	if len(list.Configs) != 1 {
		t.Fatalf("Parse returned %d configs, want the 1 the fixture holds", len(list.Configs))
	}

	config := list.Configs[0]
	if config.Version != 0xfe0d {
		t.Errorf("Version = %#04x, want 0xfe0d", config.Version)
	}
	if config.ConfigID != 0xb8 {
		t.Errorf("ConfigID = %#02x, want 0xb8", config.ConfigID)
	}
	if config.KEMID != 0x0020 {
		t.Errorf("KEMID = %#04x, want 0x0020 (DHKEM(X25519, HKDF-SHA256))", config.KEMID)
	}
	if got := hex.EncodeToString(config.PublicKey); got != fixturePublicKeyHex {
		t.Errorf("PublicKey = %s, want %s", got, fixturePublicKeyHex)
	}
	if len(config.CipherSuites) != 1 || config.CipherSuites[0] != (CipherSuite{KDFID: 0x0001, AEADID: 0x0001}) {
		t.Errorf("CipherSuites = %+v, want the single suite {KDFID:0x0001 AEADID:0x0001} (HKDF-SHA256, AES-128-GCM)", config.CipherSuites)
	}
	if config.MaximumNameLength != 0x00 {
		t.Errorf("MaximumNameLength = %d, want 0; RFC 9849 Section 4 allows zero for \"not known\" and Cloudflare publishes zero", config.MaximumNameLength)
	}
	if config.PublicName != fixturePublicName {
		t.Errorf("PublicName = %q, want %q", config.PublicName, fixturePublicName)
	}
}

// TestParseReadsMutableFieldsFromTheWire changes one byte of the fixture and
// proves the matching field is the one that moves, with the new value stated as a
// literal, and that the fields pinned to their only legal value do not move. A
// field with only one legal value cannot be exercised this way and is covered by
// the refusal tests instead: a config_id is any byte, but a kem_id or a kdf_id
// that is not the recognized value is a refusal rather than a value to read back.
//
// The break it catches is a parser that hardcodes a field, reads it from a
// neighbouring offset, or returns a field the wire never carried.
func TestParseReadsMutableFieldsFromTheWire(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		offset int
		value  byte
		check  func(*testing.T, *Config)
	}{
		{
			name:   "config_id",
			offset: offConfigID,
			value:  0x07,
			check: func(t *testing.T, config *Config) {
				if config.ConfigID != 0x07 {
					t.Errorf("ConfigID = %#02x, want 0x07", config.ConfigID)
				}
			},
		},
		{
			name:   "the first public key byte",
			offset: offPublicKey,
			value:  0x00,
			check: func(t *testing.T, config *Config) {
				want, err := hex.DecodeString(fixturePublicKeyHex)
				if err != nil {
					t.Fatalf("decode the fixture key literal: %v", err)
				}
				want[0] = 0x00
				if got := hex.EncodeToString(config.PublicKey); got != hex.EncodeToString(want) {
					t.Errorf("PublicKey = %s, want %s, the published key with only its first byte cleared", got, hex.EncodeToString(want))
				}
			},
		},
		{
			// 0x0003 is ChaCha20Poly1305, the other AEAD browsers offer, so the
			// suite stays usable and only the aead_id may move. The aead_id is
			// the uint16 at offset 47, so it is the byte at 48 that carries its
			// low octet.
			name:   "the cipher suite aead_id",
			offset: offSuiteAEADID + 1,
			value:  0x03,
			check: func(t *testing.T, config *Config) {
				if len(config.CipherSuites) != 1 || config.CipherSuites[0] != (CipherSuite{KDFID: 0x0001, AEADID: 0x0003}) {
					t.Errorf("CipherSuites = %+v, want [{KDFID:0x0001 AEADID:0x0003}]", config.CipherSuites)
				}
			},
		},
		{
			name:   "maximum_name_length",
			offset: offMaximumNameLength,
			value:  0x20,
			check: func(t *testing.T, config *Config) {
				if config.MaximumNameLength != 0x20 {
					t.Errorf("MaximumNameLength = %d, want 0x20 (32)", config.MaximumNameLength)
				}
			},
		},
		{
			// The final "m" of "cloudflare-ech.com", so the name stays 18 bytes
			// and only its last character moves. "cloudflare-ech.con" is still a
			// legal name, so the config stays parseable and the change is
			// visible only in this field.
			name:   "the public name",
			offset: offPublicName + fixturePublicNameLen - 1,
			value:  'n',
			check: func(t *testing.T, config *Config) {
				if config.PublicName != "cloudflare-ech.con" {
					t.Errorf("PublicName = %q, want %q", config.PublicName, "cloudflare-ech.con")
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw := loadFixture(t)
			raw[testCase.offset] = testCase.value

			list, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse refused the list after changing only the %s byte: %v", testCase.name, err)
			}
			if len(list.Configs) != 1 {
				t.Fatalf("Parse returned %d configs, want 1", len(list.Configs))
			}
			config := list.Configs[0]
			testCase.check(t, &config)

			// The two fields with a single legal value must not move, so a
			// mutation cannot pass by shifting more than the field under test.
			if config.Version != 0xfe0d {
				t.Errorf("Version = %#04x, want it still 0xfe0d", config.Version)
			}
			if config.KEMID != 0x0020 {
				t.Errorf("KEMID = %#04x, want it still 0x0020", config.KEMID)
			}
		})
	}
}

// TestParseRefusesWrongLengths covers the wrong lengths in the committed fixture,
// so each case differs from the published bytes only in the field named. Several
// of them would trip more than one rule, so a case that only asserted "some
// error" would still pass with the rule that actually matters deleted; each case
// therefore names the refusal it expects.
//
// The break it catches is a length check that is absent, that truncates instead
// of refusing, or that reads past the end of the buffer. The declared lengths here
// reach 0xffff against buffers as short as 33 bytes, which is where a parser that
// trusts a length instead of checking it reads out of bounds.
func TestParseRefusesWrongLengths(t *testing.T) {
	// A copy of the fixture with one or two bytes changed, so every case below
	// is the published list with exactly the named field altered.
	altered := func(edit func([]byte)) []byte {
		raw := loadFixture(t)
		edit(raw)
		return raw
	}

	for _, testCase := range []struct {
		name        string
		list        []byte
		wantRefusal string
	}{
		{
			// The list length counts every byte after itself, so 68 contradicts
			// the 69 bytes the fixture carries after offset 1.
			name:        "a list length one byte short",
			list:        altered(func(raw []byte) { raw[offListLength+1] = 0x44 }),
			wantRefusal: "list length",
		},
		{
			name:        "a list length one byte long",
			list:        altered(func(raw []byte) { raw[offListLength+1] = 0x46 }),
			wantRefusal: "list length",
		},
		{
			// The widest length the field can hold, against a 71-byte list.
			name:        "a list length far beyond the bytes present",
			list:        altered(func(raw []byte) { raw[offListLength], raw[offListLength+1] = 0xff, 0xff }),
			wantRefusal: "list length",
		},
		{
			// A list that carries no configs at all. This is the case a caller in
			// strict mode has to see as an error, because a browser handed an
			// empty ECH list has no ECH. Two bytes is a list length of zero over
			// zero bytes of content, which is the only way to reach that state:
			// widening the fixture's own content would trip the list length first.
			name:        "a list that carries no config",
			list:        []byte{0x00, 0x00},
			wantRefusal: "no ECHConfig",
		},
		{
			// The config length counts every byte after itself inside the
			// config, so 64 leaves maximum_name_length and the public name out
			// of the config they belong to.
			name:        "a config length one byte short",
			list:        altered(func(raw []byte) { raw[offConfigLength+1] = 0x40 }),
			wantRefusal: "config length",
		},
		{
			name:        "a config length one byte long",
			list:        altered(func(raw []byte) { raw[offConfigLength+1] = 0x42 }),
			wantRefusal: "config length",
		},
		{
			name:        "a config length of zero",
			list:        altered(func(raw []byte) { raw[offConfigLength], raw[offConfigLength+1] = 0x00, 0x00 }),
			wantRefusal: "config length",
		},
		{
			// The last byte of the config dropped and the list length corrected
			// to 68, so the list itself is consistent and the shortfall has to
			// be caught while walking the config.
			name: "a config truncated by one byte",
			list: func() []byte {
				raw := loadFixture(t)[:fixtureTotalLen-1]
				binary.BigEndian.PutUint16(raw[offListLength:], fixtureListLength-1)
				if len(raw) != 70 {
					t.Fatalf("the truncated fixture is %d bytes, want 70", len(raw))
				}
				return raw
			}(),
			wantRefusal: "config length",
		},
		{
			// The same truncation with the list length left alone, so the two
			// lengths disagree about how long the list is.
			name:        "a truncated list whose own length was not corrected",
			list:        loadFixture(t)[:fixtureTotalLen-1],
			wantRefusal: "list length",
		},
		{
			// A byte after the last config with the list length widened to cover
			// it, so the walk meets one byte where a config has to start.
			name: "a byte left over after the last config",
			list: func() []byte {
				raw := append(loadFixture(t), 0x41)
				binary.BigEndian.PutUint16(raw[offListLength:], fixtureListLength+1)
				if len(raw) != fixtureTotalLen+1 {
					t.Fatalf("the extended fixture is %d bytes, want %d", len(raw), fixtureTotalLen+1)
				}
				return raw
			}(),
			wantRefusal: "ECHConfig header",
		},
		{
			// A public key length of 0xffff with 33 bytes left in the list. The
			// refusal has to come from comparing the declared length with what
			// is left, not from a 64 KiB allocation and a read past the end.
			name:        "a public key length far beyond the bytes present",
			list:        altered(func(raw []byte) { raw[offPublicKeyLength], raw[offPublicKeyLength+1] = 0xff, 0xff }),
			wantRefusal: "public key",
		},
		{
			// A suite vector length of 0xffff with 20 bytes left in the config.
			name:        "a cipher suite vector length far beyond the bytes present",
			list:        altered(func(raw []byte) { raw[offCipherSuitesLength], raw[offCipherSuitesLength+1] = 0xff, 0xff }),
			wantRefusal: "cipher suite",
		},
		{
			// A one-byte public name length of 0xff with 19 bytes left in the
			// config. The name count is the narrowest of the four, so it is the
			// one a missing bound is likeliest to overrun on.
			name:        "a public name length beyond the bytes present",
			list:        altered(func(raw []byte) { raw[offPublicNameLength] = 0xff }),
			wantRefusal: "public name",
		},
		{
			// An extensions length of 0xffff with no extension bytes present.
			name:        "an extensions length far beyond the bytes present",
			list:        altered(func(raw []byte) { raw[offExtensionsLength], raw[offExtensionsLength+1] = 0xff, 0xff }),
			wantRefusal: "extensions",
		},
		{
			// An extensions length of 1, which cannot hold the two-byte type
			// every extension starts with.
			name:        "an extensions length too small for any extension",
			list:        altered(func(raw []byte) { raw[offExtensionsLength], raw[offExtensionsLength+1] = 0x00, 0x01 }),
			wantRefusal: "extensions",
		},
		{
			name:        "no bytes at all",
			list:        nil,
			wantRefusal: "list length",
		},
		{
			// One byte: not even the list length field.
			name:        "fewer bytes than the list length field",
			list:        []byte{0x00},
			wantRefusal: "list length",
		},
		{
			// A list length of 2, so two bytes of content, which cannot hold the
			// four-byte header a config starts with.
			name:        "a list too short to hold a config header",
			list:        []byte{0x00, 0x02, 0xfe, 0x0d},
			wantRefusal: "ECHConfig header",
		},
		{
			// Three bytes of content, one short of a config header.
			name:        "a list one byte short of a config header",
			list:        []byte{0x00, 0x03, 0xfe, 0x0d, 0x00},
			wantRefusal: "ECHConfig header",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assertRefused(t, testCase.name, testCase.list, testCase.wantRefusal)
		})
	}
}

// TestParseRefusesStructuralVariants covers the lists that cannot be made by
// editing a length byte in the fixture, because the fields themselves have to
// change shape. Each body is the fixture's head, then the field under test, then
// a tail carrying the fixture's own public name, and every case states the total
// size and both lengths as literals so buildList's arithmetic is checked rather
// than trusted.
//
// The break it catches is a parser that accepts a structurally impossible or
// unusable config: no cipher suites at all, a suite vector that is not a whole
// number of suites, a config whose declared length and actual fields disagree, or
// an extension this router must not forward. The one case expected to be
// accepted is there so the extension walk is proved to run rather than to
// reject everything.
func TestParseRefusesStructuralVariants(t *testing.T) {
	raw := loadFixture(t)
	name := raw[offPublicName : offPublicName+fixturePublicNameLen]
	plainTail := configTail(0x00, name, nil)

	// The fixture rebuilt from the same head, suite vector and tail has to come
	// back as the published bytes. This is what makes those three helpers
	// trustworthy for every case below.
	t.Run("the helpers rebuild the published bytes", func(t *testing.T) {
		body := append(configHead(t), suitesVector(oneSuite)...)
		body = append(body, plainTail...)
		if rebuilt := buildList(t, body, fixtureTotalLen, fixtureListLength, fixtureConfigLength); !bytes.Equal(rebuilt, raw) {
			t.Fatalf("rebuilt the fixture as\n%s\nwant\n%s", hex.EncodeToString(rebuilt), hex.EncodeToString(raw))
		}
	})

	for _, testCase := range []struct {
		name             string
		body             []byte
		wantTotal        int
		wantListLength   int
		wantConfigLength int
		wantRefusal      string
	}{
		{
			// RFC 9849 Section 4 bounds the vector at 4..2^16-4, so a config
			// offering no suite at all is not a config.
			name: "a config with no cipher suites",
			body: func() []byte {
				body := append(configHead(t), suitesVector()...)
				return append(body, plainTail...)
			}(),
			wantTotal:        67,
			wantListLength:   0x0041,
			wantConfigLength: 0x003d,
			wantRefusal:      "cipher suite",
		},
		{
			// Five bytes is not a whole number of four-byte suites. Reading four
			// and dropping the fifth is how a parser ends up agreeing with itself
			// and disagreeing with the peer. The vector declares five and carries
			// five, so the only thing wrong with it is the count.
			name: "a cipher suite vector that is not a whole number of suites",
			body: func() []byte {
				body := append(configHead(t), []byte{0x00, 0x05, 0x00, 0x01, 0x00}...)
				return append(body, plainTail...)
			}(),
			wantTotal:        70,
			wantListLength:   0x0044,
			wantConfigLength: 0x0040,
			wantRefusal:      "cipher suite",
		},
		{
			// An extension type this router knows nothing about, with the high
			// order bit clear, is one RFC 9849 Section 4.2 has a client ignore
			// and carry on past, so the list stays usable and the extension has
			// to reach the browser in Raw.
			name: "an unknown extension that is not mandatory",
			body: func() []byte {
				tail := configTail(0x00, name, []byte{0x12, 0x34, 0x00, 0x02, 0xaa, 0xbb})
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, tail...)
			}(),
			wantTotal:        77,
			wantListLength:   0x004b,
			wantConfigLength: 0x0047,
		},
		{
			// The high order bit marks the extension mandatory, and RFC 9849
			// Section 4.2 has a client that cannot honour it ignore the whole
			// config. Forwarding one would hand a browser a config it must drop,
			// which is a downgrade dressed as a success.
			name: "an unknown mandatory extension",
			body: func() []byte {
				tail := configTail(0x00, name, []byte{0x92, 0x34, 0x00, 0x02, 0xaa, 0xbb})
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, tail...)
			}(),
			wantTotal:        77,
			wantListLength:   0x004b,
			wantConfigLength: 0x0047,
			wantRefusal:      "mandatory",
		},
		{
			// RFC 9849 Section 4.2 allows extensions in any order but forbids more
			// than one of a type, so two peers could disagree about which data
			// belongs to the extension.
			name: "the same extension type twice",
			body: func() []byte {
				tail := configTail(0x00, name, []byte{
					0x12, 0x34, 0x00, 0x00,
					0x12, 0x34, 0x00, 0x00,
				})
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, tail...)
			}(),
			wantTotal:        79,
			wantListLength:   0x004d,
			wantConfigLength: 0x0049,
			wantRefusal:      "more than once",
		},
		{
			// The extension declares five data bytes and carries two.
			name: "an extension whose data length overruns the block",
			body: func() []byte {
				tail := configTail(0x00, name, []byte{0x12, 0x34, 0x00, 0x05, 0xaa, 0xbb})
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, tail...)
			}(),
			wantTotal:        77,
			wantListLength:   0x004b,
			wantConfigLength: 0x0047,
			wantRefusal:      "extensions",
		},
		{
			// A declared name length of 0. RFC 9849 Section 4 bounds the name at
			// 1..255, and an empty public name leaves a browser nothing to
			// authenticate the ECH rejection against.
			name: "a config with an empty public name",
			body: func() []byte {
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, configTail(0x00, nil, nil)...)
			}(),
			wantTotal:        53,
			wantListLength:   0x0033,
			wantConfigLength: 0x002f,
			wantRefusal:      "public name",
		},
		{
			// The longest name the one-byte count can express, against 19 bytes
			// left in the config.
			name: "a public name length of 255 with too few bytes",
			body: func() []byte {
				tail := append([]byte{0x00, 0xff}, name...)
				tail = append(tail, 0x00, 0x00)
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, tail...)
			}(),
			wantTotal:        71,
			wantListLength:   0x0045,
			wantConfigLength: 0x0041,
			wantRefusal:      "public name",
		},
		{
			// One byte of padding after the last field with the config length
			// widened to cover it. Nothing in RFC 9849 Section 4 says what that
			// byte is, so a config whose fields do not fill its declared length
			// is one this parser cannot vouch for.
			name: "a byte the config length covers but no field claims",
			body: func() []byte {
				body := append(configHead(t), suitesVector(oneSuite)...)
				return append(body, append(plainTail, 0x41)...)
			}(),
			wantTotal:        72,
			wantListLength:   0x0046,
			wantConfigLength: 0x0042,
			wantRefusal:      "config length",
		},
		{
			// A 31-byte key, with the suite vector, maximum_name_length, name and
			// extensions shifted up to follow it, so the only thing wrong with
			// the config is the key's size. Shortening the key length in place
			// cannot test this, because that would leave the fields after it
			// where the key ended.
			name: "a public key that is not an X25519 key",
			body: func() []byte {
				// Offsets 2 to 10 are the version, both length fields, config_id,
				// kem_id and the public key length: everything before the key.
				body := append([]byte(nil), raw[offVersion:offPublicKey]...)
				// The public key length is at wire offset 9, which is index 7 of a
				// body that begins at the version field.
				body[offPublicKeyLength-offVersion] = 0x00
				body[offPublicKeyLength-offVersion+1] = 0x1f
				body = append(body, raw[offPublicKey:offPublicKey+31]...)
				body = append(body, suitesVector(oneSuite)...)
				return append(body, plainTail...)
			}(),
			wantTotal:        70,
			wantListLength:   0x0044,
			wantConfigLength: 0x0040,
			wantRefusal:      "public key",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			list := buildList(t, testCase.body, testCase.wantTotal, testCase.wantListLength, testCase.wantConfigLength)
			if testCase.wantRefusal == "" {
				got, err := Parse(list)
				if err != nil {
					t.Fatalf("Parse refused a list with %s: %v", testCase.name, err)
				}
				if len(got.Configs) != 1 {
					t.Fatalf("Parse returned %d configs, want 1", len(got.Configs))
				}
				if !bytes.Equal(got.Raw, list) {
					t.Error("Raw is not the input bytes, so an extension the browser needs cannot reach it")
				}
				return
			}
			assertRefused(t, testCase.name, list, testCase.wantRefusal)
		})
	}
}

// TestParseRefusesUnusableConfigValues covers the config fields whose value, not
// whose length, decides whether a browser could use the list. Each case changes
// one field of the published bytes and nothing else, so the rule under test is
// the only rule the list can trip.
//
// The break it catches is validation that accepts anything: a version whose
// layout this parser has not read, a KEM it cannot check a key against, a cipher
// suite pair no client implements, and a public key that is not the size the KEM
// fixes.
func TestParseRefusesUnusableConfigValues(t *testing.T) {
	altered := func(edit func([]byte)) []byte {
		raw := loadFixture(t)
		edit(raw)
		return raw
	}

	for _, testCase := range []struct {
		name        string
		list        []byte
		wantRefusal string
	}{
		{
			// RFC 9849 Section 4 selects the contents layout on the version, so
			// a version this parser does not implement is a config whose bytes
			// mean something else entirely.
			name:        "a version this parser does not implement",
			list:        altered(func(raw []byte) { raw[offVersion], raw[offVersion+1] = 0xfe, 0x0c }),
			wantRefusal: "version",
		},
		{
			// 0x0021 is the next HPKE KEM in the registry after DHKEM(X25519).
			name:        "a KEM this router does not recognize",
			list:        altered(func(raw []byte) { raw[offKEMID], raw[offKEMID+1] = 0x00, 0x21 }),
			wantRefusal: "KEM",
		},
		{
			// 0x0010 is the AEAD RFC 9180 Section 7.3 reserves for export-only
			// use, so no browser offers it.
			name:        "a cipher suite no client implements",
			list:        altered(func(raw []byte) { raw[offSuiteAEADID], raw[offSuiteAEADID+1] = 0x00, 0x10 }),
			wantRefusal: "cipher suite",
		},
		{
			// 0x0000 is not an assigned AEAD at all, and is the value a parser
			// accepting any four bytes waves through.
			name:        "a cipher suite with an unassigned AEAD",
			list:        altered(func(raw []byte) { raw[offSuiteAEADID], raw[offSuiteAEADID+1] = 0x00, 0x00 }),
			wantRefusal: "cipher suite",
		},
		{
			// A kdf_id of 0x0002 is unassigned too, and the AEAD stays the
			// recognized AES-128-GCM, so a parser that looked only at the AEAD
			// would forward a suite no client can build.
			name:        "a cipher suite with an unassigned KDF",
			list:        altered(func(raw []byte) { raw[offSuiteKDFID], raw[offSuiteKDFID+1] = 0x00, 0x02 }),
			wantRefusal: "cipher suite",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assertRefused(t, testCase.name, testCase.list, testCase.wantRefusal)
		})
	}
}

// TestParseRefusesUnusablePublicNames covers the public names RFC 9849
// Section 6.1.7 has a client ignore, each built by replacing only the fixture's
// name and recomputing the three lengths that follow from its size.
//
// The break it catches is a name check that only rejects an empty string, or that
// accepts a name a browser will refuse: one that reads as an IPv4 literal, one
// outside preferred name syntax, or one with a label no resolver will carry.
func TestParseRefusesUnusablePublicNames(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		publicName string
	}{
		{
			// No dot at all, so not a dot-separated sequence of labels.
			name:       "a name with no label separator",
			publicName: "cloudflare-echcom",
		},
		{
			name:       "a name beginning with a dot",
			publicName: "." + fixturePublicName,
		},
		{
			name:       "a name ending with a dot",
			publicName: fixturePublicName + ".",
		},
		{
			name:       "a name with an empty label",
			publicName: "cloudflare..com",
		},
		{
			// RFC 9840 Section 6.1.7 has a client ignore a public_name whose final
			// label is all ASCII digits, because the name would read as an IPv4
			// literal. "cloudflare-ech.123" is 18 bytes, the same as the
			// published name, so only the three characters differ.
			name:       "a name ending in an all-digit label",
			publicName: "cloudflare-ech.123",
		},
		{
			// The other half of that rule: a final label of "0x" followed by hex
			// digits, which WHATWG URL parsing also reads as an IPv4 literal.
			name:       "a name ending in a hexadecimal IPv4-looking label",
			publicName: "cloudflare-ech.0xa",
		},
		{
			// A 64-byte label is one octet over the RFC 1035 limit, so no
			// resolver and no client can treat the name as a hostname.
			name:       "a name with a label over 63 bytes",
			publicName: strings.Repeat("x", 64) + ".io",
		},
		{
			// Four labels of at most 63 octets: 63 + 1 + 63 + 1 + 63 + 1 + 62 is
			// 254 bytes, the same shape as the longest accepted name with one
			// byte added, so the total length is the only thing wrong with it.
			name:       "a name over 253 bytes",
			publicName: strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 62),
		},
		{
			// A label may not begin or end with a hyphen in preferred name
			// syntax, so this is not a name a resolver will carry either.
			name:       "a name with a label ending in a hyphen",
			publicName: "cloudflare-ech.co-",
		},
		{
			// An underscore is not an LDH character, which is what makes a name
			// "dot-separated LDH labels" in RFC 9849 Section 6.1.7.
			name:       "a name with a character outside LDH",
			publicName: "cloudflare_ech.com",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assertRefused(t, testCase.name, withPublicName(t, testCase.publicName), "public name")
		})
	}
}

// TestParseAcceptsAUsablePublicName proves the name check is not simply a refusal
// of everything it is shown. The break it catches is a validator so eager that it
// turns away the published list's own shape, which for a rewriter would be ECH
// that never reaches a browser at all.
func TestParseAcceptsAUsablePublicName(t *testing.T) {
	for _, publicName := range []string{
		"a.io",                          // the shortest legal shape
		"ech-sites.example.net",         // the public_name of RFC 9848 Section 3's own example
		"cloudflare-ech.co.uk",          // three labels
		strings.Repeat("a", 63) + ".io", // a 63-byte label, the most a label may be
		// 63 + 1 + 63 + 1 + 63 + 1 + 60 is 253 bytes: the most a name may be,
		// and reached without any label going over 63.
		strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 60),
	} {
		t.Run(publicName, func(t *testing.T) {
			list := withPublicName(t, publicName)
			got, err := Parse(list)
			if err != nil {
				t.Fatalf("Parse refused the usable public name %q: %v", publicName, err)
			}
			if len(got.Configs) != 1 {
				t.Fatalf("Parse returned %d configs, want 1", len(got.Configs))
			}
			if got.Configs[0].PublicName != publicName {
				t.Errorf("PublicName = %q, want %q", got.Configs[0].PublicName, publicName)
			}
		})
	}
}

// Offsets inside one ECHConfig, counted from its own version field. They differ
// from the wire offsets above because a config starts after the list's own length
// field, and a list of two configs has to reach the second one's fields.
const (
	configOffsetVersion  = 0  // uint16
	configOffsetLength   = 2  // uint16, so its high octet is at 3
	configOffsetConfigID = 4  // uint8
	configBytes          = 69 // the fixture's one config, contents included
)

// TestParseRefusesDuplicateConfigIDs proves two configs in one list cannot claim
// one config_id. RFC 9849 Section 6.1 has the client name the config it encrypted
// to, so a duplicated id leaves the choice between two different public keys
// ambiguous, and the client-facing server cannot tell which private key to try.
//
// The break it catches is uniqueness checking that never runs because the walk
// stops after the first config.
func TestParseRefusesDuplicateConfigIDs(t *testing.T) {
	raw := loadFixture(t)
	config := raw[offVersion:] // the fixture's 69 config bytes
	if len(config) != configBytes {
		t.Fatalf("the fixture's config is %d bytes, want %d", len(config), configBytes)
	}
	duplicate := make([]byte, 0, 2+2*len(config))
	duplicate = append(duplicate, 0x00, 0x00)
	duplicate = append(duplicate, config...)
	duplicate = append(duplicate, config...)
	binary.BigEndian.PutUint16(duplicate[offListLength:], uint16(len(duplicate)-2))

	// The outer length field belongs to the list, so it is written once above
	// and the two copies contribute only their 69 config bytes each: 2 + 138 is
	// 140 bytes, declaring a 138-byte list.
	if len(duplicate) != 140 {
		t.Fatalf("built a %d-byte list, want 140", len(duplicate))
	}
	if got := int(binary.BigEndian.Uint16(duplicate[offListLength:])); got != 0x008a {
		t.Fatalf("built a list declaring a %d-byte list length, want 0x008a (138)", got)
	}
	// Each config's bytes start two into the list, past the list length field, so
	// its length high octet sits at 2 + 3 and then 2 + 69 + 3.
	if got := duplicate[2+configOffsetLength+1]; got != 0x41 {
		t.Fatalf("the first config declares a %d-byte length, want 0x41 (65)", got)
	}
	if got := duplicate[2+configBytes+configOffsetLength+1]; got != 0x41 {
		t.Fatalf("the second config declares a %d-byte length, want 0x41 (65)", got)
	}

	assertRefused(t, "two configs sharing one config_id", duplicate, "config_id")
}

// TestParseWalksEveryConfig proves the walk reaches the second config, so a
// refusal anywhere in the list is seen rather than a list being judged by its
// first config alone.
//
// The break it catches is a loop that parses one config and stops. This list's
// second config differs from the first in exactly the field each half changes,
// so a parser that stopped early would accept a list whose second config is
// unusable.
func TestParseWalksEveryConfig(t *testing.T) {
	raw := loadFixture(t)
	config := raw[offVersion:] // the fixture's 69 config bytes

	// Two configs whose config_ids differ, which is the only legal way to have
	// two of them in one list.
	distinct := make([]byte, 0, 2+2*len(config))
	distinct = append(distinct, 0x00, 0x00)
	distinct = append(distinct, config...)
	second := append([]byte(nil), config...)
	second[configOffsetConfigID] = 0x01
	distinct = append(distinct, second...)
	binary.BigEndian.PutUint16(distinct[offListLength:], uint16(len(distinct)-2))

	if len(distinct) != 140 {
		t.Fatalf("built a %d-byte list, want 140", len(distinct))
	}

	list, err := Parse(distinct)
	if err != nil {
		t.Fatalf("Parse refused a list of two configs with distinct config_ids: %v", err)
	}
	if len(list.Configs) != 2 {
		t.Fatalf("Parse returned %d configs, want 2", len(list.Configs))
	}
	if list.Configs[0].ConfigID != 0xb8 || list.Configs[1].ConfigID != 0x01 {
		t.Errorf("the config ids are %#02x and %#02x, want 0xb8 and 0x01 in the order they were written",
			list.Configs[0].ConfigID, list.Configs[1].ConfigID)
	}
	if list.Configs[1].PublicName != fixturePublicName {
		t.Errorf("the second config's public name is %q, want %q", list.Configs[1].PublicName, fixturePublicName)
	}

	// The same two configs with the second one's version changed has to be
	// refused. That is the property the walk-every-config claim rests on, and the
	// second config's bytes start at 2 + 69.
	secondConfig := 2 + configBytes
	unsupported := append([]byte(nil), distinct...)
	unsupported[secondConfig+configOffsetVersion] = 0xfe
	unsupported[secondConfig+configOffsetVersion+1] = 0x0c
	assertRefused(t, "two configs whose second carries an unsupported version", unsupported, "version")
}

// TestParseAcceptsTheLargestListTheFormatCanDescribe covers the top of the length
// range. The widest list the uint16 list length can describe is 2 + 0xffff bytes
// and it has to parse; one byte more cannot be described at all, and has to be
// refused rather than wrapping the declared length round to zero.
//
// The break it catches is a list-length comparison that is off by one in either
// direction, or one that stores the declared length in a uint16 without noticing
// it has wrapped.
func TestParseAcceptsTheLargestListTheFormatCanDescribe(t *testing.T) {
	// The list is the fixture's 41 bytes of head, then a cipher-suite vector,
	// then a tail. Counting a config's contents: a config_id, a kem_id, a key
	// length, the 32-byte key, the suite vector's own length, the suites, a
	// maximum_name_length, the name length, the name and the extensions length
	// come to 43 bytes plus the suites plus the name, and the list adds the two
	// length fields in front of the config, so total = 49 + suites + name. The
	// widest list the format can describe is 2 + 0xffff = 65537, which leaves
	// suites + name = 65488; the suites are a two-byte count plus whole
	// four-byte pairs, so 16371 of them is 65484 and the name is the remaining
	// four bytes, "a.io" -- two LDH labels, and chosen only to be legal at a size
	// the test controls.
	suites := make([]byte, 0, 2+4*16371)
	suites = binary.BigEndian.AppendUint16(suites, 4*16371)
	for i := 0; i < 16371; i++ {
		suites = append(suites, oneSuite...)
	}
	body := append(configHead(t), suites...)
	body = append(body, configTail(0x00, []byte("a.io"), nil)...)

	largest := buildList(t, body, 65537, 0xffff, 0xfffb)

	list, err := Parse(largest)
	if err != nil {
		t.Fatalf("Parse refused the largest list the format can describe: %v", err)
	}
	if len(list.Configs) != 1 {
		t.Fatalf("Parse returned %d configs from the largest list, want 1", len(list.Configs))
	}
	if len(list.Configs[0].CipherSuites) != 16371 {
		t.Errorf("Parse returned %d cipher suites, want 16371", len(list.Configs[0].CipherSuites))
	}
	if list.Configs[0].PublicName != "a.io" {
		t.Errorf("PublicName = %q, want %q", list.Configs[0].PublicName, "a.io")
	}
	if !bytes.Equal(list.Raw, largest) {
		t.Error("Raw is not the input bytes for the largest legal list")
	}

	// One byte more than 0xffff bytes of content. The declared length cannot
	// cover it, so the bytes and the length disagree.
	oversized := make([]byte, 0, len(largest)+1)
	oversized = append(oversized, largest...)
	oversized = append(oversized, 0x41)
	assertRefused(t, "a list one byte wider than its length can express", oversized, "list length")
}

// TestListRawIsTheInputBytes proves Raw is the caller's bytes, the whole of them,
// outer length included, and that nothing returned aliases the caller's buffer.
//
// The break it catches is the pair of mistakes this task exists to prevent: a
// parser that strips the outer length before handing the list on, which would
// corrupt the RR, and a parser that hands back a subslice of the caller's buffer,
// which would let a later write to that buffer change bytes a browser is about to
// encrypt to.
func TestListRawIsTheInputBytes(t *testing.T) {
	want := loadFixture(t)
	raw := loadFixture(t)

	list, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse refused the committed Cloudflare list: %v", err)
	}

	if !bytes.Equal(list.Raw, want) {
		t.Fatalf("Raw is\n%s\nwant the input bytes\n%s", hex.EncodeToString(list.Raw), hex.EncodeToString(want))
	}
	if len(list.Raw) != fixtureTotalLen {
		t.Errorf("Raw is %d bytes, want the whole %d-byte input including its outer length", len(list.Raw), fixtureTotalLen)
	}
	if got := binary.BigEndian.Uint16(list.Raw[:2]); got != fixtureListLength {
		t.Errorf("Raw starts with a list length of %#04x, want %#04x; the outer length has to survive into the SvcParam", got, uint16(fixtureListLength))
	}

	// Overwriting the caller's buffer has to leave Raw alone.
	for i := range raw {
		raw[i] = 0xff
	}
	if !bytes.Equal(list.Raw, want) {
		t.Fatalf("Raw changed when the caller's buffer was overwritten, so it aliases that buffer:\n%s", hex.EncodeToString(list.Raw))
	}
	// A parsed key has the same property: it is a value this parser checked, and
	// a checked value cannot be edited after the check.
	if got := hex.EncodeToString(list.Configs[0].PublicKey); got == strings.Repeat("ff", 32) {
		t.Error("PublicKey aliases the caller's buffer")
	}
}

// packAnswerWith builds a real DNS answer message carrying an HTTPS RR whose only
// SvcParam is the ech parameter holding raw, and returns the packed wire form. It
// goes through dns.Msg rather than the RR alone because that is the only exported
// way to exercise miekg/dns's SvcParam packing and unpacking, and the RR is the
// form a resolver would put on the wire.
func packAnswerWith(raw []byte) ([]byte, error) {
	rr := new(dns.HTTPS)
	rr.Hdr = dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300}
	rr.Priority = 1
	rr.Target = "example.com."
	rr.Value = append(rr.Value, &dns.SVCBECHConfig{ECH: raw})

	msg := new(dns.Msg)
	msg.MsgHdr = dns.MsgHdr{Response: true, Authoritative: true, Rcode: dns.RcodeSuccess}
	msg.Question = []dns.Question{{Name: "example.com.", Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET}}
	msg.Answer = append(msg.Answer, rr)
	return msg.Pack()
}

// unpackOnlyParam unpacks a wire message and returns the value of the sole
// SvcParam in its sole answer, so the assertion is about the bytes that reached
// the wire and not about how this test chose to build them.
func unpackOnlyParam(wire []byte) ([]byte, error) {
	var msg dns.Msg
	if err := msg.Unpack(wire); err != nil {
		return nil, err
	}
	if len(msg.Answer) != 1 {
		return nil, fmt.Errorf("the unpacked message carries %d answers, want 1", len(msg.Answer))
	}
	answer, ok := msg.Answer[0].(*dns.HTTPS)
	if !ok {
		return nil, fmt.Errorf("the unpacked answer is a %T, want a *dns.HTTPS", msg.Answer[0])
	}
	if len(answer.Value) != 1 {
		return nil, fmt.Errorf("the unpacked answer carries %d SvcParams, want 1", len(answer.Value))
	}
	ech, ok := answer.Value[0].(*dns.SVCBECHConfig)
	if !ok {
		return nil, fmt.Errorf("the unpacked SvcParam is a %T, want a *dns.SVCBECHConfig", answer.Value[0])
	}
	return ech.ECH, nil
}

// TestListRawSurvivesAnHTTPSRRRoundTrip puts Raw into a real HTTPS RR, packs it
// with the pinned miekg/dns, unpacks the wire form, and requires the ech SvcParam
// to come back as the same bytes.
//
// This is the round trip that decides the task, because dns.SVCBECHConfig.ECH is
// documented as "Specifically ECHConfigList including the redundant length prefix"
// and its pack is a verbatim copy. A Raw that had the outer length stripped, or a
// second one added, would still be a plausible-looking byte string and would still
// match a re-encoded copy of itself; it would not survive this.
func TestListRawSurvivesAnHTTPSRRRoundTrip(t *testing.T) {
	raw := loadFixture(t)
	list, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse refused the committed Cloudflare list: %v", err)
	}

	wire, err := packAnswerWith(list.Raw)
	if err != nil {
		t.Fatalf("pack an HTTPS answer carrying the ECH config: %v", err)
	}

	unpacked, err := unpackOnlyParam(wire)
	if err != nil {
		t.Fatalf("unpack the HTTPS answer back: %v", err)
	}
	if !bytes.Equal(unpacked, raw) {
		t.Fatalf("the ech SvcParam came back as\n%s\nwant the input bytes\n%s",
			hex.EncodeToString(unpacked), hex.EncodeToString(raw))
	}
}

// TestListRawCarriesTheOuterLengthExactlyOnce reads the packed wire form and
// checks the SvcParamValue is Raw itself, sitting behind exactly one two-byte
// SvcParam length and starting with the list's own uint16 length.
//
// The break it catches is the subtle one. miekg/dns writes a two-byte length for
// the SvcParamValue, and the ECHConfigList begins with a two-byte length too, so
// a Raw built to be "the value without its redundant prefix", or one built with
// the prefix added again, is still a byte string of about the right size. Only the
// bytes say otherwise, and only the wire form is what a browser reads.
func TestListRawCarriesTheOuterLengthExactlyOnce(t *testing.T) {
	raw := loadFixture(t)
	list, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse refused the committed Cloudflare list: %v", err)
	}

	wire, err := packAnswerWith(list.Raw)
	if err != nil {
		t.Fatalf("pack an HTTPS answer carrying the ECH config: %v", err)
	}

	// miekg/dns packs each SvcParam as key(2) | value length(2) | value, so the
	// key code sits four bytes before the value. Searching for Raw rather than
	// recomputing the RR's layout means a change in the library's packing shows
	// up as a failure here instead of being assumed away.
	offset := bytes.Index(wire, list.Raw)
	if offset < 4 {
		t.Fatalf("the packed answer does not carry the ECHConfigList verbatim at an offset of at least 4:\n%s", hex.EncodeToString(wire))
	}
	if got := binary.BigEndian.Uint16(wire[offset-4 : offset-2]); got != uint16(dns.SVCB_ECHCONFIG) {
		t.Errorf("the two bytes four back from the value are %#04x, want the ech key code %#04x", got, uint16(dns.SVCB_ECHCONFIG))
	}
	if got := binary.BigEndian.Uint16(wire[offset-2 : offset]); got != uint16(len(list.Raw)) {
		t.Errorf("the two bytes in front of the SvcParamValue are %#04x, want %#04x, the length of the value",
			got, uint16(len(list.Raw)))
	}
	if got := binary.BigEndian.Uint16(wire[offset:]); got != fixtureListLength {
		t.Errorf("the SvcParamValue starts with %#04x, want the list's own length %#04x, present exactly once",
			got, uint16(fixtureListLength))
	}
}
