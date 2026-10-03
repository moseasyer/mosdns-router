package dnscrypt

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	dnsstamps "github.com/jedisct1/go-dnsstamps"
	"mosdns-router/internal/config"
)

// The literals below are decoded by hand from the DNSCrypt stamp wire format
// (protocol byte, little-endian 64-bit property word, address, 32-byte provider
// public key, provider name) and from the published Quad9 resolver list, so a
// test never reuses the renderer or its helpers to build its own expectation.

// quad9ProviderPublicKey is the Ed25519 certificate key Quad9 publishes for
// `2.dnscrypt-cert.quad9.net`; it is identical in all three IPv4 filtered stamps.
const quad9ProviderPublicKey = "67c847b8c8758cd120245543be756746df34df1d84c00b8c470368df821d863e"

// foreignListener is the loopback address the foreign forward enters. It is
// never port 53, so the resolver can neither be reached off-host nor be
// mistaken for the system resolver.
const foreignListener = "127.0.0.1:15353"

// wantBootstrapResolvers resolve DNSCrypt provider names only. 9.9.9.9 and
// 149.112.112.9 are Quad9's own anycast addresses, so no query about the user's
// browsing ever leaves through a resolver this project does not also use.
var wantBootstrapResolvers = []string{"9.9.9.9:53", "149.112.112.9:53"}

// chinesePublicDNSAddresses must never appear in a generated configuration: the
// foreign branch exists so that a query can be answered somewhere that is not
// the network the user is leaving.
var chinesePublicDNSAddresses = []string{
	"223.5.5.5",       // AliDNS
	"223.6.6.6",       // AliDNS
	"119.29.29.29",    // DNSPod
	"114.114.114.114", // 114DNS
	"180.76.76.76",    // Baidu DNS
}

// quad9ECSAddresses are Quad9's ECS-capable IPv4 addresses. ECS leaks the
// client's subnet to the resolver, so no stamp may point at them.
var quad9ECSAddresses = []string{"9.9.9.11", "149.112.112.11"}

// staleCorruptAlt2Stamp is the corrupt `dnscrypt-ip4-filter-alt2` string that an
// earlier copy of https://quad9.net/dnscrypt/quad9-resolvers.md, and the plan
// text derived from it, carried. It is NOT what that list serves as of
// 2026-09-26: the live value is the third default in Defaults(), and the two are
// byte-for-byte apart in 15 contiguous bytes at offsets 74-88 plus nine appended
// bytes. This one declares a 25-byte provider name but fills it with
// `2.dnscrypt.dnscrypt-cert.` and then appends `quad9.net`, so the pinned decoder
// refuses it ("garbage after end") and dnscrypt-proxy 2.1.18 exits 255 on it. It
// is kept as the fixture that proves a stamp which does not decode is refused --
// not as a source for the shipped value, which is upstream's.
const staleCorruptAlt2Stamp = "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ"

// foreignConfig is the exact document shape dnscrypt-proxy 2.1.18 reads. It
// declares every key the renderer may emit, so the strict-decode test can prove
// the renderer emits nothing dnscrypt-proxy would ignore.
type foreignConfig struct {
	ServerNames     []string `toml:"server_names"`
	ListenAddresses []string `toml:"listen_addresses"`
	IgnoreSystemDNS *bool    `toml:"ignore_system_dns"`
	Bootstrap       []string `toml:"bootstrap_resolvers"`
	NetprobeAddress string   `toml:"netprobe_address"`
	NetprobeTimeout *int     `toml:"netprobe_timeout"`
	Cache           *bool    `toml:"cache"`
	ForceTCP        *bool    `toml:"force_tcp"`
	IPv4Servers     *bool    `toml:"ipv4_servers"`
	IPv6Servers     *bool    `toml:"ipv6_servers"`
	DNSCryptServers *bool    `toml:"dnscrypt_servers"`
	DoHServers      *bool    `toml:"doh_servers"`
	ODoHServers     *bool    `toml:"odoh_servers"`
	RequireDNSSEC   *bool    `toml:"require_dnssec"`
	RequireNoLog    *bool    `toml:"require_nolog"`
	RequireNoFilter *bool    `toml:"require_nofilter"`
	LocalDoH        struct {
		ListenAddresses []string `toml:"listen_addresses"`
		Path            string   `toml:"path"`
		CertFile        string   `toml:"cert_file"`
		CertKeyFile     string   `toml:"cert_key_file"`
	} `toml:"local_doh"`
	QueryLog struct {
		File string `toml:"file"`
	} `toml:"query_log"`
	Static map[string]struct {
		Stamp string `toml:"stamp"`
	} `toml:"static"`
}

func renderDefaults(t *testing.T) foreignConfig {
	t.Helper()
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	var decoded foreignConfig
	meta, err := toml.Decode(string(rendered), &decoded)
	if err != nil {
		t.Fatalf("rendered document is not decodable TOML: %v\n%s", err, rendered)
	}
	if undecoded := meta.Undecoded(); len(undecoded) != 0 {
		t.Fatalf("rendered document carries keys this project does not account for: %v", undecoded)
	}
	return decoded
}

// TestDefaultsDecodeToThePublishedQuad9IPv4Endpoints proves each default stamp
// is the endpoint it claims to be. The break it catches is any edit to the
// embedded bytes -- a re-pointed address, a swapped provider key, a lost
// property bit -- that a prefix check on the base64 text would not see.
func TestDefaultsDecodeToThePublishedQuad9IPv4Endpoints(t *testing.T) {
	wantNames := []string{"quad9-dnscrypt-ip4-filter-1", "quad9-dnscrypt-ip4-filter-2", "quad9-dnscrypt-ip4-filter-3"}
	wantAddresses := []string{"9.9.9.9:8443", "149.112.112.9:8443", "149.112.112.112:8443"}
	// The provider name Quad9 signs its resolvers' certificates with. It is the
	// only thing `bootstrap_resolvers` ever has to look up, so a wrong or empty
	// provider name is a stamp that cannot authenticate at all.
	const wantProviderName = "2.dnscrypt-cert.quad9.net"

	defaults := Defaults()
	if len(defaults) != len(wantNames) {
		t.Fatalf("Defaults() returned %d stamps, want %d", len(defaults), len(wantNames))
	}
	for index, want := range defaults {
		if want.Name != wantNames[index] {
			t.Errorf("Defaults()[%d].Name = %q, want %q", index, want.Name, wantNames[index])
		}
		decoded := decodeStamp(t, want.Value)
		if decoded.address != wantAddresses[index] {
			t.Errorf("Defaults()[%d] (%s) decodes to address %q, want %q", index, want.Name, decoded.address, wantAddresses[index])
		}
		if decoded.providerName != wantProviderName {
			t.Errorf("Defaults()[%d] (%s) decodes to provider name %q, want %q", index, want.Name, decoded.providerName, wantProviderName)
		}
		if decoded.providerKeyHex != quad9ProviderPublicKey {
			t.Errorf("Defaults()[%d] (%s) decodes to provider key %s, want %s", index, want.Name, decoded.providerKeyHex, quad9ProviderPublicKey)
		}
	}
}

// TestDefaultsShareOneAuthenticatedProviderKey proves the three endpoints are
// three addresses of one provider rather than three unrelated resolvers. The
// break it catches is swapping in a stamp that authenticates a different
// operator while keeping a Quad9-looking address.
func TestDefaultsShareOneAuthenticatedProviderKey(t *testing.T) {
	for _, stamp := range Defaults() {
		decoded := decodeStamp(t, stamp.Value)
		if decoded.providerKeyHex != quad9ProviderPublicKey {
			t.Errorf("%s carries provider key %s, want the key the other defaults share: %s",
				stamp.Name, decoded.providerKeyHex, quad9ProviderPublicKey)
		}
	}
}

// TestRenderNamesEveryStampAndNothingElse proves server_names and [static] stay
// in one-to-one correspondence in the order the stamps were supplied. The break
// it catches is naming a server that has no stamp (dnscrypt-proxy then runs with
// no usable resolver) or a stamp that is present but never selected.
func TestRenderNamesEveryStampAndNothingElse(t *testing.T) {
	supplied := Defaults()
	rendered := renderDefaults(t)

	if len(rendered.ServerNames) != len(supplied) {
		t.Fatalf("server_names has %d entries, want %d: %v", len(rendered.ServerNames), len(supplied), rendered.ServerNames)
	}
	for index, stamp := range supplied {
		if rendered.ServerNames[index] != stamp.Name {
			t.Errorf("server_names[%d] = %q, want %q", index, rendered.ServerNames[index], stamp.Name)
		}
		entry, ok := rendered.Static[stamp.Name]
		if !ok {
			t.Errorf("no [static.%s] section for a server listed in server_names", stamp.Name)
			continue
		}
		if entry.Stamp != stamp.Value {
			t.Errorf("[static.%s] stamp = %q, want the supplied stamp %q", stamp.Name, entry.Stamp, stamp.Value)
		}
	}
	if len(rendered.Static) != len(supplied) {
		t.Errorf("document defines %d [static] sections, want exactly the %d supplied", len(rendered.Static), len(supplied))
	}
}

// TestRenderKeepsTheForeignListenerOffTheSystemResolverPort proves the only
// listener is loopback and not port 53. The break it catches is a listener that
// is reachable from off-host or that shadows the system resolver, either of
// which turns the authenticated foreign path into an ordinary open resolver.
func TestRenderKeepsTheForeignListenerOffTheSystemResolverPort(t *testing.T) {
	rendered := renderDefaults(t)

	if len(rendered.ListenAddresses) != 1 {
		t.Fatalf("listen_addresses = %v, want exactly one entry", rendered.ListenAddresses)
	}
	if got := rendered.ListenAddresses[0]; got != foreignListener {
		t.Errorf("listen_addresses[0] = %q, want %q", got, foreignListener)
	}
}

// TestRenderLeavesTheListenerServingBothUDPAndTCP proves nothing narrows the
// listener to one transport. dnscrypt-proxy registers a UDP and a TCP listener
// for every listen address, and the foreign forward is TCP, so a rendered
// `force_tcp` or a scheme-qualified address would either drop UDP silently or
// stop the address from being a plain host:port at all.
func TestRenderLeavesTheListenerServingBothUDPAndTCP(t *testing.T) {
	rendered := renderDefaults(t)

	if rendered.ForceTCP != nil {
		t.Errorf("document sets force_tcp = %v; the listener must keep serving UDP as well as TCP", *rendered.ForceTCP)
	}
	for _, address := range rendered.ListenAddresses {
		if strings.Contains(address, "://") {
			t.Errorf("listen address %q carries a transport scheme; dnscrypt-proxy expects a bare host:port", address)
		}
	}
}

// TestRenderIsolatesTheSystemResolverFromForeignQueries proves the host's own
// resolver list is refused and replaced by an explicit provider-name bootstrap
// path. The break it catches is `ignore_system_dns` going false, which would let
// the DHCP-assigned resolver answer foreign queries whenever it answered first.
func TestRenderIsolatesTheSystemResolverFromForeignQueries(t *testing.T) {
	rendered := renderDefaults(t)

	if rendered.IgnoreSystemDNS == nil || !*rendered.IgnoreSystemDNS {
		t.Errorf("ignore_system_dns = %v, want true so the system resolver never answers a foreign query", rendered.IgnoreSystemDNS)
	}
	if got := rendered.Bootstrap; !equalStrings(got, wantBootstrapResolvers) {
		t.Errorf("bootstrap_resolvers = %v, want %v", got, wantBootstrapResolvers)
	}
}

// TestRenderExplainsThatBootstrapIsNotAQueryPath proves the generated file
// states next to bootstrap_resolvers that ordinary queries never use it. The
// break it catches is a plain resolvers-looking list left in a resolver file
// with no explanation, which is indistinguishable from a foreign fallback path
// to whoever reads the file next.
func TestRenderExplainsThatBootstrapIsNotAQueryPath(t *testing.T) {
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	document := string(rendered)

	assignment := "bootstrap_resolvers"
	index := strings.Index(document, assignment)
	if index < 0 {
		t.Fatalf("rendered document has no %s assignment:\n%s", assignment, document)
	}
	const explanation = "never receive ordinary user queries"
	if !strings.Contains(document[:index], explanation) {
		t.Errorf("no comment above %s states that these resolvers %s:\n%s", assignment, explanation, document)
	}
}

// TestRenderEnablesOnlyTheDNSCryptIPv4Path proves the protocol switches admit
// exactly the stamps this renderer accepts, and that no local DoH listener is
// configured. The break it catches is a flag left at a value that admits an
// endpoint the stamps do not contain, which dnscrypt-proxy answers by silently
// registering fewer resolvers than the file names.
func TestRenderEnablesOnlyTheDNSCryptIPv4Path(t *testing.T) {
	rendered := renderDefaults(t)

	for _, flag := range []struct {
		key  string
		got  *bool
		want bool
	}{
		{"ipv4_servers", rendered.IPv4Servers, true},
		{"dnscrypt_servers", rendered.DNSCryptServers, true},
		{"ipv6_servers", rendered.IPv6Servers, false},
		{"doh_servers", rendered.DoHServers, false},
		{"odoh_servers", rendered.ODoHServers, false},
	} {
		if flag.got == nil {
			t.Errorf("%s is absent, want an explicit %v", flag.key, flag.want)
			continue
		}
		if *flag.got != flag.want {
			t.Errorf("%s = %v, want %v", flag.key, *flag.got, flag.want)
		}
	}
	if addresses := rendered.LocalDoH.ListenAddresses; len(addresses) != 0 {
		t.Errorf("local_doh.listen_addresses = %v, want no local DoH listener at all", addresses)
	}
}

// TestRenderPinsThePropertiesItRequires proves the require_* switches match the
// property bits the rendered stamps actually carry, and that NoFilter is not
// required. The break it catches is requiring a property Quad9's filtered
// stamps do not advertise, which would leave the proxy with no resolver at all.
func TestRenderPinsThePropertiesItRequires(t *testing.T) {
	rendered := renderDefaults(t)

	for _, flag := range []struct {
		key  string
		got  *bool
		want bool
	}{
		{"require_dnssec", rendered.RequireDNSSEC, true},
		{"require_nolog", rendered.RequireNoLog, true},
		{"require_nofilter", rendered.RequireNoFilter, false},
	} {
		if flag.got == nil {
			t.Errorf("%s is absent, want an explicit %v", flag.key, flag.want)
			continue
		}
		if *flag.got != flag.want {
			t.Errorf("%s = %v, want %v", flag.key, *flag.got, flag.want)
		}
	}

	// The require_* switches are only meaningful against the stamps' own
	// property words, so this pins the rendered switches to the decoded stamps
	// rather than to a constant either side could drift from.
	for _, stamp := range Defaults() {
		decoded := decodeStamp(t, stamp.Value)
		if !decoded.dnssec {
			t.Errorf("%s does not advertise DNSSEC but the document requires it", stamp.Name)
		}
		if !decoded.noLog {
			t.Errorf("%s does not advertise NoLog but the document requires it", stamp.Name)
		}
		if decoded.noFilter {
			t.Errorf("%s advertises NoFilter; the default endpoints are the filtered ones", stamp.Name)
		}
	}
}

// TestRenderLeavesCachingToMOSDNS proves the proxy keeps no cache of its own.
// The break it catches is a cache reappearing inside the foreign path, where it
// would answer from a copy of a past response that MOSDNS never asked for and
// cannot invalidate.
func TestRenderLeavesCachingToMOSDNS(t *testing.T) {
	rendered := renderDefaults(t)

	if rendered.Cache == nil || *rendered.Cache {
		t.Errorf("cache = %v, want false: the foreign cache belongs to MOSDNS", rendered.Cache)
	}
	if rendered.QueryLog.File != "" {
		t.Errorf("query_log.file = %q, want no query log of user names", rendered.QueryLog.File)
	}
}

// TestRenderProbesReachabilityOverTLS proves the netprobe target is an explicit
// address rather than whatever the first bootstrap resolver happens to be. The
// break it catches is a probe that silently follows the bootstrap list into
// plain DNS on port 53, where a captive portal answers it and the router reports
// a working network it does not have.
//
// The timeout is here rather than in a separate case because the two are one
// decision: WHAT is probed and HOW LONG the resolver waits for it are both about
// the same sentence of the rendered document, and the break this catches is a
// document that probes the right address for so long that the listener arrives
// after the install transaction has stopped waiting for it. Measured: with the
// timeout at dnscrypt-proxy's own default of 60, a container cell with no route
// to the internet logged "Timeout while waiting for network connectivity" and
// bound 127.0.0.1:15353 at the same 60s the transaction gave up waiting, so the
// install refused on a machine whose only fault was that the transaction's
// budget equalled the resolver's own start-up budget.
//
// Zero is refused for a reason rather than as a constant: it switches the probe
// off, and a resolver that binds with no idea whether there is a network behind
// it is one this project cannot tell apart from a healthy one. The upper bound
// is `WAIT_DEADLINE_SECONDS` in installer/mosdns_installer.py, which is where
// the transaction's own budget lives and which the case in
// installer/tests/test_transaction.py reads BOTH sides of, because a bound
// written in this file and a budget written in that one can be changed in step
// and leave either file's own test green.
func TestRenderProbesReachabilityOverTLS(t *testing.T) {
	rendered := renderDefaults(t)

	if rendered.NetprobeAddress != "9.9.9.9:443" {
		t.Errorf("netprobe_address = %q, want %q", rendered.NetprobeAddress, "9.9.9.9:443")
	}
	if rendered.NetprobeTimeout == nil {
		t.Fatal("netprobe_timeout is absent, so the resolver uses dnscrypt-proxy's own default of 60 seconds")
	}
	if *rendered.NetprobeTimeout <= 0 {
		t.Errorf("netprobe_timeout = %d, which switches the probe off: a blackholed network would then be reported by nothing at all", *rendered.NetprobeTimeout)
	}
	if *rendered.NetprobeTimeout >= 60 {
		t.Errorf(
			"netprobe_timeout = %d, which is not shorter than the 60s the install transaction waits for this listener; a machine that cannot reach Quad9 binds the port at the moment the transaction stops waiting",
			*rendered.NetprobeTimeout,
		)
	}
}

// TestRenderUsesNoECSOrUnfilteredEndpoint proves the default stamps are Quad9's
// filtered, non-ECS IPv4 endpoints. ECS hands the resolver the client's subnet
// and the unfiltered endpoints drop the malware and phishing filtering this
// policy is named for, so neither may appear in a foreign query's path.
func TestRenderUsesNoECSOrUnfilteredEndpoint(t *testing.T) {
	_, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	for _, stamp := range Defaults() {
		decoded := decodeStamp(t, stamp.Value)
		for _, ecs := range quad9ECSAddresses {
			if strings.HasPrefix(decoded.address, ecs+":") {
				t.Errorf("%s points at the ECS-capable endpoint %s", stamp.Name, ecs)
			}
		}
		if decoded.noFilter {
			t.Errorf("%s is an unfiltered endpoint, not a Secure one", stamp.Name)
		}
	}
	// Defence in depth: the document itself must not name an ECS or unfiltered
	// Quad9 address, whatever the stamps happen to decode to.
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	for _, forbidden := range append(append([]string{}, quad9ECSAddresses...), "9.9.9.10", "149.112.112.10") {
		if strings.Contains(string(rendered), forbidden) {
			t.Errorf("rendered document names %s, an ECS or unfiltered endpoint", forbidden)
		}
	}
}

// TestRenderNamesNoChinesePublicResolver proves no generated foreign
// configuration points at a well-known Chinese public resolver. The break it
// catches is a stamp or bootstrap entry that would answer a foreign query
// inside the network the user is leaving.
func TestRenderNamesNoChinesePublicResolver(t *testing.T) {
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	document := string(rendered)
	for _, address := range chinesePublicDNSAddresses {
		if strings.Contains(document, address) {
			t.Errorf("rendered document names the Chinese public resolver %s", address)
		}
	}
}

// TestRenderEmitsStampsAsSingleQuotedLiterals proves stamp values are written as
// TOML literal strings in the order supplied. The break it catches is a stamp
// written as a basic string, where a `\` or `"` inside a value would be
// re-interpreted on the way back in, or a map-ordered `[static]` section list
// that makes the file differ between runs.
func TestRenderEmitsStampsAsSingleQuotedLiterals(t *testing.T) {
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	document := string(rendered)

	if !strings.HasSuffix(document, "\n") {
		t.Error("rendered document does not end with a newline")
	}
	previous := -1
	for _, stamp := range Defaults() {
		quoted := "stamp = '" + stamp.Value + "'"
		index := strings.Index(document, quoted)
		if index < 0 {
			t.Fatalf("rendered document has no %q:\n%s", quoted, document)
		}
		if index < previous {
			t.Errorf("[static] sections are not in the order the stamps were supplied:\n%s", document)
		}
		previous = index
	}
	if strings.Contains(document, `stamp = "`) {
		t.Errorf("a stamp is written as a TOML basic string:\n%s", document)
	}
}

// TestRenderUsesOnlyTheSuppliedStamps proves a custom stamp set replaces the
// defaults outright. The break it catches is a renderer that merges the default
// Quad9 endpoints into a custom list, which would silently route foreign
// queries through a provider the operator had chosen to replace.
func TestRenderUsesOnlyTheSuppliedStamps(t *testing.T) {
	custom := []Stamp{{
		Name:  "quad9-dnscrypt-ip4-filter-1",
		Value: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
	}}

	rendered, err := Render(config.Defaults(), custom)
	if err != nil {
		t.Fatalf("Render with a single custom stamp failed: %v", err)
	}
	var decoded foreignConfig
	meta, err := toml.Decode(string(rendered), &decoded)
	if err != nil {
		t.Fatalf("rendered document is not decodable TOML: %v\n%s", err, rendered)
	}
	if undecoded := meta.Undecoded(); len(undecoded) != 0 {
		t.Fatalf("rendered document carries keys this project does not account for: %v", undecoded)
	}

	if len(decoded.ServerNames) != 1 || decoded.ServerNames[0] != custom[0].Name {
		t.Errorf("server_names = %v, want only the supplied stamp %q", decoded.ServerNames, custom[0].Name)
	}
	if len(decoded.Static) != 1 {
		t.Errorf("document defines %d [static] sections, want only the 1 supplied", len(decoded.Static))
	}
	for _, replaced := range Defaults()[1:] {
		if _, ok := decoded.Static[replaced.Name]; ok {
			t.Errorf("document kept the default %s alongside the custom stamps", replaced.Name)
		}
	}
}

// TestRenderRefusesUnusableStampSets proves a stamp set that would produce a
// configuration dnscrypt-proxy cannot serve is refused at render time. The
// fixtures are real Quad9 stamps from the published resolver list, plus the one
// string that list used to serve and no longer does, so each case is a mistake
// this renderer is meant to stop rather than a value invented to fail.
//
// Each case also names the refusal it expects. Several of these stamps would
// trip more than one rule -- a DoH stamp has no provider public key as well as
// the wrong protocol -- so a case that only asserted "some error" would still
// pass with the rule that actually matters deleted.
func TestRenderRefusesUnusableStampSets(t *testing.T) {
	const (
		quad9Filtered = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"
		// Quad9 dnscrypt-ip4-nofilter-pri: NoLog and NoFilter, but no DNSSEC.
		quad9NoDNSSEC = "sdns://AQYAAAAAAAAADTkuOS45LjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA"
		// Quad9 doh-ip4-port443-filter-pri: a DoH stamp, not DNSCrypt.
		quad9DoH = "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"
		// Quad9 dnscrypt-ip6-filter-pri: DNSCrypt, but the document enables
		// ipv4_servers only, so this stamp would never be registered.
		quad9IPv6 = "sdns://AQMAAAAAAAAAElsyNjIwOmZlOjpmZV06ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"
		// DNSCrypt over IPv4 to Quad9's address, but the provider public key is
		// 16 bytes instead of the 32 an Ed25519 certificate is signed with. The
		// provider name is padded past the decoder's 66-byte floor so that this
		// stamp is refused for its key and for nothing else.
		quad9ShortKey = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MxBnyEe4yHWM0SAkVUO-dWdGITIuZG5zY3J5cHQtY2VydC5xdWFkOS5leGFtcGxlLm5ldA"
		// Quad9's address and provider key with the DNSSEC property alone: the
		// one published variant is missing, so this is built from the wire
		// format to isolate the NoLog rule, which no real Quad9 stamp violates.
		quad9NoNoLog = "sdns://AQEAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"
	)

	for _, testCase := range []struct {
		name        string
		stamps      []Stamp
		wantRefusal string
	}{
		{"no stamps at all", nil, "no DNSCrypt stamps supplied"},
		{"a stamp with no name", []Stamp{{Name: "", Value: quad9Filtered}}, "empty name"},
		{"two stamps sharing one name", []Stamp{{Name: "quad9", Value: quad9Filtered}, {Name: "quad9", Value: quad9Filtered}}, "used more than once"},
		{"a value that is not a stamp", []Stamp{{Name: "quad9", Value: "https://dns.quad9.net/dns-query"}}, `must start with "sdns://"`},
		{"a bare address instead of a stamp", []Stamp{{Name: "quad9", Value: "9.9.9.9"}}, `must start with "sdns://"`},
		{"a stamp that does not decode", []Stamp{{Name: "quad9", Value: staleCorruptAlt2Stamp}}, "does not decode"},
		{"a truncated stamp", []Stamp{{Name: "quad9", Value: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0"}}, "does not decode"},
		{"a plain-DNS stamp", []Stamp{{Name: "plain", Value: "sdns://AAAAAAAAAAAABzEuMS4xLjE"}}, "protocol is Plain"},
		{"a DoH stamp", []Stamp{{Name: "doh", Value: quad9DoH}}, "protocol is DoH"},
		{"a stamp with no DNSSEC property", []Stamp{{Name: "no-dnssec", Value: quad9NoDNSSEC}}, "does not advertise DNSSEC"},
		{"an IPv6 stamp behind ipv4_servers", []Stamp{{Name: "ipv6", Value: quad9IPv6}}, "is IPv6, but this document enables ipv4_servers only"},
		{"a stamp with a short provider key", []Stamp{{Name: "short-key", Value: quad9ShortKey}}, "provider public key is 16 bytes"},
		{"a stamp that cannot promise no-log", []Stamp{{Name: "no-nolog", Value: quad9NoNoLog}}, "does not advertise NoLog"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rendered, err := Render(config.Defaults(), testCase.stamps)
			if err == nil {
				t.Fatalf("Render accepted %v and wrote:\n%s", testCase.stamps, rendered)
			}
			if !strings.Contains(err.Error(), testCase.wantRefusal) {
				t.Fatalf("Render refused %v with %q, want a refusal naming %q", testCase.stamps, err, testCase.wantRefusal)
			}
		})
	}
}

// TestRenderRefusesECSWhenThePolicyAsksForIt proves an ECS request is refused
// rather than rendered. The stamps carry no ECS endpoint, so a document that
// claimed to forward ECS would advertise a privacy property the transport does
// not have; the policy has to be changed together with the stamps instead.
func TestRenderRefusesECSWhenThePolicyAsksForIt(t *testing.T) {
	policy := config.Defaults()
	policy.Foreign.ECS = true

	if _, err := Render(policy, Defaults()); err == nil {
		t.Fatal("Render accepted a policy that requires ECS, with stamps that cannot forward it")
	}
}

// TestCommittedConfigIsExactlyTheRenderedDefault proves the shipped
// configs/dnscrypt-proxy.toml is the output of the renderer for the shipped
// policy and stamps. The break it catches is hand-editing the file -- the file
// dnscrypt-proxy actually reads -- away from what this project believes it
// deploys.
func TestCommittedConfigIsExactlyTheRenderedDefault(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", "configs", "dnscrypt-proxy.toml"))
	if err != nil {
		t.Fatalf("cannot read the committed dnscrypt-proxy.toml: %v", err)
	}
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), Defaults()) failed: %v", err)
	}
	if string(committed) != string(rendered) {
		t.Errorf("configs/dnscrypt-proxy.toml is not the output of Render(config.Defaults(), Defaults())\n--- committed ---\n%s\n--- rendered ---\n%s", committed, rendered)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

// decodedStamp is what the pinned DNSCrypt stamp wire format actually carries.
// The tests decode with the same library dnscrypt-proxy 2.1.18 uses, so a stamp
// these tests accept is one dnscrypt-proxy can load, not one this project's own
// wrapper happens to tolerate.
type decodedStamp struct {
	address        string
	providerName   string
	providerKeyHex string
	dnssec         bool
	noLog          bool
	noFilter       bool
	proto          dnsstamps.StampProtoType
}

func decodeStamp(t *testing.T, value string) decodedStamp {
	t.Helper()
	stamp, err := dnsstamps.NewServerStampFromString(value)
	if err != nil {
		t.Fatalf("stamp %s does not decode with the library dnscrypt-proxy 2.1.18 uses: %v", value, err)
	}
	return decodedStamp{
		address:        stamp.ServerAddrStr,
		providerName:   stamp.ProviderName,
		providerKeyHex: hex.EncodeToString(stamp.ServerPk),
		dnssec:         stamp.Props&dnsstamps.ServerInformalPropertyDNSSEC != 0,
		noLog:          stamp.Props&dnsstamps.ServerInformalPropertyNoLog != 0,
		noFilter:       stamp.Props&dnsstamps.ServerInformalPropertyNoFilter != 0,
		proto:          stamp.Proto,
	}
}

// TestTheExportedListenerIsTheOneTheDocumentBinds exists because the routing
// renderer has to name this same address, and the two agreeing is the whole of
// what the ECH fetch's correctness rests on: the key is fetched through the
// listener this document binds.
//
// A second copy of the string in the routing package would make that agreement a
// coincidence, and a coincidence is invisible until the day someone edits one and
// not the other. Asserting ListenAddress equals the constant the document was
// rendered with turns the coincidence into a compile-time-ish fact.
func TestTheExportedListenerIsTheOneTheDocumentBinds(t *testing.T) {
	rendered, err := Render(config.Defaults(), Defaults())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(rendered), foreignListener) {
		t.Fatalf("the rendered resolver document does not bind %s", foreignListener)
	}
	if ListenAddress != foreignListener {
		t.Fatalf("ListenAddress is %q but the document binds %q, so the routing renderer "+
			"would read a different address than the resolver listens on", ListenAddress, foreignListener)
	}
}
