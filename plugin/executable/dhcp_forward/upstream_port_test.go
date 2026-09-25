package dhcp_forward

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
)

// forwardFromConfigArgs builds the plugin the way a mosdns configuration file
// builds it: the arguments arrive as the decoded document, so the argument
// names, the defaults and the refusals below are the ones a configuration file
// gets, not the ones this package would use for itself.
func forwardFromConfigArgs(t *testing.T, args map[string]any) (*Forward, error) {
	t.Helper()
	mosdns, err := coremain.NewMosdns(&coremain.Config{
		Log:     mlog.LogConfig{Level: "error"},
		Plugins: []coremain.PluginConfig{{Tag: "dhcp_forward", Type: "dhcp_forward", Args: args}},
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		mosdns.CloseWithErr(nil)
		_ = mosdns.GetSafeClose().WaitClosed()
	})
	forward, ok := mosdns.GetPlugin("dhcp_forward").(*Forward)
	if !ok {
		t.Fatalf("the loaded plugin is %T, want the dhcp_forward plugin of this package", mosdns.GetPlugin("dhcp_forward"))
	}
	return forward, nil
}

// TestUpstreamPortComesFromThePluginArguments covers the port a published state
// cannot carry. The bridge publishes bare addresses, so the port a query is sent
// to is a property of this plugin's configuration, and a configuration file that
// cannot set it would send every domestic query to a port nothing is listening
// on.
func TestUpstreamPortComesFromThePluginArguments(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dhcp-upstreams.json")

	unset, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile})
	if err != nil {
		t.Fatalf("mosdns refused the dhcp_forward plugin: %v", err)
	}
	if unset.rt.port != 53 {
		t.Fatalf("dial port with no upstream_port = %d, want the DNS port 53", unset.rt.port)
	}

	configured, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile, "upstream_port": 15353})
	if err != nil {
		t.Fatalf("mosdns refused a configured upstream_port: %v", err)
	}
	if configured.rt.port != 15353 {
		t.Fatalf("dial port = %d, want the configured 15353", configured.rt.port)
	}
}

// TestAnUpstreamPortOutsideItsRangeIsRefused covers the values a configuration
// file could carry that no UDP or TCP dial could use. A port that is refused
// must stop the router: clamped or wrapped, it would send domestic queries to a
// port nobody chose.
func TestAnUpstreamPortOutsideItsRangeIsRefused(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dhcp-upstreams.json")

	for name, port := range map[string]int{
		"negative":        -1,
		"one above 65535": 65536,
		"far above 65535": 100000,
	} {
		if forward, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile, "upstream_port": port}); err == nil {
			t.Fatalf("%s upstream_port %d was accepted, and the plugin would dial port %d", name, port, forward.rt.port)
		}
	}
}

// TestTheUpstreamPortRefusalSaysWhatZeroMeans covers the message rather than the
// range. This plugin accepts 0 and dials 53 for it, so a refusal that only says
// "must be between 1 and 65535" describes a range 0 is not outside of, and an
// operator who wrote upstream_port: 0 has no way to tell it from a value that was
// refused. The renderer that produces the configuration repeats the same wording,
// so the two have to agree.
func TestTheUpstreamPortRefusalSaysWhatZeroMeans(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dhcp-upstreams.json")

	_, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile, "upstream_port": 65536})
	if err == nil {
		t.Fatal("mosdns accepted a port past 65535")
	}
	refusal := err.Error()
	for name, want := range map[string]string{
		"the port it refused":  "65536",
		"that zero means 53":   "0 means the default 53",
		"the range it accepts": "between 1 and 65535",
	} {
		if !strings.Contains(refusal, want) {
			t.Errorf("the refusal does not say %s (%q):\n%v", name, want, err)
		}
	}

	// And the value the message calls the default is still dialled.
	unset, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile, "upstream_port": 0})
	if err != nil {
		t.Fatalf("mosdns refused the port the refusal calls the default: %v", err)
	}
	if unset.rt.port != 53 {
		t.Errorf("upstream_port 0 dialled port %d, want the 53 the refusal names", unset.rt.port)
	}
}
