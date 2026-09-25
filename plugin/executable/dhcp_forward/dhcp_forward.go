// Package dhcp_forward forwards a query to the DNS servers the DHCP client is
// currently configured with, and swaps them while MOSDNS keeps running.
//
// The published DHCP state is the only source of upstreams. Every query reloads
// the state file before it looks in the cache, so a DHCP DNS change takes effect
// for the next query without restarting the process. A generation owns its own
// upstream clients and its own cache, and a replaced generation stays alive for a
// retirement window so an exchange that is already in flight can still finish.
package dhcp_forward

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"go.uber.org/zap"
)

// PluginType is the tag a mosdns configuration uses for this plugin.
const PluginType = "dhcp_forward"

// The documented defaults. An unset field takes the default; a field outside its
// documented range is refused rather than clamped.
const (
	defaultUpstreamTimeoutMS  = 5000
	defaultConcurrency        = 2
	maxConcurrency            = 2
	defaultRetireAfterSeconds = 60
	defaultCacheEntries       = 4096
	defaultUpstreamPort       = 53
	maximumUpstreamPort       = 65535
)

// The two documented failure policies. A published generation that names no
// usable upstream is a real DHCP event, and the two policies disagree about
// what it means: disable-current adopts it so the branch fails closed, and
// use-last-good keeps serving the last generation that could answer. Any other
// value is a configuration error, because a safety switch nobody implements
// must not be treated as either of them.
const (
	failurePolicyDisableCurrent = "disable-current"
	failurePolicyUseLastGood    = "use-last-good"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Args is the plugin configuration.
type Args struct {
	// StateFile is the published DHCP state document. Required.
	StateFile string `yaml:"state_file"`
	// UpstreamTimeoutMS bounds one upstream attempt, including its TCP retry
	// after a truncated UDP answer. Default 5000.
	UpstreamTimeoutMS int `yaml:"upstream_timeout_ms"`
	// Concurrency is how many distinct upstreams one query races. Default and
	// maximum 2.
	Concurrency int `yaml:"concurrency"`
	// RetireAfterSeconds is how long a replaced generation keeps its clients.
	// Default 60, and never shorter than the upstream timeout.
	RetireAfterSeconds int `yaml:"retire_after_seconds"`
	// CacheEntries bounds one generation's cache. Default 4096.
	CacheEntries int `yaml:"cache_entries"`
	// UpstreamPort is the port a published address is dialled on. A published
	// state carries bare addresses, so the port is a property of this
	// configuration. Default 53, the port a DHCP DNS server answers on.
	UpstreamPort int `yaml:"upstream_port"`
	// FailurePolicy decides what a newer generation without a usable upstream
	// means: "disable-current" adopts it and fails the branch closed, and
	// "use-last-good" keeps serving the last generation that had upstreams and
	// reports how old it is. Default "disable-current".
	FailurePolicy string `yaml:"failure_policy"`
}

// Init builds the plugin from a decoded configuration.
func Init(bp *coremain.BP, args any) (any, error) {
	pluginArgs, ok := args.(*Args)
	if !ok {
		return nil, fmt.Errorf("dhcp_forward: args must be *Args, got %T", args)
	}
	return New(*pluginArgs, bp)
}

// New builds the plugin for a mosdns plugin base.
func New(args Args, bp *coremain.BP) (sequence.Executable, error) {
	if bp == nil {
		return nil, errors.New("dhcp_forward: a plugin base is required")
	}
	// The dial port is a configuration field, so it is resolved here rather
	// than injected by a caller: a configuration file that names no port gets
	// the documented default instead of a hard-coded one.
	resolved, err := args.withDefaults()
	if err != nil {
		return nil, err
	}
	return newForwardWithState(resolved, bp.L(), readDHCPState, uint16(resolved.UpstreamPort))
}

// Forward is the executable a mosdns sequence runs.
type Forward struct {
	rt *runtime
}

var _ sequence.Executable = (*Forward)(nil)

// Exec forwards one query to the current generation, or returns an error and no
// response. An error leaves the response unset so the caller fails closed.
func (f *Forward) Exec(ctx context.Context, qCtx *query_context.Context) error {
	response, err := f.rt.exchange(ctx, qCtx.Q())
	if err != nil {
		return err
	}
	qCtx.SetResponse(response)
	return nil
}

// Close releases the clients of the current and of every retired generation. It
// is safe to call more than once.
func (f *Forward) Close() error {
	return f.rt.close()
}

// newForwardWithState is the construction path that names its dependencies: a
// logger and the reader that loads a published state document. Production uses
// readDHCPState, which refuses anything the state schema rejects; a test injects
// a reader because the loopback addresses a test server listens on are not
// publishable upstreams.
func newForwardWithState(args Args, logger *zap.Logger, read readStateFunc, port uint16) (*Forward, error) {
	resolved, err := args.withDefaults()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if read == nil {
		return nil, errors.New("dhcp_forward: a state reader is required")
	}
	if port == 0 {
		return nil, errors.New("dhcp_forward: an upstream port is required")
	}
	return &Forward{rt: &runtime{
		logger:        logger,
		read:          read,
		stateFile:     resolved.StateFile,
		port:          port,
		timeout:       time.Duration(resolved.UpstreamTimeoutMS) * time.Millisecond,
		concurrency:   resolved.Concurrency,
		retireAfter:   time.Duration(resolved.RetireAfterSeconds) * time.Second,
		cacheEntries:  resolved.CacheEntries,
		failurePolicy: resolved.FailurePolicy,
	}}, nil
}

// withDefaults fills the documented defaults and refuses a configuration that
// cannot be served safely.
func (args Args) withDefaults() (Args, error) {
	resolved := args
	if resolved.StateFile == "" {
		return resolved, errors.New("dhcp_forward: state_file must not be empty")
	}
	if resolved.UpstreamTimeoutMS < 0 {
		return resolved, fmt.Errorf("dhcp_forward: upstream_timeout_ms must not be negative, got %d", resolved.UpstreamTimeoutMS)
	}
	if resolved.UpstreamTimeoutMS == 0 {
		resolved.UpstreamTimeoutMS = defaultUpstreamTimeoutMS
	}
	if resolved.Concurrency < 0 {
		return resolved, fmt.Errorf("dhcp_forward: concurrency must not be negative, got %d", resolved.Concurrency)
	}
	if resolved.Concurrency == 0 {
		resolved.Concurrency = defaultConcurrency
	}
	if resolved.Concurrency > maxConcurrency {
		return resolved, fmt.Errorf("dhcp_forward: concurrency must be between 1 and %d, got %d", maxConcurrency, resolved.Concurrency)
	}
	if resolved.RetireAfterSeconds < 0 {
		return resolved, fmt.Errorf("dhcp_forward: retire_after_seconds must not be negative, got %d", resolved.RetireAfterSeconds)
	}
	if resolved.RetireAfterSeconds == 0 {
		resolved.RetireAfterSeconds = defaultRetireAfterSeconds
	}
	if resolved.CacheEntries < 0 {
		return resolved, fmt.Errorf("dhcp_forward: cache_entries must not be negative, got %d", resolved.CacheEntries)
	}
	if resolved.CacheEntries == 0 {
		resolved.CacheEntries = defaultCacheEntries
	}
	if resolved.UpstreamPort < 0 {
		return resolved, fmt.Errorf("dhcp_forward: upstream_port must not be negative, got %d", resolved.UpstreamPort)
	}
	if resolved.UpstreamPort == 0 {
		resolved.UpstreamPort = defaultUpstreamPort
	}
	if resolved.UpstreamPort > maximumUpstreamPort {
		return resolved, fmt.Errorf("dhcp_forward: upstream_port must be between 1 and %d, got %d", maximumUpstreamPort, resolved.UpstreamPort)
	}
	if resolved.FailurePolicy == "" {
		resolved.FailurePolicy = failurePolicyDisableCurrent
	}
	if resolved.FailurePolicy != failurePolicyDisableCurrent && resolved.FailurePolicy != failurePolicyUseLastGood {
		return resolved, fmt.Errorf(
			"dhcp_forward: failure_policy must be %s or %s, got %q",
			failurePolicyDisableCurrent, failurePolicyUseLastGood, resolved.FailurePolicy,
		)
	}
	// A replaced generation has to keep its clients for as long as an exchange
	// that started against them can still run, otherwise a DHCP change could
	// cut a query that is already on the wire.
	minimumRetirement := (resolved.UpstreamTimeoutMS + 999) / 1000
	if resolved.RetireAfterSeconds < minimumRetirement {
		return resolved, fmt.Errorf(
			"dhcp_forward: retire_after_seconds must be at least %d for an upstream_timeout_ms of %d",
			minimumRetirement, resolved.UpstreamTimeoutMS,
		)
	}
	return resolved, nil
}
