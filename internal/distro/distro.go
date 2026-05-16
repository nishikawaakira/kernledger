// Package distro defines the abstraction that lets al2-mem-ir target
// different Linux distributions without sprinkling `if/switch` blocks
// throughout the codebase.
//
// Design intent:
//   - Each distribution provides an Adapter implementation.
//   - Adapters self-register via init() in their own subpackage.
//   - The CLI looks up an Adapter at startup using Detect() OR an
//     explicit --distro flag.
//   - Adding a new distro = adding a new internal/distro/<name>/ package
//     and blank-importing it from cmd/al2-mem-ir/main.go.
//
// Concrete capability interfaces are intentionally small. A new distro
// only has to implement the pieces it can meaningfully differentiate;
// shared behavior lives in helper packages instead.
package distro

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// KernelInfo is the minimum set of kernel facts that drive symbol
// generation and LiME module selection.
type KernelInfo struct {
	Release      string // e.g. "5.10.220-209.869.amzn2.x86_64"
	Version      string // e.g. uname -v
	Architecture string // e.g. "x86_64"
	Tainted      string // contents of /proc/sys/kernel/tainted (best effort)
}

// OSInfo is parsed from /etc/os-release.
type OSInfo struct {
	ID         string // e.g. "amzn"
	VersionID  string // e.g. "2"
	PrettyName string // e.g. "Amazon Linux 2"
	Name       string // e.g. "Amazon Linux"
}

// ArtifactPaths lists distro-specific log / config locations the
// collector should attempt. Globs are allowed; the collector resolves them.
type ArtifactPaths struct {
	SystemLogs       []string // e.g. /var/log/messages, /var/log/secure
	CronConfigs      []string // /etc/crontab, /etc/cron.d/*
	CloudInitLogs    []string
	AgentLogs        []string // SSM, ECS, CloudWatch agent paths
	AuthorizedKeys   []string // glob patterns
}

// ServiceQuery returns the commands used to enumerate services.
// Each entry is (name, command, args...).
type ServiceQuery struct {
	Name string
	Cmd  string
	Args []string
}

// LimeHints expose what the adapter knows about kernel-module loading.
// This information is informational only; al2-mem-ir does NOT make
// security decisions based on it.
type LimeHints struct {
	KernelDevelPackage string // e.g. "kernel-devel-<release>"
	DebuginfoPackage   string // e.g. "kernel-debuginfo-<release>"
	ModuleLoadCommand  string // typically "insmod"
	ExpectedModuleExt  string // ".ko"
}

// CloudProvider abstracts metadata lookups (EC2 IMDSv2, etc).
type CloudProvider interface {
	Name() string
	Fetch(ctx context.Context) (map[string]string, error)
}

// Adapter is the full distro contract.
type Adapter interface {
	// ID returns the short identifier, matching what --distro accepts.
	ID() string

	// Describe returns a human label, e.g. "Amazon Linux 2".
	Describe() string

	// Detect inspects the running host (or its /etc/os-release content
	// passed in) and returns true if this adapter applies.
	Detect(os OSInfo) bool

	// Paths lists log / config artifacts to collect.
	Paths() ArtifactPaths

	// ServiceQueries returns the service-enumeration commands.
	ServiceQueries() []ServiceQuery

	// LimeHints returns LiME-related package and module guidance.
	LimeHints(k KernelInfo) LimeHints

	// CloudProviders returns metadata providers to try, in order.
	CloudProviders() []CloudProvider
}

// ----- registry -----

var (
	mu       sync.RWMutex
	registry = map[string]Adapter{}
)

// Register adds an adapter. Called from each adapter's init().
// Duplicate IDs panic — this is a programming error.
func Register(a Adapter) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[a.ID()]; exists {
		panic(fmt.Sprintf("distro: duplicate adapter id %q", a.ID()))
	}
	registry[a.ID()] = a
}

// Get returns the adapter with the given ID.
func Get(id string) (Adapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := registry[id]
	return a, ok
}

// IDs returns all registered IDs in sorted order.
func IDs() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DetectFromOSRelease walks registered adapters and returns the first
// one whose Detect returns true. If --distro was supplied by the user,
// callers should use Get() instead.
func DetectFromOSRelease(os OSInfo) (Adapter, error) {
	mu.RLock()
	defer mu.RUnlock()
	// Iterate in sorted order for deterministic behavior.
	keys := make([]string, 0, len(registry))
	for k := range registry {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if registry[k].Detect(os) {
			return registry[k], nil
		}
	}
	return nil, fmt.Errorf("no distro adapter matched (id=%q, version=%q)", os.ID, os.VersionID)
}
