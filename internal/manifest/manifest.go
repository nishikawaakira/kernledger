// Package manifest defines the on-disk JSON contract for IR evidence.
//
// The manifest is the canonical chain-of-custody document. It MUST be:
//   - human-readable JSON
//   - stable across versions (use SchemaVersion)
//   - append-only with respect to a given case (never edit in place)
//
// A bundle produced by `al2-mem-ir package` contains exactly one
// Manifest covering all artifacts in the archive.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SchemaVersion bumps when fields are removed or semantically changed.
// Additive changes do not require a bump.
const SchemaVersion = "1.0.0"

// Manifest is the top-level evidence record.
type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          ToolInfo       `json:"tool"`
	Case          CaseInfo       `json:"case"`
	Host          HostInfo       `json:"host"`
	Cloud         *CloudInfo     `json:"cloud,omitempty"`
	Acquisition   *Acquisition   `json:"acquisition,omitempty"`
	Collection    *Collection    `json:"collection,omitempty"`
	Analysis      *Analysis      `json:"analysis,omitempty"`
	Artifacts     []Artifact     `json:"artifacts"`
	Events        []EventSummary `json:"events,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// ToolInfo identifies the producing binary.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Distro  string `json:"distro_adapter"`
}

// CaseInfo carries chain-of-custody fields.
type CaseInfo struct {
	CaseID    string `json:"case_id,omitempty"`
	Operator  string `json:"operator,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Authority string `json:"authority,omitempty"`
}

// HostInfo describes the target system.
type HostInfo struct {
	Hostname      string `json:"hostname"`
	KernelRelease string `json:"kernel_release"`
	KernelVersion string `json:"kernel_version,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	OSPrettyName  string `json:"os_pretty_name,omitempty"`
	OSID          string `json:"os_id,omitempty"`
	OSVersionID   string `json:"os_version_id,omitempty"`
}

// CloudInfo holds cloud metadata when --include-ec2-metadata is set.
type CloudInfo struct {
	Provider     string `json:"provider"`
	InstanceID   string `json:"instance_id,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`
	Region       string `json:"region,omitempty"`
	AvailZone    string `json:"availability_zone,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	AMIID        string `json:"ami_id,omitempty"`
}

// Acquisition records a single LiME memory acquisition attempt.
type Acquisition struct {
	Engine          string    `json:"engine"`
	ModulePath      string    `json:"module_path"`
	ModuleSHA256    string    `json:"module_sha256,omitempty"`
	OutputPath      string    `json:"output_path"`
	OutputFormat    string    `json:"output_format"`
	OutputMode      string    `json:"output_mode"`
	InsmodStartedAt time.Time `json:"insmod_started_at"`
	InsmodEndedAt   time.Time `json:"insmod_ended_at"`
	RmmodPerformed  bool      `json:"rmmod_performed"`
	RmmodEndedAt    time.Time `json:"rmmod_ended_at,omitempty"`
	ImageSHA256     string    `json:"image_sha256,omitempty"`
	ImageBytes      int64     `json:"image_bytes,omitempty"`
	DryRun          bool      `json:"dry_run"`
	DmesgTailPath   string    `json:"dmesg_tail_path,omitempty"`
	Notes           string    `json:"notes,omitempty"`
}

// Collection records a `collect` run.
type Collection struct {
	StartedAt   time.Time      `json:"started_at"`
	EndedAt     time.Time      `json:"ended_at"`
	Items       []CollectedCmd `json:"items"`
	IncludedEnv bool           `json:"included_env"`
	OutputDir   string         `json:"output_dir"`
}

// CollectedCmd is the audit row for a single collected datum.
type CollectedCmd struct {
	Name       string        `json:"name"`
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	StdoutPath string        `json:"stdout_path,omitempty"`
	StderrPath string        `json:"stderr_path,omitempty"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration_ns"`
	Err        string        `json:"error,omitempty"`
	Skipped    bool          `json:"skipped,omitempty"`
	SkipReason string        `json:"skip_reason,omitempty"`
}

// Analysis records a Volatility 3 run (analyst side).
type Analysis struct {
	Volatility   string         `json:"volatility_path"`
	ImagePath    string         `json:"image_path"`
	SymbolsPath  string         `json:"symbols_path"`
	StartedAt    time.Time      `json:"started_at"`
	EndedAt      time.Time      `json:"ended_at"`
	PluginResults []PluginResult `json:"plugin_results"`
	ReportPath   string         `json:"report_path,omitempty"`
}

// Summary counts how many plugins succeeded and failed.
//
// A plugin is considered FAILED when either:
//   - PluginResult.Err is non-empty (the executor reported a non-zero
//     exit, a context cancellation, or a binary that could not be
//     launched), OR
//   - PluginResult.ExitCode != 0 (the binary launched and returned a
//     non-zero status).
//
// Both conditions are checked so a future executor that records exit
// code without setting Err — or vice versa — still counts as a failure.
// Callers use this to decide CLI exit codes and to render summaries.
func (a *Analysis) Summary() (succeeded, failed int) {
	if a == nil {
		return 0, 0
	}
	for _, pr := range a.PluginResults {
		if pr.Err != "" || pr.ExitCode != 0 {
			failed++
		} else {
			succeeded++
		}
	}
	return
}

// PluginResult records one Volatility plugin invocation. Command/Args
// capture the exact invocation so an analyst can re-run it from the
// manifest alone — this is part of the chain-of-custody requirement
// that "what was executed" be recoverable post-hoc.
type PluginResult struct {
	Plugin     string        `json:"plugin"`
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	OutputPath string        `json:"output_path"`
	Format     string        `json:"format"`
	ExitCode   int           `json:"exit_code"`
	StartedAt  time.Time     `json:"started_at"`
	EndedAt    time.Time     `json:"ended_at"`
	Duration   time.Duration `json:"duration_ns"`
	Err        string        `json:"error,omitempty"`
}

// Artifact is a hashed file referenced from the manifest.
type Artifact struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size_bytes"`
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
}

// EventSummary mirrors a subset of audit.Event for embedding in manifests.
type EventSummary struct {
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Action    string    `json:"action"`
	Message   string    `json:"message,omitempty"`
}

// New constructs a Manifest with defaults filled in.
func New(toolVersion, commit, distroAdapter string) *Manifest {
	return &Manifest{
		SchemaVersion: SchemaVersion,
		Tool: ToolInfo{
			Name:    "al2-mem-ir",
			Version: toolVersion,
			Commit:  commit,
			Distro:  distroAdapter,
		},
		CreatedAt: time.Now().UTC(),
	}
}

// Save writes the manifest to path with 0o600 permissions.
func (m *Manifest) Save(path string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}
	return nil
}

// Load reads a manifest from disk.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return &m, nil
}
