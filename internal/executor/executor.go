// Package executor abstracts external command execution so collection
// and acquisition logic can be unit-tested without invoking real binaries.
//
// All shell-touching code in al2-mem-ir MUST go through this interface.
// That guarantees a single chokepoint for:
//   - dry-run handling
//   - audit logging
//   - timeout / cancellation
//   - test substitution
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Result captures the full outcome of a single command invocation.
// It is designed to be serialized into the acquisition / collection
// manifest verbatim — do not strip fields when persisting.
type Result struct {
	Command   string        `json:"command"`
	Args      []string      `json:"args"`
	Stdout    []byte        `json:"-"`
	Stderr    []byte        `json:"-"`
	ExitCode  int           `json:"exit_code"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Duration  time.Duration `json:"duration_ns"`
	Err       string        `json:"error,omitempty"`
	DryRun    bool          `json:"dry_run"`
}

// Executor runs commands on the host. Implementations:
//   - RealExecutor: invokes the binary
//   - DryRunExecutor: records the intent and returns synthesized success
//   - FakeExecutor:   used in tests
type Executor interface {
	Run(ctx context.Context, name string, args ...string) (*Result, error)
}

// RealExecutor runs commands via os/exec.
type RealExecutor struct {
	// DefaultTimeout is applied per command if the context has no deadline.
	DefaultTimeout time.Duration
}

func NewReal(defaultTimeout time.Duration) *RealExecutor {
	if defaultTimeout <= 0 {
		defaultTimeout = 30 * time.Second
	}
	return &RealExecutor{DefaultTimeout: defaultTimeout}
}

func (r *RealExecutor) Run(ctx context.Context, name string, args ...string) (*Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.DefaultTimeout)
		defer cancel()
	}

	res := &Result{
		Command:   name,
		Args:      append([]string(nil), args...),
		StartedAt: time.Now().UTC(),
	}

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res.EndedAt = time.Now().UTC()
	res.Duration = res.EndedAt.Sub(res.StartedAt)
	res.Stdout = stdout.Bytes()
	res.Stderr = stderr.Bytes()

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
			res.Err = err.Error()
		}
		// We still return the Result; callers decide whether the failure
		// is fatal. Forensic collection MUST continue on per-command errors.
		return res, fmt.Errorf("command %s failed: %w", name, err)
	}
	return res, nil
}

// DryRunExecutor records what would have been executed but never invokes it.
type DryRunExecutor struct {
	Calls []Result
}

func NewDryRun() *DryRunExecutor { return &DryRunExecutor{} }

func (d *DryRunExecutor) Run(_ context.Context, name string, args ...string) (*Result, error) {
	now := time.Now().UTC()
	r := Result{
		Command:   name,
		Args:      append([]string(nil), args...),
		StartedAt: now,
		EndedAt:   now,
		DryRun:    true,
	}
	d.Calls = append(d.Calls, r)
	return &r, nil
}
