package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRealExecutor_Echo(t *testing.T) {
	e := NewReal(2 * time.Second)
	r, err := e.Run(context.Background(), "sh", "-c", "echo hello && >&2 echo world")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if r.ExitCode != 0 {
		t.Errorf("exit code = %d", r.ExitCode)
	}
	if !strings.Contains(string(r.Stdout), "hello") {
		t.Errorf("stdout missing 'hello': %q", string(r.Stdout))
	}
	if !strings.Contains(string(r.Stderr), "world") {
		t.Errorf("stderr missing 'world': %q", string(r.Stderr))
	}
	if r.Duration <= 0 {
		t.Errorf("duration not recorded: %v", r.Duration)
	}
}

func TestRealExecutor_NonZeroExit(t *testing.T) {
	e := NewReal(2 * time.Second)
	r, err := e.Run(context.Background(), "sh", "-c", "exit 7")
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	if r == nil {
		t.Fatal("expected non-nil result even on failure")
	}
	if r.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", r.ExitCode)
	}
}

func TestDryRunExecutor_RecordsButDoesNotExecute(t *testing.T) {
	d := NewDryRun()
	r, err := d.Run(context.Background(), "rm", "-rf", "/")
	if err != nil {
		t.Fatalf("dry-run should never fail: %v", err)
	}
	if !r.DryRun {
		t.Error("DryRun flag not set")
	}
	if len(d.Calls) != 1 || d.Calls[0].Command != "rm" {
		t.Errorf("calls = %+v", d.Calls)
	}
}
