package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nishikawaakira/kernledger/internal/audit"
	"github.com/nishikawaakira/kernledger/internal/executor"
)

// failingExecutor always returns a non-nil error so we can exercise
// the error branch of runItem without spawning real processes.
type failingExecutor struct{}

func (failingExecutor) Run(_ context.Context, name string, args ...string) (*executor.Result, error) {
	return &executor.Result{Command: name, Args: args, ExitCode: 1}, errors.New("synthetic failure")
}

// readAuditLog parses the JSONL file at path and returns the entries
// for the given action.
func readAuditLog(t *testing.T, path, action string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]interface{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<16), 1<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		if ev["action"] == action {
			out = append(out, ev)
		}
	}
	return out
}

func TestRunItem_MandatoryFailureLogsWarn(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	log, err := audit.NewFileLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{Exec: failingExecutor{}, Log: log, Opts: Options{OutDir: dir}}

	collectDir := filepath.Join(dir, "collect")
	if err := os.MkdirAll(collectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c.runItem(context.Background(), collectDir, Item{Name: "ps", Cmd: "ps", Args: []string{"auxwwf"}, Optional: false})
	c.runItem(context.Background(), collectDir, Item{Name: "pstree", Cmd: "pstree", Args: []string{"-alp"}, Optional: true})
	log.Close()

	entries := readAuditLog(t, logPath, "collect.item.error")
	if len(entries) != 2 {
		t.Fatalf("expected 2 error entries, got %d", len(entries))
	}
	byItem := map[string]map[string]interface{}{}
	for _, e := range entries {
		f, _ := e["fields"].(map[string]interface{})
		name, _ := f["item"].(string)
		byItem[name] = e
	}
	if got := byItem["ps"]["level"]; got != "warn" {
		t.Errorf("mandatory item ps: level=%v, want warn", got)
	}
	if got := byItem["pstree"]["level"]; got != "info" {
		t.Errorf("optional item pstree: level=%v, want info", got)
	}
	// Message text should distinguish the two cases.
	if msg, _ := byItem["ps"]["message"].(string); !strings.Contains(msg, "mandatory") {
		t.Errorf("ps message lacks 'mandatory': %q", msg)
	}
	if msg, _ := byItem["pstree"]["message"].(string); !strings.Contains(msg, "optional") {
		t.Errorf("pstree message lacks 'optional': %q", msg)
	}
}

func TestCollectorRun_DryRunCreatesLayout(t *testing.T) {
	outDir := t.TempDir()
	log, err := audit.NewFileLogger(filepath.Join(outDir, "audit.log"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	c := New(executor.NewReal(0), nil, log, Options{
		OutDir: outDir,
		DryRun: true,
	})
	col, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if col == nil || len(col.Items) == 0 {
		t.Fatal("expected items in dry run")
	}
	// collect dir must exist.
	if _, err := os.Stat(filepath.Join(outDir, "collect")); err != nil {
		t.Errorf("collect dir missing: %v", err)
	}
}
