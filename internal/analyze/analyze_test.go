package analyze

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/kernledger/internal/audit"
	"github.com/example/kernledger/internal/executor"
	"github.com/example/kernledger/internal/manifest"
)

// fakeExecutor satisfies executor.Executor and records every call.
type fakeExecutor struct {
	calls []executor.Result
}

func (f *fakeExecutor) Run(_ context.Context, name string, args ...string) (*executor.Result, error) {
	now := time.Now().UTC()
	r := executor.Result{
		Command:   name,
		Args:      append([]string(nil), args...),
		Stdout:    []byte("plugin output for " + name + " " + lastArg(args)),
		StartedAt: now,
		EndedAt:   now.Add(5 * time.Millisecond),
		Duration:  5 * time.Millisecond,
		ExitCode:  0,
	}
	f.calls = append(f.calls, r)
	return &r, nil
}

func lastArg(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[len(a)-1]
}

// touch creates an empty file (used so opts.Validate passes on os.Stat checks).
func touch(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRun_CapturesCommandArgsAndDuration(t *testing.T) {
	dir := t.TempDir()
	vol := touch(t, filepath.Join(dir, "vol.py"))
	img := touch(t, filepath.Join(dir, "memory.lime"))
	syms := dir // any existing dir works for os.Stat
	outDir := filepath.Join(dir, "analysis")

	log, _ := audit.NewFileLogger("", false)
	defer log.Close()

	fe := &fakeExecutor{}
	res, err := Run(context.Background(), fe, log, Options{
		VolPath:     vol,
		ImagePath:   img,
		SymbolsPath: syms,
		OutDir:      outDir,
		Format:      "text",
		Plugins:     []string{"linux.pslist", "linux.bash"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.PluginResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res.PluginResults))
	}
	for _, pr := range res.PluginResults {
		if pr.Command != vol {
			t.Errorf("plugin %s: command = %q, want %q", pr.Plugin, pr.Command, vol)
		}
		if len(pr.Args) < 4 {
			t.Errorf("plugin %s: args too short: %v", pr.Plugin, pr.Args)
		}
		// Args[-1] must be the plugin name.
		if pr.Args[len(pr.Args)-1] != pr.Plugin {
			t.Errorf("plugin %s: last arg = %q", pr.Plugin, pr.Args[len(pr.Args)-1])
		}
		if pr.StartedAt.IsZero() || pr.EndedAt.IsZero() {
			t.Errorf("plugin %s: timestamps missing: %+v", pr.Plugin, pr)
		}
		if pr.Duration == 0 {
			t.Errorf("plugin %s: duration zero", pr.Plugin)
		}
		if pr.OutputPath == "" {
			t.Errorf("plugin %s: OutputPath unset", pr.Plugin)
		}
	}
	// report.md must exist.
	if _, err := os.Stat(res.ReportPath); err != nil {
		t.Errorf("report not written: %v", err)
	}
}

// selectiveExecutor fails plugins whose name appears in failOn; all
// other plugins succeed. Used to verify that Run() preserves both
// successful and failed results in a single Analysis.
type selectiveExecutor struct {
	failOn map[string]bool
}

func (s *selectiveExecutor) Run(_ context.Context, name string, args ...string) (*executor.Result, error) {
	now := time.Now().UTC()
	r := executor.Result{
		Command:   name,
		Args:      append([]string(nil), args...),
		StartedAt: now,
		EndedAt:   now.Add(3 * time.Millisecond),
		Duration:  3 * time.Millisecond,
	}
	plugin := lastArg(args)
	if s.failOn[plugin] {
		r.ExitCode = 1
		r.Stderr = []byte("synthetic plugin failure")
		// Match the real executor.RealExecutor shape: ExitError → non-nil err.
		return &r, errors.New("plugin returned non-zero")
	}
	r.Stdout = []byte("ok " + plugin)
	return &r, nil
}

// TestRun_PartialFailureReturnsBothResults locks in the documented
// failure model: a plugin-level error must NOT cause Run() to return an
// error, and the returned Analysis must contain results for every
// requested plugin (both successful and failed) so that callers can
// audit what was attempted.
func TestRun_PartialFailureReturnsBothResults(t *testing.T) {
	dir := t.TempDir()
	vol := touch(t, filepath.Join(dir, "vol.py"))
	img := touch(t, filepath.Join(dir, "memory.lime"))
	outDir := filepath.Join(dir, "analysis")

	log, _ := audit.NewFileLogger("", false)
	defer log.Close()

	exec := &selectiveExecutor{failOn: map[string]bool{
		"linux.envars": true,
	}}
	res, err := Run(context.Background(), exec, log, Options{
		VolPath:     vol,
		ImagePath:   img,
		SymbolsPath: dir,
		OutDir:      outDir,
		Format:      "text",
		Plugins:     []string{"linux.pslist", "linux.envars", "linux.bash"},
	})
	if err != nil {
		t.Fatalf("Run() must NOT return an error on plugin-level failure; got %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil Analysis on partial failure")
	}
	if got, want := len(res.PluginResults), 3; got != want {
		t.Fatalf("expected %d results (one per requested plugin), got %d", want, got)
	}

	byPlugin := map[string]bool{} // true == failed
	for _, pr := range res.PluginResults {
		byPlugin[pr.Plugin] = pr.Err != "" || pr.ExitCode != 0
	}
	if !byPlugin["linux.envars"] {
		t.Error("linux.envars should be recorded as failed")
	}
	if byPlugin["linux.pslist"] || byPlugin["linux.bash"] {
		t.Error("non-failing plugins must remain successful")
	}

	ok, fail := res.Summary()
	if ok != 2 || fail != 1 {
		t.Errorf("Summary = (%d,%d); want (2,1)", ok, fail)
	}
}

// TestRun_SetupFailureReturnsNilAnalysis locks the other branch of the
// contract: when Validate() fails, Run returns (nil, error) and the
// caller knows there is no manifest to persist.
func TestRun_SetupFailureReturnsNilAnalysis(t *testing.T) {
	log, _ := audit.NewFileLogger("", false)
	defer log.Close()

	res, err := Run(context.Background(), &fakeExecutor{}, log, Options{
		// Missing required fields → Validate fails.
	})
	if err == nil {
		t.Fatal("expected setup error")
	}
	if res != nil {
		t.Errorf("expected nil Analysis on setup failure, got %+v", res)
	}
}

// TestWriteReport_MarksFailedPlugins ensures the Markdown report
// surfaces failures, not just exit codes — important for analysts who
// scan report.md before reading the manifest.
func TestWriteReport_MarksFailedPlugins(t *testing.T) {
	dir := t.TempDir()
	a := &manifest.Analysis{
		PluginResults: []manifest.PluginResult{
			{Plugin: "good", ExitCode: 0},
			{Plugin: "bad", ExitCode: 1, Err: "boom"},
		},
	}
	path := filepath.Join(dir, "report.md")
	if err := writeReport(path, a); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "FAILED") {
		t.Errorf("report should mark failures; got:\n%s", b)
	}
	if !strings.Contains(string(b), "1 succeeded, 1 failed") {
		t.Errorf("report should show summary line; got:\n%s", b)
	}
}
