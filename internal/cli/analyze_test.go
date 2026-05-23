package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nishikawaakira/kernledger/internal/manifest"
)

func TestSaveAnalyzeManifest_WritesFile(t *testing.T) {
	outDir := t.TempDir()
	c := &analyzeCmd{
		version: "0.0.0",
		commit:  "test",
	}
	a := &manifest.Analysis{
		Volatility:  "/opt/vol/vol.py",
		ImagePath:   "/data/memory.lime",
		SymbolsPath: "/data/symbols",
		PluginResults: []manifest.PluginResult{
			{
				Plugin:     "linux.pslist",
				Command:    "/opt/vol/vol.py",
				Args:       []string{"-f", "/data/memory.lime", "-s", "/data/symbols", "linux.pslist"},
				OutputPath: filepath.Join(outDir, "linux_pslist.text"),
				Format:     "text",
				ExitCode:   0,
			},
		},
	}

	path, err := saveAnalyzeManifestPath(c, outDir, a)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	loaded, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Analysis == nil || len(loaded.Analysis.PluginResults) != 1 {
		t.Fatalf("analysis section missing: %+v", loaded.Analysis)
	}
	pr := loaded.Analysis.PluginResults[0]
	if pr.Command != "/opt/vol/vol.py" {
		t.Errorf("command not preserved: %q", pr.Command)
	}
	if len(pr.Args) != 5 || pr.Args[4] != "linux.pslist" {
		t.Errorf("args not preserved: %v", pr.Args)
	}
	// Identity must be auto-captured (no operator/case flag any more).
	if loaded.Identity == nil {
		t.Error("Identity not captured into analyze manifest")
	}
}

// fakeVol is a shell script that mimics vol.py: it inspects the LAST
// argument (the plugin name) and exits 0 or 1 accordingly. This lets
// us drive the real analyzeCmd.Run() — including its internal
// executor.NewReal — without depending on Volatility being installed.
const fakeVolScript = `#!/bin/sh
# Last positional arg is the plugin name (kernledger always appends it).
plugin="${@: -1}"
case "$plugin" in
  *envars*) echo "FAIL: $plugin" 1>&2; exit 1 ;;
  *)        echo "OK $plugin"; exit 0 ;;
esac
`

func writeFakeVol(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "fake-vol.sh")
	if err := os.WriteFile(path, []byte(fakeVolScript), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAnalyzeCmd_PartialFailure_PolicyLockdown is the regression test
// for the documented exit-code policy:
//
//   - plugin-level failure → manifest IS written, Run() returns error
//     (which translates to exit 1 via cli.Run/main).
//   - Both successful AND failed plugins are recorded in the manifest.
//
// It drives the real analyzeCmd through its public flag surface so the
// policy stays locked even if internal wiring shifts.
func TestAnalyzeCmd_PartialFailure_PolicyLockdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell script not portable to windows")
	}
	dir := t.TempDir()
	vol := writeFakeVol(t, dir)
	img := filepath.Join(dir, "image.lime")
	if err := os.WriteFile(img, []byte("not a real image"), 0o600); err != nil {
		t.Fatal(err)
	}
	syms := dir // any existing directory is fine for the os.Stat check
	outDir := filepath.Join(dir, "out")

	// Wire the subcommand exactly like the dispatcher does.
	c := newAnalyzeCmd("test", "test")
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	c.SetFlags(fs)
	args := []string{
		"--out", outDir,
		"--vol", vol,
		"--image", img,
		"--symbols", syms,
		"--format", "text",
		"--plugins", "linux.pslist,linux.envars,linux.bash",
		"--quiet",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}

	err := c.Run(context.Background(), fs.Args())
	// POLICY: partial failure → non-nil error from Run().
	if err == nil {
		t.Fatal("expected partial-failure error from analyzeCmd.Run")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("error should mention failure count: %v", err)
	}

	// POLICY: manifest is ALWAYS written when we got past setup.
	manifestPath := filepath.Join(outDir, "analyze-manifest.json")
	if _, statErr := os.Stat(manifestPath); statErr != nil {
		t.Fatalf("analyze-manifest.json not written on partial failure: %v", statErr)
	}
	m, lerr := manifest.Load(manifestPath)
	if lerr != nil {
		t.Fatalf("load manifest: %v", lerr)
	}
	if m.Analysis == nil || len(m.Analysis.PluginResults) != 3 {
		t.Fatalf("expected 3 plugin results in manifest, got %+v", m.Analysis)
	}
	ok, fail := m.Analysis.Summary()
	if ok != 2 || fail != 1 {
		t.Errorf("manifest summary = (%d,%d); want (2,1)", ok, fail)
	}
	// Specifically: envars must be marked failed, the others ok.
	var foundFailed bool
	for _, pr := range m.Analysis.PluginResults {
		if pr.Plugin == "linux.envars" {
			foundFailed = pr.ExitCode != 0 || pr.Err != ""
		}
	}
	if !foundFailed {
		t.Error("linux.envars not recorded as failed in manifest")
	}
}

// TestAnalyzeCmd_AllSuccess_PolicyLockdown locks the happy-path side:
// exit 0 only when EVERY plugin succeeded.
func TestAnalyzeCmd_AllSuccess_PolicyLockdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell script not portable to windows")
	}
	dir := t.TempDir()
	vol := writeFakeVol(t, dir)
	img := filepath.Join(dir, "image.lime")
	_ = os.WriteFile(img, []byte("x"), 0o600)
	outDir := filepath.Join(dir, "out")

	c := newAnalyzeCmd("test", "test")
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	c.SetFlags(fs)
	if err := fs.Parse([]string{
		"--out", outDir,
		"--vol", vol,
		"--image", img,
		"--symbols", dir,
		"--format", "text",
		"--plugins", "linux.pslist,linux.bash", // no envars → all succeed
		"--quiet",
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Run(context.Background(), fs.Args()); err != nil {
		t.Fatalf("expected nil error on all-success, got %v", err)
	}
	// Manifest must still exist.
	if _, err := os.Stat(filepath.Join(outDir, "analyze-manifest.json")); err != nil {
		t.Fatalf("manifest missing on success: %v", err)
	}
}

// TestAnalyzeCmd_SetupFailure_NoManifest locks the third branch:
// when setup (Validate) fails, no manifest is written because no
// Analysis was ever produced. Run() must still return non-nil error.
func TestAnalyzeCmd_SetupFailure_NoManifest(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	c := newAnalyzeCmd("test", "test")
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	c.SetFlags(fs)
	// Missing --vol etc. → Validate fails.
	if err := fs.Parse([]string{"--out", outDir, "--quiet"}); err != nil {
		t.Fatal(err)
	}
	err := c.Run(context.Background(), fs.Args())
	if err == nil {
		t.Fatal("expected setup error")
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "analyze-manifest.json")); statErr == nil {
		t.Error("manifest must NOT be written when setup fails (no Analysis produced)")
	}
}
