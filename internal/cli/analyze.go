package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/kernledger/internal/analyze"
	"github.com/example/kernledger/internal/executor"
	"github.com/example/kernledger/internal/manifest"
)

type analyzeCmd struct {
	version string
	commit  string
	cf      commonFlags

	volPath       string
	imagePath     string
	symbolsPath   string
	format        string
	plugins       string
	pluginTimeout time.Duration
}

func newAnalyzeCmd(version, commit string) *analyzeCmd {
	return &analyzeCmd{version: version, commit: commit}
}

func (c *analyzeCmd) Name() string     { return "analyze" }
func (c *analyzeCmd) Synopsis() string { return "drive Volatility 3 against a memory image (analyst side)" }

func (c *analyzeCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.StringVar(&c.volPath, "vol", "", "path to vol / vol.py")
	fs.StringVar(&c.imagePath, "image", "", "memory image file")
	fs.StringVar(&c.symbolsPath, "symbols", "", "directory containing symbols/linux/*.json")
	fs.StringVar(&c.format, "format", "text", "output format: text|json")
	fs.StringVar(&c.plugins, "plugins", "", "comma-separated plugin override (default = MVP set)")
	fs.DurationVar(&c.pluginTimeout, "plugin-timeout", 30*time.Minute, "per-plugin timeout")
}

// Exit code policy for `analyze` (single source of truth):
//
//   0 — every plugin succeeded (ExitCode==0 and Err=="").
//   1 — partial failure: at least one plugin failed, OR a setup error
//       (Validate / MkdirAll) prevented the run from starting, OR the
//       manifest could not be written.
//
// In ALL cases where a *manifest.Analysis was produced (i.e. we got
// past setup), analyze-manifest.json is written before we return. The
// CLI then maps an in-package summary (manifest.Analysis.Summary) into
// the exit code above. This makes "what was tried, what succeeded,
// what failed" auditable regardless of process exit code.
func (c *analyzeCmd) Run(ctx context.Context, _ []string) error {
	outDir, err := c.cf.resolveOutDir(true)
	if err != nil {
		return err
	}
	log, err := c.cf.openAudit(outDir)
	if err != nil {
		return err
	}
	defer log.Close()

	exec := executor.NewReal(c.pluginTimeout)
	if c.cf.DryRun {
		exec = nil
	}

	var pluginList []string
	if c.plugins != "" {
		for _, p := range strings.Split(c.plugins, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				pluginList = append(pluginList, p)
			}
		}
	}

	res, runErr := analyze.Run(ctx, realOrDryRun(exec, c.cf.DryRun), log, analyze.Options{
		VolPath:     c.volPath,
		ImagePath:   c.imagePath,
		SymbolsPath: c.symbolsPath,
		OutDir:      outDir,
		Format:      c.format,
		Plugins:     pluginList,
		Timeout:     c.pluginTimeout,
	})

	// Setup failure path. By the contract documented on analyze.Run,
	// runErr can only fire BEFORE any plugin ran (Validate / MkdirAll).
	// In that case there is no Analysis to persist.
	if runErr != nil && res == nil {
		log.Error("analyze.setup.failed", runErr.Error(), nil)
		return runErr
	}

	// From here on res is non-nil. Persist the manifest UNCONDITIONALLY:
	// this is the load-bearing invariant — operators must be able to
	// audit a partially-failed analysis.
	manifestPath, mErr := saveAnalyzeManifestPath(c, outDir, res)
	if mErr != nil {
		// We genuinely cannot record the analysis; this is itself a fault.
		log.Error("analyze.manifest.save.failed", mErr.Error(), nil)
		return fmt.Errorf("save analyze manifest: %w", mErr)
	}
	ok, fail := res.Summary()
	log.Info("analyze.manifest.saved", "analyze manifest written", map[string]interface{}{
		"manifest":  manifestPath,
		"plugins":   len(res.PluginResults),
		"succeeded": ok,
		"failed":    fail,
	})

	if !c.cf.Quiet {
		fmt.Printf("analyze: %d plugins (%d ok, %d failed), report=%s, manifest=%s\n",
			len(res.PluginResults), ok, fail, res.ReportPath, manifestPath)
	}

	// Partial-failure path: surface a non-zero exit so automation
	// (CI, runbooks, sentinel scripts) notices. The manifest stays the
	// authoritative record of which plugins succeeded.
	if fail > 0 {
		return fmt.Errorf("analyze completed with %d/%d plugin(s) failed; see %s",
			fail, len(res.PluginResults), manifestPath)
	}
	// runErr could in theory be non-nil with res non-nil if a future
	// version of Run adopts that pattern; treat it as partial failure.
	if runErr != nil {
		return fmt.Errorf("analyze partial: %w (manifest: %s)", runErr, manifestPath)
	}
	return nil
}

// saveAnalyzeManifestPath builds the consolidated analyze manifest and
// writes it to <outDir>/analyze-manifest.json. The returned path is
// what the operator should reference in their report.
func saveAnalyzeManifestPath(c *analyzeCmd, outDir string, a *manifest.Analysis) (string, error) {
	m := manifest.New(c.version, c.commit, "n/a-analyst-side")
	hostname, _ := os.Hostname()
	m.Host = manifest.HostInfo{
		Hostname: hostname,
	}
	m.Analysis = a
	path := filepath.Join(outDir, "analyze-manifest.json")
	if err := m.Save(path); err != nil {
		return "", err
	}
	return path, nil
}
