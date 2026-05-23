// Package analyze runs Volatility 3 plugins against a captured image.
// This package runs on the ANALYSIS workstation, never on the target.
//
// Failure model (important — load-bearing for IR auditability):
//
//   - Forensic work prefers "partial results preserved and auditable"
//     over "all-or-nothing success". A vol plugin that fails on a
//     specific image (unknown symbol, OOM, plugin bug) MUST NOT cause
//     the rest of the analysis to be discarded.
//
//   - Run() therefore distinguishes two error classes:
//
//       SETUP failure   — Validate() or MkdirAll() fails. Returns
//                         (nil, error). Nothing has happened yet, so
//                         there is no manifest to persist. The caller
//                         should surface the error and exit non-zero.
//
//       PLUGIN failure  — exec.Run() returns an error for some plugin,
//                         or the plugin exits non-zero. The Run loop
//                         records it as PluginResult.Err / ExitCode
//                         and CONTINUES with the remaining plugins.
//                         Run() returns (Analysis, nil) regardless of
//                         how many plugins failed.
//
//   - The caller MUST always persist the returned Analysis (when it is
//     non-nil) and use Analysis.Summary() to decide whether to flag
//     the run as partially failed.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/kernledger/internal/audit"
	"github.com/example/kernledger/internal/executor"
	"github.com/example/kernledger/internal/manifest"
)

// DefaultPlugins is the MVP plugin list.
var DefaultPlugins = []string{
	"linux.pslist",
	"linux.pstree",
	"linux.sockstat",
	"linux.bash",
	"linux.envars",
	"linux.lsof",
	"linux.proc.Maps",
	"linux.check_creds",
}

// Options for Run.
type Options struct {
	VolPath     string // path to vol.py or `vol` binary
	ImagePath   string // memory image path
	SymbolsPath string // directory containing symbols/linux/*.json
	OutDir      string
	Format      string // "text" | "json"
	Plugins     []string
	Timeout     time.Duration // per-plugin timeout
}

// Validate checks the options before invoking vol.
func (o Options) Validate() error {
	if o.VolPath == "" {
		return errors.New("--vol is required")
	}
	if o.ImagePath == "" {
		return errors.New("--image is required")
	}
	if o.SymbolsPath == "" {
		return errors.New("--symbols is required")
	}
	if o.OutDir == "" {
		return errors.New("--out is required")
	}
	if o.Format == "" {
		return errors.New("--format is required (text|json)")
	}
	switch o.Format {
	case "text", "json":
	default:
		return fmt.Errorf("--format must be text|json (got %q)", o.Format)
	}
	for _, p := range []string{o.VolPath, o.ImagePath, o.SymbolsPath} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("input %s: %w", p, err)
		}
	}
	return nil
}

// Run invokes each plugin and returns a manifest.Analysis section.
func Run(ctx context.Context, exec executor.Executor, log *audit.Logger, opts Options) (*manifest.Analysis, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return nil, err
	}

	plugins := opts.Plugins
	if len(plugins) == 0 {
		plugins = DefaultPlugins
	}

	a := &manifest.Analysis{
		Volatility:  opts.VolPath,
		ImagePath:   opts.ImagePath,
		SymbolsPath: opts.SymbolsPath,
		StartedAt:   time.Now().UTC(),
	}

	for _, plugin := range plugins {
		safeName := strings.ReplaceAll(plugin, ".", "_")
		outFile := filepath.Join(opts.OutDir, safeName+"."+opts.Format)

		args := []string{
			"-f", opts.ImagePath,
			"-s", opts.SymbolsPath,
		}
		if opts.Format == "json" {
			args = append(args, "-r", "json")
		}
		args = append(args, plugin)

		log.Info("analyze.plugin.start", "running "+plugin, map[string]interface{}{
			"cmd":  opts.VolPath,
			"args": args,
		})

		pctx := ctx
		if opts.Timeout > 0 {
			var cancel context.CancelFunc
			pctx, cancel = context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
		}

		res, err := exec.Run(pctx, opts.VolPath, args...)
		pr := manifest.PluginResult{
			Plugin:  plugin,
			Command: opts.VolPath,
			Args:    append([]string(nil), args...),
			Format:  opts.Format,
		}
		if res != nil {
			pr.ExitCode = res.ExitCode
			pr.StartedAt = res.StartedAt
			pr.EndedAt = res.EndedAt
			pr.Duration = res.Duration
			if werr := os.WriteFile(outFile, res.Stdout, 0o600); werr == nil {
				pr.OutputPath = outFile
			}
		}
		if err != nil {
			pr.Err = err.Error()
			log.Warn("analyze.plugin.error", plugin+": "+err.Error(), map[string]interface{}{
				"plugin":    plugin,
				"exit_code": pr.ExitCode,
			})
		} else {
			log.Info("analyze.plugin.ok", plugin+" done", map[string]interface{}{
				"plugin":   plugin,
				"out":      outFile,
				"duration": pr.Duration.String(),
			})
		}
		a.PluginResults = append(a.PluginResults, pr)
	}
	a.EndedAt = time.Now().UTC()

	reportPath := filepath.Join(opts.OutDir, "report.md")
	if err := writeReport(reportPath, a); err == nil {
		a.ReportPath = reportPath
	}
	return a, nil
}

// writeReport emits a minimal Markdown summary.
func writeReport(path string, a *manifest.Analysis) error {
	ok, fail := a.Summary()
	var b strings.Builder
	b.WriteString("# kernledger analysis report\n\n")
	fmt.Fprintf(&b, "- image: `%s`\n", a.ImagePath)
	fmt.Fprintf(&b, "- symbols: `%s`\n", a.SymbolsPath)
	fmt.Fprintf(&b, "- volatility: `%s`\n", a.Volatility)
	fmt.Fprintf(&b, "- started: %s\n", a.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- ended:   %s\n", a.EndedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- plugins: %d succeeded, %d failed\n\n", ok, fail)
	b.WriteString("## Plugins\n\n")
	b.WriteString("| plugin | status | exit | duration | output | error |\n|---|---|---|---|---|---|\n")
	for _, pr := range a.PluginResults {
		status := "ok"
		if pr.Err != "" || pr.ExitCode != 0 {
			status = "FAILED"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %d | %s | `%s` | %s |\n",
			pr.Plugin, status, pr.ExitCode, pr.Duration, pr.OutputPath, pr.Err)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
