// Package acquire orchestrates LiME-based memory acquisition.
//
// MVP scope:
//   - Plan + validate the LiME insmod command.
//   - Honor --dry-run and require an explicit --execute flag at the CLI
//     before any kernel module is actually loaded.
//   - Compute SHA-256 over the resulting image (when produced).
//   - Capture dmesg tail when a failure mode is detected.
//
// Out of scope:
//   - Repacking, compressing, or transforming the captured image.
//   - Any stealth, anti-detection, or module-renaming behavior. The
//     module is loaded with its real path and name, and the kernel will
//     observe the load in the usual way (printk, audit, EDR).
package acquire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/al2-mem-ir/internal/audit"
	"github.com/example/al2-mem-ir/internal/executor"
	"github.com/example/al2-mem-ir/internal/hashutil"
	"github.com/example/al2-mem-ir/internal/manifest"
)

// Options configures a single acquisition.
type Options struct {
	ModulePath  string // absolute path to lime.ko (or equivalent)
	OutputPath  string // path= argument to LiME
	OutputMode  string // "file" or "tcp"
	OutputFormat string // "lime" (default) / "raw" / "padded"
	TCPListen    string // ":4444" when OutputMode == "tcp"
	Rmmod        bool   // attempt rmmod after acquisition
	Execute      bool   // gate that must be true to actually run insmod
}

// Validate ensures the options make sense before we touch the kernel.
func (o Options) Validate() error {
	if o.ModulePath == "" {
		return errors.New("--module is required")
	}
	if info, err := os.Stat(o.ModulePath); err != nil {
		return fmt.Errorf("module path %s: %w", o.ModulePath, err)
	} else if info.IsDir() {
		return fmt.Errorf("module path %s is a directory", o.ModulePath)
	}
	if !strings.HasSuffix(o.ModulePath, ".ko") {
		return fmt.Errorf("module path %s does not end in .ko", o.ModulePath)
	}
	switch o.OutputMode {
	case "file":
		if o.OutputPath == "" {
			return errors.New("--output is required when --mode=file")
		}
	case "tcp":
		if o.TCPListen == "" {
			return errors.New("--tcp is required when --mode=tcp (e.g. :4444)")
		}
	default:
		return fmt.Errorf("--mode must be file|tcp (got %q)", o.OutputMode)
	}
	switch o.OutputFormat {
	case "", "lime", "raw", "padded":
		// ok
	default:
		return fmt.Errorf("--format must be lime|raw|padded (got %q)", o.OutputFormat)
	}
	return nil
}

// Plan describes what would happen. It is always produced, regardless
// of whether we actually execute.
type Plan struct {
	InsmodCmd []string
	RmmodCmd  []string
}

// BuildPlan returns the planned insmod/rmmod invocations.
func (o Options) BuildPlan() Plan {
	format := o.OutputFormat
	if format == "" {
		format = "lime"
	}
	var pathArg string
	if o.OutputMode == "tcp" {
		pathArg = "path=tcp:" + strings.TrimPrefix(o.TCPListen, ":")
	} else {
		pathArg = "path=" + o.OutputPath
	}
	return Plan{
		InsmodCmd: []string{"insmod", o.ModulePath, pathArg, "format=" + format},
		RmmodCmd:  []string{"rmmod", moduleName(o.ModulePath)},
	}
}

// moduleName derives the in-kernel module name from a file path.
// LiME's .ko is named "lime-<release>.ko" or "lime.ko"; strip the
// extension and convert "-" → "_" the way the kernel does internally.
func moduleName(modPath string) string {
	base := filepath.Base(modPath)
	base = strings.TrimSuffix(base, ".ko")
	return strings.ReplaceAll(base, "-", "_")
}

// Runner orchestrates one acquisition.
type Runner struct {
	Exec executor.Executor
	Log  *audit.Logger
}

// Acquire executes (or dry-runs) the plan and returns a manifest section.
func (r *Runner) Acquire(ctx context.Context, opts Options, dryRun bool) (*manifest.Acquisition, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	plan := opts.BuildPlan()

	modHash := ""
	if h, _, err := hashutil.FileSHA256(opts.ModulePath); err == nil {
		modHash = h
	}

	acq := &manifest.Acquisition{
		Engine:       "lime",
		ModulePath:   opts.ModulePath,
		ModuleSHA256: modHash,
		OutputPath:   opts.OutputPath,
		OutputFormat: defaultStr(opts.OutputFormat, "lime"),
		OutputMode:   opts.OutputMode,
		DryRun:       dryRun || !opts.Execute,
	}

	r.Log.Info("acquire.plan", "planned insmod", map[string]interface{}{
		"cmd":     plan.InsmodCmd,
		"dry_run": acq.DryRun,
	})

	if !opts.Execute || dryRun {
		acq.Notes = "dry-run: insmod was NOT executed. Pass --execute to actually load the LiME module."
		return acq, nil
	}

	// Real run path. We deliberately use the same executor abstraction
	// to keep audit logging consistent.
	acq.InsmodStartedAt = time.Now().UTC()
	res, err := r.Exec.Run(ctx, plan.InsmodCmd[0], plan.InsmodCmd[1:]...)
	acq.InsmodEndedAt = time.Now().UTC()
	if err != nil {
		r.Log.Error("acquire.insmod.failed", err.Error(), map[string]interface{}{
			"exit_code": resultExit(res),
		})
		dpath := captureDmesgTail(ctx, r.Exec, opts.OutputPath)
		acq.DmesgTailPath = dpath
		return acq, fmt.Errorf("insmod failed: %w", err)
	}

	if opts.OutputMode == "file" {
		// Wait briefly for LiME to flush; for very large memory it may
		// still be writing. Polling for size stability would be more
		// robust but is left for a follow-up.
		if h, n, herr := hashutil.FileSHA256(opts.OutputPath); herr == nil {
			acq.ImageSHA256 = h
			acq.ImageBytes = n
		} else {
			r.Log.Warn("acquire.hash.failed", herr.Error(), nil)
		}
	}

	if opts.Rmmod {
		if _, err := r.Exec.Run(ctx, plan.RmmodCmd[0], plan.RmmodCmd[1:]...); err != nil {
			r.Log.Warn("acquire.rmmod.failed", err.Error(), nil)
		} else {
			acq.RmmodPerformed = true
			acq.RmmodEndedAt = time.Now().UTC()
		}
	}
	return acq, nil
}

func resultExit(r *executor.Result) int {
	if r == nil {
		return -1
	}
	return r.ExitCode
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// captureDmesgTail writes the tail of dmesg next to the (would-be) image
// so investigators can diagnose insmod failures (unknown symbol, wrong
// kernel version, signature rejected). Best effort.
func captureDmesgTail(ctx context.Context, exec executor.Executor, near string) string {
	res, err := exec.Run(ctx, "dmesg", "-T")
	if err != nil || res == nil {
		return ""
	}
	dir := filepath.Dir(near)
	if dir == "" || dir == "." {
		dir = "."
	}
	p := filepath.Join(dir, "dmesg-on-failure.log")
	if err := os.WriteFile(p, res.Stdout, 0o600); err != nil {
		return ""
	}
	return p
}
