// Package symbols wraps dwarf2json invocations to produce Volatility 3
// Linux symbol JSON files.
//
// Notes:
//   - This runs on the ANALYSIS workstation, not the target host.
//   - No automatic download. The operator must already have:
//   - dwarf2json binary
//   - vmlinux  (with DWARF) OR module.ko-debuginfo
//   - We never modify ~/.cache or system paths; output goes to --out.
package symbols

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nishikawaakira/kernledger/internal/audit"
	"github.com/nishikawaakira/kernledger/internal/executor"
)

// Options for Generate.
type Options struct {
	Dwarf2JSON  string // path to dwarf2json
	Vmlinux     string // path to vmlinux (DWARF-bearing)
	BTFPath     string // optional /sys/kernel/btf/vmlinux dump
	KernelLabel string // logical label, e.g. "5.10.220-209.869.amzn2.x86_64"
	OutDir      string // where to write <label>.json
}

// Validate sanity-checks the inputs.
func (o Options) Validate() error {
	if o.Dwarf2JSON == "" {
		return errors.New("--dwarf2json is required")
	}
	if o.Vmlinux == "" && o.BTFPath == "" {
		return errors.New("either --vmlinux or --btf must be provided")
	}
	if o.KernelLabel == "" {
		return errors.New("--kernel is required")
	}
	if o.OutDir == "" {
		return errors.New("--out is required")
	}
	for _, p := range []string{o.Dwarf2JSON, o.Vmlinux, o.BTFPath} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("input %s: %w", p, err)
		}
	}
	return nil
}

// Generate runs dwarf2json and writes <out>/<kernel>.json. The file
// layout matches what Volatility 3 expects under symbols/linux/.
func Generate(ctx context.Context, exec executor.Executor, log *audit.Logger, opts Options) (string, error) {
	if err := opts.Validate(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(opts.OutDir, opts.KernelLabel+".json")
	args := []string{"linux"}
	if opts.Vmlinux != "" {
		args = append(args, "--elf", opts.Vmlinux)
	}
	if opts.BTFPath != "" {
		args = append(args, "--btf", opts.BTFPath)
	}

	log.Info("symbols.generate", "running dwarf2json", map[string]interface{}{
		"cmd":  opts.Dwarf2JSON,
		"args": args,
		"out":  dst,
	})

	start := time.Now()
	res, err := exec.Run(ctx, opts.Dwarf2JSON, args...)
	if err != nil {
		return "", fmt.Errorf("dwarf2json failed: %w", err)
	}
	// dwarf2json writes its JSON to stdout; we capture and save.
	if err := os.WriteFile(dst, res.Stdout, 0o600); err != nil {
		return "", err
	}
	log.Info("symbols.done", "symbols written", map[string]interface{}{
		"out":      dst,
		"duration": time.Since(start).String(),
	})
	return dst, nil
}
