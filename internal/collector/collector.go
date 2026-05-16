// Package collector implements volatile-artifact collection.
//
// Collection rules:
//   - Best-effort per item: a single failure NEVER aborts the run.
//   - Output goes to <outDir>/collect/<slug>.{out,err}.
//   - Each run gets a manifest section describing exit codes & durations.
//   - We avoid writing to system paths; everything lands in --out.
package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/al2-mem-ir/internal/audit"
	"github.com/example/al2-mem-ir/internal/distro"
	"github.com/example/al2-mem-ir/internal/executor"
	"github.com/example/al2-mem-ir/internal/manifest"
)

// Item is one collection step.
type Item struct {
	Name       string   // file-safe slug
	Cmd        string   // binary
	Args       []string // arguments
	Optional   bool     // do not warn if binary is missing
	Timeout    time.Duration
}

// Options drive collection.
type Options struct {
	OutDir      string
	IncludeEnv  bool
	DryRun      bool
}

// Collector runs items and produces a manifest.Collection.
type Collector struct {
	Exec    executor.Executor
	Adapter distro.Adapter
	Log     *audit.Logger
	Opts    Options
}

// New builds a Collector. When opts.DryRun, the executor is swapped
// for a DryRunExecutor regardless of what was passed in.
func New(e executor.Executor, a distro.Adapter, l *audit.Logger, opts Options) *Collector {
	if opts.DryRun {
		e = executor.NewDryRun()
	}
	return &Collector{Exec: e, Adapter: a, Log: l, Opts: opts}
}

// Run executes every item and returns a populated manifest.Collection.
func (c *Collector) Run(ctx context.Context) (*manifest.Collection, error) {
	collectDir := filepath.Join(c.Opts.OutDir, "collect")
	if err := os.MkdirAll(collectDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", collectDir, err)
	}

	col := &manifest.Collection{
		StartedAt:   time.Now().UTC(),
		IncludedEnv: c.Opts.IncludeEnv,
		OutputDir:   collectDir,
	}

	items := c.buildItems()
	for _, it := range items {
		row := c.runItem(ctx, collectDir, it)
		col.Items = append(col.Items, row)
	}

	// Also snapshot file/directory artifacts as raw copies into collect/files/.
	filesDir := filepath.Join(collectDir, "files")
	if err := os.MkdirAll(filesDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", filesDir, err)
	}
	for _, row := range c.copyArtifacts(filesDir) {
		col.Items = append(col.Items, row)
	}

	col.EndedAt = time.Now().UTC()
	return col, nil
}

// buildItems composes the full item list from the adapter + generic core.
func (c *Collector) buildItems() []Item {
	items := []Item{
		{Name: "uname", Cmd: "uname", Args: []string{"-a"}},
		{Name: "date", Cmd: "date", Args: []string{"-u", "+%FT%TZ"}},
		{Name: "uptime", Cmd: "uptime", Args: nil},
		{Name: "who", Cmd: "who", Args: nil},
		{Name: "w", Cmd: "w", Args: nil},
		{Name: "last", Cmd: "last", Args: []string{"-Faxw"}},
		{Name: "lastlog", Cmd: "lastlog", Args: nil},
		{Name: "ps", Cmd: "ps", Args: []string{"auxwwf"}},
		{Name: "pstree", Cmd: "pstree", Args: []string{"-alp"}, Optional: true},
		{Name: "ss-tcp", Cmd: "ss", Args: []string{"-antp"}},
		{Name: "ss-udp", Cmd: "ss", Args: []string{"-uanp"}},
		{Name: "ip-addr", Cmd: "ip", Args: []string{"addr"}},
		{Name: "ip-route", Cmd: "ip", Args: []string{"route"}},
		{Name: "arp", Cmd: "arp", Args: []string{"-an"}, Optional: true},
		{Name: "iptables", Cmd: "iptables", Args: []string{"-L", "-n", "-v"}},
		{Name: "nft", Cmd: "nft", Args: []string{"list", "ruleset"}, Optional: true},
		{Name: "crontab-root", Cmd: "crontab", Args: []string{"-l"}, Optional: true},
		{Name: "journal-7d", Cmd: "journalctl", Args: []string{"--since", "7 days ago", "--no-pager"}, Optional: true, Timeout: 60 * time.Second},
		{Name: "journal-kernel", Cmd: "journalctl", Args: []string{"-k", "--no-pager"}, Optional: true, Timeout: 60 * time.Second},
		{Name: "dmesg", Cmd: "dmesg", Args: []string{"-T"}, Optional: true},
		{Name: "lsmod", Cmd: "lsmod", Args: nil},
		{Name: "mount", Cmd: "mount", Args: nil},
		{Name: "lsof-deleted", Cmd: "lsof", Args: []string{"+L1"}, Optional: true, Timeout: 60 * time.Second},
		// LSM status snapshots. Both are Optional so a host that has only
		// one LSM (or neither) skips silently — common on AL2 (SELinux
		// typically disabled) and on Ubuntu cloud AMIs (AppArmor in
		// complain mode). Adding both at the generic layer means we
		// don't need to fan them out per-adapter.
		{Name: "sestatus", Cmd: "sestatus", Args: nil, Optional: true},
		{Name: "aa-status", Cmd: "aa-status", Args: nil, Optional: true},
	}

	if c.Adapter != nil {
		for _, q := range c.Adapter.ServiceQueries() {
			items = append(items, Item{Name: q.Name, Cmd: q.Cmd, Args: q.Args})
		}
	}

	if c.Opts.IncludeEnv {
		// env is treated with care: when included, we still scope to the
		// invoking process. /proc/<pid>/environ snapshots happen separately
		// during memory analysis.
		items = append(items, Item{Name: "env", Cmd: "env", Args: nil})
	}
	return items
}

func (c *Collector) runItem(ctx context.Context, dir string, it Item) manifest.CollectedCmd {
	row := manifest.CollectedCmd{
		Name:    it.Name,
		Command: it.Cmd,
		Args:    it.Args,
	}
	ictx := ctx
	if it.Timeout > 0 {
		var cancel context.CancelFunc
		ictx, cancel = context.WithTimeout(ctx, it.Timeout)
		defer cancel()
	}

	res, err := c.Exec.Run(ictx, it.Cmd, it.Args...)
	if res != nil {
		row.ExitCode = res.ExitCode
		row.Duration = res.Duration
		// Persist stdout/stderr even on error — partial output is useful.
		outPath := filepath.Join(dir, it.Name+".out")
		errPath := filepath.Join(dir, it.Name+".err")
		_ = os.WriteFile(outPath, res.Stdout, 0o600)
		_ = os.WriteFile(errPath, res.Stderr, 0o600)
		row.StdoutPath = outPath
		row.StderrPath = errPath
	}
	if err != nil {
		row.Err = err.Error()
		fields := map[string]interface{}{
			"item":      it.Name,
			"optional":  it.Optional,
			"exit_code": row.ExitCode,
		}
		// Mandatory collection items raise WARN so reviewers can spot
		// evidence gaps when scanning audit.log. Optional items (best-
		// effort: pstree, nft, crontab, etc.) stay at INFO so they
		// don't drown the signal — their absence on a given host is
		// expected, not an incident.
		if it.Optional {
			c.Log.Info("collect.item.error",
				"optional item failed (acceptable): "+it.Name+": "+err.Error(), fields)
		} else {
			c.Log.Warn("collect.item.error",
				"mandatory item failed (evidence gap): "+it.Name+": "+err.Error(), fields)
		}
	} else {
		c.Log.Info("collect.item.ok", "collected "+it.Name, map[string]interface{}{
			"item":      it.Name,
			"optional":  it.Optional,
			"exit_code": row.ExitCode,
			"duration":  row.Duration.String(),
		})
	}
	return row
}

// copyArtifacts copies adapter-declared logs/config into <out>/collect/files.
// Missing paths are skipped silently; unreadable paths are recorded.
func (c *Collector) copyArtifacts(dst string) []manifest.CollectedCmd {
	if c.Adapter == nil {
		return nil
	}
	paths := c.Adapter.Paths()
	var rows []manifest.CollectedCmd

	groups := map[string][]string{
		"system_logs":     paths.SystemLogs,
		"cron_configs":    paths.CronConfigs,
		"cloud_init_logs": paths.CloudInitLogs,
		"agent_logs":      paths.AgentLogs,
		"authorized_keys": paths.AuthorizedKeys,
	}
	for group, list := range groups {
		gdst := filepath.Join(dst, group)
		_ = os.MkdirAll(gdst, 0o700)
		for _, p := range list {
			matches, _ := filepath.Glob(p)
			if matches == nil {
				if _, err := os.Stat(p); err == nil {
					matches = []string{p}
				}
			}
			for _, m := range matches {
				row := manifest.CollectedCmd{
					Name:    "file:" + group + ":" + m,
					Command: "copy",
					Args:    []string{m},
				}
				if c.Opts.DryRun {
					row.Skipped = true
					row.SkipReason = "dry-run"
					rows = append(rows, row)
					continue
				}
				err := copyTree(m, filepath.Join(gdst, sanitizePath(m)))
				if err != nil {
					row.Err = err.Error()
					row.ExitCode = 1
				}
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func sanitizePath(p string) string {
	r := strings.ReplaceAll(p, string(os.PathSeparator), "_")
	r = strings.TrimPrefix(r, "_")
	return r
}

// copyTree is a small recursive copy that preserves regular files and
// directory structure. Symlinks are followed to a single level and
// recorded as files; we do NOT chase symlinks recursively to avoid loops
// or escaping the source tree.
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		// Record the symlink target as a sibling .symlink file.
		return os.WriteFile(dst+".symlink", []byte(target+"\n"), 0o600)
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 64*1024)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}
