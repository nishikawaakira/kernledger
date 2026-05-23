package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/nishikawaakira/kernledger/internal/audit"
	"github.com/nishikawaakira/kernledger/internal/distro"
)

// commonFlags is embedded in every subcommand. It provides cross-cutting
// concerns: dry-run, audit log, distro override, output dir.
type commonFlags struct {
	OutDir       string
	AuditLogPath string
	DryRun       bool
	DistroID     string
	Quiet        bool
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.OutDir, "out", "", "output directory (created if missing). Required for evidence-producing commands.")
	fs.StringVar(&c.AuditLogPath, "audit-log", "", "append-only audit log path (NDJSON). Defaults to <out>/audit.log when --out is set.")
	fs.BoolVar(&c.DryRun, "dry-run", false, "do not invoke external commands; print intent instead.")
	fs.StringVar(&c.DistroID, "distro", "", "force a specific distro adapter (skip /etc/os-release detection).")
	fs.BoolVar(&c.Quiet, "quiet", false, "suppress non-essential stderr output.")
}

// resolveOutDir creates the output directory if needed and returns its
// absolute path. Empty input is an error for evidence commands.
func (c *commonFlags) resolveOutDir(required bool) (string, error) {
	if c.OutDir == "" {
		if required {
			return "", fmt.Errorf("--out is required")
		}
		return "", nil
	}
	abs, err := filepath.Abs(c.OutDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", abs, err)
	}
	return abs, nil
}

// openAudit returns an audit logger. When --out is set and --audit-log
// isn't, defaults to <out>/audit.log.
func (c *commonFlags) openAudit(outDir string) (*audit.Logger, error) {
	path := c.AuditLogPath
	if path == "" && outDir != "" {
		path = filepath.Join(outDir, "audit.log")
	}
	return audit.NewFileLogger(path, !c.Quiet)
}

// resolveDistro applies --distro if set, else detects via /etc/os-release.
// The OSInfo is also returned so callers can populate manifests.
func (c *commonFlags) resolveDistro() (distro.Adapter, distro.OSInfo, error) {
	osInfo, err := distro.ParseOSRelease("")
	if err != nil {
		return nil, osInfo, err
	}
	if c.DistroID != "" {
		a, ok := distro.Get(c.DistroID)
		if !ok {
			return nil, osInfo, fmt.Errorf("unknown distro adapter %q; known: %v", c.DistroID, distro.IDs())
		}
		return a, osInfo, nil
	}
	a, err := distro.DetectFromOSRelease(osInfo)
	if err != nil {
		return nil, osInfo, err
	}
	return a, osInfo, nil
}

// rootCheck returns an error when the current process is not root.
// Several IR primitives (insmod, /proc/kcore reads, full /var/log/secure
// access) require root. We surface this early to avoid partial evidence.
func rootCheck(allowNonRoot bool) error {
	if allowNonRoot {
		return nil
	}
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("user lookup: %w", err)
	}
	if u.Uid != "0" {
		return fmt.Errorf("this command requires root (uid 0); current uid=%s. Use --allow-non-root only when you understand the evidence gaps.", u.Uid)
	}
	return nil
}

// ctxWithTimeout returns a derived context with a sane default deadline.
func ctxWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}
