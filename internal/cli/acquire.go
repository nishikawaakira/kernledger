package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/example/kernledger/internal/acquire"
	"github.com/example/kernledger/internal/distro"
	"github.com/example/kernledger/internal/executor"
	"github.com/example/kernledger/internal/manifest"
)

type acquireCmd struct {
	version string
	commit  string
	cf      commonFlags

	modulePath   string
	outputPath   string
	mode         string
	format       string
	tcpListen    string
	doRmmod      bool
	execute      bool
	allowNonRoot bool
}

func newAcquireCmd(version, commit string) *acquireCmd {
	return &acquireCmd{version: version, commit: commit}
}

func (c *acquireCmd) Name() string     { return "acquire" }
func (c *acquireCmd) Synopsis() string { return "acquire RAM via a prebuilt LiME module" }

func (c *acquireCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.StringVar(&c.modulePath, "module", "", "path to lime.ko built for the running kernel (required)")
	fs.StringVar(&c.outputPath, "output", "", "path to write the memory image (when --mode=file)")
	fs.StringVar(&c.mode, "mode", "file", "output mode: file|tcp")
	fs.StringVar(&c.format, "format", "lime", "LiME format: lime|raw|padded")
	fs.StringVar(&c.tcpListen, "tcp", "", "TCP listen spec for --mode=tcp, e.g. :4444")
	fs.BoolVar(&c.doRmmod, "rmmod", false, "rmmod after acquisition")
	fs.BoolVar(&c.execute, "execute", false, "SAFETY GATE: actually run insmod. Without this, only the plan is recorded.")
	fs.BoolVar(&c.allowNonRoot, "allow-non-root", false, "skip the root precheck")
}

func (c *acquireCmd) Run(ctx context.Context, _ []string) error {
	if err := rootCheck(c.allowNonRoot); err != nil {
		// Non-root + --execute is almost certainly a bug.
		if c.execute {
			return err
		}
		// In planning mode, root isn't strictly required; warn instead.
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	outDir, err := c.cf.resolveOutDir(true)
	if err != nil {
		return err
	}
	log, err := c.cf.openAudit(outDir)
	if err != nil {
		return err
	}
	defer log.Close()

	adapter, osInfo, err := c.cf.resolveDistro()
	if err != nil {
		return err
	}

	// Resolve the LiME output path to live inside --out unless the user
	// gave an absolute path. This minimizes accidental writes to system
	// directories on the target.
	if c.mode == "file" && c.outputPath != "" && !filepath.IsAbs(c.outputPath) {
		c.outputPath = filepath.Join(outDir, c.outputPath)
	}
	if c.mode == "file" && c.outputPath == "" {
		c.outputPath = filepath.Join(outDir, "memory.lime")
	}

	opts := acquire.Options{
		ModulePath:   c.modulePath,
		OutputPath:   c.outputPath,
		OutputMode:   c.mode,
		OutputFormat: c.format,
		TCPListen:    c.tcpListen,
		Rmmod:        c.doRmmod,
		Execute:      c.execute && !c.cf.DryRun,
	}

	exec := executor.NewReal(120 * time.Second)
	if c.cf.DryRun {
		exec = nil // not used; acquire.Runner is fine with nil for dry-run
	}

	runner := &acquire.Runner{Exec: realOrDryRun(exec, c.cf.DryRun), Log: log}

	log.Info("acquire.start", "starting acquisition", map[string]interface{}{
		"module":  c.modulePath,
		"output":  c.outputPath,
		"mode":    c.mode,
		"execute": c.execute,
		"dry_run": c.cf.DryRun,
	})

	acq, err := runner.Acquire(ctx, opts, c.cf.DryRun)
	if err != nil {
		// Still try to persist a manifest so the failure is auditable.
		if acq != nil {
			persistAcquireManifest(c, outDir, osInfo, adapter.ID(), acq)
		}
		return err
	}

	if err := persistAcquireManifest(c, outDir, osInfo, adapter.ID(), acq); err != nil {
		return err
	}

	log.Info("acquire.done", "acquisition complete", map[string]interface{}{
		"image_sha256": acq.ImageSHA256,
		"image_bytes":  acq.ImageBytes,
		"dry_run":      acq.DryRun,
	})
	if !c.cf.Quiet {
		state := "DRY-RUN"
		if !acq.DryRun {
			state = "EXECUTED"
		}
		fmt.Printf("acquire: %s, module=%s, image=%s, sha256=%s\n",
			state, c.modulePath, c.outputPath, acq.ImageSHA256)
	}
	return nil
}

func realOrDryRun(real executor.Executor, dry bool) executor.Executor {
	if dry || real == nil {
		return executor.NewDryRun()
	}
	return real
}

func persistAcquireManifest(c *acquireCmd, outDir string, osInfo distro.OSInfo, adapterID string, acq *manifest.Acquisition) error {
	hostname, _ := os.Hostname()
	m := manifest.New(c.version, c.commit, adapterID)
	m.Host = manifest.HostInfo{
		Hostname:      hostname,
		KernelRelease: readFile("/proc/sys/kernel/osrelease"),
		KernelVersion: readFile("/proc/sys/kernel/version"),
		OSPrettyName:  osInfo.PrettyName,
		OSID:          osInfo.ID,
		OSVersionID:   osInfo.VersionID,
	}
	m.Acquisition = acq
	return m.Save(filepath.Join(outDir, "acquire-manifest.json"))
}
