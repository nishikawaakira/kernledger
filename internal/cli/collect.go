package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/example/al2-mem-ir/internal/collector"
	"github.com/example/al2-mem-ir/internal/executor"
	"github.com/example/al2-mem-ir/internal/manifest"
)

type collectCmd struct {
	version string
	commit  string
	cf      commonFlags

	includeEnv   bool
	allowNonRoot bool
}

func newCollectCmd(version, commit string) *collectCmd {
	return &collectCmd{version: version, commit: commit}
}

func (c *collectCmd) Name() string     { return "collect" }
func (c *collectCmd) Synopsis() string { return "collect volatile artifacts to --out" }

func (c *collectCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.BoolVar(&c.includeEnv, "include-env", false, "include environment variables (off by default; may contain secrets)")
	fs.BoolVar(&c.allowNonRoot, "allow-non-root", false, "skip the root precheck (some artifacts will be missing or empty)")
}

func (c *collectCmd) Run(ctx context.Context, _ []string) error {
	if err := rootCheck(c.allowNonRoot); err != nil {
		return err
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

	log.Info("collect.start", "starting collection", map[string]interface{}{
		"out":     outDir,
		"adapter": adapter.ID(),
		"dry_run": c.cf.DryRun,
	})

	exec := executor.NewReal(30 * time.Second)
	col := collector.New(exec, adapter, log, collector.Options{
		OutDir:     outDir,
		IncludeEnv: c.includeEnv,
		DryRun:     c.cf.DryRun,
	})

	collection, err := col.Run(ctx)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	m := manifest.New(c.version, c.commit, adapter.ID())
	m.Host = manifest.HostInfo{
		Hostname:      hostname,
		KernelRelease: readFile("/proc/sys/kernel/osrelease"),
		KernelVersion: readFile("/proc/sys/kernel/version"),
		OSPrettyName:  osInfo.PrettyName,
		OSID:          osInfo.ID,
		OSVersionID:   osInfo.VersionID,
	}
	m.Collection = collection
	mPath := filepath.Join(outDir, "collect-manifest.json")
	if err := m.Save(mPath); err != nil {
		return err
	}
	log.Info("collect.done", "collection complete", map[string]interface{}{
		"manifest": mPath,
		"items":    len(collection.Items),
	})
	if !c.cf.Quiet {
		fmt.Printf("collect: %d items, manifest=%s\n", len(collection.Items), mPath)
	}
	return nil
}
