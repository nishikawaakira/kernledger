package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/nishikawaakira/kernledger/internal/executor"
	"github.com/nishikawaakira/kernledger/internal/symbols"
)

type symbolsCmd struct {
	version string
	commit  string
	cf      commonFlags

	dwarf2json  string
	vmlinux     string
	btf         string
	kernelLabel string
}

func newSymbolsCmd(version, commit string) *symbolsCmd {
	return &symbolsCmd{version: version, commit: commit}
}

func (c *symbolsCmd) Name() string { return "symbols" }
func (c *symbolsCmd) Synopsis() string {
	return "generate Volatility 3 Linux symbols via dwarf2json (analyst side)"
}

func (c *symbolsCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.StringVar(&c.dwarf2json, "dwarf2json", "", "path to dwarf2json binary")
	fs.StringVar(&c.vmlinux, "vmlinux", "", "path to vmlinux containing DWARF")
	fs.StringVar(&c.btf, "btf", "", "optional BTF file (e.g. /sys/kernel/btf/vmlinux)")
	fs.StringVar(&c.kernelLabel, "kernel", "", "label used as output filename, e.g. kernel release string")
}

func (c *symbolsCmd) Run(ctx context.Context, _ []string) error {
	outDir, err := c.cf.resolveOutDir(true)
	if err != nil {
		return err
	}
	log, err := c.cf.openAudit(outDir)
	if err != nil {
		return err
	}
	defer log.Close()

	exec := executor.NewReal(10 * time.Minute)
	if c.cf.DryRun {
		exec = nil
	}

	dst, err := symbols.Generate(ctx, realOrDryRun(exec, c.cf.DryRun), log, symbols.Options{
		Dwarf2JSON:  c.dwarf2json,
		Vmlinux:     c.vmlinux,
		BTFPath:     c.btf,
		KernelLabel: c.kernelLabel,
		OutDir:      outDir,
	})
	if err != nil {
		return err
	}
	if !c.cf.Quiet {
		fmt.Printf("symbols: %s\n", dst)
	}
	return nil
}
