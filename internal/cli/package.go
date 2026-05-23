package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/nishikawaakira/kernledger/internal/pkgbuild"
)

type packageCmd struct {
	version string
	commit  string
	cf      commonFlags

	inDir              string
	outPath            string
	includeEC2Metadata bool
}

func newPackageCmd(version, commit string) *packageCmd {
	return &packageCmd{version: version, commit: commit}
}

func (c *packageCmd) Name() string { return "package" }
func (c *packageCmd) Synopsis() string {
	return "bundle an --out directory into a tar.gz with manifest"
}

func (c *packageCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.StringVar(&c.inDir, "in", "", "directory previously populated by acquire/collect (required)")
	fs.StringVar(&c.outPath, "tarball", "", "output .tar.gz path (required)")
	fs.BoolVar(&c.includeEC2Metadata, "include-ec2-metadata", false, "fetch IMDSv2 metadata (off by default; AWS-signed instance-identity is the only cloud info source)")
}

func (c *packageCmd) Run(ctx context.Context, _ []string) error {
	if c.inDir == "" || c.outPath == "" {
		return fmt.Errorf("--in and --tarball are required")
	}
	log, err := c.cf.openAudit(c.inDir)
	if err != nil {
		return err
	}
	defer log.Close()

	adapter, osInfo, err := c.cf.resolveDistro()
	if err != nil {
		log.Warn("package.distro", err.Error(), nil)
	}

	res, err := pkgbuild.Build(ctx, log, pkgbuild.Options{
		InDir:              c.inDir,
		OutPath:            c.outPath,
		IncludeEC2Metadata: c.includeEC2Metadata,
		ToolVersion:        c.version,
		ToolCommit:         c.commit,
		Adapter:            adapter,
		OSInfo:             osInfo,
	})
	if err != nil {
		return err
	}
	if !c.cf.Quiet {
		fmt.Printf("package: %s (%d artifacts, tarball sha256=%s)\n",
			res.TarballPath, len(res.Manifest.Artifacts), res.TarballSHA256)
	}
	return nil
}
