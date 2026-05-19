package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/example/al2-mem-ir/internal/pkgbuild"
)

type packageCmd struct {
	version string
	commit  string
	cf      commonFlags

	inDir              string
	outPath            string
	caseID             string
	includeEC2Metadata bool
	instanceID         string
	region             string
	accountID          string
}

func newPackageCmd(version, commit string) *packageCmd {
	return &packageCmd{version: version, commit: commit}
}

func (c *packageCmd) Name() string     { return "package" }
func (c *packageCmd) Synopsis() string { return "bundle an --out directory into a tar.gz with manifest" }

func (c *packageCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.StringVar(&c.inDir, "in", "", "directory previously populated by acquire/collect (required)")
	fs.StringVar(&c.outPath, "tarball", "", "output .tar.gz path (required)")
	fs.StringVar(&c.caseID, "case-id", "", "case identifier (links manifest to ticket / case-management system)")
	fs.BoolVar(&c.includeEC2Metadata, "include-ec2-metadata", false, "fetch IMDSv2 metadata (off by default)")
	// Explicit metadata overrides. These take precedence over any
	// values pulled from IMDS and let the operator pin chain-of-custody
	// fields when running outside EC2 (e.g. forensic copy on a
	// workstation, or instance whose IMDS has been disabled).
	fs.StringVar(&c.instanceID, "instance-id", "", "explicit EC2 instance id (overrides IMDS)")
	fs.StringVar(&c.region, "region", "", "explicit AWS region (overrides IMDS)")
	fs.StringVar(&c.accountID, "account-id", "", "explicit AWS account id (overrides IMDS)")
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
		CaseID:             c.caseID,
		IncludeEC2Metadata: c.includeEC2Metadata,
		InstanceIDOverride: c.instanceID,
		RegionOverride:     c.region,
		AccountIDOverride:  c.accountID,
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
