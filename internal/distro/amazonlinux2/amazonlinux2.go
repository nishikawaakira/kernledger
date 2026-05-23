// Package amazonlinux2 is the distro adapter for Amazon Linux 2.
//
// Activation: blank-imported from cmd/kernledger/main.go so that its
// init() registers the adapter into the distro registry.
package amazonlinux2

import (
	"context"

	"github.com/nishikawaakira/kernledger/internal/distro"
	"github.com/nishikawaakira/kernledger/internal/ec2"
)

const adapterID = "amazonlinux2"

type adapter struct{}

func init() { distro.Register(&adapter{}) }

func (a *adapter) ID() string       { return adapterID }
func (a *adapter) Describe() string { return "Amazon Linux 2" }

// Detect matches Amazon Linux 2 specifically. AL2023 has ID=amzn,
// VERSION_ID="2023", so we must compare both.
func (a *adapter) Detect(os distro.OSInfo) bool {
	return os.ID == "amzn" && os.VersionID == "2"
}

func (a *adapter) Paths() distro.ArtifactPaths {
	return distro.ArtifactPaths{
		SystemLogs: []string{
			"/var/log/messages",
			"/var/log/secure",
			"/var/log/cron",
			"/var/log/audit/audit.log",
			"/var/log/dmesg",
			"/var/log/yum.log",
		},
		CronConfigs: []string{
			"/etc/crontab",
			"/etc/cron.d",
			"/etc/cron.hourly",
			"/etc/cron.daily",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			"/var/spool/cron",
		},
		CloudInitLogs: []string{
			"/var/log/cloud-init.log",
			"/var/log/cloud-init-output.log",
		},
		AgentLogs: []string{
			"/var/log/amazon/ssm",
			"/var/log/ecs",
			"/var/log/amazon-cloudwatch-agent",
		},
		AuthorizedKeys: []string{
			"/root/.ssh/authorized_keys",
			"/home/*/.ssh/authorized_keys",
		},
	}
}

func (a *adapter) ServiceQueries() []distro.ServiceQuery {
	return []distro.ServiceQuery{
		{Name: "systemctl-list-units", Cmd: "systemctl", Args: []string{"list-units", "--no-pager", "--no-legend"}},
		{Name: "systemctl-list-unit-files-enabled", Cmd: "systemctl", Args: []string{"list-unit-files", "--state=enabled", "--no-pager", "--no-legend"}},
		{Name: "systemctl-failed", Cmd: "systemctl", Args: []string{"--failed", "--no-pager", "--no-legend"}},
	}
}

func (a *adapter) LimeHints(k distro.KernelInfo) distro.LimeHints {
	return distro.LimeHints{
		// AL2 ships matched -devel packages from amazon-linux-extras / yum.
		// The exact package name embeds the kernel release.
		KernelDevelPackage: "kernel-devel-" + k.Release,
		DebuginfoPackage:   "kernel-debuginfo-" + k.Release,
		ModuleLoadCommand:  "insmod",
		ExpectedModuleExt:  ".ko",
	}
}

func (a *adapter) CloudProviders() []distro.CloudProvider {
	return []distro.CloudProvider{ec2Provider{}}
}

// ec2Provider is a thin adapter so the IMDS client satisfies the
// CloudProvider interface from the distro package without forcing a
// circular import.
type ec2Provider struct{}

func (ec2Provider) Name() string { return "aws-ec2" }

func (ec2Provider) Fetch(ctx context.Context) (map[string]string, error) {
	return ec2.New().Metadata(ctx)
}
