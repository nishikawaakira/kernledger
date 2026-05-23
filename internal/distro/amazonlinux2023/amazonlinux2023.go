// Package amazonlinux2023 is the distro adapter for Amazon Linux 2023.
//
// Activation: blank-imported from cmd/kernledger/main.go so that its
// init() registers the adapter into the distro registry.
//
// Relationship to the amazonlinux2 adapter:
//
//	AL2 and AL2023 share the broad RHEL/Fedora lineage (rpm/dnf-yum
//	packaging, systemd, NetworkManager-ish). We intentionally DO NOT
//	share code between the two adapters yet — they would only diverge
//	further as new logs/paths get added. When a third RHEL-family
//	adapter lands (RHEL 9, Rocky, AlmaLinux) we will lift the truly
//	common defaults into a `rhelfamily` helper package. Until then,
//	duplication is cheaper than the wrong abstraction.
//
// Notable AL2023 vs AL2 differences captured here:
//
//   - VERSION_ID is "2023".
//   - rsyslog is NOT enabled by default; the system journal (journald)
//     is the canonical log source. /var/log/messages is therefore
//     usually absent. We still glob the path for hosts that re-enabled
//     rsyslog manually — Paths.SystemLogs is best-effort.
//   - Package manager is dnf, so dnf.log and dnf.rpm.log replace
//     yum.log.
//   - Inspector v2 / SSM / CloudWatch agent paths are unchanged.
//   - Kernel package naming is identical to AL2 (kernel-devel-<release>,
//     kernel-debuginfo-<release>).
package amazonlinux2023

import (
	"context"

	"github.com/nishikawaakira/kernledger/internal/distro"
	"github.com/nishikawaakira/kernledger/internal/ec2"
)

const adapterID = "amazonlinux2023"

type adapter struct{}

func init() { distro.Register(&adapter{}) }

func (a *adapter) ID() string       { return adapterID }
func (a *adapter) Describe() string { return "Amazon Linux 2023" }

// Detect must precisely separate AL2023 from AL2 — both report
// ID=amzn but VERSION_ID differs.
func (a *adapter) Detect(os distro.OSInfo) bool {
	return os.ID == "amzn" && os.VersionID == "2023"
}

func (a *adapter) Paths() distro.ArtifactPaths {
	return distro.ArtifactPaths{
		SystemLogs: []string{
			// rsyslog files: AL2023 doesn't enable rsyslog by default,
			// but operators frequently install it. We try anyway —
			// missing paths are skipped silently by the collector.
			"/var/log/secure",
			"/var/log/messages",
			"/var/log/cron",
			// audit + dmesg + dnf are present in stock AL2023.
			"/var/log/audit/audit.log",
			"/var/log/dmesg",
			"/var/log/dnf.log",
			"/var/log/dnf.rpm.log",
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
			// AL2023 ships with Inspector v2 hook points in some AMIs.
			"/var/log/amazon/inspector",
			// GuardDuty Runtime Monitoring writes operational logs here
			// on AL2023 hosts running the managed agent.
			"/opt/aws/guardduty-agent/logs",
		},
		AuthorizedKeys: []string{
			"/root/.ssh/authorized_keys",
			"/home/*/.ssh/authorized_keys",
		},
	}
}

func (a *adapter) ServiceQueries() []distro.ServiceQuery {
	// systemd queries are identical to AL2's. If we ever support
	// non-systemd distros (Alpine + OpenRC, busybox) the difference
	// will live in those adapters, not in branching here.
	return []distro.ServiceQuery{
		{Name: "systemctl-list-units", Cmd: "systemctl", Args: []string{"list-units", "--no-pager", "--no-legend"}},
		{Name: "systemctl-list-unit-files-enabled", Cmd: "systemctl", Args: []string{"list-unit-files", "--state=enabled", "--no-pager", "--no-legend"}},
		{Name: "systemctl-failed", Cmd: "systemctl", Args: []string{"--failed", "--no-pager", "--no-legend"}},
	}
}

func (a *adapter) LimeHints(k distro.KernelInfo) distro.LimeHints {
	return distro.LimeHints{
		// dnf install kernel-devel-$(uname -r)
		// dnf install kernel-debuginfo-$(uname -r)
		KernelDevelPackage: "kernel-devel-" + k.Release,
		DebuginfoPackage:   "kernel-debuginfo-" + k.Release,
		ModuleLoadCommand:  "insmod",
		ExpectedModuleExt:  ".ko",
	}
}

func (a *adapter) CloudProviders() []distro.CloudProvider {
	return []distro.CloudProvider{ec2Provider{}}
}

// ec2Provider is the same minimal adapter pattern used in the AL2
// adapter. It lives here rather than in internal/ec2 to avoid a
// dependency from ec2 (a low-level transport package) up to the distro
// package's interface types.
type ec2Provider struct{}

func (ec2Provider) Name() string { return "aws-ec2" }

func (ec2Provider) Fetch(ctx context.Context) (map[string]string, error) {
	return ec2.New().Metadata(ctx)
}
