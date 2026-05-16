// Package ubuntu is the distro adapter for Ubuntu LTS releases on EC2.
//
// Activation: blank-imported from cmd/al2-mem-ir/main.go.
//
// Scope:
//
//   This adapter matches ANY Ubuntu host (`ID=ubuntu`) regardless of
//   `VERSION_ID`. The reason: log paths, systemd usage, apt/dpkg layout,
//   and kernel package naming are stable across modern Ubuntu LTS
//   releases (20.04 / 22.04 / 24.04). Pinning to specific VERSION_IDs
//   would force a rebuild every time a new LTS ships, with no real
//   forensic gain.
//
//   If a future Ubuntu version diverges meaningfully (e.g. 26.04
//   replaces systemd or changes the auth log location), we will add a
//   version-specific adapter at THAT point and keep this one as the
//   pre-divergence default. That's exactly the situation the plugin
//   pattern is built for.
//
// Notable differences from the AL2 / AL2023 adapters:
//
//   - Log conventions are Debian-style:
//       /var/log/auth.log    (vs /var/log/secure)
//       /var/log/syslog      (vs /var/log/messages)
//       /var/log/kern.log
//       /var/log/dpkg.log + /var/log/apt/*  (vs yum/dnf logs)
//       /var/log/ufw.log     (when ufw is enabled)
//
//   - Cron spool lives at /var/spool/cron/crontabs/, not /var/spool/cron/.
//
//   - Kernel build deps for LiME use the Debian naming:
//       linux-headers-<release>           (vs kernel-devel-<release>)
//       linux-image-<release>-dbgsym      (vs kernel-debuginfo-<release>)
//     Note: -dbgsym packages live on ddebs.ubuntu.com, not the default
//     archive. Operators need to enable that repo to install them.
//
//   - Ubuntu cloud AMIs frequently use flavored kernels named
//       <ver>-aws / <ver>-azure / <ver>-gcp
//     (e.g. "5.15.0-1051-aws"). KernelInfo.Release is used verbatim, so
//     this just works — no special-casing required.
//
//   - Ubuntu enables Secure Boot + lockdown more aggressively on cloud
//     AMIs. Unsigned LiME modules are commonly rejected. This is NOT
//     handled here; inspect surfaces it via the secure_boot field and
//     forensic-considerations.md documents the operational impact.
//
//   - AppArmor (not SELinux) is the default LSM. AppArmor status
//     collection lives in the generic collector as an Optional item
//     (`aa-status`) so it also runs on AL2/AL2023 hosts that have
//     installed AppArmor manually.
package ubuntu

import (
	"context"

	"github.com/example/al2-mem-ir/internal/distro"
	"github.com/example/al2-mem-ir/internal/ec2"
)

const adapterID = "ubuntu"

type adapter struct{}

func init() { distro.Register(&adapter{}) }

func (a *adapter) ID() string       { return adapterID }
func (a *adapter) Describe() string { return "Ubuntu LTS" }

// Detect intentionally ignores VERSION_ID. See package doc.
func (a *adapter) Detect(os distro.OSInfo) bool {
	return os.ID == "ubuntu"
}

func (a *adapter) Paths() distro.ArtifactPaths {
	return distro.ArtifactPaths{
		SystemLogs: []string{
			// Authentication: sshd, sudo, login, pam.
			"/var/log/auth.log",
			// General system log (rsyslog).
			"/var/log/syslog",
			"/var/log/kern.log",
			// auditd (if installed).
			"/var/log/audit/audit.log",
			// Package manager history.
			"/var/log/dpkg.log",
			"/var/log/apt/history.log",
			"/var/log/apt/term.log",
			// ufw firewall (when enabled it writes here).
			"/var/log/ufw.log",
			// dmesg snapshot, if rsyslog captures it.
			"/var/log/dmesg",
			// Unattended-upgrades audit trail.
			"/var/log/unattended-upgrades/unattended-upgrades.log",
		},
		CronConfigs: []string{
			"/etc/crontab",
			"/etc/cron.d",
			"/etc/cron.hourly",
			"/etc/cron.daily",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			// Note the `crontabs/` suffix — different from RHEL family.
			"/var/spool/cron/crontabs",
		},
		CloudInitLogs: []string{
			"/var/log/cloud-init.log",
			"/var/log/cloud-init-output.log",
		},
		AgentLogs: []string{
			// SSM agent: apt-installed amazon-ssm-agent writes here.
			// (Snap-installed agents write under /var/snap; we add that
			// path too for completeness.)
			"/var/log/amazon/ssm",
			"/var/snap/amazon-ssm-agent/current/logs",
			"/var/log/amazon-cloudwatch-agent",
			"/var/log/ecs",
		},
		AuthorizedKeys: []string{
			"/root/.ssh/authorized_keys",
			"/home/*/.ssh/authorized_keys",
			// `ubuntu` user is the default cloud account on Ubuntu AMIs;
			// the glob above covers it, but call it out so reviewers
			// know to look there first.
		},
	}
}

func (a *adapter) ServiceQueries() []distro.ServiceQuery {
	// Ubuntu 16.04+ uses systemd. Identical queries to AL2/AL2023.
	return []distro.ServiceQuery{
		{Name: "systemctl-list-units", Cmd: "systemctl", Args: []string{"list-units", "--no-pager", "--no-legend"}},
		{Name: "systemctl-list-unit-files-enabled", Cmd: "systemctl", Args: []string{"list-unit-files", "--state=enabled", "--no-pager", "--no-legend"}},
		{Name: "systemctl-failed", Cmd: "systemctl", Args: []string{"--failed", "--no-pager", "--no-legend"}},
	}
}

func (a *adapter) LimeHints(k distro.KernelInfo) distro.LimeHints {
	return distro.LimeHints{
		// apt install linux-headers-$(uname -r)
		KernelDevelPackage: "linux-headers-" + k.Release,
		// dbgsym packages require enabling ddebs.ubuntu.com:
		//   https://wiki.ubuntu.com/Debug%20Symbol%20Packages
		DebuginfoPackage:  "linux-image-" + k.Release + "-dbgsym",
		ModuleLoadCommand: "insmod",
		ExpectedModuleExt: ".ko",
	}
}

func (a *adapter) CloudProviders() []distro.CloudProvider {
	// This tool targets AWS EC2 deployments by design. Ubuntu on GCP /
	// Azure / on-prem will receive an empty CloudInfo unless the
	// operator supplies values via the --instance-id / --region /
	// --account-id flags. That's intentional — silent partial fills
	// from the wrong provider would harm chain of custody.
	return []distro.CloudProvider{ec2Provider{}}
}

type ec2Provider struct{}

func (ec2Provider) Name() string { return "aws-ec2" }

func (ec2Provider) Fetch(ctx context.Context) (map[string]string, error) {
	return ec2.New().Metadata(ctx)
}
