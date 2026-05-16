package ubuntu

import (
	"strings"
	"testing"

	"github.com/example/al2-mem-ir/internal/distro"
)

// TestDetect_AnyVersion locks in the documented policy: the Ubuntu
// adapter matches every Ubuntu LTS without pinning VERSION_ID. If
// someone adds a VERSION_ID check, this test will catch it.
func TestDetect_AnyVersion(t *testing.T) {
	a := &adapter{}
	cases := []struct {
		os   distro.OSInfo
		want bool
	}{
		{distro.OSInfo{ID: "ubuntu", VersionID: "20.04"}, true},
		{distro.OSInfo{ID: "ubuntu", VersionID: "22.04"}, true},
		{distro.OSInfo{ID: "ubuntu", VersionID: "24.04"}, true},
		{distro.OSInfo{ID: "ubuntu", VersionID: "99.99"}, true},  // future
		{distro.OSInfo{ID: "ubuntu", VersionID: ""}, true},       // stripped /etc/os-release
		{distro.OSInfo{ID: "debian", VersionID: "12"}, false},    // closely related but not Ubuntu
		{distro.OSInfo{ID: "amzn", VersionID: "2"}, false},
		{distro.OSInfo{ID: "amzn", VersionID: "2023"}, false},
		{distro.OSInfo{}, false},
	}
	for _, c := range cases {
		if got := a.Detect(c.os); got != c.want {
			t.Errorf("Detect(%+v) = %v, want %v", c.os, got, c.want)
		}
	}
}

func TestLimeHintsUseDebianNaming(t *testing.T) {
	a := &adapter{}
	hints := a.LimeHints(distro.KernelInfo{Release: "5.15.0-1051-aws"})

	// linux-headers, NOT kernel-devel.
	if hints.KernelDevelPackage != "linux-headers-5.15.0-1051-aws" {
		t.Errorf("got devel pkg %q, want linux-headers-5.15.0-1051-aws", hints.KernelDevelPackage)
	}
	if strings.HasPrefix(hints.KernelDevelPackage, "kernel-devel") {
		t.Errorf("Debian-family adapter must not use RHEL-style kernel-devel naming: %s", hints.KernelDevelPackage)
	}

	// linux-image-X-dbgsym, NOT kernel-debuginfo.
	if hints.DebuginfoPackage != "linux-image-5.15.0-1051-aws-dbgsym" {
		t.Errorf("got debuginfo pkg %q", hints.DebuginfoPackage)
	}
	if strings.HasPrefix(hints.DebuginfoPackage, "kernel-debuginfo") {
		t.Errorf("Debian-family adapter must not use RHEL-style kernel-debuginfo naming: %s", hints.DebuginfoPackage)
	}

	if hints.ModuleLoadCommand != "insmod" || hints.ExpectedModuleExt != ".ko" {
		t.Errorf("unexpected module hints: %+v", hints)
	}
}

// TestPaths_ReflectDebianConventions locks the Debian-family path
// choices that differentiate this adapter from the RHEL-family ones.
func TestPaths_ReflectDebianConventions(t *testing.T) {
	a := &adapter{}
	p := a.Paths()
	joined := strings.Join(p.SystemLogs, " ")

	// auth.log + syslog are required; /var/log/secure + /var/log/messages
	// are the RHEL equivalents and MUST NOT appear.
	if !strings.Contains(joined, "/var/log/auth.log") {
		t.Error("Ubuntu adapter SystemLogs must include /var/log/auth.log")
	}
	if !strings.Contains(joined, "/var/log/syslog") {
		t.Error("Ubuntu adapter SystemLogs must include /var/log/syslog")
	}
	if strings.Contains(joined, "/var/log/secure") {
		t.Error("Ubuntu adapter SystemLogs must not include /var/log/secure (RHEL-only)")
	}
	if strings.Contains(joined, "/var/log/messages") {
		t.Error("Ubuntu adapter SystemLogs must not include /var/log/messages (RHEL-only)")
	}
	if !strings.Contains(joined, "/var/log/dpkg.log") {
		t.Error("Ubuntu adapter SystemLogs should include /var/log/dpkg.log")
	}

	// Cron spool path on Ubuntu has the `crontabs/` suffix.
	cronJoined := strings.Join(p.CronConfigs, " ")
	if !strings.Contains(cronJoined, "/var/spool/cron/crontabs") {
		t.Error("Ubuntu CronConfigs must include /var/spool/cron/crontabs")
	}
}

func TestRegistered(t *testing.T) {
	a, ok := distro.Get("ubuntu")
	if !ok {
		t.Fatal("ubuntu not registered")
	}
	if a.ID() != "ubuntu" {
		t.Errorf("got id %s", a.ID())
	}
	if a.Describe() != "Ubuntu LTS" {
		t.Errorf("got describe %s", a.Describe())
	}
}
