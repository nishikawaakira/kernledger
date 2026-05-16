package amazonlinux2023

import (
	"strings"
	"testing"

	"github.com/example/al2-mem-ir/internal/distro"
)

func TestDetect(t *testing.T) {
	a := &adapter{}
	cases := []struct {
		os   distro.OSInfo
		want bool
	}{
		{distro.OSInfo{ID: "amzn", VersionID: "2023"}, true},
		{distro.OSInfo{ID: "amzn", VersionID: "2"}, false}, // AL2 must NOT match here
		{distro.OSInfo{ID: "amzn", VersionID: ""}, false},
		{distro.OSInfo{ID: "rhel", VersionID: "9"}, false},
		{distro.OSInfo{ID: "fedora", VersionID: "39"}, false},
		{distro.OSInfo{}, false},
	}
	for _, c := range cases {
		if got := a.Detect(c.os); got != c.want {
			t.Errorf("Detect(%+v) = %v, want %v", c.os, got, c.want)
		}
	}
}

func TestLimeHintsCarryKernelRelease(t *testing.T) {
	a := &adapter{}
	hints := a.LimeHints(distro.KernelInfo{Release: "6.1.66-91.160.amzn2023.x86_64"})
	if hints.KernelDevelPackage != "kernel-devel-6.1.66-91.160.amzn2023.x86_64" {
		t.Errorf("unexpected devel pkg: %s", hints.KernelDevelPackage)
	}
	if hints.DebuginfoPackage != "kernel-debuginfo-6.1.66-91.160.amzn2023.x86_64" {
		t.Errorf("unexpected debuginfo pkg: %s", hints.DebuginfoPackage)
	}
	if hints.ModuleLoadCommand != "insmod" || hints.ExpectedModuleExt != ".ko" {
		t.Errorf("unexpected module hints: %+v", hints)
	}
}

// TestPaths_ReflectAL2023Differences locks in the AL2023-specific path
// choices that distinguish this adapter from amazonlinux2. If someone
// removes dnf.log or re-adds yum.log, this test should yell.
func TestPaths_ReflectAL2023Differences(t *testing.T) {
	a := &adapter{}
	p := a.Paths()
	joined := strings.Join(p.SystemLogs, " ")
	if !strings.Contains(joined, "dnf.log") {
		t.Error("AL2023 SystemLogs should include /var/log/dnf.log")
	}
	if strings.Contains(joined, "yum.log") {
		t.Error("AL2023 SystemLogs must NOT include /var/log/yum.log (yum was retired)")
	}
}

func TestRegistered(t *testing.T) {
	// init() must have registered the adapter under "amazonlinux2023".
	a, ok := distro.Get("amazonlinux2023")
	if !ok {
		t.Fatal("amazonlinux2023 not registered")
	}
	if a.ID() != "amazonlinux2023" {
		t.Errorf("got id %s", a.ID())
	}
	if a.Describe() != "Amazon Linux 2023" {
		t.Errorf("got describe %s", a.Describe())
	}
}
