package amazonlinux2

import (
	"testing"

	"github.com/example/kernledger/internal/distro"
)

func TestDetect(t *testing.T) {
	a := &adapter{}
	cases := []struct {
		os   distro.OSInfo
		want bool
	}{
		{distro.OSInfo{ID: "amzn", VersionID: "2"}, true},
		{distro.OSInfo{ID: "amzn", VersionID: "2023"}, false},
		{distro.OSInfo{ID: "rhel", VersionID: "9"}, false},
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
	hints := a.LimeHints(distro.KernelInfo{Release: "5.10.220-209.869.amzn2.x86_64"})
	if hints.KernelDevelPackage != "kernel-devel-5.10.220-209.869.amzn2.x86_64" {
		t.Errorf("unexpected devel pkg: %s", hints.KernelDevelPackage)
	}
	if hints.DebuginfoPackage != "kernel-debuginfo-5.10.220-209.869.amzn2.x86_64" {
		t.Errorf("unexpected debuginfo pkg: %s", hints.DebuginfoPackage)
	}
	if hints.ModuleLoadCommand != "insmod" || hints.ExpectedModuleExt != ".ko" {
		t.Errorf("unexpected module hints: %+v", hints)
	}
}

func TestRegistered(t *testing.T) {
	// init() must have registered the adapter under "amazonlinux2".
	a, ok := distro.Get("amazonlinux2")
	if !ok {
		t.Fatal("amazonlinux2 not registered")
	}
	if a.ID() != "amazonlinux2" {
		t.Errorf("got id %s", a.ID())
	}
}
