// Package registrytest is a leaf-only test package whose purpose is to
// blank-import every distro adapter and verify that registry-level
// detection still picks the right adapter even when multiple adapters
// match the same os.ID. This catches "I added a new adapter but it
// silently shadows another" bugs.
//
// It must NOT live under cmd/ (we don't want test-only deps in the
// shipped binary) or under one adapter's package (which would only
// import one adapter at a time).
package registrytest

import (
	"testing"

	"github.com/nishikawaakira/kernledger/internal/distro"

	// Order is irrelevant — init() registers each one. We import them
	// here to populate the registry exactly the way cmd/kernledger does.
	_ "github.com/nishikawaakira/kernledger/internal/distro/amazonlinux2"
	_ "github.com/nishikawaakira/kernledger/internal/distro/amazonlinux2023"
	_ "github.com/nishikawaakira/kernledger/internal/distro/ubuntu"
)

// TestDetect_AcrossAdapters is the load-bearing test for the plugin
// pattern. The dispatcher must route by (ID, VERSION_ID) without any
// if/switch — including:
//   - AL2 vs AL2023 (same ID=amzn, different VERSION_ID)
//   - Ubuntu (different ID, matches ANY VERSION_ID by design)
//   - Unknown / closely-related distros must fail loudly
func TestDetect_AcrossAdapters(t *testing.T) {
	cases := []struct {
		os      distro.OSInfo
		wantID  string
		wantErr bool
	}{
		{distro.OSInfo{ID: "amzn", VersionID: "2"}, "amazonlinux2", false},
		{distro.OSInfo{ID: "amzn", VersionID: "2023"}, "amazonlinux2023", false},
		{distro.OSInfo{ID: "ubuntu", VersionID: "20.04"}, "ubuntu", false},
		{distro.OSInfo{ID: "ubuntu", VersionID: "22.04"}, "ubuntu", false},
		{distro.OSInfo{ID: "ubuntu", VersionID: "24.04"}, "ubuntu", false},
		// Future Ubuntu LTS should keep routing to the same adapter.
		{distro.OSInfo{ID: "ubuntu", VersionID: "26.04"}, "ubuntu", false},

		// An unknown amzn version must NOT silently bind to either
		// adapter — better to fail loudly so the operator notices.
		{distro.OSInfo{ID: "amzn", VersionID: "1"}, "", true},
		{distro.OSInfo{ID: "amzn", VersionID: ""}, "", true},

		// Debian is closely related to Ubuntu but does NOT yet have an
		// adapter. The Ubuntu adapter must not match it.
		{distro.OSInfo{ID: "debian", VersionID: "12"}, "", true},

		// Total miss.
		{distro.OSInfo{ID: "alpine", VersionID: "3.19"}, "", true},
	}
	for _, c := range cases {
		got, err := distro.DetectFromOSRelease(c.os)
		if c.wantErr {
			if err == nil {
				t.Errorf("os=%+v: expected error, got adapter %s", c.os, got.ID())
			}
			continue
		}
		if err != nil {
			t.Errorf("os=%+v: unexpected error %v", c.os, err)
			continue
		}
		if got.ID() != c.wantID {
			t.Errorf("os=%+v: got %s, want %s", c.os, got.ID(), c.wantID)
		}
	}
}

// TestIDs_IncludesAllAdapters guards against accidental adapter
// removal (e.g. a future refactor that forgets to keep one around).
func TestIDs_IncludesAllAdapters(t *testing.T) {
	ids := distro.IDs()
	wantAll := []string{"amazonlinux2", "amazonlinux2023", "ubuntu"}
	have := map[string]bool{}
	for _, id := range ids {
		have[id] = true
	}
	for _, w := range wantAll {
		if !have[w] {
			t.Errorf("registry missing %s; have=%v", w, ids)
		}
	}
}
