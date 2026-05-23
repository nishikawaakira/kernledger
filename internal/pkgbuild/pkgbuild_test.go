package pkgbuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nishikawaakira/kernledger/internal/audit"
	"github.com/nishikawaakira/kernledger/internal/distro"
	"github.com/nishikawaakira/kernledger/internal/manifest"
)

func TestBuild_HashesAndTars(t *testing.T) {
	in := t.TempDir()
	// Seed a tiny "evidence" layout.
	must(t, os.MkdirAll(filepath.Join(in, "collect"), 0o700))
	must(t, os.WriteFile(filepath.Join(in, "collect", "uname.out"), []byte("Linux test"), 0o600))
	must(t, os.WriteFile(filepath.Join(in, "audit.log"), []byte("{}\n"), 0o600))

	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	log, err := audit.NewFileLogger("", false)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	res, err := Build(context.Background(), log, Options{
		InDir:       in,
		OutPath:     out,
		ToolVersion: "0.0.0",
		ToolCommit:  "test",
		Adapter:     nil,
		OSInfo:      distro.OSInfo{ID: "amzn", VersionID: "2", PrettyName: "Amazon Linux 2"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m := res.Manifest
	if len(m.Artifacts) < 2 {
		t.Errorf("expected at least 2 artifacts, got %d", len(m.Artifacts))
	}
	// manifest.json itself MUST NOT appear in the artifact list (self-reference exclusion).
	for _, a := range m.Artifacts {
		if a.Path == "manifest.json" {
			t.Errorf("manifest.json should not be listed as artifact: %+v", a)
		}
	}

	// Verify tarball can be read back and uname.out is inside.
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(h.Name, "/collect/uname.out") {
			found = true
		}
	}
	if !found {
		t.Error("uname.out not found in tarball")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestBuild_ManifestInTarballMatchesReturned guarantees that the
// manifest.json embedded in the tarball is byte-identical to the
// manifest written to InDir (and to the in-memory Manifest returned by
// Build). This is the regression test for the self-reference bug where
// Build mutated m.Artifacts after Save().
func TestBuild_ManifestInTarballMatchesReturned(t *testing.T) {
	in := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(in, "collect"), 0o700))
	must(t, os.WriteFile(filepath.Join(in, "collect", "uname.out"), []byte("Linux test"), 0o600))
	must(t, os.WriteFile(filepath.Join(in, "audit.log"), []byte("{}\n"), 0o600))

	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	log, err := audit.NewFileLogger("", false)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	res, err := Build(context.Background(), log, Options{
		InDir:       in,
		OutPath:     out,
		ToolVersion: "0.0.0",
		ToolCommit:  "test",
		OSInfo:      distro.OSInfo{ID: "amzn", VersionID: "2"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// 1. The on-disk manifest.json (inside InDir) must decode equal to
	//    the returned Manifest.
	onDisk, err := manifest.Load(res.ManifestPath)
	if err != nil {
		t.Fatalf("load disk manifest: %v", err)
	}
	if onDisk.SchemaVersion != res.Manifest.SchemaVersion ||
		len(onDisk.Artifacts) != len(res.Manifest.Artifacts) {
		t.Errorf("on-disk vs returned mismatch: artifacts %d vs %d",
			len(onDisk.Artifacts), len(res.Manifest.Artifacts))
	}

	// 2. The manifest.json bytes inside the tarball must equal the
	//    bytes on disk in InDir. This is the strict regression check.
	diskBytes, err := os.ReadFile(res.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tarBytes := readFromTar(t, out, "/manifest.json")
	if tarBytes == nil {
		t.Fatal("manifest.json not found in tarball")
	}
	if !bytes.Equal(diskBytes, tarBytes) {
		t.Errorf("manifest bytes diverge between disk and tarball\n--- disk (%d bytes) ---\n%s\n--- tar (%d bytes) ---\n%s",
			len(diskBytes), diskBytes, len(tarBytes), tarBytes)
	}

	// 3. The returned manifest must NOT list manifest.json as an
	//    artifact (self-reference is impossible). This catches the
	//    original bug.
	for _, a := range res.Manifest.Artifacts {
		if a.Path == "manifest.json" {
			t.Errorf("manifest.json must be excluded from artifacts (got %+v)", a)
		}
	}
}

// readFromTar returns the bytes of a file inside the .tar.gz at outPath
// whose name ends with the given suffix. Returns nil if not found.
func readFromTar(t *testing.T, outPath, suffix string) []byte {
	t.Helper()
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(h.Name, suffix) {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

// TestBuild_CloudOnlyFromIMDS locks in the post-3.x policy: cloud info
// is populated ONLY when --include-ec2-metadata is set, and ONLY from
// the adapter's cloud provider. There are no operator-supplied override
// flags; an operator who needs AWS context with IMDS disabled must put
// it in the bundle's filename instead.
func TestBuild_CloudOnlyFromIMDS(t *testing.T) {
	in := t.TempDir()
	must(t, os.WriteFile(filepath.Join(in, "marker"), []byte("x"), 0o600))

	log, err := audit.NewFileLogger("", false)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	providerCalled := 0
	adapter := &fakeAdapter{name: "fake", provider: &fakeProvider{
		name: "fake-cloud",
		fetch: func() (map[string]string, error) {
			providerCalled++
			return map[string]string{
				"instance_id": "i-FROM-IMDS",
				"region":      "us-east-1",
			}, nil
		},
	}}

	// Case 1: IncludeEC2Metadata=false → provider untouched, Cloud nil.
	out1 := filepath.Join(t.TempDir(), "b1.tar.gz")
	res1, err := Build(context.Background(), log, Options{
		InDir:   in,
		OutPath: out1,
		Adapter: adapter,
	})
	if err != nil {
		t.Fatalf("build 1: %v", err)
	}
	if providerCalled != 0 {
		t.Errorf("provider called %d time(s) without IncludeEC2Metadata", providerCalled)
	}
	if res1.Manifest.Cloud != nil {
		t.Errorf("Cloud must be nil when IMDS off; got %+v", res1.Manifest.Cloud)
	}

	// Case 2: IncludeEC2Metadata=true → provider called, Cloud populated
	// purely from provider data.
	out2 := filepath.Join(t.TempDir(), "b2.tar.gz")
	res2, err := Build(context.Background(), log, Options{
		InDir:              in,
		OutPath:            out2,
		IncludeEC2Metadata: true,
		Adapter:            adapter,
	})
	if err != nil {
		t.Fatalf("build 2: %v", err)
	}
	if providerCalled != 1 {
		t.Errorf("provider should have been called exactly once; was %d", providerCalled)
	}
	if res2.Manifest.Cloud == nil {
		t.Fatal("expected Cloud populated from IMDS")
	}
	if res2.Manifest.Cloud.InstanceID != "i-FROM-IMDS" || res2.Manifest.Cloud.Region != "us-east-1" {
		t.Errorf("IMDS values not propagated: %+v", res2.Manifest.Cloud)
	}
	// Provider name must come from the adapter, NOT from "operator-supplied"
	// (that label existed in schema ≤ 3.0.0 and is gone now).
	if res2.Manifest.Cloud.Provider != "fake-cloud" {
		t.Errorf("Cloud.Provider = %q; want fake-cloud", res2.Manifest.Cloud.Provider)
	}
}

// --- test doubles ---

type fakeAdapter struct {
	name     string
	provider distro.CloudProvider
}

func (f *fakeAdapter) ID() string                                   { return f.name }
func (f *fakeAdapter) Describe() string                             { return f.name }
func (f *fakeAdapter) Detect(distro.OSInfo) bool                    { return true }
func (f *fakeAdapter) Paths() distro.ArtifactPaths                  { return distro.ArtifactPaths{} }
func (f *fakeAdapter) ServiceQueries() []distro.ServiceQuery        { return nil }
func (f *fakeAdapter) LimeHints(distro.KernelInfo) distro.LimeHints { return distro.LimeHints{} }
func (f *fakeAdapter) CloudProviders() []distro.CloudProvider {
	if f.provider == nil {
		return nil
	}
	return []distro.CloudProvider{f.provider}
}

type fakeProvider struct {
	name  string
	fetch func() (map[string]string, error)
}

func (p *fakeProvider) Name() string                                         { return p.name }
func (p *fakeProvider) Fetch(ctx context.Context) (map[string]string, error) { return p.fetch() }

// suppress unused import warning if json is not used elsewhere.
var _ = json.Marshal
