package distro

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeAdapter is used only by these tests.
type fakeAdapter struct {
	id        string
	matchID   string
	matchVer  string
}

func (f *fakeAdapter) ID() string                              { return f.id }
func (f *fakeAdapter) Describe() string                        { return f.id + "-test" }
func (f *fakeAdapter) Detect(o OSInfo) bool                    { return o.ID == f.matchID && o.VersionID == f.matchVer }
func (f *fakeAdapter) Paths() ArtifactPaths                    { return ArtifactPaths{} }
func (f *fakeAdapter) ServiceQueries() []ServiceQuery          { return nil }
func (f *fakeAdapter) LimeHints(KernelInfo) LimeHints          { return LimeHints{} }
func (f *fakeAdapter) CloudProviders() []CloudProvider         { return nil }

func TestRegister_DuplicatePanics(t *testing.T) {
	a := &fakeAdapter{id: "test-dup", matchID: "x", matchVer: "1"}
	Register(a)
	defer delete(registry, "test-dup")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	Register(a)
}

func TestDetectFromOSRelease_PicksMatching(t *testing.T) {
	Register(&fakeAdapter{id: "td-amzn2", matchID: "amzn", matchVer: "2"})
	Register(&fakeAdapter{id: "td-rhel9", matchID: "rhel", matchVer: "9"})
	defer delete(registry, "td-amzn2")
	defer delete(registry, "td-rhel9")

	got, err := DetectFromOSRelease(OSInfo{ID: "amzn", VersionID: "2"})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if got.ID() != "td-amzn2" {
		t.Errorf("got %s, want td-amzn2", got.ID())
	}
}

func TestDetectFromOSRelease_NoMatch(t *testing.T) {
	if _, err := DetectFromOSRelease(OSInfo{ID: "unobtanium", VersionID: "0"}); err == nil {
		t.Fatal("expected error when no adapter matches")
	}
}

func TestParseOSRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	body := `NAME="Amazon Linux"
VERSION="2"
ID="amzn"
VERSION_ID="2"
PRETTY_NAME="Amazon Linux 2"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := ParseOSRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "amzn" || info.VersionID != "2" || info.PrettyName != "Amazon Linux 2" {
		t.Errorf("unexpected: %+v", info)
	}
}

func TestParseOSRelease_MissingIsNotError(t *testing.T) {
	info, err := ParseOSRelease(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if info.ID != "" {
		t.Errorf("expected zero info, got %+v", info)
	}
}

// Compile-time check that the cloud provider iface is small enough that
// the test stub satisfies it.
var _ CloudProvider = (*nullProvider)(nil)

type nullProvider struct{}

func (nullProvider) Name() string                                  { return "null" }
func (nullProvider) Fetch(context.Context) (map[string]string, error) { return nil, nil }
