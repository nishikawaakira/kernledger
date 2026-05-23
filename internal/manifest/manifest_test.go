package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalysisSummary(t *testing.T) {
	cases := []struct {
		name       string
		results    []PluginResult
		wantOK     int
		wantFailed int
	}{
		{"nil-results", nil, 0, 0},
		{"all-success", []PluginResult{
			{Plugin: "a", ExitCode: 0},
			{Plugin: "b", ExitCode: 0},
		}, 2, 0},
		{"err-string-counts-as-failure", []PluginResult{
			{Plugin: "a", ExitCode: 0, Err: "synthetic"},
			{Plugin: "b", ExitCode: 0},
		}, 1, 1},
		{"non-zero-exit-counts-as-failure-even-without-err", []PluginResult{
			{Plugin: "a", ExitCode: 7},
			{Plugin: "b", ExitCode: 0},
		}, 1, 1},
		{"all-failed", []PluginResult{
			{Plugin: "a", ExitCode: 1, Err: "x"},
			{Plugin: "b", ExitCode: 2},
		}, 0, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Analysis{PluginResults: tc.results}
			ok, fail := a.Summary()
			if ok != tc.wantOK || fail != tc.wantFailed {
				t.Errorf("got (%d,%d), want (%d,%d)", ok, fail, tc.wantOK, tc.wantFailed)
			}
		})
	}

	// Nil receiver must not panic.
	var a *Analysis
	if ok, fail := a.Summary(); ok != 0 || fail != 0 {
		t.Errorf("nil receiver: got (%d,%d)", ok, fail)
	}
}

func TestRoundTrip(t *testing.T) {
	m := New("0.1.0", "abc1234", "amazonlinux2")
	m.Artifacts = []Artifact{
		{Path: "memory.lime", SHA256: "deadbeef", Size: 42, Kind: "memory_image"},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := m.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %s", got.SchemaVersion)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].SHA256 != "deadbeef" {
		t.Errorf("artifacts = %+v", got.Artifacts)
	}
	if got.Tool.Name != "kernledger" {
		t.Errorf("tool = %+v", got.Tool)
	}
	// New() must auto-capture Identity. It is OS-dependent so we only
	// check that the structure exists.
	if got.Identity == nil {
		t.Error("Identity not captured by New()")
	}
}

// TestManifest_NoCaseField is the regression test for schema 3.0.0:
// the manifest must NOT serialize a "case" field anywhere. If a future
// change re-adds CaseInfo without bumping schema, this test catches it.
func TestManifest_NoCaseField(t *testing.T) {
	m := New("0.1.0", "abc1234", "amazonlinux2")
	m.Artifacts = []Artifact{
		{Path: "x", SHA256: "y", Size: 1, Kind: "other"},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// JSON-level check: the literal "case" field must be absent.
	if strings.Contains(string(b), `"case"`) {
		t.Errorf("manifest must not contain a 'case' field in schema 3.0.0; got:\n%s", b)
	}
	if strings.Contains(string(b), `"case_id"`) {
		t.Errorf("manifest must not contain a 'case_id' field; got:\n%s", b)
	}
}

// TestCaptureIdentity exercises the OS identity capture. We can only
// assert weak invariants because the OS user identity varies by
// environment, but a nil receiver / empty struct would be a regression.
func TestCaptureIdentity(t *testing.T) {
	id := CaptureIdentity()
	if id == nil {
		t.Fatal("CaptureIdentity returned nil")
	}
	if id.EffectiveUID < 0 {
		t.Errorf("effective_uid should be >= 0, got %d", id.EffectiveUID)
	}
	// LoginUID is -1 when /proc/self/loginuid is absent (macOS, no audit).
	// On Linux with audit it's a real uid (>= 0). Either is acceptable here.
	if id.LoginUID < -1 {
		t.Errorf("login_uid out of expected range: %d", id.LoginUID)
	}
}
