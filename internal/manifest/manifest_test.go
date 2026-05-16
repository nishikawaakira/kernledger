package manifest

import (
	"path/filepath"
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
	m.Case = CaseInfo{CaseID: "C-1", Operator: "alice"}
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
	if got.Case.CaseID != "C-1" {
		t.Errorf("case = %+v", got.Case)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].SHA256 != "deadbeef" {
		t.Errorf("artifacts = %+v", got.Artifacts)
	}
	if got.Tool.Name != "al2-mem-ir" {
		t.Errorf("tool = %+v", got.Tool)
	}
}
