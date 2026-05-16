package acquire

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "lime-test.ko")
	if err := os.WriteFile(p, []byte("not-a-real-module"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOptionsValidate_RequiresModule(t *testing.T) {
	o := Options{OutputMode: "file", OutputPath: "/tmp/x"}
	if err := o.Validate(); err == nil {
		t.Fatal("expected error when module missing")
	}
}

func TestOptionsValidate_ModuleMustEndKo(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "lime.bin")
	_ = os.WriteFile(bad, []byte("x"), 0o600)
	o := Options{ModulePath: bad, OutputMode: "file", OutputPath: "/tmp/x"}
	if err := o.Validate(); err == nil {
		t.Fatal("expected error for non-.ko module path")
	}
}

func TestOptionsValidate_FileMode(t *testing.T) {
	mp := writeTempModule(t)
	o := Options{ModulePath: mp, OutputMode: "file"}
	if err := o.Validate(); err == nil {
		t.Fatal("expected error when --output missing in file mode")
	}
}

func TestOptionsValidate_TCPMode(t *testing.T) {
	mp := writeTempModule(t)
	o := Options{ModulePath: mp, OutputMode: "tcp"}
	if err := o.Validate(); err == nil {
		t.Fatal("expected error when --tcp missing in tcp mode")
	}
	o.TCPListen = ":4444"
	if err := o.Validate(); err != nil {
		t.Fatalf("expected ok in tcp mode, got %v", err)
	}
}

func TestBuildPlan_File(t *testing.T) {
	mp := writeTempModule(t)
	o := Options{ModulePath: mp, OutputMode: "file", OutputPath: "/mnt/x.lime"}
	p := o.BuildPlan()
	if p.InsmodCmd[0] != "insmod" || p.InsmodCmd[1] != mp {
		t.Errorf("insmod cmd = %v", p.InsmodCmd)
	}
	// path= and format= must both appear in args.
	found := map[string]bool{}
	for _, a := range p.InsmodCmd[2:] {
		if a == "path=/mnt/x.lime" {
			found["path"] = true
		}
		if a == "format=lime" {
			found["format"] = true
		}
	}
	if !found["path"] || !found["format"] {
		t.Errorf("missing args: %v", p.InsmodCmd)
	}
	// Module name dash→underscore.
	if p.RmmodCmd[1] != "lime_test" {
		t.Errorf("rmmod module name = %s", p.RmmodCmd[1])
	}
}

func TestBuildPlan_TCP(t *testing.T) {
	mp := writeTempModule(t)
	o := Options{ModulePath: mp, OutputMode: "tcp", TCPListen: ":4444"}
	p := o.BuildPlan()
	has := false
	for _, a := range p.InsmodCmd {
		if a == "path=tcp:4444" {
			has = true
			break
		}
	}
	if !has {
		t.Errorf("expected tcp arg, got %v", p.InsmodCmd)
	}
}
