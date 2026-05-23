package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nishikawaakira/kernledger/internal/audit"
	"github.com/nishikawaakira/kernledger/internal/distro"
	"github.com/nishikawaakira/kernledger/internal/executor"
)

type inspectCmd struct {
	version string
	commit  string
	cf      commonFlags

	jsonOnly  bool
	humanOnly bool
}

func newInspectCmd(version, commit string) *inspectCmd {
	return &inspectCmd{version: version, commit: commit}
}

func (c *inspectCmd) Name() string     { return "inspect" }
func (c *inspectCmd) Synopsis() string { return "inspect the target host (read-only)" }

func (c *inspectCmd) SetFlags(fs *flag.FlagSet) {
	c.cf.bind(fs)
	fs.BoolVar(&c.jsonOnly, "json", false, "emit JSON only")
	fs.BoolVar(&c.humanOnly, "human", false, "emit human-readable only")
}

// InspectReport is the JSON payload for `kernledger inspect`.
type InspectReport struct {
	SchemaVersion string            `json:"schema_version"`
	Timestamp     time.Time         `json:"timestamp"`
	Adapter       string            `json:"distro_adapter"`
	AdapterLabel  string            `json:"distro_adapter_label"`
	OS            distro.OSInfo     `json:"os"`
	Kernel        distro.KernelInfo `json:"kernel"`
	SecureBoot    string            `json:"secure_boot"`
	Tainted       string            `json:"kernel_tainted"`
	KernelModules struct {
		ModulesPath string `json:"modules_path"`
		Exists      bool   `json:"exists"`
	} `json:"kernel_modules"`
	DetectedAgents []string         `json:"detected_agents"`
	LimeHints      distro.LimeHints `json:"lime_hints"`
	Warnings       []string         `json:"warnings"`
}

func (c *inspectCmd) Run(ctx context.Context, _ []string) error {
	outDir, err := c.cf.resolveOutDir(false)
	if err != nil {
		return err
	}
	log, err := c.cf.openAudit(outDir)
	if err != nil {
		return err
	}
	defer log.Close()

	adapter, osInfo, err := c.cf.resolveDistro()
	if err != nil {
		// inspect should still print *some* output rather than nothing.
		log.Warn("inspect.distro", err.Error(), nil)
	}

	exec := executor.NewReal(5 * time.Second)
	if c.cf.DryRun {
		log.Info("inspect.dry-run", "dry-run: external commands skipped", nil)
	}

	rpt := InspectReport{
		SchemaVersion: "1.0.0",
		Timestamp:     time.Now().UTC(),
		OS:            osInfo,
	}
	if adapter != nil {
		rpt.Adapter = adapter.ID()
		rpt.AdapterLabel = adapter.Describe()
	}

	rpt.Kernel = readKernelInfo(ctx, exec, c.cf.DryRun, log)
	rpt.SecureBoot = readSecureBoot()
	rpt.Tainted = readFile("/proc/sys/kernel/tainted")
	rpt.KernelModules.ModulesPath = filepath.Join("/lib/modules", rpt.Kernel.Release)
	if _, err := os.Stat(rpt.KernelModules.ModulesPath); err == nil {
		rpt.KernelModules.Exists = true
	}
	rpt.DetectedAgents = detectAgents()

	if adapter != nil {
		rpt.LimeHints = adapter.LimeHints(rpt.Kernel)
	}

	rpt.Warnings = inspectWarnings(&rpt)

	if !c.jsonOnly {
		printInspectHuman(os.Stdout, &rpt)
	}
	if !c.humanOnly {
		if !c.jsonOnly {
			fmt.Fprintln(os.Stdout)
			fmt.Fprintln(os.Stdout, "---- JSON ----")
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(&rpt); err != nil {
			return err
		}
	}
	log.Info("inspect.done", "inspect complete", map[string]interface{}{
		"adapter": rpt.Adapter,
		"kernel":  rpt.Kernel.Release,
	})
	return nil
}

func readKernelInfo(ctx context.Context, exec executor.Executor, dry bool, log *audit.Logger) distro.KernelInfo {
	ki := distro.KernelInfo{
		Architecture: runtime.GOARCH,
	}
	// /proc/version + /proc/sys/kernel/tainted are fast read-only reads;
	// prefer those over forking uname when possible.
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		ki.Release = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/version"); err == nil {
		ki.Version = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/tainted"); err == nil {
		ki.Tainted = strings.TrimSpace(string(b))
	}
	// Fallback to `uname -r` if /proc was not available (rare).
	if ki.Release == "" && !dry {
		if r, err := exec.Run(ctx, "uname", "-r"); err == nil {
			ki.Release = strings.TrimSpace(string(r.Stdout))
		} else {
			log.Warn("inspect.uname", err.Error(), nil)
		}
	}
	return ki
}

func readSecureBoot() string {
	// Best effort: look for the EFI variable. Absent → "unknown".
	candidates, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	if len(candidates) == 0 {
		return "unknown (no EFI vars)"
	}
	b, err := os.ReadFile(candidates[0])
	if err != nil || len(b) < 5 {
		return "unknown"
	}
	// Layout: 4 bytes of attributes, then the value.
	if b[4] == 1 {
		return "enabled"
	}
	return "disabled"
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// detectAgents looks for filesystem footprints that strongly suggest a
// monitoring/EDR product is installed. We do NOT attempt to bypass any
// of them; we surface the information so the operator can coordinate
// with the SOC.
func detectAgents() []string {
	checks := []struct {
		name string
		path string
	}{
		{"auditd", "/etc/audit/auditd.conf"},
		{"auditd-rules", "/etc/audit/rules.d"},
		{"ssm-agent", "/usr/bin/amazon-ssm-agent"},
		{"ssm-agent-snap", "/snap/amazon-ssm-agent"},
		{"ecs-agent", "/var/lib/ecs"},
		{"cloudwatch-agent", "/opt/aws/amazon-cloudwatch-agent"},
		// GuardDuty Runtime Monitoring runs a managed agent on AL2 hosts.
		{"guardduty-agent", "/opt/aws/guardduty-agent"},
		{"crowdstrike-falcon", "/opt/CrowdStrike"},
		{"sentinelone", "/opt/sentinelone"},
		{"carbonblack", "/opt/carbonblack"},
		{"wazuh-agent", "/var/ossec"},
		{"osquery", "/etc/osquery"},
	}
	var found []string
	for _, c := range checks {
		if _, err := os.Stat(c.path); err == nil {
			found = append(found, c.name)
		}
	}
	return found
}

func inspectWarnings(r *InspectReport) []string {
	var w []string
	if r.Adapter == "" {
		w = append(w, "no distro adapter matched; collection will fall back to generic defaults (none implemented in MVP)")
	} else if r.Adapter != "amazonlinux2" {
		w = append(w, fmt.Sprintf("active adapter is %q; this MVP is validated only on amazonlinux2", r.Adapter))
	}
	if r.Tainted != "" && r.Tainted != "0" {
		w = append(w, "kernel is tainted (/proc/sys/kernel/tainted="+r.Tainted+"); LiME module load may further taint the kernel")
	}
	if r.SecureBoot == "enabled" {
		w = append(w, "Secure Boot is enabled; unsigned LiME .ko will be rejected by the kernel")
	}
	if len(r.DetectedAgents) > 0 {
		w = append(w, "monitoring agents present: "+strings.Join(r.DetectedAgents, ", ")+
			" — insmod will likely be observed. Coordinate with the SOC before acquire.")
	}
	return w
}

func printInspectHuman(w *os.File, r *InspectReport) {
	fmt.Fprintln(w, "== kernledger inspect ==")
	fmt.Fprintf(w, "  timestamp:     %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "  os:            %s (id=%s version=%s)\n", r.OS.PrettyName, r.OS.ID, r.OS.VersionID)
	fmt.Fprintf(w, "  adapter:       %s (%s)\n", r.AdapterLabel, r.Adapter)
	fmt.Fprintf(w, "  kernel:        %s\n", r.Kernel.Release)
	fmt.Fprintf(w, "  kernel ver:    %s\n", r.Kernel.Version)
	fmt.Fprintf(w, "  arch:          %s\n", r.Kernel.Architecture)
	fmt.Fprintf(w, "  tainted:       %q\n", r.Tainted)
	fmt.Fprintf(w, "  secure boot:   %s\n", r.SecureBoot)
	fmt.Fprintf(w, "  modules dir:   %s (exists=%v)\n", r.KernelModules.ModulesPath, r.KernelModules.Exists)
	fmt.Fprintf(w, "  agents seen:   %s\n", strOrNone(r.DetectedAgents))
	if r.LimeHints.KernelDevelPackage != "" {
		fmt.Fprintf(w, "  expected -devel pkg: %s\n", r.LimeHints.KernelDevelPackage)
		fmt.Fprintf(w, "  expected -debuginfo: %s\n", r.LimeHints.DebuginfoPackage)
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "  warnings:")
		for _, ww := range r.Warnings {
			fmt.Fprintf(w, "    - %s\n", ww)
		}
	}
}

func strOrNone(s []string) string {
	if len(s) == 0 {
		return "(none detected)"
	}
	return strings.Join(s, ", ")
}
