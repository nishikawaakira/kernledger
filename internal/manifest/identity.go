package manifest

import (
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Identity records WHO the kernel says is running the tool, not who
// the operator claims to be. Two sources of truth, both auto-captured:
//
//	EffectiveUID / EffectiveUsername:
//	  What os.Geteuid() returns. For a tool invoked via sudo this is
//	  typically 0 / root, which by itself tells the reviewer nothing
//	  interesting — but a non-root EUID is a real signal (the run
//	  happened without privilege escalation, so root-only artifacts
//	  are intentionally absent).
//
//	LoginUID / LoginUsername:
//	  What /proc/self/loginuid says. Linux's auditd subsystem sets
//	  loginuid to the uid of the user that initiated the login session,
//	  and the kernel preserves it across sudo/su. This is the closest
//	  thing to an "audit identity" the OS provides and it is exactly
//	  what we want for chain of custody. LoginUID == -1 means the
//	  kernel has no recorded login (boot-time invocation, container
//	  without audit support, non-Linux host).
//
// Neither field is operator-controlled at the CLI layer — both come
// from the kernel's view of the process. They CAN be tampered with by
// a privileged attacker (write to /proc/self/loginuid requires
// CAP_AUDIT_CONTROL), but that level of compromise is well beyond
// what a free-text --operator flag was defending against in the first
// place.
type Identity struct {
	EffectiveUID      int    `json:"effective_uid"`
	EffectiveUsername string `json:"effective_username,omitempty"`
	// LoginUID = -1 when /proc/self/loginuid is absent or unset.
	LoginUID      int    `json:"login_uid"`
	LoginUsername string `json:"login_username,omitempty"`
}

// CaptureIdentity reads the running process identity. It never returns
// an error — every field is best-effort and the zero values are
// meaningful (-1 for LoginUID means "unknown").
func CaptureIdentity() *Identity {
	id := &Identity{
		EffectiveUID: os.Geteuid(),
		LoginUID:     -1,
	}
	if u, err := user.LookupId(strconv.Itoa(id.EffectiveUID)); err == nil {
		id.EffectiveUsername = u.Username
	}
	// /proc/self/loginuid is Linux-specific. On macOS / containers
	// without audit support this returns nothing, and LoginUID stays -1.
	if b, err := os.ReadFile("/proc/self/loginuid"); err == nil {
		s := strings.TrimSpace(string(b))
		if n, err := strconv.Atoi(s); err == nil {
			id.LoginUID = n
			// loginuid of 4294967295 (uint32 -1) means "unset" in audit's
			// own convention; treat it as unknown.
			if n == -1 || n == 0xFFFFFFFF {
				id.LoginUID = -1
			} else if u, err := user.LookupId(s); err == nil {
				id.LoginUsername = u.Username
			}
		}
	}
	return id
}
