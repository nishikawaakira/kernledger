# Forensic considerations

This document captures the design decisions and operational constraints
that govern `al2-mem-ir`. Read it before using the tool in a real
engagement.

## 1. This tool is not stealth

`al2-mem-ir` is an **orchestration** layer over LiME. It loads the LiME
kernel module the same way an operator would by hand: `insmod
/path/to/lime-<release>.ko path=... format=lime`. The module name is
not changed. We do not unlink the `.ko` after loading, we do not strip
or mangle module metadata, and we do not suppress `printk`. As a
result:

- Every `insmod` is recorded in `/proc/modules` and visible to `lsmod`.
- The kernel emits `printk` lines that hit `dmesg`, the kernel ring
  buffer, and (when configured) `journald`.
- If `auditd` is configured with `MODULE_LOAD` or `init_module` rules,
  every load is in the audit trail.
- GuardDuty Runtime Monitoring observes kernel-module load events on
  Amazon Linux 2. Your IR action will appear in the GuardDuty console
  shortly after `--execute` completes.
- Any EDR product (CrowdStrike, SentinelOne, Carbon Black, etc.) sees
  the load through its kernel sensor or runtime probe.

This is the correct behavior for a legitimate IR tool. It is also why
**SOC coordination is a prerequisite, not a courtesy**.

## 2. Race condition with the attacker

The user requirement reads:

> 攻撃者に調査行為を察知される前に volatile evidence を取得する

The intent is to minimize the window between operator intent and actual
acquisition, not to hide acquisition from monitoring systems. We
support this by:

- Producing a small static binary (single `go build`, no runtime deps)
  that can be staged before the operation begins.
- Letting the operator dry-run `acquire` to validate the module path,
  output path, and command line **without** alerting anything.
- Performing all writes inside `--out`, which the operator typically
  points at a separate volume that the suspected attacker cannot easily
  observe (e.g. a freshly attached EBS volume).
- Avoiding any prompt-style interactivity: a single `--execute`
  invocation flips from "planned" to "executed" with no further input.

What we do **not** do is hide the acquisition from the kernel, from
auditd, or from EDR. Operators who need that level of stealth must use
hardware-level acquisition (cold boot, hypervisor introspection) which
is out of scope for an Amazon Linux 2 EC2 instance running this tool.

## 3. Volatility ordering

Per RFC 3227, volatile data has shorter half-lives than disk data. The
practical implication for this tool:

1. Run `inspect` first. It is read-only and does not perturb state.
2. Run `collect` before `acquire`. Acquiring memory takes minutes;
   process tables, sockets, and `dmesg` can shift in that interval.
3. Run `acquire` last for the on-host phase.
4. Run `package` to bundle. Avoid hashing or compressing the image
   separately in between.

Each step writes its own manifest. `package` consolidates them so the
final tarball is self-describing without consulting earlier files.

## 4. Evidence integrity

- Every regular file in the final tarball — except `manifest.json`
  itself — has a SHA-256 in `manifest.json` (artifact list).
- The LiME `.ko` is hashed before load. This lets reviewers confirm
  later that the operator did not substitute a tampered module.
- The memory image is hashed after the `insmod` returns. Note that the
  image hash is **not** a hash "of the system memory" — live memory
  mutates during the dump, so two acquisitions on the same running
  system will produce different hashes. The hash proves that nothing
  modified the image between `acquire` and the analyst workstation.
- The audit log (`audit.log`) is a JSON-Lines stream of every external
  command, decision, and warning. It is appended-only and ends up
  inside the tarball.
- The SHA-256 of the produced `.tar.gz` is printed by `package` to
  stdout and written to the audit log. Record it in the ticket.

### Self-reference rule

`manifest.json` deliberately does **not** list itself in
`manifest.artifacts`. A file cannot record its own SHA-256 — writing the
hash mutates the file. To verify a bundle without trusting the manifest
on its own:

1. Recompute the SHA-256 of each file in the bundle.
2. Compare against `manifest.artifacts[].sha256`.
3. Cross-check `manifest.acquisition` and `manifest.collection` against
   the standalone `acquire-manifest.json` and `collect-manifest.json`
   that `package` carries forward into the bundle. These two files are
   produced earlier by `acquire` and `collect` respectively and are
   themselves hashed in the artifact list.
4. Compare the tarball's SHA-256 against the value recorded in your
   ticket / audit log.

After `package` returns, the bytes of `manifest.json` on disk are
byte-identical to the bytes embedded in the tarball, and to the
in-memory representation used to print the result. This is enforced by
unit tests (`TestBuild_ManifestInTarballMatchesReturned`).

## 5. Chain of custody fields

The manifest splits "who / why" data into two layers, by design.

### Layer 1: case linkage (operator-supplied, single field)

| Field      | Purpose                                                              |
| ---------- | -------------------------------------------------------------------- |
| `case_id`  | External ticket id (Linear / Jira / SecHub finding / TheHive case). |

That is the **only** operator-typed chain-of-custody field. The
acquisition is anchored to a ticket; the ticket is anchored to a
person, an approval, and a justification — by the ticketing system,
not by free-text CLI flags.

### Layer 2: process identity (auto-captured, kernel-attested)

| Field                          | Source                              |
| ------------------------------ | ----------------------------------- |
| `identity.effective_uid`       | `os.Geteuid()`                      |
| `identity.effective_username`  | `/etc/passwd` lookup of EUID         |
| `identity.login_uid`           | `/proc/self/loginuid` (Linux audit) |
| `identity.login_username`      | `/etc/passwd` lookup of LoginUID    |

`login_uid` is the load-bearing field: Linux's audit subsystem sets it
to the uid of the user who initiated the session, and **the kernel
preserves it across sudo/su**. So even a tool run via `sudo` records
the real human user, not just `0`. `login_uid = -1` (or the sentinel
`4294967295`) means the kernel has no session record — typical on
macOS, on containers without audit support, or for boot-time invocations.

### Why we dropped `--operator`, `--reason`, `--authority`

Earlier MVPs accepted those as free-text CLI flags. We removed them
because:

1. **No real IR tool we surveyed has them** — LiME, AVML, fmem,
   Volatility, The Sleuth Kit, GRR, and Velociraptor either capture
   no identity or capture an authenticated server-side identity.
2. **Free text is forgeable.** `--operator alice` is just a string;
   the running uid is not.
3. **Case-management systems already record this stuff** at a layer
   the IR tool has no business duplicating.
4. **One linkage is harder to drift than four.** `case_id` is the
   single source of truth; everything else lives in the ticket.

If you previously consumed `manifest.case.operator` /
`manifest.case.reason` / `manifest.case.authority`, switch to
`manifest.identity.*` for who, and to the ticket pointed at by
`manifest.case.case_id` for why.

## 6. Cloud metadata

`package` populates `manifest.cloud` from two possible sources, in this
order of precedence:

1. **Explicit operator overrides** via flags:
   - `--instance-id`
   - `--region`
   - `--account-id`

   These always win. Use them when IMDS is disabled on the target,
   when `package` is being run on a workstation rather than the target
   itself, or when you need to pin runbook values regardless of host
   state.

2. **IMDSv2**, only when `--include-ec2-metadata` is set. The lookup is
   routed through the active distro adapter's `CloudProviders()`, so
   non-AWS distros can substitute their own provider (or none) without
   changes to `package`. The current AL2 adapter exposes an IMDSv2-only
   client; the IMDSv1 fallback is not implemented.

When `--include-ec2-metadata` is NOT set, `al2-mem-ir` makes no
HTTP call to `169.254.169.254`. This is verified by unit tests
(`TestBuild_CloudOverridesWinOverIMDS`).

Fields collected from IMDS when enabled:

- instance-id
- instance-type
- placement/region
- placement/availability-zone
- ami-id
- accountId (extracted from the instance-identity document)

Why this is opt-in:

- The HTTP call to `169.254.169.254` is observable in network
  monitoring; some shops want to track IR tooling that talks to IMDS.
- The instance-identity document is signed by AWS and useful for legal
  attestation. If you collect it, treat it as evidence.

## 7. What writes happen on the target

When the tool runs on the target host, the only writes are:

- Files inside `--out` (the operator's chosen directory).
- The kernel side effect of loading the LiME module (which writes to
  the LiME-managed file or TCP stream, **not** to the file system on
  the operator's behalf).

We do not touch:

- `/etc/`
- `/root/`
- The user's home directory
- systemd unit files
- `crontab`
- Any package manager state

## 8. Known limitations of this MVP

- Three distro adapters shipped: Amazon Linux 2, Amazon Linux 2023,
  and Ubuntu LTS. RHEL / Rocky / AlmaLinux / Debian need separate
  adapters; the plugin interface is in place but no implementations
  ship yet.
- No automatic LiME or symbol download. Operators must stage these
  themselves; this is intentional (supply-chain control).
- No automatic uploader. Transfer of the final tarball off the host is
  left to your IR playbook (S3 + KMS, signed URL, encrypted USB).
- No tamper-evident sealing of the tarball beyond per-file SHA-256.
  Consider co-signing with `cosign` or an offline GPG key for
  high-stakes engagements.
- No eBPF-based collection. Out of scope by design.

## 9. Safe defaults summary

| Behavior                                       | Default        |
| ---------------------------------------------- | -------------- |
| Kernel module load (`acquire`)                 | not executed   |
| Environment variables in `collect`             | not collected  |
| EC2 IMDSv2 in `package`                        | not fetched    |
| Non-root execution                             | refused        |
| Writes outside `--out`                         | never          |
| Network egress                                 | none (except opt-in IMDSv2) |
