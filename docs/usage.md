# al2-mem-ir — operator runbook

Audience: incident responders who already have authorization to act on
the target host.

> **Trying the tool for the first time?** Read this file for the
> per-command reference, but follow [`tryout-ec2.md`](tryout-ec2.md) for
> a fully concrete EC2 + LiME + Volatility 3 walkthrough you can
> reproduce in ~30 minutes.

## Supported targets

The binary auto-detects the host from `/etc/os-release` and selects
the matching distro adapter. Shipped adapters:

| `--distro` value      | Target                                        |
| --------------------- | --------------------------------------------- |
| `amazonlinux2`        | Amazon Linux 2                                |
| `amazonlinux2023`     | Amazon Linux 2023                             |
| `ubuntu`              | Ubuntu LTS (any VERSION_ID — 20.04/22.04/24.04/…) |

If auto-detection misfires (chroot, container, stripped `/etc/os-release`),
pass `--distro <id>` explicitly to every subcommand.

Adapter-specific operational notes:

- **`ubuntu`**: log paths follow Debian conventions
  (`/var/log/auth.log` instead of `/var/log/secure`, `/var/log/syslog`
  instead of `/var/log/messages`, `/var/log/dpkg.log` + `/var/log/apt/*`).
  LiME build deps are named `linux-headers-$(uname -r)` and
  `linux-image-$(uname -r)-dbgsym` (the latter requires enabling
  ddebs.ubuntu.com). Secure Boot / kernel-lockdown are enabled by
  default on most Ubuntu cloud AMIs, which rejects unsigned LiME
  modules — `inspect` surfaces this as a warning.

## 0. Pre-flight checklist

- [ ] You have written approval to acquire memory and collect artifacts.
      The ticket id goes into `--case-id`; the approving authority and
      justification are recorded in the ticket itself, not in CLI
      flags — see § "Chain of custody fields" in forensic-considerations.md.
- [ ] The SOC has been notified that a LiME kernel module will be loaded
      on the target instance. Acquisition is **visible** to GuardDuty
      Runtime Monitoring, auditd, and any EDR.
- [ ] You have a pre-built LiME `.ko` matching the **exact** `uname -r`
      of the target kernel. Building LiME against a different kernel
      will fail with "version magic" errors.
- [ ] You have a destination filesystem with enough free space for the
      memory image plus collected artifacts. For EC2 instances this is
      usually a freshly attached EBS volume mounted read-write.
- [ ] You are NOT collecting onto the system disk if you can avoid it.

## 1. inspect

Read-only. Run first.

```sh
sudo ./al2-mem-ir inspect
```

Outputs both human and JSON. Key fields:

- `kernel.release`: must match the LiME module's version magic.
- `secure_boot`: if `enabled`, unsigned LiME modules will be rejected.
- `kernel_tainted`: non-zero means the kernel will not load standard
  modules in some cases; check `dmesg` for details.
- `detected_agents`: anything listed will likely log or alert on
  acquisition. Confirm SOC coordination before continuing.

JSON form is suitable for pipelining into ticketing systems:

```sh
sudo ./al2-mem-ir inspect --json --quiet > /mnt/forensic/inspect.json
```

## 2. collect (volatile artifacts)

```sh
sudo ./al2-mem-ir collect \
  --out /mnt/forensic/CASE-1234 \
  --case-id CASE-1234
```

Effects:

- Creates `/mnt/forensic/CASE-1234/collect/`.
- Runs `uname -a`, `ps auxwwf`, `ss -antp/-uanp`, `ip addr/route`,
  `iptables -L -n -v`, `nft list ruleset`, `systemctl list-units`, etc.
- Captures stdout/stderr/exit-code for each.
- Copies system logs, cron config, cloud-init logs, SSM/ECS logs, and
  `authorized_keys` files into `collect/files/`.
- Writes `collect-manifest.json` and appends to `audit.log`.

Opt-ins:

- `--include-env` — capture process environment. Off by default because
  AWS keys / tokens commonly live in `env`.
- `--allow-non-root` — disable the root precheck. Several artifacts
  will be empty or partial. Use only when explicitly required.

## 3. acquire (memory image)

The `--execute` flag is a deliberate safety gate. Without it, the tool
**plans** the acquisition (records the exact `insmod` command, hashes
the module, writes a manifest) but does not load the module.

Plan first:

```sh
sudo ./al2-mem-ir acquire \
  --out /mnt/forensic/CASE-1234 \
  --module /tmp/lime-$(uname -r).ko \
  --output memory.lime \
  --case-id CASE-1234 \
  --dry-run
```

Inspect the resulting `acquire-manifest.json`. When you are ready:

```sh
sudo ./al2-mem-ir acquire \
  --out /mnt/forensic/CASE-1234 \
  --module /tmp/lime-$(uname -r).ko \
  --output memory.lime \
  --format lime \
  --rmmod \
  --case-id CASE-1234 \
  --execute
```

Notes:

- The output path is relative to `--out` unless absolute. Avoid writing
  to the system disk (`/var`, `/tmp`).
- `--mode tcp --tcp :4444` streams the image to a listening collector
  on another machine. The collector side is out of scope of this MVP;
  the operator typically uses `nc -l 4444 > image.lime`.
- If `insmod` fails, the tool captures `dmesg -T` next to the image as
  `dmesg-on-failure.log` to aid diagnosis.

## 4. package

After both `collect` and `acquire` are done, bundle:

```sh
sudo ./al2-mem-ir package \
  --in /mnt/forensic/CASE-1234 \
  --tarball /mnt/forensic/CASE-1234.tar.gz \
  --case-id CASE-1234 \
  --include-ec2-metadata
```

Output:

- A `tar.gz` containing every file in `--in`, prefixed with
  `<case-id>-<timestampZ>/`.
- A consolidated `manifest.json` inside the tarball that:
  - lists every file in the bundle with SHA-256 and size,
  - embeds the acquire and collect manifests,
  - records cloud metadata (when `--include-ec2-metadata` is set,
    or via the explicit overrides described below).
- The SHA-256 of the tarball, printed to stdout. Record this in the
  ticket; it is the integrity anchor for the bundle as a whole.

`manifest.json` itself is intentionally **not** listed in
`manifest.artifacts` — a file cannot record its own hash. The full set
of rules is in `docs/forensic-considerations.md` § "Self-reference rule".

### Cloud metadata: overrides vs IMDS

Order of precedence (highest first):

1. Explicit flags: `--instance-id`, `--region`, `--account-id`.
2. IMDSv2 lookup (only if `--include-ec2-metadata` is set).
3. Field is left empty.

Use the explicit flags when:

- IMDS is disabled on the instance.
- `package` is being run on a separate forensic workstation rather than
  on the target host.
- You want to pin values from your runbook regardless of what the host
  reports back.

Examples:

```sh
# Just the operator-supplied values; no network access to 169.254.169.254.
sudo ./al2-mem-ir package --in ... --tarball ... \
  --instance-id i-0abc --region ap-northeast-1 --account-id 123456789012

# Operator provides instance-id, IMDS fills the rest.
sudo ./al2-mem-ir package --in ... --tarball ... \
  --include-ec2-metadata --instance-id i-0abc
```

Transfer the tarball off the host using whatever your IR playbook
specifies (S3 with KMS, signed URL, encrypted USB, etc.).

## 5. symbols (analyst workstation)

```sh
al2-mem-ir symbols \
  --dwarf2json /opt/dwarf2json/dwarf2json \
  --vmlinux ./vmlinux-5.10.220-209.869.amzn2.x86_64 \
  --kernel  5.10.220-209.869.amzn2.x86_64 \
  --out ./symbols/linux
```

Drop the resulting JSON into a Volatility 3 symbols directory:

```
symbols/
└── linux/
    └── 5.10.220-209.869.amzn2.x86_64.json
```

## 6. analyze (analyst workstation)

```sh
al2-mem-ir analyze \
  --vol /opt/volatility3/vol.py \
  --image  ./memory.lime \
  --symbols ./symbols \
  --format text \
  --case-id CASE-1234 \
  --out ./analysis
```

Runs the MVP plugin set: `linux.pslist`, `linux.pstree`, `linux.sockstat`,
`linux.bash`, `linux.envars`, `linux.lsof`, `linux.proc.Maps`,
`linux.check_creds`. Two files land in `--out`:

- `analyze-manifest.json` — for each plugin: exact command, args,
  output path, format, exit code, start/end timestamps, duration, and
  any error string. Plus the vol.py path, image path, symbols path,
  and case fields. This is the reproducibility anchor.
- `report.md` — a short Markdown summary suitable for ticket attachment.
  Plugins that failed are explicitly marked `FAILED` in the status
  column.

### Failure model and exit codes

Forensic analysis prefers "partial results preserved and auditable"
over "all-or-nothing success". The CLI applies the following rules:

| Outcome                                       | manifest | CLI exit |
| --------------------------------------------- | -------- | -------- |
| Every plugin succeeded                        | written  | `0`      |
| At least one plugin failed (partial failure)  | written  | `1`      |
| Setup failed (`--vol`, image, symbols missing)| not written (no Analysis was produced) | `1` |

A plugin is "failed" when its `ExitCode != 0` **or** its `Err` field is
non-empty. The library-level `analyze.Run()` deliberately does **not**
return an error for plugin-level failures — it records them on the
returned `Analysis` and continues with the remaining plugins. Setup
failures (input validation, output directory creation) are the only
case where `Run()` returns an error.

Why a non-zero CLI exit on partial failure? Because automation
(runbooks, CI, sentinel scripts) needs a fast signal that something
needs human attention. The manifest remains the source of truth for
the IR review itself.

This policy is locked by unit tests:

- `TestAnalyzeCmd_PartialFailure_PolicyLockdown`
- `TestAnalyzeCmd_AllSuccess_PolicyLockdown`
- `TestAnalyzeCmd_SetupFailure_NoManifest`

## Failure modes

| Symptom                                  | What happened                                       | What to do                                              |
| ---------------------------------------- | --------------------------------------------------- | ------------------------------------------------------- |
| `insmod: ERROR: ... invalid module format` | LiME built against a different kernel              | Rebuild LiME against the exact running kernel.          |
| `insmod: Operation not permitted` while root | Secure Boot / lockdown                            | Sign the module or boot a non-Secure-Boot AMI.          |
| Image size = 0                           | LiME wrote to a path the operator did not realize was tmpfs | Use an EBS-backed `--out`.                       |
| Hash differs across two acquisitions     | Expected: live memory mutates                       | Hash is for integrity from acquire→analyst, not "same image again". |
