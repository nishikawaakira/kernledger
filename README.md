# al2-mem-ir

`al2-mem-ir` is a Go CLI that **orchestrates** memory acquisition and
volatile-artifact collection on Amazon Linux 2 for incident response.

It does **not** implement memory dumping itself — it drives the existing
[LiME](https://github.com/504ensicsLabs/LiME) kernel module — and it does
not analyze memory on the target host. Analysis happens on a separate
workstation with [Volatility 3](https://github.com/volatilityfoundation/volatility3).

> **MVP scope**: `inspect`, `collect`, `package`, and `acquire --dry-run`
> are functional. `acquire --execute`, `symbols`, and `analyze` have
> working implementations but are exercised only as plumbing in this MVP.
> Distro adapters: `amazonlinux2` is the primary target; `amazonlinux2023`
> and `ubuntu` ship as additional adapters proving the plugin pattern
> works across both RHEL-family and Debian-family hosts.

## What this tool is NOT

- It is **not** an EDR-bypass or anti-detection tool.
- It does **not** rename LiME, hide module loads, suppress kernel logs,
  unhook audit, or otherwise obscure the IR action from monitoring
  systems. Loading the LiME `.ko` will be visible to:
  - the kernel (`printk` / `dmesg`)
  - auditd (if enabled and configured to log module loads)
  - GuardDuty Runtime Monitoring
  - any installed EDR product
- It is **not** a substitute for SOC coordination, ticketing, or formal
  chain-of-custody procedures. It produces inputs for those processes.

If your engagement requires covert acquisition, talk to your IR vendor;
this tool is not the right choice and we will not add stealth features.

## What this tool IS

A small, auditable, dependency-free CLI that makes it easier to:

1. Verify the target host before touching it (`inspect`).
2. Capture volatile artifacts (`collect`).
3. Load a pre-built LiME module to dump RAM (`acquire`).
4. Bundle everything into a single hashed tarball with a manifest
   (`package`).
5. On a separate workstation, build Volatility 3 symbols and drive
   plugin runs (`symbols`, `analyze`).

Every external command is mediated by an executor abstraction with audit
logging. Every artifact in the final tarball is SHA-256 hashed and
referenced from a single JSON manifest.

## Safety model

| Concern                              | How al2-mem-ir handles it                                                          |
| ------------------------------------ | ---------------------------------------------------------------------------------- |
| Kernel module load                   | Requires explicit `--execute`. Without it, `acquire` only records the plan.        |
| Destructive operations               | None. The tool never removes data or modifies system state besides `insmod`.       |
| Writes to the target host            | Restricted to `--out`. Operator chooses (e.g. a mounted forensic volume).          |
| Root requirement                     | Enforced. Override only with `--allow-non-root` (creates evidence gaps).           |
| Audit trail                          | Every external command + outcome → NDJSON `audit.log` inside `--out`.              |
| Chain of custody                     | OS identity (uid + `/proc/self/loginuid`) auto-captured. Case linkage is expressed by the operator-chosen `--out` / `--tarball` filenames. |
| Cloud metadata access                | Off by default. Requires `--include-ec2-metadata`. Always IMDSv2.                  |
| Environment variables in collection  | Off by default (`--include-env` to opt in; may contain secrets).                   |
| EDR / GuardDuty visibility           | Surfaced in `inspect` as a warning; never circumvented.                            |

## Quick start

```sh
# Build for the target host (Amazon Linux 2 / amd64 by default).
make build
# → ./dist/al2-mem-ir-linux-amd64

# On the target host:
sudo ./al2-mem-ir inspect

# Volatile collection. Encode the case id in the directory name —
# that's the only operator-supplied case linkage.
sudo ./al2-mem-ir collect --out /mnt/forensic/CASE-1234

# Plan memory acquisition (no insmod yet):
sudo ./al2-mem-ir acquire \
  --out /mnt/forensic/CASE-1234 \
  --module /tmp/lime-$(uname -r).ko \
  --output memory.lime \
  --dry-run

# Actually run insmod (requires --execute on top of everything above):
sudo ./al2-mem-ir acquire \
  --out /mnt/forensic/CASE-1234 \
  --module /tmp/lime-$(uname -r).ko \
  --output memory.lime \
  --rmmod \
  --execute

# Bundle everything. The tarball name carries the case id forward.
sudo ./al2-mem-ir package \
  --in /mnt/forensic/CASE-1234 \
  --tarball /mnt/forensic/CASE-1234.tar.gz \
  --include-ec2-metadata

# Or pin cloud metadata fields explicitly (useful when IMDS is
# disabled, or when packaging on a separate forensic workstation):
sudo ./al2-mem-ir package \
  --in /mnt/forensic/CASE-1234 \
  --tarball /mnt/forensic/CASE-1234.tar.gz \
  --instance-id i-0abcdef1234567890 \
  --region ap-northeast-1 \
  --account-id 123456789012
```

There is **no `--case-id` / `--operator` / `--reason` / `--authority`
flag**. Case linkage is whatever filename / directory name the
operator chooses for `--out` and `--tarball`. Operator identity is
auto-captured from the kernel (`os.Geteuid()` + `/proc/self/loginuid`)
into the manifest's `identity` section — see
`forensic-considerations.md` § 5.

`package` prints the SHA-256 of the produced tarball; record it in your
ticket. The in-memory manifest is byte-identical to the `manifest.json`
embedded in the tarball (see `docs/forensic-considerations.md` §
"Self-reference rule").

On the **analyst** workstation (not the target):

```sh
al2-mem-ir symbols \
  --dwarf2json /opt/dwarf2json/dwarf2json \
  --vmlinux ./vmlinux-5.10.220-209.869.amzn2.x86_64 \
  --kernel  5.10.220-209.869.amzn2.x86_64 \
  --out ./symbols/linux

al2-mem-ir analyze \
  --vol /opt/volatility3/vol.py \
  --image  ./memory.lime \
  --symbols ./symbols \
  --format text \
  --out ./analysis
```

`analyze` writes `<out>/analyze-manifest.json` recording the vol path,
image path, symbols path, every plugin's exact command/args, exit code,
start/end timestamps, duration and output path. The plugin Markdown
summary still lands at `<out>/report.md`.

### `analyze` failure model and exit codes

The CLI prefers "partial results preserved and auditable" over
"all-or-nothing success":

| Outcome                                    | manifest | exit code |
| ------------------------------------------ | -------- | --------- |
| All plugins succeeded                      | written  | 0         |
| One or more plugins failed (partial)       | written  | 1         |
| Setup failed (`--vol` missing, image missing, ...) | not written | 1 |

A plugin is counted as failed when its `ExitCode != 0` **or** the
plugin recorded an `Err` string. Both conditions are inspected so a
crashing vol binary and a clean non-zero exit are treated the same way.

Even when the CLI exits 1 due to partial failure, the manifest contains
results for **every** requested plugin (successful and failed). That
record is the source of truth for the IR review — the non-zero exit
exists solely so automation notices.

## Project layout

```
cmd/al2-mem-ir/             # entrypoint; blank-imports distro adapters
internal/
  cli/                      # subcommands
  executor/                 # shell command abstraction (real + dry-run)
  manifest/                 # JSON manifest schema (v1.0.0)
  hashutil/                 # SHA-256 helpers
  audit/                    # NDJSON audit logger
  collector/                # `collect` engine
  acquire/                  # `acquire` engine (LiME orchestration)
  pkgbuild/                 # tar.gz bundling
  symbols/                  # `symbols` engine (dwarf2json wrapper)
  analyze/                  # `analyze` engine (Volatility 3 wrapper)
  ec2/                      # IMDSv2 client
  distro/
    distro.go               # Adapter interface + registry
    osrelease.go            # /etc/os-release parser
    amazonlinux2/           # AL2 adapter (MVP target)
    amazonlinux2023/        # AL2023 adapter
    ubuntu/                 # Ubuntu LTS adapter (any VERSION_ID)
    registrytest/           # cross-adapter disambiguation tests
docs/
  usage.md
  forensic-considerations.md
examples/manifest.json
Makefile
```

## Distro abstraction

`internal/distro` defines a plugin-style `Adapter` interface. Each
distribution lives in its own subpackage and self-registers via `init()`.
The CLI selects an adapter by parsing `/etc/os-release` or by an
explicit `--distro` flag.

```go
type Adapter interface {
    ID() string
    Describe() string
    Detect(OSInfo) bool
    Paths() ArtifactPaths
    ServiceQueries() []ServiceQuery
    LimeHints(KernelInfo) LimeHints
    CloudProviders() []CloudProvider
}
```

To add support for a new distro:

1. Create `internal/distro/<name>/<name>.go`.
2. Implement `Adapter`.
3. Add `_ "github.com/example/al2-mem-ir/internal/distro/<name>"` to
   `cmd/al2-mem-ir/main.go`.

No `if/switch` ladders anywhere in the CLI.

Adapter status:

- `amazonlinux2` — **shipped** (MVP target)
- `amazonlinux2023` — **shipped**. Detection disambiguates AL2 vs
  AL2023 by `VERSION_ID` without any if/switch in the dispatcher.
- `ubuntu` — **shipped**. Matches every Ubuntu LTS by `ID=ubuntu`
  regardless of `VERSION_ID` (20.04 / 22.04 / 24.04 / future). First
  Debian-family adapter — exercises `LimeHints` with `linux-headers-*`
  and `linux-image-*-dbgsym` naming.
- `debian` — planned (will inherit most of `ubuntu`'s paths)
- `rhel` — planned
- `rocky` / `almalinux` — planned (likely sharing a RHEL-family helper)
- `amazonlinux1` — best-effort; EOL

When a third RHEL-family adapter lands (RHEL 9, Rocky, AlmaLinux), the
truly-common defaults will be lifted into an `internal/distro/rhelfamily/`
helper. Same plan applies to Debian-family (`internal/distro/debianfamily/`)
once Debian lands. Until then adapters intentionally duplicate ~70% of
their declarations rather than choosing the wrong abstraction.

## Documentation

- [`docs/host-runbook.md`](docs/host-runbook.md) — **cheat sheet for
  the IR action itself.** Host-side commands only, ~100 lines.
  Assumes LiME `.ko` and the binary are already staged. This is what
  you keep open in another tab when you're on the keyboard.
- [`docs/usage.md`](docs/usage.md) — per-command flag reference, every
  option, all failure modes.
- [`docs/forensic-considerations.md`](docs/forensic-considerations.md) — what
  this tool means for evidence quality, EDR visibility, and SOC workflow.
  Read before defending the chain of custody to a reviewer.
- [`docs/lab-target.md`](docs/lab-target.md) — tiny helper process for
  validating `collect` against live processes, child processes, and
  open TCP/UDP sockets.
- [`docs/tryout-ec2.md`](docs/tryout-ec2.md) — **first time using the
  tool end-to-end?** Copy-paste walkthrough that covers the prep
  (launching an EC2 instance, building LiME, staging the binary), the
  IR action itself, and a full Volatility 3 plugin run from a Mac.
  ~30 minutes, ~USD $0.10. Treats analyst-side setup as in scope.

## License

Specify a license before publishing. This MVP repository intentionally
omits a `LICENSE` file so the operator can pick (Apache-2.0 / MIT / etc.)
in line with their organization's policy.
