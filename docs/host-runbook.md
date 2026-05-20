# Host-side runbook (cheat sheet)

## At a glance

- **What this doc covers**: the on-keyboard IR action on the target
  host — `inspect` → `collect` → `acquire` → `package`.
- **What it does NOT cover**: building LiME, provisioning EC2,
  generating Volatility 3 symbols, or running plugins. Those live
  elsewhere by design.
- **Have ready before opening this doc**: a LiME `.ko` matching the
  running kernel (`uname -r`) and the `al2-mem-ir` binary staged on
  the host. Full pre-flight checklist below.
- **First time end-to-end / verifying the whole pipeline**: use
  [`tryout-ec2.md`](tryout-ec2.md) — it covers prep, the IR action,
  and a full Volatility run.
- **Analyst-side workflow** (symbol generation + Volatility plugin
  runs): see [`usage.md`](usage.md) §§ 5 (symbols) and 6 (analyze).

---

## Which subcommand does what (and when to skip)

For operators who don't live in forensic work full-time. Read this
before deciding what to run.

### One-liner per subcommand

| Subcommand   | Role                                      | Always run? | Risk |
| ------------ | ----------------------------------------- | ----------- | ---- |
| `inspect`    | read-only health check on the target host | **yes**     | none |
| `collect`    | snapshot of volatile state (ps / ss / logs / authorized_keys) | usually yes | low  |
| `acquire`    | full RAM dump via LiME kernel module      | **only when needed** | **high visibility** |
| `package`    | bundle output dir into hashed tar.gz      | when handing off | none |

### Rules of thumb

- **`inspect` is free** — read-only, no kernel module, no writes.
  Run it first, no matter what. Use the output to decide whether the
  later steps will even work (e.g. Secure Boot enabled → `acquire`
  will fail; EDR present → SOC must be notified).

- **`collect` before `acquire`**. Volatile state (running processes,
  open sockets) changes by the second. Capture it BEFORE the slow
  memory dump. If you only need to know "what is running and where
  is it connecting", `collect` alone is often enough.

- **`acquire` is the loud step.** Loading the LiME kernel module is
  observable to:
    - GuardDuty Runtime Monitoring (a finding is likely)
    - auditd (logs `MODULE_LOAD`)
    - any installed EDR (CrowdStrike / SentinelOne / etc.)
    - the kernel itself (gets tainted)
  Default to **not** running it. Reach for `acquire` only when you
  have a reason to suspect memory-resident artifacts that `collect`
  alone won't reveal — fileless malware, process injection, kernel
  rootkits, or a formal evidence-preservation request from legal /
  the SOC. Always plan with `--dry-run` first; `--execute` is the
  explicit safety gate.

- **`package` only when you're handing off.** If you're investigating
  on the same host and won't ship the evidence anywhere, you can
  skip it — `--out` already has hashed manifests per step.

### Decision table

| Situation                                                  | inspect | collect | acquire | package |
| ---------------------------------------------------------- | :-----: | :-----: | :-----: | :-----: |
| "Something looks odd, I want to look around"               | ✓       |         |         |         |
| "Who's logged in, what's running, where is it talking to?" | ✓       | ✓       |         |         |
| "Ship the volatile evidence to the SOC / forensic team"    | ✓       | ✓       |         | ✓       |
| "Suspected memory-resident malware"                        | ✓       | ✓       | ✓       | ✓       |
| "Formal evidence preservation requested by legal"          | ✓       | ✓       | ✓       | ✓       |
| Secure Boot enabled + no signed LiME module                | ✓       | ✓       |  skip   | ✓       |

### Default flow when in doubt

```
inspect             # always
collect             # almost always
acquire --dry-run   # plan only
( notify SOC )      # human checkpoint
acquire --execute   # only with reason + approval
package             # only when shipping off
```

Most real-world runs end after `collect` + `package`. `acquire` is
the exception, not the rule.

---

Before you touch the keyboard:

- [ ] Authorization is in writing and you have the ticket id.
- [ ] SOC / on-call has been notified. Loading the LiME kernel module
      WILL be visible to GuardDuty Runtime Monitoring, auditd, and any
      EDR. See `forensic-considerations.md` § 1.
- [ ] `al2-mem-ir` binary is already staged on the host (e.g. `/tmp/al2-mem-ir`).
- [ ] A LiME `.ko` matching the **exact** running kernel is on the
      host (e.g. `/tmp/lime-$(uname -r).ko`).
- [ ] A separate writable filesystem is mounted (NOT the system disk).
      The examples below assume `/mnt/forensic`.
- [ ] You are running as `root` (or via `sudo`).

If any of these aren't true yet, see `tryout-ec2.md` for the
preparation steps (instance launch, LiME build, binary staging).

## Variables

Encode the ticket id in the `--out` directory and the `--tarball`
filename — those are the only places the case linkage appears. The
CLI has no `--case-id` / `--operator` / `--reason` / `--authority`
flags by design.

```sh
export CASE_ID=CASE-1234         # ticket id; used only to build path names below
export OUT=/mnt/forensic/$CASE_ID
export TOOL=/tmp/al2-mem-ir
export LIME_KO=/tmp/lime-$(uname -r).ko
```

Operator identity is captured automatically by the kernel
(`os.Geteuid()` + `/proc/self/loginuid`) into the manifest's
`identity` section. Approving authority and incident justification
stay in the ticket. See `forensic-considerations.md` § 5.

## 1. inspect (read-only, run first)

```sh
sudo $TOOL inspect --json --quiet > /mnt/forensic/inspect-$CASE_ID.json
sudo $TOOL inspect
```

Check:
- `secure boot:` must be `disabled` or `unknown` — otherwise unsigned
  LiME will be rejected.
- `kernel:` release matches the LiME `.ko` filename.
- `agents seen:` — note which monitoring is present, coordinate with SOC.

## 2. collect (volatile artifacts)

```sh
sudo $TOOL collect --out $OUT
```

Use `--include-env` only if you've decided that environment variables
(which may contain AWS keys / tokens) are in scope. Default off.

## 3. acquire — dry-run first (mandatory)

```sh
sudo $TOOL acquire \
  --out $OUT \
  --module $LIME_KO \
  --output memory.lime \
  --format lime \
  --dry-run

jq '.acquisition' $OUT/acquire-manifest.json
```

`dry_run: true` means `insmod` was not executed. Review the planned
command line before continuing.

## 4. acquire — the real run

```sh
sudo $TOOL acquire \
  --out $OUT \
  --module $LIME_KO \
  --output memory.lime \
  --format lime \
  --rmmod \
  --execute

sha256sum $OUT/memory.lime
jq '.acquisition.image_sha256, .acquisition.image_bytes' $OUT/acquire-manifest.json
```

The `sha256sum` output **must** match `image_sha256` in the manifest.
Image size will be approximately the instance's RAM.

If `insmod` fails, the tool captures `dmesg -T` to
`$OUT/dmesg-on-failure.log` automatically.

## 5. package — final bundle

```sh
sudo $TOOL package \
  --in $OUT \
  --tarball /mnt/forensic/$CASE_ID.tar.gz \
  --include-ec2-metadata
```

The command prints the SHA-256 of the tarball — **write it down** in
the ticket. It is the integrity anchor for the bundle as a whole.

If IMDS is disabled on this host, drop `--include-ec2-metadata` —
`manifest.cloud` will simply be absent from the JSON, and the AWS
context is recovered from the tarball filename / ticket instead.

## 6. Transfer the bundle off the host

The tool does not move evidence for you — your IR playbook decides
where it goes (S3 with KMS, signed URL, encrypted USB, etc.). Examples:

```sh
# S3 (preferred for AWS environments):
aws s3 cp /mnt/forensic/$CASE_ID.tar.gz \
  s3://your-evidence-bucket/$CASE_ID.tar.gz \
  --sse aws:kms --sse-kms-key-id <key-arn>

# Pull from the analyst workstation:
# (run on the analyst side)
scp ec2-user@<host>:/mnt/forensic/$CASE_ID.tar.gz ./
```

After transfer, on the analyst side, verify:

```sh
shasum -a 256 $CASE_ID.tar.gz   # compare against value printed by package
```

## Common failure modes

| Symptom                                          | What's wrong                          | Fix                                                       |
| ------------------------------------------------ | ------------------------------------- | --------------------------------------------------------- |
| `insmod: ERROR: ...: invalid module format`      | LiME built for a different kernel     | Rebuild LiME against the running kernel; reboot if needed |
| `insmod: Operation not permitted` while root     | Secure Boot / kernel-lockdown active  | Sign the module, or use a non-Secure-Boot AMI             |
| `image_bytes: 0` or very small                   | Output path is on tmpfs               | Re-run with `--out` pointing at an EBS-backed mount       |
| `collect: mandatory item failed`                 | Optional binary (e.g. `nft`) missing  | Acceptable — manifest records the gap                     |
| Hash differs across two acquire runs             | Expected — live memory mutates        | The hash is for transit integrity, not "same image twice" |

## What this runbook does NOT cover

- Building LiME on the host → see `tryout-ec2.md` Phase 2.
- Provisioning the EC2 instance, EBS volume, IAM → `tryout-ec2.md` Phase 1.
- Generating Volatility 3 symbols (`dwarf2json`) → analyst workstation
  responsibility; not part of the host action.
- Running Volatility plugins (`al2-mem-ir analyze`) → analyst
  workstation responsibility.

## Want the long form?

| Doc                              | When to read it                                                     |
| -------------------------------- | ------------------------------------------------------------------- |
| `usage.md`                       | Per-command flag reference, every option                            |
| `tryout-ec2.md`                  | First time using the tool end-to-end, including LiME build          |
| `forensic-considerations.md`     | Before defending the chain of custody to a reviewer                 |
