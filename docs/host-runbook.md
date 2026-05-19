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

Thread the same case id through every command so the manifests link up.

```sh
export CASE_ID=CASE-1234         # ticket id — the only operator-supplied chain-of-custody field
export OUT=/mnt/forensic/$CASE_ID
export TOOL=/tmp/al2-mem-ir
export LIME_KO=/tmp/lime-$(uname -r).ko
```

Operator identity is not entered as a flag — the manifest records the
effective uid and `/proc/self/loginuid` automatically. Approving
authority and incident justification stay in the ticket (`$CASE_ID`),
not in CLI flags. See `forensic-considerations.md` § 5.

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
sudo $TOOL collect \
  --out  $OUT \
  --case-id $CASE_ID
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
  --case-id $CASE_ID \
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
  --case-id $CASE_ID \
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
  --case-id $CASE_ID \
  --include-ec2-metadata
```

The command prints the SHA-256 of the tarball — **write it down** in
the ticket. It is the integrity anchor for the bundle as a whole.

Cloud metadata overrides (use when IMDS is disabled or you want to pin
runbook values regardless of host state):

```sh
sudo $TOOL package --in $OUT --tarball /mnt/forensic/$CASE_ID.tar.gz \
  --case-id $CASE_ID \
  --instance-id i-0abcdef1234567890 \
  --region ap-northeast-1 \
  --account-id 123456789012
```

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
