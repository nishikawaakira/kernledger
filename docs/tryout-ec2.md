# End-to-end tryout — EC2 + LiME + Volatility 3

A copy-paste walkthrough that takes you from an empty AWS account to a
real Volatility 3 plugin run against an actual memory image captured
by `al2-mem-ir`. Designed to be repeatable in under an hour.

> **Already familiar with the tool?** Skip this guide and use
> [`host-runbook.md`](host-runbook.md) — the host-side commands only,
> no AWS setup, no LiME build, no analyst workstation. ~100 lines.

> **Scope reminder.** This guide is for **sandbox / personal testing
> only**. Do NOT run any of these steps against a production EC2
> instance you don't own. Memory acquisition is observable to GuardDuty
> Runtime Monitoring, auditd, and any EDR; you will trigger alerts.
> See `forensic-considerations.md` § 1 ("This tool is not stealth").

## What you'll build

```
   ┌──────────────────────────────┐         ┌───────────────────────────┐
   │  EC2 (Amazon Linux 2)        │         │  Mac (analyst workstation)│
   │  ─────────────────           │  scp    │  ──────────────────       │
   │  1. al2-mem-ir collect       │ ──────► │  6. al2-mem-ir analyze    │
   │  2. al2-mem-ir acquire       │         │     (Volatility 3 plugins) │
   │     → memory.lime            │         │                           │
   │  3. dwarf2json               │         │                           │
   │     → kernel.json (symbols)  │         │                           │
   │  4. al2-mem-ir package       │         │                           │
   │     → tarball.tar.gz         │         │                           │
   └──────────────────────────────┘         └───────────────────────────┘
```

Phases 1–5 happen on EC2. Phase 6 happens on the Mac.

## Cost & time

- One `t3.medium` instance, ~30 minutes: about **USD $0.02**.
- EBS gp3 root volume (8 GB) plus forensic volume (8 GB): about **USD $0.01** for the hour.
- Spot pricing makes it even cheaper if your account allows it.

Total expected spend: **< USD $0.10** if you tear down promptly.

## Prerequisites

On your Mac:

- Go 1.22+ (for building `al2-mem-ir` and `dwarf2json`)
- Python 3.10+ (for Volatility 3)
- `awscli` v2 configured with credentials for a test account
- An SSH key pair already imported into the test region

On AWS:

- A VPC + public subnet (the default VPC works)
- A security group that allows your IP for SSH (port 22)
- IAM permissions: `ec2:RunInstances`, `ec2:CreateVolume`,
  `ec2:AttachVolume`, `ec2:DescribeInstances`, `ec2:TerminateInstances`

If you'd rather use SSM Session Manager instead of SSH, attach an
instance profile with `AmazonSSMManagedInstanceCore`. The commands
below assume SSH.

## Variables used throughout

```sh
# Choose YOUR test region. Tokyo is the example.
export AWS_REGION=ap-northeast-1
export AWS_DEFAULT_REGION=$AWS_REGION

# Use whatever key you already have.
export KEY_NAME=my-test-key
export KEY_FILE=~/.ssh/my-test-key.pem

# A case id you'll thread through every command.
export CASE_ID=TRYOUT-$(date -u +%Y%m%dT%H%M%SZ)
echo "Case: $CASE_ID"
```

---

## Phase 1 — Launch the EC2 instance

### 1.1 Find the latest AL2 AMI

```sh
AMI_ID=$(aws ssm get-parameters \
  --names /aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2 \
  --query 'Parameters[0].Value' --output text)
echo "AMI: $AMI_ID"
```

> **AL2023 variant**: replace the parameter name with
> `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64`.

### 1.2 Pick a default subnet and security group

```sh
SUBNET_ID=$(aws ec2 describe-subnets \
  --filters Name=default-for-az,Values=true \
  --query 'Subnets[0].SubnetId' --output text)
VPC_ID=$(aws ec2 describe-subnets --subnet-ids $SUBNET_ID \
  --query 'Subnets[0].VpcId' --output text)

# Reuse default SG if you have one, or create a temporary SG.
SG_ID=$(aws ec2 create-security-group \
  --group-name al2-mem-ir-tryout-$RANDOM \
  --description "al2-mem-ir tryout (auto-deleted)" \
  --vpc-id $VPC_ID --query GroupId --output text)
MY_IP=$(curl -s https://checkip.amazonaws.com)/32
aws ec2 authorize-security-group-ingress --group-id $SG_ID \
  --protocol tcp --port 22 --cidr $MY_IP
echo "SG: $SG_ID  open to $MY_IP"
```

### 1.3 Launch the instance

```sh
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.medium \
  --key-name $KEY_NAME \
  --subnet-id $SUBNET_ID \
  --security-group-ids $SG_ID \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=al2-mem-ir-tryout},{Key=Purpose,Value=ir-tool-tryout}]" \
  --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-running --instance-ids $INSTANCE_ID
HOST=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PublicDnsName' --output text)
echo "Instance: $INSTANCE_ID  ssh: ec2-user@$HOST"
```

### 1.4 Attach a separate forensic EBS volume

Writing evidence to the system disk perturbs the very state you're
acquiring. Always use a dedicated volume.

```sh
AZ=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)

VOL_ID=$(aws ec2 create-volume \
  --availability-zone $AZ \
  --size 8 --volume-type gp3 \
  --tag-specifications \
    "ResourceType=volume,Tags=[{Key=Name,Value=al2-mem-ir-forensic}]" \
  --query VolumeId --output text)
aws ec2 wait volume-available --volume-ids $VOL_ID
aws ec2 attach-volume --volume-id $VOL_ID --instance-id $INSTANCE_ID --device /dev/sdf
```

Wait ~10 seconds for the kernel to enumerate the device, then SSH in:

```sh
ssh -i $KEY_FILE -o StrictHostKeyChecking=accept-new ec2-user@$HOST
```

Once you're on the instance, format and mount the forensic volume:

```sh
# Identify the device. AL2 typically maps /dev/sdf → /dev/nvme1n1 on Nitro instances.
lsblk
DEV=$(lsblk -nrpo NAME,MOUNTPOINT | awk '$2==""{print $1; exit}')
echo "Forensic device: $DEV"

sudo mkfs.ext4 -L forensic $DEV
sudo mkdir -p /mnt/forensic
sudo mount $DEV /mnt/forensic
sudo chown ec2-user:ec2-user /mnt/forensic
```

---

## Phase 2 — Build LiME on the target

LiME must be compiled against the EXACT running kernel. Mismatched
version magic will cause `insmod` to refuse the module with no useful
error in `dmesg`.

```sh
# On the EC2 instance:
sudo yum install -y kernel-devel-$(uname -r) gcc make git

# Sanity: -devel must match running kernel.
ls /lib/modules/$(uname -r)/build || {
  echo "kernel-devel mismatch — try: sudo yum update kernel && sudo reboot"
  exit 1
}

cd /tmp
git clone --depth 1 https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make

# Result: a .ko named after the running kernel.
LIME_KO=$(ls /tmp/LiME/src/lime-*.ko)
echo "LiME module: $LIME_KO"
sha256sum "$LIME_KO"
```

If `make` fails complaining about `KDIR`, set it explicitly:

```sh
make KDIR=/lib/modules/$(uname -r)/build
```

> **AL2023 variant**: replace `yum` with `dnf`. Everything else is the same.

---

## Phase 3 — Stage the al2-mem-ir binary

On your Mac, in the project root:

```sh
make build       # → dist/al2-mem-ir-linux-amd64
scp -i $KEY_FILE dist/al2-mem-ir-linux-amd64 ec2-user@$HOST:/tmp/al2-mem-ir
```

On the instance:

```sh
chmod +x /tmp/al2-mem-ir
/tmp/al2-mem-ir --version
```

---

## Phase 4 — Generate some "interesting" volatile state (optional)

So `linux.pslist` and `linux.bash` give you something to look at later.

In a second SSH session to the instance:

```sh
# Long-running marker process visible to ps.
( exec -a tryout-marker sleep 1800 ) &

# Make linux.bash plugin show meaningful history.
bash -i << 'EOF'
echo "hello-from-tryout" > /tmp/marker.txt
cat /tmp/marker.txt
ls -la /tmp/marker.txt
EOF
```

Leave this session open so the marker process stays alive during
acquisition.

---

## Phase 5 — Run the IR workflow

Back in the first SSH session. Note `--allow-non-root` is **not** used
— we want the real root privilege checks to apply.

### 5.1 inspect (read-only, run first)

```sh
sudo /tmp/al2-mem-ir inspect --json --quiet > /mnt/forensic/inspect.json
sudo /tmp/al2-mem-ir inspect | head -30
```

Confirm:
- `adapter:` reads `amazonlinux2` (or `amazonlinux2023`).
- `secure boot:` is `disabled` or `unknown (no EFI vars)`. If it's
  `enabled`, your LiME `.ko` will be rejected and acquisition will fail
  — sign the module or boot a non-Secure-Boot AMI.

### 5.2 collect (volatile artifacts)

```sh
sudo /tmp/al2-mem-ir collect --out /mnt/forensic/$CASE_ID
```

Spot-check the result:

```sh
ls /mnt/forensic/$CASE_ID/collect/
grep tryout-marker /mnt/forensic/$CASE_ID/collect/ps.out
```

You should see the `tryout-marker` process you started in Phase 4.

### 5.3 acquire — dry-run first

The `--execute` gate is intentional. Plan once with `--dry-run`,
inspect the resulting manifest, then run for real.

```sh
sudo /tmp/al2-mem-ir acquire \
  --out /mnt/forensic/$CASE_ID \
  --module "$LIME_KO" \
  --output memory.lime \
  --format lime \
  --dry-run

cat /mnt/forensic/$CASE_ID/acquire-manifest.json | jq '.acquisition'
```

You'll see `"dry_run": true` and a `notes` field reminding you that
`insmod` was not executed.

### 5.4 acquire — the real run

```sh
sudo /tmp/al2-mem-ir acquire \
  --out /mnt/forensic/$CASE_ID \
  --module "$LIME_KO" \
  --output memory.lime \
  --format lime \
  --rmmod \
  --execute

ls -la /mnt/forensic/$CASE_ID/memory.lime
sha256sum /mnt/forensic/$CASE_ID/memory.lime
cat /mnt/forensic/$CASE_ID/acquire-manifest.json | jq '.acquisition.image_sha256, .acquisition.image_bytes'
```

Expected image size: roughly the same as the instance's RAM
(t3.medium ≈ 4 GiB). The hash in the manifest must match `sha256sum`'s
output above.

### 5.5 Generate Volatility 3 symbols on the target

Doing this on the host avoids shipping the kernel-debuginfo RPM
(hundreds of MB) to your Mac. We can ship the resulting JSON instead
(~tens of MB).

```sh
# Install the kernel debuginfo matching the running kernel.
sudo yum install -y --enablerepo='*debug*' \
  kernel-debuginfo-$(uname -r) || \
  sudo debuginfo-install -y kernel-$(uname -r)

# Install Go and dwarf2json.
sudo yum install -y golang
export GOPATH=/tmp/go
mkdir -p $GOPATH
go install github.com/volatilityfoundation/dwarf2json@latest

VMLINUX=/usr/lib/debug/lib/modules/$(uname -r)/vmlinux
ls -la $VMLINUX

mkdir -p /mnt/forensic/$CASE_ID/symbols/linux
$GOPATH/bin/dwarf2json linux --elf $VMLINUX \
  > /mnt/forensic/$CASE_ID/symbols/linux/$(uname -r).json
ls -la /mnt/forensic/$CASE_ID/symbols/linux/
```

> **AL2023 note**: the debuginfo packages live in the same repo
> mechanism. Replace `yum` with `dnf` and the rest works.

### 5.6 package — the final bundle

```sh
sudo /tmp/al2-mem-ir package \
  --in /mnt/forensic/$CASE_ID \
  --tarball /mnt/forensic/$CASE_ID.tar.gz \
  --include-ec2-metadata

ls -la /mnt/forensic/$CASE_ID.tar.gz
```

The command prints the SHA-256 of the tarball — **write it down** in
your notes. It's the integrity anchor for the bundle.

---

## Phase 6 — Transfer evidence to your Mac

From your Mac:

```sh
mkdir -p ./tryout-evidence
scp -i $KEY_FILE ec2-user@$HOST:/mnt/forensic/$CASE_ID.tar.gz ./tryout-evidence/
shasum -a 256 ./tryout-evidence/$CASE_ID.tar.gz
# Compare against the SHA-256 printed at the end of Phase 5.6.

cd ./tryout-evidence
tar -xzf $CASE_ID.tar.gz
cd ${CASE_ID}-*
ls
```

You should see:
- `manifest.json` (consolidated)
- `acquire-manifest.json`
- `collect-manifest.json`
- `audit.log`
- `collect/` (commands + copied files)
- `memory.lime`
- `symbols/linux/<kernel-release>.json`

### Integrity spot-check

```sh
# Recompute SHA-256 of the memory image and compare against the manifest.
echo "manifest says:"
jq -r '.acquisition.image_sha256' manifest.json
echo "actual:"
shasum -a 256 memory.lime | awk '{print $1}'
```

They must match.

---

## Phase 7 — Install Volatility 3 on the Mac

If you don't already have it:

```sh
# In a virtualenv to keep system Python clean.
python3 -m venv ~/venv-vol3
source ~/venv-vol3/bin/activate
pip install --upgrade pip
pip install volatility3

# Sanity: vol --help should list Linux plugins.
vol --help | grep linux | head
```

---

## Phase 8 — Run al2-mem-ir analyze

Volatility 3 expects symbols at a particular path. The symbol JSON
we generated already lives under `symbols/linux/<release>.json`, which
is the layout Volatility looks for.

```sh
# Still inside ${CASE_ID}-*/  on your Mac.
../../dist/al2-mem-ir analyze \
  --vol $(which vol) \
  --image $(pwd)/memory.lime \
  --symbols $(pwd)/symbols \
  --format text \
  --out ./analysis-$CASE_ID
```

> If you used the macOS arm64 build of al2-mem-ir, adjust the path. The
> `dist/al2-mem-ir` produced by `make build-host` is the right one.

Read the report:

```sh
cat ./analysis/report.md
```

You should see two columns:
- All MVP plugins listed (`linux.pslist`, `linux.pstree`,
  `linux.sockstat`, `linux.bash`, `linux.envars`, `linux.lsof`,
  `linux.proc.Maps`, `linux.check_creds`).
- Most should be `ok`. Some may show `FAILED` if the plugin happens
  to be incompatible with this kernel release — that's the partial-
  failure policy in action.

Look for the marker we planted in Phase 4:

```sh
grep tryout-marker ./analysis/linux_pslist.text
grep hello-from-tryout ./analysis/linux_bash.text
```

If you see both, the workflow round-tripped successfully.

The CLI's exit code is `0` if every plugin succeeded and `1` if any
plugin failed. Either way, `./analysis/analyze-manifest.json` contains
the complete record.

---

## Phase 9 — Cleanup (don't skip)

On AWS:

```sh
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
aws ec2 wait instance-terminated --instance-ids $INSTANCE_ID
# After termination, the attached EBS volume detaches automatically.
aws ec2 delete-volume --volume-id $VOL_ID
aws ec2 delete-security-group --group-id $SG_ID
```

On your Mac:

```sh
# Keep the evidence if you want to re-analyze later, otherwise:
rm -rf ./tryout-evidence
```

---

## Known pitfalls

| Symptom                                                | Fix                                                                 |
| ------------------------------------------------------ | ------------------------------------------------------------------- |
| `insmod: ERROR: ...: invalid module format`            | LiME built against the wrong kernel. Rerun Phase 2 after updating kernel and rebooting. |
| `insmod: Operation not permitted` while root           | Secure Boot / kernel-lockdown is rejecting unsigned module. Use a non-Secure-Boot AMI for the tryout. |
| `kernel-devel-X.Y.Z.amzn2.x86_64` not found            | `sudo yum update kernel && sudo reboot`, then rerun Phase 2.        |
| `dwarf2json` reports "no DWARF section"                | `kernel-debuginfo` not installed or installed for the wrong release. |
| Volatility plugin runs but produces empty output       | Symbol/kernel mismatch — confirm the JSON filename equals `uname -r`. |
| `image_sha256` differs between two acquisitions        | Expected. Live memory mutates; the hash is for transit integrity, not "same image twice". |

## Honest expectations

- Some Volatility 3 plugins **will fail** on AL2 / AL2023 kernels even
  with correct symbols. Plugin compatibility lags kernel changes. The
  partial-failure manifest is precisely so you can see what worked.
- `linux.bash` only finds bash command history that was still in
  memory at acquisition time. If you didn't run any `bash -i`
  commands, expect this plugin to return nothing useful.
- The tryout binary is amd64-only. If your test AMI is an arm64
  Graviton instance, run `make build GOARCH=arm64` on your Mac first.

## What this tryout has demonstrated

- The full chain of custody: hashes recorded at acquire time, embedded
  in the manifest, verified on the analyst workstation.
- The plugin-style distro adapter (AL2 vs AL2023 routes to different
  log paths automatically).
- The safety gate on `acquire` (dry-run vs `--execute`).
- The IMDSv2 path through `package --include-ec2-metadata`.
- The partial-failure policy on `analyze` (manifest is the truth, exit
  code is the alert signal).

If anything in this guide didn't match your output, that's a doc bug
— please report it.
