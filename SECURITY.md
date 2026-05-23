# Security policy

## Reporting a vulnerability

**Do not file public GitHub issues for security problems.**

Email **info@i-wind.jp** with:

- A description of the issue and its impact.
- Steps to reproduce (commands, inputs, environment).
- The kernledger version (`kernledger --version`) and target distro.
- Whether the issue affects evidence integrity (manifest hashes, audit
  log, chain of custody) — this is the highest-priority class.

You should expect an initial acknowledgment within **5 business days**.
We coordinate disclosure timelines based on severity and affected
versions; the default window is 90 days from acknowledgment to public
disclosure, shortened if a patch is published earlier.

## Scope

In scope:

- Code in this repository (`cmd/`, `internal/`).
- The shipped distro adapters' command lists and artifact paths.
- Manifest schema correctness and the SHA-256 chain.
- The IMDSv2 client and the boundary it draws.

Out of scope:

- Vulnerabilities in LiME, Volatility 3, or other upstream tools that
  kernledger drives. Report those to their respective projects.
- The `cmd/ir-lab-target` fixture — it is a sandbox helper, not part
  of the IR action.
- Behavior on systems running as non-root with `--allow-non-root`. The
  documented evidence gaps are not bugs.

## What we treat as critical

- Anything that lets a tampered artifact pass `package`'s hash chain
  without being flagged.
- Anything that causes `acquire` to load a kernel module without
  `--execute`.
- Anything that silently exfiltrates collected evidence outside `--out`.
- IMDS calls made without `--include-ec2-metadata`.
