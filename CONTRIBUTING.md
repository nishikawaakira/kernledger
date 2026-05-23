# Contributing to kernledger

Thanks for your interest. kernledger is an incident-response tool; we
optimize for **auditability, predictability, and small surface area**
over feature breadth.

## What we accept

- **Bug fixes**, especially anything that affects manifest integrity,
  hash chains, or the audit log.
- **New distro adapters** (`internal/distro/<name>/`). Follow the
  pattern in `internal/distro/ubuntu/`. No `if/switch` in the
  dispatcher.
- **Documentation improvements**, particularly clarifications to the
  forensic-considerations rationale.
- **Test coverage** for existing untested paths.

## What we don't accept

- Stealth features (hiding module load, suppressing kernel logs,
  unhooking audit). See README § "What this tool is NOT".
- Free-text identity flags (`--operator`, `--reason`, `--case-id`,
  cloud overrides). These were intentionally removed; see
  `docs/forensic-considerations.md` § 5.
- Vendored dependencies. kernledger is intentionally stdlib-only.

## Development workflow

```sh
make build-host      # native binary at dist/kernledger
make test            # go test ./...
make vet             # go vet ./...
make fmt             # gofmt -s -w .
```

All three must pass before opening a PR. CI runs the same commands.

## Commit style

- Short, imperative subject line (under 70 chars).
- Body explains **why**, not what — the diff shows what.
- Reference the affected component (`acquire:`, `docs:`, `distro/ubuntu:`)
  when it helps reviewers triage.
- One logical change per commit; do not bundle a refactor with a bug
  fix.

## Pull requests

- Open against `main`.
- Include a short description of the motivation and any operational
  impact (does this change manifest schema? CLI surface? exit codes?).
- Schema-affecting changes must bump the manifest schema version and
  add a regression test that pins the new shape.

## Security

Do not file security issues as public GitHub issues. See `SECURITY.md`.
