---
name: Bug report
about: Report a defect that affects evidence integrity, CLI behavior, or docs
title: ''
labels: bug
assignees: ''
---

## Summary

<!-- One-sentence description of the bug. -->

## Reproduction

```sh
# Exact commands. Include flags. Redact case ids.
```

## Expected behavior

<!-- What should have happened. -->

## Actual behavior

<!-- What did happen. Paste relevant log lines, the manifest excerpt,
     or the audit.log entry. -->

## Environment

- kernledger version (`kernledger --version`):
- Target distro (`/etc/os-release` `PRETTY_NAME`):
- Kernel (`uname -r`):
- Running as root? yes/no
- `--out` filesystem (ext4 on EBS? tmpfs? other?):

## Severity hint

- [ ] Affects evidence integrity (hash chain, manifest, audit log)
- [ ] Affects safety gate (acquire `--execute` semantics)
- [ ] CLI / UX only
- [ ] Documentation
