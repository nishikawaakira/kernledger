# Changelog

All notable changes to this project are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Project renamed from `al2-mem-ir` to `kernledger`. Module path is now
  `github.com/nishikawaakira/kernledger`. The CLI now reports
  `kernledger` in `--version`, banner, manifest `tool.name`, and the
  `analyze` report heading.

### Added
- Apache-2.0 LICENSE.
- Contributor Covenant v2.1 CODE_OF_CONDUCT.md.
- CONTRIBUTING.md, SECURITY.md, this CHANGELOG, plus GitHub Actions CI
  workflow and issue/PR templates.

## [0.3.0] — pre-publication MVP

### Changed
- Documented when to run each subcommand and when to `collect` twice
  (host-runbook).

### Removed
- `--instance-id` / `--region` / `--account-id` overrides on
  `package`. Cloud metadata comes from IMDSv2 only; absent when IMDS
  is disabled.

## [0.2.0] — pre-publication MVP

### Removed
- `--case-id` flag and `manifest.case` entirely (schema 3.0.0).
  Case linkage is now expressed only by the operator-chosen `--out`
  and `--tarball` paths.

## [0.1.0] — pre-publication MVP

### Removed
- `--operator`, `--reason`, `--authority` flags (schema 2.0.0).
  Operator identity is auto-captured from the kernel
  (`os.Geteuid()` + `/proc/self/loginuid`).

### Added
- Operational documentation: `docs/host-runbook.md` and
  `docs/tryout-ec2.md`.
- Ubuntu LTS distro adapter (any `VERSION_ID`).
- Amazon Linux 2023 distro adapter.
- Initial release: Amazon Linux 2 memory IR orchestration via LiME,
  Volatility 3 driver, hash-chained manifest, NDJSON audit log.
