<!-- Thanks for the PR. Please complete the sections below. -->

## Summary

<!-- 1-3 sentences on what changes and why. The diff shows what; this
     box is for the why. -->

## Affected surface

- [ ] CLI flags / subcommands
- [ ] Manifest schema (requires schema version bump)
- [ ] Audit log format
- [ ] Distro adapter behavior
- [ ] Documentation only
- [ ] Internal refactor (no observable change)

## Test plan

<!-- Bullet list of how you verified this. CI runs build/vet/test; if
     the change touches IR semantics (acquire, package, manifest),
     describe any manual verification you did. -->

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `gofmt -l .` clean

## Risk

<!-- Anything a reviewer should look at twice? Evidence integrity?
     Hash chain? Exit code policy? Manifest backwards compatibility? -->

## Related issues

<!-- e.g. Fixes #123, Refs #456 -->
