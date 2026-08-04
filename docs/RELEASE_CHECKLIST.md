# Release Checklist

Use this checklist for every SynVoid release. Copy this template and fill in the values for your release.

## Release Information

- **Version**: `vX.Y.Z` or `vX.Y.Z-rc.N`
- **Date**: YYYY-MM-DD
- **Release Manager**: 
- **Commit SHA**: 

## Pre-Release Gates

All gates must pass before cutting the RC tag.

### Verification

| Check | Command | Status |
|-------|---------|--------|
| Routine verification | `cargo xtask verify` | [ ] |
| Full local verification | `cargo xtask verify-full` | [ ] |
| Release verification | `cargo xtask verify-release` | [ ] |

Note: `verify-release` fails on dirty working trees by default. Ensure the tree is clean before running.

### Security & Dependencies

| Check | Command | Status |
|-------|---------|--------|
| Dependency audit | `cargo deny check` | [ ] |
| Security audit | `cargo audit` | [ ] |

## Documentation

| Check | Status | Notes |
|-------|--------|-------|
| CHANGELOG.md updated | [ ] | |
| Known limitations documented | [ ] | |
| Beta features listed | [ ] | |
| Migration notes included | [ ] | |
| SECURITY.md reflects release posture | [ ] | |
| README.md updated | [ ] | |
| FEATURE_STATUS.md updated | [ ] | |

## Publication

| Step | Status | Notes |
|------|--------|-------|
| RC tag created (`vX.Y.Z-rc.N`) | [ ] | |
| Stabilization period (min 3 days) | [ ] | |
| All gates re-pass after stabilization | [ ] | |
| Final CHANGELOG entry committed | [ ] | |
| Working tree is clean | [ ] | Dirty trees block `verify-release` |
| Internal deps use compatible semver (not `*`) | [ ] | |
| `cargo xtask verify-release` passes | [ ] | |
| All crates published to crates.io in dependency order | [ ] | |
| Crates.io availability verified for each published crate | [ ] | |
| Release tag created (`vX.Y.Z`) — after publication | [ ] | |
| Tag pushed to origin | [ ] | |
| GitHub Release created manually (optional) | [ ] | |
| Release notes announced | [ ] | |

### Publication Order

Publish crates in this exact order (see `docs/releasing.md` for the full table):

```bash
cargo publish -p pqc
cargo publish -p synvoid-utils
cargo publish -p synvoid-platform
cargo publish -p synvoid-core
# ... (see docs/releasing.md for the complete list)
cargo publish -p synvoid
```

After each crate, verify it resolves from crates.io before publishing dependents.

## Post-Release

| Step | Status | Notes |
|------|--------|-------|
| Operator channels notified | [ ] | |
| Monitoring dashboards updated | [ ] | |
| Hotfix branch created if needed | [ ] | |

## Known Limitations for This Release

Document any known limitations specific to this release:

- 
- 
- 

## Beta Features in This Release

List Beta features included:

| Feature | Status | Known Gaps |
|---------|--------|------------|
| | | |

## Sign-off

- [ ] Release Manager approval
- [ ] All pre-release gates pass
- [ ] Documentation complete
- [ ] All crates published to crates.io
- [ ] Release tag created and pushed
