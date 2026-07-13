# Release Checklist

Use this checklist for every SynVoid release. Copy this template and fill in the values for your release.

## Release Information

- **Version**: `vX.Y.Z` or `vX.Y.Z-rc.N`
- **Date**: YYYY-MM-DD
- **Release Manager**: 
- **Commit SHA**: 

## Pre-Release Gates

All gates must pass before cutting the RC tag.

### Compilation Profiles

| Profile | Command | Status |
|---------|---------|--------|
| Default | `cargo build --release` | [ ] |
| Core | `cargo build --release --no-default-features` | [ ] |
| Mesh | `cargo build --release --no-default-features --features mesh` | [ ] |
| DNS | `cargo build --release --no-default-features --features dns` | [ ] |
| Full | `cargo build --release --no-default-features --features mesh,dns` | [ ] |

### Code Quality

| Check | Command | Status |
|-------|---------|--------|
| Formatting | `cargo fmt --all -- --check` | [ ] |
| Clippy | `cargo clippy --all-targets --all-features -- -D warnings` | [ ] |
| Documentation | `cargo doc --all-features -- -D warnings` | [ ] |

### Tests

| Check | Command | Status |
|-------|---------|--------|
| Full test suite | `cargo test --release --no-fail-fast` | [ ] |
| Security regression | `cargo test --test security_regression -- --test-threads=1` | [ ] |
| Guard suite | `cargo test --test guard_suite` | [ ] |
| Plugin guardrails | `cargo test -p synvoid-plugin-runtime` | [ ] |

### Security & Dependencies

| Check | Command | Status |
|-------|---------|--------|
| Dependency audit | `cargo deny check` | [ ] |
| Security audit | `cargo audit` | [ ] |

### CI Verification

| Job | Status | Notes |
|-----|--------|-------|
| build (8-target matrix) | [ ] | |
| clippy | [ ] | |
| fmt | [ ] | |
| dns-tests | [ ] | |
| honeypot-tests | [ ] | |
| tarpit-tests | [ ] | |
| mesh-tests | [ ] | |
| upload-tests | [ ] | |
| security-audit | [ ] | |
| dependency-audit | [ ] | |
| profile-matrix | [ ] | |
| guard-suite | [ ] | |
| plugin-runtime-guardrails | [ ] | |
| fuzz-smoke | [ ] | |
| platform-compat | [ ] | |

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

## Release

| Step | Status | Notes |
|------|--------|-------|
| RC tag created (`vX.Y.Z-rc.N`) | [ ] | |
| Stabilization period (min 3 days) | [ ] | |
| All gates re-pass after stabilization | [ ] | |
| Final CHANGELOG entry committed | [ ] | |
| Release tag created (`vX.Y.Z`) | [ ] | |
| Binaries built for supported platforms | [ ] | |
| Checksums generated (`SHA256SUMS.txt`) | [ ] | |
| GitHub Release published | [ ] | |
| Release notes announced | [ ] | |

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
- [ ] Release artifacts published
