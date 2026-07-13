# Release Packaging and Operator Readiness — Results

## Executive Summary

Release packaging pass completed. All 7 workstreams addressed. Repository is **Release Candidate Ready** for supported profiles. The first release candidate tag should be `v1.1.0-rc.1`.

## Version/Tag Recommendation

- **Version**: `1.1.0` (Cargo.toml updated from 0.1.0)
- **First tag**: `v1.1.0-rc.1` (release candidate)
- **Stabilization**: Minimum 3 calendar days after RC tag
- **Release tag**: `v1.1.0` after stabilization gates pass
- **Tag format**: `vMAJOR.MINOR.PATCH` / `vMAJOR.MINOR.PATCH-rc.N`

## Documents Changed

| Document | Action | Summary |
|----------|--------|---------|
| `Cargo.toml` | Updated | Version 0.1.0 → 1.1.0; repository URL fixed |
| `CHANGELOG.md` | Updated | Links fixed (dbowm91/synvoid); validation summary and migration notes added |
| `README.md` | Updated | Git URL fixed; deployment recommendations added; ~30 broken doc links removed; first release note added |
| `SECURITY.md` | Updated | Feature name corrected (flood-ebpf); archive inspection limitation added; bincode/rsa descriptions corrected |
| `docs/FEATURE_STATUS.md` | Created | Supported/Beta/Experimental feature classifications with promotion criteria |
| `docs/RELEASE_CHECKLIST.md` | Created | Full release checklist template (pre-release, release, post-release) |

## Supported Profiles

| Profile | Command | Status |
|---------|---------|--------|
| Default | `cargo build --release` | Supported |
| Core | `cargo build --release --no-default-features` | Supported |
| Mesh | `cargo build --release --no-default-features --features mesh` | Supported |
| DNS | `cargo build --release --no-default-features --features dns` | Supported |
| Full | `cargo build --release --no-default-features --features mesh,dns` | Supported |

## Beta Features

| Feature | Flag | Platform | Known Gaps |
|---------|------|----------|------------|
| eBPF ICMP Filter | `flood-ebpf` | Linux only | Requires kernel BTF + root; falls back to nftables |
| Post-Quantum TLS | `post-quantum` | Any | Limited real-world validation |
| Post-Quantum Verify | `verify-pq` | Any | Limited real-world validation |

## Validation Commands

```bash
# Supported-profile gate (all must pass)
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
cargo audit
```

## CI Status

- **CI jobs**: 25 jobs in `.github/workflows/ci.yml`
- **CI visibility**: GitHub CI status not visible through current tooling (billing issue); local verification is authoritative
- **Release-critical jobs**: build (8-target matrix), fmt, clippy, dns-tests, honeypot-tests, tarpit-tests, mesh-tests, upload-tests, security-audit, dependency-audit, profile-matrix, guard-suite, fuzz-smoke

## Remaining Known Limitations

- `--all-features` workspace check fails on `synvoid-icmp-filter` eBPF dependency resolution (individual crate checks pass)
- wasmtime 40.0.4 (via yara-x) has known CVEs; mitigated by `[patch.crates-io]`, re-audit date 2026-10-01
- Email alerting is a stub (`src/admin/alerting/mod.rs:349`)
- `spin` idle instance eviction never cleans up old UUID entries
- DNS: DoQ is experimental; persistent TCP pipelining, EDNS keepalive, NSEC3 closest-encloser proofs, external DNSSEC tooling, bailiwick enforcement deferred
- bincode still present as direct dependency in 4 crates (migration partial)

## Final Classification

**Release Candidate Ready** — Supported profiles compile and pass tests locally. Documentation is updated. CHANGELOG exists with validation summary and migration notes. Beta features are explicitly classified with promotion criteria. Security posture is accurate and conservative. CI status visibility is limited but local verification is authoritative.
