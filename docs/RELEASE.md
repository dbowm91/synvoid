# Release Process

This document defines the release lifecycle, versioning policy, build profiles, and operator-facing procedures for SynVoid releases.

## 1. Version Numbering Policy

SynVoid follows [Semantic Versioning](https://semver.org/) (SemVer): `MAJOR.MINOR.PATCH`.

| Component | Bump When | Examples |
|-----------|-----------|----------|
| **MAJOR** | Breaking changes to the public API, config format, wire protocol, or plugin ABI | `1.0.0` to `2.0.0` |
| **MINOR** | New functionality added in a backward-compatible manner | `1.0.0` to `1.1.0` |
| **PATCH** | Backward-compatible bug fixes, security patches, documentation corrections | `1.0.0` to `1.0.1` |

### Pre-release identifiers

Pre-release versions use a hyphen suffix:

| Identifier | Meaning |
|------------|---------|
| `-alpha.N` | Early development; APIs and config format are unstable |
| `-beta.N` | Feature-complete; APIs may change based on feedback |
| `-rc.N` | Release candidate; no new features, only stabilization fixes |

Examples: `1.1.0-alpha.1`, `1.1.0-beta.2`, `1.1.0-rc.1`.

### The `1.0.0` baseline

SynVoid's `1.0.0` release establishes the stable public API. After `1.0.0`:

- Breaking changes require a MAJOR bump.
- Deprecated features must provide a migration path for at least one MINOR release cycle.
- Config file format changes are treated as breaking changes.

## 2. Release Lifecycle

```
Development --> Release Candidate --> Stabilization --> Release
     |                |                    |               |
  feature work    gates pass         only fixes      tag + publish
```

### Development

Active feature work on `main`. All commits must pass CI (fmt, clippy, tests).

### Release Candidate

A release candidate (RC) is cut when all release gates pass:

```bash
# Required gates — all must pass
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check                                          # Default profile
cargo check --no-default-features                    # Core profile
cargo check --no-default-features --features mesh    # Mesh profile
cargo check --no-default-features --features dns     # DNS profile
cargo check --no-default-features --features mesh,dns # Full profile
cargo test --release --no-fail-fast
cargo deny check
cargo audit
```

The RC tag follows the pattern `vMAJOR.MINOR.PATCH-rc.N` (e.g., `v1.1.0-rc.1`).

### Stabilization

The stabilization period begins after the RC tag is cut:

- **Minimum duration**: 3 calendar days.
- **Allowed changes**: Bug fixes, documentation updates, CI fixes, dependency patches.
- **Not allowed**: New features, config schema changes, refactoring that changes public behavior.
- **Gate**: All release gates must re-pass after every stabilization commit.

### Release

When the stabilization period ends with no outstanding issues:

1. Final CHANGELOG entry is committed.
2. The release tag is created (e.g., `v1.1.0`).
3. GitHub Release is published with artifacts.
4. Release notes are announced.

## 3. Build Profiles

SynVoid defines five compilation profiles. All five must compile and pass tests for every release. See [`architecture/release_profile_matrix.md`](../architecture/release_profile_matrix.md) for the full matrix.

### Profile summary

| Profile | Command | Use Case |
|---------|---------|----------|
| **Default** | `cargo build --release` | General-purpose deployment with all standard features |
| **Core** | `cargo build --release --no-default-features` | Minimal footprint; no DNS, no mesh |
| **Mesh** | `cargo build --release --no-default-features --features mesh` | Mesh networking without DNS |
| **DNS** | `cargo build --release --no-default-features --features dns` | DNS server without mesh |
| **Full** | `cargo build --release --no-default-features --features mesh,dns` | All supported features |

### Default features

The default profile enables: `socket-handoff`, `mesh`, `dns`, `erased_pool`, `swagger-ui`.

### Beta features

Beta features are functional and compile cleanly but have limited real-world validation or hard runtime constraints. They are **not** included in default builds.

| Feature | Platform Requirement | Runtime Constraints |
|---------|---------------------|---------------------|
| `icmp-ebpf` | Linux only | Requires kernel BTF, CAP_NET_ADMIN or root, precompiled eBPF object. Falls back to nftables when unavailable |
| `post-quantum` | Any | Experimental TLS key exchange |
| `verify-pq` | Any | Post-quantum verification |

To build with a Beta feature:

```bash
cargo build --release -p synvoid-icmp-filter --features icmp-ebpf
```

Beta features are listed in release notes and do not block the release gate for supported profiles.

## 4. Supported Platforms

Full details in [`docs/PLATFORM_SUPPORT.md`](PLATFORM_SUPPORT.md).

| Platform | Support Level | CI Tested | Notes |
|----------|--------------|-----------|-------|
| Linux x86_64 (glibc) | Production | Yes | Primary target; CPU pinning, Landlock sandboxing |
| Linux x86_64 (musl/Alpine) | Production | Yes | Full feature support |
| macOS x86_64/aarch64 | Production | Yes | Full socket support, SO_REUSEPORT |
| Windows x86_64 (10+) | Production | Yes | Named pipe IPC, Windows Service support |
| FreeBSD x86_64 | Production | Yes | SO_REUSEPORT_LB kernel distribution |

### Feature availability by platform

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| `SO_REUSEPORT` | Yes | Yes | Yes | Yes |
| CPU Core Pinning | Yes | No | Yes | No |
| Landlock/Seccomp sandboxing | Yes | No | No | No |
| eBPF ICMP filter (`icmp-ebpf`) | Yes (Beta) | No | No | No |
| WireGuard tunnel | Yes | Yes | Yes | Yes |

## 5. Release Artifacts

### What gets produced

| Artifact | Description |
|----------|-------------|
| **Source tarball** | Tagged source from GitHub (`Source code (tar.gz)` / `Source code (zip)`) |
| **Binary artifacts** | Pre-built binaries for supported platforms (Linux x86_64, macOS aarch64, Windows x86_64) |
| **Docker images** | Container images published to the registry (if applicable) |

### Checksums and signatures

Every release artifact is accompanied by:

- **SHA-256 checksums** (`SHA256SUMS.txt`) for all binaries and tarballs.
- **GPG signatures** (`SHA256SUMS.txt.sig`) for checksum verification.

To verify a release:

```bash
sha256sum -c SHA256SUMS.txt
gpg --verify SHA256SUMS.txt.sig SHA256SUMS.txt
```

### Where artifacts are published

All release artifacts are published on the [GitHub Releases](https://github.com/synvoid/synvoid/releases) page for the corresponding tag.

## 6. Release Process Checklist

### Pre-release

- [ ] All five compilation profiles compile cleanly
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --release --no-fail-fast` passes (all tests, zero failures)
- [ ] `cargo deny check` passes (license and dependency audit)
- [ ] `cargo audit` passes (security advisory check)
- [ ] Guard suite passes (all architecture invariant tests)
- [ ] CHANGELOG.md is updated with all changes since the last release
- [ ] Version is bumped in `Cargo.toml`
- [ ] Known limitations and Beta features are documented in release notes
- [ ] No `[ignore]` annotations remain in tests (or exceptions are documented)

### Release

- [ ] Stabilization period complete (minimum 3 days after RC tag)
- [ ] All gates re-pass after stabilization fixes
- [ ] Git tag created: `vMAJOR.MINOR.PATCH`
- [ ] Binaries built for all supported platforms
- [ ] Checksums and signatures generated
- [ ] GitHub Release created with release notes and artifacts
- [ ] CHANGELOG.md entry finalized and committed

### Post-release

- [ ] Release announcement published
- [ ] Operator channels notified (if applicable)
- [ ] Monitoring dashboards updated for new version
- [ ] Hotfix branch created if needed (see section 7)

## 7. Hotfix Process

Hotfixes address critical security vulnerabilities or data-corruption bugs that cannot wait for the next scheduled release.

### When to use a hotfix

- Active exploitation of a security vulnerability
- Data corruption or loss in production
- Complete service failure under common configurations

### Version numbering

Hotfixes bump the PATCH version on the current MAJOR.MINOR line:

```
v1.1.0 --> v1.1.1 (hotfix)
```

If the current version is `v1.1.0`, the hotfix is `v1.1.1`. Never skip a version number.

### Cherry-pick vs full release

| Scenario | Approach |
|----------|----------|
| Fix applies cleanly to the last release tag | Cherry-pick the fix onto a `hotfix/vX.Y.Z` branch |
| Fix depends on unreleased changes | Create a point release from `main` with the fix included |
| Fix affects multiple MAJOR versions | Create separate hotfix branches per MAJOR version |

### Hotfix checklist

- [ ] Fix is isolated to the minimum necessary scope
- [ ] Fix passes all release gates
- [ ] Regression test added for the specific bug
- [ ] CHANGELOG.md updated with `[PATCH]` entry
- [ ] Hotfix tag created and GitHub Release published
- [ ] Previous release users notified

## 8. Deprecation Policy

SynVoid provides advance notice before removing or changing existing functionality.

### Deprecation process

1. **Announcement**: The feature is marked as deprecated in the CHANGELOG and documentation with the version it was deprecated in.
2. **Warning period**: A minimum of **one MINOR release cycle** (e.g., deprecated in `1.1.0`, removed no earlier than `1.3.0`).
3. **Migration guide**: A migration path is documented in the CHANGELOG and/or a dedicated upgrade guide.
4. **Removal**: The feature is removed in the announced version with a clear changelog entry.

### What triggers a deprecation

- A feature is replaced by a strictly better alternative
- A feature cannot be made secure or reliable
- A feature conflicts with a new architectural invariant

### Deprecation indicators

Deprecated features emit a `WARN`-level log message at startup or first use, naming the replacement feature and the removal version.

## 9. Known Limitations and Tracked Exceptions

The following items are known limitations or tracked exceptions that operators should be aware of.

| Item | Classification | Impact | Notes |
|------|---------------|--------|-------|
| `icmp-ebpf` eBPF ICMP filter | **Beta** | Feature-gated, not in default profile | Requires Linux with kernel BTF, CAP_NET_ADMIN or root, precompiled eBPF object. Falls back to nftables when unavailable |
| `--all-features` workspace check | **Tracked exception** | Does not pass `cargo check --all-features` | `synvoid-icmp-filter` eBPF dependency resolution fails in `--all-features` mode. Individual crate checks pass. Not in default profile |
| wasmtime 40.0.4 (via yara-x) | **Tracked** | 11 advisory ignores in `deny.toml` | Used for YARA compilation only, not WASM sandbox. Re-audit date: 2026-10-01 |
| Email alerting (`src/admin/alerting/mod.rs:349`) | **Stub** | Logs and returns Ok, no actual sending | Not production-ready; implementation deferred |
| `spin` idle instance eviction | **Known gap** | Old UUID entries are never cleaned up | Tracked as plan DOC-L7 |
| Archive inspection | **Limitation** | ZIP-only, non-recursive | Does not inspect nested archives or non-ZIP formats |
| AI responder (honeypot) | **Disabled by default** | Requires explicit opt-in | External providers require configuration; no accidental activation |
| Mesh propagation | **Disabled by default** | Requires threshold configuration | Threat-intel sharing requires action class, confidence, and event count thresholds |

## Related Documents

| Document | Description |
|----------|-------------|
| [`architecture/release_profile_matrix.md`](../architecture/release_profile_matrix.md) | Full compilation profile and feature gate matrix |
| [`docs/PLATFORM_SUPPORT.md`](PLATFORM_SUPPORT.md) | Platform support and feature availability |
| [`docs/CONFIGURATION.md`](CONFIGURATION.md) | Configuration reference |
| [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) | Deployment patterns and Docker |
| [`docs/SECURITY.md`](SECURITY.md) | Security model and advisory policy |
| [`CHANGELOG.md`](../CHANGELOG.md) | Release history and migration notes |
