# Verification Contract

> Frozen: 2026-07-29 | Phase 1 of CI Simplification Roadmap

This document is the single source of truth for what SynVoid CI must verify, at what frequency, and with what commands. It replaces the four-lane system as the authoritative verification specification.

## 1. Routine Verification Contract

The routine contract runs on every pull request. It is expressed as a single command:

```bash
cargo xtask verify
```

Or equivalently, the raw commands:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo check --no-default-features
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1
cargo test --lib --no-run
cargo test --test boundary_composition_guard
cargo test --test lifecycle_task_guard
cargo test --test plugin_guard
cargo test --test cli_admin_guard
cargo test --test security_guard
cargo test --test root_facade_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test -p synvoid-core --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test --test failure_injection
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test abi_memory_boundary_guard
cargo test --test root_test_ownership_guard
```

### What it proves

| Property | Command | Routine CI? |
|----------|---------|:-----------:|
| Formatting conformance | `cargo fmt --all -- --check` | Yes |
| Lint correctness (default features) | `cargo clippy --all-targets -- -D warnings` | Yes |
| Core-only compilation | `cargo check --no-default-features` | Yes |
| Architecture static guards | `cargo nextest run -p synvoid-repo-guards` | Yes |
| Security regression detection | `cargo nextest run --test security_regression --test-threads=1` | Yes |
| Primary Linux compilation | `cargo test --lib --no-run` | Yes |
| Composition boundary guards | 15 individual `cargo test --test` | Yes |

### What it deliberately omits

| Property | Why omitted from routine |
|----------|------------------------|
| Full workspace tests | Too expensive for every commit (~7min cold compile) |
| Feature profile matrix | Not a regression risk per-commit; caught on main merge |
| Doctests | Not the only test for any critical behavior |
| Cross-platform builds | Expensive; caught on main merge or nightly |
| DNS full suite | Large suite; caught on main merge |
| Plugin runtime full suite | Large suite; caught on main merge |
| Dependency audit | Not per-commit; caught on main merge or nightly |
| Fuzz smoke | Expensive; nightly only |
| Miri | Expensive; nightly only |

### Budget

- **Target**: <10 minutes wall time on warm-cache Ubuntu runner
- **Blocking threshold**: >15 minutes
- **Cargo invocations**: <10 (significantly fewer than the old 45-invoke PR fast lane)

### No affected-package selection

The routine contract runs the same fixed command set regardless of which files changed. This eliminates:
- The `select-affected.py` script and its maintenance burden
- The `test-affected.sh` wrapper
- Per-package gating logic in CI workflows
- Selector normalization, fallback, and polarity guards

### No matrix or OS variation

The routine contract runs only on Linux x86_64 with default features. Cross-platform validation belongs in full local or release verification.

## 2. Full Local Verification

Full local verification is manually invoked before risky merges and during focused subsystem work. It is not automated in CI.

```bash
# Format + lint
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# All feature profile compilations
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Full workspace tests (nextest preferred)
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz

# Doctests
cargo test --workspace --doc --profile ci

# Domain-specific suites
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci
cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci

# All guard tests (repo-guards crate + root guards)
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo test --test boundary_composition_guard
cargo test --test lifecycle_task_guard
cargo test --test plugin_guard
cargo test --test cli_admin_guard
cargo test --test security_guard
cargo test --test root_facade_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test -p synvoid-core --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test --test failure_injection
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test abi_memory_boundary_guard
cargo test --test root_test_ownership_guard

# Security regression (single-threaded)
cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1
```

### What it proves (beyond routine)

| Property | Command |
|----------|---------|
| Full workspace unit/integration behavior | `cargo nextest run --workspace` |
| Documentation compilation | `cargo test --workspace --doc` |
| DNS full suite correctness | `cargo nextest run -p synvoid-dns` |
| Plugin runtime full suite correctness | `cargo nextest run -p synvoid-plugin-runtime` |
| Mesh feature compilation | Feature profile checks |
| All-features compilation (via clippy) | `cargo clippy --all-targets` |

## 3. Release Verification

Release verification includes routine + full local + additional release-specific checks. It is invoked before version tags and production artifact publication.

```bash
# Routine verification (all commands above)
# Full local verification (all commands above)

# All-features clippy (catches eBPF and other feature-gated warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Release profile compilation
cargo test --lib --no-run --release
cargo nextest run --workspace --release --exclude synvoid-fuzz

# Package assembly inspection
cargo package --list --workspace

# Publish dry-run (dependency order)
cargo publish --dry-run -p synvoid-utils
cargo publish --dry-run -p synvoid-core
# ... (all publishable crates in dependency order)
```

### What it proves (beyond full local)

| Property | Command |
|----------|---------|
| Release-mode correctness | `cargo nextest run --release` |
| All-features lint correctness | `cargo clippy --all-features` |
| Package file lists | `cargo package --list` |
| Publish metadata validity | `cargo publish --dry-run` |

### Not bundled into release

These are explicit separate tools, not silently included:

- **Fuzzing**: `cargo +nightly fuzz run <target> -- -runs=1000` (17 targets)
- **Miri**: `cargo miri test -p synvoid-utils`
- **Stress/endurance**: Not yet implemented
- **Platform-specific**: Cross-compilation checks (manual or nightly)
- **Outdated deps**: `cargo outdated --release --exit-code 2`

## 4. Disposition of Current CI Commands

Every current CI command classified by product property and routine eligibility:

| Property | Current command | Routine CI? | Disposition |
|----------|----------------|:-----------:|-------------|
| Formatting | `cargo fmt --all -- --check` | Yes | Keep in routine |
| Clippy (default) | `cargo clippy --all-targets -- -D warnings` | Yes | Keep in routine |
| Clippy (all features) | `cargo clippy --all-targets --all-features -- -D warnings` | No | Release only |
| Core profile compile | `cargo check --no-default-features` | Yes | Keep in routine |
| Mesh-only compile | `cargo check --no-default-features --features mesh` | No | Full local |
| DNS-only compile | `cargo check --no-default-features --features dns` | No | Full local |
| Full mesh+dns compile | `cargo check --no-default-features --features mesh,dns` | No | Full local |
| Default compile | `cargo check` | No | Full local |
| Repo-guards crate | `cargo nextest run -p synvoid-repo-guards` | Yes | Keep in routine |
| Security regression | `cargo nextest run --test security_regression --test-threads=1` | Yes | Keep in routine |
| Primary compilation | `cargo test --lib --no-run` | Yes | Keep in routine |
| Composition boundary guards | 15 individual `cargo test --test` | Yes | Keep in routine |
| Root test ownership | `cargo test --test root_test_ownership_guard` | Yes | Keep in routine |
| Full workspace tests | `cargo nextest run --workspace --exclude synvoid-fuzz` | No | Full local |
| Doctests | `cargo test --workspace --doc` | No | Full local |
| DNS full suite | `cargo nextest run -p synvoid-dns` | No | Full local |
| Plugin runtime full | `cargo nextest run -p synvoid-plugin-runtime` | No | Full local |
| DNS unsafe check | `grep -r "unsafe {" crates/synvoid-dns/src/` | No | Full local (covered by repo-guards) |
| Forbidden imports | `python scripts/check_imports.py` | No | Full local (covered by repo-guards) |
| Profile matrix (5 variants) | `cargo check <features>` | No | Full local |
| Documentation build | `cargo doc --no-deps --release` | No | Full local |
| Security audit | `cargo audit` | No | Full local or nightly |
| Dependency audit | `cargo deny check` | No | Full local or nightly |
| Cross-platform builds | `cross build --target <target> --release` | No | Release only |
| Cross-platform tests | `cargo nextest run --target <target>` | No | Release only |
| Alpine/musl test | `cargo build --release && cargo test --release` | No | Nightly |
| FreeBSD test | `cargo build --release && cargo test --release` | No | Nightly |
| Platform compat check | `cargo check --tests --target <target>` | No | Nightly |
| Miri | `cargo miri test -p synvoid-utils` | No | Nightly (continue-on-error) |
| Fuzz smoke (17 targets) | `cargo +nightly fuzz run <target> -- -runs=1000` | No | Nightly |
| Outdated deps | `cargo outdated --release --exit-code 2` | No | Nightly (continue-on-error) |
| Release packaging | `cargo build --release` | No | Release only |

## 5. Assumptions and Constraints

- The CI profile (`[profile.ci]`) is defined in root `Cargo.toml` and must not be removed.
- `nextest` is the preferred test runner for CI due to better concurrency and diagnostics.
- Security regression tests must run single-threaded (`--test-threads=1`) due to env var serialization.
- The repository guard crate (`synvoid-repo-guards`) must not depend on the root `synvoid` crate.
- No routine CI command uses `--release` profile.
- No routine CI command uses `--all-features` (catches eBPF compilation failures on release lane only).
- The `cargo xtask verify` command will be implemented in Phase 2.

## 6. Handoff to Phase 2

Phase 2 must:
1. Implement `cargo xtask verify` exactly as specified in Section 1
2. Replace the current `pr-fast.yml` workflow with a single-workflow CI that runs the routine contract
3. Remove affected-package selection from the PR path
4. Update branch protection to reference the new workflow
5. Remove or simplify CI-specific guard tests that no longer apply

If implementation reveals an invalid command, correct this document in the same commit with an explicit rationale. Do not improvise a broader suite or restore selector behavior.
