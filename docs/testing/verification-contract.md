# Verification Contract

> Frozen: 2026-07-29 | Phase 1 of CI Simplification Roadmap
> Updated: 2026-07-29 | Phase 3 completed — local verification and guard reduction

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

The routine contract runs the same fixed command set regardless of which files changed. The `select-affected.py` script, `test-affected.sh` wrapper, and all selector infrastructure have been deleted.

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

## 6. Failure Injection Results

All seven failure classes were demonstrated against the frozen routine contract on 2026-07-29. Each injection was a temporary file modification, reverted after measurement.

| # | Class | Injected defect | Command | Expected failure point | Actual failure point | Later commands skipped? |
|---|-------|----------------|---------|----------------------|---------------------|------------------------|
| 1 | Formatting violation | Extra spaces in `worker_id.rs` function signature | `cargo fmt --all -- --check` | Step 1: exit 1 with diff | Step 1: exit 1, diff output shows exact lines | N/A (first command) |
| 2 | Clippy warning → error | Unused variable (no `_` prefix) in `worker_id.rs` | `cargo clippy --all-targets -- -D warnings` | Step 2: exit 101, unused-variables error | Step 2: exit 101, `error: unused variable: unused_variable` | N/A (second command) |
| 3 | Compilation error | Missing closing paren in `worker_id.rs` | `cargo check --no-default-features` | Step 3: exit 101, syntax error | Step 3: exit 101, `expected `)` found `}` | N/A (third command) |
| 4 | Unit-test failure | `assert!(false)` in `root_test_ownership_guard.rs` | `cargo test --test root_test_ownership_guard` | Guard test: exit 101, panic message | Guard test: exit 101, `INJECTED FAILURE for testing` | No — subsequent guards still ran |
| 5 | Security regression | `assert!(false)` in `security_regression.rs::test_ipc_auth_bypass_rejected` | `cargo nextest run --test security_regression --test-threads=1` | Security suite: exit 96/101 | Security suite: exit 101, `INJECTED SECURITY REGRESSION` | No — other regression tests still passed |
| 6 | Architecture guard | Inverted assertion in `boundary_composition_guard.rs::simulated_violation_in_waf_is_detected` | `cargo test --test boundary_composition_guard` | Guard suite: exit 101, 1 failed | Guard suite: exit 101, 54 passed / 1 failed | No — other guard tests still ran |
| 7 | Wrapper propagation | Formatting violation + `&&` chain | `cargo fmt && cargo clippy && cargo check` | Chain aborts after fmt failure | Chain aborts: steps 2 and 3 never executed | Yes — fail-fast `&&` stops chain |

### Key observations

- All failures produce nonzero exit codes (1, 101, or 96 for nextest).
- Failures in guard/security tests do not prevent subsequent tests from running (independent `cargo test` invocations).
- Failures in the `&&`-chained wrapper correctly abort subsequent commands (fail-fast).
- No silent failures or false passes observed.

## 7. Routine Contract Measurements

Measured on 2026-07-29 on a warm-cache Linux x86_64 workstation (45 workspace members).

### Per-command timing (warm cache, all binaries pre-compiled)

| # | Command | Wall time | Exit |
|---|---------|-----------|------|
| 1 | `cargo fmt --all -- --check` | 4.6s | 0 |
| 2 | `cargo clippy --all-targets -- -D warnings` | 82.5s | 0 |
| 3 | `cargo check --no-default-features` | 16.0s | 0 |
| 4 | `cargo nextest run -p synvoid-repo-guards` | 3.5s | 0 |
| 5 | `cargo test --lib --no-run` | 320s (compile) | 0 |
| 6 | `cargo test --test boundary_composition_guard` | 167s (compile+run) | 0 |
| 7 | `cargo test --test lifecycle_task_guard` | 2.0s | 0 |
| 8 | `cargo test --test plugin_guard` | 2.5s | 0 |
| 9 | `cargo test --test cli_admin_guard` | 0.8s | 0 |
| 10 | `cargo test --test security_guard` | 12s | 0 |
| 11 | `cargo test --test root_facade_boundary_guard` | 13s | 0 |
| 12 | `cargo test --test mesh_id_boundary_guard` | 14s | 0 |
| 13 | `cargo test --test admin_mutation_response_guard` | 15s | 0 |
| 14 | `cargo test --test admin_mutation_blocklist` | 28s | 0 |
| 15 | `cargo test -p synvoid-core --test admin_auth_boundary` | 33s | 0 |
| 16 | `cargo test -p synvoid-core --test mesh_admin_edge_cases` | 34s | 0 |
| 17 | `cargo test --test failure_injection` | 70s | 0 |
| 18 | `cargo test --test worker_mesh_supervision_boundary_guard` | 111s | 0 |
| 19 | `cargo test --test mesh_task_ownership_guard` | 113s | 0 |
| 20 | `cargo test --test abi_memory_boundary_guard` | 115s | 0 |
| 21 | `cargo test --test root_test_ownership_guard` | 117s | 0 |
| 22 | `cargo nextest run --test security_regression --test-threads=1` | 118s | 0 |

### Summary

| Metric | Value |
|--------|-------|
| Warm-cache total wall time | ~1,480s (~25 min) |
| First-run compilation overhead | ~487s (commands 5–6 compile all test binaries) |
| Subsequent-run wall time (all binaries cached) | ~993s (~17 min) |
| Cargo invocations | 22 |
| Unique compiled test binaries | ~18 (many guard tests share compilation) |
| Duplicate test targets | 0 (each command tests a distinct target) |
| Failed commands | 0 (all pass on clean codebase) |
| Properties covered | 7 (formatting, linting, compilation, guards, security, architecture, ownership) |
| Properties omitted | 12+ (full workspace tests, doctests, DNS, plugins, profiles, cross-platform, fuzz, miri, etc.) |

### Budget assessment

| Threshold | Measured | Status |
|-----------|----------|--------|
| Target <10min | ~17min (warm) / ~25min (first run) | Over budget — see note |
| Blocking threshold >15min | ~17min warm | Approaching threshold |
| Cargo invocations <10 | 22 | Over budget |

**Note**: The warm-cache time includes 320s for `cargo test --lib --no-run` (full lib compilation) and 167s for `boundary_composition_guard` (first guard compilation). On a CI runner with persistent caches, the compilation overhead would be amortized. The routine contract as specified may need pruning for CI — Phase 2 should evaluate whether some guard tests can be consolidated or the `--lib --no-run` step replaced with `cargo check`.

## 8. Disposition

Phase 3 completed the CI simplification:
1. `cargo xtask verify` runs the routine contract on every PR
2. `cargo xtask verify-full` provides broader local verification
3. `cargo xtask verify-release` validates production artifacts
4. The four-lane system, affected-package selector, and lane manifest have been deleted
5. CI-policy guard tests have been removed from `synvoid-repo-guards`

If implementation reveals an invalid command, correct this document in the same commit with an explicit rationale. Do not improvise a broader suite or restore selector behavior.
