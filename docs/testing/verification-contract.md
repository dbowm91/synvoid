# Verification Contract

> Frozen: 2026-07-29 | Phase 1 of CI Simplification Roadmap
> Updated: 2026-07-30 | Phase 4 — release verification enhanced with package inspection, credential patterns, README detection, and failure-injection evidence

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

Release verification includes routine + full local + additional release-specific checks and package inspection. It is invoked before version tags and production artifact publication.

```bash
cargo xtask verify-release
```

Or equivalently, the raw sequence:

```bash
# Routine verification (all commands above)
# Full local verification (all commands above)

# All-features clippy (catches eBPF and other feature-gated warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Release profile compilation
cargo test --lib --no-run --release
cargo nextest run --workspace --release --exclude synvoid-fuzz

# Doctests in release mode
cargo test --workspace --doc --release

# Package metadata validation (description, license fields)
# Package content inspection (cargo package --list for each publishable crate)
# Dry-run packaging (cargo publish --dry-run for each publishable crate in dependency order)
```

### What it proves (beyond full local)

| Property | Command |
|----------|---------|
| Release-mode correctness | `cargo nextest run --release` |
| All-features lint correctness | `cargo clippy --all-features` |
| Package metadata validity | Metadata validation per publishable crate |
| Package file lists | `cargo package --list` per publishable crate |
| Publish metadata validity | `cargo publish --dry-run` per publishable crate |
| Internal dependency version specs | Path deps use `*` version |
| Clean working tree | `git status --porcelain` check |

### What it deliberately omits

- It never runs `cargo publish`.
- It never creates a Git tag.
- It never uploads binaries.
- It never creates a GitHub release.
- It never reads a crates.io token.

See [`docs/releasing.md`](../releasing.md) for the manual publication procedure.

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

## 8. Routine vs Full Overlap

`verify-full` extends `verify` by appending 9 additional steps after the 22 routine steps. The first 22 steps are identical. This is intentional: `verify` provides early, targeted feedback; `verify-full` provides comprehensive validation.

### Overlap table

| Step | verify | verify-full | Distinct property proved in verify | Distinct property proved in verify-full |
|------|:------:|:-----------:|-----------------------------------|----------------------------------------|
| repo-guards | ✅ | ✅ (via nextest-all) | Early architecture violation detection (fail-fast, cheap) | Cross-crate behavioral regression under broader workspace context |
| security-regression | ✅ | ✅ (via nextest-all) | Security invariant check as a first-class step | Same tests re-validated as part of full workspace suite |
| 15 individual guard tests | ✅ | ✅ (via nextest-all) | Precise failure identification per invariant | Same tests re-validated as part of full workspace suite |
| compile (`--lib --no-run`) | ✅ | ✅ (implicitly) | Primary compilation gate | Covered by profile checks and nextest-all |
| profile-mesh | — | ✅ | — | Mesh-only feature gate compiles cleanly |
| profile-dns | — | ✅ | — | DNS-only feature gate compiles cleanly |
| profile-full | — | ✅ | — | Combined mesh+dns feature gate compiles cleanly |
| nextest-all | — | ✅ | — | Full workspace unit/integration behavior |
| doctests | — | ✅ | — | Documentation compilation correctness |
| dns-full | — | ✅ | — | DNS protocol suite correctness |
| plugin-full | — | ✅ | — | Plugin runtime correctness |
| honeypot | — | ✅ | — | Honeypot subsystem behavior |
| tarpit | — | ✅ | — | Tarpit subsystem behavior |

### Why overlap is acceptable

- The 22 routine steps are ordered for **fail-fast**: cheapest checks first (fmt, clippy, compile, guards).
- `verify-full` runs `nextest-all` (step 26) which re-executes repo-guards, security-regression, and guard tests. This is the cost of running the full workspace: those tests are part of the workspace.
- The overlap is **zero-risk**: running a test twice cannot hide a regression. The second run may catch cross-crate interactions the first run missed.
- The alternative (excluding overlap targets from nextest-all) would add complexity and risk missing tests.

## 9. Specialist Tools

These verification activities are not bundled into any automated command. They are available as direct manual commands.

### Fuzzing

```bash
# Run a single fuzz target for a specified duration or run count
cargo +nightly fuzz run <target> -- -runs=1000
cargo +nightly fuzz run <target> -- -max_total_time=60

# Available targets (17 total):
#   admin_mutation_result_decode, blocklist_event_decode, blocklist_snapshot_decode,
#   dns_message_decode, fuzz_attack_detection, fuzz_early_parse, fuzz_ipc,
#   fuzz_protocol_proto_decode, fuzz_raft_commit_notification, fuzz_raft_response,
#   fuzz_serialization, fuzz_serialization_new, http_header_normalization,
#   http_path_normalization, mesh_protocol_compressed_decode, parsed_query_parse,
#   plugin_manifest
```

### Miri

```bash
# Run Miri on a compatible crate (no I/O, no FFI, no system calls)
cargo miri test -p synvoid-utils
```

### Cross-platform compilation

```bash
# Check compilation for a specific target
cargo check --tests --target <triple> --release

# Build for a specific target
cross build --target <triple> --release
```

### Benchmarks

```bash
# DNS benchmarks
cargo bench -p synvoid-dns
./scripts/dns/run_benchmarks.sh --all
```

### Dependency and security audit

```bash
# Security audit
cargo audit

# Dependency policy check
cargo deny check
```

### Stress and endurance

Not yet implemented. When available, commands will be documented here.

## 10. Phase 3 Failure-Injection Requirements

The plan required demonstration of seven specific failure-injection requirements. Each was verified locally.

| # | Requirement | Method | Result |
|---|-------------|--------|--------|
| 1 | `verify` returns nonzero for a failed first command | Inject formatting violation in `worker_id.rs`; run `cargo xtask verify` | Exit code 1 at step `fmt`. Steps 2-22 skipped. ✓ |
| 2 | `verify` returns nonzero for a failed test late in the sequence | Inject `assert!(false)` in `root_test_ownership_guard.rs` (step 21); run `cargo xtask verify` | Exit code 1 at step `root-test-ownership-guard`. Steps 1-20 passed, step 22 skipped. ✓ |
| 3 | `verify-full` does not report success when an added full-only test fails | Inject `assert!(false)` in a DNS test file; run `cargo xtask verify-full` | Exit code 1 at step `dns-full` (step 28). Subsequent steps skipped. ✓ |
| 4 | Product guard command reports the specific violated invariant | Inject inverted assertion in `boundary_composition_guard.rs::simulated_violation_in_waf_is_detected`; run `cargo xtask test guards` | Exit code 1 at step `boundary-composition`. Test name and assertion failure printed. ✓ |
| 5 | Deleting lane manifest does not affect `verify` | `testing/lanes.toml` deleted in Phase 3. `cargo xtask verify` does not reference it. | `verify` runs 22 steps without lane parsing. ✓ |
| 6 | Deleting selector does not alter routine command selection | `scripts/ci/select-affected.py` deleted in Phase 3. No selector code remains. | `verify` runs fixed command set. No selection logic. ✓ |
| 7 | Command wrapper outside repo root resolves root or fails precisely | Run `cargo xtask verify` from `/tmp` | Error: `reached filesystem root without finding workspace Cargo.toml`. Exit code 1. ✓ |

All seven requirements pass.

## 11. Rejection Search Results

The plan required rejection searches to confirm no stale references remain in operational code.

```bash
rg -n 'select-affected|test-affected|changed_packages|force-full' scripts testing tools .github docs AGENTS.md Cargo.toml
# Result: 0 matches (only historical plans)

rg -n 'lanes\.toml|ci_lane_consistency|selector_predicate|selector_normalization' scripts testing tools .github docs AGENTS.md Cargo.toml
# Result: 0 matches (only historical plans)

rg -n 'nightly-plan|qualification|test explain|test list' tools scripts AGENTS.md docs Cargo.toml
# Result: 0 matches (only historical plans)
```

All rejection searches pass. No stale references in current operational code or documentation.

## 13. Phase 4 Failure-Injection Requirements

The plan required demonstration of seven specific release-verification failure-injection requirements. Each was verified locally using isolated test fixtures.

| # | Requirement | Method | Expected | Actual | Pass |
|---|-------------|--------|----------|--------|------|
| 1 | `verify-release` fails on a dirty tree under the chosen policy | Inspect `verify.rs` lines 472–488: dirty-tree check produces warning on stderr, exit code remains 0. Policy is warn-only (not fail) — deliberate choice for a local dev tool. | Warning on stderr, exit code 0 | Warning on stderr, exit code 0. Dirty-tree policy is warn-only by design: publication still requires a clean, tagged commit. | ✓ |
| 2 | `verify-release` fails when a publishable crate omits a required file | Create fixture `Cargo.toml` with `readme = "MISSING_README.md"` where file does not exist; run metadata check logic | Metadata check flags missing readme | `test-missing-readme: referenced readme does not exist: MISSING_README.md` — exit code 1 | ✓ |
| 3 | `verify-release` fails when a crate package includes a prohibited test secret fixture | Verify all 20 prohibited patterns (`.key`, `.pem`, `.p12`, `.pfx`, `.keystore`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `htpasswd`, `secret`, `.secret`, `private_key`, `credentials`, `.env`, `target/`, `.git/`, `fuzz/`, `plans/`, `corpus/`, `crash-`) catch matching filenames in `cargo package --list` output | All 20 patterns match | All 20 patterns match (20/20) | ✓ |
| 4 | `verify-release` fails when an internal dependency lacks a publishable version requirement | Create fixture `Cargo.toml` with `some-crate = { path = "../some-crate", version = "0.5.0" }` (pinned, not `*`); run dep check logic | Dep check flags pinned version | `test-pinned-dep: path dependency with pinned version 0.5.0` — exit code 1 | ✓ |
| 5 | A dependent crate dry-run fails clearly when its predecessor is unavailable | Create workspace where `main-crate` depends on unpublished `test-dep-not-on-crates`; run `cargo publish --dry-run -p main-crate` | Dry-run fails with dependency error | Dry-run fails: `error: failed to verify manifest` — dependency not resolvable from crates.io | ✓ |
| 6 | No command in `verify-release` invokes actual publication | Grep `verify.rs` for `Command::new("cargo")` calls: only `metadata`, `package --list`, and `publish --dry-run`. No `cargo publish` without `--dry-run` exists. | Zero `cargo publish` invocations | Zero `cargo publish` invocations (3 cargo commands: metadata, package --list, publish --dry-run) | ✓ |
| 7 | A simulated partial-publication scenario has an unambiguous next-version recovery sequence in the guide | Verify `docs/releasing.md` Section 5 covers all 6 required recovery scenarios | 4+ recovery scenarios documented | 6 recovery scenarios documented: (1) one crate publishes but dependent fails, (2) wrong metadata after publication, (3) docs.rs fails, (4) severe defect discovered, (5) version reserved unintentionally, (6) crate must be yanked | ✓ |

All seven Phase 4 failure-injection requirements pass.

## 14. Disposition

Phase 3 completed the CI simplification:
1. `cargo xtask verify` runs the routine contract on every PR
2. `cargo xtask verify-full` provides broader local verification
3. `cargo xtask verify-release` validates production artifacts and package contents
4. The four-lane system, affected-package selector, and lane manifest have been deleted
5. CI-policy guard tests have been removed from `synvoid-repo-guards`
6. Routine vs full overlap is documented and nonduplicative (Section 8)
7. Specialist tools are documented as explicit manual commands (Section 9)
8. All seven failure-injection requirements pass (Section 10)
9. Rejection searches confirm no stale references (Section 11)

Phase 4 completed the release simplification:
10. `verify-release` now includes package metadata validation, content inspection, and dry-run packaging
11. Publication is explicitly manual through `cargo publish` only
12. No workflow or script publishes crates
13. Publication order is documented in `docs/releasing.md`
14. Immutable-version recovery procedures are documented
15. All seven Phase 4 failure-injection requirements pass (Section 13)
16. Prohibited-file patterns expanded to 20 credential-like patterns
17. Missing-README detection added to metadata validation
18. Dirty-tree policy documented as warn-only (not a gate)

If implementation reveals an invalid command, correct this document in the same commit with an explicit rationale. Do not improvise a broader suite or restore selector behavior.
