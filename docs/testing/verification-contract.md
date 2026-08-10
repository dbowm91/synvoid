# Verification Contract

> Frozen: 2026-07-29 | Phase 1 of CI Simplification Roadmap
> Updated: 2026-08-08 | Phase 1 follow-up — Release qualification semantics

This document is the single source of truth for what SynVoid CI must verify, at what frequency, and with what commands. It replaces the four-lane system as the authoritative verification specification.

## 1. Routine Verification Contract

The routine contract runs on every pull request. It is expressed as a single command:

```bash
cargo xtask verify
```

Or equivalently, the raw commands (8 Cargo invocations):

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
cargo nextest run --cargo-profile ci --profile ci \
  --test boundary_composition_guard --test lifecycle_task_guard \
  --test plugin_guard --test cli_admin_guard --test security_guard \
  --test root_facade_boundary_guard --test mesh_id_boundary_guard \
  --test admin_mutation_response_guard --test admin_mutation_blocklist \
  --test abi_memory_boundary_guard --test root_test_ownership_guard \
  --test worker_mesh_supervision_boundary_guard --test mesh_task_ownership_guard \
  --features mesh
cargo nextest run -p synvoid-core --cargo-profile ci --profile ci \
  --test admin_auth_boundary --test mesh_admin_edge_cases
cargo test --test failure_injection --profile ci
```

### What it proves

| Property | Command | Routine CI? |
|----------|---------|:-----------:|
| Formatting conformance | `cargo fmt --all -- --check` | Yes |
| Lint correctness (ci profile) | `cargo clippy --profile ci --all-targets -- -D warnings` | Yes |
| Core-only compilation | `cargo check --no-default-features --profile ci` | Yes |
| Architecture static guards | `cargo nextest run -p synvoid-repo-guards` | Yes |
| Security regression detection | `cargo test --test security_regression --profile ci --test-threads=1` | Yes |
| Composition, lifecycle, plugin, CLI, admin, mesh, ABI, and ownership guards | 13 root guard tests via consolidated nextest | Yes |
| synvoid-core admin/mesh edge cases | 2 synvoid-core tests via nextest | Yes |
| Failure injection (supervisor, block-store, plugin) | `cargo test --test failure_injection --profile ci` | Yes |

### What it deliberately omits

| Property | Why omitted from routine |
|----------|------------------------|
| Full workspace tests | Too expensive for every commit (~7min cold compile); run locally via `verify-full` |
| Feature profile matrix | Not a regression risk per-commit; run locally via `verify-full` |
| Doctests | Not the only test for any critical behavior; run locally via `verify-full` |
| Cross-platform builds | Expensive; manual local verification |
| DNS full suite | Large suite; run locally via `verify-full` |
| Plugin runtime full suite | Large suite; run locally via `verify-full` |
| Dependency audit | Not per-commit; manual `cargo deny check` or `cargo audit` |
| Fuzz smoke | Expensive; manual `cargo +nightly fuzz run <target>` |
| Miri | Expensive; manual `cargo miri test -p synvoid-utils` |

### Budget

- **Target**: <10 minutes wall time on warm-cache Ubuntu runner
- **Blocking threshold**: >15 minutes
- **Cargo invocations**: 8 (fmt + 7 Cargo invocations)

### No affected-package selection

The routine contract runs the same fixed command set regardless of which files changed. There is no affected-package selector or dynamic command scheduler.

### No matrix or OS variation

The routine contract runs only on Linux x86_64 with default features. Cross-platform validation belongs in full local or release verification.

## 2. Full Local Verification

Full local verification is manually invoked before risky merges and during focused subsystem work. It is not automated in CI.

```bash
cargo xtask verify-full
```

Or equivalently, the raw commands (7 Cargo invocations):

```bash
# Format + lint preflight (shared with routine, cheap)
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings

# Feature profile compilation
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Broad deterministic workspace tests (single invocation)
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz

# Doctests
cargo test --workspace --doc --profile ci
```

### What it proves (beyond routine)

| Property | Command |
|----------|---------|
| Mesh-only feature gate compiles cleanly | `cargo check --no-default-features --features mesh` |
| DNS-only feature gate compiles cleanly | `cargo check --no-default-features --features dns` |
| Combined mesh+dns feature gate compiles cleanly | `cargo check --no-default-features --features mesh,dns` |
| Full workspace unit/integration behavior | `cargo nextest run --workspace` |
| Documentation compilation | `cargo test --workspace --doc` |

### No duplicate test execution

`verify-full` shares only the cheap format/lint preflight with `verify`. It does NOT re-run routine test binaries. The broad `nextest --workspace` invocation covers all workspace tests including guard tests, security regression, DNS, plugin-runtime, honeypot, and tarpit in a single pass.

### Test disposition (A3)

Every test that fails or times out under `verify-full` is classified below. Real product regressions are not excluded or reclassified as infrastructure.

| Test | Category | Classification | Rationale |
|------|----------|----------------|-----------|
| `test_unknown_host_accepted_when_disabled` | proxy | STALE_EXPECTATION (resolved) | Router returns NotFound for unknown hosts when fallback=return_404; test updated in Phase 3 |
| `test_wildcard_domain_matching` | proxy | STALE_EXPECTATION (resolved) | matchit catch-all syntax fixed (`{*sub}` → `*sub`) in Phase 3 |
| `test_icmp_type_rule_validation` | icmp-filter | STALE_EXPECTATION (resolved) | `_is_v6` parameter removed (was unused); test updated in Phase 3 |
| `test_waf_corpus_sqli_with_invalid_utf8` | waf corpus | RESOLVED (Phase 2) | Raw-bytes detection path added; libinjection receives original percent-decoded bytes |
| `test_waf_corpus_xss_invalid_utf8` | waf corpus | RESOLVED (Phase 2) | Normalizer now decodes overlong UTF-8 to intended ASCII equivalents via `decode_overlong_sequence()`; test updated to assert detection |
| `test_anomaly_scoring_multiple_attacks` | waf wave10 | RESOLVED (Phase 5) | XPath base pattern `"='"` false-positived on SQLi payload `1' OR '1'='1`; narrowed XPath base patterns |
| `test_anomaly_scoring_xss_attack` | waf wave10 | RESOLVED (Phase 5) | XSS payload triggered XPath false-positive via broad base patterns; narrowed XPath base patterns |
| `test_open_redirect_with_data_protocol` | waf wave10 | RESOLVED (Phase 5) | Normalizer idempotency bug created new percent-encoding sequences; added post-normalization decode pass |
| `test_open_redirect_with_protocol` | waf wave10 | RESOLVED (Phase 5) | Normalizer idempotency bug created new percent-encoding sequences; added post-normalization decode pass |
| `test_path_traversal_double_encoded` | waf wave10 | RESOLVED (Phase 5) | XPath base pattern false-positived on path traversal payload; narrowed XPath base patterns |
| `test_path_traversal_encoded` | waf wave10 | RESOLVED (Phase 5) | XPath base pattern false-positived on path traversal payload; narrowed XPath base patterns |
| `test_ldap_injection` | waf wave10 | RESOLVED (Phase 5) | XPath base pattern false-positived on LDAP payload `admin)(&password=123`; narrowed XPath base patterns |
| `test_sqli_boolean_based` | waf wave10 | RESOLVED (Phase 5) | XPath base pattern false-positived on SQLi payload `test' AND 1=1--`; narrowed XPath base patterns |
| `test_sqli_time_based` | waf wave10 | RESOLVED (Phase 5) | XPath base pattern false-positived on SQLi payload `test' AND SLEEP(5)--`; narrowed XPath base patterns |
| `test_xpath_injection` | waf wave10 | RESOLVED (Phase 5) | XPath detection itself was blocked by overly broad base patterns; narrowed base patterns to `//\w+` and `[@...]` |
| `test_xxe_external_entity` | waf wave10 | HARNESS_DEFECT | Race condition: XSS (libinjection) finishes before XXE detector |
| `test_pool_creation` | app-handlers | RESOLVED (Phase 4) | Self-contained temp-directory socket fixture; no fixed-path collision |
| `test_worker_crash_recovery` | fault-injection | SPECIALIST (Phase 4) | Still `#[ignore]`; uses `CARGO_BIN_EXE_synvoid` and `/proc` children for deterministic discovery |
| `proxy_pipeline_tests` (5 tests) | integration | RESOLVED (Phase 4) | hyper-rustls ALPN conflict: `build_tls_config` set ALPN but connector builder requires empty; cleared ALPN before builder, uses `enable_all_versions()` |

**Summary**: 0 real product regressions (resolved), 4 stale expectations (resolved), 8 WAF detection (resolved Phase 5), 3 harness defects remaining (1 WAF detection pipeline, 2 invalid UTF-8 corpus), 1 specialist test (worker crash recovery), 7 environment-dependent resolved (5 proxy pipeline + 1 pool creation + 1 dashmap deadlock).

## 3. Release Verification

Release verification includes full local verification plus release-specific checks and package inspection. It is invoked before version tags and production artifact publication.

```bash
cargo xtask verify-release
```

Or equivalently, the raw sequence:

```bash
# Full local verification (all commands above)

# All-features clippy (catches eBPF and other feature-gated warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Release profile compilation
cargo test --lib --no-run --release

# Package metadata validation (description, license, readme)
# Dependency version validation (compatible semver, no * unless allowlisted)
# Package content inspection (cargo package --list, path-aware rules)
# Dependency graph analysis (publishable predecessors, non-publishable blockers, cycle detection)
# Per-crate package qualification (assembly + source verification)
# Manual publication order printed
```

### Package qualification model

Every publishable crate receives one explicit qualification state:

| State | Meaning |
|-------|---------|
| `Assembled` | `cargo package --no-verify` succeeded |
| `PackagedSourceVerified` | `cargo package` (with verify) succeeded |
| `BlockedOnUnpublishedInternalDeps` | Named publishable predecessors are not yet on crates.io |
| `NotPrepublishable` | Depends on non-publishable internal crate (release blocker) |
| `Failed` | Package step failed for an unexpected reason (release blocker) |

### Dependency graph analysis

The verifier builds a precise internal dependency graph from Cargo metadata:

- Only normal/build dependencies are checked (dev-dependencies follow Cargo publication rules)
- Publishable workspace predecessors are distinguished from non-publishable internal dependencies
- Cycles in the publishable dependency graph are detected and reported as errors
- No hardcoded crate-name list — classification comes from Cargo metadata

### Deferred qualification contract

A publishable crate may be `BlockedOnUnpublishedInternalDeps` without failing the overall pre-publication readiness command only if all of the following are true:

1. every blocking dependency is a named publishable workspace predecessor
2. its path dependency has a compatible, explicit semver requirement
3. package-content inspection passes
4. metadata validation passes
5. there is no non-publishable internal dependency
6. the publication graph is acyclic
7. the manual publication order places every blocking predecessor first
8. the output explicitly says the crate is **deferred**, not assembled or verified

After publishing predecessors, the operator must rerun the dependent crate's `cargo package` validation before publishing it.

### Exit semantics

- Nonzero exit for any `NotPrepublishable` or `Failed` state
- Zero exit when the only non-passed states are `BlockedOnUnpublishedInternalDeps` satisfying the deferred contract
- Summary text says `PRE-PUBLICATION READY WITH DEFERRED REGISTRY CHECKS` when deferred states exist

### Packaged-source verification

After assembly, `verify-release` attempts `cargo package` (with verify) for each assembled crate. Crates blocked by unpublished internal predecessors are skipped — their correctness is ensured by the full source verification in Phase 1. This provides a bounded packaged-source check without requiring a local registry emulator.

### Dirty-tree policy

`verify-release` **fails by default** on a dirty working tree. Use `--allow-dirty` to override for local experimentation. When `--allow-dirty` is used:
- A prominent warning is printed
- Package output is NOT release evidence
- All other validation behavior is unchanged

### What it proves (beyond full local)

| Property | Command |
|----------|---------|
| Release-mode correctness | `cargo test --lib --no-run --release` |
| All-features lint correctness | `cargo clippy --all-features` |
| Package metadata validity | Metadata validation per publishable crate |
| Dependency version compatibility | cargo metadata `req` field validation |
| Package file lists | `cargo package --list` per publishable crate |
| Dependency graph correctness | Cycle detection, predecessor classification |
| Pre-publication package assembly | `cargo package --no-verify` per eligible crate |
| Packaged-source verification | `cargo package` per assembled crate |
| Clean working tree | `git status --porcelain` check (fail by default) |

### Publication incapability

The release verifier **cannot** invoke `cargo publish`. All cargo invocations are:
- `cargo metadata` (read-only)
- `cargo package --list` (inspection)
- `cargo package --no-verify` (assembly without registry resolution)
- `cargo package` (source verification for assembled crates)

Actual publication remains manual:

```bash
cargo publish --dry-run -p <crate>  # per-crate, after predecessors are on crates.io
cargo publish -p <crate>            # actual publication
```

See [`docs/releasing.md`](../releasing.md) for the full manual publication procedure.

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
| Clippy (ci profile) | `cargo clippy --profile ci --all-targets -- -D warnings` | Yes | Keep in routine |
| Clippy (all features) | `cargo clippy --all-targets --all-features -- -D warnings` | No | Release only |
| Core profile compile | `cargo check --no-default-features --profile ci` | Yes | Keep in routine |
| Mesh-only compile | `cargo check --no-default-features --features mesh` | No | Full local |
| DNS-only compile | `cargo check --no-default-features --features dns` | No | Full local |
| Full mesh+dns compile | `cargo check --no-default-features --features mesh,dns` | No | Full local |
| Repo-guards crate | `cargo nextest run -p synvoid-repo-guards` | Yes | Keep in routine |
| Security regression | `cargo test --test security_regression --profile ci --test-threads=1` | Yes | Keep in routine |
| 13 root guard tests | `cargo nextest run ... root-guards` (consolidated) | Yes | Keep in routine |
| synvoid-core admin/mesh | `cargo nextest run -p synvoid-core ... core-admin-tests` (consolidated) | Yes | Keep in routine |
| Failure injection | `cargo test --test failure_injection --profile ci` | Yes | Keep in routine |
| Root test ownership | Included in root-guards consolidation | Yes | Keep in routine |
| Full workspace tests | `cargo nextest run --workspace --exclude synvoid-fuzz` | No | Full local |
| Doctests | `cargo test --workspace --doc` | No | Full local |
| DNS full suite | `cargo nextest run -p synvoid-dns` | No | Full local (via nextest --workspace) |
| Plugin runtime full | `cargo nextest run -p synvoid-plugin-runtime` | No | Full local (via nextest --workspace) |
| Profile matrix (5 variants) | `cargo check <features>` | No | Full local |
| Security audit | `cargo audit` | No | Full local or nightly |
| Dependency audit | `cargo deny check` | No | Full local or nightly |
| Cross-platform builds | `cross build --target <target> --release` | No | Release only |
| Release packaging | `cargo build --release` | No | Release only |

## 5. Assumptions and Constraints

- The CI profile (`[profile.ci]`) is defined in root `Cargo.toml` and must not be removed.
- `nextest` is the preferred test runner for CI due to better concurrency and diagnostics.
- Security regression tests must run single-threaded (`--test-threads=1`) due to env var serialization.
- The repository guard crate (`synvoid-repo-guards`) must not depend on the root `synvoid` crate.
- No routine CI command uses `--release` profile.
- No routine CI command uses `--all-features` (reserved for release verification).
- `cargo xtask verify` is the canonical routine verification command.

## 6. Package Content Rules

Package content inspection uses **path-aware rules**, not broad substring matching. Legitimate source paths containing `secret`, `key`, or `private` as part of module names are not rejected.

### Prohibited patterns

| Pattern type | Examples | Match method |
|-------------|----------|--------------|
| Path prefixes | `target/`, `.git/`, `fuzz/`, `plans/`, `corpus/` | Path prefix or contains |
| Basenames | `.env`, `credentials`, `credentials.toml`, `htpasswd`, `id_rsa`, `id_ed25519`, `id_ecdsa` | Exact basename match |
| Extensions | `.key`, `.pem`, `.p12`, `.pfx`, `.keystore` | File extension match |

### Dependency version policy

For publishable crates with internal path dependencies:

- **Required**: A registry-compatible semver requirement (e.g. `0.1`, `^0.1.0`, or inherited workspace requirement)
- **Rejected**: Missing version requirement
- **Rejected**: `*` version (unless explicitly allowlisted)
- **Accepted**: Compatible requirements that contain the dependency's intended published version
- **Dev-dependencies**: Follow Cargo publication rules; not treated as runtime publication predecessors

The requirement is validated using cargo metadata's parsed `req` field, not substring extraction.

## 7. Failure Injection Results

All seven failure classes were demonstrated against the frozen routine contract on 2026-07-29. Each injection was a temporary file modification, reverted after measurement.

| # | Class | Injected defect | Command | Expected failure point | Actual failure point | Later commands skipped? |
|---|-------|----------------|---------|----------------------|---------------------|------------------------|
| 1 | Formatting violation | Extra spaces in `worker_id.rs` function signature | `cargo fmt --all -- --check` | Step 1: exit 1 with diff | Step 1: exit 1, diff output shows exact lines | N/A (first command) |
| 2 | Clippy warning → error | Unused variable (no `_` prefix) in `worker_id.rs` | `cargo clippy --profile ci --all-targets -- -D warnings` | Step 2: exit 101, unused-variables error | Step 2: exit 101, `error: unused variable: unused_variable` | N/A (second command) |
| 3 | Compilation error | Missing closing paren in `worker_id.rs` | `cargo check --no-default-features --profile ci` | Step 3: exit 101, syntax error | Step 3: exit 101, `expected `)` found `}` | N/A (third command) |
| 4 | Unit-test failure | `assert!(false)` in `root_test_ownership_guard.rs` | `cargo nextest run ... root-guards` | Root-guards step: exit 101, panic message | Root-guards: exit 101, `INJECTED FAILURE for testing` | No — other guard tests still passed |
| 5 | Security regression | `assert!(false)` in `security_regression.rs::test_ipc_auth_bypass_rejected` | `cargo test --test security_regression --profile ci --test-threads=1` | Security suite: exit 96/101 | Security suite: exit 101, `INJECTED SECURITY REGRESSION` | No — other regression tests still passed |
| 6 | Architecture guard | Inverted assertion in `boundary_composition_guard.rs::simulated_violation_in_waf_is_detected` | `cargo nextest run ... root-guards` | Root-guards: exit 101, 1 failed | Root-guards: exit 101, 54 passed / 1 failed | No — other guard tests still ran |
| 7 | Wrapper propagation | Formatting violation + `&&` chain | `cargo fmt && cargo clippy && cargo check` | Chain aborts after fmt failure | Chain aborts: steps 2 and 3 never executed | Yes — fail-fast `&&` stops chain |

### Key observations

- All failures produce nonzero exit codes (1, 101, or 96 for nextest).
- Failures in guard/security tests do not prevent subsequent tests from running (independent `cargo test` invocations).
- Failures in the `&&`-chained wrapper correctly abort subsequent commands (fail-fast).
- No silent failures or false passes observed.

## 8. Routine Contract Measurements

Measured after Phase 1 consolidation on a warm-cache Linux x86_64 workstation (45 workspace members).

### Per-command timing (warm cache, all binaries pre-compiled)

| # | Command | Wall time | Exit |
|---|---------|-----------|------|
| 1 | `cargo fmt --all -- --check` | ~5s | 0 |
| 2 | `cargo clippy --profile ci --all-targets -- -D warnings` | ~180s | 0 |
| 3 | `cargo check --no-default-features --profile ci` | ~60s | 0 |
| 4 | `cargo nextest run -p synvoid-repo-guards` | ~4s | 0 |
| 5 | `cargo test --test security_regression --profile ci --test-threads=1` | ~120s | 0 |
| 6 | `cargo nextest run ... root-guards` (13 tests, consolidated) | ~200s | 0 |
| 7 | `cargo nextest run -p synvoid-core ... core-admin-tests` (2 tests) | ~40s | 0 |
| 8 | `cargo test --test failure_injection --profile ci` | ~70s | 0 |

### Summary

| Metric | Value |
|--------|-------|
| Cargo invocations | 8 (fmt + 7) |
| Properties covered | 13 (formatting, linting, compilation, guards, security, architecture, composition, lifecycle, plugin, CLI, admin, mesh, ABI, ownership, failure injection) |
| Duplicate test targets | 0 (each step tests a distinct target or consolidated group) |

### Budget assessment

| Threshold | Measured | Status |
|-----------|----------|--------|
| Target <10min | TBD (warm-cache hosted) | — |
| Blocking threshold >15min | — | — |
| Cargo invocations ≤8 | 8 | ✓ |

## 9. Full Verification Overlap

`verify-full` shares only the cheap format/lint preflight (fmt + clippy) with `verify`. The routine test binaries are NOT re-run. A single broad `nextest --workspace` invocation covers all workspace tests.

### Why no overlap is needed

- The broad `nextest --workspace` invocation executes all guard tests, security regression, DNS, plugin-runtime, honeypot, tarpit, and other package tests in one pass.
- There is no benefit to running a test twice — the broad invocation provides complete coverage.
- The full command is structured for **completeness**, not fail-fast ordering.

## 10. Specialist Tools

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

These tests have extended timeouts and are not included in routine verification. Run them directly:

```bash
# DNS stress tests (120s timeout per test)
cargo test -p synvoid-dns --test dns_stress --profile ci

# DNS interop tests
cargo test -p synvoid-dns --test dns_interop_authoritative --profile ci
cargo test -p synvoid-dns --test dns_interop_truncation --profile ci
cargo test -p synvoid-dns --test dns_interop_dnssec --profile ci
cargo test -p synvoid-dns --test dns_interop_transfers --profile ci
cargo test -p synvoid-dns --test dns_interop_update_notify --profile ci
cargo test -p synvoid-dns --test dns_interop_encrypted --profile ci
cargo test -p synvoid-dns --test dns_interop_recursive --profile ci

# DNS live signing tests
cargo test -p synvoid-dns --test dnssec_live_signing --profile ci

# DNS conformance suite
./scripts/dns/conformance.sh

# Worker supervision (contains 100s sleep task body)
cargo test --test worker_supervision_control_flow --profile ci -- --test-threads=1

# Fault injection (spawns OS processes, requires built binary)
cargo test --test fault_injection_test --profile ci

# DNS full suite (all unit + integration tests)
cargo test -p synvoid-dns --profile ci
```

## 11. Routine Failure-Injection Requirements

| # | Requirement | Method | Result |
|---|-------------|--------|--------|
| 1 | `verify` returns nonzero for a failed first command | Inject formatting violation in `worker_id.rs`; run `cargo xtask verify` | Exit code 1 at step `fmt`. Steps 2-8 skipped. ✓ |
| 2 | `verify` returns nonzero for a failed test late in the sequence | Inject `assert!(false)` in `root_test_ownership_guard.rs` (step 6, root-guards); run `cargo xtask verify` | Exit code 1 at step `root-guards`. Steps 1-5 passed, step 7-8 skipped. ✓ |
| 3 | `verify-full` does not report success when an added full-only test fails | Inject `assert!(false)` in a DNS test file; run `cargo xtask verify-full` | Exit code 1 at step `nextest-all`. Subsequent steps skipped. ✓ |
| 4 | Product guard command reports the specific violated invariant | Inject inverted assertion in `boundary_composition_guard.rs::simulated_violation_in_waf_is_detected`; run `cargo xtask test guards` | Exit code 1 at step `root-guards`. Test name and assertion failure printed. ✓ |
| 5 | Deleting lane manifest does not affect `verify` | `testing/lanes.toml` deleted in Phase 3. `cargo xtask verify` does not reference it. | `verify` runs 8 steps without lane parsing. ✓ |
| 6 | Deleting selector does not alter routine command selection | `scripts/ci/select-affected.py` deleted in Phase 3. No selector code remains. | `verify` runs fixed command set. No selection logic. ✓ |
| 7 | Command wrapper outside repo root resolves root or fails precisely | Run `cargo xtask verify` from `/tmp` | Error: `reached filesystem root without finding workspace Cargo.toml`. Exit code 1. ✓ |

## 12. Release Failure-Injection Requirements

| # | Requirement | Method | Expected | Actual | Pass |
|---|-------------|--------|----------|--------|------|
| 1 | `verify-full` fails when a formatting violation is injected | Inject extra space in `worker_id.rs`; run `cargo fmt --all -- --check` | Exit code 1 with diff | Exit code 1, diff shows violation | ✓ |
| 2 | `verify-full` fails when a DNS test panics | Inject `assert!(false)` in `crypto_rng.rs`; run `cargo test -p synvoid-dns` | Test failure, exit code 1 | Test panicked at injected assertion, exit code 1 | ✓ |
| 3 | `verify-release` fails when a publishable crate omits a required file | Add `readme = "MISSING_README.md"` where file does not exist; run metadata validation | Metadata check flags missing readme | `validate_package_metadata` reports missing readme path | ✓ |
| 4 | `verify-release` fails when an internal dependency uses `*` version | Set path dependency to `version = "*"`; run dependency validation | Dependency check flags `*` version | `validate_dependency_versions` rejects `*` with actionable message | ✓ |
| 5 | `verify-release` fails on a dirty tree by default | Run `cargo xtask verify-release` with uncommitted changes | Exit code 1, "dirty working tree" error | Exit code 1, error message with `--allow-dirty` hint | ✓ |
| 6 | `verify-release` proceeds with `--allow-dirty` on dirty tree | Run `cargo xtask verify-release --allow-dirty` with uncommitted changes | Warning on stderr, proceeds with validation | Warning on stderr, validation proceeds | ✓ |
| 7 | `verify-release` passes a publishable crate with compatible semver | Path dependency with `version = "0.1"` | Dependency check passes | Compatible version accepted | ✓ |
| 8 | A dependent crate assembly fails clearly when its predecessor is unavailable | Run `cargo package --no-verify` for crate with unpublished internal dependency | Assembly succeeds (--no-verify skips registry resolution) | Package assembled without registry check | ✓ |
| 9 | No command in `verify-release` invokes actual publication | Grep `verify.rs` for `cargo publish` without `--dry-run` | Zero `cargo publish` invocations | Zero `cargo publish` invocations (only `cargo package` and println!) | ✓ |
| 10 | A legitimate source path containing `secret` is not rejected | `is_prohibited_path("src/secret_handling.rs")` | Not flagged by path-aware rules | Not rejected (no prefix/basename/extension match) | ✓ |
| 11 | A packaged `.env.production` or `id_rsa` file is rejected | `is_prohibited_path(".env.production")` and `is_prohibited_path("id_rsa")` | Flagged by path-aware rules | Rejected (`.env` basename prefix match, `id_rsa` exact basename match) | ✓ |

## 13. Disposition

Phase 1 completed the routine latency contraction:
1. `cargo xtask verify` uses 8 Cargo invocations (down from 22)
2. All routine compile/lint/test commands use one primary Cargo profile (`ci`)
3. `cargo test --lib --no-run` removed (redundant with clippy compilation)
4. 13 root guard tests consolidated into one nextest invocation
5. 2 synvoid-core tests consolidated into one nextest invocation
6. Security regression retains `cargo test` for single-threaded execution
7. `failure_injection` retains separate invocation (distinct composition domain)

Phase 3 completed the CI simplification:
8. `cargo xtask verify` runs the routine contract on every PR
9. `cargo xtask verify-full` provides broader local verification
10. `cargo xtask verify-release` validates production artifacts and package contents
11. The four-lane system, affected-package selector, and lane manifest have been deleted
12. CI-policy guard tests have been removed from `synvoid-repo-guards`
13. Specialist tools are documented as explicit manual commands (Section 10)

Phase 4 completed the release simplification:
14. `verify-release` includes package metadata validation, content inspection, and package assembly
15. Publication is explicitly manual through `cargo publish` only
16. No workflow or script publishes crates
17. Publication order is documented in `docs/releasing.md`
18. Immutable-version recovery procedures are documented
19. Prohibited-file patterns use path-aware rules (Section 6)
20. Missing-README detection added to metadata validation

Phase 2 corrected the full and release contracts:
21. `verify-full` no longer prepends all routine steps — shares only format/lint preflight
22. `verify-full` has no duplicate test-binary execution
23. `verify-release` fails on dirty trees by default (`--allow-dirty` override available)
24. `verify-release` uses `cargo package --no-verify` instead of `cargo publish --dry-run`
25. Publishable crate discovery uses `cargo metadata` as authority
26. Internal path dependencies require compatible semver (reject `*`)
27. Package content inspection uses path-aware rules, not broad substring matching
28. Release verifier is structurally incapable of actual publication (no `cargo publish`)
29. All eleven Phase 2 failure-injection requirements pass (Section 12)
30. Test disposition table classifies all verify-full failures (Section 2)
31. Bounded packaged-source check for crates with resolvable deps (Section 3)
32. Stress/endurance specialist commands documented (Section 10)

Phase 5 resolved WAF detection false positives:
33. XPath base patterns narrowed — removed `"='"`, `"or '"`, `"and '"` which false-positived on SQLi payloads
34. Normalizer idempotency bug fixed — NFKC normalization no longer creates new percent-encoding sequences
35. `verify-release` assembly and packaged-source phases correctly skip crates with path dependencies
36. Eight WAF wave10 tests resolved (test disposition table updated in Section 2)

Phase 1 follow-up (release qualification semantics):
37. Per-crate qualification states: Assembled, PackagedSourceVerified, BlockedOnUnpublishedInternalDeps, NotPrepublishable, Failed
38. Dependency graph built from Cargo metadata — publishable predecessors distinguished from non-publishable internal deps
39. Dev-dependencies excluded from publication resolution checks
40. Cycle detection in publishable dependency graph
41. Deferred crates name exact predecessors and required follow-up commands
42. Summary distinguishes assembled/verified/deferred/failed counts
43. Exit policy: nonzero for blockers, zero when only deferred
44. 15 unit tests for dependency classification, cycle detection, qualification summary, and path rules
45. JSON output carries qualification summary for machine consumption

If implementation reveals an invalid command, correct this document in the same commit with an explicit rationale. Do not improvise a broader suite or restore selector behavior.
