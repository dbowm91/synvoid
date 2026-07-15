# Testing Operating Guide

Operator guide for running the SynVoid test suite, interpreting results, and troubleshooting failures. Covers local execution, CI lanes, xtask commands, test ownership, and performance budgets.

---

## 1. Quick Reference

One-command cheat sheet for the most common workflows.

| When | Command | What it runs |
|------|---------|-------------|
| Before committing | `cargo xtask test fast` | Format, clippy, guards, security, core compile, affected tests |
| Before opening PR | `cargo xtask test fast` | Same as above |
| Run affected tests only | `cargo xtask test affected --base origin/main` | Tests for changed packages + their dependents |
| Force full validation | `cargo xtask test comprehensive` | All profiles, all crates, all guards, doctests |
| Reproduce CI failure | `cargo xtask test package <name>` | nextest on a single package |
| Run all guards | `cargo xtask test guards` | 16 guard tests (repo-guards crate + 15 standalone) |
| Run security only | `cargo xtask test security` | Security regression tests (single-threaded) |
| Dry-run any lane | `cargo xtask test fast --dry-run` | Print commands without executing |
| Machine-readable output | `cargo xtask test fast --json` | JSON report for CI integration |

---

## 2. Test Execution Commands

### 2.1 xtask Commands

xtask is the primary entry point for local test execution. Run from workspace root.

| Command | Description | Steps |
|---------|-------------|-------|
| `cargo xtask test fast` | PR fast lane (<10 min target) | fmt → clippy → guards → security → core compile → affected |
| `cargo xtask test affected --base <ref>` | Affected package tests only | selector → per-package nextest → root tests → doctests |
| `cargo xtask test package <name>` | Single package | `cargo nextest run -p <name> --cargo-profile ci --profile ci` |
| `cargo xtask test guards` | All guard tests | repo-guards crate (nextest) + 15 standalone `cargo test --test` |
| `cargo xtask test security` | Security regression | `cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1` |
| `cargo xtask test comprehensive` | Full workspace validation | fmt, clippy, 5 profile checks, nextest all, doctests, guards, security |
| `cargo xtask test nightly-plan` | Preview nightly qualification | Prints commands without executing |
| `cargo xtask test qualification` | Preview release qualification | Prints commands without executing |
| `cargo xtask test release` | Preview release validation | Prints commands using `--release` profile |
| `cargo xtask test list` | List all lanes | Prints lane names, descriptions, step counts |
| `cargo xtask test explain <lane>` | Explain a lane | Prints every step name and command |

**Flags:**

| Flag | Effect |
|------|--------|
| `--dry-run` | Print commands without executing |
| `--json` | Machine-readable JSON output |
| `--verbose` | Print each command before execution |

### 2.2 Direct Cargo Commands

For debugging or running specific subsets outside xtask.

```bash
# Full test suite with CI profile (fast, no LTO)
cargo test --profile ci --no-fail-fast

# Single test by name (lib tests)
cargo test --lib <test_name>

# Integration test by file
cargo test --test <integration_test_name>

# All crate tests via nextest (preferred for parallelism)
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz

# Doctests (nextest doesn't run these)
cargo test --workspace --doc --profile ci

# Single crate with nextest
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci

# Clippy with all features
cargo clippy --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check

# Compile check (all profiles)
cargo check --no-default-features              # Core
cargo check --no-default-features --features mesh   # Mesh only
cargo check --no-default-features --features dns    # DNS only
cargo check --no-default-features --features mesh,dns  # Full
```

### 2.3 nextest Commands

nextest is the preferred runner for parallel test execution in CI.

```bash
# Run all workspace tests (exclude fuzz)
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz

# Run a specific package
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci

# Run a single test by filter
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci -- 'test_name'

# List all tests without running
cargo nextest list --workspace --cargo-profile ci --profile ci

# Run with specific profile
cargo nextest run --cargo-profile ci --profile ci

# Re-run only failed tests from last run
cargo nextest run --workspace --cargo-profile ci --profile ci --retries 0
```

### 2.4 Affected Selection

The affected package selector computes which packages changed since a base ref and runs only their tests plus transitively affected root tests.

```bash
# Run affected tests for a PR
cargo xtask test affected --base origin/main

# Preview affected packages (dry-run)
cargo xtask test affected --base origin/main --dry-run

# Direct selector invocation
python3 scripts/ci/select-affected.py --base origin/main --head HEAD --format text
python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json --dry-run
```

The selector output includes:
- `mode`: `affected` (incremental) or `full` (all tests)
- `packages`: list of affected packages
- `root_tests`: list of affected root integration tests

When the selector fails or produces invalid output, it falls back to `mode=full` (fail-closed).

### 2.5 Root Test Execution

Root integration tests live in `tests/` and are governed by `tests/OWNERSHIP.toml`. Every root test must have an ownership entry.

```bash
# Run a specific root guard test
cargo test --test boundary_composition_guard

# Run the ownership guard (validates OWNERSHIP.toml completeness)
cargo test --test root_test_ownership_guard

# Run security regression (single-threaded, env var serialization required)
cargo test --test security_regression -- --test-threads=1
```

### 2.6 Crate-Level Tests

Per-crate tests run within each crate's own directory and are the preferred location for domain-specific tests.

| Crate | Command | Lane | Notes |
|-------|---------|------|-------|
| synvoid-dns | `cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci` | PR (full on main) | 1101 tests, 31 binaries |
| synvoid-plugin-runtime | `cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci` | PR | 389 tests |
| synvoid-upload | `cargo nextest run -p synvoid-upload --cargo-profile ci --profile ci` | PR (affected) | default + mesh features |
| synvoid-honeypot | `cargo nextest run -p synvoid-honeypot --cargo-profile ci --profile ci` | PR (affected) | |
| synvoid-tarpit | `cargo nextest run -p synvoid-tarpit --all-targets --cargo-profile ci --profile ci` | PR (affected) | |
| synvoid-mesh | `cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci` | PR (affected) | |

---

## 3. CI Lane Details

SynVoid CI uses four validation lanes. Each lane has a specific trigger, permitted workload, and merge-blocking authority.

**Source of truth:** `testing/lanes.toml` defines the canonical commands for each lane. CI workflows are validated against it by `ci_lane_consistency_guard` in `synvoid-repo-guards`. If you change a command in CI, update `testing/lanes.toml` and the xtask `lanes.rs` to match.

### 3.1 PR Fast Lane

| Property | Value |
|----------|-------|
| **Trigger** | Pull requests to main/master |
| **Target duration** | <10 minutes |
| **Required for merge** | Yes |
| **Concurrency** | Superseded PR runs are automatically cancelled |

**What it runs:**

1. `cargo fmt --all -- --check` — formatting gate
2. `cargo clippy --all-targets -- -D warnings` — lint gate
3. `cargo check --no-default-features` — core-only compilation
4. `python scripts/check_imports.py` — forbidden import boundary
5. `cargo nextest run --test security_regression -- --test-threads=1` — security regression
6. `cargo nextest run -p synvoid-repo-guards` — architecture static guards
7. 15 standalone `cargo test --test <guard>` — boundary/lifecycle/plugin/admin guards
8. Per-crate tests: dns, plugin-runtime, upload, honeypot, tarpit, mesh (affected-gated)

**What it does NOT run:**
- FreeBSD/Alpine/Miri/fuzz smoke/platform-compat/full release builds

### 3.2 Main Comprehensive Lane

| Property | Value |
|----------|-------|
| **Trigger** | Push to main/master/develop |
| **Target duration** | <30 minutes |
| **Required for merge** | No (runs post-merge) |

**What it runs:**

1. 8-target build matrix (linux glibc ×2, musl, ARM64, macOS Intel, macOS ARM, Windows, FreeBSD)
2. DNS full test suite (blanket nextest + doctests + all-features check)
3. Plugin runtime full suite (unit tests + guard tests + clippy)
4. Profile matrix (5 `cargo check` variants: default, core, mesh, dns, mesh+dns)
5. Documentation build (`cargo doc --no-deps --release`)
6. Security audit (`cargo audit`)
7. Dependency audit (`cargo deny check`)

### 3.3 Scheduled Qualification Lane

| Property | Value |
|----------|-------|
| **Trigger** | Nightly (4 AM UTC) or manual dispatch |
| **Target duration** | <60 minutes |
| **Required for merge** | No |

**What it runs:**

- Alpine Linux (musl) build + test
- FreeBSD VM build + test
- Platform compatibility cross-target check (5 targets)
- Miri safety checks (continue-on-error)
- Fuzz smoke tests (16 targets × 1000 runs each)
- Outdated dependency reporting (continue-on-error)

### 3.4 Release Qualification Lane

| Property | Value |
|----------|-------|
| **Trigger** | Version tags (v*) or manual dispatch |
| **Target duration** | <60 minutes |
| **Required for merge** | No |

**What it runs:**

1. Full release-profile build matrix (8 targets)
2. Full default + mesh test suites
3. `clippy --all-targets --all-features` (all-features lint — unique to this lane)
4. Packaging smoke test

### 3.5 Lane Coverage Summary

| Category | PR | Main | Nightly | Release |
|----------|:--:|:----:|:-------:|:-------:|
| Formatting | ✓ | ✓ | — | — |
| Clippy (default) | ✓ | ✓ | — | — |
| Clippy (all features) | — | — | — | ✓ |
| Profile matrix | — | ✓ | ✓ | — |
| DNS tests | ✓ (affected) | ✓ (full) | — | ✓ (dup) |
| Plugin tests | — | ✓ | — | ✓ (dup) |
| Mesh/Upload/Honeypot/Tarpit tests | ✓ (affected) | — | — | ✓ (dup) |
| Architecture guards | ✓ | ✓ (partial) | — | ✓ (dup) |
| Security regression | ✓ | — | — | ✓ (dup) |
| Miri | — | — | ✓ | — |
| Fuzz smoke | — | — | ✓ | — |
| Alpine/FreeBSD build+test | — | — | ✓ | ✓ (cross only) |
| Docs build | — | ✓ | — | ✓ (dup) |
| Security/dependency audit | — | ✓ | — | ✓ (dup) |

---

## 4. Adding a New Test

### Step 1: Choose Location

**Default: put it in the owning crate.** Root integration tests (`tests/`) require justification.

| Location | When to use |
|----------|-------------|
| `crates/<crate>/src/` (unit) | Test exercises only that crate's internals |
| `crates/<crate>/tests/` (integration) | Test needs multiple modules within that crate |
| `tests/` (root) | Test requires cross-crate composition that can't live anywhere else |

If a domain test doesn't require root composition, it belongs in its owning crate (per `architecture/root_module_ledger.md`).

### Step 2: Add to OWNERSHIP.toml

If the test is in `tests/`, add an entry to `tests/OWNERSHIP.toml`:

```toml
[[test]]
name = "your_test_name"
class = "composition"          # static_policy | composition | facade | executable | platform | qualification
owners = ["synvoid-your-crate"]
reason = "validates X across Y"
```

The `root_test_ownership_guard` test enforces this invariant. Tests without an ownership entry will fail CI.

### Step 3: Classify Resource Requirements

See Section 6 for the full classification guide. At minimum, determine:

- **Fixed ports?** Use ephemeral (`:0`) or temp paths. Fixed ports require serialization.
- **Env var mutations?** Use `OnceLock<Mutex<()>>` guard. Requires `--test-threads=1` or nextest override.
- **OS process spawns?** Add RAII cleanup guard. Needs nextest `threads-required = 1`.
- **Slow (>30s)?** Document expected duration. Add nextest timeout override if >60s.

### Step 4: Update Feature/Target Matrix

If the test requires specific features (e.g., `mesh`, `dns`, `mesh,dns`), document them in the ownership entry and ensure the CI lane that runs it uses the correct features.

### Step 5: Budget Classification

| Budget | New test impact |
|--------|----------------|
| Root integration test file | **BLOCKING** — requires OWNERSHIP.toml entry |
| New release-mode routine test | **BLOCKING** — must use `--profile ci` |
| New fixed port | **BLOCKING** — must use `:0` |
| New serialization override | **BLOCKING** — must document in test-suite-ownership.md |
| Slow test (>30s) | **Warning** — requires comment explaining duration |
| Slow test (>60s) | **Blocking** — requires fix, exception, or budget adjustment |

---

## 5. Adding a Fuzz Target

Fuzz targets live in `fuzz/fuzz_targets/` and are run nightly in the scheduled qualification lane.

### Step 1: Create the Target

```rust
// fuzz/fuzz_targets/your_target.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz your parser/function here
});
```

### Step 2: Add to Cargo.toml

```toml
# fuzz/Cargo.toml
[[bin]]
name = "your_target"
path = "fuzz_targets/your_target.rs"
test = false
doc = false
bench = false
```

### Step 3: Add Smoke Test Entry

Add to the fuzz smoke matrix in `nightly-qualification.yml`:

```yaml
- cargo +nightly fuzz run your_target -- -runs=1000
```

### Step 4: Verify

```bash
cargo +nightly fuzz run your_target -- -runs=100
```

---

## 6. Classifying Resource Requirements

Every test should be classified by its resource requirements. This determines serialization rules, nextest overrides, and which CI lane can run it.

### 6.1 Fixed Ports

Any hardcoded port (not `:0` or ephemeral) in a test file.

**Rule:** All test port bindings must use ephemeral ports (`:0`) or temp paths. Fixed ports require serialization and are **blocking** on first occurrence.

```
BLOCKING: New fixed port in tests/
```

**Existing fixed ports:** `synvoid-tunnel` has `0.0.0.0:51821` in `src/quic/runtime.rs:431` — this is a production fallback, not a test bind. Grandfathered.

### 6.2 Serialization Overrides

Tests that mutate process-global state (env vars, static globals) require single-threaded execution.

| Mechanism | When to use | CI enforcement |
|-----------|-------------|----------------|
| `--test-threads=1` | Env var mutations (`set_var`/`remove_var`) | Security regression tests |
| `OnceLock<Mutex<()>>` | Env var mutations (preferred) | Nextest `threads-required = "num-cpus"` override |
| `#[serial]` attribute | When `serial_test` crate is used | Must document in test-suite-ownership.md |

**Current serialized tests:**

| Test | Resource | Enforcement |
|------|----------|-------------|
| `security_regression` | `SYNVOID_IPC_KEY_FILE` env var | `--test-threads=1` + `OnceLock<Mutex<()>>` guard |

**Rule:** New serialization overrides are **blocking** and must be documented.

### 6.3 Slow Tests

Tests exceeding 30 seconds must be classified:

| Duration | Action |
|----------|--------|
| >30s | Add comment explaining duration. Warning threshold. |
| >60s | Must fix, add tracked exception, or adjust budget. Blocking threshold. |

**Current slow tests:**

| Test | Estimated Duration | Nextest Timeout |
|------|--------------------|-----------------|
| `fault_injection_test.rs` | 10–30s | None (needs addition) |
| `worker_supervision_control_flow` | 30–120s | None (needs addition) |
| DNS stress/interop/live_signing/recursion | 60–120s | 120s (configured) |
| DNS server_test/config_fidelity/recursive_isolation | 30–60s | 60s (configured) |

### 6.4 Network-Heavy Tests

Tests with multiple network binds or DNS resolution. Classify under nextest `network-heavy` group if they consistently exceed 4 parallel threads.

**Current:** No tests classified as network-heavy (reserved for future use).

### 6.5 Process-Spawn Tests

Tests that spawn OS processes (subprocesses, `Command::new`). Require:

- RAII cleanup guard (`scopeguard` or custom wrapper) to prevent orphaned processes on panic
- Nextest `threads-required = 1` override
- Timeout override (60s default)

**Current process-spawn tests:**

| Test | Processes | Nextest Override |
|------|-----------|-----------------|
| `fault_injection_test` | 4 OS processes | `threads-required = 1`, `timeout = 60s` (proposed) |

### 6.6 Nextest Override Patterns

Configure in `.config/nextest.toml`:

```toml
[[profile.default.overrides]]
threads-required = "num-cpus"
filter = 'test(security_regression)'
reason = "Env var serialization guard"

[[profile.default.overrides]]
threads-required = 1
filter = 'test(fault_injection)'
reason = "OS process spawn, no panic guard"

[[profile.default.overrides]]
timeout = 120
filter = 'test(worker_supervision_control_flow)'
reason = "Contains 100s sleep"
```

---

## 7. Updating Performance Budgets

Performance budgets are defined in `docs/testing/performance-budgets.md`. Thresholds start as warnings and are tuned using baselines from `docs/testing/ci-performance-baseline.md`.

### Budget Categories

| Metric | Warning | Blocking |
|--------|---------|----------|
| PR fast moving median | >10 min | >15 min |
| Selector duration | >30s | >60s |
| Warm local affected loop | >60s | >120s |
| Slow test | >30s | >60s |
| Cache overhead | >25% | >50% |
| Root guard binary count | >30 | >40 |
| Total Cargo invocations (PR fast) | >50 | >70 |
| Feature/target matrix size | >20 | >30 |
| Fuzz smoke duration | >15 min | >30 min |

### Structural Invariants (Blocking Immediately)

| Invariant | Rule |
|-----------|------|
| New root test file | Must be in `OWNERSHIP.toml` with justification, or moved to owning crate |
| New release-mode routine test | Must use `--profile ci` |
| New fixed port | Must use `:0` |
| New serialization override | Must document in `test-suite-ownership.md` |

### Process for Updating a Budget

1. **Warning breach:** Add PR comment explaining regression + follow-up issue
2. **Blocking breach:** Fix before merge, or add tracked exception with owner + expiry + justification
3. **Budget adjustment:** Update threshold with evidence from `ci-performance-baseline.md`, approved by CI maintainers
4. **Review cadence:** Monthly (warning thresholds), per testing milestone (full recalibration), on incident (tighten)

---

## 8. Running Release Qualification

Release qualification runs on version tags (`v*`) or manual dispatch.

### Local Reproduction

```bash
# Preview what release qualification would run
cargo xtask test qualification

# Run the full release validation sequence
cargo xtask test release

# Full release test suite (production LTO)
cargo test --release --no-fail-fast

# Clippy with all features (unique to release lane)
cargo clippy --all-targets --all-features -- -D warnings
```

### CI Release Lane

The release qualification lane runs:

1. 8-target build matrix (release profile)
2. Full default + mesh test suites (CI profile)
3. `clippy --all-targets --all-features` (unique to release lane)
4. Packaging smoke test

### What Makes Release Different

| Aspect | PR/Main | Release |
|--------|---------|---------|
| Profile | `--profile ci` (opt-level=1) | `--release` (LTO, opt-level=3) |
| Build matrix | Partial (PR: native only) | Full 8-target matrix |
| All-features lint | — | ✓ (unique) |
| sccache | Active (CI profile) | **Not used** (determinism requirement) |

---

## 9. Interpreting Artifacts and Summaries

### CI Job Outputs

| Output | Location | Meaning |
|--------|----------|---------|
| Step timing | GitHub Actions job logs | Individual step wall-clock duration |
| nextest JSON | `target/nextest/` | Per-test timing, status, and binary |
| xtask JSON report | stdout (with `--json`) | Step-level success/failure/duration |
| Guard test results | `cargo test --test <guard>` output | Architecture invariant pass/fail |
| Flaky test report | Nightly qualification lane | Quarantined tests, days since quarantine |

### xtask JSON Report Format

```json
{
  "lane": "fast",
  "steps": [
    {
      "name": "fmt",
      "command": "cargo fmt --all -- --check",
      "status": "Success",
      "duration_ms": 2340
    }
  ],
  "total": 6,
  "passed": 6,
  "failed": 0,
  "duration_ms": 45000
}
```

### Common CI Failure Patterns

| Failure | Likely Cause | Fix |
|---------|-------------|-----|
| `cargo fmt` fails | Formatting drift | `cargo fmt --all` |
| `clippy` fails | New lint or existing code | Read clippy output, apply suggestion |
| Security regression fails | Env var serialization | Ensure `--test-threads=1` |
| Guard test fails | Architecture boundary violation | Check `architecture/` docs for rules |
| DNS tests fail | Feature-gated code | Ensure `--features mesh,dns` if needed |
| Plugin tests fail | Capability boundary | Check plugin manifest and capability rules |
| nextest timeout | Slow test | Add timeout override in `.config/nextest.toml` |
| Selector fails (mode=full) | Selector error or diff too large | Falls back to full suite; check selector logs |

---

## 10. Ownership and Escalation Paths

### Test Ownership

Every test must have an owner. The `tests/OWNERSHIP.toml` manifest enforces this for root tests. Per-crate tests are owned by the crate team.

| Area | Owner | Lane | Profile |
|------|-------|------|---------|
| Root integration tests | Per `OWNERSHIP.toml` | PR | ci |
| synvoid-dns | DNS team | PR (main for full) | ci |
| synvoid-plugin-runtime | Plugin team | PR | ci |
| synvoid-upload | Upload team | PR (affected) | ci |
| synvoid-honeypot | Honeypot team | PR (affected) | ci |
| synvoid-tarpit | Tarpit team | PR (affected) | ci |
| synvoid-mesh | Mesh team | PR (affected) | ci |
| synvoid-waf | WAF team | PR | ci |
| synvoid-ipc | IPC team | PR | ci |
| synvoid-platform | Platform team | PR | ci |

### CI Job Ownership

| Job | Owner | Lane |
|-----|-------|------|
| fmt, clippy, core-profile, import-check | CI infrastructure | PR |
| security-regression | Security | PR |
| guard-suite | Architecture | PR |
| plugin-runtime-guardrails | Plugin team | PR |
| dns-tests | DNS team | Main |
| upload-tests | Upload team | PR |
| honeypot-tests | Honeypot team | PR |
| tarpit-tests | Tarpit team | PR |
| mesh-tests | Mesh team | PR |
| security-audit, dependency-audit | Security | Main |
| alpine-test, freebsd-test, platform-compat | Platform | Nightly |
| miri-test | Safety | Nightly |
| fuzz-smoke | Security | Nightly |

### Escalation Path

| Issue | First contact | Escalation |
|-------|--------------|------------|
| Flaky test | Test owner (from OWNERSHIP.toml) | CI maintainers after 7 days |
| Security test quarantine | Security team | Repository maintainer (approval required) |
| Budget breach | CI maintainers | Release managers |
| Architecture guard failure | Architecture team | Domain crate owners |
| CI infrastructure failure | CI maintainers | Repository admin |

---

## 11. Troubleshooting

### Common Issues

**Test passes locally but fails in CI:**
- Check if CI uses `--profile ci` (different from `--release`)
- Check feature flags: CI may use `--all-features` or specific combos
- Check `--test-threads`: CI may run with different parallelism
- Check platform: CI runs on `ubuntu-latest`; macOS/Windows may differ

**Test fails intermittently (flaky):**
- Follow the flaky test policy in `flaky-test-policy.md`
- Requires 3+ intermittent failures before quarantine
- Document exact command, environment, and timing correlation
- Maximum quarantine: 30 days (7 days for security-critical tests)

**Performance regression in CI:**
- Check `docs/testing/ci-performance-baseline.md` for current baselines
- Verify cache isn't busted (check `Cargo.lock` changes)
- Compare PR fast lane moving median against 15-min blocking threshold
- Use `--dry-run` to check selector duration

**nextest timeout:**
- Check `.config/nextest.toml` for existing overrides
- Add timeout override for slow tests (120s max for DNS, 60s for others)
- Consider if the test should move to a different lane

**Architecture guard failure:**
- Read the specific guard output — it tells you which boundary was violated
- Check `architecture/` docs for the relevant boundary rules
- Ensure request-path modules consume narrow traits, not concrete infrastructure

**Selector falls back to `mode=full`:**
- The affected selector failed or produced invalid output
- Check selector logs for errors
- All tests run (safe fallback, but slower)

**xtask commands diverge from CI workflows:**
- xtask lane definitions in `lanes.rs` must match CI workflow steps exactly
- Use this to verify parity after changes:
  ```bash
  # Verify xtask commands match CI workflows
  cargo xtask test fast --dry-run --json | jq '.steps[].command'
  # Compare against pr-fast.yml job steps
  ```

### Debugging Techniques

```bash
# Run a single test with backtrace
RUST_BACKTRACE=1 cargo test --lib <test_name>

# Run with verbose output
cargo test --lib <test_name> -- --nocapture

# Check what the selector would run
python3 scripts/ci/select-affected.py --base origin/main --head HEAD --dry-run

# Verify a specific guard passes
cargo test --test boundary_composition_guard -- --nocapture

# Check compilation without running tests
cargo test --lib --no-run

# Run the full ownership guard
cargo test --test root_test_ownership_guard

# Verify format and lint
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

### Useful References

| Document | Purpose |
|----------|---------|
| `testing/lanes.toml` | Machine-readable lane definitions for xtask and CI |
| `docs/testing/ci-lane-policy.md` | Lane definitions and permitted workload |
| `docs/testing/performance-budgets.md` | Budget thresholds and remediation |
| `docs/testing/flaky-test-policy.md` | Quarantine process and criteria |
| `docs/testing/coverage-equivalence-matrix.md` | Where every assurance category runs |
| `docs/testing/failure-injection-procedure.md` | Controlled failure injection for CI lane validation |
| `docs/testing/test-suite-ownership.md` | Test ownership manifest |
| `docs/testing/feature-target-matrix.md` | Complete CI command×feature×target matrix |
| `docs/testing/cache-policy.md` | Cache architecture and invalidation rules |
| `docs/testing/test-resource-inventory.md` | Resource usage catalog for all tests |
| `docs/testing/ci-performance-baseline.md` | Timing baselines and known failures |
| `architecture/root_module_ledger.md` | Root vs crate test ownership rules |
