# Controlled Failure Injection Procedure

Documented procedure for proving each CI lane detects its representative failure. Each injection is performed on a temporary branch, verified, then cleaned up. **Never merge intentional failures to `main`.**

---

## Overview

| # | Injection | Expected Lane | Expected Detection |
|---|-----------|---------------|-------------------|
| 1 | Formatting violation | PR fast (fmt) | `cargo fmt --check` fails |
| 2 | Clippy warning | PR fast (clippy) | `cargo clippy -D warnings` fails |
| 3 | Unit-test assertion failure | PR fast (affected crate) | nextest reports failure |
| 4 | Domain integration failure | PR fast / Main comprehensive | crate test fails |
| 5 | Root composition failure | PR fast (guard-suite) | guard test fails |
| 6 | Architecture-boundary violation | PR fast (guard tests) | boundary guard detects |
| 7 | Security-regression failure | PR fast (security-regression) | security test fails |
| 8 | Selector failure → full fallback | PR fast (normalization step) | fallback to mode=full |
| 9 | Omitted ownership entry | PR fast (root_test_ownership_guard) | untracked test detected |
| 10 | Release-profile workflow regression | Structural guards | `no_release_in_pr_guard` detects |
| 11 | Platform-specific compile error | Main comprehensive (cross) | cross-compilation fails |
| 12 | Fuzz target crash fixture | Nightly qualification | fuzz run exits non-zero |
| 13 | Release build failure | Release qualification | `--release` build fails |

---

## Injection 1: Formatting Violation

**Patch:** Add an unformatted line to any `.rs` file.

```bash
git checkout -b failure-injection/fmt-violation
echo "fn  bad_format( ){" >> src/main.rs
git add src/main.rs && git commit -m "inject: formatting violation"
```

**Expected:** `pr-fast / fmt` job fails. `cargo fmt --all -- --check` exits non-zero.

**Verification:** Open PR, confirm fmt job is red, all other jobs unaffected.

**Cleanup:** `git checkout main && git branch -D failure-injection/fmt-violation`

---

## Injection 2: Clippy Warning

**Patch:** Add code that triggers a clippy warning.

```bash
git checkout -b failure-injection/clippy-warning
# Add to any lib.rs: let x = 1; let y = &x; println!("{}", y);
git add -A && git commit -m "inject: clippy warning"
```

**Expected:** `pr-fast / clippy` job fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/clippy-warning`

---

## Injection 3: Unit-Test Assertion Failure

**Patch:** Add a failing test to a crate.

```bash
git checkout -b failure-injection/test-failure
# Add to crates/synvoid-utils/src/lib.rs #[cfg(test)] mod t { #[test] fn fail() { assert!(false); } }
git add -A && git commit -m "inject: failing unit test"
```

**Expected:** `pr-fast / upload-tests` (or affected crate job) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/test-failure`

---

## Injection 4: Domain Integration Failure

**Patch:** Break a domain crate's integration test.

```bash
git checkout -b failure-injection/domain-integration
# Modify a DNS integration test to assert incorrect expected output
git add -A && git commit -m "inject: domain integration failure"
```

**Expected:** `pr-fast / dns-tests` (or affected) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/domain-integration`

---

## Injection 5: Root Composition Failure

**Patch:** Break a root composition test.

```bash
git checkout -b failure-injection/root-composition
# Modify tests/integration_test.rs to fail an assertion
git add -A && git commit -m "inject: root composition failure"
```

**Expected:** `pr-fast / guard-suite` (root guard tests) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/root-composition`

---

## Injection 6: Architecture-Boundary Violation

**Patch:** Add a forbidden import to a request-path module.

```bash
git checkout -b failure-injection/boundary-violation
# Add "use crate::block_store::BlockStore;" to src/waf/mod.rs
git add -A && git commit -m "inject: architecture boundary violation"
```

**Expected:** `pr-fast / guard-suite` (`boundary_composition_guard`) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/boundary-violation`

---

## Injection 7: Security-Regression Failure

**Patch:** Modify a security regression test to fail.

```bash
git checkout -b failure-injection/security-regression
# Change an expected value in tests/security_regression.rs
git add -A && git commit -m "inject: security regression failure"
```

**Expected:** `pr-fast / security-regression` fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/security-regression`

---

## Injection 8: Selector Failure → Full Fallback

**Patch:** Break the affected-package selector output.

```bash
git checkout -b failure-injection/selector-failure
# Add "exit 1" at the top of scripts/ci/select-affected.py
git add -A && git commit -m "inject: selector failure"
```

**Expected:** `pr-fast / select-affected` fails, normalization step falls back to `mode=full`, all package tests run.

**Cleanup:** `git checkout main && git branch -D failure-injection/selector-failure`

---

## Injection 9: Omitted Ownership Entry

**Patch:** Add a new root test file without adding it to `OWNERSHIP.toml`.

```bash
git checkout -b failure-injection/ownership-omission
echo "#[test] fn orphan() {}" > tests/orphan_test.rs
git add tests/orphan_test.rs && git commit -m "inject: unowned test file"
```

**Expected:** `pr-fast / guard-suite` (`root_test_ownership_guard`) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/ownership-omission`

---

## Injection 10: Release-Profile Workflow Regression

**Patch:** Add `--release` to a non-security-regression step in `pr-fast.yml`.

```bash
git checkout -b failure-injection/release-regression
# In .github/workflows/pr-fast.yml, change a cargo test line to include --release
git add -A && git commit -m "inject: release profile in PR lane"
```

**Expected:** `pr-fast / guard-suite` (`no_release_in_pr_guard`) or `ci_lane_consistency_guard` fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/release-regression`

---

## Injection 11: Platform-Specific Compile Error

**Patch:** Add platform-gated code that fails on a specific target.

```bash
git checkout -b failure-injection/platform-error
# Add #[cfg(target_os = "freebsd")] compile_error!("injected") to a lib.rs
git add -A && git commit -m "inject: platform compile error"
```

**Expected:** `main-comprehensive / build` (FreeBSD matrix entry) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/platform-error`

---

## Injection 12: Fuzz Target Crash Fixture

**Patch:** Add a fuzz target that panics on specific input.

```bash
git checkout -b failure-injection/fuzz-crash
# Add a fuzz target in fuzz/fuzz_targets/ that panics on "crash"
git add -A && git commit -m "inject: fuzz crash fixture"
```

**Expected:** `nightly-qualification / fuzz-smoke` fails when running that target.

**Cleanup:** `git checkout main && git branch -D failure-injection/fuzz-crash`

---

## Injection 13: Release Build Failure

**Patch:** Add code that only compiles in release mode and fails.

```bash
git checkout -b failure-injection/release-build
# Add #[cfg(not(debug_assertions))] compile_error!("release-only failure") to a lib.rs
git add -A && git commit -m "inject: release build failure"
```

**Expected:** `release-qualification / build` (release profile) fails.

**Cleanup:** `git checkout main && git branch -D failure-injection/release-build`

---

## Execution Checklist

For each injection:

1. Create branch: `git checkout -b failure-injection/<name>`
2. Apply patch
3. Commit with `inject:` prefix
4. Push and open PR (or use `workflow_dispatch` for non-PR lanes)
5. Observe which CI job detects the failure
6. Record result in the table below
7. Close PR / delete branch (never merge)
8. Verify `main` CI is green after cleanup

## Results Record

| # | Injection | Branch | Date | Detected By | Branch Protected | Local Repro Match |
|---|-----------|--------|------|-------------|-----------------|-------------------|
| 1 | fmt violation | | | | | |
| 2 | clippy warning | | | | | |
| 3 | test failure | | | | | |
| 4 | domain integration | | | | | |
| 5 | root composition | | | | | |
| 6 | boundary violation | | | | | |
| 7 | security regression | | | | | |
| 8 | selector failure | | | | | |
| 9 | ownership omission | | | | | |
| 10 | release regression | | | | | |
| 11 | platform compile | | | | | |
| 12 | fuzz crash | | | | | |
| 13 | release build | | | | | |

Fill this table after executing each injection. Retain this document as evidence for the Milestone F closure report.
