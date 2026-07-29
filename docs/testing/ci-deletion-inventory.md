# CI Deletion Inventory

> Frozen: 2026-07-29 | Phase 1 of CI Simplification Roadmap
> Updated: 2026-07-29 | Phase 2 completed — single workflow collapse

This document lists every file, code section, and infrastructure component scheduled for deletion or rewrite in Phases 2–4. It is the execution manifest for the CI simplification work.

## 1. Whole-File Deletions

| Path | Current purpose | Disposition | Replacement | Phase | Verification |
|------|----------------|-------------|-------------|-------|-------------|
| `.github/workflows/ci.yml` | Redirect notice pointing to split workflows | DELETE | None (obsolete redirect) | Phase 2 | Workflow no longer appears in GitHub Actions |
| `scripts/ci/select-affected.py` | Affected-package selector (680+ lines) | DELETE | None — routine contract uses fixed command set | Phase 2 | `cargo xtask verify` passes without it |
| `scripts/test-affected.sh` | Shell wrapper for select-affected.py | DELETE | None | Phase 2 | No references remain |
| `testing/lanes.toml` | Declarative lane manifest (4 lanes, 17 sections) | DELETE | `docs/testing/verification-contract.md` is the authoritative spec | Phase 3 | `lane_manifest_exists_guard` removed or updated |
| `scripts/ci/summarize-test-costs.py` | CI cost reporting script | DELETE | None (CI self-assurance) | Phase 3 | Not referenced by any retained workflow |
| `tests/ci/test_select_affected.py` | 1200+ line test suite for select-affected.py | DELETE | None — selector deleted | Phase 3 | Tests no longer exist |

## 2. Workflow Rewrites

| Path | Current purpose | Disposition | Replacement | Phase | Verification |
|------|----------------|-------------|-------------|-------|-------------|
| `.github/workflows/pr-fast.yml` | PR fast lane: 12 jobs, affected selection, per-crate gating | REWRITE to single-job workflow | `.github/workflows/ci.yml` running `cargo xtask verify` | Phase 2 | Branch protection references new workflow; all required checks pass |
| `.github/workflows/main-comprehensive.yml` | Post-merge: 7 jobs, build matrix, DNS, plugins, profiles, docs, audits | REWRITE or SIMPLIFY | Keep as-is temporarily, then simplify in Phase 3 | Phase 3 | Full local verification covers same properties |
| `.github/workflows/nightly-qualification.yml` | Nightly: 7 jobs, Alpine, FreeBSD, Miri, fuzz, outdated | Keep for now (explicit tool) | May simplify in Phase 4 | Phase 4 | Nightly schedule unchanged |
| `.github/workflows/release-qualification.yml` | Release: 3 jobs, build matrix, full tests, clippy | Keep for now | May simplify in Phase 4 | Phase 4 | Release verification contract covers same properties |

## 3. Reusable Action Changes

| Path | Current purpose | Disposition | Replacement | Phase | Verification |
|------|----------------|-------------|-------------|-------|-------------|
| `.github/actions/setup-rust-ci/action.yml` | Composite action for Rust CI setup (toolchain, cache, nextest, cross, protoc) | SIMPLIFY | Remove unused inputs (sccache, cross) in Phase 3 | Phase 3 | Existing consumers still work |

## 4. xtask Simplification

| Path | Current purpose | Disposition | Replacement | Phase | Verification |
|------|----------------|-------------|-------------|-------|-------------|
| `tools/xtask/src/lanes.rs` | Hardcoded lane definitions (9 lanes) | SIMPLIFY — remove lane planning, affected selection, JSON output | Keep only `verify` command | Phase 3 | `cargo xtask verify` works |
| `tools/xtask/src/affected.rs` | Affected package integration | DELETE | None — no affected selection in routine CI | Phase 2 | No references remain |
| `tools/xtask/src/report.rs` | LaneReport with budget checks | SIMPLIFY | Keep only basic pass/fail reporting | Phase 3 | `cargo xtask verify` reports correctly |
| `tools/xtask/src/test.rs` | Test dispatch with 9 lane handlers | SIMPLIFY — remove lane handlers, keep verify | `verify` subcommand | Phase 3 | `cargo xtask verify` works |

## 5. Guard Test Modifications

These files are in `tools/synvoid-repo-guards/tests/` and contain tests that assert CI-specific infrastructure exists. They need targeted removal or rewriting.

### `ci_policy_guard.rs` — Remove or rewrite these tests:

| Test | Current purpose | Disposition | Phase |
|------|----------------|-------------|-------|
| `lane_manifest_exists_guard` | Asserts `testing/lanes.toml` exists | DELETE — lanes.toml deleted | Phase 3 |
| `no_release_in_pr_guard` | Checks pr-fast.yml for --release | REWRITE — check new ci.yml | Phase 2 |
| `selector_script_exists_guard` | Asserts `select-affected.py` exists | DELETE — script deleted | Phase 2 |
| `test_affected_script_exists_guard` | Asserts `test-affected.sh` exists | DELETE — script deleted | Phase 2 |
| `ci_lane_consistency_guard` | Validates pr-fast.yml commands match lanes.toml | DELETE — both deleted | Phase 2 |

Keep these tests (product-level, not CI-self-assurance):

| Test | Purpose | Keep? |
|------|---------|:-----:|
| `xtask_exists_guard` | xtask crate must exist | Yes |
| `ci_profile_configured_guard` | [profile.ci] must exist | Yes |
| `performance_budgets_exist_guard` | Performance docs must exist | Yes |
| `flaky_test_policy_exist_guard` | Flaky test policy must exist | Yes |
| `coverage_matrix_exist_guard` | Coverage matrix must exist | Yes |
| `operating_guide_exist_guard` | Operating guide must exist | Yes |
| `new_root_test_ownership_guard` | Root tests must be tracked | Yes |
| `no_lto_in_ci_profile_guard` | CI profile must not use LTO | Yes |

### `cache_and_selector.rs` — Remove or rewrite these tests:

| Test | Current purpose | Disposition | Phase |
|------|----------------|-------------|-------|
| `pinned_action_versions_guard` | Checks workflow action versions | KEEP — still validates retained workflows | Phase 2 |
| `selector_script_exists_guard` | Asserts select-affected.py exists | DELETE | Phase 2 |
| `setup_rust_action_exists_guard` | Asserts setup-rust-ci action exists | KEEP | Phase 2 |
| `no_affected_selection_in_release_nightly_guard` | Checks release/nightly don't use selector | DELETE — selector deleted | Phase 2 |
| `test_affected_script_exists_guard` | Asserts test-affected.sh exists | DELETE | Phase 2 |
| `selector_predicate_polarity_guard` | Checks for inverted mode != 'full' pattern | DELETE — selector deleted | Phase 2 |
| `selector_gated_job_predicate_structure_guard` | Validates gated job predicate structure | DELETE — no more gated jobs | Phase 2 |
| `selector_normalization_step_guard` | Validates normalize step in pr-fast.yml | DELETE — pr-fast.yml rewritten | Phase 2 |
| `cache_policy_exists_guard` | Asserts cache-policy.md exists | KEEP | Phase 2 |
| `ownership_manifest_guard` | Validates OWNERSHIP.toml structure | KEEP | Phase 2 |

## 6. Documentation Updates Required

| File | Changes needed | Phase |
|------|---------------|-------|
| `AGENTS.md` | Update Quick Commands to include `cargo xtask verify`; remove affected-package references; update CI Testing Infrastructure section; update Test Orchestration section | Phase 2 |
| `README.md` | Update CI Testing section; remove four-lane table; add verification contract reference | Phase 2 |
| `docs/testing/ci-lane-policy.md` | Rewrite or archive — four-lane policy replaced by verification contract | Phase 3 |
| `docs/testing/ci-performance-baseline.md` | Archive historical data; update with new contract measurements | Phase 3 |
| `docs/testing/test-suite-ownership.md` | Simplify — remove lane columns, keep test ownership | Phase 3 |
| `docs/testing/coverage-equivalence-matrix.md` | Archive — no longer applicable with simplified CI | Phase 3 |
| `docs/testing/cache-policy.md` | Simplify — remove per-lane cache config | Phase 3 |
| `docs/testing/feature-target-matrix.md` | Archive — matrix concept removed from routine CI | Phase 3 |
| `docs/testing/performance-budgets.md` | Update — keep budget thresholds, remove lane-specific budgets | Phase 3 |
| `docs/testing/operating-guide.md` | Rewrite — simplified CI operation | Phase 3 |
| `docs/testing/failure-injection-procedure.md` | Update — remove workflow-specific failure scenarios | Phase 3 |
| `docs/testing/hosted-runner-baseline.md` | Archive — hosted runner concept removed | Phase 3 |
| `docs/testing/milestone-b-results.md` | Archive — historical milestone | Phase 3 |
| `docs/testing/nextest-policy.md` | Keep — still relevant | No change |
| `docs/testing/root-test-ownership.md` | Keep — still relevant | No change |
| `docs/testing/architecture-guard-ownership.md` | Update — remove CI-policy guard references | Phase 3 |
| `docs/testing/test-taxonomy.md` | Simplify — remove CI-lane taxonomy | Phase 3 |
| `docs/testing/test-resource-inventory.md` | Keep — still relevant | No change |
| `scripts/verify_architecture.sh` | Rewrite or delete — legacy script, guards now cover its checks | Phase 3 |

## 7. Items NOT Deleted (Product Assurance)

These are retained because they prove product properties, not CI structure:

- All architecture guard tests that check source code structure (composition boundary, lifecycle, plugin, CLI, security, mesh, ABI, etc.)
- `tests/OWNERSHIP.toml` and the `root_test_ownership_guard`
- `tools/synvoid-repo-guards/` crate (minus CI-specific guards)
- `scripts/check_imports.py` (forbidden import checks)
- `docs/testing/performance-budgets.md` (threshold definitions)
- `docs/testing/flaky-test-policy.md` (quarantine policy)
- `docs/testing/nextest-policy.md` (runner policy)
- `docs/testing/test-resource-inventory.md` (resource usage)
- `deny.toml` (dependency policy)

## 8. Items NOT Deleted (Explicit Tools)

These are intentionally kept as explicit, separately-invoked tools:

- Fuzz smoke tests (17 targets) — invoked via `cargo +nightly fuzz run`
- Miri tests — invoked via `cargo miri test`
- Cross-platform builds — invoked via `cross build`
- Alpine/FreeBSD tests — invoked via nightly workflow or manual dispatch
- Outdated dependency checks — invoked via `cargo outdated`
- Stress/endurance tests — not yet implemented

## 9. Deletion Sequencing

| Phase | Deletions | Prerequisites |
|-------|-----------|---------------|
| Phase 2 | `pr-fast.yml` rewrite, `select-affected.py`, `test-affected.sh`, xtask affected module, CI-specific guard tests | `cargo xtask verify` implemented and tested |
| Phase 3 | `lanes.toml`, `summarize-test-costs.py`, `test_select_affected.py`, xtask lane system, CI docs simplification | Phase 2 merged and verified |
| Phase 4 | `ci.yml` redirect, remaining CI docs archive, `verify_architecture.sh` rewrite, setup-rust-ci simplification | Phase 3 merged and verified |

## 10. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Deleting affected selector removes fast-feedback for large PRs | The routine contract is bounded (<10min); affected selection saved ~30% on large PRs but added significant maintenance |
| Guard tests that check CI infrastructure will fail after deletion | Guard tests are updated in same phase as deletions |
| Branch protection references old workflow job names | Phase 2 updates branch protection to reference new workflow |
| Historical CI docs become misleading | Archive with clear "historical" header; don't delete |
| xtask lane commands break for developers | `cargo xtask verify` replaces lane commands; `list` and `explain` updated |
