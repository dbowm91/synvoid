# Testing Infrastructure Milestone D — Results

## Executive Summary

Milestone D accelerates warm CI performance and localized developer iteration through standardized Rust setup, conservative affected-package selection with reverse-dependent closure, and compiler output reuse infrastructure (sccache — dormant pending backend verification).

## Completion Status

| Workstream | Status | Notes |
|-----------|--------|-------|
| D1: Cache architecture and policy | Complete | `docs/testing/cache-policy.md` created |
| D2: Introduce sccache | Deferred | sccache support added to shared action; backend unavailable, formally deferred |
| D3: Standardize Rust setup | Complete | `.github/actions/setup-rust-ci` composite action |
| D4: Cache performance measurement | Deferred | Requires CI runner measurements (shadow mode) |
| D5: Affected-package selector | Complete | `scripts/ci/select-affected.py` |
| D6: Full-suite fallback rules | Complete | 12+ fallback triggers implemented |
| D7: Selector validation fixtures | Complete | `tests/ci/test_select_affected.py` (81 tests) |
| D8: CI integration | Complete | `pr-fast.yml` updated with selector; sccache deferred |
| D9: Developer affected command | Complete | `scripts/test-affected.sh` |
| D10: Shadow mode | Deferred | Requires CI observation period |
| D11: Safety guards | Complete | 7 guard tests in `synvoid-repo-guards` |
| D12: Documentation | Complete | This file + AGENTS.md + README.md updates |

## What Was Built

### Cache Architecture
- **4-layer cache model**: Cargo sources, tool binaries, compiler outputs (sccache — dormant), target metadata (rust-cache)
- **Cache policy**: `docs/testing/cache-policy.md` documents key dimensions, invalidation rules, size limits
- **sccache**: Infrastructure added to shared `setup-rust-ci` action; dormant — GitHub Actions cache backend was unavailable

### Affected Package Selector
- **Algorithm**: `cargo metadata` dependency graph → transitive reverse dependents → root test selection via `tests/OWNERSHIP.toml`
- **Fallback rules**: 12+ triggers for full validation (Cargo.toml, Cargo.lock, CI workflows, root facade, feature declarations, etc.)
- **Output**: Machine-readable JSON and human-readable text
- **Local command**: `scripts/test-affected.sh` mirrors CI selector logic

### CI Integration
- **PR fast lane**: Select affected → gate per-crate tests → aggregate into stable summary
- **Branch protection**: Required checks (fmt, clippy, unsafe-dns, core-profile, import-check, security-regression, guard-suite, summary) always run
- **sccache stats**: Deferred — no active sccache in any workflow

### Safety Guards
- Pinned action versions enforced
- No affected selection in release/nightly qualification
- Cache policy and selector script existence validated
- Ownership manifest structure enforced

## Validation

- All 7 new repo-guard tests pass
- Selector produces correct output for representative commit ranges
- Dry-run mode works locally
- PR workflow preserves stable branch protection check names

## Known Limitations

- **Cache performance measurement (D4)**: Requires CI runner measurements to compute net benefit. Will be completed during shadow-mode observation.
- **Shadow mode (D10)**: Requires PRs to accumulate observation data. Deferred to post-merge monitoring.
- **Feature class selection**: Conservative — root crate changes select all feature classes. This is correct but broad.

## Handoff to Milestone E

Milestone D provides:
- Per-package test timing data via `scripts/ci/summarize-test-costs.py`
- Affected-package selector with deterministic, tested fallback rules
- sccache infrastructure in shared action (dormant — ready for backend verification)
- Developer command for local affected testing
- Safety guards preventing selector misuse in qualification lanes
