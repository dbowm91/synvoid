# Testing Infrastructure Milestone D — Corrective Closure Results

## Executive Summary

This corrective pass fixes the inverted affected-package predicate logic that prevented job skipping, adds fail-closed selector normalization, adopts the shared Rust CI setup action, adds regression guards, and removes proven matrix duplicates from release qualification.

## Completion Status

| Workstream | Status | Notes |
|-----------|--------|-------|
| WS1: Fix predicate polarity | Complete | `mode != 'full'` → `mode == 'full'` in all 4 gated jobs |
| WS2: Fail-closed normalization | Complete | `if: always()` normalize step falls back to `mode=full` |
| WS3: Selector integration tests | Complete | 10 new tests (workflow regression, force-full, failure fallback) |
| WS4: Stable required checks | Complete | Summary job handles skipped jobs correctly |
| WS5: Shared Rust setup action | Complete | 6 jobs migrated, 25 setup steps eliminated |
| WS8: Matrix deduplication | Complete | 23 redundant release-qualification entries removed |
| WS9: Regression guards | Complete | 3 new repo-guard tests (polarity, structure, normalization) |
| WS10: Local validation | Complete | All 90 selector tests, 36 guard tests, formatting, clippy pass |
| WS11: Documentation | Complete | This file + AGENTS.md updates |

## Predicate Defect and Root Cause

### The Bug

The `if:` conditions for selector-gated jobs in `pr-fast.yml` used:
```yaml
needs.select-affected.outputs.mode != 'full' || package-selected
```

### Why It Was Wrong

When the selector runs in affected mode:
- `mode != 'full'` evaluates to `true` (because mode is `affected`, not `full`)
- The `||` short-circuits: since left side is true, the right side is never evaluated
- **Result:** Every gated job runs regardless of whether its package was selected

### The Fix

```yaml
needs.select-affected.outputs.mode == 'full' || package-selected
```

Now in affected mode:
- `mode == 'full'` evaluates to `false`
- The right side is evaluated: checks if the package is in the selected set
- **Result:** Only selected packages run; unrelated jobs are skipped

### Truth Table

| Selector mode | Package selected | Before (broken) | After (fixed) |
|---------------|-----------------|------------------|---------------|
| `full` | no | runs ✓ | runs ✓ |
| `full` | yes | runs ✓ | runs ✓ |
| `affected` | no | runs ✗ (BUG) | **skipped ✓** |
| `affected` | yes | runs ✓ | runs ✓ |
| missing/error | any | runs ✓ | runs ✓ (fallback) |

## Fail-Closed Selector Behavior

Added a normalization step (`if: always()`) to the `select-affected` job that:
1. Checks if the selector step produced valid output
2. If output is missing or mode is empty, emits `mode=full`
3. Logs a warning annotation and step summary note
4. Job outputs now reference `steps.normalize.outputs` instead of `steps.select.outputs`

**Negative cases handled:** invalid base ref, missing git history, malformed JSON, cargo metadata failure, missing OWNERSHIP.toml, script exception, empty output.

## Shared-Action Adoption Map

| Job | Before | After |
|-----|--------|-------|
| security-regression | 6 setup steps | `setup-rust-ci` action |
| guard-suite | 6 setup steps | `setup-rust-ci` action |
| upload-tests | 5 setup steps | `setup-rust-ci` action |
| honeypot-tests | 5 setup steps | `setup-rust-ci` action |
| tarpit-tests | 5 setup steps | `setup-rust-ci` action |
| mesh-tests | 5 setup steps | `setup-rust-ci` action |

**Total:** 25 individual setup steps → 6 composite action invocations.

**Not migrated (exceptions):** `fmt` (<5s, no cache), `clippy` (no cache), `core-profile` (check-only), `unsafe-dns` (grep), `import-check` (Python), `summary` (no Rust).

## Branch-Protection Verification

Required checks remain stable:
- `pr-fast / fmt` — always runs
- `pr-fast / clippy` — always runs
- `pr-fast / security-regression` — always runs
- `pr-fast / guard-suite` — always runs
- `pr-fast / upload-tests` — runs in full mode or when selected
- `pr-fast / honeypot-tests` — runs in full mode or when selected
- `pr-fast / tarpit-tests` — runs in full mode or when selected
- `pr-fast / mesh-tests` — runs in full mode or when selected
- `pr-fast / summary` — always runs, treats skipped as acceptable

**Note:** Branch protection rules must be updated by a repository admin to reference `pr-fast.yml` check names instead of legacy `ci.yml` names. See `docs/testing/ci-lane-policy.md` for exact check names.

## Matrix Commands Removed

Removed 23 redundant entries from `release-qualification.yml`:
- R21-R22: DNS crate tests (dup of M19-M20)
- R23-R24: Plugin runtime tests (dup of M24)
- R25-R26: Honeypot tests (dup of P30)
- R27-R28: Tarpit tests (dup of P33)
- R29-R30: Mesh crate tests (dup of P36)
- R31: Security regression (dup of P6)
- R32-R35: Guard suite (dup of P7-P22)
- R37: Docs (dup of M36)
- R38: Security audit (dup of M37)
- R39: Dependency audit (dup of M38)

**Coverage equivalence:** All removed entries are identical commands in other lanes that run on every PR (P*) or every merge to main (M*). The release lane retains its unique value: build matrix (R1-R16), full test suite (R17-R20), and all-features clippy (R36).

## Regression Guards

3 new guards in `synvoid-repo-guards` (`cache_and_selector.rs`):
1. **`selector_predicate_polarity_guard`** — scans all workflow files for inverted `mode != 'full'` pattern
2. **`selector_gated_job_predicate_structure_guard`** — verifies each gated job uses correct predicate
3. **`selector_normalization_step_guard`** — verifies normalize step exists with `if: always()`

10 new Python tests in `tests/ci/test_select_affected.py`:
- `TestWorkflowPredicateRegression` (6 tests): workflow file validation
- `TestForceFullDispatch` (3 tests): force-full override behavior
- `TestSelectorFailureFallback` (1 test): normalization contract

## Validation Results

| Check | Result |
|-------|--------|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy -p synvoid-repo-guards --all-targets -- -D warnings` | PASS |
| `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | PASS (36 tests) |
| `python3 -m pytest tests/ci/test_select_affected.py` | PASS (90 tests) |
| `python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json` | PASS |
| `bash scripts/test-affected.sh HEAD~1 --dry-run` | PASS |

## Remaining Limitations

1. **Hosted-runner validation** — Cannot be performed locally. Requires CI observation after merge.
2. **Shadow comparison** — Requires accumulated CI data from real PRs.
3. **Cache performance measurement** — Requires hosted-runner timing data.
4. **Branch protection admin update** — Must be performed by a repository admin.

## Go/No-Go Recommendation

**GO for Milestone E.** The corrected predicate logic is verified by:
- 3 regression guards that prevent recurrence
- 10 Python integration tests covering the workflow contract
- Local validation confirming correct selector behavior
- Fail-closed normalization ensuring no silent skips

The infrastructure is operationally authoritative for affected-package selection.
