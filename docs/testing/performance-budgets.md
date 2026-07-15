# Performance Budgets

## Overview

Performance budgets define quantitative thresholds for CI and test infrastructure metrics. They prevent regressions in developer feedback time, resource consumption, and structural invariants. Budgets start as warnings and are tuned using observed baselines from `docs/testing/ci-performance-baseline.md`. Structural invariants (new root test files, release-mode tests, fixed ports) may be blocking immediately.

## Budget Categories

| Metric | Initial Warning Threshold | Initial Blocking Threshold |
|--------|--------------------------|---------------------------|
| PR fast moving median | >10 minutes | >15 minutes |
| Selector duration | >30 seconds | >60 seconds |
| Warm local affected loop | >60 seconds for localized changes | >120 seconds |
| New root integration test file | any unapproved addition | BLOCKING |
| New release-mode routine test | any unapproved addition | BLOCKING |
| New fixed port | any unclassified addition | BLOCKING |
| New global serialization override | any unclassified addition | BLOCKING |
| Slow test | >30 seconds unless classified | >60 seconds unless classified |
| Cache restore/save overhead | >25% of job duration | >50% of job duration |
| Root guard binary count | >30 | >40 |
| Total Cargo invocation count (PR fast) | >50 | >70 |
| Feature/target matrix size | >20 entries | >30 entries |
| Fuzz smoke duration | >15 minutes | >30 minutes |

### Budget Semantics

- **Warning**: Flags drift. Requires a comment in the PR explaining the change and a plan to address.
- **Blocking**: Blocks merge. Requires either a fix, a tracked exception with owner and expiry, or a budget adjustment.
- **Unapproved addition**: Any new entry in the category requires explicit approval from the owning team before merge.

## Measurement Methodology

### PR Fast Moving Median

Track the wall-clock time of the slowest required check in the PR fast lane (`pr-fast.yml`) across the last 20 merged PRs. Use GitHub Actions timing data or local `time` measurements. The moving median smooths outliers from cold-cache builds.

```
measurement = median(job_duration_minutes) for last 20 merged PRs
```

### Selector Duration

Measure `scripts/ci/select-affected.py` wall-clock time on the current PR diff. Record at the start of the selector job.

```
measurement = time python3 scripts/ci/select-affected.py --base origin/main --head HEAD
```

### Warm Local Affected Loop

On a warm-cache local machine, run the full PR fast lane sequence (fmt, clippy, core-compile, guards, security-regression, affected packages) and measure total wall-clock time.

```
measurement = total_wall_clock after warm cache, single developer machine
```

### New Root Integration Test File

Count of `.rs` files in `tests/` that are not in the `tests/OWNERSHIP.toml` manifest. Each new file must be justified in the PR description and added to `OWNERSHIP.toml` before merge.

```
measurement = count(tests/*.rs) - count(entries in OWNERSHIP.toml)
```

### New Release-Mode Routine Test

Any `cargo test --release` invocation outside of `main-comprehensive.yml`, `nightly-qualification.yml`, or `release-qualification.yml`. Routine tests use `--profile ci`.

```
measurement = grep -r "cargo.*test.*--release" .github/workflows/pr-fast.yml | wc -l
```

### New Fixed Port

Any hardcoded port number (not `:0` or ephemeral) in test files. All test port bindings should use ephemeral ports or temp paths.

```
measurement = grep -rnE ':(8[0-9]{3}|9[0-9]{3}|[1-9][0-9]{4,})' tests/ | grep -v ephemeral | grep -v ':0'
```

### New Global Serialization Override

Any `--test-threads=1` or `#[serial]` annotation in new test code. Existing usages are grandfathered but must be documented in `test-suite-ownership.md`.

```
measurement = grep -rn "test-threads=1\|serial" tests/ | grep -v documented
```

### Slow Test

Individual test or test binary exceeding the threshold. Measured via `cargo test` wall-clock time or nextest timing output.

```
measurement = per_test_duration from nextest JSON output or cargo test -- --report-time
```

### Cache Restore/Save Overhead

Ratio of cache restore+save time to total job duration. Measure using GitHub Actions cache step timing or `before_cache`/`post` step durations.

```
measurement = (cache_restore_time + cache_save_time) / total_job_duration
```

### Root Guard Binary Count

Number of distinct guard test files in `tests/` that perform architecture boundary checks.

```
measurement = ls tests/*guard*.rs tests/*boundary*.rs | wc -l
```

### Total Cargo Invocation Count (PR Fast)

Number of distinct `cargo` commands in `pr-fast.yml`. Each invocation pays independent compilation/link overhead.

```
measurement = grep -c "cargo " .github/workflows/pr-fast.yml
```

### Feature/Target Matrix Size

Number of entries in the feature/target build matrix (feature combinations × target platforms).

```
measurement = count(features) × count(targets) in pr-fast.yml matrix
```

### Fuzz Smoke Duration

Total wall-clock time for the fuzz smoke test matrix (all targets × 1000 runs each).

```
measurement = total fuzz smoke job duration in nightly-qualification.yml
```

## Budget Ownership

| Budget | Owner | Reviewer |
|--------|-------|----------|
| PR fast moving median | CI maintainers | Release managers |
| Selector duration | CI maintainers | — |
| Warm local affected loop | CI maintainers | — |
| New root integration test file | Test ownership (`OWNERSHIP.toml`) | CI maintainers |
| New release-mode routine test | CI maintainers | Release managers |
| New fixed port | Test authors | CI maintainers |
| New global serialization override | Test authors | CI maintainers |
| Slow test | Test ownership | CI maintainers |
| Cache restore/save overhead | CI maintainers | — |
| Root guard binary count | Guard authors | CI maintainers |
| Total Cargo invocation count (PR fast) | CI maintainers | — |
| Feature/target matrix size | CI maintainers | Release managers |
| Fuzz smoke duration | Fuzz maintainers | CI maintainers |

## Remediation Paths

### Warning Threshold Breach

1. Add a comment to the PR explaining the regression and its expected duration.
2. File a follow-up issue to address the regression.
3. If the regression is permanent (e.g., a new necessary test), update the budget threshold with justification.

### Blocking Threshold Breach

1. **Fix the regression** before merge. Common fixes:
   - Move expensive tests to a more appropriate lane (comprehensive or scheduled).
   - Consolidate guard binaries to reduce link overhead.
   - Use `--profile ci` instead of `--release` for routine tests.
   - Switch hardcoded ports to ephemeral ports.
   - Remove redundant test invocations.
2. **Tracked exception**: If the breach is justified, add a tracked exception to this file with:
   - Owner name
   - Expiry date
   - Justification
   - Plan to resolve
3. **Budget adjustment**: If the baseline has permanently shifted, update the threshold with evidence from `ci-performance-baseline.md`.

### Structural Invariant Breach (Blocking Immediately)

These budgets are blocking from first occurrence:

- **New root integration test file**: Must be added to `tests/OWNERSHIP.toml` with a justification, or moved to an owning crate per the composition boundary rules in `architecture/root_module_ledger.md`.
- **New release-mode routine test**: Must use `--profile ci` or be justified as a release-specific validation in the appropriate lane.
- **New fixed port**: Must use `:0` or a temp path. Existing fixed ports are grandfathered.
- **New global serialization override**: Must be documented in `test-suite-ownership.md` with the resource that requires serialization and a plan to eliminate it.

## Baseline Data

All threshold values are derived from the CI performance baseline captured in `docs/testing/ci-performance-baseline.md`. Key reference points:

| Metric | Baseline Value | Source |
|--------|---------------|--------|
| Root lib tests (CI profile) | 6s | Milestone A measurements |
| DNS crate (CI profile) | 103s | Milestone A measurements |
| Plugin runtime (CI profile) | 294s | Milestone A measurements |
| PR fast lane Cargo invocations | 45 (after dedup) | Milestone A results |
| Root guard binary count | 26 | Guard inventory in baseline |
| Total root integration test files | 26 | Post-Milestone C count |
| DNS Cargo invocations (before dedup) | 29 | Pre-Milestone A waste |
| DNS Cargo invocations (after dedup) | 1 | Post-Milestone A |

Budgets will be recalibrated when new baselines are established, typically at the end of each testing milestone.

## Review Cadence

- **Monthly**: Review warning thresholds against current moving medians. Adjust if baselines have shifted due to infrastructure changes (new runner hardware, Rust compiler improvements, test suite growth).
- **Per testing milestone**: Recalibrate all thresholds using fresh baseline measurements from `ci-performance-baseline.md`.
- **On incident**: Review and tighten budgets after any CI outage or regression that was not caught by existing thresholds.
- **Budget adjustments** require a PR with justification, approved by the CI maintainers team.

## Tracked Exceptions

| Budget | Owner | Expiry | Justification |
|--------|-------|--------|---------------|
| — | — | — | No current exceptions |
