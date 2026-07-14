# Testing Infrastructure Milestone D Corrective Closure Plan

## Purpose

Milestone D introduced the main infrastructure required for faster warm and localized validation: `sccache`, a reusable Rust CI setup action, an affected-package selector, reverse-dependent closure, conservative full-suite fallbacks, local reproduction tooling, selector tests, and repository guardrails. The implementation is structurally strong, but the current PR workflow does not yet realize the intended package-skipping behavior because the package-job predicates have inverted full-versus-affected logic.

This corrective pass closes that defect and converts Milestone D from infrastructure-complete to operationally authoritative. It also finishes the deferred work required to prove that caching and affected-package selection produce real wall-clock savings without weakening branch protection or omitting required tests.

The pass is deliberately narrow. It does not begin Milestone E fixture, concurrency, fuzz, stress, or testkit work. It corrects and validates the Milestone D execution path first so later performance work is measured against a trustworthy baseline.

## Current state

The repository currently has:

- `scripts/ci/select-affected.py` with Cargo metadata dependency analysis, transitive reverse-dependent closure, root-test selection, JSON/text output, and conservative fallback rules.
- `scripts/test-affected.sh` for local reproduction.
- selector unit tests under `tests/ci/test_select_affected.py`.
- cache and selector guards in `tools/synvoid-repo-guards/tests/cache_and_selector.rs`.
- `.github/actions/setup-rust-ci/action.yml` for standardized Rust, rust-cache, nextest, cross, and sccache setup.
- `sccache` enabled in selected PR jobs.
- stable aggregate PR summary checks.
- documented cache policy and feature/target matrix.

Known corrective items:

1. The package-job predicates in `.github/workflows/pr-fast.yml` currently use:

   ```yaml
   mode != 'full' || package-is-selected
   ```

   In affected mode, `mode != 'full'` is true, so every gated package job runs. The selector therefore computes a package set but does not reduce the workload.

2. Selector failure handling relies on `continue-on-error` and potentially empty outputs. The workflow must explicitly fail closed to full validation.

3. The reusable `setup-rust-ci` action exists, but several jobs still duplicate direct setup steps.

4. Cache performance measurement and shadow-mode comparison remain deferred.

5. Hosted-runner workflow activation, branch-protection verification, and cold/warm timing remain unverified through committed evidence.

6. The feature/target matrix documents redundant invocations, but the low-risk overlap reductions have not yet been applied.

## Scope

### In scope

- Correct affected/full predicate logic in every gated PR job.
- Add explicit selector-failure fallback behavior.
- Add tests or guards that detect predicate polarity regressions.
- Ensure skipped package jobs are treated correctly by the stable PR summary.
- Adopt the reusable Rust setup action in appropriate PR jobs.
- Measure cold and warm cache behavior on hosted runners.
- Run selector shadow validation against full-suite decisions.
- Verify branch-protection check names and workflow authority.
- Apply only low-risk, mechanically provable feature/target matrix deduplication.
- Produce a formal Milestone D closure report.

### Out of scope

- Moving more tests between crates.
- DNS fixture deduplication.
- New `synvoid-testkit` helpers.
- Raising test concurrency.
- Fuzz/stress matrix redesign.
- Performance budget enforcement beyond recording the new baseline.
- Product or runtime behavior changes unrelated to test infrastructure.

## Required outcome

After this pass:

- full mode runs every required package job;
- affected mode runs only selected package jobs plus invariant required checks;
- selector failure or missing output results in full validation;
- skipped optional jobs do not fail the aggregate required check;
- branch protection continues to see stable required check names;
- cache benefit is measured on real runners;
- selector decisions are compared against full-suite expectations for representative changes;
- no nightly or release qualification lane uses affected-package selection;
- the Milestone D results document no longer lists D4 and D10 as unverified without an explicit disposition.

# Workstream 1 — Correct package-job predicate semantics

## Tasks

Audit every `needs.select-affected` predicate in `.github/workflows/pr-fast.yml`.

The intended truth table is:

| Selector mode | Package selected | Run package job |
|---|---:|---:|
| `full` | no | yes |
| `full` | yes | yes |
| `affected` | no | no |
| `affected` | yes | yes |
| missing/error/unknown | any | yes |

Replace predicates conceptually with:

```yaml
needs.select-affected.outputs.mode == 'full' ||
needs.select-affected.outputs.mode == '' ||
contains(needs.select-affected.outputs.packages, '"synvoid-upload"')
```

A cleaner approach is preferred: normalize the selector job output to one of exactly two modes, `full` or `affected`, and make selector failure emit `mode=full` explicitly. Then package jobs can use:

```yaml
needs.select-affected.outputs.mode == 'full' ||
contains(needs.select-affected.outputs.packages, '"synvoid-upload"')
```

Apply equivalent logic to all gated package jobs, including at minimum:

- `upload-tests`
- `honeypot-tests`
- `tarpit-tests`
- `mesh-tests`

Audit for any additional package jobs added after the plan was written.

## Validation

Create a machine-readable predicate matrix test. This may be implemented as:

- a Python unit test that evaluates the intended truth table;
- a repository guard that parses the workflow and rejects `mode != 'full' ||` patterns;
- both, if low complexity.

The guard must fail on the exact regression pattern that landed.

## Success criteria

- A package not present in selector output is skipped in affected mode.
- All package jobs run in full mode.
- Unknown or failed selector state cannot skip tests.
- Repository guards reject inverted predicate polarity.

# Workstream 2 — Fail-closed selector behavior

## Problem

`select-affected` currently uses `continue-on-error: true`. If the selector step fails before outputs are populated, dependent jobs may receive empty values. Correctness must not depend on GitHub expression edge cases for empty outputs.

## Tasks

Choose one explicit fail-closed design.

### Preferred design

Keep the selector job non-blocking, but add a final normalization step with `if: always()` that:

1. Checks whether the selector step succeeded.
2. Validates the JSON schema and required keys.
3. Emits `mode=full` and a documented fallback reason if any validation fails.
4. Emits an empty package list only together with `mode=full`.
5. Writes the final normalized output to the step summary and artifact.

Suggested output fields:

```json
{
  "mode": "full",
  "changed_packages": [],
  "root_tests": [],
  "feature_classes": [],
  "fallback": true,
  "fallback_reason": "selector execution failed"
}
```

Do not allow `mode=affected` unless the JSON parsed successfully and all required fields are valid.

## Negative cases to test

- invalid base ref;
- missing git history;
- malformed selector JSON;
- `cargo metadata` failure;
- missing `tests/OWNERSHIP.toml`;
- unknown package path;
- selector script exception;
- unsupported mode string;
- output file missing.

## Success criteria

- Every selector failure becomes full validation.
- The PR summary states when fallback occurred and why.
- No test job can be skipped because selector output is absent or malformed.

# Workstream 3 — Expand selector integration tests

## Tasks

Retain the existing unit tests and add workflow-oriented integration coverage for the actual output contract used by GitHub Actions.

Required scenarios:

1. Change only `crates/synvoid-upload/src/...`:
   - mode is `affected`;
   - upload and reverse dependents are selected;
   - unrelated honeypot/tarpit jobs are not selected.

2. Change only documentation outside guarded architecture paths:
   - either no package jobs are selected or policy-defined minimal validation runs;
   - invariant checks still run.

3. Change root `Cargo.toml`:
   - mode is `full`.

4. Change `Cargo.lock`:
   - mode is `full`.

5. Change `.github/workflows/pr-fast.yml`:
   - mode is `full`.

6. Change `tests/OWNERSHIP.toml`:
   - mode is `full`.

7. Change a dependency crate:
   - all transitive reverse dependents are selected.

8. Selector failure:
   - normalized output is `full`.

9. Manual `force-full` dispatch:
   - mode is `full` regardless of diff.

10. Root façade or composition-root change:
    - root tests and all required feature classes are selected.

## Success criteria

- Tests cover both selector computation and workflow predicate consumption.
- A regression equivalent to the current inverted predicate is detected automatically.
- All fixtures are deterministic and require no network access.

# Workstream 4 — Preserve stable required checks

## Tasks

Verify which jobs are required by branch protection. The required surface should remain stable even when optional package jobs are skipped.

At minimum, confirm stable behavior for:

- formatting;
- Clippy;
- security regression;
- architecture guards;
- aggregate PR summary.

The aggregate summary must:

- treat `success` and intentional `skipped` as acceptable for selector-gated optional jobs;
- fail on `failure`, `cancelled`, or selector normalization failure that did not convert to full mode;
- display selector mode, selected packages, skipped jobs, and fallback reason;
- remain present on every PR run.

Document exact required check names in `docs/testing/ci-lane-policy.md`.

## Administrative verification

Using repository settings or an administrator-assisted check, confirm that branch protection references current `pr-fast.yml` checks and not legacy `ci.yml` names.

If this cannot be automated, the closure report must include:

- exact checks to require;
- exact obsolete checks to remove;
- evidence that the change was performed, or a clearly marked external blocker.

## Success criteria

- Required checks are stable across full and affected runs.
- Intentional job skips cannot leave a PR permanently pending.
- Legacy workflow jobs are not authoritative.

# Workstream 5 — Adopt the reusable Rust CI setup action

## Purpose

The composite action should become the single setup path for eligible Rust CI jobs rather than an unused abstraction.

## Tasks

Migrate suitable `pr-fast.yml` jobs from repeated steps such as:

- `dtolnay/rust-toolchain`
- `Swatinem/rust-cache`
- `taiki-e/install-action@nextest`
- `taiki-e/install-action@v2` for sccache
- repeated environment configuration

to:

```yaml
- uses: ./.github/actions/setup-rust-ci
  with:
    components: clippy,rustfmt
    nextest: 'true'
    sccache: 'true'
    cache-key: pr-upload
```

Do not force every job through the action if platform, container, nightly, Miri, cross, or release semantics differ materially. Document exceptions.

Ensure action versions remain pinned according to repository policy. If tag-based pins are accepted, document that policy; otherwise use immutable commit SHAs.

## Validation

- Compare environment variables and installed tools before and after migration.
- Confirm nextest version remains pinned.
- Confirm sccache server starts and stats are available.
- Confirm rust-cache and sccache do not use contradictory target-directory assumptions.

## Success criteria

- Eligible PR Rust jobs use the composite action.
- Duplicate setup blocks are materially reduced.
- Specialized lanes retain explicit setup where necessary.
- Tool versions and cache behavior do not drift.

# Workstream 6 — Hosted-runner activation and shadow validation

## Purpose

Local tests establish logical correctness, but the selector and cache system must be observed under GitHub Actions behavior.

## Tasks

Run representative PRs or temporary validation branches for these change classes:

1. documentation-only change;
2. isolated upload change;
3. isolated DNS change;
4. shared core change;
5. root façade change;
6. Cargo.lock change;
7. workflow change;
8. forced-full manual dispatch.

For each run, record:

- selector mode;
- selected packages;
- selected root tests;
- jobs run;
- jobs skipped;
- aggregate summary result;
- expected full-suite decision;
- whether the selector decision was correct;
- whether branch protection accepted the result.

### Shadow comparison

For at least three affected-mode scenarios, run or compare against a full validation execution on the same commit. Record whether the full run exposed any failure outside the selected set.

The selector should remain advisory or non-authoritative until the shadow comparison shows no false negatives across the agreed sample.

## Success criteria

- Representative PRs demonstrate real job skipping.
- No false-negative selection is observed.
- Stable required checks complete correctly when optional jobs skip.
- A forced-full escape hatch works.

# Workstream 7 — Measure cache effectiveness

## Tasks

For compilation-heavy PR jobs using sccache, capture:

- compile requests;
- cache hits;
- cache misses;
- cache errors;
- non-cacheable compilations;
- cache write failures;
- local and remote cache size where available;
- rust-cache restore duration;
- rust-cache save duration;
- total job duration;
- compilation step duration.

Run at least:

1. cold cache;
2. warm cache with no source changes;
3. warm cache with localized source changes;
4. dependency or feature change causing intentional invalidation.

Compute net benefit:

```text
net cache benefit = uncached compile time - (cached compile time + restore/save overhead)
```

Do not claim improvement solely from hit rate. High hit rates can still be net-negative if cache transfer overhead dominates.

## Decision rules

- Keep sccache enabled for a job class only if repeated measurements show positive net benefit.
- Disable target-directory caching where restore/save cost is consistently excessive.
- Avoid cache fragmentation by unnecessary job-specific keys.
- Preserve target/toolchain/profile separation where outputs are incompatible.

## Documentation

Update:

- `docs/testing/cache-policy.md`
- `docs/testing/ci-performance-baseline.md`
- `plans/testing_milestone_d_results.md`

with measured results and final policy decisions.

## Success criteria

- Cold and warm hosted-runner measurements exist.
- Cache effectiveness is quantified by net time, not only hit rate.
- Ineffective cache layers are removed or narrowed.

# Workstream 8 — Apply low-risk matrix deduplication

## Purpose

Milestone C identified 135 Cargo invocations and twenty-three redundant release-qualification entries. This pass should apply only mechanical overlap removals that do not alter assurance coverage.

## Tasks

Using `docs/testing/feature-target-matrix.md`, classify each proposed removal as:

- exact duplicate;
- strict subset already covered by another command;
- same target/profile/features repeated in another job;
- intentionally duplicated for lane isolation;
- not safely removable.

Remove only exact or mechanically proven duplicates.

For each removal, document:

- original command and job;
- covering command and job;
- why coverage is equivalent;
- whether artifact generation or platform context differs.

Do not collapse main, nightly, and release lanes merely because commands look similar; lane-specific authority may justify repetition.

## Success criteria

- All removed invocations have a written coverage-equivalence rationale.
- No unique feature, target, profile, artifact, or runtime property is lost.
- Release qualification remains exhaustive.

# Workstream 9 — Safety and regression guards

## Required guards

Add or extend repository guards to enforce:

1. No `mode != 'full' || package-selected` predicate pattern.
2. Qualification lanes do not use affected-package selection.
3. Selector fallback normalizes to full mode.
4. Stable aggregate summary remains present.
5. `force-full` remains available.
6. Eligible PR jobs use the shared setup action, or are listed in an exception allowlist with rationale.
7. sccache stats are reported for jobs where sccache is enabled.
8. New selector-gated jobs declare `needs: [select-affected]` and use approved predicate structure.

Negative fixtures should intentionally introduce each prohibited form and prove the guards fail.

## Success criteria

- The exact current defect cannot recur without CI failure.
- Guard messages identify the job and invalid predicate.
- Exceptions are narrow and documented.

# Workstream 10 — Final validation matrix

Run the following local validation where applicable:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-repo-guards --all-targets -- -D warnings
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
python3 -m unittest tests/ci/test_select_affected.py
python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json
bash scripts/test-affected.sh HEAD~1 --dry-run
```

Validate workflow syntax using an available YAML/action linter. At minimum:

- parse all workflow YAML files;
- validate composite action syntax;
- inspect all `if:` expressions;
- confirm outputs referenced by dependent jobs exist.

Run representative full and affected commands locally where feasible.

Hosted-runner validation must cover the scenarios from Workstream 6.

## Success criteria

- All local selector, guard, formatting, and lint tests pass.
- Workflow syntax is valid.
- Affected mode demonstrably skips unrelated jobs.
- Full mode demonstrably runs every required package job.
- Selector failure demonstrably falls back to full validation.

# Workstream 11 — Documentation and closure artifacts

Create:

```text
plans/testing_milestone_d_corrective_closure_results.md
```

The result document must include:

- commit range;
- exact predicate defect and root cause;
- before/after truth table;
- selector failure fallback behavior;
- shared-action adoption map;
- hosted-runner scenario results;
- branch-protection verification status;
- cold/warm cache measurements;
- job skip counts;
- matrix commands removed and their coverage equivalents;
- remaining limitations;
- go/no-go recommendation for Milestone E.

Update:

- `plans/testing_milestone_d_results.md`
- `docs/testing/cache-policy.md`
- `docs/testing/ci-performance-baseline.md`
- `docs/testing/ci-lane-policy.md`
- `docs/testing/feature-target-matrix.md`
- `AGENTS.md`
- `README.md` if developer commands change.

## Exit criteria checklist

Milestone D corrective closure is complete only when all applicable items are checked:

- [ ] Package-job predicate polarity is correct.
- [ ] Full mode runs all gated jobs.
- [ ] Affected mode skips unrelated gated jobs.
- [ ] Selector failure explicitly falls back to full mode.
- [ ] Predicate regression guards and negative fixtures pass.
- [ ] Stable required checks complete with intentional skips.
- [ ] Branch protection references current check names.
- [ ] Eligible PR jobs use the shared Rust setup action.
- [ ] Hosted-runner validation has been performed.
- [ ] Shadow comparisons show no selector false negatives in the agreed sample.
- [ ] Cold and warm cache measurements are recorded.
- [ ] Cache net benefit is positive or ineffective layers are disabled.
- [ ] Low-risk matrix duplicates are removed with equivalence evidence.
- [ ] Nightly and release lanes remain unaffected by selector gating.
- [ ] Documentation and closure results are complete.

# Recommended implementation sequence

1. Fix predicate polarity.
2. Add explicit fail-closed normalization.
3. Add predicate and fallback regression tests.
4. Validate skipped-job behavior in the aggregate summary.
5. Migrate eligible jobs to the shared setup action.
6. Run local validation and workflow linting.
7. Trigger hosted-runner scenario matrix.
8. Perform shadow full-versus-affected comparisons.
9. Measure cache benefit.
10. Apply mechanically safe matrix deduplication.
11. Update policies and publish closure results.

# Commit strategy

Use small, reviewable commits:

1. `test-infra: fix affected job predicate polarity`
2. `test-infra: fail closed on selector errors`
3. `test-infra: add selector workflow regression guards`
4. `ci: adopt shared Rust setup action in PR jobs`
5. `ci: remove proven duplicate matrix commands`
6. `docs: record Milestone D corrective closure results`

Do not combine predicate correction with broad matrix cleanup in one commit. The correctness fix must be independently reviewable and revertible.

# Rollback strategy

If affected selection behaves unexpectedly:

1. Set the selector normalization output to `mode=full` unconditionally.
2. Retain selector computation and reporting in shadow mode.
3. Keep stable required checks and package jobs running fully.
4. Investigate selector or predicate behavior without weakening validation.

If sccache is net-negative or unstable:

1. Disable `sccache: 'true'` for the affected job class.
2. Retain Cargo source and tool caches.
3. Preserve collected measurements in the closure report.

If the shared setup action causes platform or toolchain drift:

1. Revert only the affected jobs to explicit setup.
2. Record the exception and required divergence.
3. Keep the action for compatible jobs.

# Handoff notes

The highest-priority correction is the PR predicate truth table. No subsequent performance conclusions are trustworthy until affected mode actually skips unrelated jobs. The implementation agent should treat hosted-runner observation and branch-protection verification as required operational evidence, not optional documentation polish.

Milestone E should not begin until this plan reaches a clear go decision or affected selection has been intentionally returned to shadow-only full validation.