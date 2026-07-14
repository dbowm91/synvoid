# Testing Infrastructure Milestones A/B Operational Closure Follow-up

## Purpose

Milestones A and B are implementation-complete but still require a focused operational closure pass before the repository treats the new test topology as the authoritative protected path. This plan closes the remaining gap between locally validated implementation and production-grade CI operation.

The follow-up is intentionally narrow. It does not redesign the workflow lanes, introduce affected-package selection, move additional tests between crates, or add compiler caching. Those belong to Milestones C and D. This pass verifies that the work already landed behaves correctly on GitHub-hosted runners, that branch protection points at the new checks, that known exceptions are resolved or explicitly quarantined, and that cold/warm measurements are trustworthy enough to serve as the next baseline.

## Current state

The repository now has:

- a dedicated `[profile.ci]` that avoids production LTO settings for routine tests
- separate pull-request, main, nightly, and release workflows
- trigger overlap removed from the legacy `ci.yml`
- duplicate DNS and plugin guard execution removed
- `cargo-nextest` pinned and used for eligible test suites
- JUnit and slow-test reporting
- a lightweight `tools/synvoid-repo-guards` crate
- consolidated root guard binaries
- negative fixtures proving static guards fail on representative violations
- milestone result documents with preliminary timing data

Known closure items:

1. GitHub-hosted workflow success has not been independently confirmed for the current topology.
2. Branch protection requires manual migration from legacy check names to the new pull-request fast-lane check names.
3. `lifecycle_task_guard::plugin_runtime_owner_is_stored_for_runtime_lifetime` remains a known failing guard and needs disposition.
4. Existing timing data is mostly warm/incremental and does not fully characterize cold hosted-runner behavior, cache overhead, memory pressure, or end-to-end pull-request latency.
5. The legacy manually dispatched workflow must be proven non-authoritative and unable to interfere with required-check semantics.
6. The `cargo nextest list -p synvoid-repo-guards` empty-output behavior needs classification so future test inventory tooling does not silently rely on it.

## Scope

In scope:

- execute and inspect all new workflow lanes on GitHub-hosted runners
- verify job names, triggers, permissions, dependencies, artifacts, summaries, and failure propagation
- update or document branch-protection required checks
- resolve, narrow, or explicitly quarantine the known lifecycle guard failure
- collect cold and warm hosted-runner timing data
- measure cache restore/save cost, disk usage, and peak memory where practical
- verify the legacy workflow is manual-only and not referenced by branch protection or release documentation
- validate nextest inventory behavior for the repository-guard crate
- produce a formal A/B closure report and Milestone C handoff

Out of scope:

- moving domain tests to owning crates
- changing the feature/target matrix beyond correcting demonstrable workflow defects
- adding `sccache`
- implementing affected-package selection
- increasing global concurrency or removing serialization overrides
- large lifecycle or plugin-runtime architecture refactors
- broad test fixture redesign

## Workstream 1 — Hosted-runner workflow activation

### Tasks

1. Trigger each workflow using its supported mechanism:

   - `pr-fast.yml` through a small pull request or temporary validation branch
   - `main-comprehensive.yml` through `workflow_dispatch` and, if safe, a normal main-branch push
   - `nightly-qualification.yml` through `workflow_dispatch`
   - `release-qualification.yml` through `workflow_dispatch` without publishing a release

2. Record for every workflow:

   - run URL and commit SHA
   - trigger type
   - total wall-clock duration
   - queue duration
   - job start/end times
   - runner image and architecture
   - success, failure, cancellation, or skipped state
   - artifact names and retention
   - generated summaries

3. Inspect all job dependency graphs and ensure summary jobs use `if: always()` where intended without masking failed required jobs.

4. Confirm `cancel-in-progress` behavior for pull-request runs by pushing two successive commits to a validation branch. The older run must cancel and the newer run must remain authoritative.

5. Confirm nightly and release workflows do not unintentionally cancel independent qualification runs.

6. Verify permissions are minimal and sufficient. Pay particular attention to artifact upload, checks, pull-request read access, and any release/tag permissions.

### Validation

- all four workflows parse and start on GitHub-hosted runners
- every required pull-request job reaches a terminal result
- failure in one required test job causes the pull-request workflow to fail
- summary output accurately reflects failed, cancelled, and skipped dependencies
- generated JUnit and timing artifacts can be downloaded and inspected
- superseded pull-request runs cancel automatically

### Success criteria

- at least one successful hosted-runner execution exists for each lane
- at least one controlled failure proves required-check failure propagation
- no workflow depends on undocumented local-only tools or paths
- no workflow silently succeeds after a required test failure

## Workstream 2 — Branch-protection migration

### Tasks

1. Inventory the exact check-run names emitted by `pr-fast.yml` on a real pull request.

2. Compare them with the repository's currently required status checks.

3. Remove obsolete required checks originating from the legacy `ci.yml`.

4. Add the stable required checks from the pull-request fast lane. Prefer a small set of stable aggregate checks rather than volatile matrix-generated names where practical.

5. Verify branch protection behavior with controlled cases:

   - all checks pass: merge is permitted
   - one required check fails: merge is blocked
   - required check is pending: merge is blocked
   - nightly/release checks are absent: ordinary pull-request merge remains possible
   - legacy workflow is not run: merge is not blocked by obsolete checks

6. Document manual administrator steps if the implementation agent lacks permission to change branch protection directly.

7. Update `docs/testing/ci-lane-policy.md`, `AGENTS.md`, and any release documentation that names required checks.

### Success criteria

- required checks correspond only to active pull-request workflow jobs
- no obsolete check name can permanently block merges
- nightly and release qualification remain non-required for ordinary pull requests
- the branch-protection configuration is documented with exact check names and verification date

## Workstream 3 — Known lifecycle guard disposition

### Target

`lifecycle_task_guard::plugin_runtime_owner_is_stored_for_runtime_lifetime`

### Tasks

1. Reproduce the failure in isolation:

```bash
cargo nextest run --profile ci --test lifecycle_task_guard \
  plugin_runtime_owner_is_stored_for_runtime_lifetime --nocapture
```

If nextest filtering is unsuitable, use:

```bash
cargo test --profile ci --test lifecycle_task_guard \
  plugin_runtime_owner_is_stored_for_runtime_lifetime -- --nocapture
```

2. Determine whether the failure represents:

   - a stale source-scanning assumption
   - a legitimate ownership regression
   - an incomplete consolidation translation
   - a feature-gated source layout difference
   - a non-deterministic filesystem/path assumption
   - a documentation-only expectation that should not be a runtime guard

3. Compare the consolidated assertion with the pre-consolidation test at the parent commit to prove whether semantics changed.

4. Choose exactly one disposition:

   - fix production ownership if the guard found a real regression
   - correct the guard while preserving the intended invariant
   - split the guard into stable structural and runtime assertions
   - quarantine temporarily with `#[ignore]` only if an issue/plan, owner, rationale, and removal condition are added

5. Add a negative fixture or focused regression test for the corrected invariant.

6. Remove any unconditional known-failure note once the test passes.

### Success criteria

- the guard passes deterministically in repeated local and hosted-runner execution, or
- a narrowly scoped quarantine is documented with a concrete exit condition and does not allow the broader suite to appear fully clean
- consolidation equivalence remains demonstrated
- no assertion is weakened solely to obtain a green result

## Workstream 4 — Cold/warm hosted-runner performance baseline

### Measurement classes

Collect at least:

1. cold pull-request fast lane
2. warm pull-request fast lane with no dependency changes
3. cold main comprehensive lane
4. warm main comprehensive lane
5. one nightly qualification run
6. one release qualification dry run

### Tasks

1. Define cold-cache methodology. Prefer unique cache keys or explicit cache bypass rather than destructive cache deletion unless necessary.

2. Capture:

   - total workflow duration
   - per-job and per-step duration
   - checkout/toolchain/setup time
   - cache restore duration
   - cache save duration
   - Cargo compile/check/test duration
   - test execution duration
   - artifact upload duration
   - peak disk usage
   - peak resident memory for representative heavyweight jobs
   - number of Cargo invocations
   - number of compiled test binaries

3. Use `/usr/bin/time -v` around representative commands where supported.

4. Upload Cargo timing reports for at least:

   - root fast tests
   - DNS tests
   - plugin-runtime tests
   - consolidated guard tests

5. Feed nextest JUnit and timing artifacts through `scripts/ci/summarize-test-costs.py`.

6. Record hosted-runner variance and distinguish measurements from guaranteed budgets.

7. Update `docs/testing/ci-performance-baseline.md` with a dated before/after table.

### Success criteria

- cold and warm behavior are clearly separated
- pull-request end-to-end latency is measured on hosted runners
- cache overhead is visible rather than assumed beneficial
- at least the ten slowest binaries/tests are identified
- the baseline is reproducible enough for Milestones C and D comparisons

## Workstream 5 — Legacy workflow non-authority audit

### Tasks

1. Confirm `.github/workflows/ci.yml` has only `workflow_dispatch` triggers.

2. Search repository documentation, branch-protection notes, badges, scripts, and release instructions for references to legacy job names.

3. Confirm no reusable workflow or external automation invokes `ci.yml` unexpectedly.

4. Decide whether to retain it as a manual compatibility/diagnostic workflow or remove it in a later cleanup.

5. If retained, add a clear top-level comment and workflow name indicating that it is legacy/manual and non-authoritative.

6. Ensure it does not duplicate release qualification in a way likely to confuse operators.

### Success criteria

- no push or pull-request event launches the legacy workflow
- no required status check points to legacy jobs
- operator documentation clearly identifies the authoritative lane for each use case

## Workstream 6 — Nextest inventory behavior

### Tasks

1. Reproduce:

```bash
cargo nextest list -p synvoid-repo-guards
cargo nextest run -p synvoid-repo-guards
cargo test -p synvoid-repo-guards -- --list
```

2. Determine whether empty `nextest list` output is caused by:

   - nextest version behavior
   - workspace default-members configuration
   - package target metadata
   - command syntax/profile selection
   - test binaries being integration-only
   - output formatting or capture behavior

3. Test machine-readable listing:

```bash
cargo nextest list -p synvoid-repo-guards --message-format json
```

4. If the behavior is a known tool quirk, document the reliable inventory command and ensure future scripts do not use the broken path.

5. If caused by repository metadata, correct it and add a small CI smoke assertion that inventory returns the expected test count or package targets.

### Success criteria

- the behavior is either fixed or precisely documented
- affected-test tooling has one reliable machine-readable inventory path
- no future selection logic silently interprets an empty list as zero tests

## Workstream 7 — Closure documentation and handoff

Create:

```text
plans/testing_milestones_ab_operational_closure_results.md
```

The result document must contain:

- commit range evaluated
- workflow run URLs and SHAs
- branch-protection check names
- controlled failure results
- lifecycle guard disposition
- cold/warm timing tables
- cache overhead observations
- slowest tests/binaries
- legacy workflow disposition
- nextest inventory disposition
- remaining blockers
- explicit go/no-go recommendation for Milestone C

Update:

- `docs/testing/ci-performance-baseline.md`
- `docs/testing/ci-lane-policy.md`
- `docs/testing/nextest-policy.md`
- `docs/testing/architecture-guard-ownership.md`
- `AGENTS.md`

## Required validation matrix

```bash
cargo fmt --all -- --check
cargo check --workspace --profile ci
cargo nextest run --workspace --profile ci
cargo test --workspace --doc
cargo clippy -p synvoid-repo-guards --all-targets -- -D warnings
cargo nextest run -p synvoid-repo-guards --profile ci
cargo nextest run --profile ci --test lifecycle_task_guard
```

Also execute the workflow-specific commands exactly as encoded in each YAML file.

## Recommended commit sequence

1. `test-infra: reproduce and resolve lifecycle guard failure`
2. `test-infra: verify nextest guard inventory behavior`
3. `ci: close hosted-runner and branch-protection migration gaps`
4. `test-infra: record cold and warm hosted-runner baseline`
5. `docs: close testing milestones A and B operationally`

Keep correctness fixes separate from workflow/documentation changes so regressions are bisectable.

## Risks and mitigations

### Risk: branch protection becomes temporarily permissive

Mitigation: add new required checks before removing old checks where the platform permits, then verify with a test pull request.

### Risk: hosted-runner variance leads to misleading budgets

Mitigation: record multiple runs, medians, and ranges; do not convert single-run timing into a hard gate.

### Risk: lifecycle guard is weakened to obtain green CI

Mitigation: compare against the original assertion, add a negative fixture, and require a written invariant.

### Risk: manual-only legacy workflow remains confusing

Mitigation: rename/comment/document it or remove it in a separate explicit change.

### Risk: empty nextest inventory later causes unsafe test selection

Mitigation: establish and test a machine-readable inventory command before Milestone D.

## Exit criteria

This follow-up is complete only when:

- all four workflow lanes have successful GitHub-hosted executions
- controlled failures prove required-check propagation
- branch protection uses the new stable pull-request checks
- legacy checks are removed from branch protection
- the known lifecycle guard is passing or narrowly quarantined with an explicit closure condition
- cold and warm hosted-runner baselines are recorded
- cache restore/save overhead is measured
- the legacy workflow is proven manual and non-authoritative
- nextest inventory behavior is fixed or safely documented
- an A/B closure result document recommends proceeding to Milestone C

## Handoff to Milestone C

The closure report must provide Milestone C with:

- authoritative root integration-test inventory
- cold/warm compile and link timing by major package
- slowest root test binaries
- root tests classified as static, single-domain, or genuine composition tests
- exact feature sets used by each lane
- hosted-runner resource observations
- known tests that cannot yet move because of shared fixtures or public API constraints
