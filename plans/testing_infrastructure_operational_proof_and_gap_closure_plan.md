# Testing Infrastructure Operational Proof and Gap Closure Plan

## Purpose

The testing-infrastructure roadmap is implementation-complete, but several final claims still require operational proof on GitHub-hosted runners rather than local validation or structural inspection alone.

This plan closes those remaining gaps by producing durable evidence that:

- the pull-request selector propagates outputs correctly on GitHub Actions;
- affected-package jobs run and skip exactly as intended;
- selector failures expand to full validation;
- stable summary and required-check behavior remains correct when package jobs are skipped;
- main, nightly, and release lanes detect their assigned failure classes;
- cross-platform compile and test targets execute successfully;
- timing, cache, and artifact behavior is recorded from real hosted runners;
- repository branch protection references the current authoritative check names;
- every assurance category in the coverage-equivalence matrix has at least one verified detection path;
- the final operating documents describe observed behavior rather than intended behavior.

This pass is operational verification and evidence collection. It must not reopen the completed architecture work unless hosted-runner results demonstrate an actual defect.

## Current state

The repository now contains:

- explicit PR, main, nightly, and release workflows;
- a dedicated CI profile;
- `cargo-nextest` scheduling and JUnit output;
- a tested affected-package selector with reverse-dependent closure;
- fail-closed selector normalization;
- a machine-readable lane manifest in `testing/lanes.toml`;
- an `xtask` interface for local lane reproduction;
- root-test ownership enforcement;
- test taxonomy, resource inventory, performance budgets, flaky-test policy, and coverage-equivalence documentation;
- a controlled failure-injection procedure with thirteen scenarios;
- structural guards that enforce CI policy and lane consistency;
- cross-platform test compilation in platform-compatibility jobs;
- `sccache` formally deferred because the original GitHub Actions cache backend was unavailable.

Remaining gaps are operational:

1. The final head does not yet have a complete, retained hosted-runner evidence package.
2. The thirteen failure-injection scenarios are documented but not all recorded as executed.
3. Branch-protection settings require administrator verification.
4. Hosted-runner timing baselines, queue time, skipped-job behavior, and artifact availability need durable records.
5. The current `sccache` deferral must remain explicit unless a supported backend is proven.
6. Documentation must be updated with actual run IDs, dates, durations, and outcomes.

## Scope boundaries

### In scope

- GitHub-hosted runner execution.
- Temporary branches and pull requests used only for validation.
- `workflow_dispatch` runs for main, nightly, and release qualification.
- Controlled failure injection and cleanup.
- Branch-protection verification.
- Timing and artifact collection.
- Small corrections discovered during proof execution.
- Result documents and final acceptance evidence.

### Out of scope

- New test architecture.
- New product functionality.
- Broad test rewrites unrelated to an observed runner defect.
- Reintroducing `sccache` without a supported storage/backend design and measured benefit.
- Weakening required checks to make injections pass.
- Merging intentional-failure branches.

## Required deliverables

Create or update the following artifacts:

- `plans/testing_infrastructure_operational_proof_results.md`
- `docs/testing/hosted-runner-baseline.md`
- `docs/testing/failure-injection-procedure.md`
- `docs/testing/ci-lane-policy.md`
- `docs/testing/operating-guide.md`
- `docs/testing/ci-performance-baseline.md`
- `docs/testing/coverage-equivalence-matrix.md`

The final results document must include:

- exact commit SHA tested;
- workflow run URLs or run IDs;
- runner OS and architecture;
- workflow, job, and step durations;
- queue time where available;
- selected packages and skipped jobs for affected runs;
- artifacts produced and retention periods;
- failure-injection results;
- branch-protection check names and verification method;
- unresolved exceptions with owners and disposition.

## Workstream OP1 — Establish a controlled proof branch

Create a dedicated branch from the current `main` head:

```bash
git checkout main
git pull --ff-only
git checkout -b validation/testing-operational-proof
```

The branch should initially contain no functional changes. Open a draft pull request whose purpose is to exercise the PR workflow with a known baseline.

Record:

- base SHA;
- head SHA;
- PR number;
- initial workflow run ID;
- all check names shown in GitHub;
- which checks are required by branch protection;
- whether any legacy `ci.yml` checks appear.

### Exit criteria

- A draft proof PR exists.
- Only the intended PR workflow triggers automatically.
- Current check names are captured verbatim.
- No legacy workflow is authoritative.

## Workstream OP2 — Verify selector propagation on hosted runners

Exercise the selector with at least nine scenarios. Each scenario must record selector mode, selected packages, root tests, feature classes, package-job outcomes, summary result, and artifacts.

### Scenario matrix

1. Documentation-only change.
2. Single leaf-crate source change.
3. Shared dependency change with reverse dependents.
4. Root source change requiring full validation.
5. Workspace `Cargo.toml` change requiring full validation.
6. `Cargo.lock` change requiring full validation.
7. Workflow change requiring full validation.
8. `tests/OWNERSHIP.toml` change requiring full validation.
9. Forced-full `workflow_dispatch` run.

For each scenario verify:

- `select-affected` completes or normalizes safely;
- outputs are visible to downstream jobs;
- full-mode runs execute every package job;
- affected-mode runs execute only selected package jobs;
- unselected package jobs are `skipped`, not failed;
- the summary accepts intentional skips;
- required always-on jobs still execute;
- the selector artifact contains valid JSON;
- local `cargo xtask test affected --dry-run` agrees with the hosted selection.

### Negative selector scenario

Temporarily force the selector step to fail on a validation branch. Verify:

- the selector step reports failure;
- normalization produces `mode=full`;
- all package jobs run;
- the aggregate summary remains authoritative;
- no job is silently omitted.

Never merge this change.

### Exit criteria

- All nine normal scenarios are recorded.
- The negative selector scenario falls back to full validation.
- Local and hosted selections agree for every scenario.
- No output-propagation defect remains.

## Workstream OP3 — Verify branch-protection authority

Using repository administration access, inspect branch protection for `main`.

The authoritative required checks should be based on current GitHub-displayed names, not assumed strings from documentation. Capture screenshots or settings exports where practical.

Verify that branch protection requires the intended always-on checks, including at minimum:

- PR Fast / Rustfmt
- PR Fast / Clippy (default features)
- PR Fast / No Unsafe in DNS
- PR Fast / Core Profile (No Default Features)
- PR Fast / Forbidden Import Patterns
- PR Fast / Security Regression Tests
- PR Fast / Architecture Guard Tests
- PR Fast / PR Fast Summary

Selector-gated package jobs should generally not be individually required because a skipped required check can create merge ambiguity. Their outcomes should be aggregated by the always-running summary job.

Verify:

- stale `ci.yml` checks are removed;
- summary is required;
- skipped package jobs do not block merge when summary passes;
- a failed selected package job causes summary failure and blocks merge;
- administrators are not unintentionally allowed to bypass required checks unless policy explicitly permits it;
- required-conversation-resolution and approval rules are documented separately from CI checks.

### Exit criteria

- Branch protection references current checks only.
- A skipped package job does not create an unresolved required check.
- A selected package failure blocks merge through the summary.
- Verification evidence is recorded.

## Workstream OP4 — Capture hosted-runner performance baselines

Capture at least three representative runs for each relevant category:

### PR runs

- documentation-only affected run;
- single-crate affected run;
- full-validation PR run.

### Main runs

- cold or low-cache comprehensive run;
- warm comprehensive run;
- run after a representative dependency change.

### Nightly/release runs

- one nightly qualification run;
- one release qualification dry run or dispatch on a non-release validation ref.

For each run collect:

- workflow queue time;
- total workflow duration;
- job durations;
- setup/tool installation time;
- cache restore/save durations;
- compile/test duration;
- JUnit availability;
- slow-test summary;
- artifact upload duration;
- number of Cargo invocations where available;
- runner image and toolchain version.

Use medians rather than a single run when evaluating budgets.

Update `docs/testing/hosted-runner-baseline.md` with tables such as:

| Lane | Scenario | Median total | Longest job | Jobs run | Jobs skipped | Cache state |
|---|---|---:|---:|---:|---:|---|

### Budget interpretation

Do not fail the roadmap solely because a noisy hosted runner exceeds a target once. Classify each budget as:

- met;
- warning;
- blocking regression;
- insufficient data.

A blocking regression requires repeated evidence and an attributable change.

### Exit criteria

- At least three PR baseline classes are measured.
- Main, nightly, and release evidence exists.
- Timing records include exact run IDs and dates.
- Performance-budget documentation reflects hosted data.

## Workstream OP5 — Verify artifact production and retention

For representative runs, inspect and download:

- selector JSON artifact;
- nextest JUnit XML;
- slow-test summaries;
- timing summaries;
- fuzz crash artifacts where applicable;
- release or qualification reports;
- xtask-generated reports if uploaded.

Verify:

- artifact names are unique per job/run;
- skipped jobs do not generate misleading empty artifacts;
- required artifacts upload even when a test job fails, using `if: always()` where appropriate;
- retention periods match policy;
- artifacts contain enough metadata to identify commit, workflow, job, profile, target, and feature set;
- sensitive data, secrets, paths, or credentials are not present.

### Exit criteria

- Required artifacts are downloadable and parseable.
- Failure runs retain diagnostics.
- Retention settings are documented.
- No sensitive information is exposed.

## Workstream OP6 — Execute controlled failure-injection campaign

Execute all thirteen scenarios in `docs/testing/failure-injection-procedure.md` using temporary branches or dispatch-only refs.

### Safety rules

- Prefix branches with `failure-injection/`.
- Prefix commits with `inject:`.
- Never merge an intentional-failure branch.
- Use one failure class per branch unless testing interaction explicitly.
- Close PRs and delete branches after evidence is captured.
- Verify `main` returns to green after each cleanup.

### Required scenarios

1. Formatting violation.
2. Clippy warning.
3. Unit-test assertion failure.
4. Domain integration failure.
5. Root composition failure.
6. Architecture-boundary violation.
7. Security-regression failure.
8. Selector failure and full fallback.
9. Missing root-test ownership entry.
10. Release-profile command in PR lane.
11. Platform-specific compile failure.
12. Fuzz-target crash fixture.
13. Release-build failure.

For each scenario record:

- branch and commit SHA;
- workflow run ID;
- expected detecting job;
- actual detecting job;
- whether unrelated jobs behaved correctly;
- whether branch protection blocked merge;
- whether local xtask reproduction matched;
- artifact or log location;
- cleanup confirmation.

### Acceptance rule

A scenario passes only when the intended authoritative lane detects the injected defect. Detection by an incidental unrelated job is useful but does not prove coverage ownership.

If the expected lane does not detect the failure:

1. classify the coverage gap;
2. correct the workflow, lane manifest, test ownership, or documentation;
3. add a regression guard or fixture where practical;
4. rerun the injection;
5. record both failed and corrected attempts.

### Exit criteria

- All thirteen injections are executed or explicitly marked infeasible with a justified substitute.
- Every feasible injection is caught by the intended lane.
- The results table is complete.
- No intentional failure reaches `main`.

## Workstream OP7 — Validate cross-platform behavior

Run or dispatch the supported cross-platform qualification paths.

At minimum verify:

- Linux native PR/main tests;
- Linux musl/Alpine compilation or runtime tests;
- FreeBSD compilation/test coverage;
- macOS compilation on available architecture;
- Windows compilation on available architecture.

Pay particular attention to:

- DNS packet-info platform abstractions;
- Unix-only IPC and socket paths;
- Windows named-pipe behavior;
- feature-gated imports;
- integration tests moved from root to owning crates;
- platform-specific test compilation enabled by `--tests`.

Record unsupported or unavailable combinations as explicit limitations rather than silently omitting them.

### Exit criteria

- Every supported platform has recent hosted evidence.
- Platform-specific tests compile where intended.
- Known exclusions are documented with rationale.
- No Linux-only green result is presented as full portability proof.

## Workstream OP8 — Validate lane-manifest and xtask parity

For each lane in `testing/lanes.toml`:

```bash
cargo xtask test explain <lane>
cargo xtask test <lane> --dry-run --json
```

Compare the emitted commands against current workflow commands.

Verify:

- `fast` matches the authoritative PR policy;
- `comprehensive` matches main workflow assurance categories;
- `nightly-plan` covers nightly workloads;
- `qualification` and `release` preserve release-only commands;
- `affected` agrees with selector behavior;
- package and guard commands remain valid after test migrations;
- command profiles and feature flags match documentation.

Run `ci_lane_consistency_guard` after any correction.

### Exit criteria

- No undocumented workflow command exists.
- No lane-manifest command lacks an owning workflow or documented local-only purpose.
- xtask dry runs match CI semantics.

## Workstream OP9 — Reconcile cache policy with observed reality

`sccache` is currently dormant. Do not re-enable it merely to satisfy the original roadmap wording.

Verify that:

- PR workflows do not set stale `SCCACHE_*` variables;
- the composite setup action does not activate `sccache` unless explicitly requested;
- docs describe the backend limitation and deferred status;
- performance baselines rely on active Cargo/rust-cache behavior only;
- no budget assumes compiler-cache hit rates that are not being collected.

Optionally perform a bounded feasibility experiment on a non-required workflow using a supported remote backend or a corrected GitHub Actions integration. The experiment must record:

- setup complexity;
- restore/save or backend overhead;
- cache hit rate;
- net wall-clock effect;
- failure behavior;
- security and credential requirements.

Re-enable `sccache` only if it is operationally reliable and produces a repeatable net benefit. Otherwise retain the formal deferral.

### Exit criteria

- Active cache behavior is accurately documented.
- No stale configuration remains.
- Any experiment has a clear keep/defer decision.

## Workstream OP10 — Verify flaky-test and repetition policy

Run repetition campaigns on representative suites using hosted runners where practical:

- security regression;
- DNS interoperability;
- DNS control-plane tests;
- selector tests;
- repository guards;
- one process/network-heavy suite.

Use at least five repetitions for ordinary suites and a higher count for historically flaky tests when cost permits.

Record:

- pass count;
- failure signatures;
- runtime spread;
- retry behavior;
- whether failures reproduce locally;
- quarantine disposition if needed.

Do not add broad retries. Any retry must comply with `docs/testing/flaky-test-policy.md`.

### Exit criteria

- Representative suites have hosted repetition evidence.
- No undocumented flaky test is hidden by retries.
- Any quarantine includes owner, issue, expiry, and restoration criteria.

## Workstream OP11 — Final documentation reconciliation

Update all affected documents after evidence collection.

### `docs/testing/ci-lane-policy.md`

- Exact current required-check names.
- Verified branch-protection configuration.
- Selector-gated versus always-required jobs.

### `docs/testing/ci-performance-baseline.md`

- Hosted-runner medians.
- Cold/warm distinctions.
- Queue and artifact timing.

### `docs/testing/coverage-equivalence-matrix.md`

- Add verification status for every assurance category.
- Link each category to a successful or intentionally failing run.

### `docs/testing/failure-injection-procedure.md`

- Complete the results table.
- Record deviations and corrections.

### `docs/testing/operating-guide.md`

- Add final operational commands and troubleshooting paths.
- Document how to inspect selector artifacts and summary behavior.

### Closure results

Create `plans/testing_infrastructure_operational_proof_results.md` containing:

- executive summary;
- exact tested commit;
- complete scenario matrix;
- performance evidence;
- branch-protection evidence;
- failure-injection evidence;
- cross-platform evidence;
- remaining limitations;
- final go/no-go decision.

### Exit criteria

- Documentation matches observed runner behavior.
- No completion claim depends solely on local results.
- Every deferred item has an explicit rationale and owner.

## Implementation sequence

Execute in this order:

1. Establish proof branch and baseline PR.
2. Verify current check names and branch protection.
3. Run selector scenario matrix.
4. Correct any selector/output defects immediately.
5. Capture PR/main timing and artifacts.
6. Validate cross-platform workflows.
7. Execute failure injections 1–10.
8. Execute nightly/release injections 11–13.
9. Run repetition campaigns.
10. Reconcile cache policy.
11. Update documentation and closure results.
12. Run final clean validation on `main`.

Do not begin broad documentation closure before hosted evidence is captured; otherwise the documents will encode assumptions instead of observations.

## Validation commands

Local validation before pushing each proof or corrective branch:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-repo-guards --all-targets -- -D warnings
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
python3 -m pytest tests/ci/test_select_affected.py
cargo xtask test fast --dry-run
cargo xtask test comprehensive --dry-run
cargo xtask test affected --base origin/main --dry-run --json
cargo test --test root_test_ownership_guard
```

Final clean validation should include:

```bash
cargo check --workspace --profile ci
cargo test --workspace --doc --profile ci
cargo xtask test guards
cargo xtask test security
cargo xtask test comprehensive
```

Run platform-specific commands through their authoritative hosted workflows rather than pretending local cross-compilation proves runtime behavior.

## Evidence retention

Retain:

- final workflow run links;
- downloaded artifacts or checksums where appropriate;
- completed injection table;
- branch-protection verification date;
- median timing calculations;
- exact runner and toolchain versions;
- final closure commit SHA.

Recommended retention:

- ordinary JUnit and selector artifacts: 14–30 days;
- failure-injection diagnostics: 30–90 days;
- release qualification artifacts: according to release policy;
- permanent summarized evidence in repository documentation.

## Risks and mitigations

### Risk: Intentional failure is merged

Mitigation: draft PRs, explicit `inject:` commits, no auto-merge, branch deletion after proof.

### Risk: Required skipped jobs block merge

Mitigation: require the always-running summary rather than selector-gated jobs; verify empirically.

### Risk: Selector fallback silently omits work

Mitigation: force selector failure and verify full-mode expansion on hosted runners.

### Risk: Hosted timing noise produces false regressions

Mitigation: use multiple runs and medians; separate queue time from execution time.

### Risk: Failure injections consume excessive CI capacity

Mitigation: execute sequentially, cancel superseded runs, use minimal patches, and reuse dispatch where possible.

### Risk: Platform matrix is too expensive

Mitigation: validate supported combinations deliberately and document unavailable combinations; do not duplicate identical assurance.

### Risk: Documentation diverges after proof

Mitigation: lane consistency guards, closure results, and explicit run references.

## Commit strategy

Prefer small commits grouped by evidence class:

1. `test(infra): add hosted proof instrumentation`
2. `test(infra): record selector scenario results`
3. `test(infra): close branch protection authority`
4. `test(infra): record hosted timing baseline`
5. `test(infra): complete failure injection evidence`
6. `test(infra): record cross-platform qualification`
7. `docs(testing): close operational proof and remaining gaps`

Do not combine intentional failure fixtures with permanent corrections in the same commit.

## Final acceptance criteria

This plan is complete only when all of the following are true:

- [ ] The final tested commit SHA is recorded.
- [ ] A hosted baseline PR has completed successfully.
- [ ] All nine selector scenarios are recorded.
- [ ] Selector failure demonstrably falls back to full validation.
- [ ] Selected package jobs run and unselected jobs skip correctly.
- [ ] The summary check handles skips and failures correctly.
- [ ] Branch protection references current authoritative check names.
- [ ] No legacy CI check remains required.
- [ ] PR, main, nightly, and release hosted runs are recorded.
- [ ] Hosted timing medians and queue times are documented.
- [ ] Required artifacts are downloadable and parseable.
- [ ] All thirteen failure-injection scenarios are executed or justified.
- [ ] Intended lanes catch their assigned injected failures.
- [ ] Cross-platform compile/test evidence exists for supported targets.
- [ ] Lane manifest, xtask, workflows, and documentation agree.
- [ ] `sccache` remains explicitly deferred or is re-enabled only with proof.
- [ ] Representative repetition campaigns show deterministic behavior or documented quarantine.
- [ ] Coverage-equivalence entries have operational verification status.
- [ ] Final closure documentation contains no known stale claims.
- [ ] A final clean run on `main` passes.

## Handoff note

The implementation agent should treat GitHub Actions behavior as the source of truth for this pass. Local commands and structural guards are prerequisites, not substitutes for hosted operational evidence.

Where an expected workflow behavior differs from actual GitHub behavior, correct the implementation, add a regression test or guard, rerun the scenario, and document both the defect and final proof. The final deliverable is not simply a green workflow; it is a durable, auditable evidence package showing that each validation lane performs its assigned role.