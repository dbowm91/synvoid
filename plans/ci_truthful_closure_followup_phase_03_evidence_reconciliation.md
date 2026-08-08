# CI Truthful Closure Follow-up — Phase 3: Final Evidence Reconciliation

**Status:** PLANNED  
**Created:** 2026-08-08  
**Roadmap:** `plans/ci_truthful_closure_followup_roadmap.md`  
**Depends on:** Follow-up Phases 1 and 2 complete  
**Baseline reviewed:** `584e6fa05b5e570a13140105ca85fb237dc65468`

## 1. Objective

Produce one final, internally consistent closure state after the release-qualification and malformed-input security gaps are resolved.

This phase is not for broad new implementation. It exists to:

- run authoritative verification once from the final clean implementation head;
- reconcile current plans and documentation to the actual commands and behavior;
- remove contradictory intermediate-state claims from current status documents;
- record hosted routine evidence accurately;
- leave external repository settings explicitly unverified unless they are actually inspected.

## 2. Entry criteria

Do not start authoritative closure runs until:

- Follow-up Phase 1 acceptance criteria are satisfied;
- Follow-up Phase 2 acceptance criteria are satisfied;
- focused owning-crate tests pass;
- no known authoritative-suite failure is being deferred without a documented specialist boundary;
- the working tree is clean;
- all implementation changes intended for closure are committed.

Do not manufacture a "final SHA" before the implementation is committed.

## 3. Workstream A — Freeze the final implementation head

Immediately before authoritative proof, record:

```bash
git rev-parse HEAD
git status --porcelain
git log -1 --oneline
rustc -Vv
cargo -V
cargo nextest --version
protoc --version
uname -a
```

Requirements:

- `git status --porcelain` is empty;
- the recorded SHA is the actual committed implementation head;
- no evidence document says "pending push";
- if documentation/evidence commits are made after test execution, distinguish the tested implementation SHA from the final documentation SHA and prove no executable/configuration code changed between them.

Preferred approach: commit implementation first, run evidence against that SHA, then make documentation-only closure commits that explicitly reference the tested implementation SHA.

## 4. Workstream B — Authoritative local verification

Run exactly once after the final implementation is coherent unless a failure requires correction and rerun.

### B1. Routine

```bash
cargo xtask verify --dry-run
cargo xtask verify
```

Record:

- expanded step count;
- exact commands;
- per-step duration;
- total duration;
- exit status.

Confirm the routine contract still contains only the intended bounded checks and has not reintroduced lanes/selectors/matrices.

### B2. Full

```bash
cargo xtask verify-full --dry-run
cargo xtask verify-full
```

Record:

- exact broad-test command(s);
- total duration;
- pass/fail counts;
- ignored/skipped tests relevant to this line;
- specialist-only tests and why they are outside the authoritative local suite.

Every failure from the original Phase 1 ledger must have a final disposition consistent with the current test tree.

### B3. Release

```bash
cargo xtask verify-release --dry-run
cargo xtask verify-release
```

Record separately:

- full/source verification duration;
- release-specific metadata/content/qualification duration if measured separately;
- end-to-end command duration;
- per-crate package qualification states;
- number assembled now;
- number packaged-source verified now;
- number deferred on named unpublished predecessors;
- number blocked/failed;
- publication-order result.

Do not label release-specific overhead as total `verify-release` duration.

## 5. Workstream C — Dirty-tree failure injection

After the clean release proof:

1. modify one tracked non-sensitive file temporarily;
2. run `cargo xtask verify-release`;
3. require nonzero exit with clear dirty-tree guidance;
4. run `cargo xtask verify-release --allow-dirty` only far enough to prove the warning/override behavior if a full rerun would be wasteful and the command architecture permits a bounded proof;
5. confirm the output says overridden results are diagnostic/non-authoritative;
6. revert the temporary change;
7. confirm the tree is clean again.

Do not preserve generated evidence files in tracked paths unless they are intentionally part of the plan.

## 6. Workstream D — Failure-ledger reconciliation

Update `plans/ci_phase01_failure_ledger.md` so its top-level summary reflects the final state rather than an intermediate phase.

Requirements:

- retain the original baseline counts for historical comparison;
- add a clearly labeled final closure column/state;
- no current summary should say `1 FAIL + 5 TIMEOUT` if the final authoritative suite is green;
- every originally failing/timed-out test has exactly one final classification;
- classifications distinguish:
  - product fix;
  - stale expectation corrected with contract evidence;
  - harness repair;
  - specialist-only test with reason/preflight;
  - deferred security limitation, if any remains;
- no row simultaneously says "resolved" and "remaining";
- malformed-input WAF rows reflect Phase 2's actual boundary proof.

Historical narrative may remain if explicitly labeled as phase history.

## 7. Workstream E — Verification-contract reconciliation

Treat `docs/testing/verification-contract.md` as the current source of truth and make it match `tools/xtask/src/verify.rs` exactly.

At minimum reconcile:

### Routine

- actual number of xtask routine steps;
- actual Cargo commands;
- actual profiles;
- single-threaded security test reasoning if still required;
- routine latency target versus blocking threshold.

### Full

- actual feature checks;
- broad nextest command;
- doctest command;
- specialist exclusions;
- any ignored specialist tests;
- stress/endurance wording.

### Release

- dirty-tree policy;
- metadata requirements;
- semver requirements;
- path-aware content inspection;
- actual package assembly semantics;
- actual packaged-source command (`cargo package`, not historical `cargo package --verify` wording);
- explicit deferred predecessor states from Phase 1;
- manual publication follow-up;
- no automated publishing.

### Specialist checks

Remove or correct stale "nightly" wording unless there is an actual currently active nightly mechanism. Prefer "manual specialist check" for fuzz, Miri, cross-platform, dependency-age, and endurance checks when that is the real operating model.

## 8. Workstream F — Closure-plan status reconciliation

Inspect the current status labels and completion claims in:

- `plans/ci_verification_release_truthful_closure_roadmap.md`;
- `plans/ci_verification_release_truthful_closure_phase_01_failure_adjudication.md`;
- `plans/ci_verification_release_truthful_closure_phase_02_product_regressions.md`;
- `plans/ci_verification_release_truthful_closure_phase_03_test_contract_corrections.md`;
- `plans/ci_verification_release_truthful_closure_phase_04_harness_isolation.md`;
- `plans/ci_verification_release_truthful_closure_phase_05_operational_proof.md`;
- `plans/ci_verification_release_truthful_closure_results.md`;
- this follow-up roadmap and all three follow-up phases.

Preserve historical facts, but current status must be truthful.

Recommended approach:

- do not erase historical implementation records;
- mark the original closure result as superseded/amended if it contains claims no longer considered authoritative;
- create or rewrite one authoritative final closure-results document that references this follow-up series;
- update roadmap status to `COMPLETE` only after all final acceptance criteria pass.

## 9. Workstream G — Final closure-results record

The authoritative final record must contain:

1. executive disposition;
2. tested implementation SHA;
3. final documentation SHA if different;
4. environment/toolchain;
5. original failure baseline;
6. final failure-ledger outcome;
7. release-qualification model and per-crate summary;
8. malformed-input/WAF security disposition;
9. routine local result;
10. full local result;
11. release end-to-end result;
12. dirty-tree injection result;
13. hosted routine result;
14. specialist checks executed vs preflight-only vs not executed;
15. branch-protection evidence status;
16. residual risks that are genuinely outside this closure line;
17. explicit final statement: `COMPLETE` or `INCOMPLETE`.

Every timing must say what it measures.

## 10. Workstream H — Hosted routine proof

Obtain one hosted run of the sole `ci` job after the final implementation changes.

Record:

- workflow run ID;
- job ID;
- checked-out SHA;
- conclusion;
- cache restore status: exact/full vs partial vs miss;
- `cargo xtask verify` duration;
- full job duration;
- slowest routine steps.

Interpret timing precisely:

- **target:** warm-cache routine verification/job below the documented target (currently 10 minutes where applicable);
- **blocking threshold:** 15 minutes unless the contract is deliberately changed;
- a partial-cache 12–14 minute run can be successful without proving the warm-cache target;
- do not write "within target" when only the blocking threshold was met.

If a warm-cache proof is readily available from a subsequent equivalent run, record it. Do not create repeated CI churn solely to manufacture a timing number if the current run is below the blocking threshold and the remaining statement is simply "warm-cache target not yet demonstrated."

## 11. Workstream I — Branch protection

Branch protection remains external repository state.

If the available tooling/settings access can directly inspect it, verify that `main` requires only the current `ci` check and record dated evidence.

If it cannot be inspected:

- leave it `EXTERNALLY UNVERIFIED`;
- do not infer it from workflow success;
- do not block source-code closure solely because the connector cannot view repository settings, unless the roadmap explicitly requires operator confirmation before complete status.

No branch-protection changes are required by this phase unless the user explicitly requests them.

## 12. Rejection searches

Before final closure, search operational code/workflows for accidental reintroduction of removed complexity:

- multiple routine CI workflows/jobs;
- schedule/tag release triggers;
- `cargo publish` inside xtask/workflows;
- registry tokens/credentials in automation;
- release artifact upload;
- generated affected-package selectors;
- lane manifests;
- dynamic force-full dispatch logic;
- local registry infrastructure introduced for the follow-up;
- hidden nextest filters excluding closure tests;
- new `#[ignore]` attributes added to make the authoritative suite green.

Historical plans/docs may mention removed architecture when clearly historical.

## 13. Acceptance criteria

Phase 3 and the follow-up roadmap are complete only when:

- [ ] Phases 1 and 2 are complete with committed implementation references;
- [ ] final implementation head is clean before authoritative runs;
- [ ] `cargo xtask verify` passes;
- [ ] `cargo xtask verify-full` passes;
- [ ] `cargo xtask verify-release` passes under the truthful qualification model;
- [ ] release evidence distinguishes passed, deferred, and failed package states;
- [ ] dirty-tree verification fails by default;
- [ ] `--allow-dirty` remains visibly diagnostic-only;
- [ ] failure-ledger summary matches final authoritative results;
- [ ] malformed-input WAF disposition is evidence-backed;
- [ ] `docs/testing/verification-contract.md` matches actual xtask commands and semantics;
- [ ] stale `cargo package --verify` wording is removed from current instructions;
- [ ] stale "nightly" enforcement wording is removed or made historical/manual as appropriate;
- [ ] final closure record names the exact tested SHA;
- [ ] no closure record says `pending push`;
- [ ] hosted run evidence names exact SHA/run/job and describes cache/timing accurately;
- [ ] no release-specific timing is mislabeled as end-to-end `verify-release` timing;
- [ ] original contradictory closure record is superseded or amended clearly;
- [ ] branch protection is either directly verified or explicitly `EXTERNALLY UNVERIFIED`;
- [ ] no removed CI/release automation has been restored;
- [ ] follow-up roadmap and phases are marked `COMPLETE` only after the above evidence exists.

## 14. Stop conditions

Keep the roadmap `INCOMPLETE` if:

- any authoritative local command fails;
- a publishable crate is still silently omitted or misreported;
- malformed-input security remains unresolved;
- current docs disagree with `verify.rs`;
- the final SHA is stale, uncommitted, or ambiguous;
- hosted timing is overstated;
- a new ignore/filter hides a closure test;
- actual publishing/release automation is added;
- branch settings are represented as verified without direct evidence.

## 15. Handoff note

This phase should mostly delete ambiguity, not add machinery. One clean final implementation SHA, one authoritative local proof set, one truthful hosted-run statement, and one synchronized closure record are preferable to repeated verification matrices or large evidence frameworks.
