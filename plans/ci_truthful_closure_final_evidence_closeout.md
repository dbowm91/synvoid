# CI Truthful Closure — Final Evidence Closeout

**Status:** COMPLETE  
**Created:** 2026-08-11  
**Closed:** 2026-08-11  
**Baseline reviewed:** `bfabc1b61e05994995144023b110be636979853e`  
**Prior corrective implementation:** `3aced41c33b79a6e301ebb3ed4d777136becc65e`  
**Prior local qualification evidence:** `8265f1ef678f91ceeded86092dcbf5c073d3e8c9`  
**Prior hosted routine evidence:** `232e2de154e2fafe4a8c597fa5a7efa608f55457`  
**Depends on:** `plans/ci_truthful_closure_final_corrective_pass.md`  

## 1. Purpose

Close the CI/testing/release-verification simplification line with evidence that actually covers the current corrected verifier implementation and with no remaining contradictory operational documentation.

This is an evidence-and-record closeout pass, not another implementation phase.

The substantive corrective work is already present:

- release qualification uses `DeferredOnInternalPredecessors` rather than claiming registry publication state it cannot prove;
- deferred crates are separated from assembled and packaged-source-verified crates;
- the authoritative closure result no longer points to a nonexistent follow-up-results file;
- hosted timing language records the observed full cache-key match and does not infer a partially warm cache;
- the simplified one-workflow/one-job CI model remains intact;
- release publication remains manual and outside CI/xtask.

The remaining gaps are narrow:

1. one current operational sentence still refers to crates being blocked by "unpublished internal predecessors";
2. the executable rename in `3aced41c...` has not received fresh recorded `verify`, `verify-full`, and `verify-release` evidence;
3. the authoritative evidence table still misidentifies the pre-corrective `eb74304...` state as the "Final corrective pass";
4. `plans/ci_truthful_closure_final_corrective_pass.md` remains `PLANNED` with unchecked acceptance criteria even though almost all implementation items landed.

No other work belongs in this pass.

## 2. Hard scope constraints

Preserve the current intentionally simple operating model.

### 2.1 Do not expand CI

Do not add or restore:

- additional routine jobs;
- matrices;
- affected-package selectors;
- scheduled CI;
- dedicated release workflows;
- artifact/evidence upload pipelines;
- dynamic test schedulers;
- separate hosted full/release lanes;
- cache topology changes solely to chase the nonblocking `<10m` target.

Routine hosted CI remains one Ubuntu job invoking `cargo xtask verify`.

### 2.2 Do not automate release publication

Do not add:

- `cargo publish` execution to xtask or CI;
- crates.io credentials to GitHub Actions;
- a registry emulator;
- registry polling/probing machinery;
- automatic sequential publication;
- GitHub Release automation.

Publication remains operator-driven and manual.

### 2.3 Do not change product/security behavior

Do not modify:

- WAF normalization or detection behavior;
- malformed-input handling;
- test assertions to make verification pass;
- ignore/filter lists;
- product dependencies;
- unrelated runtime behavior.

If fresh verification exposes a genuine product or harness failure, stop this closeout and record the failure truthfully. Do not weaken the test or broaden this plan to hide it.

## 3. Workstream A — Correct the final stale operational wording

### 3.1 Current inconsistency

`docs/testing/verification-contract.md` correctly defines the release state as:

`DeferredOnInternalPredecessors`

but its packaged-source-verification section still contains wording equivalent to:

> Crates blocked by unpublished internal predecessors are skipped.

That sentence reintroduces the registry-state claim the final corrective pass intentionally removed.

The verifier proves only that a publishable crate has internal publishable predecessors that must be qualified/published first. It does not query crates.io to establish that those exact versions are absent.

### 3.2 Required correction

Replace the stale sentence with metadata-bounded language, for example:

> Crates deferred on internal publishable predecessors do not run packaged-source verification in the pre-publication pass. Their package/source verification remains deferred until the required predecessors are available through the normal manual publication sequence.

The exact prose may vary, but it must satisfy all of the following:

- use `deferred`, not `skipped = passed`;
- refer to internal predecessors without asserting their live registry state;
- make clear that deferred crates have not completed packaged-source verification;
- make clear that the operator must validate them later in publication order;
- do not introduce registry probing as a prerequisite.

### 3.3 Repository rejection search

Search current operational guidance for stale forms, at minimum:

- `unpublished internal predecessors`
- `unpublished predecessors`
- `BlockedOnUnpublishedInternalDeps`
- `path-dep crates skipped`
- `partially warm`
- `ci_truthful_closure_followup_results.md`

Historical planning documents may retain old terminology when clearly describing historical state. Current operational docs and the authoritative closure record must not.

## 4. Workstream B — Establish the exact proof-bearing SHA

### 4.1 Why fresh proof is required

The prior final corrective pass changed executable xtask code in `tools/xtask/src/verify.rs` and `tools/xtask/src/main.rs` at:

`3aced41c33b79a6e301ebb3ed4d777136becc65e`

The current authoritative results still identify:

`8265f1ef678f91ceeded86092dcbf5c073d3e8c9`

as the implementation state on which local full/release verification was executed.

That older evidence does not prove the final renamed executable state, even if the rename was intended to be behavior-preserving.

### 4.2 Prepare one proof-bearing commit

Before running the final commands:

1. apply the Workstream A wording correction;
2. make any strictly necessary current-plan/status edits that affect repository guards;
3. commit those changes;
4. ensure the worktree is clean;
5. record the exact resulting SHA as the **proof-bearing SHA**.

Do not edit `tools/xtask` merely to create a new implementation SHA. The existing executable implementation should remain unchanged unless verification reveals a real defect.

If any executable code changes after the proof-bearing SHA is established, discard the evidence and repeat the final verification sequence against the new clean commit.

### 4.3 Verify repository state before proof

Record:

- exact `git rev-parse HEAD`;
- `git status --porcelain` output is empty;
- Rust/Cargo/nextest versions if the existing evidence format requires them;
- whether the proof is local or hosted.

Dirty-tree `verify-release --allow-dirty` output is not final release evidence.

## 5. Workstream C — Run one authoritative final verification sequence

Run the three existing verification levels exactly once against the clean proof-bearing SHA after focused/preflight issues are resolved.

### 5.1 Routine verification

```bash
cargo xtask verify
```

Record:

- exit status;
- total steps passed/failed;
- end-to-end duration;
- any materially slow step if already emitted by xtask.

Required result: all routine steps pass.

### 5.2 Full verification

```bash
cargo xtask verify-full
```

Record:

- exit status;
- total verifier steps passed/failed;
- broad test pass/fail/skip totals;
- end-to-end duration;
- the identity and disposition of any remaining specialist skip.

Expected current contract:

- zero unexplained failures;
- `test_worker_crash_recovery` may remain the explicitly documented specialist test only if its existing deterministic preflight/disposition remains valid;
- no new ignores or filters may be added.

### 5.3 Release verification

```bash
cargo xtask verify-release
```

Record:

- exit status;
- all release phases;
- total publishable crate count;
- packaged-source-verified count;
- deferred-on-internal-predecessor count;
- assembled-only count, if nonzero;
- `NotPrepublishable` count;
- failed count;
- end-to-end duration.

Expected semantics:

- deferred crates are explicitly deferred, not individually passed;
- zero `Failed` states;
- zero `NotPrepublishable` states unless a new real release blocker is discovered;
- every deferred crate names its internal predecessors;
- no publication occurs;
- no registry credentials are consumed.

Do not copy the historical `39 publishable / 9 verified / 30 deferred` counts without checking the actual final output.

### 5.4 Dirty-tree contract spot check

If the dirty-tree behavior has not changed since the last directly recorded injection, it does not need another expensive full suite. A focused spot check is sufficient:

- dirty tree causes `cargo xtask verify-release` to fail before package qualification;
- `--allow-dirty` emits a prominent diagnostic warning and is not recorded as release evidence.

Do not leave the tree dirty for the authoritative final run.

## 6. Workstream D — Reconcile the authoritative closure evidence

Update:

`plans/ci_verification_release_truthful_closure_results.md`

Only after the authoritative final verification sequence completes.

### 6.1 Evidence roles must be explicit

Replace the current misleading "Final corrective pass" row that points at `eb74304...`.

Use distinct roles rather than one overloaded final SHA. At minimum record:

| Evidence role | SHA | Required meaning |
|---|---|---|
| Prior implementation qualification | `8265f1e...` | Historical local evidence before the final state rename |
| Corrective implementation | `3aced41c...` | Commit that introduced truthful defer naming and evidence corrections |
| Final proof-bearing SHA | `<new SHA>` | Clean commit on which final `verify`, `verify-full`, and `verify-release` were executed |
| Hosted routine CI | `232e2de...` or newer observed run | Exact SHA exercised by the cited hosted run |
| Final evidence/documentation SHA | `<documentation commit SHA>` | Commit containing the reconciled closure record; may be later than proof-bearing SHA if documentation-only |

If a new normal hosted CI run naturally executes the proof-bearing or evidence commit, record it. Do not change workflows to manufacture hosted proof.

### 6.2 Final verification table

Replace stale local result data with the actual final run or clearly label older data as historical.

The authoritative final section must state:

- exact proof-bearing SHA;
- clean-tree status;
- routine result and duration;
- full result, test counts, and duration;
- release result and actual qualification counts;
- whether the one specialist test remains excluded and why;
- dirty-tree behavior;
- branch-protection status.

### 6.3 Hosted CI evidence

The existing directly observed hosted evidence remains valid for its exact SHA:

- run `31426515369`;
- job `93579387906`;
- SHA `232e2de154e2fafe4a8c597fa5a7efa608f55457`;
- successful conclusion;
- full cache-key match;
- approximately 12 minutes for routine verification and 13 minutes overall;
- `<10m` target not demonstrated;
- 15-minute blocking threshold not exceeded.

If newer hosted evidence is available naturally, prefer the newer successful run and record exact observed values.

Do not characterize cache state as `warm`, `cold`, or `partially warm` unless independently measured beyond the cache-key result.

### 6.4 Branch protection

Keep:

`EXTERNALLY UNVERIFIED`

unless GitHub repository settings are directly inspected by an environment capable of doing so.

Do not infer branch protection from workflow files.

## 7. Workstream E — Close the planning record

Update:

`plans/ci_truthful_closure_final_corrective_pass.md`

only after all of its acceptance criteria are genuinely satisfied.

Required closure behavior:

- change `Status: PLANNED` to `Status: COMPLETE`;
- mark acceptance criteria complete only when supported by final evidence;
- add a short closure note identifying the proof-bearing SHA and authoritative results document;
- do not rewrite the plan's historical problem statement as though the issues never existed.

This new closeout plan may also be marked `COMPLETE` in the same evidence-documentation commit after all acceptance criteria below are met.

## 8. Minimal execution order

Use this order to avoid repeated long runs:

1. correct the stale verification-contract wording;
2. perform repository rejection searches;
3. run focused doc/repo-guard checks as needed;
4. commit the correction and establish the clean proof-bearing SHA;
5. run `cargo xtask verify`;
6. run `cargo xtask verify-full`;
7. run `cargo xtask verify-release`;
8. stop immediately if any command exposes a real blocker;
9. reconcile the authoritative results using those exact outputs;
10. update final corrective-plan status/checkboxes;
11. mark this closeout plan complete;
12. commit documentation/evidence only;
13. run lightweight repository/doc guards on the evidence commit if required.

Do not rerun the expensive full/release suites merely because the final commit changes only evidence Markdown. Clearly distinguish the proof-bearing SHA from the later evidence-documentation SHA.

## 9. Explicit acceptance criteria

This closeout is complete only when every applicable item below is true.

### 9.1 Operational wording

- [x] `docs/testing/verification-contract.md` contains no current claim that deferred predecessors are known to be unpublished unless direct registry evidence exists.
- [x] packaged-source documentation uses `deferred` semantics rather than `skipped = passed` semantics.
- [x] current operational docs use `DeferredOnInternalPredecessors` consistently.
- [x] no current operational document points to nonexistent `plans/ci_truthful_closure_followup_results.md`.
- [x] no current authoritative evidence uses unsupported `partially warm` cache wording.

### 9.2 Proof-bearing repository state

- [x] a specific proof-bearing commit SHA is recorded.
- [x] the worktree is clean before authoritative verification begins.
- [x] no executable code changes occur after the proof-bearing SHA without restarting verification.
- [x] no test assertions, ignores, filters, or product behavior are modified solely to obtain green evidence.

### 9.3 Routine verification

- [x] `cargo xtask verify` exits zero on the proof-bearing SHA.
- [x] every routine verifier step passes.
- [x] the end-to-end duration is recorded accurately.
- [x] no additional hosted CI job/lane is introduced.

### 9.4 Full verification

- [x] `cargo xtask verify-full` exits zero on the same proof-bearing SHA.
- [x] final test pass/fail/skip counts are recorded from actual output.
- [x] there are zero unexplained failures.
- [x] any remaining specialist skip is explicitly named and retains its evidence-backed disposition.
- [x] no new `#[ignore]` or hidden selector is added for closure.
- [x] the end-to-end duration is recorded accurately.

### 9.5 Release verification

- [x] `cargo xtask verify-release` exits zero on the same clean proof-bearing SHA.
- [x] the actual final publishable-crate count is recorded.
- [x] the actual packaged-source-verified count is recorded.
- [x] the actual deferred count is recorded.
- [x] every deferred crate names its internal predecessors.
- [x] deferred crates are not counted as packaged-source verified.
- [x] there are zero unexpected `Failed` states.
- [x] there are zero `NotPrepublishable` states, or the closeout remains blocked with the real release blocker documented.
- [x] publication ordering remains valid/topological.
- [x] the command performs no publication and consumes no registry credentials.
- [x] the end-to-end duration is recorded accurately.

### 9.6 Dirty-tree behavior

- [x] normal `verify-release` remains fail-by-default on a dirty tree.
- [x] `--allow-dirty` remains an explicit diagnostic/local override and is not used as release evidence.

### 9.7 Evidence record

- [x] the authoritative closure record names exactly one authoritative document.
- [x] the evidence table no longer labels `eb74304...` as the final corrective pass.
- [x] prior evidence, corrective implementation, proof-bearing SHA, hosted SHA, and final documentation SHA are distinguished when they differ.
- [x] local final verification data corresponds to the proof-bearing SHA actually tested.
- [x] release qualification counts come from the final verifier output rather than copied historical values.
- [x] hosted timing/cache claims are limited to directly observed facts.
- [x] `<10m` hosted target remains recorded as not demonstrated unless a qualifying run actually demonstrates it.
- [x] the 15-minute blocking threshold remains the blocking criterion; no CI architecture is expanded to chase the nonblocking target.
- [x] branch protection is still `EXTERNALLY UNVERIFIED` unless directly inspected.

### 9.8 Planning/status closure

- [x] `plans/ci_truthful_closure_final_corrective_pass.md` is marked `COMPLETE` only after its acceptance criteria are met.
- [x] its acceptance checklist is reconciled to actual evidence rather than mechanically checked.
- [x] this closeout plan is marked `COMPLETE` only after this plan's criteria are met.
- [x] the authoritative results document points to the final proof-bearing and documentation SHAs.
- [x] no current plan/result pair simultaneously claims both `PLANNED` and completed closure for the same final pass.

### 9.9 Scope preservation

- [x] routine CI remains one Ubuntu job.
- [x] no matrix, selector, scheduled lane, release lane, or evidence pipeline is added.
- [x] no local registry emulator or registry probing subsystem is added.
- [x] crates.io publication remains manual.
- [x] no WAF/product behavior change is included.
- [x] no unrelated architecture/skills/documentation cleanup is bundled into the closeout commit.

## 10. Stop conditions

Do **not** mark the line complete if any of the following occurs:

- `verify`, `verify-full`, or `verify-release` fails on the clean proof-bearing SHA;
- verification evidence is taken from a different executable state than the SHA claimed;
- a code change lands after full/release proof and the evidence is not rerun;
- a deferred crate is presented as packaged-source verified;
- the release verifier reports an unexplained `Failed` or `NotPrepublishable` crate;
- stale live documentation still claims internal predecessors are known to be unpublished without registry evidence;
- the authoritative results table still misidentifies the corrective/proof SHA;
- plan checkboxes are marked complete without corresponding evidence;
- a test is weakened, filtered, or ignored to obtain closure;
- CI/release architecture is expanded to solve what is now only an evidence-record problem.

If a stop condition triggers, record the exact blocker and open a separate narrowly scoped corrective plan only if genuine implementation work is required.

## 11. Expected final repository state

At successful completion:

- the executable verifier remains the corrected `DeferredOnInternalPredecessors` design;
- current release documentation describes deferment without guessing registry state;
- one clean proof-bearing SHA has successful routine, full, and release verification evidence;
- one authoritative results file records that proof accurately;
- hosted CI evidence is attributed only to the SHA it actually exercised;
- branch protection remains honestly external unless independently verified;
- the previous final corrective plan and this closeout plan both show truthful completed status;
- the verification/release-simplification roadmap has no remaining implementation or evidence blocker.

Once these criteria are satisfied, this line of work should be closed rather than extended again.

## Closure Note

Closed 2026-08-11. Proof-bearing SHA: `ab9c787f95d1bf65ca3ef1aff302dd1edbb67756`. Authoritative results: `plans/ci_verification_release_truthful_closure_results.md`.