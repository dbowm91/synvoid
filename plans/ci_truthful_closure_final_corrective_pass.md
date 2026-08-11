# CI Truthful Closure — Final Corrective Pass

**Status:** COMPLETE  
**Created:** 2026-08-11  
**Closed:** 2026-08-11  
**Baseline reviewed:** `eb74304cce8146171e81eab08ae976e9873b460e`  
**Depends on:** `plans/ci_truthful_closure_followup_roadmap.md` and completed follow-up Phases 1-3  
**Purpose:** Remove the last small truthfulness and documentation inconsistencies in the CI/release-verification closure line without reopening the architecture, expanding CI, or changing the manual release model.

## 1. Objective

The functional work from the truthful-closure roadmap is substantially complete:

- routine CI remains one Ubuntu job invoking `cargo xtask verify`;
- the malformed/overlong UTF-8 WAF case is now positively detected rather than documented as an accepted miss;
- full verification is green apart from the explicitly specialist worker-crash test;
- release verification distinguishes verified crates from deferred crates;
- hosted CI is green and remains under the existing 15-minute blocking threshold;
- crates.io publication remains manual and outside CI/xtask.

This final pass is intentionally narrow. It exists only to ensure that names, evidence records, and closure documents describe what the implementation can actually prove.

The pass has four required workstreams:

1. make the release-defer state name match the evidence actually available;
2. remove or repair the nonexistent superseding-results reference;
3. reconcile implementation, documentation, hosted-proof, and documentation-head SHAs plus release-result wording;
4. correct hosted cache/timing wording so a full cache-key hit is not described as a partially warm cache without evidence.

No other CI, test, release, WAF, dependency, or architecture work belongs in this pass.

## 2. Frozen constraints

The following constraints are non-negotiable for this corrective pass.

### 2.1 CI model

Keep:

- one routine GitHub Actions workflow/job;
- Ubuntu-only routine CI;
- `cargo xtask verify` as the routine hosted entry point;
- the existing full/release commands as manually invoked verification levels.

Do not add:

- another CI job;
- a matrix;
- affected-package selection;
- scheduled verification;
- a release workflow;
- artifact upload lanes;
- dynamic test scheduling;
- a second hosted verification tier.

### 2.2 Release model

Keep crates.io publication operator-driven and manual.

Do not add:

- `cargo publish` execution to xtask or CI;
- registry credentials to workflows;
- a local registry emulator;
- crates.io API probing solely to classify pre-publication state;
- automated sequential publication;
- GitHub Release automation.

### 2.3 Test and product behavior

This pass should not modify product behavior.

In particular:

- do not alter WAF detection thresholds or normalization behavior;
- do not change the malformed-input security contract established by the completed follow-up;
- do not add ignores or filters;
- do not weaken existing test assertions;
- do not reclassify failing tests merely to obtain green evidence.

If implementation unexpectedly requires product changes, stop and open a separate plan rather than broadening this closure pass.

## 3. Workstream A — Rename the inferred release-defer state truthfully

### 3.1 Current issue

The release verifier currently uses a state named approximately:

`BlockedOnUnpublishedInternalDeps`

and human output such as:

`Deferred (unpublished predecessors)`

The verifier can prove from Cargo metadata that a crate has internal publishable predecessors and that those predecessors must appear earlier in the manual publication order. It does not independently prove that the exact predecessor versions are absent from crates.io at execution time.

The current behavior is conservative and operationally safe, but the state name claims more registry knowledge than the verifier actually possesses.

### 3.2 Required correction

Rename the state and associated output to describe only what is proven from workspace metadata.

Preferred terminology:

- `DeferredOnInternalPredecessors { predecessors }`

or another equally precise name.

Human-readable output should use wording such as:

- `Deferred pending internal predecessors`
- `Deferred on internal predecessors`
- `Registry qualification deferred until predecessor publication/availability`

Avoid asserting `unpublished` unless the verifier has direct registry evidence. This pass must not add registry querying merely to preserve the old name.

### 3.3 Scope of rename

Update all directly affected locations together:

- `CrateQualification` variant;
- release qualification summary fields if their names contain `unpublished`;
- JSON output field names if they encode the same unsupported claim;
- human-readable summary text;
- follow-up instructions;
- unit tests for qualification state/summary serialization;
- `docs/testing/verification-contract.md`;
- release documentation that references the state;
- authoritative closure-results wording.

If changing a JSON field would break a documented external contract, retain compatibility explicitly and document the semantic name separately. Do not introduce a versioned schema framework for this pass.

### 3.4 Required semantics after rename

The operational meaning must remain unchanged:

- deferred crates do not count as assembled;
- deferred crates do not count as packaged-source verified;
- real `Failed` or `NotPrepublishable` states remain release blockers;
- a release verification run may still exit zero when the only outstanding package states are valid dependency-order deferments;
- manual follow-up commands remain explicit;
- the final human summary must continue to say that registry checks are deferred rather than implying complete package qualification.

### 3.5 Focused validation

At minimum verify:

1. root/no-internal-predecessor crate => eligible for assembly/verification;
2. dependent publishable crate => deferred on named internal predecessor;
3. deferred crate is absent from assembled/verified totals;
4. JSON and human summaries use equivalent semantics;
5. `Failed` and `NotPrepublishable` still produce nonzero release verification;
6. publication order remains unchanged and topological.

## 4. Workstream B — Repair the authoritative closure-document chain

### 4.1 Current issue

`plans/ci_verification_release_truthful_closure_results.md` currently begins with a superseding reference to:

`plans/ci_truthful_closure_followup_results.md`

That target does not exist on the reviewed baseline.

A closure document must not point readers to a nonexistent authoritative record.

### 4.2 Required resolution

Choose the smallest truthful option.

Preferred options, in order:

1. If the existing `ci_verification_release_truthful_closure_results.md` is intended to remain the authoritative consolidated result, remove the nonexistent `Superseded by` line and make that explicit.
2. If the repository's documentation structure genuinely requires a dedicated follow-up results file, create it only if it adds material value and make the authority chain unambiguous.

Default to option 1. Do not create another closure file merely to satisfy the stale link if the existing consolidated results document already contains the final evidence.

### 4.3 Authority requirements

After the pass:

- exactly one document should be clearly authoritative for this CI/release closure line;
- older closure documents may point to it as superseded;
- the authoritative document must not itself point to a missing or less-current record;
- no two documents should both claim incompatible `COMPLETE` states or different final evidence without explaining the distinction.

### 4.4 Rejection check

Search the repository for:

`ci_truthful_closure_followup_results`

and ensure no stale reference remains unless that file actually exists and is deliberately authoritative.

## 5. Workstream C — Reconcile SHA and release-result evidence

### 5.1 Current issue

Several distinct commits represent different kinds of evidence and should not be collapsed into one ambiguous `Final SHA` field.

Known reviewed sequence:

- `8265f1ef678f91ceeded86092dcbf5c073d3e8c9` — release-qualification implementation/fix state used for local final verification evidence;
- `232e2de154e2fafe4a8c597fa5a7efa608f55457` — documentation reconciliation and the commit exercised by hosted CI run `31426515369` / job `93579387906`;
- `eb74304cce8146171e81eab08ae976e9873b460e` — current reviewed documentation/evidence head before this final corrective plan.

The authoritative results currently mix phrases such as `Final SHA`, `Documentation SHA`, and later references to another documentation commit in a way that can imply they are all the same evidence boundary.

### 5.2 Required evidence model

Use a small explicit evidence table rather than overloading one field.

Recommended fields:

| Evidence role | SHA | Meaning |
|---|---|---|
| Implementation qualification SHA | `<sha>` | Code state on which local full/release verification was executed |
| Hosted routine CI SHA | `<sha>` | Exact commit exercised by the cited GitHub Actions run |
| Documentation reconciliation SHA | `<sha>` | Commit that reconciled closure docs with implementation |
| Final corrective documentation/code SHA | `<sha>` | Commit produced by this pass, if implementation wording/state names change |

If the release-state rename changes Rust code, the new corrective commit becomes the new implementation head. Do not claim prior `verify-full`/`verify-release` runs exercised that new code unless they are rerun.

### 5.3 Fresh proof requirement after code changes

If Workstream A changes `tools/xtask/src/verify.rs` or any executable code, run fresh authoritative verification on the resulting clean implementation head:

1. `cargo xtask verify`
2. `cargo xtask verify-full`
3. `cargo xtask verify-release`

Record:

- exact commit SHA;
- clean-tree status;
- exit status;
- test totals where available;
- release qualification counts;
- end-to-end durations.

Do not reuse older local full/release evidence as proof of the renamed implementation.

If Workstream A is implemented as a pure internal rename with zero behavioral change, the commands are still required because the final closure claim should reference the actual final executable state.

### 5.4 Hosted proof requirement

A new hosted run is desirable if the final corrective implementation changes code that routine CI compiles. However, do not alter CI or add workflows to obtain it.

Use the normal push-triggered `ci` run if one occurs naturally from the corrective commit.

Record the run only after it completes successfully. If no new hosted run is available at documentation time:

- retain the last directly observed hosted proof with its exact SHA;
- state that it exercises the immediately preceding equivalent routine-verification implementation where that is true;
- do not claim the latest commit itself was hosted-verified.

### 5.5 Release-result terminology correction

Replace stale table wording such as:

- `PASS (path-dep crates skipped)`

with wording matching the explicit qualification model, for example:

- package qualification: `PASS — 9 verified, 30 deferred on internal predecessors`
- packaged-source verification: `9 verified now; 30 registry checks deferred`

Do not call deferred crate checks `PASS` individually.

The overall `verify-release` command may be recorded as successful only under the documented pre-publication-readiness semantics.

### 5.6 Release counts

Verify the actual current counts before writing them into the final evidence document. Do not blindly preserve `9 verified / 30 deferred / 39 publishable` if the final verifier output differs.

## 6. Workstream D — Correct hosted cache and timing language

### 6.1 Current evidence

The reviewed hosted run reports:

- workflow run: `31426515369`;
- job: `93579387906`;
- commit: `232e2de154e2fafe4a8c597fa5a7efa608f55457`;
- job conclusion: success;
- cache restore: full key match;
- `cargo xtask verify`: approximately 722.9 seconds (~12m03s);
- overall job: approximately 13m12s;
- existing warm-cache target: under 10 minutes;
- existing blocking threshold: over 15 minutes.

### 6.2 Current wording issue

The closure text describes the run as effectively or partially warm despite the Actions log reporting a full cache-key match.

A full cache-key match does not guarantee zero recompilation, but it is the observed cache fact. The evidence record should not infer a different cache state merely because compilation work remained.

### 6.3 Required wording

Use only directly observed facts:

- `Cache key restore: full match`
- `Routine verify duration: ~12m03s`
- `Overall job duration: ~13m12s`
- `<10m target: not demonstrated`
- `15m blocking threshold: not exceeded`
- `Substantial recompilation occurred despite the full cache-key restore`

Do not label the run `warm`, `cold`, or `partially warm` unless the repository has a defined, evidence-backed cache-state metric beyond the key-match signal.

### 6.4 Performance disposition

This pass must leave CI performance as a nonblocking residual unless a fresh normal hosted run exceeds the established 15-minute blocking threshold.

Do not respond to the ~12-13 minute run by adding:

- more caches;
- custom cache partitioning;
- job splitting;
- selector logic;
- build graphs;
- remote build systems;
- CI matrices.

Any future optimization should be separately justified from measurements.

## 7. Documentation reconciliation checklist

Review and update only files actually affected by these four corrections.

Likely files:

- `tools/xtask/src/verify.rs`;
- focused xtask tests in the same module or existing test location;
- `docs/testing/verification-contract.md`;
- `docs/releasing.md` if it contains the old defer wording;
- `plans/ci_verification_release_truthful_closure_results.md`;
- `plans/ci_truthful_closure_followup_roadmap.md` only if its terminology now conflicts;
- completed follow-up phase documents only where they contain a currently false authoritative statement.

Avoid broad historical rewriting. Historical plans may retain terminology that was accurate to their execution point if they are clearly historical; only current operational guidance and authoritative closure evidence must match the final implementation.

## 8. Validation sequence

Use the smallest sequence that establishes final truth.

### 8.1 During implementation

Run focused checks first:

1. `cargo fmt --all -- --check`
2. focused xtask qualification tests;
3. `cargo check -p xtask` or repository-equivalent xtask build check;
4. `cargo xtask verify-release --dry-run` only if useful for inspecting presentation/command expansion.

Do not run repeated full verification after every wording edit.

### 8.2 Final local proof

After all executable changes are committed and the tree is clean:

1. `cargo xtask verify`
2. `cargo xtask verify-full`
3. `cargo xtask verify-release`

Capture results once against the exact final implementation SHA.

### 8.3 Final documentation proof

After evidence is inserted:

- repository markdown/link guards must pass;
- search for nonexistent superseding references;
- search for stale `BlockedOnUnpublishedInternalDeps` / `unpublished predecessors` wording in current operational docs if the state was renamed;
- search for `path-dep crates skipped` in the authoritative results;
- search for `partially warm` / `warm-cache` claims that contradict observed hosted evidence;
- ensure branch protection remains `EXTERNALLY UNVERIFIED` unless settings were directly inspected.

A documentation-only commit after the final implementation verification is acceptable. If so, distinguish implementation-proof SHA from documentation SHA explicitly.

## 9. Acceptance criteria

This final corrective pass is complete only when all of the following are true:

### Release truthfulness

- [ ] the deferred release state name does not claim that predecessor crates are unpublished unless direct registry evidence exists;
- [ ] every deferred crate still names its internal predecessors;
- [ ] deferred crates are not counted as assembled or packaged-source verified;
- [ ] real package failures remain failures;
- [ ] `NotPrepublishable` remains a release blocker;
- [ ] the verifier still performs no publication and consumes no registry credentials;
- [ ] publication ordering remains topological;
- [ ] focused qualification tests pass.

### Closure-document authority

- [ ] no authoritative closure document points to a nonexistent `ci_truthful_closure_followup_results.md` file;
- [ ] exactly one current closure record is clearly authoritative;
- [ ] older superseded records point only to existing, more-current records;
- [ ] no current `COMPLETE` document contradicts another current `COMPLETE` document.

### Evidence reconciliation

- [ ] implementation verification SHA is recorded distinctly from hosted CI SHA and documentation SHA when they differ;
- [ ] any executable change in this pass receives fresh `verify`, `verify-full`, and `verify-release` proof on a clean committed head;
- [ ] the authoritative release table uses `verified` / `deferred` semantics rather than `skipped = pass` language;
- [ ] actual final publishable/verified/deferred counts are taken from the final verifier output;
- [ ] dirty-tree release behavior remains fail-by-default with explicit `--allow-dirty` diagnostic override;
- [ ] branch protection remains explicitly `EXTERNALLY UNVERIFIED` unless directly inspected.

### Hosted timing truthfulness

- [ ] the recorded hosted run's full cache-key match is stated accurately;
- [ ] no unsupported `partially warm` characterization remains for that run;
- [ ] routine verify duration and overall job duration are distinguished;
- [ ] the under-10-minute target is explicitly recorded as not demonstrated if the observed run remains ~12-13 minutes;
- [ ] the 15-minute blocking threshold is explicitly recorded as not exceeded;
- [ ] no CI complexity is added solely to improve this nonblocking timing residual.

### Scope preservation

- [ ] routine CI remains one Ubuntu job;
- [ ] no CI matrix or additional routine lane is introduced;
- [ ] no registry emulator is introduced;
- [ ] no release automation is introduced;
- [ ] no WAF/product behavior changes are included;
- [ ] no tests are ignored, filtered, or weakened for closure;
- [ ] no unrelated refactor is bundled into the pass.

## 10. Stop conditions

Do not mark this pass complete if any of the following remains:

- a release state still asserts predecessor publication status without evidence;
- deferred work is presented as completed package verification;
- an authoritative results document points at a missing file;
- the final evidence document claims one SHA covered checks actually executed on another SHA without distinguishing them;
- the release table still describes deferred crates as `skipped` passes;
- hosted cache language contradicts the Actions log;
- a code change lands after the recorded final `verify-full` / `verify-release` evidence;
- the final full or release verifier fails;
- a new CI/release subsystem is introduced to solve these documentation-level gaps.

## 11. Handoff guidance

Treat this as a final polish/closure task, not another verification project.

Expected implementation size should be small:

- one localized release-state rename and focused tests;
- a handful of documentation/result corrections;
- one final authoritative verification pass;
- normal hosted CI evidence if the push naturally produces it.

Prefer deleting inaccurate wording over adding abstractions. Prefer precise evidence roles over a generic `Final SHA`. Prefer `deferred on internal predecessors` over guessing registry publication state. Preserve the intentionally simple CI and manual-release model.

Once the acceptance criteria above are met, this CI verification/release-simplification line can be marked complete without another roadmap extension.