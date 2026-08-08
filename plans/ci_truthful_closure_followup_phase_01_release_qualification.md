# CI Truthful Closure Follow-up — Phase 1: Release Qualification Semantics

**Status:** PLANNED  
**Created:** 2026-08-08  
**Roadmap:** `plans/ci_truthful_closure_followup_roadmap.md`  
**Baseline reviewed:** `584e6fa05b5e570a13140105ca85fb237dc65468`

## 1. Objective

Correct the remaining semantic gap in `cargo xtask verify-release` so that every publishable crate receives an explicit, truthful qualification result and no skipped package step is reported as a successful package step.

The existing verifier already provides useful metadata, semver, path-aware package-content, dirty-tree, and topological-order checks. Preserve those. This phase is specifically about the boundary between:

- what can be proven from the workspace before publication;
- what Cargo can package before internal predecessors exist on crates.io;
- what must be verified manually after predecessors are published;
- how those states are represented in output and closure evidence.

Do not solve this by introducing registry emulation or publication automation.

## 2. Current defect

At the reviewed baseline, `verify-release` checks whether a publishable crate has any path dependency. If it does, the crate is skipped from both:

- package assembly; and
- packaged-source verification.

The command then still prints a global success message for package assembly. This violates the prior closure contract because skipped work and successful work are not equivalent.

The implementation also uses the broad condition "has any path dependency" rather than determining whether the path dependency is actually an unpublished publishable predecessor, a non-publishable internal workspace dependency, or otherwise registry-resolvable.

## 3. Required qualification model

Introduce a small explicit result model in xtask. Keep it local to release verification; do not create a general workflow engine.

Recommended states:

- `Assembled` — `cargo package --no-verify -p <crate>` completed successfully.
- `PackagedSourceVerified` — normal `cargo package -p <crate>` completed successfully, including package build verification.
- `BlockedOnUnpublishedInternalDeps { deps }` — the package step cannot currently complete because named publishable internal predecessors are not yet registry-resolvable.
- `NotPrepublishable { reason }` — use only if a publishable crate structurally depends on a non-publishable internal crate or another condition makes its intended crates.io publication impossible. This is a release blocker, not a benign skip.
- `Failed { phase, reason }` — the attempted qualification step failed for a reason other than an explicitly understood unpublished-predecessor condition.

The exact Rust type names may differ, but the semantic distinctions must be preserved.

Do not use a single Boolean "skipped" flag for all cases.

## 4. Workstream A — Build a precise internal dependency graph

Use Cargo metadata already loaded by xtask.

For every publishable crate:

1. enumerate internal workspace dependencies;
2. distinguish publishable internal dependencies from non-publishable/internal-tooling dependencies;
3. record each dependency's package name and actual workspace version;
4. validate that every publishable internal dependency has a compatible non-wildcard semver requirement;
5. determine whether the dependency is a predecessor in the manual publication graph;
6. detect cycles among publishable crates and fail clearly if one exists.

Acceptance requirements:

- no hardcoded crate-name list when Cargo metadata can provide the information;
- no dependency is classified as "unpublished" merely because it has a local path;
- a publishable crate depending on a non-publishable internal crate is surfaced as a release-contract defect unless there is an explicit supported packaging mechanism already present;
- publication order remains a topological ordering of publishable internal dependencies.

## 5. Workstream B — Package assembly semantics

### B1. Attempt assembly when feasible

For each publishable crate, run the existing package-content inspection first.

Then determine whether `cargo package --no-verify -p <crate>` can be expected to resolve its internal dependencies in the current registry state.

Preferred behavior:

- attempt assembly for crates with no unresolved internal publishable predecessors;
- if Cargo reports a missing internal predecessor that is known to be a publishable workspace crate not yet on crates.io at the required version, record `BlockedOnUnpublishedInternalDeps` with the exact dependency name(s);
- if Cargo fails for metadata, file-content, manifest, build-script, readme/license, or unrelated registry reasons, record `Failed` and fail the verifier;
- do not convert arbitrary `cargo package` failures into benign predecessor blocks based only on stderr substring matching.

### B2. Do not claim skipped assembly passed

Replace summary language such as:

`Package assembly successful for all publishable crates`

when some crates were not assembled.

The summary must instead report counts such as:

- assembled now;
- packaged-source verified now;
- deferred because named internal predecessors are unpublished;
- blockers/failures.

A deferred crate may be acceptable for pre-publication readiness only if all criteria in Section 7 are satisfied.

## 6. Workstream C — Packaged-source verification semantics

For crates whose dependency graph is registry-resolvable at the currently published versions, run normal `cargo package -p <crate>` and require success.

For crates blocked by unpublished internal predecessors:

- record the predecessor names;
- record the crate's position in the topological publication order;
- state the exact operator follow-up command to run after predecessor publication;
- do not mark the packaged-source check as passed.

Do not use the invalid historical syntax `cargo package --verify`; normal `cargo package` performs source verification unless `--no-verify` is supplied.

## 7. Acceptable deferred qualification contract

A publishable crate may be `BlockedOnUnpublishedInternalDeps` without failing the overall pre-publication readiness command only if **all** of the following are true:

1. every blocking dependency is a named publishable workspace predecessor;
2. its path dependency has a compatible, explicit semver requirement matching the workspace predecessor version;
3. package-content inspection passes;
4. metadata validation passes;
5. source/full verification passes;
6. there is no non-publishable internal dependency that would make crates.io publication impossible;
7. the publication graph is acyclic;
8. the manual publication order places every blocking predecessor first;
9. the output explicitly says the crate is **deferred**, not assembled or verified;
10. release documentation requires rerunning the crate's normal `cargo package` or `cargo publish --dry-run` after predecessors become registry-resolvable and before actual publication.

If any item is false, the crate is a release blocker.

## 8. Workstream D — Summary and exit semantics

The verifier's final release summary must distinguish:

- local source/full verification: pass/fail;
- metadata/semver/content inspection: pass/fail;
- package assembly: pass/fail/deferred by crate;
- packaged-source verification: pass/fail/deferred by crate;
- publication-order validation: pass/fail.

Recommended exit policy:

- nonzero for any real blocker/failure;
- zero may be allowed when the only non-passed package states are explicit `BlockedOnUnpublishedInternalDeps` states satisfying Section 7;
- if zero is used with deferred states, the human summary must say `PRE-PUBLICATION READY WITH DEFERRED REGISTRY CHECKS`, not imply every crate has been fully package-verified;
- JSON output, if supported for this path, must carry the same distinctions.

Do not add an elaborate status framework outside xtask.

## 9. Workstream E — Dirty-tree behavior

Preserve the current default:

- dirty tree => fail before authoritative release evidence;
- `--allow-dirty` => explicit diagnostic-only warning.

Verify that package commands receive `--allow-dirty` only when the xtask override was explicitly supplied.

Add or retain focused tests for:

- clean tree accepted;
- dirty tree rejected by default;
- dirty tree accepted only with override;
- diagnostic output states that overridden results are not release evidence.

## 10. Workstream F — Tests for qualification logic

Prefer unit tests around dependency classification and summary logic plus a small number of command-level fixtures. Do not create a local registry.

At minimum cover:

1. publishable crate with no internal deps => assembly/verification eligible;
2. publishable crate with publishable internal predecessor => deferred when predecessor is unavailable;
3. publishable crate with compatible internal semver => accepted dependency metadata;
4. wildcard internal semver => rejected;
5. incompatible internal semver => rejected;
6. publishable crate depending on non-publishable workspace crate => blocker;
7. cyclic publishable dependency graph => blocker;
8. deferred crate is not counted in assembled/verified totals;
9. arbitrary package failure is not mislabeled as an unpublished-predecessor deferment;
10. topological order puts dependencies before dependents.

If existing xtask test infrastructure makes process fixtures disproportionately expensive, extract pure dependency-classification helpers and test those directly.

## 11. Documentation changes required in this phase

Update only release-semantics documentation necessary for correctness. Final global reconciliation belongs to Phase 3.

At minimum adjust:

- `docs/testing/verification-contract.md` release section;
- `docs/releasing.md` if it describes package verification order;
- any xtask help text describing `verify-release`.

Required wording:

- actual publication is manual;
- normal `cargo package` is the packaged-source verification command;
- path-dependent crates may have registry checks deferred only for named unpublished publishable predecessors;
- deferred does not mean passed;
- after publishing predecessors, the operator must rerun the dependent crate's package/dry-run validation before publishing it.

## 12. Validation sequence

Use a bounded validation sequence.

During implementation:

1. `cargo fmt --all -- --check` for touched Rust;
2. focused xtask tests;
3. `cargo check -p xtask` or the repository-equivalent xtask build check;
4. `cargo xtask verify-release --dry-run` if useful to inspect command expansion/state reporting;
5. targeted release-verifier execution sufficient to exercise metadata/qualification logic.

Do **not** repeatedly run `verify-full` during this phase. Phase 3 owns authoritative broad proof.

## 13. Acceptance criteria

Phase 1 is complete only when:

- [ ] every publishable crate gets an explicit qualification state;
- [ ] no deferred crate is reported as successfully assembled or packaged-source verified;
- [ ] internal dependency classification comes from Cargo metadata rather than path-presence alone;
- [ ] publishable predecessors are distinguished from non-publishable internal dependencies;
- [ ] non-publishable internal dependencies of publishable crates fail the release contract unless explicitly supportable;
- [ ] wildcard and incompatible internal semver requirements fail;
- [ ] publication order is topological and cycle-checked;
- [ ] package assembly is attempted wherever registry resolution permits it;
- [ ] normal `cargo package` is used for packaged-source verification;
- [ ] deferred registry checks name exact predecessor crates and required follow-up commands;
- [ ] real package failures remain failures;
- [ ] dirty-tree enforcement remains fail-by-default;
- [ ] xtask/workflows still contain no automated publishing or registry credential handling;
- [ ] focused tests for the qualification model pass;
- [ ] release documentation matches the implemented semantics.

## 14. Stop conditions

Do not mark this phase complete if:

- a skipped crate is counted as passed;
- a path dependency is treated as automatically unpublished without graph analysis;
- a publishable crate cannot ever be published because of a non-publishable internal dependency and the verifier still returns readiness;
- dependency cycles exist;
- package failures are hidden by broad stderr matching;
- actual publication is added to xtask or CI;
- a local registry emulator is introduced solely to satisfy this plan.

## 15. Handoff note

The desired result is a small, truthful release-readiness verifier. Prefer explicit state and precise diagnostics over machinery. The important invariant is that an operator can tell exactly which crates are proven now, which are deferred solely because predecessor versions are not yet on crates.io, and what must happen before each deferred crate is published.
