# CI, Full Verification, and Release Truthful Closure Roadmap

**Status:** COMPLETE  
**Created:** 2026-08-04  
**Completed:** 2026-08-07  
**Baseline:** `f8c19b0f8c4abe73818ae8794d45abcf293d9b78`  
**Final SHA:** (see closure record)  
**Scope:** Correct the remaining test, harness, release-evidence, and closure-accounting gaps after the CI simplification work.  
**Primary constraint:** Preserve the simplified one-workflow, one-job, manually released operating model.

## 1. Purpose

The CI simplification and release-verifier corrections have substantially improved the repository:

- routine CI is a single Linux job invoking `cargo xtask verify`;
- affected-package selectors, lane manifests, scheduled qualification workflows, release workflows, and automated publishing are absent;
- routine verification has been consolidated and is within the intended warm-cache budget;
- `verify-full` no longer deliberately re-runs the routine test binaries before the workspace suite;
- `verify-release` now fails on a dirty tree by default, rejects wildcard internal dependency requirements, uses path-aware package-content rules, and cannot publish;
- package metadata and internal path dependency versions have been populated across the publishable workspace graph.

The line of work is not yet truthfully closed. The current verification contract records a non-green `verify-full` population and classifies the failures as five product regressions, twenty-one stale expectations, two environment-dependent tests, and three harness or timeout defects. Several entries classified as stale are security-sensitive WAF cases where missing detection, false-positive behavior, or changed attack categorization cannot be accepted solely because the current implementation behaves differently from the test.

This roadmap closes that gap without restoring the former CI apparatus or expanding routine CI.

## 2. Closure Principle

A verification command is not complete merely because its wrapper is structurally correct. Closure requires the command to pass against a clean current head while retaining meaningful assertions.

The implementation must therefore distinguish four categories using evidence rather than convenience:

1. **Product regression:** implementation violates an intended product, persistence, security, routing, or protocol contract.
2. **Stale expectation:** the implementation contract intentionally changed and the test asserts obsolete behavior.
3. **Harness defect:** the product behavior cannot be evaluated because setup, teardown, transport configuration, process management, synchronization, or timeout behavior is defective.
4. **Environment-bound specialist test:** the test requires an explicit external prerequisite that is unsuitable for the default full suite and cannot reasonably be made self-contained.

A failing test must not be moved into categories 2–4 simply to obtain a green suite. Security-sensitive cases default to product-regression treatment until the intended contract is documented and proven otherwise.

## 3. Frozen Architectural Constraints

The corrective work must preserve all of the following:

- `.github/workflows/ci.yml` remains the only routine verification workflow.
- Routine CI remains one Ubuntu job with no matrix.
- CI continues to invoke only `cargo xtask verify` as its repository verification entry point.
- No affected-package selector, lane manifest, dynamic scheduler, coverage matrix, nightly workflow, release workflow, or tag-triggered publication is introduced.
- Crates.io publication remains a manual operator action.
- No command under `cargo xtask verify-release` may call `cargo publish`, create a tag, create a GitHub release, upload artifacts, or read a registry token.
- `cargo xtask verify-full` and `cargo xtask verify-release` remain explicit local/manual commands rather than blocking every pull request.
- Routine hosted CI retains a warm-cache target below ten minutes and a blocking threshold of fifteen minutes.
- No broad `#[ignore]`, global nextest exclusion, blanket timeout inflation, or fail-open wrapper may be used to obtain green results.
- No test may be weakened from a security outcome assertion to an implementation-detail assertion without a documented contract decision.

## 4. Phase Sequence

### Phase 1 — Current-Head Failure Adjudication

Reproduce `verify`, `verify-full`, and `verify-release` on a clean current head and replace the provisional disposition table with an evidence-backed ledger. Each failing or timing-out test receives an exact reproducer, observed result, intended contract, classification, owner subsystem, and required resolution.

Detailed plan:

- `plans/ci_verification_release_truthful_closure_phase_01_failure_adjudication.md`

### Phase 2 — Product and Security Regression Repair

Correct the confirmed product defects, beginning with block-store restart persistence and the WAF scoring/streaming failures already classified as real regressions. Re-adjudicated security-sensitive WAF cases are included here whenever the intended contract requires detection, blocking, stable normalization, or false-positive avoidance.

Detailed plan:

- `plans/ci_verification_release_truthful_closure_phase_02_product_regressions.md`

### Phase 3 — Test Contract and Expectation Correction

Update only tests that Phase 1 proves are genuinely stale. The work must document the intended contract, avoid asserting incidental implementation details, and retain the strongest meaningful security or routing outcome.

Detailed plan:

- `plans/ci_verification_release_truthful_closure_phase_03_test_contract_corrections.md`

### Phase 4 — Harness and Environment Isolation

Repair self-containment and determinism for Unix-socket setup, supervisor/process fixtures, proxy TLS/ALPN setup, and concurrent DashMap behavior. Environment-bound tests must either become self-contained or move to an explicit specialist command with a documented prerequisite and a deterministic preflight failure.

Detailed plan:

- `plans/ci_verification_release_truthful_closure_phase_04_harness_isolation.md`

### Phase 5 — Full, Release, and Operational Closure Proof

Run all authoritative commands against a clean final head, validate package graph and package-content behavior, obtain fresh hosted routine evidence, reconcile every status document, and record branch-protection configuration separately as an externally controlled repository setting.

Detailed plan:

- `plans/ci_verification_release_truthful_closure_phase_05_operational_proof.md`

## 5. Ordering and Gates

The phases are ordered and may not be collapsed in a way that bypasses adjudication.

- Phase 1 must complete before changing any currently failing test expectation.
- Product fixes identified by Phase 1 belong in Phase 2 even if the current disposition calls them stale.
- Phase 3 may change expectations only when the Phase 1 ledger records the authoritative contract and explains why current behavior is intentional.
- Phase 4 may not solve product failures by adding sleeps, increasing timeouts without a measured bound, or excluding tests.
- Phase 5 begins only when all targeted tests pass in their intended execution environment.

Implementation commits should remain subsystem-scoped. Product changes and test-harness changes should not be mixed unless the same minimal patch is required to expose and verify the corrected behavior.

## 6. Required Evidence Model

The final closure record must contain, at minimum:

- final commit SHA;
- Rust toolchain, nextest version, operating system, and relevant system dependency versions;
- clean-tree confirmation;
- exact commands and exit codes;
- total and per-step durations for `verify`, `verify-full`, and `verify-release`;
- final failure-adjudication ledger with every entry resolved;
- list of product files changed for confirmed regressions;
- list of tests changed as stale expectations with contract rationale;
- harness-isolation evidence, including repeated targeted execution;
- package metadata and dependency-version validation result;
- package-content inspection result for every publishable crate;
- `cargo package --no-verify` assembly result for every publishable crate;
- `cargo package --verify` result for every registry-resolvable crate, with explicit reasons for any unresolved internal-dependency skip;
- confirmation that no publishing command exists in CI or xtask;
- hosted CI run identifier and wall-clock duration;
- branch-protection evidence or an explicit statement that the setting remains manually unverified.

A local warm-cache result alone is not sufficient evidence for hosted routine performance. An `--allow-dirty` release run is not release evidence.

## 7. Global Acceptance Criteria

This roadmap is complete only when all of the following are true:

1. `cargo xtask verify` passes on a clean final head.
2. A hosted `ci` job passes on the final implementation and remains below the ten-minute target on a warm cache, or a documented runner anomaly is reproduced and resolved without restoring CI complexity.
3. `cargo xtask verify-full` passes without hidden exclusions, newly ignored tests, or unbounded timeout increases.
4. `cargo xtask verify-release` passes on a clean tree.
5. `cargo xtask verify-release` fails on a dirty tree by default.
6. `cargo xtask verify-release --allow-dirty` emits an unmistakable non-evidence warning and proceeds only for local diagnosis.
7. Every test in the Phase 1 failure ledger is resolved as a product fix, justified expectation correction, repaired harness, or explicitly documented specialist test.
8. Security-sensitive WAF cases retain meaningful detection/blocking and false-positive assertions; they are not normalized to current implementation behavior without a contract decision.
9. The block-store restart/unblock invariant is covered by a deterministic regression test.
10. Proxy, socket, process, TLS/ALPN, and concurrency fixtures are self-contained or have deterministic prerequisite checks.
11. Package metadata, path dependency semver, package file-list inspection, package assembly, and bounded packaged-source verification are green for their defined scope.
12. No actual publication, tagging, release creation, artifact upload, registry-token access, selector, matrix, nightly workflow, or release workflow is added.
13. `docs/testing/verification-contract.md`, release documentation, the original corrective roadmap, the Phase 2 plan, and the closure-results document agree with the actual implementation and command results.
14. No plan or closure document states `COMPLETE` while any authoritative acceptance criterion remains unmet.

## 8. Non-Goals

This roadmap does not authorize:

- a redesign of the WAF engine beyond the defects required by the adjudicated tests;
- a new attack-classification taxonomy project;
- a block-store persistence rewrite unrelated to the restart/unblock invariant;
- a new integration-test framework;
- Docker, VM, local registry, or service-orchestration infrastructure solely for verification;
- a cross-platform CI matrix;
- automatic crates.io publication;
- performance benchmarking unrelated to verification wall-clock behavior;
- correction of unrelated warnings, refactors, or dependency upgrades.

## 9. Handoff Rule

Implementers must treat this roadmap and its five phase plans as the active closure authority for this line of work. Earlier `COMPLETE` labels are historical claims, not permission to skip the final evidence gates. When implementation evidence contradicts a current classification, update the ledger and execute the corresponding phase rather than weakening the acceptance criterion.