# CI Simplification Corrective Phase 3 — Residual Cleanup and Operational Closure

## Status

Planned. Begins only after Phases 1 and 2 have produced stable, passing `verify`, `verify-full`, and `verify-release` commands.

## Objective

Remove vestigial CI-policy assertions and stale operational language, reconcile repository settings with the final single-check model, and close the simplification roadmap using actual local and hosted evidence.

This phase must not add new verification machinery. Its purpose is to remove obsolete control-plane residue and record the final operating contract truthfully.

## Current residual issues

- The repository guard suite still contains negative fixtures for deleted lane, coverage-matrix, operating-guide, flaky-test-policy, performance-budget, and release-in-PR concepts.
- Current documents still use `main merge`, `nightly`, or equivalent language for checks whose workflows were deleted.
- The closure-results document contains contradictory statements about hosted proof and outstanding blockers.
- The original roadmap and Phase 5 status do not fully account for failing `verify-full` and `verify-release` commands.
- Branch protection for `main` has not been independently confirmed to require only `ci`.
- The latest hosted proof predates the latency and contract corrections from Phases 1 and 2.

## Non-goals

- No product refactor.
- No new workflow.
- No new CI policy guard.
- No evidence artifact upload.
- No automated branch-protection mutation unless an existing trusted repository tool already supports the exact change.
- No broad historical-document rewriting.

## Workstream 1 — Remove obsolete CI-policy fixtures

Inspect `tools/synvoid-repo-guards/tests/negative_fixtures.rs` and related guard modules.

Delete fixtures whose only purpose is proving enforcement of removed infrastructure, including tests equivalent to:

```text
ci_no_release_guard_detects_release_flag
ci_no_release_guard_allows_security_regression
coverage_matrix_guard_detects_missing_doc
flaky_test_policy_guard_detects_missing_doc
lane_manifest_guard_detects_invalid_toml
operating_guide_guard_detects_missing_doc
performance_budgets_guard_detects_missing_doc
```

Also delete helper functions, imports, fixtures, and comments that become unused.

Retain negative fixtures that prove current product/security boundaries, including:

- root-facade isolation
- request-path/control-plane separation
- background-task ownership
- lifecycle `mem::forget` policy
- HTTP handler lifecycle isolation
- documentation-link validity if it remains a current product documentation guard
- truthful native-plugin sandbox language
- secret/credential package checks introduced by Phase 2 when implemented as current release safeguards

Rename files or modules whose names still imply selector/lane ownership when the remaining contents are product-oriented. Prefer a narrow rename such as `repository_policy.rs` or `product_boundary_fixtures.rs`; do not create a new hierarchy.

## Workstream 2 — Remove stale CI-policy guard assertions

Search the active guard crate for enforcement of:

```text
workflow filename presence
old lane names
nightly/main/release workflow shape
coverage matrix documents
operating guide documents
performance budget documents
flaky-test policy documents
selector normalization
cache naming
release profile exceptions tied to PR lane terminology
```

Delete these assertions unless they protect a current product or release safety property.

A current guard may remain for a simple, direct invariant such as:

- no routine `--release` use, if enforced against the canonical verify command rather than a deleted PR workflow
- no actual `cargo publish` invocation in repository automation
- required `[profile.ci]` configuration, if the final command still depends on it

Do not preserve a guard merely by renaming old terminology.

## Workstream 3 — Reconcile verification documentation

Update current operational documents only:

```text
README.md
AGENTS.md
docs/testing/verification-contract.md
docs/releasing.md
docs/RELEASE.md
docs/RELEASE_CHECKLIST.md
docs/PLATFORM_SUPPORT.md
architecture/release_profile_matrix.md
```

Required language:

- Routine CI is one Ubuntu workflow and one `ci` job.
- `cargo xtask verify` is the exact hosted command.
- `verify-full` and `verify-release` are manual local commands.
- Omitted specialist checks run only when a maintainer invokes their documented commands.
- No deleted main-comprehensive, nightly-qualification, or release-qualification workflow is implied.
- Cross-platform support claims distinguish routine hosted verification from manual/best-effort support.
- crates.io publication and release cadence remain manual.

Remove statements such as:

```text
caught on main merge
caught nightly
release lane
PR fast lane
profile matrix job
scheduled qualification
```

when they refer to no active mechanism.

Historical plans, changelogs, and completed architecture reports may retain accurate historical references. Do not rewrite them to pretend the old system never existed.

## Workstream 4 — Reconcile roadmap and closure records

Update:

```text
plans/ci_verification_release_simplification_roadmap.md
plans/ci_simplification_phase_05_operational_closure.md
plans/ci_verification_release_simplification_closure_results.md
plans/ci_simplification_corrective_roadmap.md
```

Rules:

- Preserve the originally reviewed commit and historical results.
- Add a clearly dated corrective section rather than silently replacing prior measurements.
- Remove contradictory claims such as hosted proof both obtained and outstanding.
- Do not classify a failing required command as nonblocking when the governing acceptance criteria require it to pass.
- Record the final corrected command counts and durations.
- Use only `COMPLETE`, `INCOMPLETE`, or `BLOCKED`.

The final closure record must identify the exact final commit SHA, not only an earlier phase commit.

## Workstream 5 — Branch-protection reconciliation

Inspect GitHub branch protection or rulesets for `main`.

Required state:

```text
required status check: ci
stale required checks: none
required workflow approvals for ordinary merge: none unless independently required by repository policy
release environments: not involved in ordinary merge
```

If the available automation cannot read or write branch protection:

1. document the exact settings path and expected check name
2. have a repository administrator apply the change
3. record the date and confirmation in the closure results
4. keep status `INCOMPLETE` until confirmation exists

Do not guess based on workflow YAML. Repository settings are part of closure.

## Workstream 6 — Final local verification

From a clean Linux checkout at the final commit, run:

```bash
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

Record for each:

- exit status
- wall time
- command count
- warnings
- explicitly skipped specialist checks

All three must pass for closure.

Also run the direct specialist-command help or dry-run where available to verify documentation references valid commands. Do not execute long fuzz/stress campaigns merely for closure.

## Workstream 7 — Final hosted proof

Push the final implementation commit and observe the ordinary GitHub Actions run.

Record:

- workflow run ID and URL
- final commit SHA
- trigger
- number of workflows started
- number of jobs started
- cache status and restore duration
- `cargo xtask verify` duration
- total job duration
- job conclusion
- artifact count

Required outcome:

- one `CI` workflow
- one `ci` job
- success
- no artifacts
- `verify` duration at or below ten minutes on warm cache
- total job duration at or below twelve minutes on warm cache

If the first final run has a cold cache, permit one subsequent ordinary run to obtain a warm-cache measurement. Do not create a special performance workflow.

## Workstream 8 — Rejection searches

Run and interpret:

```bash
find .github/workflows -maxdepth 1 -type f -print | sort
rg -n 'pr-fast|main-comprehensive|nightly-qualification|release-qualification' . --glob '!plans/**' --glob '!target/**'
rg -n 'select-affected|test-affected|changed_packages|force-full' . --glob '!plans/**' --glob '!target/**'
rg -n 'testing/lanes\.toml|lane_manifest_guard|coverage_matrix_guard|operating_guide_guard|performance_budgets_guard|flaky_test_policy_guard' . --glob '!plans/**' --glob '!target/**'
rg -n 'caught on main merge|caught nightly|release lane|PR fast lane|Scheduled Qualification|Release Qualification' README.md AGENTS.md docs architecture scripts tools .github Cargo.toml
rg -n 'schedule:|tags:|strategy:|matrix:|upload-artifact|download-artifact' .github/workflows
rg -n 'cargo publish|CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN' .github scripts tools --glob '!**/testdata/**'
```

Allowed matches:

- historical plan/result material
- manual `cargo publish` commands in release documentation
- explicit prohibition text

Any current executable or operational instruction referencing deleted architecture is a closure failure.

## Workstream 9 — Final failure-injection matrix

Perform only the minimal final set needed to prove the corrected owners:

1. Formatting defect fails `ci`.
2. Clippy warning fails `ci`.
3. Critical security test defect fails `ci`.
4. Product architecture guard defect fails `ci`.
5. Full-only deterministic test defect fails `verify-full`.
6. Dirty tree fails `verify-release` unless `--allow-dirty` is explicit.
7. Prohibited package credential path fails `verify-release`.
8. Actual publication remains unreachable.
9. Version-like tag push starts no workflow beyond any explicitly manual dispatch already requested.
10. A second push to the same PR cancels the superseded run.

Reuse evidence from Phases 1 and 2 when it applies to the identical final implementation. Do not reinject every historical failure class redundantly.

## Required closure-results structure

The final corrective section in `plans/ci_verification_release_simplification_closure_results.md` must contain:

```text
review metadata
final workflow inventory
final command inventory
local command results
hosted run proof
branch-protection confirmation
rejection searches
final failure injections
before/after timing and invocation counts
residual issue classification
final status
```

Do not add JSON, artifact manifests, or generated evidence directories.

## Acceptance criteria

Phase 3 and the corrective roadmap are complete only when:

- Obsolete CI-policy negative fixtures and guards are absent.
- Current documentation contains no operational references to deleted nightly/main/release lanes.
- The original closure record is internally consistent and includes the corrective results.
- `verify`, `verify-full`, and `verify-release` pass on the exact final commit.
- The final hosted workflow succeeds within the Phase 1 latency budget.
- Exactly one workflow and one job run.
- Branch protection requires only `ci` and contains no stale checks.
- No workflow publishes, triggers on tags, runs on a schedule, uploads artifacts, or uses a matrix.
- All ten final failure-injection checks behave as required.
- Rejection searches contain no active obsolete references.
- No blocking residual remains.
- The roadmap and closure result are marked `COMPLETE` only after all above criteria are recorded.

## Stop conditions

Use `INCOMPLETE` when:

- branch-protection confirmation is unavailable
- any required local command is red
- the hosted job exceeds the accepted warm-cache budget
- an obsolete CI-policy executable path remains
- current documentation still directs contributors to deleted mechanisms

Use `BLOCKED` only for a specifically identified external restriction. Do not use qualified completion language.
