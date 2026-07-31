# CI Simplification Phase 5 — Operational Closure

## Status

**INCOMPLETE** — Local verification passes, rejection searches clean, documentation updated, hosted runner proof obtained (run `30600003285`, success). Pending: branch-protection configuration. See `plans/ci_verification_release_simplification_closure_results.md`.

## Objective

Prove that the simplified verification and release model works in practice, that the removed machinery is no longer operationally reachable, and that repository settings and current documentation agree with the checked-in implementation.

This phase is evidence-driven but deliberately avoids recreating an evidence-management system. Closure evidence consists of reproducible commands, actual GitHub-hosted workflow results, repository-setting inspection, and a concise checked-in result record.

## Independence requirement

The closure reviewer should not rely solely on implementation notes. Reinspect the repository from the roadmap's binding decisions and run the final commands directly.

Do not mark the roadmap complete because files were deleted or plans were followed. Mark it complete only when the final operating model is demonstrably usable.

## Required deliverable

Create:

```text
plans/ci_verification_release_simplification_closure_results.md
```

The result record must identify:

- reviewed commit SHA
- review date
- reviewer or agent identity where available
- final workflow inventory
- final command inventory
- local verification results
- GitHub-hosted verification result and run URL or run identifier
- branch-protection status
- rejection-search results
- failure-injection results
- any residual items
- final status: `COMPLETE`, `INCOMPLETE`, or `BLOCKED`

Do not create a JSON ledger, evidence directory, artifact manifest, or workflow-generated closure report.

## Workstream 1 — Reinspect the final workflow topology

Run:

```bash
find .github/workflows -maxdepth 1 -type f -print | sort
```

Confirm:

- one active routine workflow exists
- no redirect workflow remains
- no dormant legacy workflow remains
- triggers are limited to pull requests, pushes to `main`, and manual dispatch
- concurrency cancellation is enabled
- permissions are minimal
- runner is Ubuntu
- no matrix exists
- canonical routine verification is invoked once
- no publication or release artifact logic exists

Record exact workflow and job names because repository settings must match them.

## Workstream 2 — Reinspect command authority

Identify all human-facing verification commands and all code paths capable of running test orchestration.

Confirm exactly one authority for each:

```text
verify
verify-full
verify-release
```

Reject:

- duplicate shell and xtask implementations
- deprecated lane aliases that still execute
- hidden CI-only command branches
- affected-selection code
- command strings independently copied into workflow YAML and another manifest
- release commands that can publish

Run the commands from a clean checkout or equivalent clean worktree.

## Workstream 3 — Positive local verification

Run and record:

```bash
<verify command>
<verify-full command>
<verify-release command>
```

For each record:

- commit SHA
- environment
- command
- exit status
- wall time
- notable warnings
- skipped checks and explicit reason

`verify-release` must stop before actual publication and print the manual publication order.

Do not require identical timing across machines. The closure criterion is practical usability and bounded routine feedback, not a brittle time threshold.

## Workstream 4 — Hosted runner proof

Push the reviewed commit and observe the actual GitHub Actions result.

Confirm:

- only the intended routine workflow starts
- the final required job succeeds
- no nightly, comprehensive, release, platform, or tag workflow starts
- logs show the canonical command
- no secrets are requested
- no artifacts are uploaded unless explicitly retained and justified
- a superseded pull-request run cancels when tested

Record the workflow run URL or numeric identifier in the closure result.

A local success without hosted proof is insufficient for `COMPLETE`.

## Workstream 5 — Branch-protection reconciliation

Inspect branch protection or rulesets for `main`.

Required final state:

- required status checks reference only current job names
- deleted `PR Fast`, main-comprehensive, nightly, release, selector-gated, or summary checks are not required
- at most one required check exists by default; at most two only if Phase 2 documented the measured justification
- no environment approval or release gate controls ordinary mergeability

If connector permissions cannot inspect or modify repository settings, record this as a specific manual closure item and mark the roadmap `INCOMPLETE`, not `COMPLETE`.

Documentation must include the exact required check name for the maintainer to configure.

## Workstream 6 — Full rejection search

Run from repository root:

```bash
rg -n 'pr-fast|main-comprehensive|nightly-qualification|release-qualification' . --glob '!plans/**' --glob '!target/**'
rg -n 'select-affected|test-affected|affected package selector|changed_packages|force-full' . --glob '!plans/**' --glob '!target/**'
rg -n 'testing/lanes\.toml|ci_lane_consistency|selector_predicate|selector_normalization' . --glob '!plans/**' --glob '!target/**'
rg -n 'four validation lanes|PR Fast|Main Comprehensive|Scheduled Qualification|Release Qualification' AGENTS.md README.md docs scripts tools .github Cargo.toml
rg -n 'schedule:|tags:|strategy:|matrix:' .github/workflows
rg -n 'macos-|windows-|freebsd|alpine|cargo miri|cargo .*fuzz|cargo outdated' .github/workflows
rg -n 'upload-artifact|download-artifact|GITHUB_STEP_SUMMARY|junit|affected-packages' .github/workflows
rg -n 'cargo publish|CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN' .github scripts tools
```

Interpret matches rather than reporting counts blindly.

Allowed matches:

- historical plan and result files
- manual release documentation for maintainer-executed `cargo publish`
- explicit text explaining that deleted mechanisms are prohibited
- product source identifiers unrelated to CI terminology

Any active executable or current operational reference is a closure failure.

## Workstream 7 — Failure-injection closure matrix

Perform temporary, isolated failure injection. Each case must fail the final required CI check or appropriate local verifier.

### Required routine-CI failures

1. Formatting violation.
2. Clippy warning.
3. Compilation failure.
4. Routine unit or integration test failure.
5. Critical security-regression failure.
6. Product architecture guard failure.
7. Child command failure inside the wrapper.

### Required orchestration-negative checks

8. Push a version-like tag and confirm no release workflow starts.
9. Confirm no scheduled workflow exists to start automatically.
10. Confirm deletion of the old lane manifest has no runtime effect.
11. Confirm a localized crate change still executes the same static routine contract rather than a selector-derived subset.
12. Push a second commit to a test PR and confirm the superseded run cancels.

### Required release failures

13. Dirty-tree policy failure.
14. Package-content violation.
15. Invalid publishable dependency metadata.
16. Failed dry run for one crate stops the release verifier before later publication steps.
17. Search or trace proof that `verify-release` cannot invoke actual `cargo publish`.

Use throwaway branches or local worktrees. Do not merge injected defects and do not publish test versions.

## Workstream 8 — Compare before and after complexity

Record a concise before/after table.

Required metrics:

| Metric | Before | After |
|---|---:|---:|
| Active workflow files | 4 plus redirect | target 1 |
| Routine workflow jobs | record actual | target 1, maximum 2 |
| Routine runner OSes | record actual | 1 |
| Routine matrix entries | record actual | 0 |
| Scheduled workflows | 1 or actual | 0 |
| Tag-triggered workflows | 1 or actual | 0 |
| Affected-selector code paths | record actual | 0 |
| Lane definition authorities | record actual | 0 |
| Required branch checks | record actual | target 1, maximum 2 |
| Automated publish paths | record actual | 0 |
| Routine artifact uploads | record actual | 0 unless justified |
| Canonical local verification commands | fragmented | 3 levels, one authority each |

Also record representative routine wall time before and after where comparable. Do not make unsupported percentage claims from unlike cache states.

## Workstream 9 — Documentation consistency review

Review current, nonhistorical documentation:

```text
README.md
AGENTS.md
docs/testing/verification-contract.md
docs/releasing.md
crate-level contributor or release guidance
```

Confirm all describe:

- one routine Ubuntu CI workflow
- the final required check name
- `verify`, `verify-full`, and `verify-release`
- manual crates.io publication
- no tag-triggered release automation
- truthful platform support
- direct specialist commands for fuzzing, Miri, platform checks, stress, and audits

No current document may call the old four-lane model authoritative.

## Workstream 10 — Residual issue handling

Classify every residual as:

- `BLOCKING_CORRECTNESS`
- `BLOCKING_SETTINGS`
- `NONBLOCKING_DOCUMENTATION`
- `DEFERRED_PRODUCT_TESTING`
- `HISTORICAL_ONLY`

Rules:

- A stale required branch check is blocking.
- A failing hosted routine workflow is blocking.
- An active tag or schedule trigger is blocking.
- A surviving selector execution path is blocking.
- A missing manual release recovery procedure is blocking.
- A specialist test not automated is not blocking when its direct command and support implication are documented.
- Historical plans describing the old system are not blocking.

## Acceptance criteria

The roadmap may be marked `COMPLETE` only when:

- One active routine workflow exists.
- One job exists, or two with prior measured justification.
- Routine CI is Ubuntu-only and matrix-free.
- No schedule or tag trigger exists.
- No automated publication or release artifact path exists.
- No affected selector or lane definition remains operational.
- CI calls the same `verify` command used locally.
- `verify`, `verify-full`, and `verify-release` all pass on the reviewed commit.
- `verify-release` cannot publish.
- The hosted workflow is green.
- Superseded PR runs cancel.
- Branch protection references only current checks.
- All 17 closure failure-injection checks behave as required.
- Rejection searches contain no active obsolete references.
- Documentation consistently describes the simplified model.
- The closure result file contains no unresolved blocking item.

## Status rules

Use `COMPLETE` only when all acceptance criteria are met.

Use `INCOMPLETE` when implementation is substantially present but hosted proof, branch settings, rejection cleanup, or a required failure-injection result remains outstanding.

Use `BLOCKED` only when an external constraint prevents execution and the exact blocker is identified.

Do not use phrases such as “effectively complete,” “mostly complete,” or “complete except for branch protection.” Repository settings are part of the operating system and are required for closure.

## Anti-regression rule

After closure, changes to CI should be evaluated against a strict complexity budget:

- no new workflow without an independently justified trigger and property
- no new matrix without a unique support claim
- no selector or lane manifest
- no scheduled qualification by default
- no tag-triggered release process
- no automated crates.io publishing
- no CI self-policy guard unless it protects a security boundary rather than a naming convention

When a real regression escapes, add the smallest deterministic assertion to the existing command level that should catch it. Do not respond by restoring broad qualification machinery.
