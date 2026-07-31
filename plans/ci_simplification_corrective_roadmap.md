# CI Simplification Corrective Roadmap

## Status

**COMPLETE** — All three corrective phases finished. Phase 3 residual cleanup and operational closure completed 2026-07-31. See `plans/ci_verification_release_simplification_closure_results.md` for final results.

## Purpose

The first simplification pass successfully removed the four-lane workflow topology, affected-package selector, scheduled qualification, tag-triggered release qualification, release automation, matrices, and most CI-specific policy machinery. The repository now has one Ubuntu workflow and one required job that calls `cargo xtask verify`.

The remaining problem is that simplification of topology did not sufficiently simplify execution. Hosted run `30600003285` succeeded, but `cargo xtask verify` consumed approximately 998.5 seconds and the full job took roughly 18 minutes despite a cache hit. `verify-full` and `verify-release` are also not currently usable as green handoff commands, and several deleted CI-policy concepts remain in tests or documentation.

This corrective roadmap closes those gaps without restoring matrices, selectors, scheduled workflows, release automation, evidence ledgers, or broad product refactoring.

## Binding constraints

- Keep exactly one routine GitHub Actions workflow and one routine job.
- Keep Ubuntu as the only routine hosted platform.
- Keep publication manual through local `cargo publish` commands.
- Do not add scheduled workflows, tag triggers, release artifacts, automated publishing, affected-package selection, path filters, lane manifests, reusable workflow layers, or job matrices.
- Do not add a new benchmark service, timing database, workflow-generated evidence bundle, or persistent CI telemetry system.
- Prefer deletion and command consolidation over new abstractions.
- Do not modify production behavior merely to make verification green.
- Product defects discovered by broader verification must be reported separately rather than hidden by the CI correction.
- Specialist fuzzing, Miri, stress, platform, and dependency-audit commands remain explicit manual activities.

## Baseline findings to correct

### Routine execution

Hosted run `30600003285` reported approximately:

| Step | Duration |
|---|---:|
| `cargo clippy --all-targets -- -D warnings` | 179.5 s |
| security regression command | 405.1 s |
| `cargo test --lib --no-run` | 310.4 s |
| complete `cargo xtask verify` | 998.5 s |

The routine contract uses 22 Cargo invocations and mixes dev, test, and CI profiles, causing repeated compilation of overlapping graphs.

### Full verification

`cargo xtask verify-full` currently prepends all routine steps and then runs a broad workspace test command that re-executes many of the same test binaries. It also fails on long-running or unstable WAF/proxy tests.

### Release verification

`cargo xtask verify-release` currently fails on workspace metadata and uses policies that need correction:

- internal path dependencies are incorrectly required to use `version = "*"`
- package-content detection uses broad substring matching such as `secret`
- dirty-tree handling is warn-only despite release verification representing an exact-source check
- all-crate `cargo publish --dry-run` is not a reliable pre-publication operation when newly versioned internal dependencies are not yet available from crates.io

### Residual control-plane material

Negative fixtures and current documents still refer to deleted lane, coverage-matrix, nightly, operating-guide, and CI-policy concepts. Closure records are internally inconsistent about hosted proof and outstanding blockers.

## Corrective phases

### Phase 1 — Routine CI latency contraction

Detailed plan: `plans/ci_simplification_corrective_phase_01_routine_latency.md`

Consolidate routine compilation and test execution around one Cargo profile and a small number of invocations. Remove redundant compilation, preserve critical product/security guards, and prove the final command on one hosted run.

### Phase 2 — Full and release verifier correction

Detailed plan: `plans/ci_simplification_corrective_phase_02_full_release_contract.md`

Make `verify-full` nonduplicative and deterministic. Correct release package discovery, metadata validation, dependency requirements, package-content inspection, dirty-tree policy, and pre-publication packaging semantics. Keep actual publication manual.

### Phase 3 — Residual cleanup and operational closure

Detailed plan: `plans/ci_simplification_corrective_phase_03_closure_and_settings.md`

Remove vestigial CI-policy fixtures, reconcile current documentation, verify branch protection, rerun the final local commands, obtain hosted timing proof, and record a truthful closure result.

## Dependency order

Phases execute in order.

1. Phase 1 changes the routine command and hosted runtime contract.
2. Phase 2 reuses the stable command components while correcting full and release verification.
3. Phase 3 removes stale assertions and closes repository settings only after command behavior is stable.

Do not combine all three phases into one undifferentiated commit. Small implementation commits within a phase are acceptable.

## Global acceptance criteria

The corrective line of work is complete only when:

- `.github/workflows/ci.yml` remains the only workflow.
- The workflow still has one Ubuntu job and no matrix, schedule, tag trigger, artifact upload, or publication path.
- Routine verification uses no affected-package selection and no dynamic command scheduler.
- Routine verification uses at most eight Cargo invocations; a lower count is preferred when it does not reduce coverage.
- A warm-cache hosted `cargo xtask verify` run completes in ten minutes or less.
- The complete hosted job completes in twelve minutes or less, including setup and cache restore.
- `cargo xtask verify`, `cargo xtask verify-full`, and `cargo xtask verify-release` pass on the reviewed clean commit.
- `verify-full` does not deliberately rerun routine-only test binaries through a blanket workspace command.
- Long-duration stress/endurance tests are either deterministic and retained or explicitly moved to a documented specialist command; they are not silently ignored.
- Release verification uses Cargo metadata rather than ad hoc line parsing where metadata already exposes the required fact.
- Publishable path dependencies carry meaningful semver requirements rather than wildcard requirements.
- Package-content checks use path-aware rules with narrowly documented exceptions rather than broad source-name substring bans.
- Release verification cannot invoke an actual publication.
- CI-policy fixtures tied to deleted workflows, lanes, matrices, or documents are absent.
- Current documentation contains no operational claims that omitted checks run on a deleted nightly or main-comprehensive workflow.
- Branch protection for `main` requires only the current `ci` check.
- The final closure record has no unresolved blocking item and reports actual measured values.

## Rejection criteria

Reject an implementation that introduces any of the following:

- a second routine workflow or job fan-out
- an OS, feature, or target matrix
- scheduled or tag-triggered qualification
- path filtering or affected-package selection
- automated crates.io publication
- release artifact uploads
- a replacement lane manifest
- a timing/evidence database
- test exclusion without an explicit disposition and direct command
- blanket `allow-failure` or `continue-on-error` for correctness checks
- a claim of completion while full or release verification remains red

## Closure evidence

Only the following evidence is required:

- one local warm-cache timing table before and after Phase 1
- one successful hosted run with job and `verify` durations
- final outputs for `verify`, `verify-full`, and `verify-release`
- rejection-search output
- branch-protection inspection or an explicit administrator-applied settings record

Do not create workflow artifacts or a machine-readable evidence subsystem for this roadmap.
