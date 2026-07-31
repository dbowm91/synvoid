# CI, Verification, and Release Simplification Roadmap

## Status

**COMPLETE** — Implementation and closure complete. Corrective Phase 3 finished 2026-07-31. Obsolete CI-policy fixtures removed, documentation reconciled. Hosted runner proof obtained (run `30600003285`, success). Branch protection requires only `ci` check — manual repository administrator action. See `plans/ci_verification_release_simplification_closure_results.md` for details.

## Purpose

SynVoid's verification apparatus has become a material impediment to iteration. The repository currently maintains separate pull-request, main-branch, nightly, and release-qualification workflows; an affected-package selector; machine-readable lane definitions; CI/xtask parity guards; workflow-policy guards; repeated platform and feature matrices; JUnit and artifact plumbing; and tag-triggered release qualification.

This roadmap replaces that architecture with a deliberately small operating contract:

1. One routine GitHub Actions workflow.
2. One required branch-protection check, or two only when measured wall-clock data proves that splitting lint and tests materially improves feedback.
3. Ubuntu as the routine hosted-CI environment.
4. A small, static, understandable correctness suite with no dependency-aware scheduler.
5. Explicit local commands for ordinary, full, and release verification.
6. Manual crates.io publication and manual release cadence.
7. No GitHub Actions publishing, tag-triggered qualification, scheduled qualification, release artifact assembly, or GitHub-controlled release state machine.

The central objective is not to preserve the current CI topology while making it faster. The objective is to delete the topology and retain only verification that has a clear, direct correctness or security purpose.

## Binding architectural decisions

The implementation must preserve these decisions throughout all phases.

### Routine CI

- `.github/workflows/ci.yml` becomes the only routine workflow.
- It triggers on pull requests, pushes to `main`, and manual dispatch.
- It uses `concurrency.cancel-in-progress` for superseded pull-request work.
- It runs on Ubuntu only.
- It contains one job by default. A maximum of two jobs is permitted only if a recorded comparison demonstrates lower developer-visible latency without duplicating compilation.
- It performs no release builds, publishing, artifact packaging, platform matrix, scheduled fuzzing, Miri, FreeBSD virtualization, Alpine runtime qualification, outdated-dependency reporting, or broad feature matrix.
- It uploads no routine JUnit, selector, timing, corpus, or release artifacts unless a concrete downstream consumer is identified in the same change.

### Verification source of truth

- Exactly one repository-local command definition is authoritative for routine CI.
- CI calls that command rather than duplicating a large command list in YAML and another list in xtask configuration.
- The existing `testing/lanes.toml` four-lane model is removed.
- The affected-package selector and its fallback/predicate machinery are removed.
- CI-specific guards that validate workflow topology, lane parity, selector polarity, artifact names, summary construction, or cache-key structure are removed.
- Product and security guards remain only when they enforce a real source, API, lifecycle, memory, privilege, or trust boundary.

### Release model

- Release cadence is exclusively manual.
- Crates are published manually with `cargo publish` in documented dependency order.
- GitHub Actions does not publish crates, create releases, upload release binaries, decide whether a version is releasable, or run automatically from version tags.
- Release verification is performed locally against the exact commit and crate package contents intended for publication.
- A pushed tag records a release decision; it does not initiate a release process.

### Platform policy

- Routine CI proves the primary supported Linux path.
- Additional platforms are tested manually when a change touches platform-specific code or before a release when the maintainer intends to make a support claim.
- A best-effort cross-target check that converts failures to warnings is not qualification and must not be retained merely to claim coverage.
- Support documentation must distinguish primary support, best-effort compilation, and unqualified platforms.

## Non-goals

This roadmap does not weaken product-level security invariants, remove tests solely because they are inconvenient, automate crates.io publication, add another CI abstraction layer, introduce a new distributed cache service, retain the current four-lane model under different names, or create an evidence ledger that requires ongoing maintenance.

It also does not promise simultaneous first-class support for every target currently present in the matrix. Support claims must follow actual project intent and reproducible verification, not the existence of a GitHub Actions matrix entry.

## Target operating model

### Required hosted CI

The final workflow should be conceptually equivalent to:

```text
checkout
install stable Rust with rustfmt and clippy
install protobuf compiler
restore one Rust cache
run canonical routine verification command
```

The canonical routine command must include, at minimum:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
one primary Linux compile/check contract
one bounded correctness test contract
critical security and repository-boundary tests not already covered by that contract
```

The exact bounded test command is frozen during Phase 1 after measuring current runtime and identifying tests that require special serialization or features. It must be static and inspectable. It must not invoke a changed-package selector.

### Local verification levels

The repository exposes three human-facing levels:

- `verify`: exact routine CI reproduction.
- `verify-full`: broader workspace, feature, doctest, and project-specific correctness validation used before risky merges or on demand.
- `verify-release`: full local release readiness, including package-content inspection and `cargo publish --dry-run` for publishable crates.

These may be implemented through a simplified existing xtask or a small script. The implementation must choose the option with the lowest net maintenance burden and one command authority. It must not preserve lane manifests, command-parity guards, JSON planning output, lane explanation subcommands, or affected-package orchestration merely to retain the existing interface.

## Phased roadmap

### Phase 1 — Freeze the contract and build the deletion inventory

Establish the exact routine, full, and release verification contracts. Inventory every workflow, selector, lane definition, CI-specific guard, documentation reference, branch-protection name, and release trigger that must be removed or rewritten. Produce a coverage disposition table distinguishing product assurance from CI self-assurance.

Detailed plan: `plans/ci_simplification_phase_01_contract_and_deletion_inventory.md`

### Phase 2 — Collapse GitHub Actions to one routine workflow

Replace the redirect and four active workflows with a single Ubuntu workflow. Remove scheduled and tag triggers, matrices, routine artifacts, summary jobs, and repeated setup. Preserve cancellation and a stable required check name.

Detailed plan: `plans/ci_simplification_phase_02_single_workflow_collapse.md`

### Phase 3 — Remove verification control-plane machinery

Delete the affected-package selector, lane manifest, selector tests, CI-policy guards, parity guards, and obsolete xtask lane surface. Consolidate product-level guards behind ordinary Cargo commands and establish the three local verification levels without introducing another policy engine.

Detailed plan: `plans/ci_simplification_phase_03_local_verification_and_guard_reduction.md`

### Phase 4 — Codify manual crates.io release and truthful platform support

Remove release qualification and artifact assumptions from documentation and commands. Add a precise manual crates.io checklist, dependency-order publication rules, package inspection, dry runs, immutable-version recovery, tag ordering, and an explicit platform support statement.

Detailed plan: `plans/ci_simplification_phase_04_manual_release_and_documentation.md`

### Phase 5 — Operational closure and anti-regression proof

Run positive and negative verification, confirm deleted machinery cannot trigger, update branch protection to the final check name, reconcile stale documentation, record before/after workflow and command counts, and close only when the simplified path is demonstrated on an actual GitHub runner and locally.

Detailed plan: `plans/ci_simplification_phase_05_operational_closure.md`

## Dependency order

Phases must execute in order. Phase 1 freezes the target contract. Phase 2 changes hosted execution. Phase 3 removes supporting control-plane code only after the replacement workflow is present. Phase 4 changes release and support documentation after command names are stable. Phase 5 performs independent closure and repository-setting reconciliation.

A phase may be split into multiple commits, but no phase may claim completion while its rejection searches still find active references to deleted architecture.

## Global acceptance criteria

This line of work is complete only when all of the following are true:

- Exactly one active routine GitHub Actions workflow exists.
- No workflow has a `schedule` trigger.
- No workflow triggers from `push.tags`.
- No workflow publishes to crates.io or assembles GitHub release artifacts.
- Routine CI uses Ubuntu and no target or operating-system matrix.
- Routine CI exposes one required check, or two with recorded justification.
- No affected-package selector participates in CI or local verification.
- `testing/lanes.toml` and four-lane command definitions are absent.
- No guard test enforces the deleted CI architecture.
- One local command exactly reproduces hosted routine verification.
- Full and release verification remain explicit local commands, not implicit GitHub events.
- The manual release guide includes package inspection, dry run, dependency order, crates.io verification, immutable-version recovery, and tag sequencing.
- Branch protection references only current check names.
- The final GitHub-hosted CI run is green on the implementation commit.
- A deliberate formatting, clippy, compilation, test, and critical guard failure each causes the required CI check to fail.
- Searches for obsolete workflow names, lane terminology, selector commands, and release-qualification triggers return no active operational references.

## Required rejection searches

The closure phase must run and interpret at least:

```bash
find .github/workflows -maxdepth 1 -type f -print | sort
rg -n 'pr-fast|main-comprehensive|nightly-qualification|release-qualification' . --glob '!plans/**' --glob '!target/**'
rg -n 'select-affected|test-affected|affected package selector' . --glob '!plans/**' --glob '!target/**'
rg -n 'testing/lanes\.toml|ci_lane_consistency|selector_predicate|selector_normalization' . --glob '!plans/**' --glob '!target/**'
rg -n 'schedule:|push:\s*$|tags:|cargo publish|upload-artifact' .github/workflows
rg -n 'four validation lanes|PR Fast|Main Comprehensive|Scheduled Qualification|Release Qualification' AGENTS.md README.md docs scripts tools .github Cargo.toml
```

Historical plan and result files may describe the previous architecture. They must not be rewritten to falsify history, but current operational documentation must clearly identify the new authority.

## Rollback policy

Rollback is file-level and phase-local. Do not restore the four-lane topology as a generic response to one failing test. When the bounded CI contract misses a real regression, add the smallest deterministic test or command that detects that class of failure. Do not reintroduce selectors, scheduled qualification, broad matrices, artifact ledgers, or release automation without a new design decision supported by measured need.
