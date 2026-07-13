# Testing Infrastructure Milestone B — Modernize Test Execution

## Purpose

Milestone B modernizes how SynVoid executes and structures tests after Milestone A has established measurement, workload lanes, a dedicated CI profile, and authoritative test ownership.

This milestone has two primary goals:

1. Adopt `cargo-nextest` for eligible native test execution so concurrency, timeout behavior, slow-test reporting, retries, and machine-readable results are explicit and controlled.
2. Reduce root-level compilation and linking cost by consolidating architecture guards and moving static repository/source checks into a lightweight tool crate that does not depend on the root SynVoid package.

Milestone B must improve scheduling and diagnostics without introducing hidden retries, unsafe concurrency, test selection gaps, or loss of architecture-policy coverage.

## Preconditions

Before starting this milestone, confirm Milestone A has produced:

- `docs/testing/ci-performance-baseline.md`
- `docs/testing/test-suite-ownership.md`
- `docs/testing/ci-lane-policy.md`
- a working `[profile.ci]`
- separate PR, main, scheduled, and release workflow lanes
- removal of known DNS and plugin duplication
- an inventory of tests requiring serial execution, fixed ports, global state, long timeouts, or external resources
- a current inventory of root integration-test binaries and architecture guard commands

If these artifacts are incomplete, repair them first rather than guessing at nextest policy or guard ownership.

## Relationship to the roadmap

This plan implements roadmap phases 4 and 5 from `plans/testing_infrastructure_optimization_roadmap.md`:

- nextest adoption and execution policy
- architecture/repository guard consolidation

Milestone C will later move broader domain tests into owning crates and rationalize the target/feature matrix. Milestone B should not prematurely perform those larger migrations except where required to create the lightweight guard crate.

## Scope

### In scope

- Pinning and installing `cargo-nextest` in CI.
- Adding `.config/nextest.toml`.
- Migrating eligible unit and integration tests to nextest.
- Keeping doctests or specialized harnesses on Cargo where appropriate.
- Defining slow-test, timeout, retry, thread, and resource policies.
- Publishing JUnit results and slow-test summaries.
- Removing broad serialization where selective serialization is safe.
- Classifying architecture guards as static/source or runtime.
- Creating a lightweight `synvoid-repo-guards` tool crate.
- Moving manifest, source, import, documentation, and ownership-policy guards out of root integration linkage.
- Consolidating remaining runtime guards into domain-oriented binaries where safe.
- Reducing separate Cargo invocations in the guard suite.
- Measuring before/after test and guard cost.

### Out of scope

- Full migration of all root tests into owning crates.
- Dependency-aware test selection.
- `sccache` rollout.
- Major fixture or network lifecycle rewrites.
- Broad fuzz, benchmark, or Miri migration to nextest.
- Changing product behavior to make tests easier.
- Adding retries to deterministic tests.
- Eliminating runtime guard coverage.

## Required deliverables

Milestone B must produce at minimum:

```text
.config/nextest.toml

tools/synvoid-repo-guards/Cargo.toml
tools/synvoid-repo-guards/src/...
tools/synvoid-repo-guards/tests/...

docs/testing/nextest-policy.md
docs/testing/architecture-guard-ownership.md
docs/testing/milestone-b-results.md
```

The workspace manifest and CI workflows must be updated as needed. If a different lightweight crate path is chosen, document the rationale and preserve the same dependency-boundary objective.

## Workstream B1 — Establish nextest compatibility inventory

### Tasks

1. Review `docs/testing/test-suite-ownership.md` and classify every suite as:
   - nextest eligible
   - Cargo-only
   - doctest
   - specialized harness
   - fuzz/Miri/benchmark
   - unknown, requiring investigation
2. Identify tests that depend on:
   - libtest-specific output ordering
   - doctest execution
   - custom harness behavior
   - `#[ignore]` semantics
   - environment variables
   - fixed ports
   - process-global state
   - thread-local assumptions
   - child processes
   - privileged networking
3. Run an initial inventory command:

```bash
cargo nextest list --workspace --profile ci
```

4. Compare nextest-discovered tests against Cargo's inventory.
5. Confirm required feature profiles are passed explicitly.
6. Record suites that must remain on Cargo and why.

### Output

Create a compatibility table in `docs/testing/nextest-policy.md`:

| Suite | Nextest eligible | Required features | Resource class | Timeout class | Serialization | Cargo fallback reason |
|---|---|---|---|---|---|---|

### Success criteria

- Every migrated suite is inventoried before workflow changes.
- Doctests and specialized harnesses are not silently lost.
- Feature-dependent test discovery is explicit.
- Cargo-only exceptions have documented reasons.

## Workstream B2 — Pin and install nextest reproducibly

### Tasks

1. Choose a pinned nextest version compatible with the repository's stable Rust policy.
2. Install through a maintained action or `taiki-e/install-action` with an explicit version.
3. Avoid unpinned `cargo install cargo-nextest` in every job.
4. Cache the installed binary only if the installation action does not already handle this efficiently.
5. Record the version in `docs/testing/nextest-policy.md`.
6. Add a simple version check in CI logs:

```bash
cargo nextest --version
```

7. Ensure local developer installation instructions are documented.

### Success criteria

- CI uses a reproducible nextest version.
- Local reproduction instructions are available.
- Installation overhead is measured and not repeated unnecessarily within the same job.

## Workstream B3 — Add base nextest configuration

### Initial configuration

Add `.config/nextest.toml` with a conservative baseline similar to:

```toml
[profile.default]
fail-fast = false

[profile.ci]
fail-fast = false
status-level = "pass"
final-status-level = "slow"
slow-timeout = { period = "30s", terminate-after = 2 }

[profile.ci.junit]
path = "target/nextest/ci/junit.xml"
```

Adjust exact keys to the pinned nextest schema.

### Tasks

1. Define separate profiles if useful:
   - local default
   - CI fast
   - CI comprehensive
   - qualification
2. Keep retries disabled by default.
3. Define an explicit slow-test threshold.
4. Define a termination policy for hung tests.
5. Preserve sufficient output for debugging without flooding normal successful logs.
6. Configure JUnit output paths that avoid collisions between jobs.
7. Document how nextest profile names relate to Cargo compilation profiles; do not conflate the two.

### Success criteria

- Configuration validates under the pinned nextest version.
- A hanging test cannot consume a runner indefinitely.
- Slow tests are reported.
- Successful logs remain readable.
- JUnit files are produced deterministically.

## Workstream B4 — Define serialization and resource policy

### Tasks

1. Use the Milestone A resource inventory to classify tests into:
   - unconstrained
   - high CPU
   - high memory
   - fixed/global network resource
   - process-global state
   - external process
   - privileged/platform-specific
2. Add nextest overrides for known conflicts.
3. Prefer `threads-required` or test groups over whole-suite serialization.
4. Reserve `--test-threads=1` or one-thread groups for tests that truly cannot be isolated yet.
5. Do not serialize a complete package because one test uses global state.
6. Document each constrained test and the reason.
7. Add a TODO/issue reference for constraints that should be removed in Milestone E.

### Example policy

```toml
[[profile.ci.overrides]]
filter = 'test(/fixed_port|global_state|process_global/)'
threads-required = "num-cpus"

[[profile.ci.overrides]]
filter = 'test(/stress|interop|live_signing/)'
slow-timeout = { period = "120s", terminate-after = 1 }
```

Use valid syntax for the pinned version rather than copying examples blindly.

### Success criteria

- Independent tests run concurrently.
- Conflicting tests remain deterministic.
- Every serialization rule has an owner and rationale.
- Broad one-thread execution decreases where safe.
- No concurrency-related flakiness is accepted as normal.

## Workstream B5 — Define retry policy

### Policy

Retries are forbidden by default.

A retry may be added only when:

- the nondeterminism source is external and documented
- the first failure remains visible in reports
- a tracking issue or plan exists to remove the retry where possible
- security-critical deterministic tests are not masked

### Tasks

1. Search for existing retry wrappers or shell loops.
2. Record any current retry behavior.
3. Add nextest retry overrides only for approved cases.
4. Cap retries narrowly, normally at one.
5. Do not retry compile failures, architecture guards, policy guards, or deterministic unit tests.

### Success criteria

- Default retries remain zero.
- Any exception is documented in `docs/testing/nextest-policy.md`.
- Reports expose initial failures.

## Workstream B6 — Migrate the PR fast lane

### Tasks

1. Replace eligible Cargo test commands with nextest in the PR fast lane.
2. Preserve separate Cargo doctest commands if required.
3. Keep explicit features and package selectors.
4. Use the Cargo CI compilation profile consistently.
5. Upload JUnit results and slow-test summaries even on failure.
6. Print a directly reproducible local command in the job summary.
7. Compare discovered and executed test counts before and after migration.

### Suggested shape

```bash
cargo nextest run --workspace --cargo-profile ci --profile ci
cargo test --workspace --doc --profile ci
```

Confirm exact supported flags for the pinned nextest version.

### Success criteria

- PR test coverage is equivalent to the Milestone A fast lane.
- Doctests are retained where applicable.
- Failure output identifies the exact test binary and case.
- Test counts are reconciled.
- PR wall time does not regress materially.

## Workstream B7 — Migrate comprehensive native suites

### Tasks

Migrate eligible primary-Linux comprehensive jobs, including:

- root workspace tests
- DNS package tests
- mesh tests
- upload tests
- honeypot tests
- tarpit tests
- plugin-runtime tests
- security regression tests
- remaining domain suites

Use separate nextest invocations only when the groups have distinct features, resource classes, or lane ownership. Do not recreate the old pattern of dozens of one-target Cargo invocations.

Keep platform-specific or special-harness suites on Cargo until validated.

### Success criteria

- Comprehensive native test execution uses nextest where compatible.
- Feature profiles are explicit.
- No duplicated package plus individual target execution returns.
- Test count and ownership remain consistent.

## Workstream B8 — Publish JUnit and slow-test diagnostics

### Tasks

1. Upload JUnit XML for each nextest job using unique paths.
2. Produce a Markdown summary containing:
   - total tests
   - passed/failed/skipped
   - retries
   - timed-out tests
   - slowest tests
   - total execution time
3. Preserve reports on failure with `if: always()`.
4. Integrate results with `scripts/ci/summarize-test-costs.py` where practical.
5. Set artifact retention appropriate to debugging needs.
6. Ensure test names and paths do not expose secrets or sensitive runtime values.

### Success criteria

- Every migrated CI job produces machine-readable results.
- Slow and timed-out tests are visible without parsing raw logs.
- Artifacts remain available after failure.

## Workstream B9 — Classify architecture guards

### Tasks

Review every guard currently under root `tests/` and classify it as one of:

### Static repository/source guard

Examples:

- manifest ownership
- dependency ownership
- forbidden imports
- module/path boundaries
- documentation references
- source text patterns
- feature declaration policy
- unsafe/native language policy based on source inspection

These should move to the lightweight guard crate.

### Runtime architecture guard

Examples:

- supervisor task ownership behavior
- plugin failure isolation
- admin authorization behavior
- worker composition
- mesh task lifecycle
- request pipeline behavior
- mutation response semantics

These remain runtime tests, but should be grouped by domain and moved to owning crates later where appropriate.

### Ambiguous guards

For guards mixing source inspection and runtime behavior:

- split static assertions from runtime assertions
- move only static parts to the lightweight crate
- preserve runtime behavior in an appropriate integration target

### Output

Create `docs/testing/architecture-guard-ownership.md` with:

| Guard | Current path | Classification | New owner | New target | Features | Runtime dependency required |
|---|---|---|---|---|---|---|

### Success criteria

- Every current guard is classified.
- No guard is moved solely based on its name.
- Mixed guards are split carefully.
- Coverage intent is documented before code movement.

## Workstream B10 — Create the lightweight repository guard crate

### Proposed location

```text
tools/synvoid-repo-guards/
```

### Dependency boundary

The crate must not depend on the root `synvoid` package or heavyweight runtime crates unless a specific static parser requires a small dependency.

Preferred dependencies include:

- `anyhow` or `thiserror`
- `toml` or `cargo_metadata`
- `walkdir`
- `regex` only where structured parsing is not appropriate
- lightweight syntax parsing if genuinely needed

Avoid Wasmtime, AWS-LC, Quinn, Tonic, OpenRaft, SQLite, and broad internal runtime dependencies.

### Tasks

1. Add the crate to the workspace.
2. Implement a repository-root locator that works locally and in CI.
3. Provide shared helpers for:
   - reading manifests
   - walking Rust source
   - normalizing paths
   - producing actionable diagnostics
   - checking allowlists/ownership ledgers
4. Move static guards in coherent groups:
   - architecture boundaries
   - dependency policy
   - documentation/path references
   - plugin static policy
   - source safety/import policy
5. Preserve individual assertion names and actionable failure messages.
6. Add tests for the guard framework itself.
7. Ensure a guard failure names the violating file, rule, and expected remediation.

### Success criteria

- Static guards run without linking the root SynVoid dependency graph.
- The new crate has a deliberately small dependency tree.
- Diagnostics are at least as precise as before.
- Workspace checks and tests include the new crate.

## Workstream B11 — Consolidate static guard execution

### Tasks

1. Replace dozens of root `cargo test --test ...` commands for static guards with one or a small number of package-level commands:

```bash
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
```

2. Group tests by coherent domain rather than one binary per assertion.
3. Avoid creating a single enormous opaque test function; retain named tests inside grouped binaries/modules.
4. Remove old root guard files only after the new tests pass against known-good and known-bad fixtures.
5. Update ownership documentation and workflows.
6. Measure compilation, link, and execution time before and after.

### Success criteria

- Static guard Cargo invocation count falls to one or a small bounded number.
- Static guard binaries no longer link root dependencies.
- Every moved rule has equivalent coverage.
- Old duplicate guard targets are removed.

## Workstream B12 — Consolidate runtime guard binaries

### Tasks

1. Group remaining runtime guards by domain where they share feature sets and dependencies:
   - supervisor/worker lifecycle
   - request/data-plane composition
   - plugin runtime behavior
   - mesh behavior
   - admin/security behavior
2. Prefer modules within a smaller number of integration binaries.
3. Keep separate binaries where isolation is required because of:
   - process-global state
   - distinct feature sets
   - platform restrictions
   - external process lifecycle
   - materially different resource budgets
4. Preserve named test functions and failure locality.
5. Do not consolidate in a way that causes one global initialization failure to obscure unrelated guards.
6. Update CI to invoke package/test groups rather than each binary individually.

### Success criteria

- Root runtime guard binary count decreases materially.
- Cargo invocation count decreases.
- Runtime isolation remains where justified.
- Failure output remains actionable.

## Workstream B13 — Validate guard equivalence with failure injection

### Tasks

For representative guard categories, create temporary controlled violations or fixture-based negative cases:

- forbidden dependency ownership
- invalid root module boundary
- stale documentation path
- plugin manifest authority violation
- supervisor lifecycle violation where fixtureable
- admin authorization violation where fixtureable

Confirm the new guard detects the violation and reports the expected path/rule. Revert all temporary production-source mutations before committing.

Prefer permanent negative fixtures in the guard crate where possible.

### Success criteria

- Static guard migrations are proven against failing fixtures.
- Runtime consolidation does not weaken assertions.
- No moved guard only passes because it no longer inspects the intended files.

## Workstream B14 — Performance and resource comparison

### Tasks

Compare Milestone A and Milestone B for:

- test execution wall time
- root and guard compilation time
- link time
- peak RSS
- number of test binaries
- number of Cargo invocations
- slowest tests
- number of serial constraints
- JUnit/report availability
- PR and main critical-path duration

Create `docs/testing/milestone-b-results.md`.

### Required conclusions

The report must explain:

- gains from nextest scheduling
- gains from static guard decoupling
- gains from runtime binary consolidation
- remaining tests that require Cargo or full serialization
- remaining root integration hotspots for Milestone C
- resource conflicts deferred to Milestone E

### Success criteria

- Results are based on multiple representative runs where possible.
- Compilation/link gains are separated from test-runtime gains.
- Any regression has a documented cause and follow-up.

## Workstream B15 — Documentation and developer handoff

### Tasks

Update developer documentation with:

- installing the pinned nextest version
- running the fast suite locally
- running comprehensive native tests
- running repository guards
- interpreting timeout and slow-test output
- reproducing CI feature profiles
- when to use Cargo instead of nextest
- how to add a new serialization or retry exception
- how to add a new architecture guard

Suggested commands:

```bash
cargo nextest run --workspace --cargo-profile ci --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo test --workspace --doc --profile ci
```

### Success criteria

- CI failures provide reproducible local commands.
- New guard authors know which crate and category to use.
- Retry and serialization exceptions require explicit documentation.

## Commit sequencing

Recommended commits:

1. `test-infra: document nextest and guard ownership policy`
2. `test-infra: add pinned nextest configuration`
3. `ci: migrate pull request tests to nextest`
4. `ci: migrate comprehensive native tests to nextest`
5. `ci: publish nextest junit and slow-test reports`
6. `test-infra: add lightweight repository guard crate`
7. `test-infra: migrate static architecture guards`
8. `test-infra: consolidate runtime guard targets`
9. `ci: simplify architecture guard execution`
10. `docs: record milestone B validation and performance results`

Avoid combining the entire guard migration into one commit. Move coherent guard families so failures can be traced and reviewed.

## Validation matrix

Run at minimum:

```bash
cargo metadata --no-deps
cargo fmt --all -- --check
cargo check --workspace
cargo nextest list --workspace --cargo-profile ci
cargo nextest run --workspace --cargo-profile ci --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo test --workspace --doc --profile ci
cargo clippy -p synvoid-repo-guards --all-targets -- -D warnings
```

Also run feature-specific nextest commands corresponding to the ownership manifest, including mesh and DNS profiles where required.

Manually validate:

- PR fast workflow
- main comprehensive workflow
- JUnit upload on success
- JUnit upload on failure
- timeout handling with a controlled fixture
- slow-test reporting
- representative static guard negative fixtures

## Rollback strategy

### Nextest migration rollback

If nextest produces coverage ambiguity:

1. Retain `.config/nextest.toml` and documentation.
2. Revert the affected job to its Milestone A Cargo command.
3. Compare test discovery and feature selection.
4. Fix the compatibility gap before remigrating.

Do not keep Cargo and nextest running the same complete suite in parallel as a permanent workaround.

### Guard migration rollback

If a moved guard loses fidelity:

1. Restore that guard to its original root test target.
2. Keep successfully migrated guard families in the lightweight crate.
3. Add a failing fixture demonstrating the gap.
4. Correct the helper/parser before attempting migration again.

## Risks and mitigations

### Risk: doctests disappear during nextest migration

Mitigation: inventory doctests explicitly and retain a Cargo doctest command.

### Risk: higher concurrency exposes hidden shared state

Mitigation: start conservatively, use explicit groups/threads-required, and treat new races as defects rather than normal flakiness.

### Risk: retries mask deterministic failures

Mitigation: retries remain zero by default and require documented external nondeterminism.

### Risk: static guards become brittle text scans

Mitigation: prefer structured manifest/source parsing and permanent negative fixtures.

### Risk: one consolidated guard binary becomes opaque

Mitigation: retain individually named test functions and group only by dependency/feature domain.

### Risk: workspace guard crate accidentally gains heavyweight dependencies

Mitigation: document and inspect its dependency tree as a milestone gate:

```bash
cargo tree -p synvoid-repo-guards
```

### Risk: nextest installation overhead offsets gains

Mitigation: pin and install efficiently, measure setup time, and avoid repeated installation within one job.

## Milestone completion criteria

Milestone B is complete only when all of the following are true:

- A pinned nextest version and repository configuration are present.
- Eligible PR and comprehensive native suites run under nextest.
- Cargo-only exceptions, including doctests, are documented and retained.
- Slow-test and timeout policies are explicit.
- Retries are disabled by default and all exceptions are documented.
- Serialization is selective rather than broadly global where safe.
- JUnit and slow-test summaries are published on success and failure.
- Every architecture guard is classified as static/source or runtime.
- Static guards run from a lightweight crate that does not depend on the root SynVoid package.
- Static guard Cargo invocation and link costs decrease materially.
- Remaining runtime guards are consolidated where safe.
- Guard failure equivalence is demonstrated with negative fixtures or controlled failure injection.
- Before/after timing, memory, binary count, and Cargo invocation count are documented.
- No test or architecture-policy coverage is lost.
- Remaining root integration hotspots and resource conflicts are handed off clearly to Milestones C and E.

## Handoff notes for Milestone C

The Milestone B completion report must identify:

- every remaining root integration binary
- its owning domain and dependency closure
- whether it is genuine cross-crate composition or misplaced single-domain testing
- candidate destination crate
- shared fixtures required from `synvoid-testkit`
- feature and platform requirements
- current compile/link cost
- consolidation or migration risks

It must also identify matrix redundancies observed during nextest migration, especially jobs that compile equivalent feature sets or build and test inconsistent feature graphs.
