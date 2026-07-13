# Testing Infrastructure Optimization Roadmap

## Purpose

This roadmap restructures SynVoid's testing and CI infrastructure to reduce wall-clock time, CPU pressure, memory consumption, linker pressure, cache churn, and duplicated work without weakening correctness, security, portability, or release-readiness guarantees.

The current pipeline is thorough but behaves like a release-qualification system on ordinary pushes and pull requests. It repeatedly compiles a large workspace under expensive profiles and overlapping feature sets, runs some suites more than once, invokes many root integration binaries separately, serializes broad groups of tests, and places platform, fuzz, Miri, stress, and dependency-maintenance work on the synchronous iteration path.

This line of work separates fast developer feedback from comprehensive assurance and release qualification, then progressively reduces compilation scope and test-level contention.

## Current baseline

The workspace contains the root package plus a large set of internal crates, examples, UI components, fuzz targets, and platform-specific packages. The root package depends on heavyweight subsystems including Wasmtime/YARA-X, AWS-LC/Rustls, Quinn, SQLite, Tonic, OpenRaft, DNSSEC, and many internal crates.

Known cost multipliers in the current infrastructure include:

- Routine tests frequently use `cargo test --release`.
- The production release profile enables LTO and `codegen-units = 1`.
- Full or broad tests run on several operating-system targets.
- The build matrix can compile one feature set and test another.
- DNS package tests are followed by individually enumerated integration-test commands.
- Architecture guards are split across many separate root integration binaries and Cargo invocations.
- Plugin guard tests overlap with the dedicated plugin-runtime job.
- Alpine, FreeBSD, Miri, fuzz smoke, outdated dependency checks, platform compatibility, feature profiles, and broad release builds participate in the same overall required pipeline.
- Some suites use global `--test-threads=1` rather than selectively serializing conflicting tests.
- CI caching is fragmented across job-specific target caches and feature/profile combinations.
- There is no repository-wide test ownership manifest or performance budget.

## Objectives

The roadmap must achieve all of the following:

1. Reduce pull-request feedback latency and build-system occupancy.
2. Preserve all existing assurance categories by assigning them to appropriate lanes.
3. Eliminate duplicated test execution and unnecessary Cargo process startup.
4. Stop using production optimization settings for routine correctness testing.
5. Improve test scheduling, timeout reporting, and selective serialization.
6. Reduce root-package integration-test linkage and move tests toward owning crates.
7. Rationalize the feature and target matrix so every retained configuration proves a distinct property.
8. Introduce measurable compiler-cache effectiveness and affected-package selection.
9. Improve fixture reuse, task cleanup, port allocation, and concurrency safety.
10. Give developers one reproducible interface for fast, affected, comprehensive, and qualification testing.
11. Establish budgets and guardrails that prevent gradual CI-cost regression.

## Non-goals

This roadmap does not:

- Remove security, portability, fuzzing, Miri, stress, or release qualification.
- Lower test assertions merely to improve timing.
- Hide flaky tests through broad retries.
- Increase concurrency before resource conflicts are classified.
- Treat hosted-runner timing variance as a deterministic product regression.
- Replace production release builds with lower-optimization artifacts.
- Introduce unsafe test shortcuts that differ materially from production behavior without documentation.

## Target operating model

SynVoid should have four explicit validation lanes.

### Pull-request fast lane

Required before merge:

- formatting
- workspace metadata sanity
- primary Linux compile/check
- changed or affected package linting
- fast unit tests
- architecture and policy guards
- targeted integration tests
- core security regression tests
- one representative default feature profile

### Main-branch comprehensive lane

Run after merge or on direct pushes:

- full primary-Linux workspace tests
- complete important feature profiles
- DNS integration and interoperability suites
- mesh, plugin-runtime, upload, honeypot, tarpit, and other domain suites
- documentation build
- security and dependency policy validation

### Scheduled qualification lane

Run nightly or several times weekly:

- FreeBSD VM testing
- Alpine/musl runtime testing
- macOS and Windows runtime suites
- Miri
- fuzz smoke matrix
- outdated dependency reporting
- broad target compilation
- expensive stress and endurance tests
- all-features and extended interoperability checks

### Release qualification lane

Run manually or on release tags:

- production release profile builds
- full target matrix
- packaging and artifact smoke tests
- full security regression
- performance baseline comparison
- provenance, reproducibility, and release documentation checks

## Initial performance targets

The implementation agent must measure before enforcing these as hard gates. Initial goals are:

| Metric | Initial target |
|---|---:|
| Typical required pull-request checks | 10 minutes or less |
| Warm fast-path Rust test execution | 3 minutes or less |
| Local affected-package loop | 60 seconds or less for localized changes |
| Duplicate test execution in one lane | zero unless explicitly justified |
| Superseded pull-request runs | automatically cancelled |
| Root integration-test binary count | materially reduced from baseline |
| Slow-test reporting | available on every comprehensive run |
| Cache effectiveness | measured with restore/save cost and compiler hit rate |

## Milestone overview

### Milestone A — Measure and stop obvious waste

Covers roadmap phases 0 through 3:

- establish baseline observability
- add a dedicated CI test profile
- split fast, comprehensive, scheduled, and release lanes
- cancel superseded iteration runs
- remove duplicate test execution
- establish authoritative test ownership

Expected outcome: immediate, low-risk reduction in compile/link cost and synchronous CI scope while preserving every assurance category.

### Milestone B — Modernize test execution

Covers roadmap phases 4 and 5:

- adopt `cargo-nextest`
- classify timeouts, slow tests, and serialization requirements
- publish JUnit and slow-test output
- consolidate source/repository guards into a lightweight crate
- reduce root integration binaries and repeated Cargo invocations

Expected outcome: improved scheduling and diagnostics plus a substantial reduction in root-level linking overhead.

### Milestone C — Reduce compilation scope

Covers roadmap phases 6 and 7:

- move single-domain tests to owning crates
- expand `synvoid-testkit` where shared fixtures are needed
- reserve root tests for genuine cross-crate composition
- rationalize target and feature matrices
- ensure build and test commands use consistent feature sets

Expected outcome: localized changes compile and link smaller dependency graphs, and each retained matrix entry proves a distinct compatibility property.

### Milestone D — Accelerate warm and localized runs

Covers roadmap phases 8 and 9:

- standardize Cargo caching
- introduce `sccache`
- report cache statistics
- implement affected-package and reverse-dependent selection
- add conservative full-suite fallback rules

Expected outcome: warm CI and local changes reuse compiler outputs and avoid testing unrelated workspace areas.

### Milestone E — Improve test-level efficiency

Covers roadmap phases 10 and 11:

- audit fixed ports, global state, filesystem collisions, leaked tasks, sleeps, and repeated fixture setup
- add reusable testkit helpers
- selectively serialize only conflicting tests
- separate property, fuzz, stress, interoperability, and performance workloads
- matrix fuzz targets with a resource cap

Expected outcome: higher safe parallelism, reduced flakiness risk, and specialized workloads no longer blocking routine correctness feedback.

### Milestone F — Operationalize and protect the gains

Covers roadmap phases 12 through 14:

- add a developer-facing test CLI or `xtask`
- route CI through shared orchestration where practical
- define performance and structural budgets
- detect duplicate ownership and expensive profile regressions
- run coverage-equivalence and failure-injection closure validation

Expected outcome: a maintainable testing system with stable local commands, documented ownership, enforced cost controls, and proof that assurance was preserved.

## Phase 0 — Baseline and observability

### Work

Instrument representative cold-cache and warm-cache runs. Capture:

- workflow, job, and step duration
- queue time
- dependency compilation time
- first-party compilation time
- link time
- test-binary and individual-test duration
- peak resident memory
- disk usage
- cache restore/save duration and hit state
- number of Cargo invocations
- unique target/profile/feature combinations
- duplicate test targets across jobs

Use tools such as:

```bash
cargo build --timings
/usr/bin/time -v cargo test ...
```

Create a summarizer under `scripts/ci/` and publish timing artifacts.

### Exit criteria

- At least three representative runs are recorded.
- Cold and warm behavior are distinguished.
- The ten most expensive compilation units and twenty slowest tests are known.
- Duplicate execution and serial-resource requirements are inventoried.

## Phase 1 — Dedicated CI profile

### Work

Add a profile such as:

```toml
[profile.ci]
inherits = "dev"
opt-level = 1
debug = "line-tables-only"
incremental = false
panic = "unwind"
```

Use package-specific optimization overrides only where execution-time data justifies them. Migrate routine tests from `--release` to `--profile ci`. Keep production artifacts and release qualification on the existing release profile.

### Exit criteria

- Routine correctness jobs no longer use production LTO/link settings without justification.
- Test behavior remains equivalent.
- Compile and link time improve relative to Phase 0.

## Phase 2 — Workload lanes

### Work

Split the current monolithic CI topology into clear workflows, preferably:

```text
.github/workflows/pr-fast.yml
.github/workflows/main-comprehensive.yml
.github/workflows/nightly-qualification.yml
.github/workflows/release-qualification.yml
```

Add pull-request cancellation:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Move FreeBSD, Alpine full runtime tests, Miri, broad fuzz smoke, outdated dependency checks, extensive platform matrices, and long stress suites off the required pull-request path.

### Exit criteria

- Every existing check is assigned to a lane.
- Pull requests no longer wait for qualification-only workloads.
- Main/nightly/release assurance remains automated.
- Superseded pull-request runs are cancelled.

## Phase 3 — Duplicate removal and test ownership

### Work

Create `docs/testing/test-suite-ownership.md`. Record for each test target:

- owning crate
- owning workflow lane
- owning job
- feature and platform requirements
- expected duration
- serialization and external-resource requirements

Remove package-level plus individually enumerated reruns. Remove duplicate plugin guard ownership. Add a duplicate-target detector if practical.

### Exit criteria

- No test binary runs twice in one lane unless explicitly documented.
- DNS and plugin overlap is removed.
- Every test has one authoritative owner per lane.

## Phase 4 — Nextest adoption

### Work

Add `.config/nextest.toml`, migrate eligible native tests, define slow-test timeouts, selectively serialize resource-conflicting tests, and publish JUnit output.

Retries must be disabled by default and allowed only for documented external nondeterminism.

### Exit criteria

- Independent tests run concurrently.
- Conflicting tests are selectively constrained.
- Slow and timed-out tests are visible.
- Broad `--test-threads=1` use is reduced.

## Phase 5 — Guard consolidation

### Work

Classify guards as either repository/source inspection or runtime architecture validation. Move static source/manifests/docs/import guards into a lightweight tool crate such as `tools/synvoid-repo-guards` that does not depend on the root SynVoid package. Consolidate remaining runtime guards into a small number of domain-oriented integration binaries.

### Exit criteria

- Static guards do not link the root dependency graph.
- Root integration binary count and Cargo invocation count decrease materially.
- Failure output remains precise.

## Phase 6 — Move tests to owning crates

### Work

Audit root `tests/` and move single-domain behavior into the appropriate crate. Expand `synvoid-testkit` for reusable fixtures instead of retaining tests at the root for convenience.

Keep root tests only for genuine cross-crate composition, executable startup, or public façade behavior.

### Exit criteria

- Most domain tests compile only their owning dependency graph.
- Root tests have documented composition rationale.
- Coverage is preserved.

## Phase 7 — Feature and target matrix rationalization

### Work

Document what each target/profile/feature combination proves. Remove redundant entries. Ensure matrix build and test commands use identical feature sets. Keep a minimal representative PR matrix and broad nightly/release matrices.

### Exit criteria

- Every retained matrix entry has a unique purpose.
- No accidental second feature graph is compiled in the same job.
- Portability coverage remains explicit.

## Phase 8 — Compiler and dependency caching

### Work

Standardize Rust caching and introduce `sccache`. Report cache hits, misses, restore/save cost, and compilation savings. Avoid unnecessary per-job cache isolation and oversized target-directory caches.

### Exit criteria

- Warm-run compiler reuse is measurable.
- Cache overhead is lower than time saved.
- Cache failures safely fall back to normal compilation.

## Phase 9 — Change-aware selection

### Work

Use `cargo metadata`, `guppy`, or equivalent dependency-graph logic to select changed packages and reverse dependents. Define conservative full-suite fallbacks for root manifests, lockfiles, shared build scripts, core public traits, testkit changes, and selector changes.

Provide a local reproduction command under `scripts/` or `cargo xtask`.

### Exit criteria

- Localized changes run affected packages and dependents.
- Cross-cutting changes trigger broad validation.
- Selection decisions are visible and reproducible.

## Phase 10 — Resource isolation and fixture optimization

### Work

Audit fixed ports, environment mutation, global tracing initialization, shared databases, leaked tasks, process spawning, sleeps, certificate generation, Wasmtime compilation, DNS fixtures, and SQLite setup.

Add testkit helpers for ephemeral ports, temporary databases, certificates, deterministic clocks, controlled supervisors, DNS fixtures, mesh nodes, and cleanup assertions.

### Exit criteria

- Most tests can run concurrently.
- Global serialization is removed where unnecessary.
- Task/process leaks and avoidable sleeps are eliminated.

## Phase 11 — Specialized workload separation

### Work

Classify unit, integration, architecture, security, property, fuzz, stress, endurance, benchmark, performance, and interoperability tests. Assign each modality an appropriate lane and case/time budget. Convert the serial fuzz target loop into a matrix with controlled concurrency.

### Exit criteria

- Specialized workloads do not block routine feedback.
- Fuzz, stress, and interoperability assurance remain automated.
- Performance comparisons use stable baselines rather than single raw wall-clock thresholds.

## Phase 12 — Developer test CLI

### Work

Add a stable interface using `cargo xtask`, `just`, or an equivalent repository-owned command:

```bash
cargo xtask test fast
cargo xtask test affected
cargo xtask test crate synvoid-dns
cargo xtask test comprehensive
cargo xtask test qualification
cargo xtask test guards
cargo xtask test security
cargo xtask test fuzz-smoke
cargo xtask test release
```

CI should call the same orchestration layer where practical.

### Exit criteria

- CI failures print a reproducible local command.
- Developers do not need to memorize workflow-specific Cargo commands.
- Local and CI behavior do not drift.

## Phase 13 — Budgets and regression enforcement

### Work

Track moving medians for fast-lane duration, job duration, binary count, Cargo invocation count, root integration target count, slow tests, cache overhead, retries, fuzz duration, and matrix size.

Initially report regressions. Promote stable structural rules to blocking checks after observation.

### Exit criteria

- New expensive tests require classification and ownership.
- Release-mode routine tests, duplicate ownership, and unclassified root integration binaries are detected.
- Fast-lane cost remains within the agreed budget.

## Phase 14 — Closure and assurance-equivalence validation

### Work

Run the original inventory and new lane structure against the same commit. Compare test, feature, platform, security, docs, fuzz, Miri, release, and packaging coverage. Inject controlled failures into representative categories to prove each lane detects its assigned defects.

Create `docs/testing/test-infrastructure-closure-report.md` with before/after timing, coverage equivalence, failure-injection results, and deferred items.

### Exit criteria

- No assurance category is unintentionally absent.
- Pull-request latency and resource consumption improve materially.
- Main/nightly/release lanes detect their assigned failures.
- Branch protection references stable required checks.

## Cross-cutting implementation rules

1. Measure before and after every milestone.
2. Preserve a conservative fallback when selection or classification is uncertain.
3. Do not use retries to normalize deterministic failures.
4. Do not increase concurrency before shared resources are isolated.
5. Keep release artifact validation separate from routine correctness profiles.
6. Keep workflow lane ownership and local reproduction commands documented.
7. Prefer moving tests to owning crates over adding more root integration binaries.
8. Prefer one authoritative test command over package-level plus enumerated reruns.
9. Treat CI-time regressions as maintainability defects.
10. Preserve security and portability depth even when moving it off the synchronous PR path.

## Final completion criteria

This roadmap is complete when:

- the PR fast lane meets its agreed latency budget on representative warm runs
- every test and assurance category has documented ownership
- routine tests use a dedicated CI profile rather than production LTO settings
- duplicate execution is eliminated
- nextest schedules eligible tests with explicit timeout and serialization policy
- static guards no longer link the root package
- most domain tests live with owning crates
- feature and target matrices are non-redundant
- compiler-cache performance is measured
- affected-package selection has conservative fallbacks
- specialized workloads are separated from routine feedback
- local and CI orchestration share stable commands
- performance budgets and structural guardrails prevent regression
- closure validation demonstrates assurance equivalence
