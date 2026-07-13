# Testing Infrastructure Milestone A — Measure and Stop Obvious Waste

## Purpose

Milestone A delivers the first operational reduction in SynVoid test and CI cost. It establishes a reproducible performance baseline, removes the most expensive routine profile choice, separates fast iteration from qualification workloads, cancels superseded work, and eliminates known duplicate test execution.

This milestone is deliberately conservative. It should produce major wall-clock and resource improvements without requiring test migration, architectural refactoring, broad fixture rewrites, or dependency-aware selection.

The implementation agent must preserve every existing assurance category. Checks may move between workflow lanes, but none may disappear without an explicit, reviewed deferral.

## Relationship to the roadmap

This plan implements roadmap phases 0 through 3 from `plans/testing_infrastructure_optimization_roadmap.md`:

1. Baseline and observability.
2. Dedicated CI profile.
3. Workload lane separation and cancellation.
4. Duplicate removal and test ownership.

Milestone B depends on the artifacts produced here, especially the timing baseline, ownership manifest, lane definitions, and test-resource classification.

## Current known problems

The existing CI topology has several high-confidence cost multipliers:

- routine correctness tests use `--release`
- `[profile.release]` enables LTO and one codegen unit
- broad test execution occurs on multiple OS targets
- build and test commands can use inconsistent feature sets
- DNS package tests are followed by individually enumerated integration-test reruns
- plugin guard tests overlap between the architecture guard and plugin-runtime jobs
- many expensive qualification activities are part of the same synchronous workflow
- superseded pull-request runs are not explicitly cancelled
- no authoritative test ownership or expected-duration inventory exists

## Scope

### In scope

- Measuring current CI and local test cost.
- Capturing cold-cache and warm-cache behavior.
- Counting Cargo invocations, profiles, feature sets, targets, and duplicate test binaries.
- Adding a dedicated `[profile.ci]`.
- Migrating routine correctness tests off the production release profile.
- Retaining release mode only where production artifacts or measured execution cost justify it.
- Splitting the current workflow into fast, comprehensive, scheduled, and release lanes.
- Adding concurrency cancellation for pull-request iteration.
- Moving qualification-only workloads off the required PR path.
- Removing duplicate DNS and plugin test execution.
- Creating test-suite ownership and lane documentation.
- Recording before/after timing and resource results.

### Out of scope

- Adopting nextest; that is Milestone B.
- Consolidating architecture guard binaries; that is Milestone B.
- Moving root tests into owning crates; that is Milestone C.
- Introducing `sccache`; that is Milestone D.
- Implementing affected-package selection; that is Milestone D.
- Broad fixture or test concurrency refactors; that is Milestone E.
- Removing platform, fuzz, Miri, stress, or release checks.
- Changing production release optimization settings.

## Required deliverables

Milestone A must produce at minimum:

```text
plans/testing_milestone_a_measure_and_stop_obvious_waste.md

docs/testing/ci-performance-baseline.md
docs/testing/test-suite-ownership.md
docs/testing/ci-lane-policy.md

scripts/ci/summarize-test-costs.py

.github/workflows/pr-fast.yml
.github/workflows/main-comprehensive.yml
.github/workflows/nightly-qualification.yml
.github/workflows/release-qualification.yml
```

The agent may use reusable workflows or shared scripts if that produces a cleaner result. If the old `ci.yml` remains temporarily, it must be disabled, reduced to orchestration, or documented so it does not duplicate the new workflows.

## Workstream A1 — Inventory the current workflow and test surface

### Tasks

1. Enumerate all workflow jobs and commands in `.github/workflows/`.
2. Record every distinct:
   - Cargo subcommand
   - package selector
   - target triple
   - profile
   - feature set
   - test target
   - use of `--all-targets`
   - use of `--all-features`
   - use of `--test-threads=1`
3. Enumerate root integration-test targets under `tests/`.
4. Enumerate package-level integration tests under each workspace crate.
5. Identify commands where a package-level test invocation already includes later individually named test targets.
6. Identify tests or jobs repeated in more than one workflow job.
7. Identify qualification-only jobs currently blocking ordinary iteration.
8. Record all commands that build one feature set and test another.
9. Record tests that require:
   - privileged execution
   - platform-specific facilities
   - fixed ports
   - global process state
   - external binaries
   - long timeouts
   - serial execution

### Suggested commands

```bash
find .github/workflows -type f -maxdepth 2 -print
find tests -maxdepth 1 -type f -name '*.rs' -print | sort
find crates -path '*/tests/*.rs' -type f -print | sort
rg -n 'cargo (test|check|build|clippy)|cross (test|build)|test-threads|all-features|all-targets' .github/workflows
rg -n '^\[\[test\]\]|^name\s*=|required-features' Cargo.toml crates/**/Cargo.toml
```

### Output

Create a current-state table in `docs/testing/ci-performance-baseline.md` with columns:

| Lane/job | Command | Package | Profile | Features | Target | Test scope | Duplicate owner | Notes |
|---|---|---|---|---|---|---|---|---|

### Success criteria

- Every existing job and test command is represented.
- Known DNS and plugin duplication is confirmed or disproven with exact command semantics.
- Qualification-only jobs are explicitly identified.
- The inventory is detailed enough to prove that later workflow movement did not drop coverage.

## Workstream A2 — Establish timing and resource baseline

### Tasks

1. Measure at least three representative runs where feasible:
   - cold or mostly cold cache
   - warm dependency cache
   - warm local incremental state, if relevant
2. Collect per-job and per-step durations from GitHub Actions where available.
3. Instrument representative local or CI commands with:

```bash
/usr/bin/time -v cargo test ...
cargo build --timings ...
```

4. Record:
   - total wall time
   - user and system CPU time
   - maximum resident set size
   - filesystem I/O where available
   - compilation duration
   - link duration
   - test execution duration
   - number of test binaries
   - number of Cargo invocations
   - cache restore/save duration
5. Preserve Cargo timing reports as artifacts.
6. Add `scripts/ci/summarize-test-costs.py` or equivalent to turn available timing/JUnit/job data into Markdown.
7. Avoid making hard performance claims from one hosted-runner sample; record median and range where possible.

### Baseline suites

At minimum measure:

```bash
cargo test --release --no-fail-fast
cargo test -p synvoid-dns --release
cargo test -p synvoid-plugin-runtime
cargo test --test security_regression -- --test-threads=1
```

Also measure the architecture guard sequence as currently executed.

### Output

`docs/testing/ci-performance-baseline.md` must include:

- environment and runner information
- commit SHA
- cache state
- command
- wall time
- peak memory
- binary count
- known confounders
- top expensive units/tests where available

### Success criteria

- A reproducible baseline exists before profile or workflow changes.
- Cold and warm behavior are not conflated.
- At least the root suite, DNS suite, plugin suite, and guard suite are characterized.
- The baseline clearly separates compilation/linking cost from test runtime where possible.

## Workstream A3 — Add a dedicated CI profile

### Tasks

1. Add to the root manifest:

```toml
[profile.ci]
inherits = "dev"
opt-level = 1
debug = "line-tables-only"
incremental = false
panic = "unwind"
```

2. Confirm the profile is valid for all relevant workspace members.
3. Measure representative suites under both release and CI profiles.
4. Identify tests whose runtime degrades materially under `opt-level = 1`.
5. Add narrowly scoped package overrides only when data demonstrates that additional optimization reduces total wall time.
6. Do not add LTO or `codegen-units = 1` to the CI profile.
7. Convert routine correctness commands from:

```bash
cargo test --release
```

to:

```bash
cargo test --profile ci
```

8. Retain production release mode for:
   - release artifacts
   - release packaging smoke tests
   - performance/benchmark qualification
   - rare tests with explicit evidence that total time is lower in release mode
9. Document every remaining release-mode test invocation and its rationale.

### Validation

```bash
cargo test --profile ci --no-fail-fast
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-plugin-runtime --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
```

### Success criteria

- Routine test jobs use `--profile ci` or the default test profile rather than production release mode.
- Production release settings remain unchanged.
- Test pass/fail behavior is equivalent.
- Representative compile/link time improves materially.
- Any retained release-mode test is documented.

## Workstream A4 — Define CI lane policy

### Tasks

Create `docs/testing/ci-lane-policy.md` defining triggers, purpose, required status, and permitted workload for each lane.

### Pull-request fast lane

Must include:

- `cargo fmt --all -- --check`
- metadata sanity
- primary Linux compile/check
- core linting
- fast unit and integration coverage
- architecture/policy guards
- core security regression
- one representative feature profile

Must not include by default:

- FreeBSD VM
- Alpine full release test
- Miri
- broad fuzz target loop
- outdated dependency scan
- complete platform runtime matrix
- long stress/endurance tests
- full release artifact matrix

### Main comprehensive lane

Must include:

- broad primary-Linux workspace tests
- important feature profiles
- domain-specific DNS, mesh, upload, honeypot, tarpit, plugin, admin, and other suites
- documentation build
- security/dependency policy checks

### Scheduled qualification lane

Must own:

- FreeBSD
- Alpine/musl runtime
- macOS/Windows runtime
- Miri
- fuzz smoke matrix or current fuzz loop until Milestone E
- outdated dependencies
- broad target compilation
- expensive stress/interoperability/all-feature checks

### Release qualification lane

Must own:

- production release profile builds
- packaging and artifact smoke tests
- full release target matrix
- release-specific security and performance validation

### Success criteria

- Every current job maps to exactly one primary lane, with documented secondary reuse only where justified.
- Required PR checks are clearly distinguished from assurance that runs later.
- Branch-protection migration requirements are documented.

## Workstream A5 — Split workflow topology

### Tasks

1. Create separate workflow files or equivalent reusable-workflow orchestration.
2. Preserve manual dispatch for comprehensive, scheduled, and release workflows.
3. Add cancellation to PR-oriented workflows:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

4. Keep `fail-fast: false` where broad result collection is valuable, but do not confuse it with cancellation of superseded runs.
5. Ensure required summary checks report the actual fast-lane status.
6. Avoid keeping the legacy workflow active alongside the new workflows if it causes duplicate execution.
7. Use stable job names suitable for branch protection.
8. Add comments explaining why expensive jobs are scheduled rather than PR-gated.
9. Preserve artifact uploads and diagnostics needed to debug failures.

### Migration safety

During transition, compare the old job inventory against the new lane ownership document. Do not delete the old workflow until every check has a destination.

### Success criteria

- PR pushes launch only the fast lane plus intentionally required checks.
- Main pushes launch comprehensive validation.
- Scheduled qualification is operational.
- Release qualification is manually/tag triggerable.
- Superseded PR runs cancel.
- The legacy workflow no longer duplicates the new workflows.

## Workstream A6 — Remove DNS duplicate execution

### Tasks

1. Confirm whether:

```bash
cargo test -p synvoid-dns --release
```

already executes the individually listed DNS integration targets.
2. Choose one authoritative structure:
   - one package-level test command, or
   - explicit non-overlapping `--lib` and `--tests` commands, or
   - filtered groups where special suites require separate lanes
3. Do not run unrestricted package tests followed by the same named integration binaries.
4. Keep stress, interoperability, live-signing, or environment-dependent tests separately classified if needed.
5. Record each DNS test target in `docs/testing/test-suite-ownership.md`.
6. Measure before/after DNS wall time and Cargo invocation count.

### Success criteria

- Each DNS test binary executes once per intended lane.
- No DNS test coverage is lost.
- DNS Cargo invocation count decreases.
- Before/after timing is recorded.

## Workstream A7 — Remove plugin and guard overlap

### Tasks

1. Compare the architecture guard job against plugin-runtime guardrails.
2. Assign ownership according to semantics:
   - structural/source policy guards belong to architecture/repository guard ownership
   - runtime plugin behavior belongs to plugin-runtime ownership
3. Remove duplicated commands from one job.
4. Record authoritative owners in the test ownership document.
5. Preserve feature requirements and failure diagnostics.
6. Do not yet consolidate the physical binaries; that is Milestone B.

### Success criteria

- No plugin guard runs twice in the same lane.
- Structural and runtime ownership is explicit.
- Plugin-runtime unit coverage remains intact.

## Workstream A8 — Build the test-suite ownership manifest

### Required fields

For every test target or coherent suite, record:

| Field | Description |
|---|---|
| Name | Cargo target or suite name |
| Owning crate | Package responsible for behavior |
| Source path | Test source location |
| Lane | PR, main, scheduled, release |
| Job | Authoritative workflow job |
| Profile | CI, default test, release |
| Features | Required feature set |
| Platform | Any OS/target restriction |
| Resource class | CPU, memory, network, fixed port, global state, external process |
| Serialization | None, selective, full binary |
| Expected duration | Initial measured budget |
| Duplicate status | Unique or justified duplicate |
| Notes | Failure reproduction and caveats |

### Tasks

1. Populate the manifest from Workstream A1.
2. Include all root tests and important crate integration tests.
3. Mark unknown fields explicitly rather than guessing.
4. Add a maintenance rule requiring new suites to declare ownership.
5. Optionally add a script that compares workflow test target references against manifest entries.

### Success criteria

- Every currently invoked explicit test target has an owner.
- Unknown resource requirements are visible for Milestone B/E follow-up.
- The document can be used to prove no coverage was dropped during lane separation.

## Workstream A9 — Validate assurance preservation

### Tasks

1. Build a before/after coverage matrix:

| Assurance category | Old job | New lane/job | Trigger | Required? |
|---|---|---|---|---|

2. Include:
   - formatting
   - Clippy
   - root tests
   - crate tests
   - DNS
   - mesh
   - plugin runtime
   - architecture guards
   - security regression
   - docs
   - dependency audit
   - Miri
   - fuzz
   - Alpine
   - FreeBSD
   - target compatibility
   - feature profiles
   - release builds
3. Trigger each workflow manually where possible.
4. Verify permissions, caches, artifacts, and summary jobs.
5. Confirm no branch-protection-required check disappears unexpectedly.
6. Record any repository settings requiring manual administrator changes.

### Success criteria

- Every old assurance category has a new owner.
- All new workflows parse and launch successfully.
- Required fast-lane checks are stable.
- Scheduled/release checks remain available.

## Workstream A10 — Measure milestone impact

### Tasks

Re-run the baseline suites and compare:

- wall time
- compilation time
- link time
- test execution time
- peak RSS
- Cargo invocation count
- test binary count
- required PR critical-path duration
- total runner-minutes per PR

Update `docs/testing/ci-performance-baseline.md` with a Milestone A results section.

### Required conclusions

The report must state:

- which gains came from profile changes
- which gains came from moving work off the PR path
- which gains came from duplicate removal
- which bottlenecks remain for Milestone B
- whether any test-runtime regression appeared under the CI profile

### Success criteria

- The milestone has measurable before/after evidence.
- The PR critical path is shorter.
- Total required runner consumption is lower.
- No assurance category was removed.

## Commit sequencing

Recommended commits:

1. `test-infra: add CI performance baseline instrumentation`
2. `test-infra: document test ownership and lane policy`
3. `build: add dedicated CI compilation profile`
4. `ci: split pull request and comprehensive workflows`
5. `ci: add scheduled and release qualification workflows`
6. `ci: cancel superseded pull request runs`
7. `ci: remove duplicate DNS test execution`
8. `ci: remove overlapping plugin guard execution`
9. `docs: record milestone A performance results`

Commits may be combined where necessary, but avoid mixing profile changes, lane restructuring, and duplicate removal into one unreviewable patch.

## Validation matrix

Run at minimum:

```bash
cargo metadata --no-deps
cargo fmt --all -- --check
cargo check --workspace
cargo test --profile ci --no-fail-fast
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-plugin-runtime --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
```

Also manually dispatch:

- main comprehensive workflow
- scheduled qualification workflow
- release qualification workflow in non-publishing mode where possible

## Rollback strategy

If workflow separation causes coverage uncertainty:

1. Keep the new CI profile and observability changes.
2. Re-enable the legacy comprehensive workflow temporarily.
3. Disable duplicate new jobs rather than running both systems indefinitely.
4. Correct ownership gaps using the before/after coverage matrix.
5. Reattempt lane migration only after every old check has an explicit destination.

If the CI profile causes a test execution timeout:

1. Measure whether the problem is test runtime rather than compilation.
2. Add a narrow package optimization override.
3. Retain release mode for that suite only as a temporary documented exception.
4. Create a follow-up item to reduce the test's algorithmic or fixture cost.

## Risks and mitigations

### Risk: checks are accidentally dropped during workflow split

Mitigation: maintain an explicit old-to-new coverage matrix and do not disable the legacy workflow until ownership is complete.

### Risk: lower optimization makes CPU-heavy tests slower

Mitigation: measure total compile plus execution time and add package-specific overrides only where justified.

### Risk: scheduled checks become invisible

Mitigation: provide workflow summaries, failure notifications, manual dispatch, and documented release gates.

### Risk: branch protection references obsolete job names

Mitigation: use stable fast-lane job names and document required repository-setting updates before removing old checks.

### Risk: timing data is noisy

Mitigation: record multiple runs, cache state, runner type, medians, and ranges.

## Milestone completion criteria

Milestone A is complete only when all of the following are true:

- A reproducible cold/warm performance baseline exists.
- A dedicated CI profile is in use for routine correctness tests.
- Production release profile settings remain unchanged.
- PR, main, scheduled, and release lanes are operational.
- Superseded PR runs cancel automatically.
- FreeBSD, Alpine full tests, Miri, broad fuzzing, outdated dependencies, broad platform validation, and long qualification workloads no longer block ordinary PR feedback.
- Every original assurance category has a documented destination.
- DNS package/integration duplication is removed.
- Plugin guard overlap is removed.
- Every explicitly invoked test target has an authoritative owner.
- Before/after timing and resource results are documented.
- No unresolved coverage loss or branch-protection ambiguity remains.

## Handoff notes for Milestone B

The Milestone A completion report must provide Milestone B with:

- slowest test binaries and individual tests
- current use of `--test-threads=1`
- tests requiring global state or scarce resources
- architecture guard binary inventory
- static/source guards versus runtime guards classification
- current Cargo invocation count for guard execution
- current root integration link cost
- candidate nextest filters and timeout classes
- any test suites that could not leave release mode
- any remaining duplication or ownership ambiguity
