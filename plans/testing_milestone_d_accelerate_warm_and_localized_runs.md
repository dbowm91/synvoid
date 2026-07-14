# Testing Infrastructure Milestone D — Accelerate Warm and Localized Runs

## Purpose

Milestone D improves warm CI performance and localized developer iteration after Milestone C has reduced compilation scope. It standardizes Rust caching, introduces compiler-output reuse through `sccache`, reports cache effectiveness, and implements conservative affected-package selection with reverse-dependent closure and explicit full-suite fallbacks.

This milestone must optimize only after establishing stable feature/profile/target classes. Cache design applied before matrix rationalization would amplify fragmentation, and test selection applied before ownership cleanup could miss root-level coverage. Milestone D therefore assumes Milestone C has produced authoritative package ownership, commands, and matrix definitions.

## Preconditions

Before implementation begins:

- Milestones A/B operational closure is complete
- Milestone C is complete or has no unresolved ownership/matrix blockers
- canonical feature, profile, and target classes are documented
- package-level compile timing exists
- stable package-scoped and full validation commands exist
- root tests are classified and ownership metadata is authoritative
- known triggers that must force full validation are documented

## Objectives

1. Improve warm compile/check/test latency through reusable compiler artifacts.
2. Standardize registry, git, target metadata, and compiler-cache behavior across workflows.
3. Measure cache hit rate, restore/save cost, storage growth, and net benefit.
4. Select changed packages and all affected reverse dependents conservatively.
5. Preserve root composition and cross-cutting validation when changes warrant it.
6. Provide one reproducible local affected-test command.
7. Make selection decisions visible, inspectable, and fail-safe.
8. Avoid cache or selection correctness depending on opaque job-local assumptions.

## Non-goals

This milestone does not:

- remove full workspace validation from main/nightly/release lanes
- use changed-files-only testing without dependency analysis
- cache final release artifacts as a substitute for release builds
- share incompatible compiler outputs across targets, toolchains, profiles, or feature classes
- treat cache hit rate alone as success if restore/save overhead exceeds savings
- silently skip tests when selector metadata is incomplete
- introduce remote third-party cache infrastructure requiring secrets unless separately approved
- redesign test fixtures, fuzzing, stress testing, or per-test concurrency

## Target end state

At completion:

- all Rust workflows use a consistent caching policy
- `sccache` is enabled for eligible hosted-runner compilation
- cache statistics appear in CI summaries
- cache keys align with canonical toolchain, target, profile, and feature classes
- localized changes run changed packages plus reverse dependents and relevant root composition tests
- uncertain or cross-cutting changes automatically fall back to broader validation
- developers can reproduce the selector locally
- main, nightly, and release lanes retain authoritative comprehensive coverage

## Workstream D1 — Cache architecture and policy

### Tasks

1. Inventory current caching in all workflows:

- `actions/cache`
- `Swatinem/rust-cache`
- cached `target/` directories
- Cargo registry and git caches
- cargo tool binary caches
- nightly/stable separation
- target-specific keys

2. Record current cache keys, paths, restore prefixes, sizes, hit rates, and restore/save durations.

3. Define cache layers:

### Layer 1 — Cargo source caches

- `~/.cargo/registry/index`
- `~/.cargo/registry/cache`
- `~/.cargo/git/db`

These are broadly reusable but must respect Cargo.lock and source changes where necessary.

### Layer 2 — Tool binaries

- pinned `cargo-nextest`
- pinned `cargo-fuzz`
- `cargo-audit`
- `cargo-deny`
- optional `sccache` binary

Cache or install through pinned actions where the install cost justifies it.

### Layer 3 — Compiler outputs

Use `sccache` as the primary cross-job reusable compiler-output layer.

### Layer 4 — Cargo target metadata

Use `Swatinem/rust-cache` or carefully scoped target caching only where measurements show net benefit. Avoid indiscriminate full-target archives for every job.

4. Create:

```text
docs/testing/cache-policy.md
```

The policy must specify:

- supported cache layers
- key dimensions
- invalidation rules
- maximum expected cache size
- jobs that intentionally do not cache
- release and security considerations
- fallback behavior
- measurement requirements

### Success criteria

- every cache path has an owner and rationale
- duplicate/competing target caches are removed
- key fragmentation is reduced without mixing incompatible outputs
- cache failures degrade to normal compilation

## Workstream D2 — Introduce `sccache`

### Tasks

1. Pin an `sccache` version or trusted installation action.

2. Enable GitHub Actions-backed storage where supported:

```yaml
env:
  RUSTC_WRAPPER: sccache
  SCCACHE_GHA_ENABLED: "true"
```

3. Start and stop/report the server explicitly where required:

```bash
sccache --start-server || true
sccache --zero-stats || true
# Rust commands
sccache --show-stats
```

4. Ensure `RUSTC_WRAPPER` applies to Cargo compilation but does not break:

- Miri
- rustdoc/doctests
- cross/cross-rs
- fuzzing
- release LTO builds
- platform-specific runners

Disable `sccache` for jobs where unsupported or demonstrably unhelpful.

5. Test key isolation across:

- stable vs nightly
- Linux vs macOS vs Windows
- GNU vs musl
- host vs cross targets
- CI vs release profiles
- feature classes
- patched git dependencies

6. Capture statistics:

- compile requests
- cache hits
- cache misses
- non-cacheable calls
- cache errors
- cache size
- elapsed compile time

7. Add a summary step that always runs and never masks the primary job result.

### Success criteria

- eligible jobs report valid `sccache` statistics
- warm jobs demonstrate compiler-output reuse
- incompatible toolchain/target outputs are not mixed
- jobs continue successfully if the cache backend is unavailable
- Miri, fuzz, cross, and release behavior is explicitly validated

## Workstream D3 — Standardize reusable workflow setup

### Tasks

1. Reduce duplicated Rust setup across workflow files using either:

- a local composite action under `.github/actions/setup-rust-ci`
- reusable workflows
- a small set of copied but generated/guarded snippets if GitHub limitations make abstraction unsafe

2. The setup interface should accept:

- toolchain
- target
- components
- cache class
- whether nextest is required
- whether sccache is enabled
- whether release-mode behavior is required

3. Pin third-party actions to stable versions or commit SHAs according to repository policy.

4. Add a policy guard that detects workflows bypassing the standardized setup without an allowlisted reason.

5. Avoid hiding important commands behind overly opaque abstractions; workflow logs must still show effective toolchain, target, and cache class.

### Success criteria

- Rust setup and cache behavior are consistent across lanes
- exceptions are explicit
- updating pinned tool versions requires one controlled change
- logs remain diagnosable

## Workstream D4 — Cache performance measurement

### Tasks

For representative jobs, collect at least three cold and three warm runs:

- PR fast core test job
- root composition/guard job
- DNS job
- plugin-runtime job
- main workspace test job
- one cross-target build
- one release build

Measure:

- setup duration
- cache restore duration
- compile duration
- test duration
- cache save duration
- total job duration
- archive size
- `sccache` hit/miss rate
- non-cacheable compile percentage
- peak disk usage

Compute net benefit:

```text
net cache benefit = uncached compile time
                    - warm compile time
                    - restore time
                    - save time
```

Do not retain a cache layer that is consistently net-negative.

### Success criteria

- cache effectiveness is reported as time saved, not merely hit percentage
- cache growth and restore overhead remain bounded
- warm-run improvements are reproducible
- non-beneficial cache layers are removed or limited

## Workstream D5 — Affected-package selector design

### Purpose

Select the minimum conservative validation set for a change while preserving reverse-dependent and root-composition coverage.

### Inputs

- merge-base commit
- head commit
- changed file list
- `cargo metadata` package graph
- package ownership map from Milestone C
- root test ownership manifest
- canonical feature/target matrix

### Outputs

The selector must produce machine-readable and human-readable data:

```json
{
  "mode": "affected",
  "reason": "localized crate changes",
  "changed_packages": ["synvoid-filter"],
  "reverse_dependents": ["synvoid-waf", "synvoid-http", "synvoid"],
  "root_tests": ["worker_request_pipeline"],
  "feature_classes": ["default"],
  "full_fallback": false
}
```

### Tasks

1. Implement under a stable path such as:

```text
scripts/ci/select-affected.py
```

or a Rust `xtask` if dependency-graph correctness and maintainability justify it.

2. Use `cargo metadata --format-version 1` as the source of workspace package relationships.

3. Map changed files to packages by manifest roots.

4. Compute transitive reverse dependents within the workspace.

5. Select relevant root tests from `tests/OWNERSHIP.toml` based on owning packages.

6. Emit explicit reasons for every selected package/test and every fallback.

7. Exit nonzero on malformed metadata or selector-internal errors unless full fallback is emitted safely.

### Success criteria

- changed package mapping is deterministic
- reverse-dependent closure is complete
- relevant root composition tests are included
- output is both machine-readable and reviewable
- uncertainty results in broader validation, never silent omission

## Workstream D6 — Conservative full-suite fallback rules

### Mandatory full fallback triggers

At minimum, run broad validation when changes affect:

- root `Cargo.toml`
- workspace member lists
- `[workspace.dependencies]`
- `Cargo.lock`
- `.cargo/config*`
- toolchain files
- build scripts used by multiple crates
- shared protobuf/schema/code-generation inputs
- `synvoid-testkit`
- root public façade modules
- core public traits used broadly
- CI workflow files
- selector implementation or ownership metadata
- feature definitions
- release/profile definitions
- patched dependencies
- multiple unrelated package roots above a configured threshold

### Tasks

1. Encode fallback rules in data or a clearly tested policy module.

2. Print the exact rule that caused fallback.

3. Distinguish fallback scopes:

- full PR fast lane
- full primary-Linux workspace
- full feature matrix
- full platform qualification

4. Avoid launching all nightly/release work on every fallback unless the changed files truly require it.

5. Add tests for every fallback rule.

### Success criteria

- all cross-cutting changes force an appropriate broad mode
- fallback decisions are transparent
- no selector error produces an empty test set

## Workstream D7 — Selector validation and adversarial fixtures

### Tasks

Create fixture graphs and changed-file cases covering:

- leaf crate source change
- crate public API change
- core crate change with many reverse dependents
- root façade change
- test-only change
- documentation-only change
- Cargo.lock change
- workspace dependency change
- build.rs change
- CI workflow change
- ownership manifest change
- renamed/moved crate file
- deleted package file
- newly added workspace crate
- feature declaration change
- multiple package changes
- selector parse failure

For each fixture, assert exact selected packages, tests, features, and fallback mode.

Add negative tests proving the selector does not:

- select only direct dependents
- omit root composition tests
- treat unknown files as safe
- ignore deleted or renamed files
- continue with malformed metadata

### Success criteria

- selector behavior is covered by deterministic unit tests
- reverse-transitive and fallback behavior are proven
- negative fixtures prevent vacuous success

## Workstream D8 — CI integration

### Pull-request lane

1. Add an initial selector job.

2. Publish selection output to the workflow summary.

3. Use job outputs to construct package/test matrices.

4. Preserve stable branch-protection check names. Dynamic matrices should report through stable aggregate jobs.

5. Keep a manual override input or label-based mechanism for forcing broad validation if operationally useful.

### Main lane

Main should remain comprehensive by default. Affected selection may optimize non-authoritative auxiliary jobs, but must not replace the full primary-Linux assurance lane without a separate roadmap decision.

### Nightly/release lanes

Do not use affected selection to skip qualification. These lanes validate the repository state, not only a diff.

### Tasks

- ensure empty valid selections produce an explicit no-code-change result, not skipped required checks with ambiguous status
- aggregate dynamic job results into stable required checks
- upload selector output as an artifact
- add `workflow_dispatch` options to force full selection for testing

### Success criteria

- pull requests use affected mode for localized changes
- broad changes trigger full PR validation
- branch protection remains stable
- main/nightly/release assurance is preserved

## Workstream D9 — Developer-facing affected command

### Tasks

Provide one local command, for example:

```bash
scripts/test-affected.sh origin/main
```

or:

```bash
cargo xtask test affected --base origin/main
```

The command must:

- determine or accept a merge base
- run the same selector as CI
- print selected packages, root tests, features, and fallback reasons
- invoke the same nextest/Cargo profiles as CI
- support dry-run/JSON output
- support `--full` override
- fail clearly when the base ref is unavailable

Add examples to `AGENTS.md` and testing documentation.

### Success criteria

- local and CI selection outputs match for the same commit range
- developers can reproduce a failed affected run with one command
- dry-run mode is fast and deterministic

## Workstream D10 — Selection telemetry and shadow mode

### Purpose

Before making affected selection authoritative, compare it against comprehensive results.

### Tasks

1. Run the selector in shadow mode for a defined observation period.

2. On pull requests, execute selected tests and periodically or conditionally execute the broader baseline.

3. Record:

- selected package count
- full package count
- selected root tests
- fallback frequency
- time saved
- any failures found only by the broad run

4. Treat any broad-only failure caused by a missed dependency as a selector correctness defect.

5. Update fallback rules and tests before making the selector authoritative.

### Success criteria

- no unexplained broad-only failures occur during the observation window
- fallback frequency is neither effectively 100% nor suspiciously low
- measured time savings justify the added complexity

## Workstream D11 — Cache and selector safety guards

### Tasks

Add repository guards for:

- unpinned nextest/sccache versions
- workflows using divergent cache key schemas
- Rust jobs bypassing standard setup without allowlist
- affected selection used in nightly/release qualification
- required aggregate jobs missing selector failure propagation
- selector/ownership changes not forcing full validation
- malformed root test ownership entries

### Success criteria

- structural regressions are caught during PR validation
- unsafe selector use cannot silently spread to qualification lanes

## Workstream D12 — Measurement and documentation

Create:

```text
plans/testing_milestone_d_results.md
```

Update:

- `docs/testing/cache-policy.md`
- `docs/testing/ci-performance-baseline.md`
- `docs/testing/ci-lane-policy.md`
- `docs/testing/test-suite-ownership.md`
- `AGENTS.md`

The result document must include:

- cache architecture and key classes
- cold/warm measurements
- restore/save overhead
- `sccache` hit/miss statistics
- net time saved by job class
- affected-selector algorithm
- fallback rules
- selector fixture coverage
- shadow-mode comparison
- branch-protection behavior
- known limitations
- Milestone E handoff

## Required validation matrix

### Repository validation

```bash
cargo fmt --all -- --check
cargo check --workspace --profile ci
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace --profile ci
cargo test --workspace --doc
```

### Selector validation

```bash
python scripts/ci/select-affected.py --base HEAD~1 --head HEAD --dry-run
python scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json
# or equivalent xtask commands
```

Run selector unit and fixture tests, then compare output against manually computed reverse dependency closures for representative packages.

### Cache validation

For each supported job class:

1. clean/cold run
2. unchanged warm run
3. localized source change
4. dependency or feature change
5. cache unavailable fallback

### Workflow validation

- localized leaf-crate PR
- core-crate PR
- Cargo.lock PR
- workflow-only PR
- docs-only PR
- forced-full PR
- selector-error injection

## Recommended commit sequence

1. `test-infra: document cache architecture and baseline`
2. `ci: standardize Rust setup and compiler caching`
3. `test-infra: add affected package selector and fixtures`
4. `ci: run affected selector in pull-request shadow mode`
5. `ci: make validated affected selection authoritative for PR fast lane`
6. `test-infra: add cache and selector policy guards`
7. `docs: record milestone D warm and localized run results`

Keep cache integration and selector logic in separate commits so performance regressions and correctness defects are bisectable.

## Risks and mitigations

### Risk: cache restore/save overhead exceeds compile savings

Mitigation: calculate net benefit per job and remove or narrow net-negative layers.

### Risk: incompatible outputs share a cache

Mitigation: key by toolchain, target, profile, and canonical feature class; validate with controlled changes.

### Risk: sccache causes failures in specialized jobs

Mitigation: explicitly test and disable it for unsupported Miri, fuzz, cross, rustdoc, or release cases.

### Risk: affected selection misses a reverse dependency

Mitigation: use `cargo metadata`, transitive closure, root ownership metadata, adversarial fixtures, and shadow-mode comparison.

### Risk: dynamic matrices destabilize required checks

Mitigation: use stable aggregate jobs for branch protection and propagate all child failures.

### Risk: fallback rules are so broad that selection provides little value

Mitigation: measure fallback frequency, refine only with evidence, and retain correctness-first defaults.

### Risk: selector complexity becomes unmaintainable

Mitigation: keep the algorithm deterministic, data-driven, heavily tested, and available through one local/CI interface.

### Risk: cache backend outage blocks CI

Mitigation: cache operations must be best-effort and compilation must proceed normally.

## Exit criteria

Milestone D is complete only when:

- Rust cache behavior is standardized and documented
- eligible jobs use `sccache` with reported statistics
- cache net benefit is measured across representative cold/warm runs
- affected-package selection computes changed packages and transitive reverse dependents
- relevant root composition tests are selected from authoritative ownership data
- cross-cutting and uncertain changes trigger conservative fallback
- selector fixtures cover normal, edge, and failure cases
- pull-request selection passes a shadow-mode comparison period
- stable required checks remain intact
- local and CI affected commands produce equivalent output
- main, nightly, and release comprehensive assurance remains unchanged
- a Milestone D result document records measurable improvements and limitations

## Handoff to Milestone E

Milestone D must provide:

- per-test and per-binary timing after cache/selection stabilization
- tests still requiring broad serialization
- cache-cold tests whose execution, not compilation, dominates latency
- jobs limited by fixture setup, fixed ports, sleeps, or leaked tasks
- selector data identifying frequently rebuilt/tested packages
- stable local commands for targeted reproduction
- resource measurements for designing safe test-level parallelism
