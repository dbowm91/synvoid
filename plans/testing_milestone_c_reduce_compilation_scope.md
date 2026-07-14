# Testing Infrastructure Milestone C — Reduce Compilation Scope

## Purpose

Milestone C reduces the amount of code that must compile and link for ordinary domain-level tests. Milestones A and B improved profile cost, workflow topology, execution scheduling, and guard structure. The next dominant cost is compilation scope: too many single-domain tests remain in the root package, where they inherit the root crate's large dependency graph and trigger broad relinking after unrelated changes.

This milestone moves tests toward the crates that own the behavior, expands `synvoid-testkit` only where shared fixtures justify it, reserves root integration tests for genuine cross-crate composition, and rationalizes the target/feature matrix so each retained configuration proves a distinct compatibility property.

## Preconditions

Before implementation begins:

- the Milestones A/B operational closure plan should be complete or have no unresolved blockers affecting workflow authority
- root guard consolidation must remain green
- the current root integration-test inventory must be captured
- cold/warm baseline measurements must exist for comparison
- authoritative feature sets for PR, main, nightly, and release lanes must be documented

## Objectives

1. Reduce root integration-test binary count and root-package linking.
2. Move single-domain tests to their owning crates without reducing coverage.
3. Keep root tests only for public façade behavior, executable startup, and genuine cross-crate composition.
4. Expand shared test infrastructure without creating a new heavyweight dependency hub.
5. Ensure each CI target/feature combination has a documented purpose.
6. Prevent build/test feature mismatches within the same job.
7. Reduce duplicated compilation graphs across lanes.
8. Produce measurable before/after compile, link, and wall-clock data.

## Non-goals

This milestone does not:

- add `sccache`
- implement affected-package selection
- broadly refactor production architecture merely to relocate tests
- remove platform or feature coverage without an equivalence argument
- collapse all root integration tests into one binary regardless of domain
- add broad test retries
- optimize individual fixtures or fixed-port behavior beyond what is required for test relocation
- redesign fuzz, stress, or benchmark workflows

## Target end state

At completion:

- domain behavior is tested in the owning crate
- `synvoid-testkit` provides narrowly scoped reusable fixtures
- root `tests/` contains only cross-crate composition, executable, façade, or policy tests that truly require the root package
- root test files include a short ownership rationale
- feature and target matrices are documented and mechanically aligned with workflow commands
- build and test steps in a job use the same feature set unless explicitly documented
- localized changes compile materially smaller graphs

## Workstream C1 — Root integration-test inventory and classification

### Tasks

1. Enumerate all root integration targets:

```bash
find tests -maxdepth 1 -type f -name '*.rs' -print | sort
cargo test --profile ci --tests --no-run --message-format=json \
  | tee /tmp/synvoid-root-tests.json
```

2. Record for every root test file:

- test target name
- number of test functions
- owning domain
- direct imports from `synvoid` and internal crates
- required features
- platform constraints
- external processes or network listeners
- use of shared fixtures
- compile/link duration
- execution duration
- whether it validates one crate or true cross-crate behavior

3. Classify each test into exactly one category:

- `STATIC_POLICY`: source/repository policy; should generally live in `synvoid-repo-guards`
- `DOMAIN`: behavior owned by one internal crate; should move to that crate
- `COMPOSITION`: interaction across two or more production crates; may remain at root or move to a dedicated composition package
- `FACADE`: public root API compatibility; remains at root
- `EXECUTABLE`: startup, CLI, process, packaging, or binary behavior; remains at root or moves to an executable-test package
- `PLATFORM`: OS-specific behavior; moves to owning crate where possible
- `QUALIFICATION`: long/stress/interoperability behavior; may move to scheduled/release lane and owning crate

4. Add the classification to:

```text
docs/testing/root-test-ownership.md
```

5. Add a migration disposition for every `DOMAIN` test:

- destination crate
- required public/test-only API
- fixture dependencies
- feature gates
- expected migration batch

### Success criteria

- every root integration target has one classification and one owner
- no root test remains unclassified
- all single-domain candidates have a concrete destination
- current compile/link timing is captured for the highest-cost binaries

## Workstream C2 — Establish migration rules

### Rules

A test should move to an owning crate when all meaningful assertions concern that crate's behavior, even if the test currently reaches the behavior through the root façade.

A test should remain at root only when at least one of the following is true:

- it validates public compatibility of the root `synvoid` API
- it validates composition among multiple domain crates
- it validates one of the shipped binaries as an external consumer would
- it validates workspace-level policy not suitable for the lightweight guard crate
- moving it would require exposing production internals solely for test convenience with no stable ownership rationale

### Tasks

1. Add a short header comment to retained root tests:

```rust
//! Root-test ownership: COMPOSITION
//! Rationale: validates interaction between synvoid-http, synvoid-waf,
//! and synvoid-block-store through the root worker assembly.
```

2. Reject migration approaches that expose broad internal APIs merely to make tests compile.

3. Prefer crate-local `tests/` or `#[cfg(test)]` modules according to the behavior boundary:

- public crate API behavior: crate integration test
- private implementation details: unit test inside the module
- cross-module but crate-local behavior: crate integration test or crate-private test support

4. Document any test-only public API using feature gates or `#[cfg(test)]` with clear ownership.

### Success criteria

- retained root tests explain why root ownership is necessary
- moved tests do not create accidental public API expansion
- crate-local tests use the narrowest practical visibility

## Workstream C3 — Migrate static and single-domain guards

### Tasks

1. Re-audit remaining root guards after Milestone B.

2. Move any source-only policy checks that do not require compiled root behavior to `tools/synvoid-repo-guards`.

3. Move domain-specific structural checks to the owning crate when they only inspect that crate.

4. Keep runtime ownership checks at root only where they inspect true root composition.

5. For each move, preserve:

- original assertions
- allowlist liveness tests
- negative fixtures
- feature-gated behavior
- failure messages

6. Run equivalence validation before deleting the old target.

### Success criteria

- no source-scanning root guard links the root package without a documented reason
- migrated guards have positive and negative validation
- root guard count decreases or remaining guards are justified

## Workstream C4 — Domain migration batches

Execute migration in small, domain-oriented batches. Each batch must compile and validate independently.

### Batch 1 — Core/config/utils/filter

Candidate destinations:

- `synvoid-core`
- `synvoid-config`
- `synvoid-utils`
- `synvoid-filter`

Tasks:

- move pure configuration fidelity tests
- move network classification tests owned by `synvoid-core`
- move serialization/helper tests that do not depend on root composition
- move filter parsing and evaluation behavior

Validation:

```bash
cargo nextest run -p synvoid-core --profile ci
cargo nextest run -p synvoid-config --profile ci
cargo nextest run -p synvoid-utils --profile ci
cargo nextest run -p synvoid-filter --profile ci
```

### Batch 2 — HTTP/WAF/proxy/static-files

Candidate destinations:

- `synvoid-http`
- `synvoid-waf`
- `synvoid-proxy`
- `synvoid-proxy-cache`
- `synvoid-static-files`

Tasks:

- move request normalization, header, path, and protocol behavior
- move attack-detection and WAF policy tests
- move cache semantics owned by proxy-cache
- move static-file semantics and range/path behavior
- retain only tests that exercise assembled request pipelines across crates

### Batch 3 — DNS/TLS/HTTP3/upstream

Candidate destinations:

- `synvoid-dns`
- `synvoid-tls`
- `synvoid-http3`
- `synvoid-upstream`
- `synvoid-http-client`

Tasks:

- move protocol-specific integration tests
- preserve feature gates and network fixture behavior
- separate live/interoperability qualification tests from fast domain tests
- avoid requiring the root package merely for shared certificates or listeners

### Batch 4 — Mesh/block-store/integrity/IPC

Candidate destinations:

- `synvoid-mesh`
- `synvoid-block-store`
- `synvoid-integrity`
- `synvoid-ipc`

Tasks:

- move persistence, replay, provenance, serialization, and mesh protocol tests
- retain root tests only for worker/mesh lifecycle composition
- ensure feature-gated mesh tests remain discoverable in the correct lane

### Batch 5 — Plugin/serverless/app/admin/CLI

Candidate destinations:

- `synvoid-plugin-runtime`
- `synvoid-serverless`
- `synvoid-app-server`
- `synvoid-app-handlers`
- `synvoid-admin`
- `synvoid-cli`

Tasks:

- move runtime policy tests to plugin-runtime
- move admin authorization/mutation behavior to admin
- move CLI parsing/dispatch behavior to CLI unless validating the shipped binary
- retain process-level executable tests at root or in a dedicated executable test package

### Batch 6 — Upload/honeypot/tarpit/tunnel/VPN/platform

Candidate destinations:

- `synvoid-upload`
- `synvoid-honeypot`
- `synvoid-tarpit`
- `synvoid-tunnel`
- `synvoid-vpn-client`
- `synvoid-platform`

Tasks:

- move single-subsystem tests
- retain only assembled server behavior at root
- preserve OS-specific gating and scheduled-lane ownership

### Per-batch success criteria

- destination crate tests pass before old root files are removed
- test counts and assertion coverage are reconciled
- root dependency graph is absent from the migrated test target unless genuinely required
- CI ownership documentation is updated in the same commit
- no batch mixes unrelated domains

## Workstream C5 — Expand `synvoid-testkit` carefully

### Purpose

Some tests remain at root because fixtures are coupled to root modules. Extract shared test infrastructure without turning `synvoid-testkit` into a dependency magnet.

### Candidate helpers

- ephemeral TCP/UDP listener allocation
- deterministic temporary directories
- certificate and key fixtures
- test tracing initialization
- in-memory or temporary SQLite stores
- mock upstream servers
- deterministic clocks or time controls
- controlled task supervisor and shutdown helpers
- DNS packet/zone builders
- mesh node/test transport builders
- HTTP request/response fixtures
- reusable assertion helpers

### Design constraints

- testkit must not depend on the root `synvoid` crate
- helpers should depend on the narrowest owning crates
- heavyweight optional helpers should be feature-gated
- production crates must not acquire testkit as a normal dependency
- fixture APIs should make cleanup explicit
- no hidden global runtime or process-global mutable state

### Tasks

1. Inventory duplicated fixture code across root and crate tests.

2. Add helpers only when used by at least two meaningful test suites or when necessary to break root ownership.

3. Add tests for cleanup, deterministic behavior, and feature gating.

4. Document feature groups in `crates/synvoid-testkit/README.md` or crate-level docs.

### Success criteria

- migrated tests do not duplicate large fixture implementations
- testkit remains lightweight by default
- heavy helpers are optional and owned
- testkit does not recreate the root dependency graph

## Workstream C6 — Root test composition boundary

### Tasks

1. Define the accepted root test categories in an automated guard.

2. Add a lightweight manifest file, for example:

```text
tests/OWNERSHIP.toml
```

Each root test entry should record:

```toml
[[test]]
name = "worker_request_pipeline"
class = "composition"
owners = ["synvoid-http", "synvoid-waf", "synvoid-block-store"]
reason = "validates assembled worker request flow"
```

3. Add a repository guard that fails when:

- a root test exists without an ownership entry
- an ownership entry names a missing test
- a `domain` classification remains at root without an approved exception

4. Keep the schema minimal and deterministic.

### Success criteria

- new root tests require explicit ownership
- stale manifest entries are detected
- single-domain root-test growth becomes visible in review

## Workstream C7 — Feature matrix rationalization

### Tasks

1. Inventory every feature combination used in all four workflow lanes.

2. For each combination, document:

- exact command
- target triple
- enabled/default-disabled features
- assurance property proved
- lane
- whether tests run or compile only
- overlap with another entry

3. Establish a canonical matrix in:

```text
docs/testing/feature-target-matrix.md
```

4. At minimum evaluate:

- default
- no-default-features
- mesh
- dns
- mesh+dns
- all-features
- wireguard
- icmp-filter
- platform-specific combinations

5. Remove or merge matrix entries that prove no distinct property.

6. Ensure build and test commands use identical feature strings within one job unless the distinction is explicitly intentional.

7. Avoid accidental use of `${FEATURES:-default}` where `default` is treated as a literal feature rather than normal default-feature behavior.

8. Prefer one compile-only check for unsupported cross targets and runtime tests only on supported native runners.

9. Verify optional dependencies remain optional under `--no-default-features` profiles.

### Success criteria

- every retained matrix entry has a unique written purpose
- no job builds one feature graph and tests another accidentally
- redundant target/profile combinations are removed
- broad all-features validation remains in nightly/release lanes
- PR lane retains only representative fast configurations

## Workstream C8 — Target matrix rationalization

### Tasks

1. Classify targets by assurance type:

- native runtime tested
- cross-compiled only
- packaging validated
- best-effort experimental

2. Verify platform support documentation matches actual CI behavior.

3. Avoid duplicate coverage such as separate cross-check and build-matrix entries proving the same compile property.

4. Keep at least one authoritative path for:

- primary Linux GNU runtime
- musl/Alpine compatibility
- macOS runtime
- Windows runtime
- FreeBSD compatibility
- aarch64 Linux compile or runtime where available

5. Move expensive platform runtime validation to nightly/release where not already done.

6. Ensure release qualification still validates all supported artifact targets.

### Success criteria

- target matrix is minimal but complete
- platform documentation and workflows agree
- unsupported or best-effort targets cannot appear fully supported by accident

## Workstream C9 — Measurement and comparison

### Tasks

Measure before and after:

- root integration-test binary count
- total root test source count
- root test compile/link duration
- destination crate test compile/link duration
- total PR fast-lane duration
- main comprehensive duration
- cold and warm behavior
- amount of compiled first-party code for representative localized changes

Use representative changes in:

- one small core crate
- DNS
- plugin-runtime
- static-files or upload

Record whether unrelated root tests rebuild.

### Success criteria

- root linking cost decreases materially
- localized crate changes no longer rebuild unrelated root integration targets where ownership was migrated
- no assurance category is lost
- measurements are included in Milestone C results

## Workstream C10 — Documentation and handoff

Create:

```text
plans/testing_milestone_c_results.md
```

Update:

- `docs/testing/root-test-ownership.md`
- `docs/testing/test-suite-ownership.md`
- `docs/testing/feature-target-matrix.md`
- `docs/testing/ci-lane-policy.md`
- `docs/testing/ci-performance-baseline.md`
- `AGENTS.md`

The result document must include:

- tests moved by source and destination
- retained root tests and rationale
- root binary count before/after
- feature/target entries removed or merged
- compile/link timing before/after
- test count reconciliation
- known deferred migrations
- Milestone D handoff data

## Required validation matrix

```bash
cargo fmt --all -- --check
cargo check --workspace --profile ci
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace --profile ci
cargo test --workspace --doc
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo check --all-features
```

Also run every canonical target/feature command documented in the final matrix.

## Recommended commit sequence

1. `test-infra: inventory and classify root integration tests`
2. `test-infra: expand lightweight shared test fixtures`
3. `test-infra: migrate core and request-path domain tests`
4. `test-infra: migrate DNS mesh and plugin domain tests`
5. `test-infra: enforce root test ownership manifest`
6. `ci: rationalize feature and target validation matrix`
7. `docs: record milestone C compilation-scope results`

Large migration batches should be split further when they exceed one reviewable domain.

## Risks and mitigations

### Risk: test migration changes visibility or behavior

Mitigation: run destination tests before removing originals, compare test counts, and preserve assertions verbatim before cleanup.

### Risk: testkit becomes a heavyweight central crate

Mitigation: forbid root dependency, use optional feature groups, and require reuse justification for new helpers.

### Risk: root composition coverage is lost

Mitigation: retain explicit root composition tests and add ownership metadata before deleting domain duplicates.

### Risk: feature-matrix reduction removes unique coverage

Mitigation: require a written assurance property for every removed or merged entry and retain broad nightly/release validation.

### Risk: public APIs are expanded only for tests

Mitigation: prefer unit tests, crate-private test modules, or test-only features; require rationale for public test support.

### Risk: platform support is overstated

Mitigation: classify native runtime, cross-compile, and best-effort support separately in docs and CI.

## Exit criteria

Milestone C is complete only when:

- every root test has an explicit ownership class
- all practical single-domain tests are moved to owning crates
- retained root tests have documented composition/façade/executable rationale
- `synvoid-testkit` supports required shared fixtures without a root dependency
- root integration binary count and linking cost are materially reduced
- feature and target matrices are canonical and documented
- build/test feature mismatches are eliminated
- all moved and retained tests pass in authoritative lanes
- test counts and coverage categories are reconciled
- a Milestone C result document provides measured before/after data and a Milestone D handoff

## Handoff to Milestone D

Milestone C must provide:

- canonical target/profile/feature classes for cache key design
- package-level compile timing data
- representative cold and warm runs
- root and crate-local test ownership map
- stable commands for full and package-scoped validation
- list of workspace packages and reverse-dependency relationships requiring affected-package selection
- conservative triggers that must always force full validation
