# Testing Infrastructure Milestone E — Improve Test-Level Efficiency

## Purpose

Milestone E improves the efficiency, determinism, and safe parallelism of SynVoid’s tests after Milestones A through D have reduced workflow scope, eliminated duplicate execution, modernized scheduling, moved tests to owning crates, and introduced affected-package selection.

The dominant remaining costs are now inside test execution itself:

- fixed ports and shared filesystem paths;
- process-global environment and tracing state;
- leaked or unjoined Tokio tasks;
- sleeps used as readiness synchronization;
- expensive fixtures rebuilt repeatedly;
- broad serialization for conflicts affecting only a subset of tests;
- specialized fuzz, stress, interoperability, and performance workloads sharing ordinary correctness paths;
- substantial duplicated DNS and protocol fixture construction.

This milestone must improve concurrency without weakening isolation. The implementation agent must classify conflicts before removing serialization and must prefer deterministic readiness, cleanup, and fixture ownership over higher raw thread counts.

## Preconditions

Before implementation begins:

- Milestone D final closure has no unresolved correctness blocker;
- affected-package selection and fail-closed behavior are authoritative;
- branch protection uses current stable checks;
- active cache behavior is accurately documented;
- root and per-crate ownership metadata is current;
- the current nextest serialization overrides are inventoried;
- baseline slow-test and resource data is available.

## Objectives

1. Eliminate unnecessary global serialization.
2. Remove fixed-port, shared-path, and process-global collisions.
3. Replace timing sleeps with explicit readiness and deterministic clocks.
4. Ensure spawned tasks and processes are shut down and joined.
5. Deduplicate expensive fixtures within owning crates.
6. Keep `synvoid-testkit` limited to genuinely cross-crate helpers.
7. Separate correctness, property, fuzz, stress, interoperability, and performance workloads.
8. Make fuzz and specialized suites independently schedulable with bounded resource usage.
9. Produce measurable improvements in wall-clock time and flake resistance.

## Non-goals

This milestone does not:

- weaken assertions to make tests faster;
- add broad retries for deterministic failures;
- increase global concurrency without resource classification;
- move domain fixtures into a generic testkit merely for centralization;
- convert integration tests into mocks when production semantics are required;
- introduce production behavior changes solely to satisfy tests without architectural justification;
- enforce final long-term performance budgets; that belongs to Milestone F.

## Workstream E1 — Build the test-resource inventory

Create:

```text
docs/testing/test-resource-inventory.md
```

Inventory all tests that use or mutate:

- TCP or UDP ports;
- Unix sockets or Windows named pipes;
- shared temporary paths;
- current working directory;
- environment variables;
- process-global tracing subscribers;
- global cryptographic providers;
- global registries or singleton managers;
- SQLite files or shared databases;
- child processes;
- background Tokio tasks;
- system time or long timers;
- DNS listeners and zones;
- certificates and keys;
- Wasmtime engines or compiled modules;
- privileged operations, eBPF, raw sockets, or platform-specific APIs;
- external network or services.

For each test binary or relevant test group, record:

- owner crate;
- resource type;
- current isolation mechanism;
- whether tests can run concurrently;
- current nextest override;
- expected maximum duration;
- cleanup behavior;
- proposed correction;
- lane classification.

Use searches such as:

```bash
rg -n '127\.0\.0\.1:[0-9]+|0\.0\.0\.0:[0-9]+|localhost:[0-9]+' --glob '*.rs'
rg -n 'set_var|remove_var|set_current_dir|tracing_subscriber::fmt\(\)\.init|try_init' --glob '*.rs'
rg -n 'tokio::spawn|spawn_blocking|Command::new|std::process::Command' tests crates --glob '*.rs'
rg -n 'sleep\(|timeout\(' tests crates --glob '*.rs'
rg -n 'NamedTempFile|tempdir|sqlite|\.db' tests crates --glob '*.rs'
```

### Exit criteria

- every broad nextest serialization override has a documented cause;
- every fixed port and shared path is inventoried;
- the top twenty slow tests have a resource classification;
- privileged and external-service tests are clearly separated from ordinary correctness tests.

## Workstream E2 — Eliminate fixed ports and shared endpoint collisions

Replace fixed listener ports with ephemeral allocation:

```rust
let listener = TcpListener::bind("127.0.0.1:0").await?;
let addr = listener.local_addr()?;
```

For UDP:

```rust
let socket = UdpSocket::bind("127.0.0.1:0").await?;
let addr = socket.local_addr()?;
```

Rules:

- allocate and retain the bound socket rather than probing a free port and closing it;
- pass the actual bound address to clients;
- avoid race-prone `find_free_port()` helpers that release the port before use;
- use per-test Unix socket paths under a unique temp directory;
- use unique named-pipe identifiers on Windows;
- remove hardcoded ports from tests unless the protocol behavior explicitly depends on a standard port;
- document rare cases requiring serial port ownership.

Add reusable domain-local helpers where appropriate:

```text
crates/synvoid-dns/tests/support/
crates/synvoid-ipc/tests/support/
crates/synvoid-mesh/tests/support/
```

Cross-crate endpoint helpers may be added to `synvoid-testkit` only when used by at least two independent crates.

### Validation

Run affected suites repeatedly and concurrently:

```bash
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci --run-ignored all
cargo nextest run -p synvoid-ipc --cargo-profile ci --profile ci
cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci
```

Use nextest stress repetition or shell loops for collision-sensitive suites.

### Exit criteria

- ordinary tests do not depend on fixed ports;
- endpoint allocation is race-free;
- concurrent repeated runs show no address-in-use failures;
- any retained fixed port has an explicit reason and serialization rule.

## Workstream E3 — Isolate environment and process-global state

Audit environment-variable mutation and process-global initialization.

Preferred approaches:

- pass configuration explicitly instead of reading environment variables in lower-level tests;
- move environment-dependent tests into dedicated binaries so process-global mutation is contained;
- use scoped guards that restore previous values;
- serialize only the specific binary or test group that mutates global state;
- use `tracing_subscriber::fmt().try_init()` through a shared `OnceLock` helper;
- initialize global crypto providers once and treat repeated initialization as idempotent;
- avoid changing the process current directory; pass absolute paths instead.

A scoped environment helper must:

- capture the prior value;
- restore it on drop;
- prevent parallel mutation where the Rust standard library cannot guarantee safety;
- clearly state that environment mutation is process-global.

Do not introduce unsound environment mutation in parallel tests.

### Exit criteria

- process-global mutations are confined to clearly identified test binaries;
- broad suite-wide serialization is replaced with targeted constraints;
- tracing and crypto initialization are deterministic and non-panicking;
- no test leaves environment or current-directory changes behind.

## Workstream E4 — Task, process, and listener lifecycle hygiene

Audit every test-spawned background task and child process.

Required properties:

- every spawned task is owned by a handle or task group;
- shutdown is signaled explicitly;
- tasks are awaited or aborted and then awaited;
- child processes are terminated and waited on;
- listeners and sockets are dropped after dependents stop;
- timeout paths still perform cleanup;
- no detached task retains a temp directory, port, database, or runtime.

Add test helpers such as:

```rust
pub struct TestTaskGroup { /* owned JoinHandles */ }

impl TestTaskGroup {
    pub fn spawn<F>(&mut self, name: &'static str, fut: F) { /* ... */ }
    pub async fn shutdown_and_join(self, deadline: Duration) -> Result<(), TestCleanupError> { /* ... */ }
}
```

Prefer existing production lifecycle abstractions when they accurately model the tested component. Do not create a parallel test-only lifecycle model that hides production defects.

Add cleanup assertions where practical:

- task group empty after shutdown;
- no child process remains;
- no socket accepts connections after teardown;
- temp directory can be deleted;
- database file can be reopened or removed.

### Exit criteria

- no known test intentionally leaks a task or process;
- timeout and failure paths join cleanup work;
- repeated execution does not accumulate threads, subprocesses, or open descriptors;
- lifecycle-sensitive tests no longer require global serialization solely because prior runs leaked resources.

## Workstream E5 — Replace fixed sleeps with explicit readiness

Classify each `sleep` in test code:

- protocol behavior under test;
- retry/backoff behavior under test;
- readiness synchronization;
- cleanup delay;
- rate-limit timing;
- arbitrary stabilization delay.

Replace readiness sleeps with:

- oneshot or watch channels;
- listener-bound notification;
- health/readiness endpoints;
- explicit state transitions;
- barriers or notifies;
- polling with bounded deadline and meaningful diagnostics.

Example:

```rust
let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
let server = tokio::spawn(run_server(listener, ready_tx, shutdown_rx));
ready_rx.await.expect("server readiness signal");
```

Use Tokio paused time for timer-driven unit tests when valid:

```rust
#[tokio::test(start_paused = true)]
async fn backoff_advances_deterministically() {
    // ...
    tokio::time::advance(Duration::from_secs(30)).await;
}
```

Do not use paused time for tests that require real socket deadlines unless semantics are validated.

### Exit criteria

- arbitrary readiness sleeps are eliminated from high-value suites;
- timer-heavy unit tests execute deterministically;
- failure diagnostics identify the missing readiness condition rather than timing out opaquely;
- test duration falls without increasing flakes.

## Workstream E6 — Deduplicate DNS and protocol fixtures

Milestone C identified roughly 1,600 lines of duplicated DNS fixtures.

Create domain-local support modules for shared DNS integration-test construction:

```text
crates/synvoid-dns/tests/support/mod.rs
crates/synvoid-dns/tests/support/query.rs
crates/synvoid-dns/tests/support/zone.rs
crates/synvoid-dns/tests/support/context.rs
crates/synvoid-dns/tests/support/dnssec.rs
```

Candidate helpers:

- `build_query`;
- `build_test_zone`;
- `setup`;
- `make_ctx`;
- `build_notify_query`;
- `build_axfr_query`;
- `build_update_add_record`;
- ED25519 and other DNSSEC test keys;
- deterministic records and serials.

Requirements:

- helpers return explicit values rather than mutating global state;
- fixture defaults are documented;
- tests can override relevant fields;
- keys and certificates are deterministic where security semantics permit;
- no production-only secrets or unsafe shortcuts;
- helper failures include context.

Likewise, extract IPC endpoint and shared protocol helpers into owning crates.

### Exit criteria

- duplicate DNS fixture code is materially reduced;
- test intent becomes clearer rather than hidden behind overly broad builders;
- fixture changes have one authoritative implementation;
- domain-local helpers do not add root-package dependencies.

## Workstream E7 — Define the cross-crate `synvoid-testkit` boundary

Audit the existing unused `synvoid-testkit` crate.

Adopt it only for helpers with cross-crate value, such as:

- generic ephemeral TCP/UDP servers;
- temporary certificate/key material used by multiple crates;
- test tracing initialization;
- generic temp-directory lifecycle;
- deterministic test clocks or readiness primitives;
- shared process cleanup wrappers.

Do not move DNS query builders, mesh routing fixtures, WAF corpora, or IPC-specific endpoints into the generic testkit.

Decision options:

1. activate and narrow the crate with at least two real consumers per helper family;
2. keep it intentionally minimal and document deferred adoption;
3. remove it if it has no justified consumers and preserving it creates maintenance ambiguity.

Any public helper must have tests and API documentation.

### Exit criteria

- the testkit has a clear, enforced responsibility;
- no generic helper duplicates domain-specific behavior;
- every retained module has real consumers or a documented reason;
- workspace dependency direction remains clean.

## Workstream E8 — Refine nextest scheduling and serialization

Using the resource inventory, revise `.config/nextest.toml`.

Replace broad pattern overrides with explicit filters based on:

- package;
- test binary;
- test name where stable;
- resource class.

Define groups such as:

```toml
[test-groups.global-env]
max-threads = 1

[test-groups.fixed-resource]
max-threads = 1

[test-groups.process-spawn]
max-threads = 2

[test-groups.network-heavy]
max-threads = 4
```

Example override:

```toml
[[profile.ci.overrides]]
filter = 'package(synvoid-ipc) & binary(process_lifecycle_test)'
test-group = 'process-spawn'
slow-timeout = { period = "60s", terminate-after = 2 }
```

Rules:

- do not use retries for deterministic races;
- retries require a documented external nondeterminism source;
- timeouts must reflect observed behavior and provide cleanup time;
- serialization must have a resource rationale in the inventory;
- remove obsolete overrides after fixture fixes.

### Exit criteria

- no global `--test-threads=1` remains where nextest grouping can express the constraint;
- each serialized group has a documented shared resource;
- unaffected tests execute concurrently;
- slow-test output identifies remaining bottlenecks.

## Workstream E9 — Separate test modalities

Create or update the test taxonomy:

```text
docs/testing/test-taxonomy.md
```

Classify:

- unit;
- integration;
- composition;
- static policy guard;
- security regression;
- property;
- fuzz smoke;
- fuzz campaign;
- stress;
- endurance;
- interoperability;
- benchmark;
- performance regression;
- platform qualification.

Assign each modality to PR, main, nightly, or release lanes.

### PR lane

- deterministic unit/integration tests;
- small bounded property counts;
- security and architecture guards;
- no sustained fuzz/stress/endurance.

### Main lane

- broader integration and feature combinations;
- moderate property counts;
- selected interoperability tests.

### Nightly lane

- fuzz smoke matrix;
- concurrency/resource stress;
- larger property counts;
- platform qualification;
- leak and endurance probes.

### Release lane

- extended fuzz corpus;
- performance baseline comparisons;
- sustained recovery/resource tests;
- packaging and release semantics.

### Exit criteria

- every specialized suite has one authoritative lane;
- ordinary PR correctness is not blocked by sustained workloads;
- no specialized suite is silently dropped;
- taxonomy and test ownership documents agree.

## Workstream E10 — Matrix fuzz targets with resource caps

Replace serial shell loops over fuzz targets with a job matrix.

Requirements:

- one target per matrix job or small coherent groups;
- `max-parallel` set according to runner cost and workspace compile pressure;
- shared build cache where beneficial and supported;
- per-target timeout;
- corpus/crash artifact upload;
- deterministic target list generated or guarded against drift;
- failures isolated to the specific target.

Example structure:

```yaml
strategy:
  fail-fast: false
  max-parallel: 4
  matrix:
    target:
      - dns_parser
      - http_parser
      - waf_request
      - mesh_message
```

Run bounded smoke counts nightly. Extended campaigns belong to manual or release workflows.

### Exit criteria

- fuzz targets run independently;
- concurrency is capped;
- crashes and corpora are retained as artifacts;
- one target failure does not suppress all other results;
- PR workflows do not run extended fuzz campaigns.

## Workstream E11 — Measure impact and flake resistance

Capture before/after data for:

- package test wall-clock time;
- individual slow tests;
- nextest effective concurrency;
- serialized test count;
- fixed-port count;
- arbitrary sleep count;
- task/process cleanup failures;
- repeated-run failure rate;
- peak threads and memory for representative suites.

Run repetition campaigns for touched suites, for example:

```bash
for i in $(seq 1 20); do
  cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci || exit 1
done
```

Use a practical repetition count based on suite cost. Record environment and profile.

Do not claim flake elimination from one successful run.

### Exit criteria

- touched suites pass repeated concurrent runs;
- wall-clock improvements are measured;
- no new race or leak signature appears;
- remaining slow/serialized tests have explicit follow-up classification.

## Workstream E12 — Documentation and handoff

Create:

```text
plans/testing_milestone_e_results.md
```

Update:

- `.config/nextest.toml` rationale;
- `docs/testing/test-resource-inventory.md`;
- `docs/testing/test-taxonomy.md`;
- `docs/testing/test-suite-ownership.md`;
- `docs/testing/ci-performance-baseline.md`;
- `AGENTS.md` testing commands;
- affected workflow lane documentation.

Record:

- helpers added;
- fixtures deduplicated;
- serialization removed or narrowed;
- sleeps removed;
- lifecycle fixes;
- fuzz/workload lane changes;
- before/after timing;
- known limitations;
- Milestone F handoff data.

## Recommended implementation sequence

1. Resource inventory and taxonomy.
2. Fixed-port and shared-path removal.
3. Environment/global-state isolation.
4. Task/process lifecycle cleanup.
5. Readiness and deterministic-time conversion.
6. DNS/IPC fixture consolidation.
7. Testkit boundary decision.
8. Nextest override refinement.
9. Specialized workload separation.
10. Fuzz matrix conversion.
11. Repetition and performance validation.
12. Documentation and results.

Keep resource-correctness changes separate from scheduling changes so regressions can be isolated.

## Validation matrix

At minimum:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci
cargo nextest run -p synvoid-ipc --cargo-profile ci --profile ci
cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci
cargo nextest run -p synvoid-waf --cargo-profile ci --profile ci
cargo test --profile ci --tests
```

Run native platform and nightly specialized workflows before closure.

## Rollback strategy

- If concurrency exposes a defect, restore a narrow test-group constraint rather than serializing the entire workspace.
- If a shared fixture changes semantics, revert the fixture extraction while keeping resource-isolation fixes.
- If paused time changes behavior, return the affected test to real time with explicit readiness and bounded deadlines.
- If fuzz matrix pressure exceeds runner capacity, reduce `max-parallel`; do not return to one opaque serial loop unless necessary for correctness.
- If testkit abstraction becomes overly generic, move helpers back to owning crates.

## Final exit criteria

Milestone E is complete only when:

- resource conflicts are inventoried;
- ordinary tests use ephemeral endpoints and isolated paths;
- process-global mutation is confined and documented;
- spawned work is shut down and joined;
- arbitrary readiness sleeps are materially reduced;
- duplicated DNS/protocol fixtures are consolidated;
- testkit responsibility is explicit;
- nextest serialization is narrow and evidence-based;
- specialized workloads have authoritative lanes;
- fuzz targets are independently scheduled with resource caps;
- repeated-run validation shows no material flake increase;
- before/after timing and resource results are committed;
- Milestone F receives stable commands and measured budgets.
