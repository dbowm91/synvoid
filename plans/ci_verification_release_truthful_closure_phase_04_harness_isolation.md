# Phase 4 — Harness and Environment Isolation

**Status:** COMPLETED  
**Completed:** 2026-08-06  
**Commit:** `4142a9eb`  
**Verification:** `cargo xtask verify` 8/8 pass; CI run `31049895629` passed (13m12s)  
**Roadmap:** `plans/ci_verification_release_truthful_closure_roadmap.md`  
**Depends on:** Phase 1 adjudication  
**Purpose:** Make the remaining environment- and harness-classified tests deterministic, self-contained, and truthful without increasing routine CI complexity.

## 1. Current Provisional Inventory

The current verification disposition identifies these harness/environment areas:

- `test_pool_creation`: assumes a Unix socket at `/tmp/test.sock` that the test does not create;
- `test_worker_crash_recovery`: depends on a pre-built executable, process discovery, and a running supervisor;
- five `proxy_pipeline_tests`: fail during TLS setup due to an ALPN/configuration panic;
- `test_dashmap_modify_in_place`: hangs under concurrent execution, provisionally attributed to a test-fixture/runtime deadlock.

Phase 1 may refine this list. The final Phase 1 ledger is authoritative.

## 2. Scope Boundaries

### In scope

- temporary socket/listener creation and cleanup;
- deterministic process binary discovery/build prerequisite handling;
- child-process readiness, termination, and cleanup;
- TLS certificate, client configuration, ALPN, and test-server fixture repair;
- deterministic concurrency coordination for the DashMap test;
- targeted nextest test-group or per-test timeout adjustment when justified by measured behavior;
- explicit specialist-command preflight for tests that cannot reasonably be self-contained.

### Out of scope

- a generic integration-test framework;
- container or VM orchestration;
- new CI jobs or service containers;
- global timeout inflation;
- replacing the proxy TLS stack;
- replacing DashMap or redesigning production concurrency unless Phase 1 proves a product deadlock;
- adding `#[ignore]` or default filters;
- broad process-supervisor redesign.

## 3. Harness Design Requirements

Every corrected fixture must satisfy:

- unique resources per test invocation;
- no dependence on a pre-existing `/tmp` path, port, process, or global environment state;
- explicit readiness rather than fixed sleeps;
- bounded timeout with actionable diagnostics;
- cleanup on success, assertion failure, panic, and timeout where practical;
- no leaked child processes, sockets, files, or environment-variable mutations;
- compatibility with nextest parallel execution or explicit narrow serialization;
- deterministic failure when an unavoidable prerequisite is absent.

Prefer RAII guards, temporary directories, OS-assigned ports, and scoped environment restoration.

## 4. Workstream A — Application Handler Unix-Socket Fixture

### A1. Remove the undeclared external prerequisite

For `test_pool_creation`, determine whether the pool constructor is expected to connect eagerly or lazily.

If eager:

- create a temporary directory;
- bind a Unix listener at a unique path inside it;
- start the smallest viable test server or accept loop;
- wait for readiness through a channel or successful connect probe;
- construct the pool;
- assert the documented behavior;
- terminate the server and remove the socket through fixture teardown.

If lazy:

- avoid requiring a listener for construction;
- separately test connection failure and successful first use using controlled fixtures.

Do not use `/tmp/test.sock`, a fixed filename, or a sleep-based readiness assumption.

### A2. Required cases

Cover:

- pool creation with a live socket;
- missing socket returns the documented error at the documented stage;
- stale socket path is handled predictably;
- fixture cleanup permits immediate rerun;
- parallel test invocations do not collide.

## 5. Workstream B — Worker Crash-Recovery Fixture

### B1. Identify the actual boundary

Determine whether `test_worker_crash_recovery` is intended as:

- a unit/integration test of supervisor state transitions using an injected fake worker;
- an executable-level integration test against the built SynVoid binary;
- a specialist operational test requiring an external process environment.

Prefer dependency injection or a minimal purpose-built child executable when that accurately tests supervision. Avoid testing process discovery through unrelated system state.

### B2. Binary discovery

If a real workspace binary is required:

- use Cargo-provided test binary environment variables when available;
- otherwise define an explicit prebuild command and deterministic path;
- fail with a clear prerequisite message rather than timing out;
- do not search arbitrary processes with broad `pgrep` matching.

### B3. Process lifecycle

The fixture must:

- launch a child with a unique identifier;
- signal readiness explicitly;
- induce a controlled crash/exit;
- observe the supervisor recovery transition;
- assert restart count/backoff/state according to the public contract;
- terminate all descendants on teardown;
- bound the test below the documented specialist timeout.

Replace long fixed sleeps with controllable clocks, short configured backoff, or event-driven observation where the production API permits. Do not alter production defaults solely for the test.

### B4. Specialist fallback

If the test genuinely cannot be self-contained, move it to an explicit specialist command only after documenting:

- required binary/build step;
- required platform tools;
- required privileges;
- expected duration;
- deterministic preflight checks;
- reason it is excluded from `verify-full`.

Such a move requires a Phase 1 contract decision and must not hide an ordinary product regression.

## 6. Workstream C — Proxy Pipeline TLS/ALPN Fixture

### C1. Reproduce the setup panic independently

Run each of the five pipeline tests and identify whether they fail before product routing logic due to:

- empty or incompatible ALPN protocol list;
- mismatch between HTTP/1.1 and HTTP/2 client/server configuration;
- invalid certificate/SNI setup;
- rustls provider initialization;
- test server not reaching readiness;
- incorrect hyper-rustls builder sequence.

The fixture correction must reach the actual pipeline behavior under test.

### C2. Define transport modes explicitly

Create narrow helpers or parameters that clearly configure:

- HTTP/1.1 over TLS where required;
- HTTP/2 over TLS where required;
- expected ALPN identifiers;
- test certificate trust and server name;
- server-side protocol support.

Avoid a broad shared helper refactor unless all five tests truly use the same valid setup.

### C3. Required assertions

After fixture repair, each pipeline test must prove its original product behavior. Add a fixture-level smoke assertion only if needed to distinguish TLS setup failure from proxy logic failure.

Do not treat successful TLS connection as sufficient replacement for the pipeline assertions.

## 7. Workstream D — DashMap Concurrency Test

### D1. Determine harness versus product deadlock

Instrument the smallest reproducer for `test_dashmap_modify_in_place` and identify:

- locks/guards held across await points;
- nested access to the same shard while a mutable guard is live;
- runtime flavor and worker count;
- barrier/channel ordering;
- whether production code or only the test fixture performs the deadlocking sequence.

If production code can execute the same deadlock, reclassify the item as a Phase 2 product regression.

### D2. Correct fixture sequencing

If the defect is test-only:

- release guards before re-entering the map;
- use barriers/channels to coordinate exact phases;
- avoid scheduler-dependent sleeps;
- use a bounded timeout around the whole scenario for diagnostics;
- assert final map state and mutation count.

The corrected test should fail quickly on regression rather than hang until the global timeout.

### D3. Repetition evidence

Run the targeted test repeatedly outside CI to establish determinism. Five consecutive executions are sufficient for handoff unless Phase 1 identifies a rarer schedule-dependent condition. Do not add repeated execution to routine CI.

## 8. Timeout and Nextest Policy

Timeout changes are allowed only when:

- the fixture is otherwise deterministic;
- measured normal runtime justifies the bound;
- the timeout remains narrow to the affected test or test group;
- termination diagnostics identify the stuck phase;
- the change does not turn a hang into a long wait.

Review `.config/nextest.toml` after fixture repair. Remove obsolete special handling where the test no longer requires it. Do not create a broad `network-heavy` or `process-spawn` exemption as a substitute for fixture correctness.

## 9. Validation Sequence

For each repaired harness:

1. run the original failing test unchanged to confirm the failure mode;
2. correct setup/teardown or synchronization;
3. run the targeted test five consecutive times where practical;
4. run the complete owning test binary;
5. run the owning crate suite;
6. run the relevant tests under nextest with normal parallelism;
7. run `cargo xtask verify`;
8. record resource-cleanup checks and final duration.

Where platform-specific Unix sockets are involved, keep the correction scoped to the currently supported Linux/macOS behavior and use existing conditional compilation conventions. Do not add a cross-platform CI project.

## 10. Prohibited Shortcuts

Do not:

- add `#[ignore]`;
- exclude the test from `verify-full` by filter;
- replace a failure with a warning;
- use fixed ports or fixed `/tmp` socket names;
- rely on `pgrep` against a generic process name;
- insert large sleeps;
- increase all nextest timeouts;
- suppress ALPN or certificate validation globally;
- leak child processes after failure;
- call a production deadlock a fixture defect without tracing the same code path.

## 11. Acceptance Criteria

Phase 4 is complete only when:

- every Phase 1 `HARNESS_DEFECT` entry is repaired and passes its original product assertions;
- every `SPECIALIST_ENVIRONMENT` entry is either made self-contained or has an explicit command, deterministic preflight, and justified exclusion;
- `test_pool_creation` owns its socket lifecycle and has no fixed-path collision;
- worker crash recovery uses deterministic binary/process discovery, readiness, crash, observation, and cleanup;
- all proxy pipeline tests reach and validate product logic with valid TLS/ALPN setup;
- the DashMap test completes deterministically and a production deadlock has been ruled out or reclassified;
- targeted tests pass five consecutive local runs where practical;
- owning test binaries and crate suites pass;
- no leaked processes, sockets, or temporary files remain after execution;
- timeout changes are narrow and evidence-backed;
- `cargo xtask verify` passes;
- no new workflow, matrix, service container, VM, selector, or release automation is added;
- Phase 1 ledger rows include the repairing commit, final command, duration, and classification outcome.

## 12. Closure Evidence

Record for each fixture:

- original prerequisite or deadlock failure;
- root cause;
- resource/readiness model after correction;
- cleanup behavior;
- targeted repeated-run results;
- owning suite result;
- timeout or nextest configuration changes;
- confirmation that original product assertions remain intact.