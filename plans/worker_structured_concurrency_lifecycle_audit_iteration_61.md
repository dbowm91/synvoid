# Worker Structured Concurrency and Lifecycle Audit — Iteration 61

## Purpose

SynVoid’s accepted default data-plane model is one unified Tokio worker plus CPU offload workers. HTTP, HTTPS, HTTP/3, routing, proxying, mesh integration, health checks, feeds, persistence loops, and other background services therefore share one long-lived async process.

That architecture makes task ownership and shutdown behavior part of the reliability boundary. A detached or silently failed background task can leave one subsystem stale while the worker remains nominally healthy; an unjoined task can also make shutdown, reload, or supervisor restart behavior nondeterministic.

This pass should inventory long-lived tasks, define explicit ownership and cancellation contracts, and make worker shutdown bounded, observable, and testable.

The invariant is:

> Every long-lived task has an owner, a cancellation path, a join path, and an explicit failure policy.

## Current Known State

The repository uses `tokio::spawn`, `spawn_blocking`, threads, interval loops, broadcast shutdown channels, and subsystem-specific shutdown methods across:

- unified worker/server lifecycle;
- mesh transport and synchronization;
- threat-feed ingestion;
- block-store persistence;
- DNS and DNSSEC;
- auth/session cleanup;
- metrics and health monitoring;
- upstream health checks;
- tunnel/VPN/WireGuard/QUIC components;
- honeypot listeners;
- serverless execution;
- admin/WebSocket services;
- TCP/UDP listeners;
- CPU offload workers.

Task ownership and shutdown signaling appear decentralized. Some loops accept shutdown signals; others spawn and drop handles. The first pass should preserve behavior while establishing a common lifecycle model.

## Non-Goals

Do not rewrite every async subsystem in one iteration.

Do not centralize all tasks into one global task manager.

Do not change request-path semantics.

Do not alter blocklist, threat-intel, mesh-ID, or composition-root boundaries.

Do not replace Tokio.

Do not convert bounded per-request child tasks into long-lived service tasks unnecessarily.

Do not introduce unbounded graceful-shutdown waits.

Do not change supervisor restart policy unless task-failure findings require it.

## Phase 1 — Inventory All Spawn Sites

Search for:

- `tokio::spawn`
- `tokio::task::spawn`
- `spawn_blocking`
- `std::thread::spawn`
- `JoinHandle`
- `JoinSet`
- `broadcast::channel`
- `watch::channel`
- `CancellationToken`
- `interval(`
- `sleep(` inside loops
- `loop {`
- `shutdown_tx`
- `shutdown_rx`
- `stop_accepting`
- `abort()`

For each spawn/task, record:

- file/function;
- task name/responsibility;
- owner object or composition root;
- whether the handle is retained;
- cancellation mechanism;
- join mechanism;
- whether it is critical, restartable, bounded child work, CPU offload, or intentionally detached;
- behavior on panic or unexpected return;
- whether shutdown is bounded;
- persistence/flush requirements.

Create a canonical inventory document:

```text
architecture/worker_task_lifecycle.md
```

Suggested table:

| Task | File/function | Class | Owner | Cancel path | Join path | Failure policy | Notes |
|------|---------------|-------|-------|-------------|-----------|----------------|-------|

## Phase 2 — Define Task Classes

Use explicit task classes.

### CriticalService

Examples:

- listener accept loops;
- mesh transport core loop;
- supervisor/worker IPC loop;
- critical persistence writer where loss breaks correctness.

Policy:

- owner retains handle;
- unexpected exit or panic is surfaced immediately;
- worker/service may transition unhealthy or terminate;
- shutdown awaits completion with timeout.

### RestartableBackground

Examples:

- health checks;
- periodic metrics export;
- threat-feed refresh;
- cache cleanup;
- noncritical reconciliation.

Policy:

- owner retains handle or task-group membership;
- cancellation is explicit;
- unexpected exit is logged and optionally restarted with bounded backoff;
- restart policy is documented.

### BoundedChild

Examples:

- per-connection/request tasks;
- bounded dispatch helpers;
- short-lived async jobs.

Policy:

- may live in local `JoinSet`/connection task group;
- drained or aborted after timeout;
- must not outlive owning connection/service indefinitely.

### CpuOffload

Examples:

- compression/minification/image transforms/deep scans;
- blocking filesystem/CPU work.

Policy:

- bounded queue/concurrency;
- cancellation semantics documented;
- shutdown stops intake and drains or aborts after timeout.

### Detached

Allowed only for truly fire-and-forget work where result and lifetime do not affect correctness.

Policy:

- rare;
- explicitly documented with rationale;
- source guard should make detached spawn visible.

## Phase 3 — Define Worker-Level Lifecycle Primitive

Introduce a small worker-level ownership primitive, or adapt an existing one.

Possible shape:

```rust
pub struct WorkerTaskRegistry {
    cancellation: CancellationToken,
    critical: JoinSet<NamedTaskExit>,
    background: JoinSet<NamedTaskExit>,
}
```

Alternative acceptable shapes:

- `tokio_util::task::TaskTracker` plus `CancellationToken`;
- per-subsystem task groups registered with worker lifecycle;
- explicit retained `JoinHandle`s on service structs.

Required capabilities:

- register named task;
- classify task;
- obtain child cancellation token;
- observe unexpected exit/panic;
- initiate cancellation;
- join with bounded timeout;
- report timed-out/aborted tasks.

Avoid a single giant manager that knows subsystem internals. Subsystems may own local task groups and expose a common lifecycle contract.

## Phase 4 — Define Service Lifecycle Contract

For long-lived services, prefer an explicit contract such as:

```rust
#[async_trait]
pub trait ManagedService: Send + Sync {
    fn name(&self) -> &'static str;
    async fn shutdown(&self);
    async fn join(&self) -> Result<(), ServiceExitError>;
}
```

Or concrete methods:

```rust
impl ThreatFeedClient {
    pub async fn shutdown(&self);
    pub async fn join(&self) -> Result<(), ThreatFeedError>;
}
```

Required semantics:

- `shutdown()` is idempotent;
- `join()` can be called after shutdown;
- task exit reason distinguishes cancellation, clean completion, panic, and error;
- drop behavior is documented;
- no hidden long-lived task survives owner drop unless intentionally detached.

## Phase 5 — Prioritize High-Risk Long-Lived Tasks

Do not migrate every spawn at once. Prioritize:

1. Unified worker/server accept and control loops.
2. Supervisor/worker IPC loop.
3. Mesh transport/reconciliation loops.
4. Block-store persistence task.
5. Threat-feed background fetch loop.
6. Upstream health checks.
7. DNS background tasks.
8. Tunnel/VPN/WireGuard/QUIC health and runtime loops.
9. Metrics/prometheus/background exporters.

For each migrated task:

- retain handle;
- add cancellation select branch;
- name/log task identity;
- define panic/unexpected-exit behavior;
- integrate into shutdown sequence.

## Phase 6 — Threat Feed First Concrete Migration

`ThreatFeedClient::start_background_fetching()` is a useful first target.

Current concern:

- spawns an interval loop;
- handle is not visibly retained;
- no explicit cancellation/join API;
- unexpected exit is not surfaced to owner.

Recommended change:

- add cancellation token or shutdown receiver;
- store task handle in the client/service owner;
- make start idempotent or reject duplicate starts;
- expose `shutdown()` and `join()`;
- use `tokio::select!` between interval tick and cancellation;
- distinguish fetch errors from task-level failure;
- add tests for normal shutdown, duplicate start, and cancellation during sleep/fetch.

This should serve as the pattern for later background services.

## Phase 7 — Define Shutdown Ordering

Document and implement a bounded shutdown sequence.

Recommended order:

1. Stop accepting new external connections.
2. Signal request/connection draining.
3. Stop periodic producers and background refresh loops.
4. Stop mesh, synchronization, health-check, and feed loops.
5. Stop new CPU-offload submissions.
6. Drain bounded request/connection children.
7. Flush block-store and other persistent state.
8. Await critical service tasks.
9. Await background tasks.
10. Abort remaining tasks after timeout and report them.

Important constraints:

- persistent flush must happen after producers stop mutating state;
- request drain must be bounded;
- shutdown must not wait forever on a lost peer/socket;
- cancellation must be propagated before handles are awaited;
- task timeouts must be observable.

## Phase 8 — Failure and Panic Policy

Define behavior for task exits.

Critical task exits:

- log task name and exit cause;
- mark worker/service unhealthy;
- trigger coordinated shutdown or return fatal error to supervisor;
- do not silently restart unless explicitly designed.

Restartable background exits:

- log and increment metrics;
- optional bounded restart with exponential backoff/jitter;
- cap consecutive restart attempts;
- escalate to unhealthy state if retries are exhausted.

Panics:

- detect `JoinError::is_panic()`;
- record task identity;
- classify severity based on task class;
- avoid silently dropping panic results.

## Phase 9 — Partial Startup Failure

Audit startup paths where some tasks start before later initialization fails.

Required behavior:

- already-started tasks are cancelled;
- handles are joined or aborted within timeout;
- sockets/listeners are released;
- persistence tasks flush only if initialized safely;
- no orphan background loops survive failed initialization.

Add a startup guard pattern if useful:

```rust
let mut startup = StartupTaskGuard::new(...);
...
startup.commit();
```

or rely on registry drop/cancel behavior with explicit tests.

## Phase 10 — Observability

Add structured logs/metrics where existing telemetry supports it.

Suggested fields/counters:

- task name;
- task class;
- owner/service;
- started/stopped count;
- clean exits;
- unexpected exits;
- panics;
- restarts;
- shutdown timeout/abort count;
- shutdown duration;
- tasks remaining at timeout.

Do not create high-cardinality labels from dynamic request IDs.

## Phase 11 — Guardrails

Add a focused source guard:

```text
tests/background_task_ownership_guard.rs
```

Guardrail goals:

- flag obvious dropped long-lived `tokio::spawn(...)` handles in audited service modules;
- allow bounded per-request spawns only in explicit files/functions;
- require comments/allowlist for intentionally detached tasks;
- prevent new interval loops without cancellation select in audited modules;
- ensure critical services expose shutdown/join ownership.

Use a scoped allowlist and document reasons. Do not attempt to perfectly parse Rust.

Suggested first audited paths:

- `src/worker/unified_server/**`
- `src/server/**`
- `src/waf/threat_intel/feed_client.rs`
- `crates/synvoid-block-store/**`
- `crates/synvoid-mesh/**`
- `crates/synvoid-upstream/**`

## Phase 12 — Tests

Add focused tests.

### Registry/task-group tests

- named task starts and joins cleanly;
- cancellation propagates;
- panic is reported with task name;
- unexpected return is distinguished from cancellation;
- hung task is aborted after timeout;
- shutdown is idempotent.

### Threat-feed tests

- background loop stops on cancellation;
- join completes after shutdown;
- duplicate start is rejected or idempotent;
- fetch failure does not kill the task unexpectedly unless configured;
- owner drop behavior is explicit.

### Worker lifecycle tests

- stop-accepting occurs before task cancellation;
- producers stop before persistence flush;
- persistent flush completes before final join;
- partial startup failure cancels already-started tasks;
- shutdown completes within configured deadline;
- critical task panic initiates unhealthy/fatal path.

### Regression tests

- existing data-plane composition guard passes;
- blocklist snapshot/provenance tests pass;
- threat-intel actionability guards pass;
- mesh-ID boundary guard passes.

## Phase 13 — Documentation

Create/update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `architecture/worker_data_plane_composition_root.md`
- `AGENTS.md`
- worker `AGENTS.override.md`
- subsystem skill docs where lifecycle contracts change

Docs must state:

- task classes;
- owner/cancellation/join requirements;
- worker shutdown ordering;
- critical versus restartable failure policy;
- detached-task policy;
- partial-startup rollback behavior;
- how to add a new long-lived task safely.

## Phase 14 — Verification Commands

Run focused checks:

```bash
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test -p synvoid-block-store --lib
cargo test -p synvoid-mesh --lib
cargo test -p synvoid-upstream --lib
cargo test --lib --no-run
```

If common task lifecycle types or service signatures change:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This pass is complete when:

1. Long-lived tasks are inventoried and classified.
2. Every migrated long-lived task has a named owner.
3. Every migrated task has explicit cancellation and join behavior.
4. Critical task exits/panics are observable and cannot fail silently.
5. Worker shutdown ordering is documented and implemented for audited services.
6. Shutdown completion is bounded by timeout.
7. Persistence flush occurs after state-producing background tasks stop.
8. Partial startup failure cleans up already-started tasks.
9. Threat-feed background fetching is no longer an unowned detached loop.
10. A source guard prevents new unowned long-lived tasks in audited paths.
11. Existing request-path, blocklist, threat-intel, and mesh-ID boundaries remain intact.
12. Documentation explains how to add and own new background tasks.

## Notes for the Implementer

This should be an incremental structured-concurrency pass, not a total async rewrite.

Start with the worker lifecycle primitive and a few high-risk services. Establish the pattern, tests, and guardrails first; migrate lower-risk subsystems in later iterations.
