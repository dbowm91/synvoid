# Mesh Transport Startup/Shutdown Corrective Pass — Iteration 70

## Purpose

Iterations 68–69 established the core mesh lifecycle architecture: mesh-local task ownership, direct `MeshTaskExit` return values, stable exit publication, cancellation-aware periodic loops, peer-session ownership, lifecycle state tracking, and bounded shutdown APIs.

The remaining defects are now concentrated in startup rollback and shutdown finalization:

1. Several post-spawn startup failures still return through `?` without invoking rollback.
2. Lifecycle transition to `Running` occurs before the staged task group is fully committed to transport ownership.
3. Startup rollback only stops tasks; it does not unwind peer connections, topology entries, or staged runtime resources created during the attempt.
4. `MeshStartupPolicy` and `MeshStartupReport` exist but are not wired into startup behavior.
5. Peer-session shutdown uses a fresh timeout per session, can exceed the caller’s shutdown budget, and aborts without awaiting all aborted sessions.
6. Handshake-child drain/abort counts are not propagated into `MeshShutdownReport`.
7. Worker mesh supervision is documented but not active in the current unified-worker supervision loop.
8. `ManagedMeshService::is_running()` uses `blocking_lock()` over an async mutex.
9. `MeshTaskId` is only unique within one task-group generation while the stable exit channel spans generations.

This pass should make startup and shutdown guarantees mechanically true, clarify deferred worker integration, and close the remaining reporting and lifecycle-state inconsistencies.

The invariant is:

> After the first mesh task is spawned, every failure must flow through rollback; after shutdown returns, every mesh-owned task and peer session must be terminated and accounted for within one bounded deadline.

## Current Known State

At `f36186974c6fbac3196748b1c1d17a20cf00e43e`:

- `MeshTaskGroup` handles return `MeshTaskExit` directly.
- pre-shutdown critical/background completion becomes `UnexpectedCompletion`.
- stable `mesh_exit_tx` survives task-group replacement.
- `peer_message_loop` is stored in a transport-owned `JoinSet`.
- `shutdown_with_timeout()` closes peers, joins top-level tasks, and drains peer sessions.
- failure-injection hooks exist for six startup phases.

Known remaining defects:

- `AfterCriticalTasks`, `DuringSeedBootstrap`, `DuringPeerConnect`, and `DuringDhtBootstrap` hook failures use `?` after critical tasks have already spawned.
- transition to `Running` uses `?` without rollback.
- task group is stored after lifecycle state becomes `Running`.
- rollback does not undo attempt-created peer/topology/runtime state.
- startup policy/report types are unused by `start()`.
- peer-session draining uses repeated fixed five-second timeouts rather than one shared deadline.
- `abort_all()` is not followed by joining all aborted peer sessions.
- aborted peer-session counts are incomplete.
- handshake child counts never reach the final report.
- production worker supervision does not consume mesh exit events.

## Non-Goals

Do not redesign mesh protocol semantics.

Do not alter DHT/Raft consistency boundaries.

Do not change peer authentication, TLS identity, threat-intel, blocklist, or membership rules.

Do not add task restart policies.

Do not migrate unrelated worker tasks.

Do not add new transport protocols.

## Phase 1 — Define The Startup Attempt Boundary

Introduce an explicit staged-startup object that owns every task and resource created by one attempt.

Suggested shape:

```rust
struct MeshStartupStage {
    task_group: MeshTaskGroup,
    created_peer_sessions: Vec<String>,
    created_peer_nodes: Vec<String>,
    runtime_started: bool,
    committed: bool,
}
```

Add fields only for resources actually created during startup.

Required semantics:

- the stage is created before the first task spawn;
- every post-spawn phase mutates only staged state or records what it created;
- no staged task group can be dropped without explicit rollback or commit;
- commit transfers ownership to `MeshTransport` exactly once;
- rollback can be invoked from every fallible post-spawn path.

Do not rely on async cleanup in `Drop`.

## Phase 2 — Route Every Post-Spawn Error Through One Funnel

Refactor `start()` so every operation after the first task spawn is wrapped in one staged result.

Suggested structure:

```rust
pub async fn start_with_policy(
    &self,
    policy: MeshStartupPolicy,
) -> Result<MeshStartupReport, MeshTransportError> {
    self.transition_to_starting().await?;
    let mut stage = self.create_startup_stage();

    match self.run_startup_phases(&mut stage, &policy).await {
        Ok(report) => self.commit_startup(stage, report).await,
        Err(error) => {
            let rollback = self.rollback_startup(&mut stage).await;
            self.finish_failed_startup().await;
            Err(error.with_rollback(rollback))
        }
    }
}
```

At minimum, these failures must enter the funnel:

- `AfterCriticalTasks` hook;
- seed-bootstrap hook and required seed failure;
- configured-peer hook and required peer failure;
- DHT hook and required DHT failure;
- runtime server startup failure;
- accept-loop registration failure;
- lifecycle commit failure;
- post-commit test hook failure.

No post-spawn `?` may directly leave `start()`.

## Phase 3 — Preserve A Compatibility `start()` API

If callers currently require:

```rust
start() -> Result<(), MeshTransportError>
```

retain it as:

```rust
pub async fn start(&self) -> Result<(), MeshTransportError> {
    self.start_with_policy(self.default_startup_policy())
        .await
        .map(|_| ())
}
```

Expose the report-capable API separately:

```rust
pub async fn start_with_policy(
    &self,
    policy: MeshStartupPolicy,
) -> Result<MeshStartupReport, MeshTransportError>;
```

Do not leave `MeshStartupPolicy` and `MeshStartupReport` as documentary-only types.

## Phase 4 — Implement Required Versus Optional Bootstrap Behavior

Wire policy into each bootstrap phase.

### Seed Bootstrap

On failure:

- `require_seed_connectivity == true` -> fatal error and rollback;
- otherwise append degraded reason and continue.

Record actual number of successful seed connections.

### Configured Peers

On failure:

- `require_configured_peers == true` -> fatal error and rollback;
- otherwise append degraded reason and continue.

Record number of successfully connected configured peers.

### DHT Bootstrap

On failure:

- `require_dht_bootstrap == true` -> fatal error and rollback;
- otherwise append degraded reason and continue.

Record `dht_bootstrapped` accurately.

Do not infer success only from absence of an error if zero work occurred; distinguish “not configured,” “not required,” and “attempted successfully” where useful.

## Phase 5 — Make Startup Commit Race-Safe

Current ordering exposes `Running` before the new task group is stored.

Required commit order:

1. All fallible startup phases complete.
2. Staged runtime/listener handles are ready.
3. Acquire lifecycle/ownership commit locks in one documented order.
4. Transfer staged task group into `self.task_group`.
5. Store other staged runtime resources.
6. Transition lifecycle state from `Starting` to `Running`.
7. Publish running/degraded health state.
8. Mark stage committed.
9. Return `MeshStartupReport`.

A concurrent shutdown must not observe `Running` while still owning the previous task group.

Recommended: serialize start/stop transitions with one lifecycle operation mutex or generation token.

## Phase 6 — Add A Lifecycle Operation Lock

Prevent concurrent `start()` and `shutdown_with_timeout()` from interleaving commit/teardown.

Suggested field:

```rust
lifecycle_op: tokio::sync::Mutex<()>
```

Both start and shutdown acquire it for the full transition operation.

This lock should protect lifecycle orchestration, not every steady-state mesh operation.

Required properties:

- only one startup or shutdown transition occurs at a time;
- shutdown cannot consume an old group while startup later stores a new group;
- repeated start/shutdown calls return deterministic lifecycle conflicts or idempotent results.

## Phase 7 — Roll Back Attempt-Created Peer State

Track resources created by the startup attempt.

For every outbound peer established during startup, record:

- session ID;
- peer/node ID;
- topology entry created or modified;
- connection handle if needed.

Rollback should:

1. close attempt-created QUIC connections;
2. remove attempt-created entries from `peer_connections`;
3. remove or restore attempt-created topology entries;
4. cancel/join any peer sessions created by the attempt;
5. clear attempt-specific pending bootstrap state.

Do not indiscriminately clear peers that predated the startup attempt unless the transport contract guarantees no pre-existing peers in `Stopped`/`Failed` state.

## Phase 8 — Roll Back Runtime And Listener Resources

If `runtime.start_server()` or related setup creates resources before failure, rollback must actively stop them.

Audit the runtime API for:

- stop accepting;
- shutdown listener;
- close endpoint;
- release bound socket.

Add a staged-runtime cleanup method if needed.

Required test:

- fail after runtime bind/start;
- rollback completes;
- a subsequent startup can bind the same endpoint successfully.

## Phase 9 — Define Failed Versus Stopped After Rollback

Current rollback leaves lifecycle state at `Failed`, while documentation also suggests returning to `Stopped`.

Choose one explicit policy.

Recommended:

- transition to `Failed` while rollback is in progress or if rollback itself is incomplete;
- transition to `Stopped` after successful complete rollback;
- remain `Failed` only when cleanup could not be completed safely.

Expose rollback status in the returned error/report.

This makes retry semantics meaningful:

- `Stopped` -> safe retry;
- `Failed` -> operator intervention or explicit recovery required.

## Phase 10 — Enrich Startup Errors With Rollback Diagnostics

Add an error shape capable of preserving the original startup error and cleanup failures.

Suggested:

```rust
MeshTransportError::StartupRollbackFailed {
    startup_error: String,
    rollback_errors: Vec<String>,
}
```

or a structured report attached to the error.

Do not replace the original startup failure with a generic rollback error.

## Phase 11 — Make Failure-Injection Tests Truly Behavioral

Rewrite `tests/mesh_startup_rollback.rs` so tests invoke real `MeshTransport::start()` or `start_with_policy()`.

Required instrumentation:

- atomic counters or drop guards inside spawned critical/background loops;
- deterministic runtime/bootstrap test doubles;
- lifecycle state inspection;
- peer/topology state inspection;
- retry after rollback.

Required scenarios:

### Failure After Critical Tasks

- trigger `AfterCriticalTasks`;
- `start()` returns error;
- spawned tasks terminate;
- counters stop changing;
- lifecycle is `Stopped` after successful rollback;
- task group is empty;
- retry succeeds.

### Failure During Seed/Peer/DHT Phases

- required mode -> rollback and error;
- optional mode -> startup report contains degraded reason and startup succeeds.

### Runtime Start Failure

- all previously spawned tasks terminate;
- runtime/listener resources are released;
- retry succeeds.

### Lifecycle Commit Failure

- stored/staged group is rolled back;
- service never becomes externally visible as running.

### Rollback Failure

- lifecycle remains `Failed`;
- error preserves startup and rollback details.

## Phase 12 — Use One Shared Shutdown Deadline

`shutdown_with_timeout(timeout)` must define one total mesh shutdown budget.

Set:

```rust
let deadline = Instant::now() + timeout;
```

All shutdown phases consume the same deadline:

- top-level task join;
- handshake child drain;
- peer-session drain;
- runtime/listener shutdown;
- final cleanup.

Do not apply a fresh fixed timeout per task/session.

Provide a helper:

```rust
fn remaining(deadline: Instant) -> Duration
```

## Phase 13 — Abort And Await All Peer Sessions

Refactor peer-session shutdown.

Required algorithm:

1. Close all peer connections.
2. Drain completed sessions until the shared deadline.
3. If deadline expires:
   - capture `remaining = sessions.len()`;
   - call `abort_all()`;
   - continue `join_next()` until the set is empty;
   - count each aborted/cancelled session.
4. Do not drop the `JoinSet` while tasks remain.

Required report semantics:

- `drained_peer_sessions`: sessions that completed without forced abort during shutdown;
- `aborted_peer_sessions`: sessions still active at deadline and forcibly aborted;
- counts must sum to sessions present at shutdown start, accounting for sessions that completed concurrently.

## Phase 14 — Return Structured Accept-Loop Completion Data

The accept loop currently returns `()` and loses handshake drain metrics.

Introduce:

```rust
pub struct MeshAcceptLoopReport {
    pub drained_handshakes: usize,
    pub aborted_handshakes: usize,
    pub rejected_at_capacity: usize,
}
```

Make the accept-loop task return this report through a result-aware task handle or a dedicated completion channel.

Possible approach:

```rust
spawn_critical_value("mesh_accept_loop", async move -> Result<MeshAcceptLoopReport, E> { ... })
```

If generalizing `MeshTaskGroup` to arbitrary output is too invasive, store the report in an owned oneshot/shared result slot whose sender is owned by the accept-loop task.

The final `MeshShutdownReport` must populate:

- `drained_peer_children`;
- `aborted_peer_children`.

## Phase 15 — Keep Task Exit And Service Report Separate

`MeshTaskExit` describes why a task ended; `MeshAcceptLoopReport` describes internal child drainage.

Do not overload `MeshTaskExitReason` with child metrics.

Use a task-specific report channel or structured task output plus exit metadata.

## Phase 16 — Fix `ManagedMeshService::is_running()`

Do not use `blocking_lock()` on a Tokio mutex from a synchronous trait method.

Choose one:

### Preferred

Make the trait method async:

```rust
async fn is_running(&self) -> bool;
```

### Alternative

Maintain an atomic lifecycle projection:

```rust
running_projection: AtomicBool
```

updated only by lifecycle transition helpers.

### Alternative

Use a synchronous lock for the small lifecycle enum if async locking is unnecessary.

Whichever is chosen, keep one authoritative state machine and test for no divergence.

## Phase 17 — Make Task IDs Unique Across Generations

The stable exit channel spans task-group replacements, so per-group IDs can collide.

Add a transport-level ID allocator:

```rust
mesh_task_id_seq: Arc<AtomicU64>
```

Pass it into each new `MeshTaskGroup`.

Alternative:

```rust
MeshTaskId {
    generation: u64,
    sequence: u64,
}
```

Required property:

- no two events on the stable transport exit channel share the same ID during process lifetime.

Update documentation and dedup tests.

## Phase 18 — Decide Worker Supervision Scope Explicitly

The production worker currently does not consume mesh exits.

Choose one of two honest outcomes.

### Outcome A — Wire It Now

If the worker currently constructs/owns the mesh service:

1. subscribe before mesh startup;
2. select mesh exits alongside registry and lifecycle channels;
3. map fatal exits to `WorkerShutdownCause::MeshServiceExit`;
4. ignore expected/nonfatal exits;
5. call mesh shutdown before final supervisor acknowledgement.

### Outcome B — Explicit Deferral

If mesh control-plane construction is intentionally disabled:

- remove claims that worker integration is active;
- mark `MeshServiceExit` and trait wiring as staged infrastructure;
- add a guard/test ensuring the future integration point subscribes before start;
- record the exact feature/architecture condition that re-enables it.

Do not leave documentation implying active supervision when no runtime branch exists.

## Phase 19 — Correct Documentation Around Startup Policy

Update docs to reflect actual API and defaults.

Document:

- whether `start()` uses a default policy;
- role-specific defaults;
- what degraded startup means operationally;
- how degraded health is surfaced;
- when a startup failure rolls back to `Stopped` versus remains `Failed`.

Do not claim that policy is active until production startup consumes it.

## Phase 20 — Strengthen Guardrails

Update `tests/mesh_task_ownership_guard.rs`.

Add checks that:

- no post-spawn failure hook uses direct `?` without rollback funnel;
- lifecycle transition failure after task creation enters rollback;
- task group is stored before `Running` becomes visible;
- startup and shutdown share a lifecycle operation lock;
- peer-session `abort_all()` is followed by draining the `JoinSet`;
- peer-session shutdown uses the caller’s shared deadline;
- accept-loop child counts reach `MeshShutdownReport`;
- `blocking_lock()` is not used for `is_running()`;
- task IDs are transport-global or generation-qualified;
- documentation accurately marks worker integration active or deferred.

## Phase 21 — Shutdown Report Tests

Add behavioral tests for report accuracy.

Required scenarios:

- zero active peers/sessions -> all counts zero;
- N sessions drain cleanly -> `drained_peer_sessions == N`;
- N sessions hang -> `aborted_peer_sessions == N` and all are joined;
- mixed sessions -> exact drained/aborted split;
- handshake children drain/abort -> exact child counts;
- `remaining_peers == 0` after clean shutdown;
- total shutdown duration does not materially exceed caller timeout plus abort-join cleanup margin.

## Phase 22 — Concurrency Tests

Add tests for start/stop races.

Scenarios:

- shutdown begins while startup is before commit;
- shutdown begins while task group is being committed;
- duplicate concurrent start calls;
- start after complete shutdown;
- retry after successful rollback;
- retry rejected after incomplete rollback/`Failed` state.

Assert no task group replacement occurs after shutdown has taken ownership.

## Phase 23 — Suggested Implementation Sequence

Implement in this order:

1. Add lifecycle operation lock.
2. Introduce `MeshStartupStage` and one rollback funnel.
3. Route every post-spawn failure through rollback.
4. Track and clean attempt-created peer/runtime resources.
5. Wire startup policy/report into production API.
6. Fix commit ordering.
7. Replace peer-session timeout loop with shared deadline and abort-and-await.
8. Add accept-loop report propagation.
9. Fix sync `is_running()` access.
10. Make task IDs globally unique across generations.
11. Wire worker supervision or explicitly document deferral.
12. Add behavioral tests, guardrails, and docs.

## Phase 24 — Verification Commands

Run:

```bash
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh task_group
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh shutdown
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
```

If worker runtime integration is enabled or lifecycle trait signatures change:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This iteration is complete when:

1. Every failure after the first mesh task spawn enters rollback.
2. Failure-injection tests invoke real startup and prove all staged tasks stop.
3. Lifecycle cannot remain `Starting` after a failed startup.
4. A fully rolled-back attempt returns to `Stopped`; incomplete rollback remains `Failed`.
5. Attempt-created peer/topology/runtime resources are removed during rollback.
6. Task group ownership is committed before `Running` becomes externally visible.
7. Concurrent start/shutdown cannot swap in a live group after shutdown begins.
8. `MeshStartupPolicy` changes real startup behavior.
9. `MeshStartupReport` reflects degraded and successful bootstrap outcomes.
10. Peer-session shutdown uses one shared deadline.
11. Every aborted peer session is awaited and accurately counted.
12. Handshake child drain/abort counts populate `MeshShutdownReport`.
13. `is_running()` no longer uses `blocking_lock()` on a Tokio mutex.
14. Mesh task IDs are unique across task-group generations.
15. Worker supervision is either actively wired or explicitly and accurately deferred.
16. No mesh-owned task survives failed startup or completed shutdown.
17. Existing blocklist, threat-intel, provenance, mesh-ID, composition, and worker lifecycle guardrails remain green.

## Notes for the Implementer

This is a correctness pass, not a mesh feature pass.

The first priority is the post-spawn error funnel. Until every such failure invokes rollback, the lifecycle guarantees remain incomplete regardless of the presence of failure-injection hooks or task ownership primitives.
