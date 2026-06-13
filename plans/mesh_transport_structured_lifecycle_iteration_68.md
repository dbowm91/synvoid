# Mesh Transport Structured Lifecycle and Partial-Startup Rollback — Iteration 68

## Purpose

The worker-level structured-concurrency track is now stable enough to host managed subsystems. The next highest-risk area is `MeshTransport`, which currently starts a dense set of critical and periodic tasks with dropped `JoinHandle`s, inconsistent cancellation, and no transactional rollback when later startup stages fail.

This pass should make `MeshTransport` own its runtime, expose a bounded lifecycle contract to the worker composition root, and ensure no mesh task survives failed startup or completed shutdown.

The invariant is:

> Every mesh task has an owner, every long-lived loop has cancellation, startup either commits fully or rolls back fully, and shutdown does not return while mesh-owned tasks are still running.

## Current Known State

`MeshTransport::start()` currently:

- sets `running = true` near the beginning;
- creates a broadcast shutdown channel;
- starts global-node self-attestation;
- starts PoW nonce refresh for edge nodes;
- starts ML-KEM key rotation;
- starts mesh maintenance;
- starts datagram listener;
- bootstraps seeds;
- connects configured peers;
- bootstraps DHT;
- starts peer connection maintenance;
- starts peer health checks;
- starts proactive cache warming;
- starts DHT cache resync;
- starts load reporting;
- starts global-node heartbeat;
- starts the QUIC accept loop;
- spawns detached per-peer connection children inside the accept loop.

Several loops have no shutdown branch. Several critical tasks have dropped handles. Startup can fail after tasks have already started, leaving partial runtime state alive.

## Non-Goals

Do not redesign mesh protocol semantics.

Do not change DHT/Raft responsibility boundaries.

Do not alter peer authentication, blocklist, threat-intel, or membership semantics.

Do not move mesh internal tasks into the worker’s `WorkerTaskRegistry` individually.

Do not add automatic restart for every background task in this iteration.

Do not rewrite QUIC transport internals.

Do not change request-path behavior.

## Phase 1 — Inventory Mesh Runtime Tasks

Create or update a canonical mesh lifecycle inventory.

Suggested document:

```text
architecture/mesh_transport_lifecycle.md
```

Inventory every task started by:

- `MeshTransport::start()`;
- threat-intel background startup;
- discovery/bootstrap helpers;
- QUIC accept loop;
- per-peer connection handling;
- maintenance/reconciliation helpers.

For each task record:

- task name;
- file/function;
- class;
- owner;
- current cancellation path;
- current join path;
- startup dependency;
- failure policy;
- whether it must drain children;
- whether it mutates persistent/shared state.

Use these classes:

- `CriticalService`
- `RestartableBackground`
- `BoundedChild`
- `OneShotStartup`

Initial expected classification:

### CriticalService

- mesh maintenance loop;
- datagram listener;
- QUIC accept loop;
- any core dispatch loop required for mesh availability.

### RestartableBackground

- PoW nonce refresh;
- ML-KEM key rotation;
- peer connection maintenance;
- peer health checks;
- proactive cache warming;
- DHT cache resync;
- load reporting;
- global-node heartbeat;
- threat-intel synchronization loops.

### BoundedChild

- incoming peer handshake/connection setup tasks;
- bounded peer-specific maintenance tasks.

### OneShotStartup

- global-node self-attestation;
- seed bootstrap;
- explicit peer connection setup;
- DHT bootstrap.

## Phase 2 — Introduce A Mesh-Local Task Group

Add an internal mesh lifecycle primitive owned by `MeshTransport`.

Suggested shape:

```rust
pub struct MeshTaskGroup {
    shutdown_tx: watch::Sender<bool>,
    critical: JoinSet<MeshTaskExit>,
    background: JoinSet<MeshTaskExit>,
    children: JoinSet<MeshTaskExit>,
    shutdown_started: AtomicBool,
}
```

Acceptable alternatives:

- retained `JoinHandle`s grouped by class;
- `TaskTracker` plus cancellation token;
- separate task-group structs for transport and peer children.

Required capabilities:

- spawn named critical task;
- spawn named background task;
- spawn bounded child task;
- obtain child cancellation receiver/token;
- begin shutdown;
- observe unexpected critical exit;
- join with bounded timeout;
- abort and await timed-out tasks;
- report task exit details.

The mesh crate should remain self-contained. The worker should manage `MeshTransport` as one service, not own its internal tasks individually.

## Phase 3 — Define Mesh Task Exit Types

Introduce explicit exit metadata.

Suggested shape:

```rust
pub enum MeshTaskClass {
    CriticalService,
    RestartableBackground,
    BoundedChild,
    OneShotStartup,
}

pub enum MeshTaskExitReason {
    CleanCompletion,
    Cancelled,
    UnexpectedCompletion,
    Error(String),
    Panic(String),
    Aborted,
}

pub struct MeshTaskExit {
    pub name: &'static str,
    pub class: MeshTaskClass,
    pub reason: MeshTaskExitReason,
}
```

Required semantics:

- critical pre-shutdown completion is abnormal;
- background pre-shutdown completion is observable but not automatically fatal;
- post-shutdown completion is expected;
- panic/error detail is retained;
- timed-out tasks are explicitly aborted and awaited.

## Phase 4 — Make Startup Transactional

Refactor `MeshTransport::start()` into explicit prepare/start/commit phases.

Recommended ordering:

1. Acquire startup guard and verify not already running.
2. Validate configuration and required runtime handles.
3. Create a fresh task group and shutdown state.
4. Start only the minimum listener/runtime required for bootstrap.
5. Perform seed bootstrap.
6. Connect configured peers.
7. Perform DHT bootstrap.
8. Start critical transport loops.
9. Start periodic background loops.
10. Start one-shot self-attestation if applicable.
11. Commit lifecycle state.
12. Set `running = true` only after required startup succeeds.

If any phase fails:

- record the startup error;
- begin cancellation;
- join/abort all tasks started during the attempt;
- close listener/runtime resources;
- clear shutdown/task-group state;
- ensure `running = false`;
- return the original startup error plus rollback diagnostics if needed.

Do not leave `running = true` on failure.

## Phase 5 — Add A Startup Guard

Introduce a guard to prevent orphaned partial startup.

Suggested shape:

```rust
struct MeshStartupGuard<'a> {
    transport: &'a MeshTransport,
    committed: bool,
}
```

or an owned staging state:

```rust
struct MeshStartupState {
    task_group: MeshTaskGroup,
    listener_started: bool,
    runtime_started: bool,
}
```

Required behavior:

- uncommitted startup state rolls back;
- commit happens once;
- rollback is bounded;
- duplicate `start()` calls are idempotent or explicitly rejected.

Recommended policy:

- already running -> return `Ok(())` only if runtime state is healthy;
- starting/stopping -> return a typed lifecycle error;
- failed prior startup -> allow clean retry after rollback.

## Phase 6 — Convert All Periodic Loops To Cancellation-Aware Tasks

Every interval loop must select between work and shutdown.

Required conversions:

- PoW nonce refresh;
- ML-KEM key rotation;
- peer connection maintenance;
- peer health checking;
- proactive cache warming;
- DHT cache resync;
- load reporting;
- global-node heartbeat;
- threat-intel mesh synchronization loops in scope.

Preferred pattern:

```rust
loop {
    tokio::select! {
        _ = interval.tick() => {
            run_iteration().await;
        }
        _ = shutdown.changed() => {
            if *shutdown.borrow() {
                break;
            }
        }
    }
}
```

Required semantics:

- cancellation does not wait for the next interval tick;
- in-progress async iteration is either allowed to finish or explicitly cancellable;
- final cleanup is documented per task;
- no loop relies only on dropping an `Arc`.

## Phase 7 — Own Critical Mesh Loops

Register and retain handles for:

- mesh maintenance loop;
- datagram listener loop;
- QUIC accept loop.

Required behavior:

- unexpected critical exit is sent to a mesh supervision channel;
- mesh service transitions unhealthy;
- worker can observe the fatal mesh exit;
- normal shutdown completion is not classified as failure;
- panic detail is preserved.

Add:

```rust
pub fn subscribe_exits(&self) -> broadcast::Receiver<MeshTaskExit>
```

or a narrower critical-exit receiver.

## Phase 8 — Bound Incoming Peer Children

Refactor `mesh_accept_loop()` so per-peer tasks are owned.

Current pattern:

```rust
tokio::spawn(async move {
    transport.handle_incoming_peer_connection(incoming_conn).await
});
```

Required model:

- accepted connection children enter a `JoinSet` or bounded child group;
- child count is bounded by configured concurrency;
- accepting pauses or rejects when capacity is exhausted;
- shutdown stops new accepts;
- active handshakes receive cancellation where possible;
- children drain up to timeout;
- remaining children are aborted and awaited.

Add metrics/logging for:

- active peer children;
- rejected/over-capacity connections;
- handshake failures;
- shutdown-aborted children.

## Phase 9 — Define Peer Handshake Cancellation

Audit blocking points in `handle_incoming_peer_connection()`:

- `accept_bi()`;
- length read;
- hello payload read;
- authentication/validation;
- downstream connection registration.

Wrap network reads with bounded timeouts where not already bounded.

Required protections:

- max handshake duration;
- max hello size remains enforced;
- cancellation can interrupt waiting on peer input;
- shutdown does not wait indefinitely for silent peers.

Suggested config:

```rust
pub struct MeshHandshakeLimits {
    pub accept_stream_timeout: Duration,
    pub hello_read_timeout: Duration,
    pub total_handshake_timeout: Duration,
    pub max_concurrent_handshakes: usize,
}
```

Reuse existing config if equivalent fields exist.

## Phase 10 — Define One Authoritative Shutdown API

Add a bounded shutdown contract.

Suggested API:

```rust
pub async fn shutdown(
    &self,
    timeout: Duration,
) -> Result<MeshShutdownReport, MeshTransportError>;
```

Suggested report:

```rust
pub struct MeshShutdownReport {
    pub clean_tasks: usize,
    pub failed_tasks: Vec<MeshTaskExit>,
    pub aborted_tasks: Vec<MeshTaskExit>,
    pub drained_peer_children: usize,
    pub aborted_peer_children: usize,
    pub remaining_peers: usize,
}
```

Required ordering:

1. Mark shutdown intent.
2. Stop accepting new peers.
3. Signal periodic/maintenance tasks.
4. Stop datagram/listener loops.
5. Drain peer children.
6. Close active peer connections as appropriate.
7. Await critical tasks.
8. Await background tasks.
9. Abort and await remnants.
10. Clear lifecycle state.
11. Set `running = false`.

Shutdown must be:

- idempotent;
- bounded;
- safe after partial startup;
- safe after critical task failure.

## Phase 11 — Define Start/Stop State Machine

Replace the boolean-only lifecycle model with explicit state if necessary.

Suggested enum:

```rust
pub enum MeshLifecycleState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}
```

Required transitions:

```text
Stopped -> Starting -> Running
Starting -> Failed -> Stopped (after rollback)
Running -> Stopping -> Stopped
Running -> Failed -> Stopping/Stopped
```

Reject invalid concurrent transitions.

Do not allow two concurrent `start()` calls to create duplicate loops.

## Phase 12 — Partial Startup Rollback Tests

Add deterministic failure injection around startup phases.

Required scenarios:

- seed bootstrap fails after listeners/tasks start;
- explicit peer connection fails;
- DHT bootstrap fails;
- runtime server start fails;
- one critical task panics during startup;
- self-attestation task fails after startup commit.

For each failure:

- `start()` returns error;
- `running == false` after rollback;
- task group is empty;
- no periodic counter continues changing;
- listener/runtime resources are released;
- a subsequent clean `start()` can succeed where supported.

Use test hooks or trait-injected bootstrap/runtime components rather than network flakiness.

## Phase 13 — Shutdown Tests

Required scenarios:

### Normal Shutdown

- all critical/background tasks receive cancellation;
- all handles join;
- report contains no aborted tasks;
- `running == false`.

### Hung Periodic Task

- task ignores cancellation or blocks;
- timeout expires;
- task is explicitly aborted and awaited;
- report records abort.

### Hung Peer Handshake

- child waits on peer input;
- shutdown timeout cancels/aborts it;
- no child remains.

### Critical Task Panic

- panic is surfaced immediately;
- mesh service becomes unhealthy;
- worker receives fatal mesh exit;
- shutdown still cleans remaining tasks.

### Repeated Shutdown

- second shutdown is safe and returns an empty/already-stopped report.

### Repeated Start

- concurrent or duplicate start does not create duplicate loops.

## Phase 14 — Worker Composition-Root Integration

Integrate `MeshTransport` as one managed service.

Preferred worker-facing contract:

```rust
pub trait ManagedMeshService {
    fn subscribe_critical_exits(&self) -> broadcast::Receiver<MeshTaskExit>;
    async fn shutdown(&self, timeout: Duration) -> MeshShutdownReport;
}
```

Worker responsibilities:

- own the concrete `Arc<MeshTransport>`;
- subscribe before mesh startup where possible;
- treat unexpected critical mesh exit as a fatal worker cause;
- call mesh shutdown during coordinated worker teardown;
- await mesh completion before final worker acknowledgement.

Do not expose internal mesh task handles to the worker.

## Phase 15 — Map Mesh Failure Into Worker Shutdown Cause

Add a worker-level cause if useful:

```rust
WorkerShutdownCause::MeshServiceExit(MeshTaskExit)
```

or map to:

```rust
CriticalTaskExit(NamedTaskExit)
```

Preferred: a typed mesh-service cause if it improves diagnostics without coupling crates excessively.

Supervisor error should include:

- mesh task name;
- exit reason;
- whether transport rollback/shutdown succeeded.

## Phase 16 — Observability

Add mesh lifecycle metrics/logs:

- lifecycle state;
- task counts by class;
- critical exits;
- background exits;
- task panics;
- task aborts;
- startup rollback count;
- startup rollback duration;
- shutdown duration;
- active peer children;
- handshake timeouts;
- shutdown-aborted handshakes.

Avoid peer-ID labels with unbounded cardinality.

## Phase 17 — Guardrails

Add:

```text
tests/mesh_task_ownership_guard.rs
```

Guardrail goals:

- no unowned long-lived `tokio::spawn()` in audited mesh runtime files;
- periodic loops require cancellation selection;
- critical loops must be registered with the mesh task group;
- per-peer children must enter the child group;
- `start()` must not set running before commit;
- failed startup must call rollback;
- shutdown must abort and await timed-out tasks.

Initial audited files:

- `crates/synvoid-mesh/src/mesh/transport.rs`
- `crates/synvoid-mesh/src/mesh/threat_intel.rs`
- `crates/synvoid-mesh/src/mesh/discovery.rs`
- relevant QUIC runtime integration files.

Use reason-bearing exceptions for any intentionally detached one-shot task.

## Phase 18 — Documentation

Create/update:

- `architecture/mesh_transport_lifecycle.md`
- `architecture/worker_task_lifecycle.md`
- mesh architecture docs;
- `AGENTS.md`
- `crates/synvoid-mesh/AGENTS.override.md` if present;
- worker lifecycle docs.

Document:

- mesh task classes;
- startup state machine;
- transactional startup;
- rollback ordering;
- shutdown ordering;
- child handshake ownership;
- critical failure propagation;
- worker integration boundary;
- how to add a new mesh background task safely.

## Phase 19 — Suggested Implementation Sequence

Implement in this order:

1. Add task/exit/state types.
2. Add mesh-local task group.
3. Add cancellation-aware periodic spawn helpers.
4. Convert critical maintenance/datagram/accept loops.
5. Convert periodic background loops.
6. Add child connection group and handshake limits.
7. Refactor startup into transactional phases.
8. Add rollback.
9. Add bounded shutdown/report.
10. Integrate worker critical-exit subscription.
11. Add guardrails and docs.

Do not combine protocol changes with lifecycle migration.

## Phase 20 — Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-mesh transport
cargo test -p synvoid-mesh lifecycle
cargo test -p synvoid-mesh startup
cargo test -p synvoid-mesh shutdown
cargo test --test mesh_task_ownership_guard
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh -- -D warnings
```

If worker integration changes shared lifecycle types:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This iteration is complete when:

1. Every long-lived mesh task has an owner.
2. Every periodic mesh loop has explicit cancellation.
3. Critical mesh loops retain handles and report unexpected exits.
4. Mesh startup is transactional.
5. Failed startup rolls back all started tasks and resources.
6. `running` is true only after successful commit.
7. Incoming peer children are bounded and owned.
8. Peer handshakes have bounded duration and shutdown behavior.
9. Mesh shutdown is idempotent, bounded, and aborts-and-awaits remnants.
10. No mesh-owned task survives completed shutdown.
11. Critical mesh failure is observable by the worker composition root.
12. Worker shutdown awaits mesh shutdown before supervisor completion acknowledgement.
13. Guardrails prevent new detached long-lived mesh tasks.
14. Existing blocklist, threat-intel, provenance, mesh-ID, composition, and worker lifecycle guardrails remain green.

## Notes for the Implementer

This is a lifecycle/ownership pass, not a mesh protocol redesign.

The desired end state is:

- `MeshTransport` is one managed service from the worker’s perspective;
- mesh internals own and supervise their own tasks;
- startup is all-or-nothing;
- shutdown is bounded and complete;
- critical failures retain enough detail to drive worker-level failure policy.
