# Worker Mesh Supervision Runtime Correction — Iteration 83

## Purpose

Iteration 82 established the correct worker-level supervision architecture but left several runtime integration defects. The current head at `b47b304f169985251ea55f842c37e84a7e9aaa61` contains the right conceptual pieces:

- `MeshSupervisionPolicy`;
- `WorkerMeshStatus` and `WorkerMeshPhase`;
- `MeshSupervisionEvent` and `MeshSupervisorDecision`;
- a worker-owned mesh exit observer;
- a supervision coordinator;
- restart budget/backoff primitives;
- mesh-specific worker shutdown causes;
- heartbeat fields and readiness helper;
- composition-root startup/shutdown integration.

However, the runtime wiring is not yet semantically complete. The primary defects are:

1. The supervision pipeline updates a separate `WorkerMeshStatus` instead of `state.mesh_status`, so heartbeat/readiness do not see actual transitions.
2. The worker sends `UnifiedServerWorkerReady` before required mesh startup succeeds.
3. Required mesh currently treats `Degraded` as ready.
4. `Started` is classified as `NoAction`, so status never transitions to `Running`.
5. Restart decisions are emitted but not executed.
6. Mesh startup is wrapped in an outer timeout that can cancel the startup future and bypass transactional rollback.
7. Mesh shutdown receives a budget calculated from total worker uptime rather than shutdown start time.
8. Incomplete mesh shutdown is logged but does not affect the final worker cause or exit status.
9. All fatal mesh decisions are collapsed into `MeshStartupFailed`, losing typed cause information.
10. Policy is hard-coded to the required default instead of being derived from authoritative configuration.
11. `mesh_startup` is registered as a long-lived background task despite being a bounded one-shot operation.
12. Pre-transport mesh/DHT/DNS background tasks are spawned outside both `MeshTaskGroup` and `WorkerTaskRegistry`.

This plan corrects the runtime integration without reopening mesh transport internals.

The central invariant is:

> One authoritative worker mesh status object drives policy, readiness, heartbeat, restart, and shutdown. Required mesh must be operational before readiness, and every startup/restart/shutdown path must preserve typed causes and structured task ownership.

---

## Non-Goals

Do not redesign HTTP-over-mesh framing.

Do not change DHT/Raft consistency boundaries.

Do not introduce unbounded automatic restart.

Do not add a second supervision loop.

Do not make mesh internals directly terminate the worker process.

Do not create new public test-only APIs.

Do not rewrite the entire unified worker lifecycle.

---

# Part A — Establish One Authoritative Worker Mesh Status

## Phase 1 — Remove The Duplicate Status Allocation

In `src/worker/unified_server/mod.rs`, remove the local allocation:

```rust
let mesh_status = Arc::new(RwLock::new(WorkerMeshStatus::default()));
```

Use:

```rust
let mesh_status = state.mesh_status.clone();
```

Pass that exact `Arc` to:

- `create_supervision_pipeline()`;
- `run_mesh_exit_observer()`;
- restart execution;
- readiness checks;
- heartbeat snapshotting.

Acceptance condition:

```rust
Arc::ptr_eq(&mesh_status, &state.mesh_status)
```

should hold in a module-local integration test.

## Phase 2 — Add Explicit Status Transition Helpers

Add methods on `WorkerMeshStatus` or free helpers:

```rust
impl WorkerMeshStatus {
    fn transition_starting(&mut self);
    fn transition_running(&mut self);
    fn transition_degraded(&mut self, reason: String);
    fn transition_restarting(&mut self);
    fn transition_failed(&mut self, reason: String);
    fn transition_stopping(&mut self);
    fn transition_stopped(&mut self);
}
```

Recommended fields:

```rust
pub struct WorkerMeshStatus {
    pub phase: WorkerMeshPhase,
    pub health: MeshServiceHealth,
    pub last_exit: Option<MeshTaskExit>,
    pub last_failure: Option<String>,
    pub restart_attempts: u32,
    pub generation: u64,
    pub last_transition: Instant,
}
```

Each transition must update `last_transition`.

## Phase 3 — Apply Event Transitions Before Policy Decisions

The coordinator currently maps `Started` to `NoAction`, which leaves status unchanged.

Refactor coordinator processing into:

1. read current status;
2. apply event-level status mutation;
3. compute policy decision from the updated status;
4. apply decision-level mutation;
5. publish decision.

Suggested helpers:

```rust
fn apply_mesh_event_to_status(
    status: &mut WorkerMeshStatus,
    event: &MeshSupervisionEvent,
);

fn apply_mesh_decision_to_status(
    status: &mut WorkerMeshStatus,
    decision: &MeshSupervisorDecision,
);
```

Required event transitions:

- `Started` -> `Running`, `Healthy`;
- `StartupFailed` -> `Failed` or temporary degraded/restarting state before policy action;
- `TaskExit` -> store `last_exit`;
- `ExitStreamLagged` -> `Degraded`;
- `ExitStreamClosed` -> `Degraded` or `Failed` before policy action;
- `RestartTimerElapsed` -> no direct phase change until restart execution begins;
- `WorkerShutdownStarted` -> `Stopping`.

## Phase 4 — Use The Real Status During Classification

Replace:

```rust
decide_mesh_action(
    &self.policy,
    &WorkerMeshStatus::default(),
    ...
)
```

with a snapshot of `self.status`.

Do not hold the write lock while awaiting on decision channel sends.

Pattern:

```rust
let status_snapshot = {
    let status = self.status.read().await;
    status.clone_for_policy()
};
```

If `WorkerMeshStatus` cannot derive `Clone` because of `Instant` or error types, add a lightweight `WorkerMeshStatusSnapshot`.

---

# Part B — Derive Mesh Policy And Enabled State From Configuration

## Phase 5 — Add A Policy Builder

Add:

```rust
fn build_mesh_supervision_policy(
    config: &ConfigManager,
    mesh_transport_present: bool,
) -> MeshSupervisionPolicy
```

The policy must derive from authoritative configuration rather than `MeshSupervisionPolicy::default()`.

Determine:

- mesh enabled/disabled;
- required/optional participation;
- restart limit/window;
- readiness requirement;
- restart backoff;
- startup/critical/restartable actions.

If no explicit config field exists for required/optional behavior, add one under the mesh config surface:

```toml
[mesh.supervision]
required = true
restart_enabled = false
restart_limit = 3
restart_window_secs = 300
restart_backoff_initial_secs = 5
restart_backoff_max_secs = 60
allow_degraded_readiness = false
```

Use backward-compatible defaults.

## Phase 6 — Represent Disabled Mesh Explicitly

When mesh is disabled or no transport exists:

- status phase = `Disabled`;
- health = `Healthy` or an explicit disabled state if available;
- no observer/coordinator/startup task is spawned;
- readiness is not blocked;
- heartbeat reports `Disabled`;
- shutdown does not attempt mesh teardown.

Do not create a required policy with no transport.

## Phase 7 — Add Readiness Policy Fields

Extend policy:

```rust
pub readiness_requires_mesh: bool,
pub allow_degraded_readiness: bool,
```

Required policy defaults:

```text
readiness_requires_mesh = true
allow_degraded_readiness = false
```

Optional policy defaults:

```text
readiness_requires_mesh = false
allow_degraded_readiness = true
```

---

# Part C — Correct Worker Readiness Ordering

## Phase 8 — Move Ready Signaling After Required Mesh Startup

Currently the worker sends `UnifiedServerWorkerReady` before the mesh supervision pipeline and startup task exist.

Reorder startup:

1. construct state;
2. subscribe to worker task exits;
3. register core lifecycle/server tasks;
4. construct mesh supervision pipeline;
5. subscribe to mesh exits;
6. start required mesh and await startup result;
7. evaluate worker readiness;
8. send `UnifiedServerWorkerReady` only if ready;
9. enter supervision loop.

Optional mesh may start asynchronously after local server readiness, but required mesh must finish startup first.

## Phase 9 — Add A Readiness Gate Function

Replace the current permissive helper with:

```rust
pub async fn is_mesh_ready(&self) -> bool {
    let status = self.mesh_status.read().await;

    if !self.mesh_policy.readiness_requires_mesh {
        return true;
    }

    match status.phase {
        WorkerMeshPhase::Running => true,
        WorkerMeshPhase::Degraded => self.mesh_policy.allow_degraded_readiness,
        _ => false,
    }
}
```

Health should also be checked if `MeshServiceHealth` distinguishes failed/degraded states independently of phase.

## Phase 10 — Add One Worker Readiness Function

Avoid sending ready based only on mesh state.

Add:

```rust
async fn worker_is_ready(state: &UnifiedServerWorkerState) -> bool
```

It should combine:

- server/listener readiness;
- required app services;
- mesh readiness;
- shutdown intent false.

Use this function before sending ready and in any readiness endpoint.

## Phase 11 — Handle Required Mesh Startup Failure Before Ready

For required mesh startup failure:

- never send ready;
- create a typed `WorkerShutdownCause`;
- enter coordinated shutdown;
- send `WorkerError` to supervisor;
- return nonzero exit status.

For optional mesh startup failure:

- status -> `Degraded`;
- send ready if all non-mesh readiness conditions pass;
- report degradation in heartbeat.

---

# Part D — Make Startup Cancellation-Safe

## Phase 12 — Remove The Outer `tokio::time::timeout()` Around `start_with_policy()`

Do not cancel the startup future externally.

Preferred:

```rust
transport.start_with_policy(policy).await
```

where `MeshStartupPolicy` already contains bounded stage deadlines.

If a total startup deadline is still required, implement it inside the mesh crate:

```rust
async fn start_with_deadline(
    &self,
    policy: MeshStartupPolicy,
    deadline: Instant,
) -> Result<MeshStartupReport, MeshTransportError>
```

The method must route deadline expiry through rollback before returning.

## Phase 13 — Add A Worker-Facing Cancellation-Safe Startup Contract

Extend `ManagedMeshService` minimally:

```rust
async fn start_managed(
    &self,
    timeout: Duration,
) -> Result<(), MeshTransportError>;
```

Contract:

- never returns while lifecycle remains `Starting`;
- timeout triggers rollback internally;
- on error, lifecycle is `Stopped` or `Failed` with recoverable diagnostics;
- no staged resources escape.

The worker should not call concrete `start_with_policy()` directly.

## Phase 14 — Verify Lifecycle State After Startup Failure

After error:

```rust
match mesh.lifecycle_state().await {
    Stopped => ...,
    Failed => ...,
    Starting | Running | Stopping => treat as invariant violation/fatal,
}
```

Add tests for timeout, bind failure, and injected stage failure.

## Phase 15 — Treat Startup As A One-Shot Operation

Do not register `mesh_startup` as a long-lived background task.

Choose one:

### Preferred

Await startup directly in the composition root before readiness.

### Alternative

Add a one-shot task registration API:

```rust
registry.spawn_one_shot("mesh_startup", future)
```

where clean completion is expected and not classified as background failure.

Direct awaiting is simpler and preferred for required mesh.

---

# Part E — Preserve Typed Mesh Failure Causes

## Phase 16 — Add Exhaustive Conversion

Implement:

```rust
fn mesh_failure_to_worker_cause(
    cause: MeshFailureCause,
) -> WorkerShutdownCause
```

Required mapping:

- `CriticalServiceExit(exit)` -> `MeshServiceExit(exit)`;
- `StartupFailed(reason)` -> `MeshStartupFailed(reason)`;
- `ShutdownTimeout { ... }` -> `MeshShutdownIncomplete(summary)`;
- future variants must cause a compile error until mapped.

Do not convert everything to `MeshStartupFailed`.

## Phase 17 — Preserve Restart Exhaustion As Its Own Cause

Add one of:

```rust
WorkerShutdownCause::MeshRestartExhausted {
    attempts: u32,
    last_error: String,
}
```

or:

```rust
MeshFailureCause::RestartExhausted { ... }
```

Map to nonzero exit and supervisor notification.

Do not mislabel restart exhaustion as startup failure.

## Phase 18 — Add Cause Priority Rules

During shutdown, multiple causes may occur.

Define priority:

```text
process/lifecycle infrastructure failure
> critical runtime mesh failure
> startup/restart exhaustion
> incomplete mesh shutdown
> external expected shutdown
```

Implement:

```rust
fn merge_worker_shutdown_cause(
    current: WorkerShutdownCause,
    new: WorkerShutdownCause,
) -> WorkerShutdownCause
```

Use this when mesh shutdown reveals incomplete cleanup after an expected external cause.

---

# Part F — Use A Real Worker Shutdown Deadline

## Phase 19 — Establish The Deadline At Shutdown Entry

Immediately after determining `drain_timeout`:

```rust
let shutdown_started_at = Instant::now();
let shutdown_deadline = shutdown_started_at + drain_timeout;
```

Add helper:

```rust
fn remaining_shutdown_budget(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}
```

Use it for:

- connection drain;
- app server stop if bounded;
- mesh shutdown;
- registry shutdown;
- remaining legacy handles.

Do not subtract worker uptime.

## Phase 20 — Make `shutdown_cause` Mutable/Accumulative

Change:

```rust
let (shutdown_cause, ...)
```

into:

```rust
let (mut shutdown_cause, ...)
```

After mesh shutdown classification:

```rust
if let MeshShutdownDisposition::Incomplete(cause) = disposition {
    shutdown_cause = merge_worker_shutdown_cause(
        shutdown_cause,
        mesh_failure_to_worker_cause(cause),
    );
}
```

## Phase 21 — Invoke Mesh Shutdown Once

Track per-generation shutdown:

```rust
let mut mesh_shutdown_done = false;
```

or maintain it in a runtime controller.

Fatal mesh exit and external shutdown must converge on one call.

Do not call shutdown in both restart executor and final worker shutdown concurrently.

## Phase 22 — Record Final Mesh Status

Before mesh shutdown:

- phase -> `Stopping`.

After clean/forced-complete shutdown:

- phase -> `Stopped`;
- health -> healthy/disabled as appropriate.

After incomplete shutdown:

- phase -> `Failed`;
- health -> failed;
- retain reason.

---

# Part G — Implement Or Explicitly Disable Restart

Restart should not remain a log-only branch.

## Phase 23 — Choose Runtime Policy For This Pass

Choose one of two explicit outcomes.

### Outcome A — Implement Restart Fully

Preferred if scope remains manageable.

### Outcome B — Disable Restart Decisions Until Implemented

If restart cannot be completed safely in this pass:

- set `restart_enabled = false` by default;
- policy builder must never return `RestartMesh`;
- map restartable failures to `Degrade` or `ShutdownWorker`;
- remove misleading “restart attempt” state transitions and metrics;
- retain helper primitives as unused only if clearly documented.

Do not leave `RestartMesh` as a warning-only no-op.

The rest of this section assumes Outcome A.

## Phase 24 — Add A Worker Mesh Runtime Controller

Create:

```rust
struct WorkerMeshRuntime {
    service: Arc<dyn ManagedMeshService>,
    status: Arc<RwLock<WorkerMeshStatus>>,
    policy: MeshSupervisionPolicy,
    generation: u64,
    restart_budget: RestartBudget,
    restart_task: Option<JoinHandle<()>>,
    shutdown_started: Arc<AtomicBool>,
}
```

The composition root owns this object.

Responsibilities:

- start;
- restart;
- shutdown;
- generation tracking;
- readiness state;
- single-flight protection.

## Phase 25 — Add A Restart Executor

Implement:

```rust
async fn execute_mesh_restart(
    runtime: &mut WorkerMeshRuntime,
    event_tx: mpsc::Sender<MeshSupervisionEvent>,
) -> Result<(), MeshFailureCause>
```

Sequence:

1. reject if worker shutdown started;
2. ensure no restart already active;
3. check/record restart budget;
4. increment generation;
5. phase -> `Restarting`;
6. cancel stale timer/task;
7. wait bounded backoff with shutdown select;
8. inspect lifecycle state;
9. if `Running`, shutdown current generation first;
10. if `Failed`, call `prepare_restart()`/recovery;
11. call cancellation-safe `start_managed()`;
12. on success emit `Started`;
13. on failure emit `StartupFailed` with generation;
14. never leave phase `Restarting` indefinitely.

## Phase 26 — Put Generation On Events

Change:

```rust
Started
StartupFailed(String)
```

into:

```rust
Started { generation: u64 }
StartupFailed { generation: u64, reason: String }
```

Also include generation on restart timer events.

Ignore stale events whose generation does not match current runtime generation.

## Phase 27 — Add Backoff Timer Cancellation

Use `tokio::select!` over:

- backoff sleep;
- worker shutdown token;
- generation cancellation token.

No stale restart timer may start mesh after shutdown or a newer generation.

## Phase 28 — Restore Readiness After Restart

On successful restart:

- phase -> `Running`;
- health -> `Healthy`;
- heartbeat reflects generation/restart count;
- required worker readiness becomes true again.

During restart:

- required mesh -> not ready;
- optional mesh -> ready but degraded unless policy says otherwise.

---

# Part H — Bring Pre-Transport Background Work Under Ownership

## Phase 29 — Inventory Unowned Startup Spawns

Audit `init_mesh_and_threat_intel()` and directly called helpers for:

- `topology.start_background_tasks()`;
- `routing_manager.start_background_tasks()`;
- DHT `init()` spawn;
- DNS verification loop spawn;
- other bare `tokio::spawn()` calls.

Create a table in code comments or docs:

```text
Task | Owner | Start point | Stop signal | Join handle | Restart behavior
```

## Phase 30 — Move Transport-Internal Tasks Under Mesh Ownership

Tasks that are part of mesh transport lifecycle must be started by `MeshTransport::start*()` and owned by:

- `MeshTaskGroup`;
- peer/session registries;
- auxiliary registry.

Examples likely include:

- topology maintenance;
- DHT routing maintenance;
- DHT initialization;
- verification loops tied to mesh runtime.

Do not start them in `init_mesh_and_threat_intel()`.

`init_mesh_and_threat_intel()` should construct dependencies only.

## Phase 31 — Move Worker-Level Tasks Under `WorkerTaskRegistry`

If a task is not transport-internal but belongs to the worker process, return a startup descriptor/handle to the composition root and register it in `WorkerTaskRegistry`.

No bare spawn should remain without a reason-bearing ownership exception.

## Phase 32 — Add Shutdown And Restart Tests

For each moved task:

- prove it starts exactly once per mesh generation;
- prove it stops on mesh shutdown;
- prove it does not survive restart;
- prove restart creates a new generation without duplicate loops;
- prove failed startup rolls it back.

---

# Part I — Correct Worker Task Classification

## Phase 33 — Add One-Shot Worker Task Class If Needed

If startup remains task-based, extend worker task classes:

```rust
pub enum WorkerTaskClass {
    Critical,
    Background,
    OneShot,
}
```

One-shot clean completion is expected.

One-shot error/panic remains observable and can be fatal according to call-site policy.

## Phase 34 — Classify Observer And Coordinator Deliberately

Recommended:

- mesh exit observer -> critical worker supervision infrastructure;
- mesh supervision coordinator -> critical worker supervision infrastructure;
- restart timer -> background/one-shot;
- mesh startup -> directly awaited or one-shot;
- mesh shutdown -> directly awaited in shutdown path.

If observer/coordinator exits while worker is running, that should be fatal for required mesh supervision.

## Phase 35 — Avoid Double Classification

Mesh internal task exits are observed through `MeshTaskExit` and should not also appear as worker task exits unless they are worker-owned observer/coordinator tasks.

Keep internal and worker ownership domains distinct.

---

# Part J — Heartbeat, Health, And Readiness Integration

## Phase 36 — Report The Authoritative Status

Heartbeat must read `state.mesh_status`, which now must be the same object used by coordinator/runtime.

Add fields if useful:

```rust
mesh_generation: u64
mesh_last_failure: Option<String>
mesh_required: bool
```

Avoid high-cardinality raw error text in metrics; error text is acceptable in IPC payload if bounded.

## Phase 37 — Separate Liveness From Readiness

Document and enforce:

- liveness: worker process and supervision loop functioning;
- readiness: worker can safely serve according to required dependencies;
- health: typed state including degraded/restarting/failed.

Required mesh restart must drop readiness without implying immediate process death.

## Phase 38 — Add Supervisor-Side Handling Tests

Verify supervisor IPC parsing handles the new mesh heartbeat fields and does not treat default empty strings as healthy mesh.

Use typed phase where feasible instead of free-form strings.

Preferred schema:

```rust
pub enum MeshHeartbeatPhase {
    Disabled,
    Starting,
    Running,
    Degraded,
    Restarting,
    Failed,
    Stopping,
    Stopped,
}
```

If wire compatibility prevents enum migration now, validate the string values centrally.

---

# Part K — File-Level Implementation Guide

## `src/worker/unified_server/mod.rs`

Implement:

- authoritative status reuse;
- policy derivation;
- startup/readiness reordering;
- cancellation-safe managed startup;
- typed cause mapping;
- real shutdown deadline;
- cause accumulation;
- restart execution or explicit disablement;
- one mesh shutdown invocation.

## `src/worker/mesh_supervision.rs`

Implement:

- event/status transition helpers;
- real status snapshots in classification;
- generation-aware events;
- restart executor helpers or disable restart decisions;
- typed failure conversion;
- cause priority/merge helper;
- tests.

## `src/worker/unified_server/state.rs`

Implement:

- correct readiness policy;
- authoritative status fields;
- optional worker-wide readiness helper.

## `src/worker/unified_server/lifecycle.rs`

Implement:

- heartbeat from authoritative status;
- typed phase/health payload;
- no duplicate status object.

## `src/worker/unified_server/init_mesh.rs`

Refactor:

- construct dependencies only;
- remove bare background spawns;
- return task descriptors if worker-owned;
- move transport-internal starts into mesh lifecycle.

## `crates/synvoid-mesh/src/mesh/worker_integration.rs`

Add minimal worker-facing methods:

```rust
async fn start_managed(&self, timeout: Duration) -> Result<(), MeshTransportError>;
async fn prepare_restart(&self, timeout: Duration) -> Result<(), MeshTransportError>;
async fn lifecycle_state(&self) -> MeshLifecycleState;
```

Keep implementation cancellation-safe.

## `src/worker/task_registry.rs`

Update:

- one-shot classification if needed;
- mesh restart exhaustion cause;
- typed cause conversion tests;
- observer/coordinator criticality.

## Configuration

Add/validate supervision fields in the authoritative mesh config and map external/internal representations consistently.

## Documentation

Update:

- `architecture/worker_task_lifecycle.md`;
- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `src/worker/AGENTS.override.md`;
- `skills/synvoid_mesh.md`;
- root `AGENTS.md`.

---

# Part L — Ordered Execution Sequence For A Smaller Model

Implement in this exact order.

1. Replace duplicate mesh status with `state.mesh_status.clone()`.
2. Add status transition helpers and event-level transitions.
3. Make coordinator classify using the real status snapshot.
4. Derive mesh policy/enabled state from configuration.
5. Correct `is_mesh_ready()` semantics.
6. Reorder startup so required mesh completes before ready is sent.
7. Remove outer startup timeout and add cancellation-safe managed startup.
8. Preserve typed mesh failure causes.
9. Establish a real shutdown deadline and cause accumulator.
10. Promote incomplete mesh shutdown into final worker cause.
11. Decide restart outcome: implement fully or disable explicitly.
12. If implementing restart, add generation-aware events and executor.
13. Fix startup/observer/coordinator task classification.
14. Move pre-transport background spawns under mesh or worker ownership.
15. Add heartbeat/readiness integration tests.
16. Add startup/restart/shutdown race tests.
17. Add guardrails and update documentation.

Do not begin unrelated worker refactors during this pass.

---

# Part M — Behavioral Test Matrix

## Authoritative Status Tests

- coordinator and heartbeat share the same `Arc`;
- `Started` transitions to `Running`;
- startup failure transitions to `Failed`/`Degraded` according to policy;
- degradation appears in heartbeat;
- restart count appears in heartbeat;
- shutdown transitions `Stopping -> Stopped`.

## Readiness Tests

- mesh disabled -> ready when local services ready;
- required mesh starting -> not ready;
- required mesh running -> ready;
- required mesh degraded + default policy -> not ready;
- required mesh degraded + explicit allow -> ready;
- optional mesh failed -> ready but degraded;
- restarting required mesh -> not ready;
- shutdown started -> not ready.

## Startup Tests

- required startup success before ready message;
- required startup failure never emits ready;
- optional startup failure emits ready with degraded health;
- startup timeout performs rollback and leaves no `Starting` state;
- startup failure and exit event race yields one authoritative cause;
- startup one-shot clean completion is not classified as background failure.

## Cause Mapping Tests

- critical mesh task exit -> `MeshServiceExit`;
- startup failure -> `MeshStartupFailed`;
- shutdown incomplete -> `MeshShutdownIncomplete`;
- restart exhausted -> dedicated typed cause;
- expected external shutdown plus incomplete mesh cleanup -> incomplete cause wins;
- existing higher-priority critical cause remains authoritative.

## Shutdown Deadline Tests

- old worker with 30-second drain still gives mesh nearly 30 seconds at shutdown start;
- time spent draining requests reduces later mesh budget correctly;
- zero-budget shutdown still invokes fail-closed cleanup;
- mesh shutdown called exactly once under external shutdown/fatal exit race;
- incomplete report changes final exit code and supervisor message.

## Restart Tests — if enabled

- restart decision invokes actual restart;
- restart budget enforced;
- backoff cancellable by shutdown;
- stale generation events ignored;
- successful restart restores readiness;
- failed restart emits next failure event;
- exhausted restart budget shuts down worker;
- parallel failures do not create parallel restarts.

## Ownership Tests

- topology/DHT/DNS loops are registered under mesh or worker ownership;
- no bare spawn survives mesh shutdown;
- restart creates exactly one new generation of each loop;
- failed startup rolls all loops back;
- worker shutdown joins all worker-owned mesh support tasks.

---

# Part N — Guardrails

Add or extend `tests/worker_mesh_supervision_boundary_guard.rs` to enforce:

- supervision pipeline uses `state.mesh_status.clone()`;
- no second `WorkerMeshStatus::default()` is allocated in composition-root wiring;
- ready message occurs only after required mesh startup path;
- `is_mesh_ready()` does not treat degraded required mesh as ready by default;
- no outer `tokio::time::timeout()` directly wraps `start_with_policy()`;
- typed mesh failure conversion exists and is exhaustive;
- shutdown budget uses a shutdown deadline, not `state.start_time.elapsed()`;
- incomplete mesh shutdown updates final cause;
- `RestartMesh` is either executed or impossible by policy;
- mesh startup is not registered as ordinary long-lived background work;
- no bare `tokio::spawn()` remains in `init_mesh_and_threat_intel()` without a documented ownership exception;
- heartbeat reads the same status object used by supervision;
- observer/coordinator remain worker-owned;
- mesh internals do not directly terminate the process.

Behavioral tests remain authoritative.

---

# Verification Commands

Run focused worker tests:

```bash
cargo test -p synvoid --lib worker::mesh_supervision --features mesh,dns
cargo test worker::unified_server --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
```

Run mesh lifecycle regressions:

```bash
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh startup
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Run broader regressions:

```bash
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy --workspace --all-targets --features mesh,dns -- -D warnings
```

If full workspace clippy is too expensive, at minimum:

```bash
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
cargo clippy --bin synvoid --features mesh,dns -- -D warnings
```

---

# Acceptance Criteria

This pass is complete only when all of the following are true:

1. Supervision, heartbeat, and readiness share one authoritative `WorkerMeshStatus`.
2. `Started` transitions status to `Running/Healthy`.
3. Required mesh startup completes before worker ready is sent.
4. Required degraded mesh is not ready by default.
5. Optional mesh failure can degrade without preventing readiness.
6. Mesh policy is derived from authoritative configuration.
7. Disabled mesh creates no supervisor pipeline or startup task.
8. Startup timeout/failure cannot leave lifecycle in `Starting` or leak staged resources.
9. Mesh startup is directly awaited or classified as one-shot expected completion.
10. Typed mesh failure causes are preserved through worker shutdown.
11. Restart exhaustion has a distinct typed cause.
12. Worker shutdown uses a deadline established at shutdown entry.
13. Mesh shutdown receives the actual remaining shutdown budget.
14. Incomplete mesh shutdown can change the final worker cause and exit status.
15. Mesh shutdown is invoked once per generation.
16. `RestartMesh` is either fully executed or explicitly disabled by policy.
17. If restart is enabled, generation/backoff/budget/shutdown cancellation are implemented.
18. Pre-transport topology/DHT/DNS background work is under structured ownership.
19. Heartbeat accurately reports phase, health, degradation, generation, and restart attempts.
20. No mesh support task survives failed startup, shutdown, or restart.
21. Worker observer/coordinator exits while active are treated according to required/optional policy.
22. Existing mesh transport, topology/DHT restoration, threat-intel, provenance, mesh-ID, and worker lifecycle guardrails remain green.

---

## Notes For The Implementer

This is a runtime-integration correction, not another transport redesign.

Keep the ownership boundary explicit:

- mesh transport owns internal resources and cancellation-safe lifecycle;
- worker supervision owns readiness, restart, shutdown policy, process exit, and supervisor reporting.

Three rules should guide every change:

> There is exactly one authoritative worker mesh status object.

> Required dependencies become ready before the worker advertises readiness.

> A policy decision is not implemented until the composition root performs the corresponding runtime action.
