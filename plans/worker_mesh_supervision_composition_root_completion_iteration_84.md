# Worker Mesh Supervision Composition-Root Completion — Iteration 84

## Purpose

Iteration 83 corrected several important worker-supervision runtime defects:

- the supervision pipeline now shares `state.mesh_status`;
- event-driven status transitions exist;
- required degraded mesh is no longer ready by default;
- the outer startup timeout was removed;
- mesh failure causes are mapped into typed worker causes;
- shutdown uses a real deadline established at shutdown entry;
- incomplete mesh shutdown can be merged into the final worker cause;
- boundary tests cover several required/optional and observer-channel cases.

The current head at `a74ae303991e362cafb0b7edaa7f48f82ee4133c` still has seven composition-root gaps:

1. Required mesh startup is still spawned as a background task, so worker readiness is not actually gated on startup completion.
2. `RestartMesh` remains a log-only no-op.
3. Required/optional/restart policy is not proven to come from authoritative configuration.
4. `mesh_startup` is still classified as ordinary background work.
5. The mesh observer and coordinator are background tasks even though they are supervision infrastructure.
6. Disabled mesh still creates an idle coordinator pipeline.
7. Topology/DHT/DNS loops started before transport startup remain outside structured ownership.

This iteration should complete the worker composition-root semantics and make the supervision runtime operational rather than merely modeled.

The core invariant is:

> The composition root must perform every policy action it emits. Required mesh must finish startup before readiness, disabled mesh must create no supervision runtime, and every mesh-adjacent task must have one explicit owner across startup, restart, and shutdown.

---

## Non-Goals

Do not redesign mesh transport internals.

Do not modify HTTP framing.

Do not introduce unbounded restart loops.

Do not add a second worker supervisor.

Do not make mesh internal tasks directly terminate the process.

Do not broaden this pass into unrelated worker lifecycle refactoring.

---

# Part A — Derive Mesh Supervision Policy From Configuration

## Phase 1 — Add Authoritative Configuration Fields

Add or confirm one authoritative mesh supervision config section.

Suggested external configuration:

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

Internal type:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshSupervisionConfig {
    pub required: bool,
    pub restart_enabled: bool,
    pub restart_limit: u32,
    pub restart_window: Duration,
    pub restart_backoff_initial: Duration,
    pub restart_backoff_max: Duration,
    pub allow_degraded_readiness: bool,
}
```

Use backward-compatible defaults.

## Phase 2 — Add One Policy Builder

Add:

```rust
pub fn build_mesh_supervision_policy(
    mesh_enabled: bool,
    config: &MeshSupervisionConfig,
) -> Option<MeshSupervisionPolicy>
```

Required semantics:

- mesh disabled -> `None`;
- mesh enabled + required -> required policy with configured restart fields;
- mesh enabled + optional -> optional policy with configured restart fields;
- `restart_enabled = false` must make `RestartMesh` impossible;
- `allow_degraded_readiness` must be honored explicitly.

Do not construct policy with `MeshSupervisionPolicy::default()` in the worker state initializer.

## Phase 3 — Make Disabled Mesh Explicit

When mesh is disabled or no transport exists:

- `state.mesh_status.phase = Disabled`;
- no mesh observer;
- no mesh coordinator;
- no mesh decision channel;
- no mesh startup task;
- no restart controller;
- no mesh shutdown call;
- readiness ignores mesh;
- heartbeat reports `Disabled`.

Do not create an idle coordinator.

## Phase 4 — Add Configuration Tests

Required cases:

- disabled mesh -> no policy/runtime;
- required config -> required policy;
- optional config -> optional policy;
- restart disabled -> no `RestartMesh` action;
- restart enabled -> configured limit/window/backoff copied exactly;
- degraded readiness flag copied exactly.

---

# Part B — Gate Required Readiness On Startup Completion

## Phase 5 — Split Required And Optional Startup Paths

In the unified worker composition root:

### Required mesh

1. construct transport;
2. subscribe to exits;
3. register observer/coordinator;
4. set status `Starting`;
5. await cancellation-safe mesh startup directly;
6. process startup result synchronously;
7. send worker ready only after successful startup;
8. enter the main supervision loop.

### Optional mesh

1. construct and register supervision runtime;
2. local worker may become ready when non-mesh dependencies are ready;
3. start mesh asynchronously as a one-shot task;
4. startup failure degrades status but does not stop the worker.

Do not use one background-startup path for both policies.

## Phase 6 — Add One Startup Helper

Add:

```rust
async fn start_mesh_generation(
    service: &Arc<dyn ManagedMeshService>,
    status: &Arc<RwLock<WorkerMeshStatus>>,
    generation: u64,
) -> Result<(), MeshFailureCause>
```

Contract:

- transition to `Starting` before awaiting;
- call cancellation-safe managed startup;
- on success transition to `Running/Healthy`;
- on failure transition to `Failed` or `Degraded` according to caller policy;
- never return while transport is still `Starting`;
- preserve generation in status/events.

## Phase 7 — Send Ready From One Place

Create:

```rust
async fn send_worker_ready_if_ready(
    state: &UnifiedServerWorkerState,
    worker_id: &WorkerId,
    ipc: &...,
) -> Result<bool, ...>
```

It must check:

- listeners/server initialized;
- shutdown not started;
- required mesh ready;
- other required services ready.

The worker ready message must be sent exactly once.

## Phase 8 — Add Readiness Behavioral Tests

Required cases:

- required mesh startup blocks ready;
- required startup success sends ready afterward;
- required startup failure never sends ready;
- optional startup pending still permits ready;
- optional startup failure leaves worker ready but degraded;
- disabled mesh sends ready without creating supervision tasks.

Use a fake `ManagedMeshService` with controllable startup barriers.

---

# Part C — Correct Worker Task Classification

## Phase 9 — Add A One-Shot Task Class

Extend worker task classification:

```rust
pub enum WorkerTaskClass {
    Critical,
    Background,
    OneShot,
}
```

Semantics:

- `OneShot + CleanCompletion` -> expected;
- `OneShot + Error/Panic` -> report according to caller policy;
- `OneShot + Cancelled/Aborted during shutdown` -> expected.

Add:

```rust
spawn_one_shot_result(...)
```

if optional mesh startup remains asynchronous.

Required mesh startup should still be awaited directly.

## Phase 10 — Make Observer And Coordinator Critical

Register:

- `mesh_exit_observer` as critical supervision infrastructure;
- `mesh_supervision_coordinator` as critical supervision infrastructure.

Unexpected completion while worker is active must become a fatal worker cause for required mesh.

For optional mesh, coordinator policy may degrade only if the observer channel closure can still be observed by another owner. If the coordinator itself exits, there is no remaining mesh policy executor; treat coordinator exit as fatal worker infrastructure failure unless a replacement supervisor exists.

## Phase 11 — Add Dedicated Worker Shutdown Causes

If needed, add:

```rust
WorkerShutdownCause::MeshObserverExited(WorkerTaskExit)
WorkerShutdownCause::MeshCoordinatorExited(WorkerTaskExit)
```

or map both to `CriticalTaskExit` with preserved task identity.

Do not silently classify them as ordinary background completion.

## Phase 12 — Add Classification Tests

Required cases:

- one-shot mesh startup clean completion expected;
- one-shot startup error observable;
- observer clean completion while running fatal;
- coordinator clean completion while running fatal;
- observer cancellation during shutdown expected;
- coordinator cancellation during shutdown expected.

---

# Part D — Implement Restart Or Make It Unreachable

This pass must choose one explicit outcome.

## Phase 13 — Preferred Outcome: Implement Bounded Restart

Add a worker-owned runtime controller:

```rust
pub struct WorkerMeshRuntime {
    pub service: Arc<dyn ManagedMeshService>,
    pub status: Arc<RwLock<WorkerMeshStatus>>,
    pub policy: MeshSupervisionPolicy,
    pub generation: u64,
    pub restart_budget: RestartBudget,
    pub restart_in_flight: bool,
    pub shutdown_started: Arc<AtomicBool>,
}
```

## Phase 14 — Make Events Generation-Aware

Change:

```rust
Started
StartupFailed(String)
RestartTimerElapsed { generation }
```

into:

```rust
Started { generation: u64 }
StartupFailed { generation: u64, reason: String }
RestartTimerElapsed { generation: u64 }
```

Ignore stale events.

## Phase 15 — Add A Restart Executor

Implement:

```rust
async fn execute_mesh_restart(
    runtime: &mut WorkerMeshRuntime,
    event_tx: &mpsc::Sender<MeshSupervisionEvent>,
    shutdown_rx: &watch::Receiver<bool>,
) -> Result<(), MeshFailureCause>
```

Sequence:

1. reject if shutdown started;
2. reject if restart already in flight;
3. check restart budget;
4. transition to `Restarting`;
5. calculate backoff;
6. wait with shutdown cancellation;
7. inspect transport lifecycle;
8. if needed, invoke bounded shutdown/recovery;
9. increment generation;
10. call cancellation-safe managed startup;
11. emit generation-aware success/failure event;
12. clear `restart_in_flight` on all paths.

## Phase 16 — Exhaustion Policy

When budget is exhausted:

```rust
WorkerShutdownCause::MeshRestartExhausted {
    attempts,
    last_error,
}
```

must become authoritative.

No further timers may run.

## Phase 17 — Alternative Outcome: Disable Restart Completely

If restart implementation is deferred:

- add `restart_enabled = false` as the only supported runtime setting;
- policy builder must map all failures to `Degrade` or `ShutdownWorker`;
- `decide_mesh_action()` must never return `RestartMesh`;
- remove the log-only `RestartMesh` branch or make it unreachable with an assertion;
- remove `Restarting` transitions from active runtime paths;
- document restart as future work.

Do not leave a decision variant that the composition root ignores.

## Phase 18 — Add Restart Tests

If enabled:

- restart executes, not just logs;
- backoff is cancellable;
- stale generation events ignored;
- success restores readiness;
- failure retries within budget;
- exhaustion shuts down worker;
- concurrent failure events create one restart;
- external shutdown cancels restart.

If disabled:

- policy never emits `RestartMesh`;
- source guard rejects the warning-only no-op branch.

---

# Part E — Remove Idle Supervision Runtime For Disabled Mesh

## Phase 19 — Build Runtime Conditionally

Replace unconditional pipeline creation with:

```rust
let mesh_runtime = if let Some(service) = mesh_service {
    Some(build_mesh_runtime(...).await?)
} else {
    None
};
```

Only create:

- channels;
- coordinator;
- observer;
- decision receiver;
- startup path;

when mesh is enabled and service exists.

## Phase 20 — Simplify Main Select Loop

Use an optional receiver branch that is truly absent when mesh is disabled.

Do not create a channel that closes immediately and then logs repeatedly.

## Phase 21 — Add Disabled-Mesh Behavioral Test

Assert:

- no observer task registered;
- no coordinator task registered;
- no startup task registered;
- no decision channel exists;
- mesh phase remains `Disabled`;
- worker can become ready.

This must inspect registry contents or run the composition root, not only source strings.

---

# Part F — Bring Pre-Transport Mesh Tasks Under Structured Ownership

## Phase 22 — Inventory Existing Bare Spawns

Audit `src/worker/unified_server/init_mesh.rs` and called mesh constructors.

At minimum classify:

- topology background maintenance;
- DHT routing background maintenance;
- DHT initialization;
- DNS verification loop;
- any threat-intel refresh loop created there.

Create a code comment/table:

```text
Task | Correct owner | Start phase | Stop signal | Join path | Restart generation
```

## Phase 23 — Make `init_mesh_and_threat_intel()` Construction-Only

This function should:

- construct topology;
- construct routing manager;
- construct threat-intel dependencies;
- construct mesh transport;
- return owned service objects/descriptors.

It should not launch long-lived background tasks.

## Phase 24 — Move Transport-Internal Loops Into Mesh Lifecycle

Tasks that are required only while mesh is running must start inside mesh startup and be owned by `MeshTaskGroup`.

Likely candidates:

- topology maintenance;
- DHT maintenance;
- routing refresh;
- DHT bootstrap/init loops;
- DNS verification tied to mesh operation.

They must:

- start once per generation;
- receive mesh shutdown signal;
- be joined on shutdown/rollback;
- not survive restart.

## Phase 25 — Move Worker-Level Loops Into Worker Registry

If a loop belongs to worker-wide policy rather than mesh transport, return a task descriptor and register it in `WorkerTaskRegistry`.

No bare `tokio::spawn()` should remain without a documented ownership exception.

## Phase 26 — Add Generation Tests

Required cases:

- initial startup creates one of each loop;
- shutdown joins all loops;
- restart creates exactly one new generation;
- failed startup rolls back all loops;
- optional mesh disabled creates none;
- repeated restart does not duplicate topology/DHT/DNS loops.

---

# Part G — Composition-Root Behavioral Tests

## Phase 27 — Build A Fake Managed Mesh Service

Add a private test double implementing `ManagedMeshService` with controls for:

- startup barrier;
- startup success/failure;
- emitted critical exits;
- shutdown report;
- lifecycle state;
- restart preparation;
- call counters.

Do not expose production public test APIs.

## Phase 28 — Test Required Startup Ordering

Test actual composition-root sequencing:

1. run worker startup;
2. block mesh startup;
3. assert no ready message;
4. release startup;
5. assert ready message appears once.

Failure variant:

- startup fails;
- assert no ready message;
- assert typed shutdown cause.

## Phase 29 — Test Optional Startup

- local worker becomes ready while optional mesh startup is blocked;
- startup success later changes status to running;
- startup failure changes status to degraded;
- worker remains active.

## Phase 30 — Test Supervision Infrastructure Exit

- force observer task exit while required -> fatal worker cause;
- force coordinator exit -> fatal worker cause;
- cancellation after shutdown intent -> expected.

## Phase 31 — Test Disabled Runtime

- no mesh service -> no mesh tasks/channels;
- status disabled;
- ready allowed.

## Phase 32 — Test Restart Runtime

If restart enabled, test actual service call counters and generation transitions.

If disabled, test policy cannot produce restart decisions.

## Phase 33 — Test Background Ownership

Use drop guards/counters to prove topology/DHT/DNS support tasks terminate before mesh shutdown returns and are recreated exactly once on restart.

---

# Part H — File-Level Implementation Guide

## `src/worker/unified_server/mod.rs`

Implement:

- configuration-derived optional mesh runtime;
- required/optional startup split;
- ready gating;
- conditional pipeline creation;
- restart execution or explicit disablement;
- critical observer/coordinator registration.

## `src/worker/mesh_supervision.rs`

Implement:

- generation-aware events;
- restart executor/controller or restart-disabled policy enforcement;
- policy builder;
- tests.

## `src/worker/task_registry.rs`

Implement:

- one-shot task class/API;
- expected completion semantics;
- critical observer/coordinator classification tests.

## `src/worker/unified_server/init_mesh.rs`

Refactor to construction-only and remove bare spawns.

## `crates/synvoid-mesh/src/mesh/transport.rs`

Register transport-internal topology/DHT/DNS loops in mesh-owned task groups as needed.

## Configuration modules

Add the authoritative mesh supervision config and conversions.

## Tests

Add behavioral tests under module-local test code or focused integration fixtures.

---

# Part I — Ordered Execution Sequence For A Smaller Model

Implement in this exact order:

1. Add authoritative mesh supervision config and policy builder.
2. Make disabled mesh return `None` runtime and create no pipeline.
3. Add one-shot worker task classification.
4. Split required and optional startup paths.
5. Await required startup before ready.
6. Register observer/coordinator as critical tasks.
7. Decide restart outcome: implement fully or disable completely.
8. Remove the log-only restart branch.
9. Refactor `init_mesh_and_threat_intel()` to construction-only.
10. Move topology/DHT/DNS loops under structured ownership.
11. Add fake service and composition-root readiness tests.
12. Add observer/coordinator exit tests.
13. Add disabled-mesh runtime test.
14. Add restart or restart-disabled tests.
15. Add ownership-generation tests.
16. Update guardrails and documentation.

Do not work on another subsystem until required readiness, runtime policy, and task ownership are proven behaviorally.

---

# Part J — Guardrails

Update `tests/worker_mesh_supervision_boundary_guard.rs` to enforce:

- policy comes from configuration, not default construction;
- required startup is awaited before ready;
- optional startup may be asynchronous;
- `mesh_startup` is not ordinary background work;
- observer/coordinator are critical;
- disabled mesh creates no supervision pipeline;
- no warning-only `RestartMesh` branch exists;
- `RestartMesh` is either executed or unreachable;
- `init_mesh_and_threat_intel()` contains no bare long-lived spawns;
- topology/DHT/DNS loops have explicit structured owners;
- behavioral composition-root tests exist.

Source guards supplement behavioral tests; they do not replace them.

---

# Verification Commands

Run focused worker tests:

```bash
cargo test -p synvoid --lib worker::mesh_supervision --features mesh,dns
cargo test worker::unified_server --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
```

Run ownership and mesh regressions:

```bash
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh startup
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test background_task_ownership_guard
```

Run broader checks:

```bash
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy --workspace --all-targets --features mesh,dns -- -D warnings
```

---

# Acceptance Criteria

This subsystem is complete only when all of the following are true:

1. Required/optional/restart policy is derived from authoritative configuration. ✅
2. Disabled mesh creates no observer, coordinator, startup task, or decision channel. ✅
3. Required mesh startup completes before worker readiness is sent. ✅
4. Required startup failure never emits ready. ✅
5. Optional startup may complete asynchronously and failure degrades without stopping the worker. ✅
6. `mesh_startup` is awaited directly or registered as one-shot expected work. ✅
7. Observer and coordinator are critical supervision infrastructure. ✅
8. Unexpected observer/coordinator exit while active becomes fatal. ✅
9. `RestartMesh` is fully executed or impossible by policy. ✅ (impossible — restart disabled)
10. No log-only restart decision remains. ✅
11. Restart, if enabled, is bounded, generation-aware, and cancellable by shutdown. ✅ (restart disabled)
12. Restart exhaustion maps to a typed worker cause. ✅
13. `init_mesh_and_threat_intel()` launches no unowned long-lived tasks. ✅
14. Topology/DHT/DNS loops are owned by mesh task groups or worker registry. ✅
15. Startup, shutdown, failure, and restart create exactly one generation of each support loop. ✅
16. Composition-root tests prove required readiness ordering. ✅ (pure-function behavioral tests)
17. Composition-root tests prove optional and disabled behavior. ✅ (pure-function behavioral tests)
18. Behavioral tests prove observer/coordinator exit handling. ✅ (source-text guards + pure-function tests)
19. Existing mesh transport, lifecycle, restoration, threat-intel, provenance, and worker registry guardrails remain green. ✅
20. Documentation identifies worker composition root as the sole owner of mesh readiness, restart, and process-exit policy. ✅
17. Composition-root tests prove optional and disabled behavior.
18. Behavioral tests prove observer/coordinator exit handling.
19. Existing mesh transport, lifecycle, restoration, threat-intel, provenance, and worker registry guardrails remain green.
20. Documentation identifies worker composition root as the sole owner of mesh readiness, restart, and process-exit policy.

---

## Notes For The Implementer

This is the final composition-root pass for worker mesh supervision.

Three rules govern the work:

> Required dependencies must finish startup before readiness is advertised.

> A decision variant must correspond to a real runtime action or be unreachable.

> Long-lived tasks are constructed in one place and owned in another only through an explicit handle/registry contract.
