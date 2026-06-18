# Worker Mesh Supervision Corrective Pass — Iteration 85

## Purpose

Iteration 84 completed most of the composition-root integration for worker-level mesh supervision. The current head at `3db36957ce5ba9e3c8a112c80fcd45d5fe936207` now has:

- required mesh startup awaited before worker readiness;
- optional mesh startup registered as one-shot work;
- mesh observer and coordinator registered as critical worker tasks;
- configuration-backed supervision policy types;
- disabled/no-transport runtime branches;
- typed mesh shutdown causes;
- real worker shutdown deadlines;
- registry ownership for several mesh-adjacent loops;
- extensive worker supervision tests.

The review found eight remaining contradictions that prevent subsystem closure:

1. `mesh.enabled = false` can still construct topology, routing, and transport objects, then fall back to a required supervision policy.
2. `restart_enabled = true` exposes `RestartMesh`, but the composition root does not restart mesh and instead exits immediately.
3. `topology.start_background_tasks()` and `routing_manager.start_background_tasks()` still run during construction outside structured ownership.
4. The registered YARA broadcast loop still launches detached per-message `tokio::spawn()` children.
5. Mesh-generation-specific support tasks start before required mesh startup succeeds.
6. Required startup failure is routed asynchronously through the coordinator even though the composition root already has the fatal result.
7. Startup status transitions are performed both by `start_mesh_generation()` and again through supervision events.
8. Current tests do not directly prove disabled-config construction suppression, restart-enabled behavior, or generation-safe support-task cleanup.

This pass should remove those contradictions and complete worker mesh supervision without reopening transport internals.

The central invariant is:

> Disabled mesh constructs and starts nothing. Enabled mesh starts one generation of owned work only after admission succeeds. Every exposed policy action corresponds to a real runtime action or is rejected at configuration time.

---

## Non-Goals

Do not redesign HTTP framing.

Do not change topology, DHT, Raft, or threat-intel semantics.

Do not implement unbounded restart loops.

Do not add a second worker supervisor.

Do not add public test-only APIs.

Do not refactor unrelated worker startup or shutdown code.

---

# Part A — Make Disabled Mesh Truly Construction-Free

## Phase 1 — Stop Constructing Mesh When `enabled = false`

In `src/worker/unified_server/init_mesh.rs`, inspect the external mesh config before converting it into the internal mesh config.

Required pattern:

```rust
let mesh_config_external = {
    let config = shared_config.read().await;
    config.main.tunnel.mesh.clone()
};

let Some(mesh_external) = mesh_config_external else {
    return MeshInit::disabled();
};

if !mesh_external.enabled {
    tracing::info!("Mesh disabled by configuration");
    return MeshInit::disabled();
}
```

Only then construct:

- internal mesh config;
- topology;
- routing manager;
- record store;
- transport manager;
- threat-intel mesh dependencies;
- DNS verification registries;
- YARA broadcast components.

## Phase 2 — Add `MeshInit::disabled()`

Implement one canonical constructor returning no runtime resources:

```rust
impl MeshInit {
    pub fn disabled() -> Self {
        Self {
            transport_manager: None,
            threat_intel: None,
            mesh_signer: None,
            canonical_snapshot: None,
            dns_verification_registries: Vec::new(),
            yara_broadcast: None,
            dht_routing_init: None,
            // any new owned task descriptors empty
        }
    }
}
```

Use it for:

- missing mesh config;
- `enabled = false`;
- early construction failures that should disable optional mesh.

## Phase 3 — Preserve Policy As `Option<MeshSupervisionPolicy>`

The policy builder already returns `None` for disabled mesh. Do not convert that to a required policy.

Replace:

```rust
build_mesh_supervision_policy(...)
    .unwrap_or_else(MeshSupervisionPolicy::required)
```

with:

```rust
let mesh_policy: Option<MeshSupervisionPolicy> =
    build_mesh_supervision_policy(mesh_enabled, &supervision_config);
```

Store one of:

```rust
pub mesh_policy: Option<MeshSupervisionPolicy>
```

or a dedicated enum:

```rust
pub enum WorkerMeshMode {
    Disabled,
    Enabled(MeshSupervisionPolicy),
}
```

Preferred: `WorkerMeshMode`, because it prevents accidental fallback construction.

## Phase 4 — Require Policy And Transport Together

Build the supervision runtime only when both are present:

```rust
match (&state.mesh_mode, mesh_transport) {
    (WorkerMeshMode::Disabled, None) => None,
    (WorkerMeshMode::Enabled(policy), Some(transport)) => Some(...),
    (WorkerMeshMode::Disabled, Some(_)) => invariant violation,
    (WorkerMeshMode::Enabled(_), None) => startup/configuration failure,
}
```

Do not infer enabled state solely from transport existence.

## Phase 5 — Add Disabled-Config Tests

Required cases:

- no mesh section -> `MeshInit::disabled()`;
- `enabled = false` -> no topology construction side effects;
- disabled config -> no transport manager;
- disabled config -> no observer/coordinator/startup/support tasks;
- disabled config -> status remains `Disabled`;
- disabled config -> worker readiness proceeds normally;
- disabled config never creates a required fallback policy.

Use counters/test constructors where needed to prove construction did not occur.

---

# Part B — Disable Restart Until A Real Executor Exists

The safest immediate correction is to make restart unavailable. Structured ownership is not yet generation-safe enough to support restart.

## Phase 6 — Reject `restart_enabled = true` During Validation

Add config validation:

```rust
if supervision.restart_enabled {
    return Err(ConfigError::Unsupported(
        "mesh.supervision.restart_enabled is not implemented"
    ));
}
```

If hard failure would break existing deployments, use:

- startup warning;
- force `restart_enabled = false`;
- reject only in strict validation mode.

Preferred: explicit validation error. A setting must not claim behavior the runtime does not implement.

## Phase 7 — Make `RestartMesh` Unreachable

Update `build_mesh_supervision_policy()` so it never returns `MeshFailureAction::RestartMesh`.

Required mapping while restart is disabled:

- required startup failure -> `ShutdownWorker`;
- optional startup failure -> `Degrade`;
- required critical exit -> `ShutdownWorker`;
- optional critical exit -> `Degrade`;
- required restartable background exit -> `ShutdownWorker` or `Degrade` by explicit policy;
- optional restartable exit -> `Degrade`.

Remove or quarantine:

- restart budget use in the live coordinator path;
- generation increments on `RestartMesh`;
- transition to `Restarting` from active decisions;
- composition-root `RestartMesh` branch that reports fake exhaustion.

The enum may remain for future work only if all production policy builders make it unreachable and a guard test proves that.

## Phase 8 — Correct Restart Exhaustion Semantics

Do not emit:

```rust
MeshRestartExhausted {
    attempts: 0,
    last_error: "restart not implemented"
}
```

That cause is false.

If an impossible `RestartMesh` decision reaches the composition root, treat it as an invariant failure:

```rust
WorkerShutdownCause::CriticalTaskExit(...)
```

or panic only in debug/test builds while returning a typed configuration/runtime invariant failure in production.

## Phase 9 — Add Restart-Disabled Tests

Required cases:

- config validation rejects `restart_enabled = true`;
- policy builder never emits `RestartMesh`;
- coordinator never transitions to `Restarting`;
- composition root contains no warning/error-only restart branch;
- no restart metrics increment in supported configurations;
- future re-enablement requires explicit acceptance-test changes.

---

# Part C — Move Topology And DHT Maintenance Under Structured Ownership

## Phase 10 — Remove Construction-Time Starts

Delete these calls from `init_mesh_and_threat_intel()`:

```rust
topology.start_background_tasks();
routing_manager.start_background_tasks();
```

Construction functions must construct only.

## Phase 11 — Refactor Components To Return Task Futures

Change topology and DHT APIs from internal spawning to owned task descriptors.

Preferred shape:

```rust
pub struct MeshBackgroundTaskSpec {
    pub name: &'static str,
    pub class: MeshTaskClass,
    pub future: Pin<Box<dyn Future<Output = Result<(), MeshTransportError>> + Send>>,
}
```

Or component-specific builders:

```rust
impl MeshTopology {
    pub fn build_background_tasks(
        self: &Arc<Self>,
        shutdown: watch::Receiver<bool>,
    ) -> Vec<MeshBackgroundTaskSpec>;
}
```

```rust
impl DhtRoutingManager {
    pub fn build_background_tasks(
        self: &Arc<Self>,
        shutdown: watch::Receiver<bool>,
    ) -> Vec<MeshBackgroundTaskSpec>;
}
```

Do not hide `tokio::spawn()` inside these methods.

## Phase 12 — Start Transport-Internal Loops During Transactional Mesh Startup

Register topology and DHT maintenance with `MeshTaskGroup` inside the mesh startup transaction.

Required ordering:

1. validate configuration/dependencies;
2. stage topology/DHT maintenance task specs;
3. start required listeners/runtime resources;
4. register staged background tasks with the startup generation;
5. commit startup only after all mandatory stages succeed.

On failure:

- signal cancellation;
- abort and await tasks;
- restore topology/DHT state if mutated;
- leave lifecycle `Stopped` or verified `Failed`.

## Phase 13 — Define Task Criticality

Classify explicitly:

- topology membership/maintenance loop: likely `RestartableBackground` or `CriticalService` depending on whether transport can safely serve without it;
- DHT maintenance loop: likely `RestartableBackground`;
- bootstrap/init one-shot: `OneShotStartup`;
- threat-intel mesh loop: classify according to required/optional policy.

Do not rely on task-name matching.

## Phase 14 — Remove Misleading Ownership Documentation

Update the ownership table only after code matches it.

The table must include:

- concrete owner;
- task class;
- generation scope;
- shutdown signal;
- join path;
- startup rollback path.

## Phase 15 — Add Ownership Tests

Required cases:

- construction alone starts no task;
- successful mesh startup starts exactly one topology loop generation;
- successful startup starts exactly one DHT maintenance generation when enabled;
- failed startup leaves zero topology/DHT tasks;
- shutdown joins all topology/DHT tasks;
- zero-budget shutdown aborts and awaits them;
- second startup after clean shutdown starts exactly one new generation;
- disabled mesh starts none.

Even though restart is disabled at the worker level, transport restartability should remain testable through explicit start/shutdown/start.

---

# Part D — Own YARA Broadcast Children

## Phase 16 — Replace Per-Message Detached Spawn With A `JoinSet`

Inside the registry-owned `yara_broadcast` task:

```rust
let mut children: JoinSet<()> = JoinSet::new();
```

On each message:

1. enforce configured concurrency;
2. acquire permit;
3. spawn child into `JoinSet`;
4. reap completed children through a `select!` branch.

Do not use bare `tokio::spawn()`.

## Phase 17 — Bound Intake Explicitly

The semaphore already bounds concurrent broadcasts. Keep it, but define behavior when saturated:

- wait for a permit while still responding to shutdown; or
- drop/coalesce according to explicit policy.

Preferred:

```rust
tokio::select! {
    permit = semaphore.acquire_owned() => ...,
    _ = shutdown.changed() => break,
    Some(result) = children.join_next(), if !children.is_empty() => ...,
}
```

Do not block shutdown indefinitely waiting for a permit.

## Phase 18 — Drain Children On Shutdown

When outer shutdown begins or the message channel closes:

1. stop accepting new messages;
2. wait for active children until a bounded deadline;
3. abort remaining children;
4. await every child;
5. return from the registered outer task only after `JoinSet` is empty.

Use the worker’s remaining shutdown budget if available. Otherwise use a documented local drain timeout.

## Phase 19 — Preserve Broadcast Errors

Classify child results:

- clean completion;
- transport error;
- panic;
- cancellation during shutdown.

At minimum, emit structured logs and counters. Do not silently discard failures.

## Phase 20 — Add YARA Ownership Tests

Required cases:

- concurrent children never exceed semaphore limit;
- shutdown while children active drains or aborts-and-awaits them;
- no child survives outer task return;
- channel close drains existing children;
- child panic is observed;
- zero-budget drain aborts and awaits all children.

---

# Part E — Start Generation-Specific Support Work Only After Mesh Startup

## Phase 21 — Split Support Tasks By Ownership And Dependency

Classify current Phase 13.5 tasks:

### Start after successful mesh startup

- DNS verification loops that require live mesh transport;
- YARA broadcast loop;
- DHT initialization if it assumes live transport/networking.

### May start independently

Only tasks proven independent of mesh lifecycle.

Do not start generation-specific work before the generation exists.

## Phase 22 — Add `MeshGenerationSupport` Runtime Bundle

Create a worker-owned bundle:

```rust
struct MeshGenerationSupport {
    generation: u64,
    task_ids: Vec<TaskId>,
}
```

Or a focused start helper:

```rust
async fn start_mesh_generation_support(
    state: &UnifiedServerWorkerState,
    mesh_init: &mut MeshInit,
    generation: u64,
) -> Result<MeshGenerationSupport, WorkerShutdownCause>
```

Required behavior:

- invoked only after mesh startup succeeds;
- registers all worker-owned support tasks;
- returns task IDs for diagnostics;
- can be cancelled/joined as a group during worker shutdown.

Because worker restart is disabled, one generation is sufficient now, but retain generation identity for future safety.

## Phase 23 — Keep DHT One-Shot Semantics Accurate

If DHT `init()` is required for successful mesh operation, it should be part of mesh startup, not an asynchronous worker one-shot after readiness.

Choose explicitly:

### Required DHT bootstrap

- await during mesh startup;
- failure causes rollback/startup failure.

### Advisory DHT bootstrap

- start after mesh success as one-shot;
- failure degrades mesh but does not invalidate startup.

Document the selected semantics and test them.

## Phase 24 — Add Startup-Order Tests

Required cases:

- required mesh startup blocked -> no generation support tasks yet;
- startup success -> support tasks start afterward;
- startup failure -> support tasks never start;
- optional mesh startup failure -> support tasks never start;
- disabled mesh -> support tasks never start;
- worker shutdown joins support tasks.

---

# Part F — Handle Required Startup Failure Directly

## Phase 25 — Return A Direct Startup Outcome

For required mesh startup, the composition root already has:

```rust
Result<(), MeshFailureCause>
```

On failure:

- update status once;
- set authoritative `SupervisionOutcome::DirectCause` immediately;
- skip ready message;
- skip normal runtime supervision loop;
- enter coordinated shutdown.

Do not depend on:

- sending `StartupFailed` to the coordinator;
- the coordinator receiving it;
- the decision channel remaining healthy.

## Phase 26 — Keep Metrics Without Asynchronous Round Trip

Call a direct metrics/status helper:

```rust
record_mesh_startup_failure(&status, &cause);
```

If the coordinator needs the event for observability, send it only as best-effort notification after the direct cause is already fixed. It must not control fatal startup handling.

## Phase 27 — Add Required Failure Tests

Required cases:

- startup failure produces direct typed cause;
- no ready message;
- normal supervision loop is not entered;
- coordinator failure cannot suppress startup failure;
- shutdown still joins observer/coordinator/support tasks;
- cause remains `MeshStartupFailed`, not generic critical-task exit.

---

# Part G — Make Status Transition Ownership Singular

## Phase 28 — Choose One Status Owner

Preferred model:

- runtime helpers return facts only;
- coordinator/event handlers mutate `WorkerMeshStatus` for runtime events;
- direct required-startup failure path mutates status because it bypasses coordinator.

Refactor `start_mesh_generation()` so it does not mutate status:

```rust
pub async fn start_mesh_generation(
    transport: &Arc<MeshTransport>,
    generation: u64,
) -> Result<MeshStartupFact, MeshFailureCause>
```

Where:

```rust
pub enum MeshStartupFact {
    Started { generation: u64 },
}
```

Or simply return `Result<(), MeshFailureCause>` and let caller transition status.

## Phase 29 — Avoid Duplicate `Started` And `StartupFailed` Transitions

For optional startup:

- one-shot task emits event;
- coordinator performs transition.

For required startup:

- composition root directly transitions status and handles fatal result;
- do not also send the same event unless event handling is idempotent and explicitly notification-only.

## Phase 30 — Add Transition Tests

Required cases:

- successful required startup updates `last_transition` once;
- failed required startup updates status once;
- optional startup event updates once;
- no duplicate restart-attempt or failure metrics;
- heartbeat observes stable phase after startup.

---

# Part H — Configuration And Runtime Invariant Guards

## Phase 31 — Add Explicit Invariant Checks

At composition-root setup:

```rust
match (mesh_enabled, mesh_policy.is_some(), transport.is_some()) {
    (false, false, false) => {}
    (true, true, true) => {}
    other => return Err(configuration/runtime invariant error),
}
```

Do not silently repair contradictions with fallback policy.

## Phase 32 — Validate Support Components Against Enabled State

When mesh is disabled, assert:

- DNS verification registries empty;
- YARA broadcast absent;
- DHT init absent;
- topology/DHT task specs empty;
- transport manager absent.

## Phase 33 — Add Guardrails

Update `tests/worker_mesh_supervision_boundary_guard.rs` to enforce:

- no `.unwrap_or_else(MeshSupervisionPolicy::required)` after policy builder;
- `init_mesh_and_threat_intel()` checks `enabled` before constructing runtime objects;
- no construction-time `start_background_tasks()` calls;
- no bare `tokio::spawn()` inside YARA broadcast loop;
- restart-enabled configuration is rejected or restart executor exists;
- required startup failure maps directly to shutdown outcome;
- generation support tasks start only after successful startup;
- status transitions have one owner.

Source guards supplement behavioral tests.

---

# Part I — File-Level Implementation Guide

## `src/worker/unified_server/init_mesh.rs`

Implement:

- early disabled return;
- `MeshInit::disabled()`;
- construction-only topology/DHT objects;
- no background starts;
- task specs/components returned for later ownership.

## `src/worker/unified_server/mod.rs`

Implement:

- optional/enum mesh policy state;
- strict policy/transport invariant checks;
- direct required-startup failure handling;
- support-task startup after mesh success;
- removal of restart no-op branch;
- YARA `JoinSet` ownership or delegated helper.

## `src/worker/mesh_supervision.rs`

Implement:

- restart-disabled policy behavior;
- removal of active `RestartMesh` path;
- single-owner status transitions;
- direct startup metrics helper if needed.

## `src/worker/task_registry.rs`

Add helper APIs if needed for:

- grouped generation support tasks;
- bounded child `JoinSet` task wrappers;
- querying task IDs by generation/prefix for tests.

## Topology/DHT components

Refactor:

- internal spawn methods into task-future builders;
- explicit shutdown receivers;
- returned joinable task specs.

## Configuration modules

Implement:

- restart unsupported validation;
- disabled mesh defaults;
- tests.

## Documentation

Update ownership tables only after code matches them.

---

# Part J — Ordered Execution Sequence For A Smaller Model

Implement in this exact order:

1. Add `MeshInit::disabled()` and early `enabled = false` return.
2. Preserve mesh policy as `Option`/`WorkerMeshMode`; remove required fallback.
3. Add policy/transport invariant checks and disabled-config tests.
4. Reject restart-enabled configuration and make `RestartMesh` unreachable.
5. Remove construction-time topology/DHT background starts.
6. Refactor topology/DHT loops into owned task specs.
7. Register those specs in transactional mesh startup.
8. Replace YARA child spawns with a local `JoinSet` and bounded drain.
9. Move generation-specific support task startup after mesh success.
10. Handle required startup failure directly.
11. Consolidate status transition ownership.
12. Add ownership, disabled-config, restart-disabled, and startup-order tests.
13. Add source guardrails.
14. Update documentation.

Do not implement real worker-level restart in this pass. First make one-generation ownership fully correct.

---

# Verification Commands

Run focused worker tests:

```bash
cargo test -p synvoid --lib worker::mesh_supervision --features mesh,dns
cargo test worker::unified_server --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
```

Run mesh ownership tests:

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

This corrective pass is complete only when all of the following are true:

1. `mesh.enabled = false` constructs no topology, routing, transport, DNS, YARA, or DHT runtime resources.
2. Disabled mesh creates no policy, observer, coordinator, startup task, support task, or shutdown call.
3. No required fallback policy is created from a disabled policy result.
4. `restart_enabled = true` is rejected until a real executor exists.
5. Production policy cannot emit `RestartMesh`.
6. No fake `MeshRestartExhausted { attempts: 0 }` path remains.
7. Topology and DHT maintenance do not start during construction.
8. Topology and DHT maintenance are owned by `MeshTaskGroup` and joined on rollback/shutdown.
9. YARA per-message broadcasts are owned in a `JoinSet` and drained or aborted-and-awaited.
10. Generation-specific support tasks start only after mesh startup succeeds.
11. Required startup failure produces a direct typed worker cause without entering normal supervision.
12. Required startup failure never emits ready.
13. Startup status transitions and metrics occur exactly once.
14. Construction-only tests prove no hidden tasks start before explicit lifecycle entry.
15. Shutdown tests prove no topology, DHT, DNS, YARA, or support child survives.
16. Explicit start/shutdown/start tests create exactly one generation each time.
17. Existing mesh transport, lifecycle, restoration, threat-intel, provenance, mesh-ID, and worker registry guardrails remain green.
18. Documentation accurately reflects actual owners and no longer claims ownership that code does not provide.

---

## Notes For The Implementer

This is a one-generation correctness pass.

Do not implement worker-level automatic restart until all generation-scoped work is demonstrably owned and repeatable.

Three rules govern the work:

> Disabled means no construction and no task creation.

> Construction methods return components or futures; lifecycle owners perform spawning.

> A configuration option is supported only when the composition root performs the promised runtime action.
