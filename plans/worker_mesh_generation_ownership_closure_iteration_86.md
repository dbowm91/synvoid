# Worker Mesh Generation Ownership Closure — Iteration 86

## Purpose

Iteration 85 corrected disabled-mesh construction, removed construction-time topology/DHT starts, disabled restart in production policy, made required startup failure direct, and replaced detached YARA child spawning with a local `JoinSet`.

The current head at `6710975ba7d005a723116c29b54884cd564d2e76` still has nine concrete defects:

1. DNS verification, YARA broadcasting, and DHT initialization are registered before required mesh startup succeeds.
2. Topology and routing maintenance are no longer started at all.
3. `MeshTopology` now self-manages hidden `JoinHandle`s instead of exposing lifecycle-owned task futures.
4. The unreachable `RestartMesh` branch still fabricates `MeshRestartExhausted { attempts: 0 }`.
5. YARA child draining is unbounded and permit acquisition is not cancellation-aware.
6. Policy/transport invariant mismatches only log and continue.
7. Optional startup does not transition status to `Starting`.
8. Required startup still transitions to `Running` directly and then emits `Started`, producing duplicate status mutation.
9. Restart-enabled configuration is silently overridden rather than rejected.

This pass should close one-generation ownership and startup sequencing. Automatic restart remains out of scope until generation ownership is fully proven.

The governing invariants are:

> No mesh-generation support task starts before the mesh generation commits successfully.

> Topology and DHT maintenance are owned by the mesh lifecycle, not by hidden internal handle stores.

> Every bounded child set drains to a deadline, aborts the remainder, and awaits every handle.

---

## Non-Goals

Do not implement worker-level automatic restart.

Do not redesign HTTP framing.

Do not change DHT/Raft consistency semantics.

Do not add a general task framework.

Do not introduce public test-only APIs.

---

# Part A — Move Generation Support Registration After Startup

## Phase 1 — Remove Phase 13.5 Pre-Startup Registration

Delete the current pre-start block that registers:

- DNS verification loops;
- YARA broadcast loop;
- DHT initialization.

These resources should remain inside `MeshInit` until startup succeeds.

## Phase 2 — Add `register_mesh_generation_support()`

Create a helper in `src/worker/unified_server/mod.rs` or a focused module:

```rust
#[cfg(feature = "mesh")]
async fn register_mesh_generation_support(
    state: &UnifiedServerWorkerState,
    mesh_init: &mut MeshInit,
    generation: u64,
    shutdown_deadline: Option<Instant>,
) -> Result<MeshGenerationSupport, WorkerShutdownCause>
```

Suggested result:

```rust
pub struct MeshGenerationSupport {
    pub generation: u64,
    pub task_ids: Vec<TaskId>,
}
```

Responsibilities:

- consume DNS registries, YARA receiver, and advisory DHT init descriptors exactly once;
- register all worker-owned support tasks;
- return task IDs for diagnostics/tests;
- fail if called twice for the same consumed resources.

## Phase 3 — Invoke Only After Successful Startup

Required mesh:

1. transition `Starting`;
2. await mesh startup;
3. transition `Running`;
4. register generation support;
5. send ready.

Optional mesh:

1. transition `Starting` before one-shot spawn;
2. startup task reports result;
3. on success, coordinator/composition root registers support;
4. on failure, support is never registered.

If support registration itself fails for required mesh, treat startup as failed and enter coordinated shutdown before ready.

## Phase 4 — Define DHT Init Semantics

Choose explicitly:

### Preferred

DHT initialization is required startup work and belongs inside the mesh startup transaction.

If that is too invasive for this pass:

### Acceptable

DHT init is advisory one-shot support registered only after mesh startup. Failure marks mesh degraded but does not invalidate startup.

Document and test the chosen semantics.

## Phase 5 — Add Startup-Order Tests

Required cases:

- required startup blocked -> no DNS/YARA/DHT support tasks;
- required startup succeeds -> support tasks appear afterward;
- required startup fails -> support tasks never start;
- optional startup pending -> no support tasks yet;
- optional startup fails -> no support tasks;
- disabled mesh -> no support tasks;
- support registration runs once per successful generation.

---

# Part B — Put Topology And DHT Maintenance Under `MeshTaskGroup`

## Phase 6 — Remove Internal Handle Ownership From `MeshTopology`

Delete or deprecate:

```rust
background_handles: Mutex<Vec<JoinHandle<()>>>
shutdown_tx: watch::Sender<bool>
```

unless the shutdown signal is supplied by the owning mesh lifecycle.

`MeshTopology` should not act as an independent task supervisor.

## Phase 7 — Replace `start_background_tasks()` With Task Builders

Add:

```rust
pub fn build_background_tasks(
    self: &Arc<Self>,
    shutdown: watch::Receiver<bool>,
) -> Vec<MeshBackgroundTaskSpec>
```

Suggested task descriptor:

```rust
pub struct MeshBackgroundTaskSpec {
    pub name: &'static str,
    pub class: MeshTaskClass,
    pub future: Pin<Box<dyn Future<Output = Result<(), MeshTransportError>> + Send>>,
}
```

Do the same for `DhtRoutingManager`.

No `tokio::spawn()` inside builders.

## Phase 8 — Register Specs During Transactional Startup

Inside `MeshTransport::start_with_policy()` or the appropriate startup stage:

1. build topology specs;
2. build DHT routing specs;
3. register each with `MeshTaskGroup` using the current generation;
4. record task IDs in `MeshStartupStage`;
5. rollback them on startup failure;
6. include their exits in the normal mesh exit stream.

## Phase 9 — Classify Task Criticality Explicitly

Recommended baseline:

- topology maintenance loop: `RestartableBackground` unless routing correctness requires fatality;
- DHT maintenance loop: `RestartableBackground`;
- mandatory bootstrap one-shot: startup-stage task, not long-lived background;
- optional advisory loops: `RestartableBackground`.

Do not classify by task-name strings.

## Phase 10 — Ensure Shutdown/Re-Start Semantics

On mesh shutdown:

- signal the shared mesh shutdown channel;
- drain task group to deadline;
- abort and await remaining topology/DHT tasks;
- leave zero hidden handles.

On explicit start/shutdown/start:

- exactly one new generation of each loop starts;
- no prior generation survives.

## Phase 11 — Add Ownership Tests

Required cases:

- constructing topology/routing starts zero tasks;
- successful mesh startup starts exactly one topology maintenance task;
- routing-enabled startup starts exactly one DHT maintenance task;
- startup failure rolls both back;
- shutdown drains both;
- zero-budget shutdown aborts and awaits both;
- second startup creates one new generation only;
- exit events contain typed topology/DHT task exits.

---

# Part C — Make YARA Child Ownership Fully Bounded

## Phase 12 — Extract A Dedicated YARA Loop Helper

Create:

```rust
async fn run_yara_broadcast_loop(
    mut broadcast_rx: mpsc::Receiver<MeshMessage>,
    mesh_transport: Arc<...>,
    semaphore: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
) -> YaraBroadcastReport
```

Suggested report:

```rust
pub struct YaraBroadcastReport {
    pub completed: usize,
    pub failed: usize,
    pub aborted: usize,
}
```

## Phase 13 — Make Permit Acquisition Cancellation-Aware

Do not await permit acquisition directly inside the receive branch.

Use a pending message state and `tokio::select!` over:

- shutdown signal;
- child completion;
- semaphore permit;
- next message only when no pending message exists.

A simpler acceptable implementation is to use `try_acquire_owned()` and drop/coalesce with explicit metrics when saturated.

## Phase 14 — Add Deadline-Bounded Drain

When shutdown or channel closure occurs:

1. stop intake;
2. compute drain deadline;
3. wait on `join_next()` with remaining timeout;
4. on deadline, call `abort_all()`;
5. await every remaining child;
6. return report.

Never perform an unbounded final `while let Some(...) = join_next().await`.

## Phase 15 — Preserve Child Failures

Classify:

- clean completion;
- transport error;
- panic;
- cancellation after explicit abort.

Return/report counts and emit low-cardinality metrics.

## Phase 16 — Add YARA Tests

Required cases:

- active children never exceed configured limit;
- shutdown during permit wait exits promptly;
- channel close drains children;
- hung child is aborted at deadline;
- every aborted child is awaited;
- panic increments failure count;
- zero timeout aborts immediately;
- no child survives outer task completion.

---

# Part D — Remove False Restart Semantics

## Phase 17 — Reject Restart Configuration

Change config validation so:

```rust
restart_enabled = true
```

returns an explicit configuration error.

Do not merely warn and override.

The error should state that restart is unsupported until generation ownership is complete.

## Phase 18 — Remove The Fake Exhaustion Branch

Delete the composition-root branch that emits:

```rust
MeshRestartExhausted {
    attempts: 0,
    last_error: "restart not implemented"
}
```

If `RestartMesh` remains in the enum for future work, handle it as an invariant violation:

```rust
WorkerShutdownCause::MeshSupervisionInvariantViolation(
    "RestartMesh reached while restart is disabled"
)
```

or make the branch unreachable in release-safe form.

## Phase 19 — Align Presets With Production Policy

`MeshSupervisionPolicy::optional()` currently advertises a positive restart limit while production policy disables restart.

Update presets so all supported constructors have:

```rust
restart_limit = 0
restartable_exit = Degrade or ShutdownWorker
```

Add tests proving no supported policy emits `RestartMesh`.

---

# Part E — Make Policy/Transport Invariants Fatal At Startup

## Phase 20 — Replace Log-Only Checks

Replace policy/transport mismatch logging with a returned startup error.

Invalid combinations:

- transport present, no policy;
- policy present, no transport.

Suggested cause:

```rust
WorkerShutdownCause::MeshConfigurationInvariant(String)
```

Do not continue to later `.expect()` calls.

## Phase 21 — Validate `MeshInit` Consistency

When disabled:

- no transport;
- no topology;
- no routing manager;
- no DNS registries;
- no YARA bundle;
- no DHT init descriptor.

When enabled:

- policy and transport both present;
- component set matches feature/config expectations.

Add one pure validation helper:

```rust
fn validate_mesh_runtime_inputs(
    mesh_init: &MeshInit,
    policy: Option<&MeshSupervisionPolicy>,
) -> Result<(), WorkerShutdownCause>
```

---

# Part F — Complete Status Transition Ownership

## Phase 22 — Optional Startup Must Enter `Starting`

Before spawning optional startup one-shot:

```rust
mesh_status.write().await.transition_starting();
```

Heartbeat should show `Starting` while the startup future is active.

## Phase 23 — Remove Duplicate Required Success Transition

Preferred flow:

- required startup caller transitions `Starting`;
- after success, caller transitions `Running`;
- do not emit `Started` to the coordinator for status mutation.

If an event is needed for metrics, add a notification-only event or ensure the coordinator does not mutate status for that event.

## Phase 24 — Keep Optional Event-Driven Transition

For optional startup:

- one-shot emits `Started` or `StartupFailed`;
- coordinator performs the only terminal transition.

Do not also mutate status inside the one-shot task.

## Phase 25 — Add Transition Tests

Required cases:

- optional startup reports `Starting` while blocked;
- required success updates `last_transition` once;
- optional success updates once;
- required failure updates once;
- no duplicate success/failure metrics;
- heartbeat observes stable final state.

---

# Part G — File-Level Implementation Guide

## `src/worker/unified_server/mod.rs`

Implement:

- post-start support registration;
- strict invariant failure;
- bounded YARA helper integration;
- fake restart branch removal;
- optional `Starting` transition;
- duplicate required transition removal.

## `src/worker/unified_server/init_mesh.rs`

Keep construction-only behavior and return unconsumed support descriptors/components for post-start registration.

## `src/worker/mesh_supervision.rs`

Implement:

- restart-disabled presets;
- notification/state-transition separation;
- optional startup status behavior;
- invariant-failure cause mapping if needed.

## `crates/synvoid-config/src/mesh.rs`

Reject unsupported restart configuration.

## `crates/synvoid-mesh/src/mesh/topology.rs`

Replace internal handle ownership with background task specs.

## `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs`

Expose DHT maintenance task specs and remove hidden spawning.

## `crates/synvoid-mesh/src/mesh/transport.rs`

Register topology/DHT specs inside transactional startup and own them in `MeshTaskGroup`.

## Tests

Add real startup/shutdown/start generation tests and bounded YARA tests.

---

# Part H — Ordered Execution Sequence For A Smaller Model

Implement in this exact order:

1. Reject restart-enabled config and remove fake exhaustion branch.
2. Align all policy presets with restart-disabled behavior.
3. Replace invariant logging with startup failure.
4. Move support-task registration after startup success.
5. Add optional `Starting` transition and remove duplicate required transition.
6. Extract bounded YARA loop helper and tests.
7. Remove topology internal handle ownership.
8. Expose topology/DHT task specs.
9. Register specs in transactional mesh startup.
10. Add start/failure/shutdown/start generation tests.
11. Add support ordering tests.
12. Update guardrails and documentation.

Do not implement worker restart in this pass.

---

# Part I — Guardrails

Update `tests/worker_mesh_supervision_boundary_guard.rs` and mesh ownership guards to enforce:

- support registration occurs only after startup success;
- no pre-start DNS/YARA/DHT registration block remains;
- topology/DHT builders do not call `tokio::spawn()`;
- topology stores no hidden `JoinHandle` registry;
- mesh startup registers topology/DHT specs with `MeshTaskGroup`;
- YARA final drain is deadline-bounded and uses `abort_all()`;
- permit acquisition is shutdown-aware;
- restart-enabled config is rejected;
- no fake `MeshRestartExhausted { attempts: 0 }` remains;
- policy/transport mismatch returns an error;
- optional startup transitions to `Starting`;
- required startup success is not transitioned twice.

Behavioral tests remain authoritative.

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

This pass is complete only when all of the following are true:

1. DNS, YARA, and advisory DHT support tasks start only after successful mesh startup.
2. Failed or disabled startup creates no generation support tasks.
3. Topology and DHT maintenance run exactly once per successful mesh generation.
4. Topology and DHT maintenance are owned by `MeshTaskGroup` and emit typed exits.
5. No hidden topology/DHT `JoinHandle` registry remains.
6. Startup rollback leaves zero topology/DHT tasks.
7. Shutdown and zero-budget shutdown await or abort-and-await every topology/DHT task.
8. YARA permit acquisition is shutdown-aware.
9. YARA child drain is deadline-bounded and aborts/awaits all remnants.
10. No YARA child survives outer task completion.
11. Unsupported restart configuration is rejected.
12. Production policy cannot emit `RestartMesh`.
13. No fake zero-attempt restart-exhaustion cause remains.
14. Policy/transport mismatches fail startup rather than logging and continuing.
15. Optional startup reports `Starting` while in progress.
16. Required startup success and failure each mutate status exactly once.
17. Explicit start/shutdown/start creates exactly one new support generation.
18. Existing mesh transport, restoration, threat-intel, provenance, mesh-ID, and worker lifecycle guardrails remain green.
19. Documentation accurately identifies the owner and generation scope of every mesh-adjacent task.

---

## Notes For The Implementer

This is the final one-generation ownership closure pass.

Three rules govern the implementation:

> Start support work only after the generation commits.

> Components return task futures; lifecycle owners perform spawning and joining.

> Unsupported policy settings fail validation instead of being silently rewritten.
