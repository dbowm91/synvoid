# Worker Mesh DHT and Support-Generation Closure — Iteration 87

## Purpose

Iteration 86 completed most of the worker/mesh ownership architecture:

- topology and DHT maintenance now expose declarative task specs;
- those specs are staged inside `MeshTaskGroup` during transactional startup;
- DNS, YARA, and DHT support work is delayed until mesh startup succeeds;
- YARA children are owned in a `JoinSet` with bounded drain and abort-and-await fallback;
- restart configuration is rejected;
- policy/transport mismatches fail startup;
- optional startup reports `Starting`;
- required startup no longer performs the prior duplicate `Started` event transition.

The current head at `c71ab5954bd6fb93afe14708b3ab8557b84c337e` still has one correctness blocker and several closure items:

1. DHT routing initialization occurs only as a worker one-shot after mesh startup, while transport Phase 6 attempts DHT bootstrap before the routing table exists.
2. Worker-owned support tasks are not represented as a generation bundle, so optional mesh failure cannot stop DNS/YARA support without shutting down the whole worker.
3. The new YARA tests do not exercise the real helper under timeout, saturation, panic, or forced-abort conditions.
4. Topology/DHT ownership tests mostly use synthetic specs instead of the real builders.
5. YARA overload drops are not observable through metrics.
6. Some ownership documentation says “post-startup” even though topology/DHT maintenance is staged before commit during transactional startup.
7. `MeshBackgroundTaskSpec` documentation inaccurately says the future “takes” a shutdown receiver even though the receiver is already captured.

This pass should correct the DHT ordering defect and finish support-generation ownership and direct behavioral proof.

The governing invariants are:

> The DHT routing table must exist before any bootstrap or maintenance operation can mutate or inspect it.

> Every worker-owned mesh support task belongs to a named generation and can be stopped independently when that generation fails.

> Closure tests must invoke production helpers and real component builders, not only equivalent synthetic futures.

---

## Non-Goals

Do not implement worker-level automatic mesh restart.

Do not redesign DHT routing semantics.

Do not change Raft or canonical ownership.

Do not reopen HTTP framing or peer-session lifecycle work.

Do not add a general-purpose worker subregistry framework beyond the minimum generation-support primitive.

---

# Part A — Move DHT Initialization Into Transactional Mesh Startup

## Phase 1 — Remove Worker-Owned `dht_routing_init`

Delete DHT routing initialization from `register_mesh_generation_support()`:

```rust
registry.spawn_one_shot("dht_routing_init", async move {
    manager.init().await;
});
```

`MeshSupportTasks` should no longer carry `dht_routing_manager` solely for initialization.

If the worker still needs a reference for diagnostics, keep it separately from support-task ownership.

## Phase 2 — Add An Explicit DHT Initialization Startup Stage

Inside `MeshTransport::run_startup_phases()` add a stage before DHT bootstrap.

Recommended order:

```text
Phase 3.x: initialize or restore DHT routing table
Phase 4: bootstrap transport seeds
Phase 5: connect configured peers
Phase 6: bootstrap DHT from connected seeds
Phase 7: register topology/DHT maintenance specs
```

Suggested helper:

```rust
async fn initialize_dht_routing(
    &self,
    stage: &mut MeshStartupStage,
    policy: &MeshStartupPolicy,
    report: &mut MeshStartupReport,
) -> Result<(), MeshTransportError>
```

## Phase 3 — Make Initialization Idempotent And State-Aware

Add an explicit routing-manager state query:

```rust
pub async fn is_initialized(&self) -> bool
```

or:

```rust
pub async fn initialization_state(&self) -> DhtInitializationState
```

Required behavior:

- disabled routing -> no-op;
- already initialized from persisted state -> do not overwrite;
- uninitialized -> create a routing table;
- invalid persisted state -> fail or degrade according to startup policy;
- repeated start after clean shutdown must not accidentally retain stale generation state unless persistence policy explicitly requires it.

## Phase 4 — Track DHT Initialization In Startup Staging

Extend `MeshStartupStage` with an explicit DHT initialization marker or snapshot:

```rust
pub struct DhtInitializationSnapshot {
    pub was_initialized: bool,
    pub persisted_before: Option<PersistedRoutingTable>,
}
```

The stage must know whether initialization mutated routing state.

On rollback:

- restore the prior persisted table if one existed;
- otherwise return routing state to uninitialized/empty;
- verify the rollback result.

Do not infer DHT mutation from task registration.

## Phase 5 — Correct DHT Bootstrap Preconditions

Before `dht_bootstrap_from_seeds()`:

```rust
if !routing_manager.is_initialized().await {
    return Err(MeshTransportError::StartupFailed(
        "DHT bootstrap attempted before routing initialization".into()
    ));
}
```

This is a hard invariant, not a debug assertion.

`add_peer()` should also stop silently returning when uninitialized. Prefer one of:

```rust
pub async fn add_peer(...) -> Result<bool, DhtRoutingError>
```

or a narrower checked method used during startup.

At minimum, startup bootstrap must detect the uninitialized state before attempting insertion.

## Phase 6 — Decide Required Versus Advisory Initialization

Add or reuse startup policy fields:

```rust
pub require_dht_initialization: bool
pub require_dht_bootstrap: bool
```

Recommended default:

- routing enabled -> initialization required;
- bootstrap may remain advisory unless explicitly required.

Initialization failure must not be reported as successful degraded startup if no routing table exists but DHT maintenance is then started.

## Phase 7 — Add DHT Ordering Tests

Required production-path tests:

- routing table exists before Phase 6 bootstrap;
- connected seed is inserted during bootstrap;
- bootstrap cannot report success while routing state is absent;
- disabled routing skips initialization/bootstrap/maintenance;
- initialization failure triggers rollback;
- rollback restores prior persisted routing state;
- successful start registers DHT maintenance only after initialization;
- start/shutdown/start initializes one valid routing generation each time;
- no worker-owned `dht_routing_init` task remains.

---

# Part B — Add Worker-Owned Mesh Support Generation Bundles

## Phase 8 — Introduce `MeshGenerationSupport`

Add a worker-owned support-generation type:

```rust
#[cfg(feature = "mesh")]
pub struct MeshGenerationSupport {
    pub generation: u64,
    pub task_ids: Vec<TaskId>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
}
```

Alternative:

```rust
pub struct MeshGenerationSupport {
    pub generation: u64,
    pub task_ids: Vec<TaskId>,
    pub cancellation: CancellationToken,
}
```

Use the cancellation primitive already established in the worker registry where possible.

## Phase 9 — Give Support Tasks A Generation-Specific Stop Signal

Do not rely only on the whole-worker registry shutdown token.

DNS verification and YARA support tasks should select over:

- worker shutdown;
- generation cancellation.

Suggested helper:

```rust
pub struct MeshGenerationStop {
    worker_shutdown: watch::Receiver<bool>,
    generation_shutdown: watch::Receiver<bool>,
}
```

Each support task exits when either signal fires.

## Phase 10 — Return The Bundle From Registration

Change:

```rust
async fn register_mesh_generation_support(...) -> ()
```

to:

```rust
async fn register_mesh_generation_support(
    ...,
    generation: u64,
) -> Result<MeshGenerationSupport, WorkerShutdownCause>
```

Required behavior:

- register every support task under the worker registry;
- collect task IDs;
- return the generation cancellation handle;
- fail cleanly if any mandatory support task cannot be registered;
- do not partially return an untracked generation.

## Phase 11 — Store The Active Support Generation

The worker composition root should hold:

```rust
let mut active_mesh_support: Option<MeshGenerationSupport> = None;
```

On required startup success:

- register support;
- store bundle;
- then send ready.

On optional startup success:

- register support;
- store bundle through a coordinator/runtime message rather than losing it inside an unobserved one-shot closure.

Preferred design: optional startup reports a typed startup result to the composition root, which performs support registration centrally.

## Phase 12 — Stop Support On Optional Mesh Failure

When optional mesh transitions to failed/degraded due to a critical transport exit:

1. signal the active generation support bundle;
2. await or verify support-task completion to a bounded deadline;
3. clear `active_mesh_support`;
4. then leave the worker in degraded state.

DNS and YARA work must not continue targeting a failed transport.

## Phase 13 — Add A Registry Subset Join Primitive

Add the minimum worker-registry API needed to wait for known task IDs:

```rust
pub async fn cancel_and_join_tasks(
    &mut self,
    task_ids: &[TaskId],
    timeout: Duration,
) -> WorkerTaskJoinReport
```

If per-task cancellation is not supported by current wrappers, generation cancellation can make tasks exit cooperatively, while the registry API only waits/verifies those IDs.

Do not remove unrelated tasks from registry ownership.

## Phase 14 — Support Generation Tests

Required cases:

- required startup success creates one support bundle;
- optional startup success creates one support bundle;
- startup failure creates none;
- optional critical mesh failure stops DNS/YARA support while worker remains running;
- whole-worker shutdown also stops active support;
- calling stop twice is idempotent;
- no support task survives bundle teardown;
- task IDs belong to the expected generation;
- future explicit start/shutdown/start can create a new bundle without old tasks surviving.

---

# Part C — Strengthen YARA Production-Helper Tests

## Phase 15 — Make The YARA Helper Testable Without Concrete Transport Coupling

Extract the broadcast action behind a crate-private trait or closure:

```rust
#[async_trait]
trait YaraBroadcastSink: Send + Sync {
    async fn broadcast(&self, msg: MeshMessage);
}
```

Production adapter wraps `MeshTransport`.

Alternatively make the helper generic over:

```rust
F: Fn(MeshMessage) -> Fut + Send + Sync
```

Keep the API private to the worker module.

## Phase 16 — Test The Real `run_yara_broadcast_loop()`

Required direct tests:

- normal child completion increments `completed`;
- child panic increments `failed`;
- hung child is aborted after drain timeout;
- aborted child increments `aborted`;
- zero drain timeout aborts immediately;
- shutdown while semaphore is saturated exits promptly;
- channel closure drains active children;
- concurrency never exceeds permit count;
- helper returns only after `JoinSet` is empty;
- dropped-on-overload messages increment a counter.

Do not replace these with tests of raw `mpsc`, `Semaphore`, or synthetic `JoinSet` behavior.

## Phase 17 — Add YARA Overload Metrics

Add bounded metrics:

```text
yara_mesh_broadcast_submitted_total
yara_mesh_broadcast_completed_total
yara_mesh_broadcast_failed_total
yara_mesh_broadcast_aborted_total
yara_mesh_broadcast_dropped_total
```

No node IDs, peer IDs, rule IDs, or raw errors in labels.

The drop policy remains acceptable if explicit and observable.

---

# Part D — Test Real Topology And DHT Builders

## Phase 18 — Replace Synthetic Spec Tests

Current tests manually construct `MeshBackgroundTaskSpec` values. Retain one generic task-group registration test, but add direct component tests:

```rust
let specs = topology.build_background_tasks(shutdown_rx);
```

and:

```rust
let specs = routing_manager.build_background_tasks(shutdown_rx);
```

Assert real names, classes, and counts.

## Phase 19 — Test Real Builder Shutdown

For topology:

- construct a real minimal topology;
- register actual specs in a `MeshTaskGroup`;
- begin shutdown;
- join;
- verify both exits are cancelled/expected.

For DHT:

- initialize a real routing manager;
- register actual specs;
- shutdown and join;
- verify all expected loops exit.

## Phase 20 — Test Transactional Startup Integration

Use the real `MeshTransport` startup fixture and assert:

- topology spec task names appear in active task group;
- DHT spec task names appear only when routing enabled;
- injected failure after Phase 7 rolls them back;
- commit transfers them to transport ownership;
- shutdown reports contain their exits;
- second generation receives globally unique task IDs.

---

# Part E — Documentation And Type Cleanup

## Phase 21 — Correct `MeshBackgroundTaskSpec` Documentation

Replace wording equivalent to:

> “The future takes a shutdown receiver.”

with:

> “The future is fully constructed by the component builder and captures the lifecycle-owned shutdown receiver.”

## Phase 22 — Correct Startup-Phase Language

Documentation should distinguish:

- topology/DHT maintenance: staged during transactional startup before commit;
- worker support tasks: registered after successful mesh commit;
- readiness: sent only after required transport and mandatory support registration succeed.

Do not call topology/DHT maintenance “post-startup.”

## Phase 23 — Document DHT Initialization Semantics

Document:

- initialization/restore stage;
- bootstrap precondition;
- required/advisory policy;
- rollback behavior;
- maintenance registration after successful initialization;
- no worker-owned routing-init task.

## Phase 24 — Document Optional Failure Teardown

Describe that optional mesh may leave the worker serving in degraded mode, but its generation-specific DNS/YARA support is stopped immediately when the transport generation fails.

---

# Part F — File-Level Implementation Guide

## `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- DHT initialization/restore stage before Phase 6;
- bootstrap precondition checks;
- startup report fields for DHT initialization;
- rollback integration;
- removal of assumptions that worker initializes routing later.

## `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs`

Implement:

- explicit initialization-state query;
- checked initialization;
- checked peer insertion or startup-specific error path;
- rollback/restore helper if needed;
- direct builder tests.

## `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update:

- startup stage/report fields;
- accurate `MeshBackgroundTaskSpec` documentation.

## `src/worker/unified_server/mod.rs`

Implement:

- remove DHT init from support registration;
- `MeshGenerationSupport` lifecycle;
- central optional-startup success handling;
- support teardown on optional mesh failure;
- YARA metric wiring.

## `src/worker/task_registry.rs`

Add:

- task-ID subset wait/verification helper;
- optional generation cancellation support if required.

## Tests

Add direct production-helper and real-builder tests.

---

# Part G — Ordered Execution Sequence For A Smaller Model

Implement in this exact order:

1. Move DHT initialization into transactional mesh startup.
2. Add initialization-state and bootstrap-precondition checks.
3. Remove worker-owned `dht_routing_init`.
4. Add rollback and start/shutdown/start DHT tests.
5. Introduce `MeshGenerationSupport` and generation cancellation.
6. Centralize optional-startup support registration in the composition root.
7. Stop support generation on optional mesh failure.
8. Add registry subset join/verification.
9. Extract a testable YARA broadcast sink.
10. Add direct YARA helper tests and drop metrics.
11. Replace synthetic topology/DHT tests with real builder tests.
12. Add real transactional startup integration tests.
13. Correct documentation and guardrails.

Do not implement worker-level restart in this pass.

---

# Part H — Guardrails

Update worker and mesh boundary guards to enforce:

- `routing_manager.init()` is not spawned from worker support registration;
- DHT initialization occurs before `dht_bootstrap_from_seeds()`;
- bootstrap has an explicit initialized-state check;
- DHT maintenance specs are registered only after successful initialization;
- optional mesh failure tears down generation support;
- support tasks have a generation-specific cancellation path;
- direct YARA helper tests exist;
- YARA drop metrics exist;
- tests call real topology/DHT builders;
- documentation distinguishes staged startup tasks from post-commit worker support.

Behavioral tests remain authoritative.

---

# Verification Commands

Run focused mesh tests:

```bash
cargo test -p synvoid-mesh --features mesh dht
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Run focused worker tests:

```bash
cargo test -p synvoid --lib worker::mesh_supervision --features mesh,dns
cargo test worker::unified_server --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
```

Run broader checks:

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

---

# Acceptance Criteria

This pass is complete only when all of the following are true:

1. DHT routing state is initialized or restored before bootstrap.
2. Bootstrap cannot silently operate against an absent routing table.
3. Connected seed peers are inserted during bootstrap.
4. DHT initialization participates in startup rollback.
5. No worker-owned `dht_routing_init` task remains.
6. DHT maintenance starts only after successful initialization.
7. Worker support tasks are represented by a named generation bundle.
8. Optional mesh failure stops DNS/YARA support without stopping unrelated worker tasks.
9. Support teardown is bounded, idempotent, and leaves no surviving task IDs.
10. Direct tests invoke the real YARA helper under saturation, panic, timeout, and abort.
11. YARA overload drops are observable through metrics.
12. Direct tests invoke real topology and DHT background-task builders.
13. Transactional startup tests prove real builder tasks roll back and commit correctly.
14. Start/shutdown/start produces one valid DHT and support generation each time.
15. Documentation accurately distinguishes staged mesh tasks from post-commit worker support.
16. Existing mesh transport, worker supervision, restoration, threat-intel, provenance, and lifecycle guardrails remain green.

---

## Notes For The Implementer

This is the final correction before subsystem closure.

Three rules govern the implementation:

> Initialize state before bootstrapping or starting maintenance against it.

> Optional service degradation must stop generation-specific support work.

> Tests should call the same helpers and builders production uses.
