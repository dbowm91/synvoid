# Mesh Transport Lifecycle Corrective Pass — Iteration 69

## Purpose

Iteration 68 established the first mesh-local lifecycle framework: `MeshTaskGroup`, `MeshLifecycleState`, cancellation-aware periodic loops, bounded handshake concurrency, peer-child draining, `MeshShutdownReport`, and a worker-facing managed-service contract.

The review of `5b793a67833e28fffc1a5b433680d88dc7d6cf0d` identified several correctness gaps that must be addressed before the mesh lifecycle track can be considered complete:

1. Startup is not actually transactional. Tasks are spawned before later fallible startup stages, but post-spawn errors can return without rollback, leaving detached tasks and lifecycle state stuck at `Starting`.
2. `MeshTaskGroup` exit accounting can discard another task's exit event while searching by name, causing panic/error metadata to be lost.
3. Successful pre-shutdown critical-task returns are classified as clean rather than `UnexpectedCompletion`.
4. The worker-facing critical-exit subscription is a disconnected stub.
5. The legacy `running` boolean can disagree with `MeshLifecycleState`.
6. `peer_message_loop` remains detached after handshake completion.
7. `MeshShutdownReport` does not accurately report peer-child drainage or remaining peers.
8. Guardrails and tests currently prove structural presence more than runtime correctness.

This pass should correct those issues without broadening into mesh protocol changes.

The invariant is:

> Mesh startup is all-or-nothing, every task exit retains its true reason, every long-lived mesh task remains owned until termination, and the worker receives real critical mesh failures.

## Current Known State

At `5b793a67833e28fffc1a5b433680d88dc7d6cf0d`:

- `MeshTransport::start()` transitions to `Starting` and creates a local `MeshTaskGroup`.
- `mesh_maintenance` and `datagram_listener` are started before seed/peer/DHT bootstrap.
- seed, explicit-peer, and DHT bootstrap failures are logged and ignored.
- `runtime.start_server()` can fail after many tasks have started.
- the local task group is only stored after all startup phases complete.
- dropping the unstored local task group drops handles and detaches tasks.
- `MeshTaskGroup::join_all()` drains an internal broadcast receiver by task name.
- unmatched exit events are discarded.
- task wrappers return `JoinHandle<()>` and emit exit metadata on a side channel.
- task wrappers classify successful pre-shutdown completion as `CleanCompletion`.
- `ManagedMeshService::subscribe_critical_exits()` returns a fresh disconnected receiver.
- `MeshTransport::subscribe_exits()` is async and subscribes through the current task group.
- `ManagedMeshService::is_running()` reads the legacy boolean.
- `start()` commits `MeshLifecycleState::Running` but does not visibly synchronize the legacy boolean.
- the accept loop owns handshake tasks, but `peer_message_loop` is spawned detached after handshake completion.
- `MeshShutdownReport::remaining_peers` is populated from the pre-clear count.
- accept-loop child drain/abort counts are not propagated into the report.

## Non-Goals

Do not redesign mesh protocol semantics.

Do not change DHT/Raft consistency boundaries.

Do not alter peer authentication, TLS policy, blocklist, threat-intel, or membership semantics.

Do not introduce background-task restart policy in this iteration.

Do not move all mesh internals into the worker task registry.

Do not change request-path behavior.

Do not add new transport protocols.

## Phase 1 — Make Task Handles Return `MeshTaskExit`

Remove the fragile side-channel lookup pattern from `MeshTaskGroup`.

Current shape:

```rust
JoinHandle<()>
```

plus:

```rust
broadcast::Sender<MeshTaskExit>
```

and later name-based lookup.

Required shape:

```rust
JoinHandle<MeshTaskExit>
```

Each wrapper should return its own exit record directly:

```rust
async move {
    let result = AssertUnwindSafe(future).catch_unwind().await;
    let exit = classify_mesh_task_exit(name, class, result, shutdown_started);
    let _ = exit_tx.send(exit.clone());
    exit
}
```

Then `join_all()` reads the exact exit from the joined handle.

Required consequences:

- remove `exit_rx` from `MeshTaskGroup` unless needed for supervision only;
- remove `drain_exit_for()`;
- no exit event can be discarded while joining another task;
- panic/error/unexpected completion metadata remains task-specific;
- shutdown reports use the handle-returned exit as the source of truth.

## Phase 2 — Add Result-Aware Spawn APIs

Current spawn APIs only accept `Future<Output = ()>`, so `MeshTaskExitReason::Error` cannot be produced naturally.

Add APIs such as:

```rust
pub fn spawn_critical<F, E>(...)
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Display + Send + 'static;
```

and equivalent background/child APIs.

If maintaining unit-returning convenience APIs is useful, provide both:

```rust
spawn_critical_unit(...)
spawn_critical_result(...)
```

Required classification:

- `Ok(Ok(()))` before shutdown:
  - `CriticalService` -> `UnexpectedCompletion`
  - `RestartableBackground` -> `UnexpectedCompletion`
  - `BoundedChild` -> `CleanCompletion`
  - `OneShotStartup` -> `CleanCompletion`
- `Ok(Ok(()))` after shutdown -> `Cancelled` or `CleanCompletion`, according to documented convention.
- `Ok(Err(e))` -> `Error(e.to_string())`.
- panic -> `Panic`.

Do not classify every successful return as clean.

## Phase 3 — Make Critical Exit Supervision Stable Across Task-Group Replacement

Add a stable exit broadcaster directly to `MeshTransport`:

```rust
mesh_exit_tx: broadcast::Sender<MeshTaskExit>
```

Construct it in `MeshTransport::new()`.

Every task group created for a startup attempt should receive a clone of this sender.

Required API:

```rust
pub fn subscribe_exits(&self) -> broadcast::Receiver<MeshTaskExit>
```

This must be synchronous and valid before `start()`.

Remove the disconnected receiver in `ManagedMeshService::subscribe_critical_exits()` and delegate to the stable transport sender.

Required semantics:

- subscribers can attach before startup;
- startup-attempt task failures are observable;
- replacing the task group does not replace the exit channel;
- a failed startup cannot strand subscribers on an obsolete channel.

## Phase 4 — Filter Critical Exits Correctly

The worker-facing method is named `subscribe_critical_exits()` but the current task-group sender emits all exits.

Choose one explicit model:

### Preferred

Expose all exits:

```rust
fn subscribe_exits(&self) -> broadcast::Receiver<MeshTaskExit>
```

and let worker code filter with `exit.is_fatal()`.

### Acceptable

Maintain a dedicated critical-exit sender populated only for fatal critical exits.

Do not retain a method name implying critical-only behavior if it emits all exits.

## Phase 5 — Implement A Real Startup Staging Object

Introduce an owned staging object that contains every task and resource started during one startup attempt.

Suggested shape:

```rust
struct MeshStartupStage {
    task_group: MeshTaskGroup,
    runtime_started: bool,
    listeners_started: bool,
    committed: bool,
}
```

or:

```rust
struct MeshStartupGuard<'a> {
    transport: &'a MeshTransport,
    group: Option<MeshTaskGroup>,
    committed: bool,
}
```

Required behavior:

- the staging object owns every started task;
- no task group is dropped without cancellation and join;
- commit transfers the fully initialized group into `MeshTransport`;
- rollback is explicit and async;
- rollback runs on every post-spawn error path.

Because async cleanup cannot run in `Drop`, do not rely on `Drop` alone. Use an explicit staged startup function returning a commit object or a single error funnel.

## Phase 6 — Refactor `start()` Into A Single Error Funnel

Refactor startup into:

```rust
pub async fn start(&self) -> Result<(), MeshTransportError> {
    self.transition_to_starting().await?;

    match self.start_staged().await {
        Ok(stage) => self.commit_startup(stage).await,
        Err(err) => {
            self.rollback_startup(err).await
        }
    }
}
```

All fallible work after the first task spawn must flow through rollback.

Required rollback sequence:

1. Mark staged task-group shutdown intent.
2. Broadcast cancellation.
3. Stop staged listeners/runtime resources where possible.
4. Abort and await remaining staged tasks within a bounded rollback timeout.
5. Close staged peer connections.
6. Clear partial peer/topology state created by the attempt where appropriate.
7. Set lifecycle state to `Failed` while reporting rollback diagnostics.
8. Transition to `Stopped` after rollback completes if immediate retry is supported.
9. Ensure the authoritative running state is false.
10. Return the original startup error, optionally enriched with rollback failures.

## Phase 7 — Define Fatal Versus Degraded Bootstrap Policy

Current bootstrap errors are always warnings.

Make policy explicit for each startup stage:

### Seed Bootstrap

Decide based on role/configuration:

- required for non-genesis nodes -> fatal startup error;
- optional for isolated/genesis/test mode -> degraded but allowed.

### Configured Peer Connections

- required peers may be fatal;
- optional peers may warn and continue.

### DHT Bootstrap

- if DHT is enabled and required for the node role, failure should be fatal or explicitly degraded;
- if DHT is optional, record degraded startup state.

Introduce explicit configuration/policy helpers rather than inferring from empty lists.

Suggested outcome:

```rust
pub struct MeshStartupPolicy {
    pub require_seed_connectivity: bool,
    pub require_configured_peers: bool,
    pub require_dht_bootstrap: bool,
}
```

Document which roles use which defaults.

## Phase 8 — Support Degraded Startup Explicitly

If some bootstrap failures remain nonfatal, do not silently call the service fully healthy.

Options:

- add `MeshLifecycleState::RunningDegraded`;
- retain `Running` and store a `MeshServiceHealth::Degraded` reason;
- emit a nonfatal startup report.

Suggested report:

```rust
pub struct MeshStartupReport {
    pub degraded_reasons: Vec<String>,
    pub connected_seed_count: usize,
    pub connected_configured_peer_count: usize,
    pub dht_bootstrapped: bool,
}
```

The worker should be able to observe degraded startup separately from fatal startup failure.

## Phase 9 — Unify Lifecycle State Authority

Remove or strictly synchronize the legacy `running: Arc<RwLock<bool>>`.

Preferred outcome:

- derive `is_running()` from `MeshLifecycleState`;
- remove the boolean where feasible.

If compatibility requires the boolean temporarily:

- update it only inside lifecycle transition helpers;
- set true exactly when transition to `Running` commits;
- set false before/while transitioning to `Stopping`, `Failed`, or `Stopped`;
- add tests proving no divergence.

`ManagedMeshService::is_running()` should use the authoritative state.

If a sync method is required, consider storing lifecycle state in an atomic representation or using a dedicated atomic running projection updated by the state machine.

## Phase 10 — Make Startup Commit Atomic From The Service Perspective

Commit order should prevent externally visible half-running state.

Recommended order:

1. All required bootstrap and runtime startup succeeds.
2. Stable exit sender is already active.
3. Task group is transferred into transport ownership.
4. Runtime/listener handles are stored.
5. Lifecycle state transitions to `Running`.
6. Running projection becomes true.
7. Startup report is published.

Do not transition to `Running` before the task group is stored.

If storing the group can fail or block, complete that before the state transition.

## Phase 11 — Own `peer_message_loop` Tasks

The successful handshake path currently detaches `peer_message_loop`.

Introduce a transport-owned peer-session task group.

Possible designs:

### A. MeshTaskGroup Child Registration

Allow tasks spawned from cloned transport instances to register a bounded child through a shared task-group handle.

### B. Dedicated PeerSessionTaskGroup

Store:

```rust
peer_sessions: Arc<Mutex<JoinSet<MeshTaskExit>>>
```

or retained named handles.

Required behavior:

- every peer message loop has a retained handle;
- session task is associated with peer/session ID for diagnostics;
- connection close causes normal session completion;
- shutdown closes connections, then drains session tasks;
- remaining sessions are aborted and awaited;
- peer/session tasks cannot survive completed shutdown.

Avoid using dynamic peer IDs as unbounded metrics labels.

## Phase 12 — Clarify Handshake Child Versus Session Child Ownership

The accept loop currently owns only the handshake future.

Define two distinct task classes:

- handshake child: bounded, short-lived, semaphore-limited;
- peer session child: long-lived for connection lifetime.

The handshake task should either:

- transfer ownership of the live session task to the transport session group; or
- itself remain alive and run the session loop, so the accept loop child group owns the full connection lifetime.

Preferred: explicit transfer to a session group, because handshake concurrency and live peer-session concurrency are different limits.

## Phase 13 — Make Shutdown Report Truthful

Correct `MeshShutdownReport` semantics.

### Remaining Peers

Set:

```rust
report.remaining_peers = self.peer_connections.len();
```

after close/clear/drain completes.

If reporting peers present at shutdown start is useful, add a separate field:

```rust
pub peers_at_shutdown_start: usize
```

### Handshake Children

Have the accept loop return structured completion metadata:

```rust
pub struct MeshAcceptLoopReport {
    pub drained_handshakes: usize,
    pub aborted_handshakes: usize,
    pub rejected_at_capacity: usize,
}
```

The task handle should return this value, or publish it through an owned report channel.

### Peer Sessions

Add:

```rust
pub drained_peer_sessions: usize,
pub aborted_peer_sessions: usize,
```

if session ownership is introduced.

Do not leave report fields permanently zero when actual activity occurred.

## Phase 14 — Improve Task-Group Join Semantics

Use one direct exit value per handle.

Suggested internal type:

```rust
struct NamedMeshTask {
    name: &'static str,
    class: MeshTaskClass,
    handle: JoinHandle<MeshTaskExit>,
}
```

On timeout:

1. abort handle;
2. await aborted handle;
3. produce `Aborted` if no more specific terminal result exists.

Use a shared deadline across all tasks, but consider class ordering:

1. critical services;
2. peer sessions/children;
3. background tasks.

Document why that order is chosen.

## Phase 15 — Preserve Immediate Exit Supervision Without Double Accounting

The stable broadcast channel provides immediate observation, while joined handles provide authoritative final exit values.

Avoid double counting by:

- assigning `MeshTaskId` values;
- storing observed IDs in a small dedup map/set;
- treating handle return as the authoritative shutdown report value;
- treating broadcast delivery as runtime notification only.

Suggested type:

```rust
pub struct MeshTaskId(u64);
```

Add ID to `MeshTaskExit`.

## Phase 16 — Wire Worker Supervision For Real

Integrate mesh service exit subscription into the unified worker composition root.

Required sequence:

1. Obtain stable mesh exit receiver before `mesh.start()`.
2. Start mesh.
3. Select mesh exit events alongside worker registry and lifecycle events.
4. Ignore expected shutdown exits after coordinated shutdown begins.
5. Treat fatal critical mesh exits as worker-fatal.
6. Preserve task name/reason in worker shutdown cause and supervisor notification.
7. During worker shutdown, call mesh bounded shutdown before final supervisor completion acknowledgement.

Suggested worker cause:

```rust
WorkerShutdownCause::MeshServiceExit(MeshTaskExit)
```

or map through a typed `MeshFailureCause`.

Do not flatten mesh failure into a generic string if the task metadata is available.

## Phase 17 — Integrate Startup Failure And Degraded Startup Into Worker Policy

Worker composition root should distinguish:

- fatal mesh startup failure;
- degraded mesh startup;
- successful healthy startup.

Recommended behavior:

- fatal failure -> worker startup fails and rolls back already-started worker services;
- degraded startup -> worker may continue, but health/metrics reflect degraded mesh;
- healthy startup -> normal operation.

Document node-role-specific policy.

## Phase 18 — Correct Shutdown Ordering With Worker

Worker shutdown ordering should include mesh explicitly:

1. record worker shutdown intent;
2. stop external request intake;
3. stop mesh from accepting new peers;
4. stop mesh periodic producers;
5. close/drain peer sessions;
6. join/abort mesh tasks;
7. continue worker persistence/finalization;
8. send supervisor completion acknowledgement last.

Mesh shutdown report failures should be logged and may influence final worker exit status for unexpected shutdown causes.

## Phase 19 — Fix Guardrail Weaknesses

Strengthen `tests/mesh_task_ownership_guard.rs`.

Current structural checks can pass despite missing rollback.

Add checks that:

- every `?` or `return Err` after the first mesh task spawn flows through a rollback helper;
- `runtime.start_server()` failure cannot directly escape after tasks start;
- local staged task groups are never dropped uncommitted;
- `subscribe_critical_exits()` does not create a new disconnected broadcast channel;
- `peer_message_loop` is not spawned with bare `tokio::spawn()`;
- `drain_exit_for()` no longer exists;
- pre-shutdown critical unit completion maps to `UnexpectedCompletion`;
- `remaining_peers` is measured after shutdown;
- accept-loop child counts reach `MeshShutdownReport`.

Behavioral tests remain authoritative.

## Phase 20 — Add Failure-Injection Hooks

Introduce test-only or trait-based hooks for deterministic startup failure.

Needed failure points:

- after first critical task spawn;
- seed bootstrap;
- configured peer connection;
- DHT bootstrap;
- runtime server start;
- lifecycle commit;
- worker mesh subscription/start handoff.

Avoid tests that depend on random port conflicts or external network availability.

## Phase 21 — Startup Rollback Tests

Required tests:

### Runtime Start Failure After Tasks Spawn

- start critical/background tasks;
- inject runtime start failure;
- assert `start()` returns error;
- assert all staged tasks terminate;
- assert no counters continue changing;
- assert lifecycle is not `Starting` or `Running`;
- assert running projection is false;
- assert retry can succeed.

### Required Seed Failure

- configure required seed connectivity;
- inject seed failure;
- assert rollback and fatal startup result.

### Optional Seed Failure

- configure optional seed policy;
- assert startup succeeds with degraded report.

### DHT Bootstrap Failure

- test both required and optional policy modes.

### Commit Failure

- inject state/commit failure after runtime starts;
- assert rollback closes runtime and all tasks.

## Phase 22 — Exit Accounting Tests

Add tests proving no exit metadata loss.

Scenarios:

- two tasks finish before join; one panics and one completes;
- join order differs from exit order;
- each returned exit retains its own reason;
- no event is discarded;
- immediate broadcast and final join share the same task ID;
- no duplicate accounting.

Add explicit tests for:

- critical unit return before shutdown -> `UnexpectedCompletion` and fatal;
- critical result error -> `Error` and fatal;
- background unit return before shutdown -> unexpected but nonfatal;
- bounded child completion -> clean;
- post-shutdown completion -> expected.

## Phase 23 — Peer Session Ownership Tests

Required scenarios:

- successful handshake transfers session ownership;
- session loop exits when connection closes;
- shutdown drains active sessions;
- hung session is aborted and awaited;
- no detached session survives completed shutdown;
- handshake capacity and session capacity are independently enforced if both limits exist.

## Phase 24 — Worker Integration Tests

Required scenarios:

- worker subscribes before mesh startup;
- critical mesh task fails immediately after startup and worker observes it;
- fatal mesh exit becomes `WorkerShutdownCause::MeshServiceExit` or equivalent;
- background mesh exit does not stop worker;
- worker shutdown awaits mesh shutdown before acknowledgement;
- mesh startup failure triggers worker startup rollback;
- degraded mesh startup produces degraded health but not fatal exit where policy allows.

## Phase 25 — Documentation Corrections

Update:

- `architecture/mesh_transport_lifecycle.md`
- `architecture/mesh.md`
- `architecture/worker_task_lifecycle.md`
- `skills/synvoid_mesh.md`
- `AGENTS.md`
- `crates/synvoid-mesh/AGENTS.override.md` if present

Correct any statement that currently claims:

- startup rollback is complete;
- worker critical-exit subscription is active;
- every peer child is owned;
- shutdown report child counts are authoritative.

After implementation, document:

- staged startup/rollback;
- required versus optional bootstrap policy;
- stable exit subscription;
- task ID/dedup semantics;
- handshake/session ownership split;
- truthful shutdown report fields;
- worker integration and failure policy.

## Phase 26 — Suggested Implementation Sequence

Implement in this order:

1. Change task handles to return `MeshTaskExit`.
2. Add task IDs and dedup semantics.
3. Add result-aware spawn APIs and correct `UnexpectedCompletion` classification.
4. Add stable transport-level exit sender.
5. Replace disconnected worker subscription.
6. Add startup staging/rollback object.
7. Refactor all post-spawn errors through rollback.
8. Define required/degraded bootstrap policy.
9. Unify lifecycle state and running projection.
10. Own peer message/session loops.
11. Correct shutdown reporting.
12. Wire worker supervision and shutdown integration.
13. Strengthen tests, guardrails, and docs.

Do not begin worker integration until stable exit publication and startup rollback are correct.

## Phase 27 — Verification Commands

Run:

```bash
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh task_group
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh shutdown
cargo test -p synvoid-mesh --features mesh worker_integration
cargo test --test mesh_lifecycle_tests
cargo test --test mesh_task_ownership_guard
cargo test --test worker_supervision_control_flow
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh -- -D warnings
```

If worker shutdown-cause types or startup wiring change:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This corrective iteration is complete when:

1. No post-spawn startup error can return without rollback.
2. Runtime-start failure after task spawn terminates every staged task.
3. Lifecycle state cannot remain stuck at `Starting` after failed startup.
4. Retry after rolled-back startup is supported where policy allows.
5. Every joined task returns its own exact `MeshTaskExit`.
6. No task exit event can be discarded while joining another task.
7. Pre-shutdown critical completion is classified as `UnexpectedCompletion`.
8. Result-returning tasks can produce `MeshTaskExitReason::Error`.
9. Mesh exit subscription is stable before and across startup attempts.
10. Worker composition root receives real fatal mesh exits.
11. Legacy `running` state cannot disagree with `MeshLifecycleState`.
12. `peer_message_loop` and other live peer-session tasks are owned and joined.
13. Shutdown report peer and child counts reflect actual post-shutdown state.
14. No mesh-owned task survives failed startup or completed shutdown.
15. Required versus optional bootstrap failure policy is explicit and tested.
16. Existing blocklist, threat-intel, provenance, mesh-ID, composition, and worker lifecycle guardrails remain green.

## Notes for the Implementer

This is a corrective lifecycle pass, not a mesh feature pass.

The highest-priority fixes are:

1. real rollback for every post-spawn startup failure;
2. direct per-handle exit accounting;
3. stable worker-visible exit publication.

Do not rely on dropped `JoinHandle`s, shared-name exit lookup, or disconnected placeholder receivers. The desired end state is a mesh service whose startup, supervision, and shutdown guarantees are mechanically true rather than documentary.