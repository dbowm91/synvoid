# Mesh Transport Polish and Worker-Level Supervision — Iteration 82

## Purpose

Iteration 81 completed the mesh transport/lifecycle subsystem as an ownership and framing architecture. The current head at `918d228bced3c5bc23c1870ff1b80eabec2a6701` now has:

- transactional mesh startup and rollback;
- restart-safe failed-state recovery;
- owned top-level, session, stream, datagram, and auxiliary tasks;
- bounded shutdown with zero-budget abort-and-await semantics;
- verified topology and DHT restoration;
- complete HTTP/1.x request/response framing for the supported contract;
- informational-response handling;
- bounded chunked, fixed-length, and close-delimited response bodies;
- lifecycle-state-gated auxiliary submission;
- production-path shutdown/recovery race tests.

The mesh transport itself should no longer be treated as the primary architectural problem. The next meaningful target is to integrate the mesh service into the existing worker supervision root so that mesh failures affect worker health, readiness, restart/escalation policy, and process exit semantics in one authoritative place.

This plan has two parts:

1. A small, explicitly bounded mesh transport/lifecycle polish pass.
2. Worker-level mesh supervision integration using the existing `WorkerTaskRegistry`, `WorkerShutdownCause`, `SupervisionOutcome`, `ManagedMeshService`, and unified worker lifecycle coordinator.

The central invariant is:

> The mesh transport owns and reports its internal lifecycle; the worker composition root owns the decision about whether a reported mesh condition is healthy, degradable, restartable, or fatal for the worker process.

---

## Current Architectural Seams

The repository already contains most of the required primitives.

### Mesh side

`ManagedMeshService` exposes:

```rust
fn subscribe_critical_exits(&self) -> broadcast::Receiver<MeshTaskExit>;
async fn start(&self) -> Result<(), MeshTransportError>;
async fn shutdown(&self, timeout: Duration) -> MeshShutdownReport;
fn is_running(&self) -> bool;
```

`MeshFailureCause` already models:

- critical service exit;
- startup failure;
- shutdown timeout.

`MeshServiceHealth` already sketches:

- `Healthy`;
- `Degraded`;
- `Failed`.

### Worker side

`WorkerTaskRegistry` already provides:

- critical/background task registration;
- exit broadcast subscription;
- shutdown classification;
- bounded join/abort;
- `WorkerShutdownCause::MeshServiceExit`;
- `SupervisionOutcome`;
- process exit-code mapping;
- supervisor-notification policy.

The unified worker lifecycle already coordinates:

- IPC lifecycle requests;
- shutdown intent ordering;
- `WorkerLifecycleEvent`;
- acknowledgement before critical task completion;
- health and heartbeat reporting.

The implementation should use these seams. Do not add a second, mesh-specific worker supervisor loop running independently of the existing composition-root loop.

---

## Non-Goals

Do not redesign mesh transport internals.

Do not add a general-purpose service orchestration framework.

Do not introduce automatic infinite restart loops.

Do not make every mesh background-task exit fatal.

Do not change DHT/Raft ownership boundaries.

Do not add mesh hot reload.

Do not change process-manager semantics outside the worker exit/shutdown cause already used by Synvoid.

Do not create duplicate health/readiness endpoints if an authoritative worker health surface already exists.

---

# Part A — Final Mesh Transport/Lifecycle Polish

This section must remain narrow. Complete it before worker supervision integration so worker policy observes clean transport semantics.

## Phase 1 — Reject Malformed Response Header Lines

In `crates/synvoid-mesh/src/mesh/transport_peer.rs`, change response-header parsing so that:

- the first line is explicitly parsed as the status line;
- every subsequent non-empty line must contain `:`;
- obsolete line folding is rejected;
- a malformed header line returns `HttpResponseFramingError` rather than being skipped.

Suggested error:

```rust
MalformedHeaderLine(String)
```

Do not silently ignore malformed lines, because backend/client parser disagreement can become a request-smuggling or response-splitting surface.

## Phase 2 — Reject Coalesced Bytes After No-Body Final Responses

For final responses that must not contain a body:

- `HEAD` request responses;
- status `1xx` where applicable to the sequence parser;
- `204`;
- `304`;

reject a non-empty `body_prefix` after the header terminator.

Suggested error:

```rust
UnexpectedBodyBytesForNoBodyResponse {
    status: u16,
    observed: usize,
}
```

This enforces the one-response-per-stream contract and prevents silently discarding pipelined or ambiguous bytes.

Important: informational responses are processed by the sequence parser. Their following bytes belong to the next response and must remain in the persistent sequence buffer. Apply this rejection only after identifying the final response and its request-method/status semantics.

## Phase 3 — Enforce Header Limit In The Pure Parser

`try_parse_http_response_head()` accepts `max_header_bytes`. Enforce:

```rust
if header_end > max_header_bytes {
    return Err(HttpResponseFramingError::HeaderTooLarge);
}
```

The async reader already limits input, but the pure parser must uphold its own contract for direct callers and tests.

## Phase 4 — Use Saturating Deadline Arithmetic

Replace any pattern that computes:

```rust
deadline.duration_since(Instant::now())
```

before checking expiry with:

```rust
let now = Instant::now();
if now >= deadline { ... }
let remaining = deadline.saturating_duration_since(now);
```

Apply consistently in request/response framing helpers.

## Phase 5 — Correct Generic Auxiliary Metrics

`spawn_auxiliary_task()` is generic but currently emits `edge_refresh_*` metrics for all task kinds.

Choose one:

### Preferred

Add task-kind-aware metrics:

```rust
match kind {
    AuxiliaryTaskKind::EdgeReplicaRefresh => ...,
    AuxiliaryTaskKind::PreflightRoute => ...,
    AuxiliaryTaskKind::Other => ...,
}
```

Keep labels low-cardinality. A fixed `kind` label is acceptable if the metrics framework supports bounded enum labels.

### Acceptable

Move edge-refresh-specific counters to the edge-refresh call site and keep only generic `mesh_auxiliary_*` counters in the helper.

## Phase 6 — Avoid Spawning Rejected Auxiliary Wrappers

The current gated wrapper is safe, but it is created before lifecycle/capacity admission.

Because `auxiliary_submission_lock` serializes submission, simplify the order:

1. acquire submission lock;
2. validate lifecycle state;
3. perform dedup/capacity checks;
4. abort and await stale tasks;
5. create gated wrapper;
6. insert `Running` entry;
7. open gate;
8. release lock.

Rejected user futures must never execute, and rejected submissions should not create a Tokio task or publish a cancellation event.

Do not weaken the existing insertion-before-execution guarantee.

## Phase 7 — Add Deterministic Race Hooks

The current production-path race tests are valuable but scheduler-dependent.

Add private `#[cfg(test)]` barriers at one or two critical points:

- after acquiring `auxiliary_submission_lock` and before lifecycle state check;
- after admission and before registry insertion;
- after insertion and before gate release.

Use an internal optional hook structure, for example:

```rust
#[cfg(test)]
struct AuxiliarySubmissionTestHooks {
    after_lock: Option<Arc<Barrier>>,
    before_insert: Option<Arc<Barrier>>,
    before_gate_release: Option<Arc<Barrier>>,
}
```

Do not expose production public APIs.

## Phase 8 — Add Focused Polish Tests

Required cases:

- malformed response header line rejected;
- folded response header rejected;
- pure parser enforces header limit directly;
- final `204` with coalesced bytes rejected;
- final `304` with coalesced bytes rejected;
- `HEAD` response with coalesced bytes rejected;
- generic auxiliary metrics do not misclassify preflight tasks as edge refreshes;
- lifecycle/capacity rejection creates no wrapper task;
- deterministic shutdown-versus-submission interleaving;
- deterministic recovery-versus-submission interleaving.

After these tests pass, stop modifying mesh transport unless worker integration reveals a concrete contract defect.

---

# Part B — Define Worker-Level Mesh Supervision Policy

## Phase 9 — Create One Explicit Policy Type

Add a worker-side policy type, preferably in:

```text
src/worker/mesh_supervision.rs
```

or a focused module under `src/worker/unified_server/`.

Suggested shape:

```rust
#[cfg(feature = "mesh")]
#[derive(Debug, Clone)]
pub struct MeshSupervisionPolicy {
    pub required: bool,
    pub startup_failure: MeshFailureAction,
    pub critical_exit: MeshFailureAction,
    pub restartable_exit: MeshFailureAction,
    pub restart_limit: u32,
    pub restart_window: Duration,
    pub restart_backoff_initial: Duration,
    pub restart_backoff_max: Duration,
    pub readiness_requires_mesh: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshFailureAction {
    Ignore,
    Degrade,
    RestartMesh,
    ShutdownWorker,
}
```

Do not infer policy from task names in multiple locations. Centralize it.

## Phase 10 — Define Default Policy By Deployment Role

Determine policy from authoritative worker/mesh configuration.

Recommended baseline:

### Mesh required

For workers whose role requires mesh participation:

- startup failure -> `ShutdownWorker`;
- unexpected critical mesh exit -> `ShutdownWorker` after bounded restart policy is exhausted, or immediately if restart is not yet enabled;
- restartable background exit -> `Degrade` or bounded `RestartMesh` only when the transport remains internally consistent;
- readiness requires mesh healthy/running.

### Mesh optional

For configurations where local serving may continue without mesh:

- startup failure -> `Degrade`;
- critical exit -> `Degrade` or bounded restart;
- readiness may remain true if local serving is safe;
- health must clearly expose degraded mesh state.

Do not silently default required mesh to optional behavior.

## Phase 11 — Define Exit Classification From Typed Fields

Classify `MeshTaskExit` using:

- `MeshTaskClass`;
- `MeshTaskExitReason`;
- transport lifecycle state;
- shutdown intent;
- supervision policy.

Do not classify primarily by string task name.

Recommended rules:

```text
CriticalService + Panic/Error/UnexpectedCompletion => critical failure
CriticalService + CleanCompletion while worker running => unexpected critical failure
CriticalService + Cancelled/Aborted during coordinated shutdown => expected
RestartableBackground + Error/Panic => degraded or restart candidate
RestartableBackground + CleanCompletion while running => unexpected background completion
Any task exit after worker shutdown intent => expected unless cleanup report says otherwise
```

## Phase 12 — Represent Worker-Observed Mesh State

Add a worker-owned state object separate from the transport’s internal lifecycle:

```rust
#[derive(Debug, Clone)]
pub struct WorkerMeshStatus {
    pub phase: WorkerMeshPhase,
    pub health: MeshServiceHealth,
    pub last_exit: Option<MeshTaskExit>,
    pub restart_attempts: u32,
    pub last_transition: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerMeshPhase {
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

Store it in the unified worker state or a dedicated `Arc<RwLock<...>>` owned by the composition root.

The transport remains authoritative for its internal state. The worker state is the policy/health projection.

---

# Part C — Subscribe Before Mesh Start

## Phase 13 — Establish The Subscription Ordering In The Composition Root

The worker composition root must:

1. construct the mesh service;
2. call `subscribe_critical_exits()`;
3. register the worker-side mesh observer/supervisor task;
4. only then call `mesh.start()`.

This prevents missing early bind/listener/task exits during startup.

Add an explicit comment and guardrail around this ordering.

## Phase 14 — Add A Worker Mesh Exit Observer

The observer should be a worker-owned critical or policy-controlled task registered in `WorkerTaskRegistry`.

Suggested function:

```rust
#[cfg(feature = "mesh")]
pub fn spawn_mesh_exit_observer(
    registry: &mut WorkerTaskRegistry,
    mesh: Arc<dyn ManagedMeshService>,
    exits: broadcast::Receiver<MeshTaskExit>,
    status: Arc<RwLock<WorkerMeshStatus>>,
    control_tx: mpsc::Sender<MeshSupervisionEvent>,
) -> TaskId
```

The observer’s job is only to:

- receive mesh exit events;
- handle lag/closure explicitly;
- forward typed supervision events;
- stop on worker shutdown token.

Do not perform restart/shutdown orchestration directly inside the broadcast receive loop.

## Phase 15 — Handle Broadcast Lag And Closure

For `RecvError::Lagged(n)`:

- increment a metric;
- query mesh lifecycle/running state;
- mark status degraded because events were lost;
- request reconciliation from the coordinator;
- do not assume the missed event was harmless.

For `RecvError::Closed` while worker is running:

- treat it as supervision infrastructure failure;
- escalate according to required/optional policy;
- do not silently stop observing.

During coordinated shutdown, channel closure is expected.

---

# Part D — Add A Single Mesh Supervision Coordinator

## Phase 16 — Define Supervision Events

Create:

```rust
#[derive(Debug)]
pub enum MeshSupervisionEvent {
    Started,
    StartupFailed(String),
    TaskExit(MeshTaskExit),
    ExitStreamLagged(u64),
    ExitStreamClosed,
    RestartTimerElapsed { generation: u64 },
    WorkerShutdownStarted,
}
```

Use a bounded `mpsc` channel.

## Phase 17 — Run Policy Decisions In The Worker Composition Root

Integrate mesh events into the existing worker supervision `tokio::select!` or add one registered coordinator task whose output becomes a typed `WorkerShutdownCause`.

Preferred outcome model:

```rust
pub enum MeshSupervisorDecision {
    NoAction,
    MarkDegraded(String),
    RestartMesh,
    ShutdownWorker(MeshFailureCause),
}
```

The decision function should be mostly pure and unit-testable:

```rust
fn decide_mesh_action(
    policy: &MeshSupervisionPolicy,
    status: &WorkerMeshStatus,
    event: &MeshSupervisionEvent,
    worker_shutdown_started: bool,
) -> MeshSupervisorDecision
```

## Phase 18 — Map Fatal Mesh Failure Into Existing Worker Causes

Use the existing:

```rust
WorkerShutdownCause::MeshServiceExit(MeshTaskExit)
```

for critical task exits.

For startup failure or shutdown timeout, either:

### Preferred

Extend `WorkerShutdownCause` with typed variants:

```rust
MeshStartupFailed(String)
MeshShutdownIncomplete(MeshShutdownReportSummary)
```

### Acceptable

Add a broader:

```rust
MeshFailure(MeshFailureCause)
```

and migrate `MeshServiceExit` into it if the change remains contained.

Avoid encoding startup/shutdown failures as synthetic `MeshTaskExit` values unless required for backward compatibility.

Update:

- `nonzero_exit_code()`;
- `should_notify_supervisor()`;
- `is_expected()`;
- `Display`;
- tests.

## Phase 19 — Preserve Existing Lifecycle Acknowledgement Ordering

When mesh failure causes worker shutdown:

1. call `WorkerTaskRegistry::begin_shutdown()` before shared stop flags;
2. mark worker mesh phase `Stopping` or `Failed`;
3. notify supervisor using the existing direct-cause path;
4. stop intake/drain requests;
5. invoke mesh bounded shutdown;
6. join worker tasks;
7. exit with typed cause.

Do not route direct mesh failure through an IPC lifecycle event that requires an acknowledgement sender unless the existing composition-root contract explicitly does so.

---

# Part E — Startup Integration

## Phase 20 — Treat Mesh Startup As A Managed Worker Startup Phase

At worker startup:

1. set worker mesh phase `Starting`;
2. subscribe and start observer;
3. call `mesh.start()`;
4. on success:
   - phase `Running`;
   - health `Healthy`;
   - publish readiness according to policy;
5. on failure:
   - capture `MeshFailureCause::StartupFailed`;
   - set `Failed` or `Degraded`;
   - apply policy;
   - if fatal, enter coordinated worker shutdown rather than returning through an unrelated error path.

## Phase 21 — Avoid Startup Event Races

The observer may receive a critical exit while `mesh.start()` is still returning.

Use a startup generation or coordinator state so that:

- the first fatal condition wins;
- duplicate startup error + critical exit does not initiate two shutdowns;
- status retains both diagnostics where useful;
- only one `WorkerShutdownCause` becomes authoritative.

Suggested field:

```rust
mesh_generation: u64
```

Include it in coordinator-owned restart/start attempts, even if mesh internal exits do not expose it directly.

## Phase 22 — Define Worker Readiness During Startup

For required mesh:

- worker readiness remains false until mesh phase is `Running` and health is `Healthy` or explicitly allowed `Degraded`.

For optional mesh:

- readiness may become true after local listeners are ready;
- mesh degradation must be observable separately.

Do not conflate process liveness with readiness.

---

# Part F — Health, Readiness, And Supervisor Reporting

## Phase 23 — Add Mesh Health To Worker State

Extend `UnifiedServerWorkerState` or its metrics/health projection with mesh fields:

```rust
mesh_enabled: bool
mesh_required: bool
mesh_phase: WorkerMeshPhase
mesh_healthy: bool
mesh_degraded: bool
mesh_restart_attempts: u32
mesh_last_failure: Option<String>
```

Keep high-cardinality task/session details out of metrics labels.

## Phase 24 — Expose Mesh Health In Heartbeats

The heartbeat task should snapshot worker mesh status and include it in the authoritative worker health payload or an adjacent IPC message.

Preferred approach:

- extend the worker heartbeat payload if protocol compatibility permits;
- otherwise send a dedicated bounded `MeshHealth` IPC message.

Required semantic distinctions:

- mesh disabled;
- starting;
- healthy;
- degraded but serving;
- failed/fatal;
- restarting;
- stopping.

Do not reduce all states to one boolean if the IPC schema can support a typed enum.

## Phase 25 — Integrate With Readiness

Locate the worker readiness/health endpoint or internal readiness gate.

Required policy:

```text
required mesh + not Running/Healthy => not ready
optional mesh + local service healthy => ready but degraded
worker shutdown started => not ready
mesh restarting and required => not ready
```

Add tests for each combination.

## Phase 26 — Add Metrics

Suggested bounded counters/gauges:

- `mesh_worker_health_state` gauge by bounded state enum;
- `mesh_worker_exit_events_total` by task class/reason category;
- `mesh_worker_restart_attempts_total`;
- `mesh_worker_restart_exhausted_total`;
- `mesh_worker_supervision_lagged_total`;
- `mesh_worker_startup_failures_total`;
- `mesh_worker_shutdown_incomplete_total`.

Do not label with node ID, peer ID, task ID, or raw error text.

---

# Part G — Bounded Restart Policy

Implement restart only after basic fatal/degraded supervision is correct. Keep restart bounded and explicit.

## Phase 27 — Restart Preconditions

A mesh restart may be attempted only when:

- worker shutdown has not begun;
- policy action is `RestartMesh`;
- transport lifecycle is `Stopped` or recoverable `Failed`;
- previous mesh shutdown/recovery completed;
- restart budget remains;
- no concurrent restart is active.

If transport is `Failed`, call `recover_failed_state()` before `start()`.

Expose recovery in `ManagedMeshService` if worker code should remain decoupled:

```rust
async fn recover(&self, timeout: Duration) -> Result<(), MeshTransportError>;
async fn lifecycle_state(&self) -> MeshLifecycleState;
```

Alternatively add a single:

```rust
async fn prepare_restart(&self, timeout: Duration) -> Result<(), MeshTransportError>;
```

Prefer the narrowest worker-facing contract.

## Phase 28 — Add Restart Budget Tracking

Use a sliding window or simple timestamp deque:

```rust
struct RestartBudget {
    attempts: VecDeque<Instant>,
    limit: u32,
    window: Duration,
}
```

Before restart:

- remove attempts older than window;
- reject when count >= limit;
- record accepted attempt once;
- increment generation.

Recommended default: conservative, such as 3 attempts in 5 minutes.

## Phase 29 — Add Exponential Backoff With Jitter

Suggested:

```rust
backoff = min(initial * 2^attempt, max)
```

Add bounded jitter.

The timer must be worker-owned and cancellable by shutdown.

Do not `sleep()` inside a critical receive loop while blocking other supervision events. Use a timer future or separate registered background task that emits `RestartTimerElapsed`.

## Phase 30 — Cancel Stale Restart Timers

Include a restart generation in timer events.

Ignore a timer when:

- generation no longer matches;
- worker shutdown started;
- mesh already running;
- another fatal cause became authoritative.

## Phase 31 — Restart Result Policy

On successful restart:

- set phase `Running`;
- set health `Healthy`;
- preserve cumulative restart counter;
- clear transient last failure only if policy says so;
- restore readiness when required conditions hold.

On failed restart:

- record failure;
- schedule next attempt if budget remains;
- otherwise emit fatal `WorkerShutdownCause`.

Do not loop indefinitely.

---

# Part H — Shutdown Integration

## Phase 32 — Make Mesh Shutdown An Explicit Worker Shutdown Phase

During coordinated worker shutdown:

1. set worker readiness false;
2. call worker task registry `begin_shutdown()`;
3. prevent new mesh supervision/restart actions;
4. set mesh phase `Stopping`;
5. invoke `ManagedMeshService::shutdown(remaining_deadline)`;
6. classify `MeshShutdownReport`;
7. continue worker task/server drain;
8. include incomplete mesh cleanup in final process exit cause/report.

Use one worker shutdown deadline, not a fresh mesh timeout independent of the caller’s deadline.

## Phase 33 — Classify Shutdown Reports

Define a helper:

```rust
fn classify_mesh_shutdown_report(
    report: &MeshShutdownReport,
) -> MeshShutdownDisposition
```

Suggested:

```rust
pub enum MeshShutdownDisposition {
    Clean,
    ForcedButComplete,
    Incomplete(MeshFailureCause),
}
```

Interpretation:

- aborted internal tasks but zero remaining resources may be `ForcedButComplete`;
- remaining peers/resources or failed tasks may be incomplete;
- child-session forced parent abort diagnostics should be surfaced.

Do not treat every abort as fatal if cleanup was nevertheless complete and shutdown was already expected.

## Phase 34 — Avoid Double Shutdown

The worker coordinator must ensure mesh shutdown is invoked once per mesh generation.

Use:

- coordinator phase;
- generation;
- or `OnceCell`/stored shutdown future result.

A fatal mesh exit and external worker shutdown arriving concurrently must converge on one shutdown path.

---

# Part I — File-Level Implementation Guide

## `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Polish only:

- reject malformed response header lines;
- reject unexpected bytes after final no-body responses;
- enforce pure-parser header limit;
- saturating deadline arithmetic;
- focused tests.

## `crates/synvoid-mesh/src/mesh/transport.rs`

Polish only:

- task-kind-correct auxiliary metrics;
- admission before spawning wrapper;
- deterministic private test hooks;
- no public test APIs.

## `crates/synvoid-mesh/src/mesh/worker_integration.rs`

Extend the worker-facing contract only as required:

- lifecycle/restart preparation;
- health snapshot if useful;
- typed failure mapping.

Keep concrete transport internals hidden.

## `src/worker/task_registry.rs`

Update:

- typed mesh shutdown causes if needed;
- exit-code and supervisor-notification mappings;
- tests for expected/fatal mesh outcomes.

Do not duplicate registry task tracking for mesh internal tasks; the worker observes mesh exits through the mesh contract.

## `src/worker/mesh_supervision.rs` — new preferred module

Implement:

- policy types;
- worker mesh status;
- event and decision types;
- pure classification function;
- restart budget/backoff helpers;
- coordinator logic or helpers.

## `src/worker/unified_server/mod.rs`

Integrate:

- mesh service construction;
- subscribe-before-start ordering;
- observer/coordinator registration;
- startup result handling;
- supervision select branch;
- shutdown sequencing.

## `src/worker/unified_server/lifecycle.rs`

Integrate:

- mesh health in heartbeat/reporting;
- mesh-triggered coordinated shutdown if appropriate;
- no duplicate IPC lifecycle acknowledgement path.

## `src/worker/unified_server/state.rs`

Add authoritative worker mesh status/readiness projection.

## Documentation

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/worker_task_lifecycle.md`;
- `architecture/mesh.md`;
- `docs/adr/ADR-003-unified-worker-process.md` if architectural ownership changes;
- `skills/synvoid_mesh.md`;
- `src/worker/AGENTS.override.md`;
- root `AGENTS.md`.

---

# Part J — Ordered Execution Sequence For A Smaller Model

Implement in this exact order.

1. Complete the narrow mesh parser/auxiliary polish items.
2. Add focused polish tests and confirm all mesh suites remain green.
3. Add `src/worker/mesh_supervision.rs` with policy, status, event, and pure decision types.
4. Add unit tests for classification before wiring runtime code.
5. Extend `ManagedMeshService` only with the minimum restart/lifecycle methods required.
6. Add worker mesh status to unified worker state.
7. Subscribe to mesh exits before mesh start.
8. Register a worker-owned mesh exit observer in `WorkerTaskRegistry`.
9. Route observer events to one supervision coordinator.
10. Map fatal decisions into typed `WorkerShutdownCause`.
11. Integrate mesh startup failure into coordinated worker startup/shutdown.
12. Add health/readiness projection.
13. Integrate bounded mesh shutdown into the worker shutdown deadline.
14. Add fatal/degraded supervision integration tests.
15. Add bounded restart budget/backoff only after fatal/degraded behavior passes.
16. Add deterministic restart/shutdown race tests.
17. Update guardrails and documentation.

Do not implement automatic restart before the non-restarting supervision path is proven correct.

---

# Part K — Behavioral Test Matrix

## Policy Unit Tests

Required cases:

- required mesh startup failure -> fatal;
- optional mesh startup failure -> degraded;
- critical panic while running -> fatal/restart according to policy;
- restartable background error -> degraded/restart candidate;
- clean critical completion while running -> unexpected/fatal;
- cancelled critical exit after shutdown intent -> expected;
- broadcast lag -> degraded/reconcile;
- exit stream closure while running -> fatal or degraded by policy;
- exit stream closure during shutdown -> expected.

## Subscription Ordering Test

Use a fake `ManagedMeshService` that emits a critical exit synchronously during `start()`.

Assert the worker observer receives it because subscription occurred first.

## Startup Tests

- mesh required + start succeeds -> worker ready;
- mesh required + start fails -> worker shutdown cause typed and nonzero;
- mesh optional + start fails -> worker remains serving but degraded;
- startup error and exit event race -> one authoritative shutdown decision.

## Runtime Exit Tests

- critical mesh exit produces `WorkerShutdownCause`;
- restartable background exit does not immediately kill optional worker;
- expected cancellation during shutdown does not produce fatal cause;
- observer lag triggers reconciliation;
- observer channel closure while running escalates.

## Health/Readiness Tests

- required mesh starting -> not ready;
- required mesh degraded -> policy-specific readiness false by default;
- optional mesh degraded -> ready but health degraded;
- restarting required mesh -> not ready;
- stopped worker -> not ready;
- heartbeat reflects typed mesh phase.

## Shutdown Tests

- external shutdown and fatal mesh exit race converge on one mesh shutdown call;
- worker deadline is propagated to mesh shutdown;
- clean mesh report yields expected worker exit;
- forced-but-complete report remains expected during shutdown;
- incomplete mesh report changes final cause/exit code;
- mesh observer exits cleanly after worker shutdown intent.

## Restart Tests

- restart budget permits bounded attempts;
- exponential backoff generation cancels stale timer;
- successful restart restores status/readiness;
- failed restart schedules next attempt;
- exhausted budget escalates to fatal worker shutdown;
- shutdown during backoff cancels restart;
- concurrent failure events do not start parallel restarts.

---

# Part L — Guardrails

Add or extend source/boundary tests to enforce:

- worker subscribes to mesh exits before calling mesh start;
- only the worker composition root decides worker shutdown/restart policy;
- mesh internals do not directly terminate the process;
- worker supervision uses typed `MeshTaskClass`/`MeshTaskExitReason`, not task-name string matching;
- mesh critical exits map to typed worker causes;
- readiness depends on worker mesh status according to required/optional policy;
- restart attempts are bounded;
- no unbounded restart loop exists;
- worker shutdown uses one shared deadline;
- no duplicate mesh shutdown invocation exists;
- mesh observer is registered in `WorkerTaskRegistry`;
- no public test-only API is added;
- malformed response headers and no-body trailing bytes are rejected;
- generic auxiliary tasks do not emit edge-refresh-only metrics.

Suggested new test:

```text
tests/worker_mesh_supervision_boundary_guard.rs
```

Behavioral tests remain authoritative.

---

# Verification Commands

Run mesh polish suites:

```bash
cargo test -p synvoid-mesh --features mesh http
cargo test -p synvoid-mesh --features mesh auxiliary
cargo test --test mesh_http_framing --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test mesh_forced_cleanup --features mesh,dns
```

Run worker supervision suites:

```bash
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test worker::mesh_supervision --features mesh,dns
cargo test worker::unified_server --features mesh,dns
```

Run integration and regressions:

```bash
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy --workspace --all-targets --features mesh,dns -- -D warnings
```

If the full workspace lint is too expensive, at minimum run:

```bash
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
cargo clippy --bin synvoid --features mesh,dns -- -D warnings
```

No known certificate failure should be silently ignored; reproduce any pre-existing failure at the base commit and document it.

---

# Acceptance Criteria

This iteration is complete only when all of the following are true:

1. Malformed backend response header lines are rejected.
2. Final no-body responses reject unexpected coalesced bytes.
3. The pure response-head parser enforces its own header limit.
4. Framing deadline arithmetic is saturation-safe.
5. Auxiliary metrics reflect the actual task kind.
6. Rejected auxiliary submissions create no Tokio wrapper task.
7. Deterministic auxiliary submission/shutdown race tests exist.
8. Worker subscribes to mesh exits before starting mesh.
9. Mesh exit observation is worker-owned and registered in `WorkerTaskRegistry`.
10. One worker-level policy classifies mesh events as ignore, degraded, restart, or fatal.
11. Critical mesh failure maps to a typed `WorkerShutdownCause`.
12. Expected mesh cancellation during coordinated shutdown is not treated as fatal.
13. Required versus optional mesh policy affects readiness and fatality explicitly.
14. Worker heartbeat/health exposes mesh phase and degraded/failed state.
15. Mesh startup failure follows coordinated worker policy rather than an ad hoc return path.
16. Mesh shutdown receives the worker’s remaining shared deadline.
17. Concurrent external shutdown and mesh failure invoke mesh shutdown once.
18. Restart attempts, if enabled, are bounded by count, window, and backoff.
19. Stale restart timers cannot restart mesh after shutdown or a newer generation.
20. Exhausted restart budget escalates to a typed fatal worker cause.
21. No mesh internal task directly controls process termination.
22. Existing worker lifecycle, mesh ownership, topology/DHT restoration, threat-intel, provenance, mesh-ID, and composition guardrails remain green.
23. Documentation marks mesh transport/lifecycle as closed and identifies worker supervision as the active ownership layer.

---

## Notes For The Implementer

This plan crosses an ownership boundary. Keep that boundary explicit.

The mesh service reports facts:

- start result;
- internal task exit;
- lifecycle state;
- shutdown report.

The worker decides policy:

- whether the worker is ready;
- whether service may continue degraded;
- whether mesh should restart;
- whether the worker must shut down;
- what exit code and supervisor notification are appropriate.

Do not move worker policy back into the mesh crate, and do not make the worker duplicate mesh internal task ownership.
