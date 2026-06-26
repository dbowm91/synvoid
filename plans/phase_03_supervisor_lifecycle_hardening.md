# Phase 3 Plan: Supervisor Lifecycle and Control-Plane Task Hardening

Status: detailed handoff plan.

Roadmap position: Phase 3 of `plans/roadmap.md`.

Primary goal: bring supervisor task ownership, shutdown semantics, and control-plane runtime discipline up to the quality already established in the worker-side mesh/task registry architecture.

## Architectural Context

`src/supervisor/process.rs` owns the supervisor process runtime. It holds `SupervisorState`, `ProcessManager`, `DrainManager`, `DrainProtocol`, process-event receiver, running flag, and IPC listener. It initializes shared connection/rate-limit tables, spawns unified server workers, starts the IPC accept loop, starts the gRPC control server, then runs the main supervisor event loop.

The worker side has strong lifecycle architecture: task registry, critical/restartable classes, startup rollback, mesh supervision policy, shutdown cause mapping, and guardrails. The supervisor side should get an equivalent but smaller model. The supervisor is the control-plane root; its long-lived tasks should be named, classified, observable, and drainable.

## Non-Goals

Do not redesign `ProcessManager` internals unless needed for task registration.

Do not change IPC message formats except where typed shutdown/reporting requires local-only additions.

Do not add supervisor mesh restart behavior.

Do not move supervisor out of the root crate.

## Deliverables

1. `SupervisorTaskRegistry` or equivalent local task registry.
2. Registered supervisor IPC accept loop.
3. Registered gRPC control API server task.
4. `SupervisorShutdownCause` taxonomy.
5. Deterministic mapping from shutdown cause to logs, metrics, drain behavior, and process exit classification.
6. Guardrail preventing unmanaged supervisor `tokio::spawn` calls outside approved registration points.
7. Tests for supervisor task registration, shutdown reporting, and drain-aware shutdown cause mapping.
8. Documentation update in a new or existing architecture document.

## Step 1: Add Supervisor Shutdown Cause Taxonomy

Create `src/supervisor/shutdown.rs` or add to a focused existing module if preferred.

Suggested taxonomy:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorShutdownCause {
    Requested,
    IpcListenerFailed(String),
    ControlApiFailed(String),
    WorkerHealthFatal(String),
    ProcessManagerFailed(String),
    DrainTimeout,
    TaskFailed { task: String, reason: String },
    InternalInvariant(String),
}

impl SupervisorShutdownCause {
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::Requested | Self::DrainTimeout)
    }

    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::IpcListenerFailed(_) => "ipc_listener_failed",
            Self::ControlApiFailed(_) => "control_api_failed",
            Self::WorkerHealthFatal(_) => "worker_health_fatal",
            Self::ProcessManagerFailed(_) => "process_manager_failed",
            Self::DrainTimeout => "drain_timeout",
            Self::TaskFailed { .. } => "task_failed",
            Self::InternalInvariant(_) => "internal_invariant",
        }
    }
}
```

If the process currently does not return an exit code from this layer, do not force one immediately. The first pass can emit structured logs and metrics and store the cause in a shutdown report.

## Step 2: Add Supervisor Task Registry

Create `src/supervisor/task_registry.rs`.

Suggested minimal model:

```rust
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorTaskClass {
    CriticalControlPlane,
    RestartableControlPlane,
    BestEffortMaintenance,
    ShutdownOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SupervisorTaskId(u64);

pub struct SupervisorTaskRegistry {
    next_id: u64,
    tasks: BTreeMap<SupervisorTaskId, SupervisorTaskEntry>,
}

pub struct SupervisorTaskEntry {
    pub name: &'static str,
    pub class: SupervisorTaskClass,
    pub handle: tokio::task::JoinHandle<SupervisorTaskOutcome>,
}

#[derive(Debug)]
pub enum SupervisorTaskOutcome {
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Debug, Default)]
pub struct SupervisorTaskShutdownReport {
    pub completed: usize,
    pub failed: usize,
    pub aborted: usize,
    pub timed_out: usize,
}
```

Required methods:

```rust
impl SupervisorTaskRegistry {
    pub fn new() -> Self;

    pub fn register(
        &mut self,
        name: &'static str,
        class: SupervisorTaskClass,
        handle: tokio::task::JoinHandle<SupervisorTaskOutcome>,
    ) -> SupervisorTaskId;

    pub async fn join_finished(&mut self) -> Vec<(SupervisorTaskId, SupervisorTaskOutcome)>;

    pub async fn shutdown_and_join(
        &mut self,
        timeout: Duration,
    ) -> SupervisorTaskShutdownReport;
}
```

Do not overbuild restart semantics in this phase. The first registry can report failures and allow the main supervisor loop to decide whether a critical task failure triggers shutdown.

## Step 3: Register IPC Accept Loop

Current supervisor logic starts an IPC accept loop by spawning a task directly after binding `IpcListener`. Replace that with registry ownership.

Extract the loop into a function:

```rust
async fn run_supervisor_ipc_accept_loop(
    listener: IpcListener,
    pm: Arc<ProcessManager>,
    state: SupervisorState,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> SupervisorTaskOutcome {
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => {
                return SupervisorTaskOutcome::Completed;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok(ipc) => {
                        let pm_clone = pm.clone();
                        let state_clone = state.clone();
                        tokio::spawn(async move {
                            SupervisorProcess::handle_connection(ipc, pm_clone, state_clone).await;
                        });
                    }
                    Err(e) => {
                        tracing::debug!("Supervisor IPC accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}
```

Important: the per-connection spawn is shorter-lived and may remain as-is initially, but add a TODO or second-level registry plan if those connections can be long-running. If possible, use a `JoinSet` inside the accept loop to own connection tasks and drain them on shutdown.

Better version:

```rust
let mut connections = tokio::task::JoinSet::new();
// spawn connection handlers into JoinSet
// on shutdown, stop accepting and drain/abort connection handlers with timeout
```

The task returned to `SupervisorTaskRegistry` should be the accept-loop owner.

## Step 4: Register gRPC Control API Server

Current supervisor logic spawns `super::api::start_grpc_server(...)` directly. Wrap it as a registered critical task.

Suggested helper:

```rust
async fn run_supervisor_control_api_task(
    addr: std::net::SocketAddr,
    pm: Arc<ProcessManager>,
    state: SupervisorState,
    tls: Option<crate::tls::config::InternalTlsConfig>,
) -> SupervisorTaskOutcome {
    match super::api::start_grpc_server(addr, pm, state, tls).await {
        Ok(()) => SupervisorTaskOutcome::Completed,
        Err(e) => SupervisorTaskOutcome::Failed(e.to_string()),
    }
}
```

If the gRPC server currently has no shutdown signal, add one if the API supports it. If not, document it as a known blocker and make `shutdown_and_join` abort the task after timeout.

## Step 5: Integrate Registry into `SupervisorProcess`

Add field:

```rust
supervisor_tasks: SupervisorTaskRegistry,
```

Initialize in `SupervisorProcess::new()`.

In `run()`:

- Register IPC accept loop after listener setup.
- Register gRPC control API task if configured.
- In the main loop, periodically check finished supervisor tasks.
- If a `CriticalControlPlane` task fails, set a `SupervisorShutdownCause::TaskFailed` and begin shutdown.
- On ordinary shutdown signal, use `SupervisorShutdownCause::Requested`.
- During shutdown, call `supervisor_tasks.shutdown_and_join(timeout)` before or after worker drain depending on desired semantics.

Recommended shutdown order:

1. Stop accepting new supervisor/control-plane requests.
2. Begin drain-aware worker shutdown.
3. Join/abort supervisor auxiliary tasks.
4. Clear drain state and emit shutdown report.

If control API is needed during drain, reverse steps 2 and 3 for the control API only. Document the chosen order.

## Step 6: Harden Drain Reporting

`drain_aware_shutdown()` currently logs drain start, registers workers, asks workers to drain, waits, logs status, shuts down workers, clears the drain manager, and logs completion.

Add a return report:

```rust
#[derive(Debug)]
pub struct SupervisorDrainReport {
    pub drain_id: u64,
    pub worker_count: usize,
    pub drained: usize,
    pub timed_out: usize,
    pub errored: usize,
    pub forced_shutdown: bool,
}
```

Change:

```rust
async fn drain_aware_shutdown(&self) -> SupervisorDrainReport
```

or if that is too disruptive, add a helper that computes/report metrics while preserving existing behavior.

Metrics to add if metrics crate is already available in root:

- `supervisor_shutdown_total{cause=...}`
- `supervisor_drain_started_total`
- `supervisor_drain_timeout_total`
- `supervisor_task_failed_total{task=...,class=...}`
- `supervisor_task_aborted_total{task=...,class=...}`

## Step 7: Add Guardrail for Supervisor Spawns

Create `tests/supervisor_task_ownership_guard.rs`.

Behavior:

- Scan `src/supervisor/` for `tokio::spawn`.
- Allow only approved files/functions that register tasks or spawn bounded per-connection handlers.
- Fail on new unclassified spawns.

Suggested allowlist entries:

- `src/supervisor/task_registry.rs`: allowed to own task registration internals.
- `src/supervisor/process.rs`: allowed only in `run_supervisor_ipc_accept_loop` for per-connection handlers if not yet converted to `JoinSet`; document blocker.

Guard message should explain that long-lived supervisor tasks must be registered in `SupervisorTaskRegistry`.

## Step 8: Tests

Add unit tests for `SupervisorTaskRegistry`:

- `register_assigns_unique_ids`.
- `join_finished_returns_completed_task`.
- `shutdown_and_join_reports_completed_tasks`.
- `shutdown_and_join_aborts_timeout_tasks`.
- `critical_task_failure_maps_to_shutdown_cause`.

Add behavior tests where feasible:

- IPC accept loop exits on shutdown signal.
- gRPC task failure returns `SupervisorTaskOutcome::Failed`.
- drain report counts timeout/error outcomes.

If integration tests are difficult due to real sockets/processes, keep first pass unit-level and add TODOs for later failure-injection tests.

## Step 9: Documentation

Create `architecture/supervisor_lifecycle.md` or update an existing supervisor architecture document.

Include:

- Supervisor task classes.
- Which tasks are critical.
- Shutdown order.
- Drain report semantics.
- Rule: long-lived supervisor tasks must be registered.
- Known exceptions and planned cleanup.

Update `AGENTS.md` verification commands with:

```bash
cargo test --test supervisor_task_ownership_guard
cargo test -p synvoid supervisor::task_registry
```

## Verification Commands

Run:

```bash
cargo fmt
cargo test -p synvoid supervisor::task_registry
cargo test -p synvoid supervisor::shutdown
cargo test --test supervisor_task_ownership_guard
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo check
```

If supervisor tests require default features, document why and add narrower unit tests where possible.

## Acceptance Criteria

This phase is complete when:

- Supervisor IPC accept loop is owned by a named registered task or a documented equivalent.
- gRPC control API server is owned by a named registered task or documented shutdown handle.
- Critical supervisor task failure is observable and maps to a shutdown cause.
- Drain-aware shutdown returns or emits a structured report.
- A guardrail prevents new unmanaged long-lived supervisor spawns.
- Tests cover registry behavior and at least one shutdown/failure path.
- Documentation describes supervisor lifecycle ownership.

## Handoff Notes for Smaller Models

Do not rewrite `ProcessManager` first. Add the supervisor registry around existing behavior.

Keep per-connection IPC handling simple unless converting it to `JoinSet` is straightforward.

Preserve existing shutdown behavior first, then add reports and metrics.

Avoid broad allowlists in the spawn guard. Every exception should name the owning function and reason.
