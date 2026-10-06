# Supervisor Lifecycle — Phase 3

## Purpose

Document the supervisor's long-lived task lifecycle, shutdown cause taxonomy, drain reporting, and structured concurrency model. This is the canonical reference for **Supervisor Task Ownership and Lifecycle Hardening (Phase 3)**.

Every long-lived supervisor task must be registered in `SupervisorTaskRegistry` with a defined class, ownership, and bounded shutdown path. This mirrors the worker-side equivalent in `architecture/worker_task_lifecycle.md`.

## Task Classes

Every spawned supervisor task is classified into exactly one of four severity classes (defined in `src/supervisor/task_registry.rs`).

### CriticalControlPlane

IPC accept loop, gRPC control server. Unexpected exit is fatal; triggers supervisor shutdown.

- Owner retains handle; failure surfaced immediately via `join_finished()` poll in the main event loop.
- Shutdown awaits with configurable timeout; timeout expiry triggers abort.
- Examples: `supervisor_ipc_accept`, `supervisor_grpc_control_api`.

### RestartableControlPlane (declared, no production task)

Declared in `SupervisorTaskClass` but **no task is currently registered under it**, and the supervisor implements no automatic task-restart path.

- The main event loop has no retry/respawn branch: a registered task returning `TaskOutcome::Failed` breaks the loop and escalates to `SupervisorShutdownCause::TaskFailed` (`process.rs:294-309`).
- The only bounded exponential backoff in supervisor shutdown code is the drain-status
  poll retry (`drain_manager.rs:314-343`: `100 * (1 << attempt)` ms, `max_retries = 3`)
  — a drain poll, not a task restart.

### BestEffortMaintenance

Drained during shutdown, best-effort. Not monitored live; best-effort join at shutdown.

- No live monitoring; task runs in background until shutdown.
- During shutdown, given a bounded time window to complete; aborted on timeout.
- Examples: periodic config caching, non-critical metric aggregation.

### ShutdownOnly (declared, no production task)

Declared in `SupervisorTaskClass` but **no task is currently registered under it**.

- Shutdown joins all registered tasks against one shared 10 s deadline
  (`SupervisorTaskRegistry::shutdown_and_join(10s)`, `task_registry.rs:180-186`).

## Supervisor Task Inventory

### Currently Registered Tasks

| # | Task Name | File:Line | Class | Notes |
|---|-----------|-----------|-------|-------|
| 1 | `supervisor_ipc_accept` | `process.rs:140` | CriticalControlPlane | IPC accept loop over Unix domain socket / named pipe. `#[cfg(feature = "mesh")]`-gated registration (per-connection handlers are NOT registered) |
| 2 | `supervisor_grpc_control_api` | `process.rs:260` | CriticalControlPlane | tonic gRPC control plane server; `#[cfg(feature = "mesh")]`-gated (mesh-gated — absent without the feature) |
| 3 | `eggbench_telemetry_exporter` | `telemetry_bridge.rs` (exported future) | BestEffortMaintenance | Optional supervisor-side Prometheus exporter for `synvoid.eggbench-telemetry.v2`; spawned only when `[metrics].enabled = true`. Loopback-only by config + runtime contract; exporter future is owned via the bridge's explicit `tokio::spawn` and shuts down on supervisor shutdown signal. |
| 4 | `supervisor_eggbench_telemetry_exporter` | `process.rs:196` | BestEffortMaintenance | Registry-owned wrapper around the same exporter future; registered only when telemetry is enabled |
| 5 | `supervisor_eggbench_telemetry_bridge` | `process.rs:209` | BestEffortMaintenance | Heartbeat → bridge aggregation loop that feeds the exporter |

### Known Exceptions (Not in Registry)

These tasks are spawned but intentionally not registered in `SupervisorTaskRegistry`:

| Task | Reason |
|------|--------|
| Per-connection IPC handlers | Short-lived; spawned per-connection, bounded by connection lifetime |
| Mesh agent mode spawns (`mesh.rs`) | Spawned in a separate process context (`--mesh-agent`); lifecycle managed by mesh agent event loop |
| ProcessManager internal tasks | Owned by `ProcessManager`, not directly by supervisor event loop |

## Shutdown Cause Taxonomy

Defined in `src/supervisor/shutdown.rs` as `SupervisorShutdownCause`.

| Variant | Fatal? | Metric Label | Trigger |
|---------|--------|--------------|---------|
| `Requested` | No | `requested` | Clean shutdown via signal or admin command |
| `IpcListenerFailed(String)` | Yes | `ipc_listener_failed` | IPC accept loop socket error |
| `ControlApiFailed(String)` | Yes | `control_api_failed` | gRPC control server error |
| `WorkerHealthFatal(String)` | Yes | `worker_health_fatal` | Worker health check returned fatal status |
| `ProcessManagerFailed(String)` | Yes | `process_manager_failed` | Supervisor `event_rx` channel closed (no more `ProcessEvent`s) |
| `DrainTimeout` | No | `drain_timeout` | Drain timed out before all workers finished |
| `TaskFailed { task, reason }` | Yes | `task_failed` | Registered background task failed unexpectedly |
| `InternalInvariant(String)` | Yes | `internal_invariant` | Programming error / internal invariant violation |

**Fatal causes** (`is_fatal() == true`) require process restart or operator alerting. Non-fatal causes (`Requested`, `DrainTimeout`) represent clean or expected-shutdown paths.

**Construction reality (verified):** only three variants are ever constructed today
— `Requested` (`process.rs:272/279/324`), `TaskFailed` (`process.rs:294`) and
`ProcessManagerFailed` (`process.rs:316`). The remaining five are declared but
never produced:

- `IpcListenerFailed` — the accept loop **retries** per-connection accept errors with a
  flat 100 ms sleep and a `debug!` log (`process.rs:530-533`); it only ever returns
  `Ok(())` when the shutdown receiver resolves. The `IpcListenerFailed` path is unreachable.
- `ControlApiFailed` — reachable in effect, but through the generic
  `TaskFailed { task: "supervisor_grpc_control_api", .. }` mapping, not this variant.
- `WorkerHealthFatal` — the supervisor event loop does not read worker health
  status into a shutdown cause; worker health surfaces via `ProcessEvent` handling.
- `DrainTimeout` — a drain timeout is recorded in the `SupervisorDrainReport`
  counters and `forced_shutdown` flag only; it never becomes the shutdown cause.
- `InternalInvariant` — no construction site exists.

The main event loop in `SupervisorProcess::run()` tracks the current `SupervisorShutdownCause` and transitions to a fatal cause if any registered task fails or a critical subsystem errors.

## Shutdown Ordering

The supervisor follows a strict 4-phase shutdown sequence (implemented in `SupervisorProcess::run()`, `process.rs:80`; task join at `process.rs:275`; drain/shutdown at `process.rs:363`):

### Phase 1: Stop Control-Plane Tasks

```
supervisor_tasks.shutdown_and_join(Duration::from_secs(10))
```

- Stops the IPC accept loop and gRPC control server.
- No new connections or RPCs accepted after this point.
- All tasks share one absolute 10-second deadline; a task later in the shutdown order only receives the *remaining* budget (`remaining = deadline.saturating_duration_since(now)`, `task_registry.rs:182`). Timed-out tasks are aborted and awaited.
- Returns `SupervisorTaskShutdownReport` with completed/failed/aborted/timed_out counts.

### Phase 2: Drain Workers

```
drain_aware_shutdown() → SupervisorDrainReport
```

- Starts a drain cycle via `DrainManager::start_drain()`.
- For each `UnifiedServerWorker`:
  1. Sends `DrainRequest` with timeout.
  2. Sends `StopAccepting` to stop new connections.
  3. Polls `DrainStatusRequest` until drain complete or timeout.
- Workers are given `graceful_shutdown_timeout_secs` to complete drain.
- Returns `SupervisorDrainReport` with per-worker outcomes.

### Phase 3: Join / Abort Auxiliary Tasks

Handled within `shutdown_and_join()`:
- Any tasks still running after Phase 1's deadline are aborted.
- Abort is followed by `handle.await` to prove termination (no `mem::forget`).

### Phase 4: Emit Report

```
tracing::info!("Drain report: ...");
```

- Logs the `SupervisorTaskShutdownReport` (completed/failed/aborted/timed_out).
- Logs the `SupervisorDrainReport` (drain_id, worker_count, drained, timed_out, errored, forced).
- If the shutdown cause is fatal, logs an error-level message for alerting.

## Drain Report Semantics

Defined in `src/supervisor/shutdown.rs` as `SupervisorDrainReport`:

```rust
pub struct SupervisorDrainReport {
    pub drain_id: u64,         // Unique drain cycle identifier
    pub worker_count: usize,   // Total workers registered for drain
    pub drained: usize,        // Workers that completed drain successfully
    pub timed_out: usize,      // Workers that exceeded drain timeout
    pub errored: usize,        // Workers that returned an error during drain
    pub forced_shutdown: bool, // True if drain was force-completed (timeout expired)
}
```

**Semantics:**
- `forced_shutdown == !drain_complete` (`process.rs:448`): it reflects the **manager-wide** drain result from `wait_for_drain()`, not a per-worker timeout tally. A single stalled worker therefore marks the whole report as forced.
- `drained + timed_out + errored <= worker_count`, **not** `==`: a worker whose IPC handle is absent from the process-manager map is skipped by the `if let Some(ipc)` guard (`process.rs:389`) and is counted in none of the three buckets. The sum is only exact when every registered worker has a live IPC handle.
- The report is emitted at `info` level and available for structured logging / metric emission.

## Registration Rule

**All long-lived supervisor tasks must be registered in `SupervisorTaskRegistry`.**

This is enforced by the supervisor spawn-allowlist section of the lifecycle guard
(`tests/lifecycle_task_guard.rs` SECTION 2; mirrored in
`tools/synvoid-repo-guards/tests/lifecycle_ownership.rs`). It scans for
`tokio::spawn` calls in supervisor code and verifies each returned handle is
registered before being dropped. There is no standalone
`tests/supervisor_task_ownership_guard.rs` file any more.

**Exceptions** (documented above):
- Per-connection IPC handlers (short-lived, bounded by connection).
- Mesh agent mode spawns (separate process context).
- `ProcessManager` internal tasks (owned by subcomponent).

When adding a new long-lived task to the supervisor:
1. Classify it using the four task classes above.
2. Register it via `supervisor_tasks.register(name, class, handle)`.
3. Ensure the task returns `SupervisorTaskOutcome` (Completed/Failed/Cancelled).
4. The guardrail test will verify registration automatically.

## Relationship to Worker-Side Equivalent

| Aspect | Supervisor | Worker |
|--------|-----------|--------|
| `src/supervisor/telemetry_bridge.rs` | Owner of the Eggbench M003 supervisor-side exporter; bridges `ProcessManager` heartbeats into `synvoid.eggbench-telemetry.v2` Prometheus metrics; bound to supervisor lifecycle via shared `broadcast::Receiver<()>` |
| Task classes | 4 declared (see above); only `CriticalControlPlane` and `BestEffortMaintenance` are in production use | 6 classes (`CriticalService`, `RestartableBackground`, `BoundedChild`, `CpuOffload`, `Detached`, `OneShot`) |
| Documentation | This document | `architecture/worker_task_lifecycle.md` |
| Shutdown budget | 10 seconds (task join) + `graceful_shutdown_timeout_secs` (drain) | Per-task cancellation tokens + `JoinSet` drain |
| Enforcement test | `tests/lifecycle_task_guard.rs` (SECTION 2) | `tests/lifecycle_task_guard.rs` (SECTION 1) |

The supervisor registry is simpler because the supervisor has far fewer long-lived tasks than the worker (which manages 40+ background tasks across HTTP, WAF, proxy, mesh, and plugin subsystems).

## Key Source Files

| File | Purpose |
|------|---------|
| `src/supervisor/task_registry.rs` | `SupervisorTaskRegistry`, task classes, join/shutdown logic |
| `src/supervisor/shutdown.rs` | `SupervisorShutdownCause`, `SupervisorDrainReport` |
| `src/supervisor/process.rs` | Main event loop, task registration, shutdown orchestration |
| `src/supervisor/mod.rs` | Public re-exports (`SupervisorDrainReport`, `SupervisorShutdownCause`) |
