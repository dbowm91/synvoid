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

### RestartableControlPlane

Tasks that can be logged and optionally restarted on failure, but do not warrant immediate supervisor exit.

- Unexpected exit is logged; bounded exponential backoff restart may be attempted.
- Cap consecutive restart attempts; escalate to `TaskFailed` if retries exhausted.
- Examples: mesh agent background tasks (when mesh feature is enabled).

### BestEffortMaintenance

Drained during shutdown, best-effort. Not monitored live; best-effort join at shutdown.

- No live monitoring; task runs in background until shutdown.
- During shutdown, given a bounded time window to complete; aborted on timeout.
- Examples: periodic config caching, non-critical metric aggregation.

### ShutdownOnly

Only joined during shutdown, not monitored live at all.

- Spawned and forgotten during normal operation.
- At shutdown, added to the join set with a shared deadline.
- Examples: one-shot diagnostic tasks, deferred cleanup.

## Supervisor Task Inventory

### Currently Registered Tasks

| # | Task Name | File:Line | Class | Notes |
|---|-----------|-----------|-------|-------|
| 1 | `supervisor_ipc_accept` | `process.rs:127` | CriticalControlPlane | IPC accept loop over Unix domain socket / named pipe |
| 2 | `supervisor_grpc_control_api` | `process.rs:160` | CriticalControlPlane | tonic gRPC control plane server |

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
| `ProcessManagerFailed(String)` | Yes | `process_manager_failed` | Process manager unrecoverable error |
| `DrainTimeout` | No | `drain_timeout` | Drain timed out before all workers finished |
| `TaskFailed { task, reason }` | Yes | `task_failed` | Registered background task failed unexpectedly |
| `InternalInvariant(String)` | Yes | `internal_invariant` | Programming error / internal invariant violation |

**Fatal causes** (`is_fatal() == true`) require process restart or operator alerting. Non-fatal causes (`Requested`, `DrainTimeout`) represent clean or expected-shutdown paths.

The main event loop in `SupervisorProcess::run()` tracks the current `SupervisorShutdownCause` and transitions to a fatal cause if any registered task fails or a critical subsystem errors.

## Shutdown Ordering

The supervisor follows a strict 4-phase shutdown sequence (implemented in `SupervisorProcess::run()`, `process.rs:234`):

### Phase 1: Stop Control-Plane Tasks

```
supervisor_tasks.shutdown_and_join(Duration::from_secs(10))
```

- Stops the IPC accept loop and gRPC control server.
- No new connections or RPCs accepted after this point.
- Each task gets a share of the 10-second deadline; timed-out tasks are aborted.
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
- `drained + timed_out + errored == worker_count` (all workers accounted for).
- `forced_shutdown == true` when any worker exceeded the timeout, indicating connections may have been dropped.
- The report is emitted at `info` level and available for structured logging / metric emission.

## Registration Rule

**All long-lived supervisor tasks must be registered in `SupervisorTaskRegistry`.**

This is enforced by the `supervisor_task_ownership_guard` test, which scans for `tokio::spawn` calls in supervisor code and verifies each returned handle is registered before being dropped.

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
| Registry type | `SupervisorTaskRegistry` | `WorkerTaskRegistry` |
| Task classes | 4 classes (see above) | 5 classes (`CriticalService`, `RestartableBackground`, `BoundedChild`, `CpuOffload`, `Detached`) |
| Documentation | This document | `architecture/worker_task_lifecycle.md` |
| Shutdown budget | 10 seconds (task join) + `graceful_shutdown_timeout_secs` (drain) | Per-task cancellation tokens + `JoinSet` drain |
| Enforcement test | `supervisor_task_ownership_guard` | `background_task_ownership_guard` |

The supervisor registry is simpler because the supervisor has far fewer long-lived tasks than the worker (which manages 40+ background tasks across HTTP, WAF, proxy, mesh, and plugin subsystems).

## Key Source Files

| File | Purpose |
|------|---------|
| `src/supervisor/task_registry.rs` | `SupervisorTaskRegistry`, task classes, join/shutdown logic |
| `src/supervisor/shutdown.rs` | `SupervisorShutdownCause`, `SupervisorDrainReport` |
| `src/supervisor/process.rs` | Main event loop, task registration, shutdown orchestration |
| `src/supervisor/mod.rs` | Public re-exports (`SupervisorDrainReport`, `SupervisorShutdownCause`) |
