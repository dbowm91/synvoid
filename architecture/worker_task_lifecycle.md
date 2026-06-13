# Worker Task Lifecycle — Iteration 64

## Purpose

Document every long-lived background task in the SynVoid unified worker and related subsystems, classify them by severity, define ownership/cancellation/join contracts, and specify the shutdown ordering.

This document is the canonical reference for the **Worker Structured Concurrency and Lifecycle Audit**. Every long-lived spawned task must appear in the inventory table, have a defined class, and be reachable through a bounded shutdown path.

## Task Classes

Every spawned background task is classified into exactly one of five severity classes.

### CriticalService

Listener accept loops, mesh transport core loop, supervisor/worker IPC loop, critical persistence writer.

- Owner retains handle; unexpected exit surfaced immediately; worker may transition unhealthy.
- Shutdown awaits with configurable timeout; timeout expiry triggers abort.
- Examples: IPC loop, server accept tasks, block-store persistence, mesh maintenance, CPU worker accept thread.

### RestartableBackground

Health checks, metrics export, threat-feed refresh, cache cleanup, noncritical reconciliation.

- Owner retains handle or task-group membership; cancellation explicit via shutdown signal.
- Unexpected exit logged + optionally restarted with bounded exponential backoff and jitter.
- Cap consecutive restart attempts; escalate to unhealthy state if retries exhausted.
- Examples: heartbeat task, threat-intel background fetches, GeoIP update, health checks.

### BoundedChild

Per-connection/request tasks, bounded dispatch helpers, short-lived async jobs.

- May live in `JoinSet` or connection task group; drained or aborted after timeout.
- Must not outlive owning connection; connection close implies child cancellation.
- Examples: per-HTTP-request handler tasks, CPU offload request dispatch.

### CpuOffload

Compression, minification, image transforms, deep scans, blocking filesystem/CPU work.

- Bounded queue/concurrency; cancellation documented per task type.
- Shutdown stops intake and drains after timeout.
- Examples: compression queue, YARA scan, image resize, minification.

### Detached

Only for truly fire-and-forget work where result and lifetime do not affect correctness.

- Rare; explicitly documented with rationale; source guard makes detached spawn visible.
- Must have an explicit allowlist entry in the guardrail test.
- Examples: fire-and-forget telemetry emission (if any).

## Task Inventory Table

All long-lived spawned tasks are listed below, grouped by subsystem.

### UnifiedServer Worker (`src/worker/unified_server/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 1 | `spawn_heartbeat_task` | `lifecycle.rs:58` | RestartableBackground | WorkerTaskRegistry | `child_token()` watch | Registry join | log+continue on error | **Migrated (Iteration 62)**: Periodic heartbeat to supervisor |
| 2 | `spawn_bandwidth_persist_task` | `lifecycle.rs:129` | RestartableBackground | WorkerTaskRegistry | `child_token()` watch | Registry join | runs forever | **Migrated (Iteration 62)**: Bandwidth counter persistence |
| 3 | `spawn_ipc_loop` | `lifecycle.rs:140` | CriticalService | WorkerTaskRegistry | `child_token()` watch | Registry join | break on error, marks `master_dead` | **Migrated (Iteration 62)**: Supervisor/worker IPC message loop |
| 4 | `spawn_server_run_task` | `lifecycle.rs:744` | CriticalService | WorkerTaskRegistry | `child_token()` watch | Registry join | marks `running.stop()` on error | **Migrated (Iteration 63)**: Unified server main run loop; registered via `spawn_critical_result` as `CriticalService` under `WorkerTaskRegistry` |
| 5 | Shared connection heartbeat | `state.rs:190` | RestartableBackground | (unowned) | NONE | Dropped | runs forever, no shutdown | Per-connection heartbeat; no shutdown signal |
| 6 | `spawn_port_honeypot` | `init_waf.rs:108` | RestartableBackground | (unowned) | `shutdown_tx` inside runner | Dropped | runs forever | Honeypot listener on configured ports |

### UnifiedServer Server (`src/server/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 7 | Threat level auto-scale | `mod.rs:799` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Periodic threat-level recalculation |
| 8 | HTTP/HTTPS/HTTP3 servers (6 listeners) | `mod.rs:919-1011` | CriticalService | UnifiedServer::run | `shutdown_rx` broadcast | Awaited directly | graceful shutdown | Multiple accept loops; all must drain |
| 9 | TCP/UDP connection pools | `mod.rs:1015-1032` | CriticalService | UnifiedServer::run | internal shutdown | Awaited directly | graceful | Connection pool maintenance |
| 10 | DNS server | `mod.rs:1037` | CriticalService | UnifiedServer::run | internal shutdown | Awaited directly | feature-gated | DNS listener; compiled out without `dns` feature |
| 11 | ACME cert renewal | `mod.rs:538` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Periodic TLS certificate renewal |

### Threat Intel (`src/waf/threat_intel/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 12 | `ThreatFeedClient::start_background_fetching` | `feed_client.rs:118` | RestartableBackground | (unowned) | NONE | Dropped | NO cancellation, fire-and-forget | Background threat-intel feed polling; no shutdown signal |

### Block Store (`crates/synvoid-block-store/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 13 | BlockStore persistence task | `lib.rs:691` | CriticalService | BlockStore | `shutdown_rx` mpsc | Dropped | flushes on shutdown | Dirty-flag persistence writer; must flush on shutdown |

### Mesh (`crates/synvoid-mesh/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 14 | Threat intel background tasks (2 loops) | `threat_intel.rs:2756` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Threat-intel synchronization loops |
| 15 | PoW nonce refresh | `transport.rs:2049` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Periodic proof-of-work nonce rotation |
| 16 | ML-KEM key rotation | `transport.rs:2079` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Post-quantum key rotation |
| 17 | Mesh maintenance loop | `transport.rs:2124` | CriticalService | MeshTransport | `shutdown_rx` broadcast | Dropped | graceful | Core mesh peer maintenance |
| 18 | Datagram listener | `transport.rs:2130` | CriticalService | MeshTransport | `datagram_shutdown` broadcast | Dropped | graceful | Mesh UDP datagram receive loop |
| 19 | Peer connection maintenance | `transport.rs:2154` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Peer connection state reconciliation |
| 20 | Peer health check | `transport.rs:2165` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Periodic peer health probing |
| 21 | Proactive cache warming | `transport.rs:2183` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | DHT cache pre-warming |

### Upstream (`crates/synvoid-upstream/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 22 | `HealthChecker::start` | `health.rs:77` | RestartableBackground | HealthChecker | `shutdown_rx` broadcast | Dropped | graceful | Upstream health check loop |
| 23 | UpstreamPool health check | `pool.rs:776` | RestartableBackground | UpstreamPool | `handle.abort()` | Retained in `RwLock` | abortable | Pool-level health monitor |

### Supervisor (`src/supervisor/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 24 | IPC accept loop | `process.rs:114` | CriticalService | SupervisorProcess | NONE | Dropped | runs forever | Worker IPC connection accept |
| 25 | gRPC control server | `process.rs:156` | CriticalService | SupervisorProcess | internal shutdown | Dropped | graceful | gRPC API server |

### Admin (`src/admin/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 26 | Metrics publisher | `metrics.rs:10` | RestartableBackground | (unowned) | `shutdown_rx` mpsc | Managed | graceful | Periodic metrics publication |

### Other Crates

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 27 | GeoIP update | `geoip/manager.rs:147` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Periodic GeoIP database refresh |
| 28 | Granian health check | `granian.rs:415` | RestartableBackground | GranianSupervisor | `shutdown_rx` broadcast + `running` | Dropped | graceful | Granian process health monitor |
| 29 | DNS RFC 5011 refresh | `resolver.rs:785` | RestartableBackground | HickoryResolver | watch channel | Retained | graceful | DNSSEC key rollover per RFC 5011 |
| 30 | DNS anycast sync | `anycast_sync.rs:176` | RestartableBackground | (unowned) | NONE | Dropped | runs forever | Anycast endpoint synchronization |
| 31 | Proxy cache cleanup | `store.rs:308` | RestartableBackground | ProxyCache | watch channel `shutdown_rx` | Returned | graceful | Expired entry eviction |
| 32 | Static files YARA refresh | `file_manager.rs:283` | RestartableBackground | (unowned) | NONE | Returned | runs forever | YARA rule refresh for static file scanning |
| 33 | System health monitor | `health.rs:12` | CriticalService | SystemHealthMonitor | NONE | Dropped | runs forever | OS-level health telemetry |
| 34 | Serverless instance pool cleanup | `instance_pool.rs:416` | RestartableBackground | InstancePool | watch channel `shutdown_tx` | Managed | graceful | Idle WASM instance eviction |
| 35 | FastCGI health check | `pool.rs:152` | RestartableBackground | FastCgiPool | `handle.abort()` | Retained | abortable | FastCGI backend health probe |

### CPU Worker (`src/worker/cpu_task/`)

| # | Task | File:Line | Class | Owner | Cancel Path | Join Path | Failure Policy | Notes |
|---|------|-----------|-------|-------|-------------|-----------|----------------|-------|
| 36 | Unix socket accept thread | `mod.rs:149` | CriticalService | run_cpu_worker | `running.is_running()` | Dropped (std::thread) | OS thread | Blocking accept on Unix socket; must join OS thread |
| 37 | IPC message loop | `mod.rs:249` | CriticalService | run_cpu_worker | `running.is_running()` | Local select | graceful | IPC message handling for CPU tasks |
| 38 | Compression queue | `mod.rs:432` | RestartableBackground | run_cpu_worker | `running.is_running()` | Local select | graceful | Bounded compression task queue |
| 39 | Watch/heartbeat loop | `mod.rs:461` | RestartableBackground | run_cpu_worker | `running.is_running()` | Local select | graceful | CPU worker heartbeat to supervisor |
| 40 | Config reload | `mod.rs:532` | RestartableBackground | run_cpu_worker | `running.is_running()` | Local select | graceful | Config change detection and reload |

## Shutdown Ordering

The bounded shutdown sequence for the unified worker is ordered to preserve correctness invariants.

### Phase 1: Stop Accepting

Stop accepting new external connections (`stop_accepting` broadcast). Existing connections continue processing.

### Phase 2: Signal Draining

Signal request/connection draining (`drain_state`). In-flight requests are allowed to complete within a bounded timeout.

### Phase 3: Stop Producers

Stop periodic producers and background refresh loops (`running.stop()`). This includes:
- Heartbeat tasks
- Bandwidth persist
- Threat-intel feed refresh
- Metrics publication
- Cache cleanup loops
- Health-check probes

### Phase 4: Stop Mesh and Synchronization

Stop mesh transport, synchronization, health-check, and feed loops. This includes:
- Mesh maintenance loop
- Peer connection maintenance
- Peer health check
- Proactive cache warming
- PoW nonce refresh
- ML-KEM key rotation

### Phase 5: Stop CPU Offload

Stop new CPU-offload submissions. Existing queued work continues processing within a bounded timeout.

### Phase 6: Drain Children

Drain bounded request/connection children with timeout. Per-connection tasks and BoundedChild tasks are awaited up to the drain timeout.

### Phase 7: Flush Persistent State

Flush block-store and other persistent state. This must happen **after** producers stop mutating state to avoid partial writes.

### Phase 8: Await Critical Services

Await critical service tasks with timeout. This includes:
- IPC loop
- Server accept tasks
- BlockStore persistence
- DNS server
- CPU worker accept thread

### Phase 9: Await Background Tasks

Await background tasks with timeout. Includes all RestartableBackground tasks that were not stopped in earlier phases.

### Phase 10: Abort Remnants

Abort remaining tasks after timeout and report them. `shutdown_and_join()` explicitly aborts any tasks that exceed their deadline and awaits the abort to complete (no detached tasks remain). The task identity and class are logged for post-mortem analysis.

### Constraints

- **Persistent flush must happen after producers stop mutating state** — flushing during mutation risks partial/corrupt writes.
- **Request drain must be bounded** — shutdown must not wait indefinitely for slow clients.
- **Shutdown must not wait forever on a lost peer/socket** — timeout expiry triggers abort for all critical tasks.
- **Cancellation must be propagated before handles are awaited** — tasks must observe the shutdown signal before join, or they will hang.
- **Task timeouts must be observable** — timeout expiry must be logged with task identity for diagnostics.

## Failure and Panic Policy

### Critical task exits

- Log task name and exit cause at `error` level.
- Mark worker/service unhealthy.
- Trigger coordinated shutdown or return fatal error to supervisor.
- Do **not** silently restart unless explicitly designed with documented rationale.

### RestartableBackground exits

- Log at `warn` level and increment task failure metrics.
- Optional bounded restart with exponential backoff and jitter.
- Cap consecutive restart attempts (default: 5 within 60 seconds).
- Escalate to unhealthy state if retries exhausted.

### Panics

- Detect `JoinError::is_panic()` on task join.
- Record task identity (name, class, file:line of spawn site).
- Classify severity based on task class:
  - CriticalService panic → immediate coordinated shutdown.
  - RestartableBackground panic → log, increment metrics, optionally restart.
  - BoundedChild panic → log, decrement connection count, continue.
  - CpuOffload panic → log, decrement queue depth, continue.
  - Detached panic → log at debug level.
- Avoid silently dropping panic results; always record in metrics.

## Migration Status Labels

Tasks are tracked using the following status labels to indicate their lifecycle management state:

- **`Migrated`** — Task is registered with `WorkerTaskRegistry` and uses registry spawn APIs (`spawn_critical`, `spawn_background`, etc.). Provides automatic panic detection via `catch_unwind`, immediate exit notifications via `subscribe_exits()`, and bounded shutdown with abort.
- **`LegacyOwned`** — Task is tracked in `state.task_handles` (or equivalent) but not yet migrated to the registry. Owner retains the join handle and is responsible for cancellation/join.
- **`UnownedKnownGap`** — Task is spawned without proper ownership tracking. The join handle is dropped or not retained. This is a known gap that should be addressed.
- **`DetachedApproved`** — Task is intentionally fire-and-forget with a documented rationale. Must have an explicit allowlist entry in `tests/background_task_ownership_guard.rs`.

## WorkerTaskRegistry

The `WorkerTaskRegistry` (introduced in `src/worker/task_registry.rs`) provides structured lifecycle management for spawned background tasks.

### Design

- **Cancellation**: Uses `tokio::sync::watch` for cancellation with a child-token pattern. Each registered task receives a cancellation token derived from the registry's root token.
- **Task sets**: Two `JoinSet`s — one for critical tasks, one for background tasks — enabling class-aware shutdown ordering.
- **Named tasks**: Every task is registered with a `&'static str` name and a `TaskClass` enum variant, making instrumentation and diagnostics straightforward.
- **Bounded shutdown**: Shutdown accepts a configurable timeout. Critical tasks are drained first, then background tasks, then remaining tasks are aborted.
- **Metrics counters**: Tracks `tasks_started`, `tasks_stopped`, `tasks_aborted`, and `tasks_panicked` per task class.

### API

```rust
/// Opaque task identifier for deduplication in exit records.
pub struct TaskId(pub u64);

pub struct WorkerTaskRegistry { /* ... */ }

impl WorkerTaskRegistry {
    pub fn new() -> Self;
    pub fn child_token(&self) -> watch::Receiver<bool>;
    pub fn subscribe_exits(&self) -> broadcast::Receiver<NamedTaskExit>;
    pub fn is_shutdown_started(&self) -> bool;
    pub fn spawn_critical<F>(&mut self, name: &'static str, fut: F) -> usize;
    pub fn spawn_critical_result<F, E>(&mut self, name: &'static str, fut: F) -> usize;
    pub fn spawn_background<F>(&mut self, name: &'static str, fut: F) -> usize;
    pub fn spawn_cancellable_background<F>(&mut self, name: &'static str, fut: F) -> usize;
    pub fn shutdown(&self);
    pub async fn shutdown_and_join(
        &mut self,
        critical_timeout: Duration,
        background_timeout: Duration,
    ) -> Vec<NamedTaskExit>;
}

/// Result of joining a single task, with metadata for logging and metrics.
pub struct NamedTaskExit {
    pub id: TaskId,
    pub name: &'static str,
    pub class: TaskClass,
    pub reason: TaskExitReason,
    pub expected_during_shutdown: bool,
}

/// Outcome of a task exit.
pub enum TaskExitReason {
    Cancelled,
    CleanCompletion,
    UnexpectedCompletion,
    Panic(String),
    Error(String),
    Aborted,
}
```

**Key behaviors:**

- **Panic detection**: All spawn methods (`spawn_critical`, `spawn_critical_result`, `spawn_background`, `spawn_cancellable_background`) wrap the provided future with `AssertUnwindSafe(future).catch_unwind()` to capture panics and classify them as `TaskExitReason::Panic`.
- **Immediate supervision**: `subscribe_exits()` returns a broadcast receiver that delivers `NamedTaskExit` events immediately when any task completes, panics, or errors — no need to await `shutdown_and_join`.
- **Deduplication**: `record_exit_metrics()` records metrics inside the task wrapper and stores the exit in `reported_exits` map. When `shutdown_and_join` later joins the same task, it checks `reported_exits` to avoid double-counting metrics.
- **`is_shutdown_started()`**: Returns whether `shutdown()` has been called, useful for tasks that check shutdown state without a watch channel.

## ManagedService Trait

Services that own long-lived background tasks should implement `ManagedService` for uniform lifecycle management.

```rust
pub trait ManagedService {
    /// Human-readable service name for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Initiate graceful shutdown. Must be idempotent — safe to call multiple times.
    async fn shutdown(&self);

    /// Wait for the service to fully stop. Returns Ok(()) on clean exit,
    /// or Err(ServiceExitError) on failure/panic.
    async fn join(&self) -> Result<(), ServiceExitError>;
}
```

Implementations:
- `HealthChecker` — graceful shutdown via broadcast channel.
- `InstancePool` — graceful shutdown via watch channel.
- `ProxyCache` — graceful shutdown via watch channel.
- `FastCgiPool` — abort via `JoinHandle::abort()`.
- `UpstreamPool` — abort via `JoinHandle::abort()`.

## How to Add a New Long-Lived Task

1. **Determine the task class.** Choose one of: CriticalService, RestartableBackground, BoundedChild, CpuOffload, Detached. Document the rationale.
2. **Register with WorkerTaskRegistry.** For CriticalService and RestartableBackground tasks, use `spawn_critical` or `spawn_background` on the registry. This provides automatic cancellation and shutdown.
3. **Implement cancellation.** Every interval/polling loop must include a `tokio::select!` branch on the shutdown signal. Never run an unbounded loop without cancellation.
4. **Store the JoinHandle.** Either retain the `JoinHandle` in a `task_handles` map, register with the registry's `JoinSet`, or document why the handle is dropped (fire-and-forget with rationale).
5. **Define panic/unexpected-exit behavior.** Specify whether the task is restartable, what happens on failure, and whether the worker transitions unhealthy.
6. **Add to the shutdown sequence.** If the task has ordering dependencies (e.g., must stop before persistence flush), add an explicit step in the shutdown ordering section.
7. **For Detached tasks only:** Add an explicit allowlist entry in `tests/background_task_ownership_guard.rs` with a written rationale for why detachment is safe.
8. **Update this document.** Add a row to the task inventory table with all fields filled in.

## Iteration 62: First Registry-Migrated Tasks

The IPC loop (`spawn_ipc_loop`), heartbeat task (`spawn_heartbeat_task`), and bandwidth persist task (`spawn_bandwidth_persist_task`) are the first set of tasks migrated to `WorkerTaskRegistry` (Iteration 62). These tasks were previously tracked in `state.task_handles` and are now registered via `spawn_critical` / `spawn_background` on the registry.

## Iteration 63: Server Run Task Migration + Supervision Corrections

The server run task (`spawn_server_run_task`, task #4) is now registered under `WorkerTaskRegistry` via `spawn_critical_result` as a `CriticalService`. The old standalone `spawn_server_run_task` function has been removed.

### Supervision Control Flow

The supervision loop (`Phase 15`) in `src/worker/unified_server/mod.rs` enforces the following invariants:

#### Subscription-Before-Spawn

`subscribe_exits()` is called **before** any tasks are spawned (Phase 12), ensuring no task exit event is missed. The exit receiver is obtained from the registry's broadcast channel before `spawn_heartbeat_task`, `spawn_bandwidth_persist_task`, `spawn_ipc_loop`, and `spawn_critical_result("server_run", ...)` are invoked.

#### Fatality Policy by Task Class/Reason

The `is_fatal_exit(exit, shutdown_started)` helper classifies task exits:

| Task Class | Before Shutdown | During Shutdown |
|------------|----------------|-----------------|
| **CriticalService** | Fatal for `UnexpectedCompletion`, `Panic`, `Error`, and `Cancelled` | Fatal for `UnexpectedCompletion`, `Panic`, `Error` only |
| **RestartableBackground** | Never fatal (logged/degraded) | Never fatal (logged/degraded) |
| Other classes | Not part of worker-level exit channel | Not part of worker-level exit channel |

#### True `UnexpectedCompletion` Semantics

- **Pre-shutdown**: `Ok(())` from a `CriticalService` that was not cancelled is classified as `UnexpectedCompletion` — the task finished without being told to stop.
- **Post-shutdown** (`shutdown_started == true`): `Ok(())` is classified as `CleanCompletion` — the task returned cleanly during coordinated shutdown.

#### Server Task Ownership

The server run task is now registry-owned via `spawn_critical_result("server_run", ...)`. The old standalone `spawn_server_run_task` function has been removed. All supervision, shutdown, and metrics recording flows through `WorkerTaskRegistry`.

#### Broadcast Lag/Closure Policy

The supervision loop handles `broadcast::error::RecvError` as follows:

- **`Lagged(skipped)`**: Treated as a lifecycle infrastructure failure. The receiver missed events, so supervision integrity is compromised. Triggers shutdown with `RegistryExitChannelClosed` cause.
- **`Closed` during shutdown**: Expected — the registry has been shut down and the broadcast sender dropped. Triggers `SupervisorShutdown` cause.
- **`Closed` while active**: Lifecycle failure — the exit channel closed while the registry was still running. Triggers `RegistryExitChannelClosed` cause.

#### Final Bandwidth Persistence Guarantee

The bandwidth persist task performs a final flush after its loop breaks on every shutdown cause. `persist_global_bandwidth_tracker()` is called unconditionally after the select-loop exits, ensuring no dirty state is lost regardless of how the shutdown signal was received.

#### Primary Shutdown-Cause Selection

`WorkerShutdownCause` classifies the root cause of worker shutdown:

| Variant | Meaning | Nonzero Exit Code | Notify Supervisor |
|---------|---------|-------------------|-------------------|
| `ServerExited` | Server run task exited (normal or error) | No | No |
| `CriticalTaskExit(NamedTaskExit)` | Critical service exited abnormally | Yes | Yes |
| `SupervisorShutdown` | Supervisor initiated coordinated shutdown | No | No |
| `SupervisorDisconnected` | IPC connection lost | Yes | Yes |
| `RegistryExitChannelClosed` | Broadcast channel closed unexpectedly | Yes | Yes |
| `ExternalStop` | External stop signal received | No | No |
| `RunningFlagCleared` | Worker running flag cleared (resize) | No | No |

#### IPC Loop Typed Completion

The IPC loop returns typed completion via `IpcLoopExit` (expected completions) and `IpcLoopError` (failures):

- **`IpcLoopExit::MasterShutdown`**: Processed master shutdown command.
- **`IpcLoopExit::WorkerResize`**: Processed threadpool resize command.
- **`IpcLoopExit::RegistryShutdown`**: Registry cancellation during coordinated shutdown.
- **`IpcLoopExit::RunningFlagCleared`**: Worker running flag intentionally cleared.
- **`IpcLoopError::ConnectionLost`**: Supervisor connection lost (maps to `SupervisorDisconnected`).
- **`IpcLoopError::Unexpected(String)`**: Unexpected panic or error.

`IpcLoopExitCause` (shared `Arc<RwLock<Option<IpcLoopExit>>>`) communicates the specific exit path to the caller when the loop returns `Ok(())`.

## Iteration 64: Coordinated Shutdown Intent and Lifecycle Events

### Shutdown Intent vs Cancellation

The `WorkerTaskRegistry` now separates shutdown intent from task cancellation:

- **`begin_shutdown()`**: Records coordinated shutdown intent by setting `shutdown_started` and `shutdown_started_arc` atomic flags. Changes task completion classification from `UnexpectedCompletion` to `CleanCompletion` immediately. Does NOT send the cancellation signal to tasks.
- **`broadcast_shutdown()`**: Sends `true` on the watch channel, signaling tasks to stop cooperatively.
- **`shutdown()`**: Calls both `begin_shutdown()` + `broadcast_shutdown()` (defensive full shutdown).

The composition root must call `begin_shutdown()` before any tasks are asked to return, ensuring their completion is classified as expected.

### WorkerLifecycleEvent Channel

The IPC task now emits typed lifecycle events instead of performing inline shutdown:

```rust
pub enum WorkerLifecycleEvent {
    MasterShutdown { graceful: bool, timeout: Duration },
    WorkerResize { worker_threads: usize },
    SupervisorDisconnected,
}
```

The IPC loop stores the event in a shared `Arc<RwLock<Option<WorkerLifecycleEvent>>>` and returns cleanly. The composition root reads the event after the supervision loop exits to determine the correct shutdown procedure.

### Authoritative WorkerShutdownCause

`WorkerShutdownCause` is now the single authoritative source for:

- Process exit code (`exit_code()` method)
- Supervisor notification policy (`should_notify_supervisor()`)
- Expected/unexpected classification (`is_expected()`)

The `worker_exit_code` field has been removed. The `master_dead` flag is retained as a health observation but does not independently override the primary shutdown cause.

#### ServerExited Split

`ServerExited` has been split into two variants:

| Variant | Meaning | Exit Code | Expected |
|---------|---------|-----------|----------|
| `ServerExitedUnexpectedly` | Server task returned while worker is active | 1 | No |
| `ServerStoppedForShutdown` | Server task completed after coordinated shutdown | 0 | Yes |

#### WorkerResize Variant

`WorkerResize { worker_threads: usize }` carries the requested thread count and uses the special exit code `100`.

### Composition-Root Shutdown Procedure

The ordered shutdown sequence is now owned by the composition root in `src/worker/unified_server/mod.rs`:

1. Record primary shutdown cause from lifecycle event
2. Call `registry.begin_shutdown()`
3. Stop accepting new connections
4. Graceful drain (if requested, bounded by `drain_timeout`)
5. Stop app servers (Granian supervisors)
6. Clear running flag
7. Broadcast registry cancellation
8. Await registry tasks with bounded timeouts
9. Abort remaining non-migrated task handles
10. Send `UnifiedServerWorkerShutdownComplete` (if not a fatal cause)
11. Derive exit code from `shutdown_cause.exit_code()`

### ShutdownComplete Acknowledgement Ordering

`UnifiedServerWorkerShutdownComplete` is now sent from the composition root **after** all registry-owned tasks have been joined or aborted, not from the IPC task's inline shutdown branch. This ensures the supervisor is told "complete" only when shutdown is actually complete.

### Bandwidth Persistence Ownership

The bandwidth persist background task owns both periodic and final flushes. The composition root does NOT call `persist_global_bandwidth_tracker()` directly — the background task's final flush after the shutdown signal is the single authoritative persistence point. This eliminates double-flush ambiguity.

### IPC Loop Behavioral Changes

The IPC loop no longer performs inline shutdown for `MasterShutdown` or `WorkerResize`. Instead:

- **`MasterShutdown`**: Stores `WorkerLifecycleEvent::MasterShutdown { graceful, timeout }` and returns `Ok(())`
- **`WorkerResize`**: Stores `WorkerLifecycleEvent::WorkerResize { worker_threads }` and returns `Ok(())`
- **`ConnectionLost`**: Stores `WorkerLifecycleEvent::SupervisorDisconnected` and returns `Err(IpcLoopError::ConnectionLost)`

The `IpcLoopExitCause` side-channel is retained for backward compatibility but is no longer consumed by the composition root.

### Guardrail Additions

New guardrail tests in `tests/background_task_ownership_guard.rs`:

- `master_shutdown_begins_intent_before_running_stop` — `begin_shutdown()` precedes `running.stop()`
- `shutdown_complete_sent_from_composition_root` — `ShutdownComplete` after `shutdown_and_join`
- `ipc_loop_emits_lifecycle_event_not_inline_shutdown` — IPC emits events, not inline shutdown
- `worker_shutdown_cause_has_exit_code` — `exit_code()` method exists
- `server_exit_distinguishes_expected_unexpected` — `ServerExitedUnexpectedly` and `ServerStoppedForShutdown` variants
- `begin_shutdown_and_broadcast_are_separate` — separate `begin_shutdown()` and `broadcast_shutdown()` methods
- `exit_code_derived_from_shutdown_cause` — exit code from `shutdown_cause.exit_code()`, not `worker_exit_code`
- `graceful_fields_consumed_by_drain` — `graceful` and `drain_timeout` consumed by shutdown path

## Guardrail

The test `tests/background_task_ownership_guard.rs` enforces structured concurrency hygiene:

- **Unregistered long-lived spawn detection**: Scans audited modules for `tokio::spawn` calls and verifies each is registered with a task registry or has an explicit exception.
- **Missing cancellation select**: Flags interval/polling loops that lack a `tokio::select!` branch on a shutdown signal.
- **Missing shutdown/join in critical services**: Ensures every CriticalService task has a registered cancellation path and join handle.
- **New detached task allowlist**: Any `tokio::spawn` without a retained handle must appear in the explicit allowlist with documented rationale.

Run the guardrail with:

```bash
cargo test --test background_task_ownership_guard
```
