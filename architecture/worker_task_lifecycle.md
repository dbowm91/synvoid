# Worker Task Lifecycle — Iteration 67

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

#### IPC Loop Error Handling

The IPC loop returns typed errors via `IpcLoopError`:

- **`IpcLoopError::ConnectionLost`**: Supervisor connection lost (triggers `SupervisorDisconnected`).
- **`IpcLoopError::Unexpected(String)`**: Unexpected panic or error.

Lifecycle events are communicated via the `LifecycleRequest` channel, not via shared state.

## Iteration 64: Coordinated Shutdown Intent and Lifecycle Events

### Shutdown Intent vs Cancellation

The `WorkerTaskRegistry` now separates shutdown intent from task cancellation:

- **`begin_shutdown()`**: Records coordinated shutdown intent by setting `shutdown_started` and `shutdown_started_arc` atomic flags. Changes task completion classification from `UnexpectedCompletion` to `CleanCompletion` immediately. Does NOT send the cancellation signal to tasks.
- **`broadcast_shutdown()`**: Sends `true` on the watch channel, signaling tasks to stop cooperatively.
- **`shutdown()`**: Calls both `begin_shutdown()` + `broadcast_shutdown()` (defensive full shutdown).

The composition root must call `begin_shutdown()` before any tasks are asked to return, ensuring their completion is classified as expected.

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

### Bandwidth Persistence Ownership

The bandwidth persist background task owns both periodic and final flushes. The composition root does NOT call `persist_global_bandwidth_tracker()` directly — the background task's final flush after the shutdown signal is the single authoritative persistence point. This eliminates double-flush ambiguity.

## Iteration 65: Lifecycle Event Channel and Acknowledgement

### Lifecycle Event Channel (Phase 1)

The IPC task now communicates lifecycle events to the composition root via a real `tokio::sync::mpsc` channel instead of a shared `Arc<RwLock<Option<...>>>`:

```rust
pub struct LifecycleRequest {
    pub event: WorkerLifecycleEvent,
    pub accepted: tokio::sync::oneshot::Sender<()>,
}
```

The IPC loop sends a `LifecycleRequest` containing the event and a oneshot acknowledgement sender. The composition root receives the request, calls `begin_shutdown()`, then acknowledges via the oneshot channel.

### Coordinator Acknowledgement Handshake (Phase 2)

For expected lifecycle events (`MasterShutdown`, `WorkerResize`), the IPC task waits for the composition root's acknowledgement before returning:

1. IPC task receives `MasterShutdown` or `WorkerResize` from supervisor
2. IPC task sends `LifecycleRequest` to composition root via mpsc channel
3. IPC task awaits `accepted` oneshot receiver
4. Composition root calls `begin_shutdown()` then sends acknowledgement
5. IPC task returns — its exit is classified as `CleanCompletion`

For `SupervisorDisconnected`, the IPC task sends the event, awaits acknowledgement, then returns `Err(IpcLoopError::ConnectionLost)`.

### Supervision Loop Integration (Phase 3)

The supervision loop selects over both lifecycle events and task exits:

```rust
let (shutdown_cause, lifecycle_ack) = loop {
    tokio::select! {
        request = lifecycle_rx.recv() => {
            // Lifecycle event from IPC — break with event and ack sender
        }
        exit = exit_rx.recv() => {
            // Task exit from registry — handle fatality
        }
    }
};
```

Lifecycle events arrive **before** the IPC critical task returns, ensuring `begin_shutdown()` is called before any task is allowed to exit.

### Removed Types (Phase 4)

`IpcLoopExitCause` and `IpcLoopExit` have been removed. They were a shared-state side channel that is now redundant with the lifecycle event channel. The IPC loop no longer writes to `Arc<RwLock<Option<IpcLoopExit>>>`.

### Dedicated Resize Acknowledgement (Phase 6)

The composition root now sends `UnifiedServerWorkerResizeAck` for `WorkerResize` causes instead of `UnifiedServerWorkerShutdownComplete`:

| Cause | Message Sent |
|-------|-------------|
| `SupervisorShutdown` | `UnifiedServerWorkerShutdownComplete` |
| `WorkerResize` | `UnifiedServerWorkerResizeAck` |
| `CriticalTaskExit` | `WorkerError` |
| `ServerExitedUnexpectedly` | `WorkerError` |
| `RegistryExitChannelClosed` | `WorkerError` |
| `SupervisorDisconnected` | no-op (channel unavailable) |
| Other | no-op |

### Legacy Handle Abort-and-Await (Phase 7)

Legacy `state.task_handles` are now aborted **and awaited** before shutdown completion is reported:

```rust
let mut handles = state.task_handles.lock().await;
let handles_to_await: Vec<_> = std::mem::take(&mut *handles);
drop(handles);
for handle in handles_to_await {
    handle.abort();
    let _ = handle.await;
}
```

No legacy handle remains in the vector after shutdown. Every aborted handle is awaited.

### Explicit Fatal Supervisor Notification (Phase 8)

When the cause is fatal and IPC remains available, the composition root sends a structured `WorkerError` before closing down:

- `CriticalTaskExit` → WorkerError with task name/reason
- `ServerExitedUnexpectedly` → WorkerError with runtime failure
- `RegistryExitChannelClosed` → WorkerError with infrastructure failure
- `SupervisorDisconnected` → no-op (channel unavailable)

### Acknowledgement Routing (Phase 9)

The `notify_supervisor_of_worker_exit` logic is now a `match` on `WorkerShutdownCause` with explicit routing per cause, replacing the previous `should_notify_supervisor()` boolean guard.

### Composition-Root Shutdown Procedure (Updated)

The ordered shutdown sequence:

1. Receive lifecycle event from IPC task (supervision loop)
2. Map event to `WorkerShutdownCause`
3. Call `registry.begin_shutdown()` — records coordinated shutdown intent
4. Acknowledge lifecycle event — IPC task can return cleanly
5. Stop accepting new connections
6. Graceful drain (if requested, bounded by `drain_timeout`)
7. Stop app servers (Granian supervisors)
8. Clear running flag
9. Broadcast registry cancellation
10. Await registry tasks with bounded timeouts
11. Abort and await legacy non-migrated task handles
12. Send supervisor acknowledgement by cause (ShutdownComplete/ResizeAck/WorkerError)
13. Derive exit code from `shutdown_cause.exit_code()`

### Guardrail Additions

New guardrail tests in `tests/background_task_ownership_guard.rs`:

- `ipc_lifecycle_uses_channel_not_shared_state` — IPC must use channel, not Arc<RwLock>
- `ipc_loop_exit_cause_removed` — IpcLoopExitCause/IpcLoopExit must be removed
- `resize_cause_routes_to_resize_ack` — resize sends ResizeAck
- `legacy_handles_awaited_after_abort` — legacy handles are awaited after abort
- `fatal_causes_send_worker_error` — fatal causes send WorkerError
- `lifecycle_ack_after_begin_shutdown` — lifecycle ack happens after begin_shutdown
- `supervision_selects_lifecycle_events` — supervision loop selects lifecycle_rx

New integration tests in `tests/worker_supervision_control_flow.rs`:

- `test_lifecycle_channel_master_shutdown_classifies_cleanly` — real MasterShutdown via lifecycle channel produces clean completion
- `test_lifecycle_channel_closure_during_shutdown` — channel closure is handled gracefully
- `test_resize_cause_maps_to_resize_exit_code` — resize exit code and properties
- `test_fatal_cause_should_notify_supervisor` — fatal cause notification
- `test_supervisor_disconnect_no_notification` — disconnect no-op
- `test_legacy_handle_abort_and_await_completes` — abort+await completes within timeout
- `test_shutdown_ordering_begin_before_stop_accepting` — ordering verification

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

## Iteration 66: Supervision Cause Preservation Cleanup

The supervision loop now returns a typed `SupervisionOutcome` instead of `(WorkerLifecycleEvent, Option<oneshot::Sender<()>>)`. This preserves direct shutdown causes without converting them to fake lifecycle events.

### Key Changes

- **`SupervisionOutcome` enum**: Two variants — `Lifecycle { event, accepted }` and `DirectCause(WorkerShutdownCause)`. Lifecycle events flow through the existing acknowledgement handshake; direct causes bypass it.
- **Fatal task exits**: Use `map_task_exit_to_shutdown_cause()` — `server_run` maps to `ServerExitedUnexpectedly`, other critical tasks to `CriticalTaskExit(exit)`.
- **Registry lag/closure**: Use `map_exit_recv_error_to_shutdown_cause()` — `RecvError::Lagged` always maps to `RegistryExitChannelClosed`; `RecvError::Closed` maps to `RegistryExitChannelClosed` only if shutdown not started.
- **Lifecycle channel closure**: Use `map_lifecycle_channel_closed()` — returns `RegistryExitChannelClosed` if active, `None` if shutdown already started.
- **No lifecycle channel closure synthesizes `MasterShutdown`**.
- **`should_notify_supervisor()` corrected**: `SupervisorDisconnected` returns `false` (channel unavailable), `ServerExitedUnexpectedly` returns `true`.
- **IPC lifecycle sends**: Use `request_lifecycle_transition()` which returns `IpcLoopError` on channel closure or dropped acknowledgement.
- **Helper functions** (`map_task_exit_to_shutdown_cause`, `map_exit_recv_error_to_shutdown_cause`, `map_lifecycle_channel_closed`) are public and tested.

### New Tests

- 15 new tests in `tests/worker_supervision_control_flow.rs`
- 8 new guardrail checks in `tests/background_task_ownership_guard.rs`

## Iteration 67: Shutdown Intent and Lifecycle Error Cleanup

### Lifecycle Transition Error Propagation

All terminal `request_lifecycle_transition()` calls in the IPC loop now propagate errors with `?` instead of discarding them with `let _ =`. This makes lifecycle coordination failures visible as real task failures:

- **MasterShutdown**: lifecycle transition error produces `IpcLoopError::Unexpected`
- **WorkerResize**: lifecycle transition error produces `IpcLoopError::Unexpected`
- **SupervisorDisconnected**: if lifecycle transition fails, returns the coordination error; if it succeeds, returns `IpcLoopError::ConnectionLost`

### Supervision Loop is Side-Effect Free

The supervision loop (Phase 15) no longer calls `state.running.stop()` before returning the cause. It selects causes only — all teardown side effects happen in the composition root (Phase 16). This eliminates the race window where secondary task exits could be misclassified as `UnexpectedCompletion` during the transition between cause selection and `begin_shutdown()`.

### begin_coordinated_shutdown Helper

A `begin_coordinated_shutdown()` helper in `lifecycle.rs` enforces the critical ordering invariant:

1. `registry.begin_shutdown()` — records coordinated shutdown intent
2. Lifecycle acknowledgement — IPC task can return cleanly

This helper is called before any stop-accepting, running-flag, listener, or cancellation action.

### Server Exit Detail Preservation

`ServerExitedUnexpectedly` now carries `NamedTaskExit` for diagnostic detail:

```rust
pub enum WorkerShutdownCause {
    ServerExitedUnexpectedly(NamedTaskExit),
    // ...
}
```

The supervisor `WorkerError` message now includes the task name and exit reason: `"Server task 'server_run' exited unexpectedly: error: ..."`.

### Secondary Exit Classification

After a primary cause is selected, secondary task exits are classified as expected cleanup:
- They do not increment `tasks_unexpectedly_completed`
- They cannot replace the primary `WorkerShutdownCause`
- They are classified as `CleanCompletion` (post-`begin_shutdown`) or expected cancellation

### New Tests

- 8 new tests in `tests/worker_supervision_control_flow.rs` covering lifecycle transition failures, secondary exit classification, server exit detail preservation, and primary cause immutability
- 4 new guardrail checks in `tests/background_task_ownership_guard.rs` verifying supervision side-effect freedom, helper encapsulation, lifecycle error propagation, and server exit detail preservation

## Mesh Transport Lifecycle (Iterations 68–69)

The mesh transport now uses structured lifecycle management:

### Mesh Task Classes
- **CriticalService**: mesh maintenance, datagram listener, QUIC accept loop
- **RestartableBackground**: PoW refresh, ML-KEM rotation, health checks, cache warming, DHT resync, load reporting, heartbeat
- **BoundedChild**: per-peer connection handlers
- **OneShotStartup**: self-attestation, seed bootstrap

### Lifecycle State Machine
- `Stopped -> Starting -> Running -> Stopping -> Stopped`
- `Starting -> Failed -> Stopped` (rollback on startup failure)
- `Running -> Failed -> Stopping/Stopped`

### Transactional Startup (Iteration 69: Staged)
Startup proceeds in phases using `MeshStartupStage`:
1. Validate state and configuration
2. Create fresh `MeshStartupStage` and `MeshTaskGroup`
3. Start critical loops (staged)
4. Bootstrap seeds/peers/DHT (policy-gated via `MeshStartupPolicy`)
5. Start background loops (staged)
6. Commit lifecycle state; stage hands off to running task group

If any phase fails, `rollback_startup()` cancels and joins all staged tasks — no task group is dropped without cancellation and join.

### MeshStartupPolicy
Controls required vs optional bootstrap:
- `require_seed_connectivity` (default false)
- `require_configured_peers` (default false)
- `require_dht_bootstrap` (default false)

Default is all-optional (degraded startup allowed). A required bootstrap failure triggers rollback.

### Bounded Shutdown (Iteration 69: Truthful Reporting)
`shutdown_with_timeout(timeout)` returns `MeshShutdownReport`:
1. Capture `peers_at_shutdown_start`
2. Transition to Stopping
3. Signal all tasks via watch channel
4. Close QUIC connections
5. Drain peer sessions (`peer_sessions: Arc<Mutex<JoinSet<()>>>`)
6. Drain handshake children
7. Join tasks with timeout, aborting stragglers
8. Measure `remaining_peers` after drain
9. Transition to Stopped

### Peer Session Ownership (Iteration 69)
- Handshake children: bounded, short-lived, semaphore-limited (in `JoinSet`)
- Peer sessions: long-lived, stored in `peer_sessions: Arc<Mutex<JoinSet<()>>>`
- Shutdown drains sessions after closing connections

### MeshServiceExit Variant (Iteration 69)
`WorkerShutdownCause` gains `MeshServiceExit(MeshTaskExit)` for mesh task failures. Fatal when the mesh task is `CriticalService` with `Error`, `Panic`, or `UnexpectedCompletion`. Worker supervision observes mesh exits via stable `subscribe_exits()` on `ManagedMeshService`.

### Mesh Shutdown Ordering (Iteration 69)
Mesh is drained before worker persistence/finalization:
1. Mesh `shutdown_with_timeout()` runs (stops mesh tasks, closes connections, drains sessions)
2. Worker stops CPU offload
3. Worker drains request children
4. Worker flushes persistent state

## Iteration 85: Worker Mesh Supervision Corrective Pass

### Disabled Mesh is Construction-Free

When `mesh.enabled = false` or mesh config is absent, `MeshInit::disabled()` returns no runtime resources. No topology, routing, transport, DNS, YARA, or DHT objects are created. No supervision pipeline exists.

### Restart is Disabled

`restart_enabled` is overridden to `false` at policy-build time regardless of config. `RestartMesh` is unreachable in production policy. No restart metrics increment.

### Topology and DHT Background Tasks

Topology and DHT routing background tasks are returned in `MeshInit` as component handles. The composition root starts them after mesh startup succeeds and registers them in `WorkerTaskRegistry`. They use internal shutdown signals — construction functions construct only, never start background tasks.

### YARA Broadcast Uses JoinSet

The YARA broadcast loop owns per-message children in a local `tokio::task::JoinSet<()>`. Children are spawned into the set with semaphore-bounded concurrency. On shutdown, the loop drains or aborts-and-awaits the `JoinSet` before returning. No bare `tokio::spawn()` remains.

### Required Startup Failure is Handled Directly

For required mesh startup, the composition root already has `Result<(), MeshFailureCause>`. On failure: status transitions once, `SupervisionOutcome::DirectCause` is set immediately, no ready message is sent, the normal supervision loop is not entered, and coordinated shutdown begins. No coordinator round-trip is needed.

### Status Transitions Have Singular Ownership

`start_mesh_generation()` returns facts only (`Result<(), MeshFailureCause>`) without mutating status. The caller transitions `WorkerMeshStatus`. The coordinator handles runtime event transitions. Required startup failure transitions status directly.
5. Worker awaits critical services
