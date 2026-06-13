# Worker Task Lifecycle — Iteration 61

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
| 1 | `spawn_heartbeat_task` | `lifecycle.rs:58` | RestartableBackground | UnifiedServerWorkerState | `running.is_running()` check | JoinHandle in `task_handles` | log+continue on error | Periodic heartbeat to supervisor |
| 2 | `spawn_bandwidth_persist_task` | `lifecycle.rs:129` | RestartableBackground | (unowned) | NONE | JoinHandle in `task_handles` | runs forever | Bandwidth counter persistence |
| 3 | `spawn_ipc_loop` | `lifecycle.rs:140` | CriticalService | UnifiedServerWorkerState | `running.is_running()` + `MasterShutdown` | JoinHandle in `task_handles` | break on error, marks `master_dead` | Supervisor/worker IPC message loop |
| 4 | `spawn_server_run_task` | `lifecycle.rs:744` | CriticalService | UnifiedServerWorkerState | `shutdown_tx` broadcast | Awaited directly | marks `running.stop()` on error | Unified server main run loop |
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

Abort remaining tasks after timeout and report them. Any tasks still running after the final timeout are forcibly aborted. The task identity and class are logged for post-mortem analysis.

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
pub struct WorkerTaskRegistry { /* ... */ }

impl WorkerTaskRegistry {
    pub fn new(config: TaskRegistryConfig) -> Self;
    pub fn shutdown_token(&self) -> CancellationToken;
    pub fn spawn_critical<F>(&self, name: &'static str, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
    pub fn spawn_background<F>(&self, name: &'static str, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
    pub async fn shutdown(self) -> TaskRegistryShutdownSummary;
}

pub struct TaskRegistryShutdownSummary {
    pub critical_joined: usize,
    pub background_joined: usize,
    pub aborted: Vec<(&'static str, TaskClass)>,
    pub panicked: Vec<(&'static str, TaskClass)>,
}
```

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
