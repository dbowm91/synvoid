# ADR-003: Unified Worker Process Architecture

## Status
Accepted

## Date
2026-04-01

## Context
SynVoid originally planned a multi-process architecture with separate worker processes for HTTP, HTTPS, and AppServer workloads. The architecture evolved to a unified worker process.

## Decision
**The default data-plane model is `1 UnifiedServerWorker + N CPU offload workers`.**

The unified worker uses one tokio async event loop for latency-sensitive network I/O and cheap request-path work (HTTP, HTTPS, HTTP/3, routing, and streaming proxying). CPU-heavy transforms run in separate CPU offload workers.

## Architecture

### Why Single Async Process?
- **Internal parallelism**: Use `tokio::spawn()` and async concurrency primitives (semaphores, channels) within the worker, NOT process-level parallelism
- **Efficient resource utilization**: A single event loop handles thousands of sites concurrently via cooperative scheduling
- **No context switching overhead**: Avoids IPC overhead between multiple worker processes
- **Simpler deployment**: Single worker process to manage

### Thread Pool for Connection Accepting
The unified worker uses an internal connection-accept pool (`tcp.worker_pool_size`) that runs inside the same process. This is an I/O scaling knob, not a CPU-heavy transform knob.

## Scaling Contract
**Do NOT use `unified_server_workers` as a general-purpose throughput scaling knob.**

Use each control for its intended scope:
- `worker_threads` (tokio runtime): internal async scheduling parallelism in the unified worker process.
- `tcp.worker_pool_size`: connection accept path throughput.
- CPU offload worker count: bounded execution capacity for heavy transforms (compression/minification/image transforms/deep scanning/plugin execution).
- `unified_server_workers`: advanced mode only, for explicit process isolation or specialized deployments.
- Multi-worker shared-port startup (`SO_REUSEPORT`): listener bind is the source of truth; pre-bind conflict checks are skipped only for explicit shared-port mode.

## Performance Characteristics

| Scenario | Recommended Approach |
|----------|---------------------|
| Many concurrent connections | Single unified worker + async concurrency |
| CPU-intensive request processing | Offload to CPU workers |
| Connection accepting bottleneck | Increase `worker_pool_size` |
| Truly independent process isolation | Advanced multi-unified-worker mode |

## Consequences

### Positive
- Efficient handling of many concurrent connections
- Simpler architecture and debugging
- Lower memory footprint than multi-process
- Cooperative scheduling avoids lock contention

### Negative
- Single point of failure (mitigated by supervisor restarting worker)
- CPU-bound work can block the event loop if not offloaded (mitigated by CPU workers)
- Less isolation than multi-process (acceptable for WAF workload)

## Multi-Worker Semantics (Advanced Mode)

When `unified_server_workers > 1` is explicitly configured:

- This is an advanced isolation mode, not a default scaling recommendation.
- Shared-port (`SO_REUSEPORT`) startup uses listener bind as source of truth; pre-bind port checks are skipped only for that path.
- Runtime state is primarily per-worker (connections, in-memory caches, local counters).
- Supervisor owns global aggregation and management-plane reporting across workers.
- Cache invalidation/reload behavior is coordinated by supervisor commands, with per-worker cache refresh and eventual convergence.

## References
- `src/worker/unified_server/mod.rs` - Main unified server implementation
- `src/worker/mod.rs` - Worker process management
- `src/app_server/granian.rs` - AppServer/Granian integration

## Structured Concurrency (Iteration 61)

Every long-lived task in the unified worker has an owner, a cancellation path, a join path, and an explicit failure policy. The `WorkerTaskRegistry` in `src/worker/task_registry.rs` provides the lifecycle primitive. See `architecture/worker_task_lifecycle.md` for the full task inventory and shutdown ordering.

## Supervision Edge-Case Corrections (Iteration 63)

The supervision loop was corrected to close several edge-case gaps:

- **Subscription-before-spawn**: `subscribe_exits()` is called before any tasks are spawned to ensure no exit event is missed.
- **Fatality classification**: `is_fatal_exit()` distinguishes pre-shutdown from during-shutdown state. CriticalService is fatal before shutdown for `UnexpectedCompletion`, `Panic`, `Error`, and `Cancelled`; during shutdown, only abnormal exits are fatal.
- **`UnexpectedCompletion` semantics**: Pre-shutdown `Ok(())` from a non-cancelled CriticalService is `UnexpectedCompletion` (supervision failure). Post-shutdown `Ok(())` is `CleanCompletion` (expected).
- **Server run task ownership**: Now registered under `WorkerTaskRegistry` via `spawn_critical_result` as a `CriticalService`, completing the migration of all critical worker tasks.
- **Broadcast channel robustness**: `Lagged` errors cause conservative shutdown (supervision integrity compromised). `Closed` during shutdown is expected; `Closed` while active is a lifecycle failure.
- **Typed IPC completion**: `IpcLoopExit`/`IpcLoopError` provide structured exit reasons for the IPC loop, replacing ad-hoc flag checks.
- **Shutdown cause classification**: `WorkerShutdownCause` enum explicitly classifies the primary cause of worker shutdown for supervisor notification and exit code selection.
- **Final bandwidth flush**: Bandwidth persist task performs an unconditional final flush after its loop breaks, regardless of shutdown cause.

## Coordinated Shutdown Intent (Iteration 64)

The worker shutdown procedure was refactored to ensure shutdown intent is recorded before tasks are asked to return:

- **Shutdown intent vs cancellation**: `WorkerTaskRegistry::begin_shutdown()` records intent (atomic flags), `broadcast_shutdown()` sends cancellation. The composition root calls `begin_shutdown()` before stopping any services.
- **IPC lifecycle events**: The IPC task emits `WorkerLifecycleEvent` (MasterShutdown, WorkerResize, SupervisorDisconnected) instead of performing inline shutdown. The composition root orchestrates the full shutdown sequence.
- **Authoritative shutdown cause**: `WorkerShutdownCause::exit_code()` determines process exit code. `ServerExited` split into `ServerExitedUnexpectedly` (nonzero) and `ServerStoppedForShutdown` (zero). `WorkerResize` uses exit code 100.
- **ShutdownComplete ordering**: The supervisor acknowledgement is sent after all registry-owned tasks stop, not from the IPC task's inline handler.
- **Bandwidth persistence**: Single owner is the background task's final flush, eliminating double-flush ambiguity.
