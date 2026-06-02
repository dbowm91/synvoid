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
- `src/worker/unified_server.rs` - Main unified server implementation
- `src/worker/mod.rs` - Worker process management
- `src/app_server/granian.rs` - AppServer/Granian integration
