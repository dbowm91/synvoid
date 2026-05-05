# ADR-003: Unified Worker Process Architecture

## Status
Accepted

## Date
2026-04-01

## Context
SynVoid originally planned a multi-process architecture with separate worker processes for HTTP, HTTPS, and AppServer workloads. The architecture evolved to a unified worker process.

## Decision
**The worker uses a single `UnifiedServer` with one tokio async event loop** that handles all workload types (HTTP, HTTPS, AppServer/Granian) concurrently via cooperative scheduling.

## Architecture

### Why Single Async Process?
- **Internal parallelism**: Use `tokio::spawn()` and async concurrency primitives (semaphores, channels) within the worker, NOT process-level parallelism
- **Efficient resource utilization**: A single event loop handles thousands of sites concurrently via cooperative scheduling
- **No context switching overhead**: Avoids IPC overhead between multiple worker processes
- **Simpler deployment**: Single worker process to manage

### Thread Pool for Connection Accepting
The worker uses an internal thread pool (`tcp.worker_pool_size: 4`) for accepting connections, but this runs within the single async context.

## What NOT to Do
**Do NOT increase `unified_server_workers` for scaling purposes.** This setting controls internal threading for connection accepting, not async concurrency.

For scaling, instead:
- Tune `tcp.worker_pool_size` for more connection accepting threads
- Use async concurrency primitives within the existing event loop
- Consider running multiple worker processes only if CPU cores are underutilized

## Performance Characteristics

| Scenario | Recommended Approach |
|----------|---------------------|
| Many concurrent connections | Single worker + async concurrency |
| CPU-intensive request processing | Offload to upstream (Granian) |
| Connection accepting bottleneck | Increase `worker_pool_size` |
| Truly independent isolation | Multiple worker processes |

## Consequences

### Positive
- Efficient handling of many concurrent connections
- Simpler architecture and debugging
- Lower memory footprint than multi-process
- Cooperative scheduling avoids lock contention

### Negative
- Single point of failure (mitigated by supervisor restarting worker)
- CPU-bound work blocks the event loop (mitigated by offloading to upstream)
- Less isolation than multi-process (acceptable for WAF workload)

## References
- `src/worker/unified_server.rs` - Main unified server implementation
- `src/worker/mod.rs` - Worker process management
- `src/app_server/granian.rs` - AppServer/Granian integration
