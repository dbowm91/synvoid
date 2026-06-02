# Performance & Latency Guide

This guide covers performance tuning and latency optimization for SynVoid's default unified-worker architecture.

## Architecture Overview

SynVoid uses a two-tier architecture:
- **Supervisor**: Centralized Control Plane. Handles heavy coordination (Raft, Mesh, gRPC) away from the data plane.
- **Data Plane**: One latency-sensitive UnifiedServerWorker plus bounded CPU offload workers.

## Zero-Jitter Unified Data Plane

The core performance strategy is keeping request I/O on a unified async worker and pushing heavy transforms to bounded offload workers:

### 1. Kernel-Level Load Balancing (SO_REUSEPORT)
`SO_REUSEPORT` is available for advanced multi-unified-worker mode, but it is not the default throughput strategy.

### 2. CPU Core Affinity
On Linux, worker threads can be pinned to specific CPU cores via `sched_setaffinity`. This ensures:
- **Cache Locality:** The worker's memory and CPU caches stay hot.
- **Zero Context Switching:** Eliminates jitter caused by the OS scheduler moving processes between cores.

### 3. Unified Async Event Loop
The default unified worker runs the latency-sensitive HTTP path on a tokio runtime. CPU-heavy work should be offloaded to CPU workers to avoid event-loop stalls.

## Performance Tuning

### 1. Worker Configuration

Tune runtime and accept-path knobs first, then CPU worker count for heavy transforms.

```toml
[server]
worker_threads = 0         # 0 = tokio auto (recommended default)
unified_server_workers = 1 # default data-plane model

[tcp]
worker_pool_size = 4       # tune accept path throughput
```

### 2. gRPC Control Plane Efficiency
The Supervisor handles all administrative tasks (status, reloads, mesh sync) via gRPC. By relegating these tasks to a separate process, the Workers can dedicate 100% of their CPU time to request inspection and proxying.

### 3. IPC Communication
The Supervisor pushes configuration updates and threat intelligence to workers via a high-speed binary IPC protocol. Updates are applied by workers using lock-free `arc-swap` mechanisms, ensuring that configuration reloads do not stall traffic.

### 4. Rate Limiting Efficiency
Rate limiting mode can be tuned based on consistency vs overhead trade-offs:

```toml
[ratelimit]
mode = "isolated" # Per-worker limits (zero IPC overhead)
# OR
mode = "distributed" # Supervisor-coordinated (consistent across nodes)
```

### 5. HTTP/2 Scope Notes

SynVoid supports HTTP/2 upstream traffic, but scope differs by request path:
- Typed client path: supported and stable for full-body style upstream use.
- Erased-client streaming path: full HTTP/2 streaming pooling is not the default path and remains an advanced/deferred optimization.

## Monitoring for Performance

Key metrics to watch:

- **Worker Core Utilization:** Ensure even distribution across cores.
- **p99 Latency:** Monitor for jitter that might indicate core contention.
- **Event Loop Lag:** Detect CPU-heavy leakage into the unified worker path.
- **Offload Queue Depth/Timeouts:** Detect CPU worker saturation.

Unified worker heartbeat payloads now surface `event_loop_lag_ms`, `request_queue_time_ms`,
`active_connections`, per-phase inline CPU timings, and the async CPU offload submission,
timeout, rejection, and fallback counters. CPU worker heartbeat payloads include
`worker_rss_bytes` and the existing offload stats, including task submissions, inline-small
fallbacks, and `cpu_offload_task_duration_ms` summaries, so the supervisor can distinguish
I/O stalls from offload saturation, task latency regressions, and process growth.

## Benchmarking

Use tools like `wrk` or `oha` to benchmark. Expect improvements when tuning the right knob for the bottleneck:
- `worker_threads` for runtime scheduling parallelism
- `tcp.worker_pool_size` for accept throughput
- CPU worker count for heavy transform throughput

```bash
# Benchmark with 100 concurrent connections
wrk -t4 -c100 -d30s http://localhost:80/
```

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [PROCESS_MANAGEMENT.md](./PROCESS_MANAGEMENT.md) - Supervisor & Worker details
- [DEVELOPER.md](./DEVELOPER.md) - Technical deep-dive
