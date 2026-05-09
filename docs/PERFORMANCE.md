# Performance & Latency Guide

This guide covers performance tuning and latency optimization for SynVoid's Shared-Nothing Architecture.

## Architecture Overview

SynVoid uses a two-tier **Shared-Nothing Architecture** to eliminate coordination overhead and achieve linear scalability:
- **Supervisor**: Centralized Control Plane. Handles heavy coordination (Raft, Mesh, gRPC) away from the data plane.
- **Workers**: Lightweight Data Plane engines. Each worker is isolated, core-pinned, and handles requests independently.

## Zero-Jitter Shared-Nothing Data Plane

The transition to a shared-nothing model is the cornerstone of SynVoid's performance:

### 1. Kernel-Level Load Balancing (SO_REUSEPORT)
Workers use `SO_REUSEPORT` to allow the OS kernel to distribute incoming connections. This eliminates the "thundering herd" problem and removes the need for a user-space master to distribute file descriptors.

### 2. CPU Core Affinity
On Linux, workers are automatically pinned to specific CPU cores via `sched_setaffinity`. This ensures:
- **Cache Locality:** The worker's memory and CPU caches stay hot.
- **Zero Context Switching:** Eliminates jitter caused by the OS scheduler moving processes between cores.

### 3. Independent Event Loops
Each worker runs a dedicated, single-threaded Tokio runtime. Since there is no shared state between workers, there is zero lock contention in the request-handling hot path.

## Performance Tuning

### 1. Worker Configuration

Match the number of workers to your physical CPU cores for optimal performance.

```toml
[server]
worker_processes = "auto" # Automatically pins one worker per core
```

### 2. gRPC Control Plane Efficiency
The Supervisor handles all administrative tasks (status, reloads, mesh sync) via gRPC. By relegating these tasks to a separate process, the Workers can dedicate 100% of their CPU time to request inspection and proxying.

### 3. IPC Communication
The Supervisor pushes configuration updates and threat intelligence to workers via a high-speed binary IPC protocol. Updates are applied by workers using lock-free `arc-swap` mechanisms, ensuring that configuration reloads do not stall traffic.

### 4. Rate Limiting Efficiency
In shared-nothing mode, rate limiting can be configured for maximum performance:

```toml
[ratelimit]
mode = "isolated" # Per-worker limits (zero IPC overhead)
# OR
mode = "distributed" # Supervisor-coordinated (consistent across nodes)
```

## Monitoring for Performance

Key metrics to watch:

- **Worker Core Utilization:** Ensure even distribution across cores.
- **p99 Latency:** Monitor for jitter that might indicate core contention.
- **SO_REUSEPORT Distribution:** Verify the kernel is balancing connections fairly.

## Benchmarking

Use tools like `wrk` or `oha` to benchmark. Because of the shared-nothing design, you should see near-linear throughput increases as you add CPU cores.

```bash
# Benchmark with 100 concurrent connections
wrk -t4 -c100 -d30s http://localhost:80/
```

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [PROCESS_MANAGEMENT.md](./PROCESS_MANAGEMENT.md) - Supervisor & Worker details
- [DEVELOPER.md](./DEVELOPER.md) - Technical deep-dive
