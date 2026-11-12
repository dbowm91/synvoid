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
[process_manager]
worker_threads = 0         # 0 = tokio auto (recommended default)

[defaults.worker_pool]
workers = 1                # type default and shipped default
allow_multi_worker = false # required acknowledgement above 1

[tcp]
worker_pool_size = 4       # accept loops per bound TCP listener
```

`workers > 1` is an isolation opt-in, not a throughput knob: sessions, CSRF
tokens, the admin rate-limit budget, the metrics feed and request logs stay
per worker. For HTTP throughput raise `worker_threads` first, then tune the
accept path; for TCP services raise `[tcp].worker_pool_size`.

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
mode = "shared" # Coordinated limits (consistent across workers)
```

Only `shared` and `isolated` are valid modes (anything else fails config
validation).

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

**The repository does not publish a cross-host headline RPS claim.** The
"1M+ RPS" wording that appeared in early design notes is a design target, not a
measured release property. A throughput number is only meaningful with the host,
kernel, CPU, build profile, concurrency, workload and network topology attached;
the repository therefore records dated, reproducible runs instead of a single
marketing figure.

Use the manual multi-service harness for end-to-end evidence:

```bash
# Smoke: validates the harness pipeline only. Never adjudication evidence.
python3 benchmarks/multi_service/driver.py --smoke

# Focused run: one process profile, named workloads, 15 s each.
python3 benchmarks/multi_service/driver.py \
  --process-profiles default \
  --workloads vhost-1,vhost-100,vhost-1000,h1-concurrent,waf-small,waf-body \
  --duration 15

# Tokio thread scaling curve.
python3 benchmarks/multi_service/driver.py \
  --process-profiles threads-1,threads-4,threads-8 --workloads h1-concurrent
```

The harness starts SynVoid and its local upstreams, records the revision SHA,
harness SHA, toolchain, host CPU/kernel, build profile, topology, command line
and concurrency, and writes JSON + Markdown under
[`benchmarks/multi_service/results/YYYY-MM-DD/`](../benchmarks/multi_service/results/).
The latest full smoke run (pipeline check, not adjudication evidence) is
`benchmarks/multi_service/results/2026-11-11/2026-11-11T050811Z-85cd26-summary.md`;
it predates canonical multi-listener support. The focused post-change
multi-listener run is
`benchmarks/multi_service/results/2026-11-11/2026-11-11T230416Z-fe8be0-summary.md`,
which probes and measures both the main and extra `[[http.listeners]]` entries.
`multi-listener` is now classified as supported by the harness; a fresh full
matrix run is still required before using counts from the older summary.
See [`benchmarks/multi_service/README.md`](../benchmarks/multi_service/README.md)
for the workload matrix, result schema and the unsupported-workload contract.

`wrk` or `oha` are still useful for quick tuning loops. Expect improvements
when tuning the right knob for the bottleneck:

- `worker_threads` for runtime scheduling parallelism
- `tcp.worker_pool_size` for TCP accept-loop concurrency
- `[udp].worker_pool_size` for UDP receive-loop concurrency
- CPU worker count for heavy transform throughput

```bash
# Quick local check, not evidence: 100 concurrent connections.
wrk -t4 -c100 -d30s http://localhost:80/
```

### How to reproduce and what loopback means

1. Build the subject from the SHA you will record (`cargo build --release`) and
   do not rebuild during a run.
2. Run the harness on an otherwise idle host. Do not run a container build,
   browser or another load generator at the same time.
3. Keep a no-WAF baseline (`--waf-profile off`) beside the WAF run
   (`--waf-profile on`) and the terminal-action run (`--waf-profile block`).
4. Keep the dated result directory; never overwrite a prior run.

The harness is loopback-only: client, SynVoid and upstream share `127.0.0.1`.
That removes the NIC, the network RTT and most kernel packet processing, so real
deployments normally show lower request rates and higher tail latency. **Never
compare results across hosts, kernels, CPU models, build profiles or container
runtimes.** The result files record the exact host and topology for this reason.

## Campaign Evidence (Phases 49-55, 2026-09)

The performance-optimization campaign is closed. Before/after evidence,
methodology, and hypothesis dispositions live in
`architecture/performance_optimization_closeout.md`; the measurement baseline
in `architecture/performance_optimization_baseline.md`; the Phases 56–57
corrective runtime/evidence record (stateful writer shutdown, runner-owned
maintenance, strict `TeeBody` reservation, durable runner lifecycle with
terminal one-instance ownership, immutable requalification incl. WAF
concurrency 1/8/32/128, host/target separation) in
`architecture/performance_optimization_corrective_closeout.md`. Headline results on
the campaign host: WAF small-request latency ~4-5× (borrowed inline detector
evaluation replaced per-request task fanout), upstream selection 2-13×
(allocation-free predicate selection), per-site metric accounting 1.7×,
honeypot SQLite isolated off Tokio workers with drain-capable shutdown, and
buffer-pool correctness hardening (zero-prefix, stale-reuse, accounting, and
tiering invariants) with bounded retention. No public API, config, WAF
coverage, metric, or protocol behavior changed. Known cost retained:
isolated single 10 KiB-body WAF latency regressed while all concurrent
batches improved; whole-stage offload stays deferred pending event-loop
evidence.

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [PROCESS_MANAGEMENT.md](./PROCESS_MANAGEMENT.md) - Supervisor & Worker details
- [DEVELOPER.md](./DEVELOPER.md) - Technical deep-dive
