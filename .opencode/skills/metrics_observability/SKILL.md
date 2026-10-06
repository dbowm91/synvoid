---
name: metrics_observability
description: Metrics collection, naming conventions, Prometheus export, health and bandwidth tracking. Use when adding counters/gauges, touching the /metrics endpoint, or wiring admin observability.
---

# Metrics & Observability

## Overview

`crates/synvoid-metrics/` owns collection; the Prometheus exporter lives at
`src/admin/prometheus_exporter.rs` (composition root — keep export wiring
there, reusable aggregation in the crate).

## Key Files

- `crates/synvoid-metrics/src/collection.rs` - Collector registry + scrape
- `crates/synvoid-metrics/src/types.rs` - Metric types (atomics-backed;
  timing summaries with avg/p50/p95/p99 via sorted samples)
- `crates/synvoid-metrics/src/payloads.rs` - `SiteMetricsPayload`,
  `WorkerMetricsPayload`, `ServerlessMetrics`, `TimingStatsPayload`,
  `HealthStatus`
- `crates/synvoid-metrics/src/bandwidth.rs` - `BandwidthTracker`
- `crates/synvoid-metrics/src/health.rs` - Health aggregation
- `crates/synvoid-metrics/src/adapter.rs` - Exporter adapters
- `src/admin/prometheus_exporter.rs` - Prometheus exposition wiring

## Conventions

- **Atomic hot path**: counters are `AtomicU64`/sharded (`DashMap`) — never
  lock on the request path for a metric increment.
- **Bounded summaries**: latency samples are fixed-size (`LATENCY_SAMPLE_SIZE`);
  p50/p95/p99 computed on sorted snapshot, never on unbounded Vec growth.
- **`synvoid.` prefix is the convention for newer metrics, not a universal one.**
  `metrics::counter!` / `gauge!` names use the `synvoid.<area>.<name>` dotted
  shape for current work (e.g. `synvoid.http.streaming_body_blocked`,
  `synvoid.supervisor.tasks_failed_total`, `synvoid.flood.connection_limited`),
  but a large set of older subsystem metrics is un-prefixed and underscore-shaped
  (e.g. `dns_cache_hits_total`, `dns_firewall_queries_blocked_total`). Match the
  surrounding subsystem's existing names rather than renaming across the divide;
  there is no bulk migration and no guard enforcing the prefix.
- **Diagnostics ≠ enforcement**: metrics observe; never gate a block/allow
  decision on a metric value (see `architecture/distributed_state_contract.md`).

## Verification

```bash
cargo nextest run -p synvoid-metrics --cargo-profile ci --profile ci
```
