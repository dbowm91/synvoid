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
- **`synvoid.` prefix**: metric names in code use the `synvoid.<area>.<name>`
  shape (e.g. `synvoid.http.streaming_body_blocked`, `synvoid.waf.rule_update_success`).
  Keep new names in the same hierarchy; check `collection.rs` for collisions.
- **Diagnostics ≠ enforcement**: metrics observe; never gate a block/allow
  decision on a metric value (see `architecture/distributed_state_contract.md`).

## Verification

```bash
cargo nextest run -p synvoid-metrics --cargo-profile ci --profile ci
```
