# Phase 04 Plan: Wire the Metrics Publisher and Request-Log Sinks

Status: **READY** (branch `plans/admin-panel-operator-correctness`; not started).

Registered in: `plans/roadmap.md`.

Campaign: `plans/admin_panel_operator_correctness_roadmap.md`.
Predecessor: none required for implementation (independent of Phases 01–03);
Phase 05 requires it.

## The finding

With live traffic flowing through the data plane, every admin telemetry
surface reads zero/empty: `/api/stats/summary` → `total_requests: 0`,
`/api/stats/history?seconds=300` → `[]`, `/api/stats/requests?limit=5` →
`{"entries":[],"total":0}`, per-site counters all zero with
`"upstream_healthy":"unknown"`. The panel's dashboard graphs, request-log
tab, and WAF block visibility are dead in **every** deployment mode, not
just standalone.

## Root cause (three breaks, one design)

1. `start_metrics_publisher` (`src/admin/metrics.rs:10`) — the sole writer
   of `AdminState` aggregated metrics, site metrics, and history via
   `update_metrics` / `update_site_metrics` / `add_metrics_to_history` — has
   **no production caller** (only `pub use` at `src/admin/mod.rs:31`; the
   `admin_surface_truthfulness` guard doc already records this). Nothing
   ever populates what `get_summary` / `get_sites_stats` read.
2. Request logs fork into the wrong deque. The data plane sends them only
   over IPC (`send_request_log_if_enabled` requires `Some(ipc)` +
   `Some(worker_id)`, `src/http/server/observability.rs:70`), the supervisor
   stores them in `ProcessManager.request_logs`
   (`crates/synvoid-ipc/src/manager.rs:1402`), but the admin API reads
   `AdminState.request_logs` (`src/admin/state.rs:679`), whose writer
   `add_request_log` (`state.rs:671`) has zero production callers. In
   standalone mode both halves are `None`, so logs are silently dropped.
3. Deployment config gate (operator-local, not committed): `~/prodtest`
   `main.toml` sets `[logging.verbose_request_logging] enabled = false`
   with all categories false — even a wired pipeline records nothing until
   this is enabled.

## Fix scope

- Spawn `start_metrics_publisher` from the composition root in both modes:
  - **Supervised:** pass the live `ProcessManager` (existing signature
    already takes it) and bridge `ProcessManager.request_logs` →
    `AdminState` (drain or snapshot-copy on the publisher tick; do not
    move the deque — the supervisor keeps owning it).
  - **Standalone:** feed the publisher a synthetic single-worker entry
    derived from the already-recorded `ServerSharedState.metrics`
    (`Option<Arc<WorkerMetrics>>`, `src/server/mod.rs:67`, attached to the
    data-plane servers) via the same `WorkerMetricsPayload` conversion the
    IPC heartbeat path uses — no second metrics system.
- Request-log sink for the no-IPC case: a narrow sink trait consumed by
  `send_request_log_if_enabled` (default no-op preserves current call
  sites), implemented in composition to push into `AdminState.request_logs`
  when no IPC handle exists. Request-path code must not name `AdminState`.
- Lifecycle: the publisher task is a runtime task — owned, named, and
  drained on shutdown like the other admin background tasks (no orphaned
  `tokio::spawn`).
- Deployment (operator-local, `~/prodtest`, never committed): set
  `[logging.verbose_request_logging] enabled = true` with at least
  `log_blocked = true` after the pipeline is wired.
- Tests: `tests/OWNERSHIP.toml` entry for any new root test file; extend the
  admin contract/smoke coverage to assert a request through the data plane
  becomes visible in `/api/stats/summary` and `/api/stats/requests`
  (standalone harness). No new crate, no new root dependency (ledger
  allowlist untouched), no new config section, no new mutating endpoint.

Non-goals: no change to `HealthStatus` semantics or the `unknown` default
(Phase 02 owns the display side); no Prometheus/metrics-export work; no
retention/query feature beyond the existing bounded deques; no supervised
worker-spawning changes.

## Verification

- `cargo xtask verify` full gate (this phase touches composition and the
  request path; no lane skips).
- New/updated tests: publisher aggregates a synthetic standalone feed;
  supervisor bridge copies IPC-received logs into admin-visible state;
  request-log sink no-ops without breaking existing
  `send_request_log_if_enabled` callers.
- Live standalone: send traffic (200s + a blocked probe), assert
  `total_requests` > 0, history non-empty, `/api/stats/requests` returns the
  entries, blocked probe visible; dashboard graphs render.
- Live supervised (local `--workers N` run): same assertions plus workers
  tab populated (cross-checks Phase 03's mode detection).
