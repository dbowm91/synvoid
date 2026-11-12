# Phase 04 Plan: Worker Pool Defaults and Multi-Worker State

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: none.

## The finding

The canonical data plane is one `UnifiedServerWorker` with one Tokio runtime;
throughput scales with `[process_manager].worker_threads`, not worker-process
count (`architecture/worker_architecture.md`). The shipped `config/main.toml`
sets `[defaults.worker_pool].workers = 1`.

The type default disagrees:

- `WorkerPoolDefaults::default()` sets `workers: 4`
  (`crates/synvoid-config/src/defaults.rs`).
- `default_workers()` also returns 4.
- `run_supervisor_mode` derives
  `ProcessManagerConfig.unified_server_workers` from
  `main_config.defaults.worker_pool.workers.max(1)`.
- The supervisor only logs a warning when the value is greater than one; it
  starts the workers anyway.

If an operator omits `[defaults.worker_pool]`, four worker processes start.
Each worker has its own:

- admin session map and CSRF-token map
  (`src/admin/state.rs::{sessions,csrf_tokens}`);
- in-memory admin rate-limit budget;
- admin metrics feed and request-log sink
  (`src/server/listener_tasks.rs::spawn_admin_service`,
  `spawn_metrics_publisher_service`);
- violation/threat-level state unless a shared path explicitly covers it.

The admin listener is served by every worker and binds with `SO_REUSEPORT`, so
a browser request can land on any worker. A login can succeed on one worker and
the next request can land on another with no session. Prometheus and the admin
panel observe one worker at a time. This is a production trap hidden behind an
advanced-isolation option.

## Recommended model

Default to **one** worker. Treat `workers > 1` as an explicit, documented
opt-in for fault isolation, not as a throughput knob. Do not build a
distributed session store in this phase. Scale a single worker with Tokio
threads and the accept path.

## Work items

### 04.1 Default and validation

- Change `WorkerPoolDefaults::default()` and `default_workers()` to `1`.
- Keep the shipped config at `1`.
- Add validation in `DefaultsConfig::validate`:
  - `workers >= 1`;
  - if `workers > 1`, require an explicit opt-in field, for example
    `[defaults.worker_pool] allow_multi_worker = true`, and reject the
    combination `workers > 1` + `[admin].enabled = true` unless the admin
    limitation is accepted.
- Fail startup rather than logging a warning when the opt-in is absent.
  The supervisor warning can stay as a second line of defense.

### 04.2 Admin and observability under N>1

If the opt-in remains:

- Serve the admin router on exactly one worker (worker 0) or through a
  supervisor-owned admin proxy. Do not bind the same admin port on every
  worker with independent session maps.
- If the admin stays worker-local, label the metrics/request-log feed with
  `worker_id` and document that the panel is worker-scoped.
- Add a supervisor-level aggregation path or an explicit "selected worker"
  UI state before claiming cluster-wide metrics.
- Test a login, CSRF mutation and WebSocket upgrade across a multi-worker
  deployment; assert the session does not bounce between workers.
- Test `workers = 2` with the opt-in on and off; off must fail closed.

### 04.3 Shared enforcement state

- Audit which enforcement state is already shared: the shared connection
  table, shared rate-limit table and block store are initialized by the
  supervisor. Confirm the block store and violation/threat-level state used by
  admission are visible to every worker.
- If a ban created by worker A is not enforced by worker B, either make that
  state shared or document that `workers > 1` weakens enforcement. Do not
  claim consistent bans in the multi-worker docs.
- Add an integration test that blocks an IP on one worker and asserts the
  other worker's admission path sees it.

### 04.4 Documentation

- `architecture/worker_architecture.md`: state that the type default is 1 and
  that `workers` is isolation, not throughput.
- `docs/CONFIGURATION.md`: document `allow_multi_worker`, the admin/session
  limitation and the metrics scope.
- `docs/PERFORMANCE.md`: keep `worker_threads` as the scaling lever and the
  accept path as the second lever; remove any implication that
  `unified_server_workers` is a normal scaling knob.
- `docs/DEPLOYMENT.md`: capacity planning assumes one worker per process;
  state how to run multiple instances behind a load balancer if needed.

## Non-goals

- A distributed session/CSRF store.
- A supervisor-wide metrics aggregation implementation unless 04.2 proves it
  is required for the opt-in.
- Changing the CPU offload worker count.
- Changing the admin authority contract.

## Verification

```bash
cargo test -p synvoid-config --profile ci
cargo test --test admin_smoke_flow --features mesh,dns,icmp-filter --profile ci
cargo test --test admin_router_composition --features mesh,dns,icmp-filter --profile ci
cargo test --test e2e_process_test --profile ci
cargo xtask verify
```

Live: start with an omitted `[defaults.worker_pool]` and assert one worker;
start with `workers = 2` and no opt-in and assert startup fails; with the
opt-in, assert admin login stability and metric visibility.

## Exit criteria

- An omitted worker-pool section starts one worker.
- Multi-worker requires an explicit acknowledgement and documents its state
  limits.
- No default or shipped config silently starts four workers.

## Completion evidence

Implemented 2026-11-11. `WorkerPoolDefaults::default()` and `default_workers()`
return 1; `allow_multi_worker` defaults false. Validation rejects `workers > 1`
without the acknowledgement, with an additional admin-specific error when the
admin listener is enabled; the supervisor refuses to start without the opt-in.
`config/main.toml` and generated templates ship one worker. Worker, admin and
deployment docs now describe `worker_threads` as the scaling lever and the
worker-local session/CSRF/metrics limits of the opt-in. Config, supervisor and
admin contract tests pass.

