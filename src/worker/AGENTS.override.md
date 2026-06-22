# Worker Module - AGENTS.override.md

## ExtensionRuntime Pattern

Worker lifecycle extensions (Mesh, DNS, Serverless, Honeypot) are managed via `ExtensionRuntime` trait and `ExtensionRegistry`.

See `skills/extension_runtime.md` for full documentation.

### Key Types

- `ExtensionRuntime` trait in `src/worker/extension.rs`
- `ExtensionRegistry` - manages lifecycle and health
- `ExtensionFailurePolicy` - FailClosed or FailOpen
- `RequestServices` - dependency injection context in `src/worker/context.rs`

### Global Singleton Deprecation

Global singletons (`get_threat_intel()`, `get_yara_rules()`, `get_upload_validator()`) are deprecated. Use `RequestServices` instead:

```rust
// Old (deprecated) — WafCore::get_threat_intel() removed in Iteration 59
let threat_intel = get_threat_intel().cloned();

// New
let threat_intel = request_services.threat_intel.clone();
```

## Worker Submodule Layout (2026-06 split)

The two large worker files were split into subdirectories to keep each
file focused on a single architectural phase.

### `src/worker/cpu_task/`

CPU offload worker (`run_static_worker` / `run_cpu_worker`).

- `mod.rs`      - submodule root + `run_static_worker` bootstrap
- `state.rs`    - `StaticWorkerArgs`, `CpuWorkerArgs`, `StaticWorkerState`,
                   `CompressionTask`, `CpuTaskLimits`, `CpuTaskLimiter`,
                   `CpuTaskPermit`
- `metrics.rs`  - all `static CPU_TASK_*` atomics + record/summarize helpers
- `payload.rs`  - `apply_file_backed_payload`, deadline helpers, size estimators
- `dispatch.rs` - `process_cpu_task_request_sync` (the big match on payload)
- `connection.rs` - `handle_minify_client_connection` (sync IPC loop)
- `yara.rs`     - `build_yara_scanner_from_main_config`

### `src/worker/unified_server/`

UnifiedServer worker (`run_unified_server_worker`).

- `mod.rs`         - thin orchestrator over the init phases
- `state.rs`       - `UnifiedServerWorkerArgs`, `UnifiedServerWorkerState`,
                      panic handler, IPC/config/CPU-affinity/port helpers,
                      `wait_for_drain`
- `services.rs`    - `DataPlaneServices` and `DataPlaneServicesBuilder`:
                       bundled data-plane service handles (request_services,
                       serverless_manager, port_honeypot_runner, mesh_transport,
                       threat_intel, record_store, optional
                       ThreatIntelPolicyContext under mesh); `cross_wire_mesh_services()`
                       **Boundary rule**: `DataPlaneServicesBuilder::new()` requires
                       an explicit `Arc<ServerlessManager>` — no default or global
                       fallback. Callers must provide one at construction time.
- `init_runtime.rs`- re-exports from `state` (CPU affinity, shared-conn heartbeat)
- `init_config.rs` - re-exports from `state` (config, bandwidth, port check)
- `init_apps.rs`   - Granian supervisors, serverless manager, ACME wiring;
                       `build_default_serverless_manager()` fallback helper
- `init_waf.rs`    - WAF background tasks, UploadValidator, port honeypot
- `passthrough_validation.rs` - TLS passthrough classification and validation:
                       `classify_passthrough_sites()` is a pure function (no I/O,
                       no side effects) that classifies sites into passthrough,
                       passthrough-with-WAF, bypass, and bypass-without-rate-limit
                       categories. `site_has_rate_limit()` is a pure helper that
                       checks whether a site has rate limit configuration.
                       `evaluate_passthrough_policy()` is a pure function returning
                       `PassthroughPolicyEvaluation` with per-site `PassthroughPolicyViolation`
                       enum variants. `validate_tls_passthrough_waf_policy()` returns
                       `Result<(), String>`, logs warnings/errors and emits metrics for
                       misconfigured sites. Gated by `security.strict_tls_passthrough_policy`.
- `init_mesh.rs`   - Mesh + Threat Intel + YARA rules initialization
- `lifecycle.rs`   - heartbeat task, bandwidth-persist task, IPC message
                       handling loop, initial blocklist request;
                       `LifecycleRequest` handshake for composition-root coordination
- `startup_plan.rs` - Worker startup orchestration (identity through mesh pipeline);
                       extracted from `run_unified_server_worker()` in Iteration 93
- `supervision_loop.rs` - Supervision select loop (lifecycle events, task exits,
                       mesh decisions); extracted from `run_unified_server_worker()`
                       in Iteration 93
- `shutdown_executor.rs` - Ordered shutdown procedure (shutdown-and-join, IPC
                       notification, exit-code mapping); extracted from
                       `run_unified_server_worker()` in Iteration 93
- `supervisor_notify.rs` - Supervisor IPC notification and exit-code mapping;
                       extracted from `run_unified_server_worker()` in Iteration 93

### Helper files outside the subdirectories

- `src/worker/response_builder.rs` (visibility: `pub(in crate::worker)`) -
  the Minify/Compress responses consumed by `cpu_task::dispatch`. Holds
  `CompressionTask` and `StaticWorkerState` field references but is at the
  worker-module level.
- `src/worker/image_rights.rs` (visibility: `pub(in crate::worker)`) -
  `mark_image_rights_sync` consumed by `cpu_task::dispatch`.
- `src/worker/connection.rs` (visibility: `pub(super)`) - the original
  `WorkerState` + `create_waf` helper used by the worker bootstraps; **this
  is a different module from `cpu_task::connection`** and must be referenced
  with `crate::worker::connection` to avoid confusion.

## Architecture Boundary Cleanup (Iteration 2, updated Iteration 60)

### `DataPlaneServicesBuilder::new()` requires explicit `serverless_manager`

`DataPlaneServicesBuilder::new()` takes `Arc<ServerlessManager>` as a required
parameter. There is no default or global fallback — callers must provide one at
construction time. This is a hard boundary: the builder never consults global
plugin manager state.

```rust
// Correct
let sm = Arc::new(ServerlessManager::new());
let services = DataPlaneServicesBuilder::new(sm).build();

// Wrong — does not compile, no default
let services = DataPlaneServicesBuilder::new().build();
```

### `build_default_serverless_manager()` fallback helper

**Location**: `src/worker/unified_server/init_apps.rs:46`

When the serverless subsystem is disabled or fails to initialize, upstream code
still expects a `ServerlessManager` to exist. `build_default_serverless_manager()`
creates one using the global plugin manager's WASM runtime, but it will have no
loaded functions.

Used in `mod.rs:101`:
```rust
let serverless_manager = init_apps::init_serverless_manager(&shared_config)
    .await
    .unwrap_or_else(init_apps::build_default_serverless_manager);
```

### `passthrough_validation.rs` — pure classification

**Location**: `src/worker/unified_server/passthrough_validation.rs`

- `classify_passthrough_sites(sites)` — pure function, no I/O, no side effects.
  Classifies sites into: `passthrough_sites`, `passthrough_with_waf`,
  `bypass_sites`, `bypass_sites_without_rate_limit`.
- `site_has_rate_limit(site)` — pure helper that checks whether a site has
  rate limit configuration.
- `evaluate_passthrough_policy(config)` — pure function returning
  `PassthroughPolicyEvaluation` with per-site `PassthroughPolicyViolation`
  enum variants (no I/O).
- `validate_tls_passthrough_waf_policy(config)` — returns `Result<(), String>`;
  reads config, calls `classify_passthrough_sites` and `evaluate_passthrough_policy`,
  emits `tracing::error!` for bypass sites and missing rate limits. Returns `Err`
  when `security.strict_tls_passthrough_policy` is enabled and violations are found.

### `RECORD_STORE_GLOBAL` is legacy/fallback only

**Location**: `crates/synvoid-mesh/src/mesh/mod.rs:161`

`RECORD_STORE_GLOBAL` (via `get_global_record_store()`) is a compatibility
fallback for code that cannot easily receive an explicit handle. All production
paths should use the explicit `record_store` field on `DataPlaneServices`:

```rust
// Preferred
let record_store = data_plane.record_store.as_ref();

// Legacy fallback (avoid in new code)
let record_store = get_global_record_store();
```

### `DataPlaneServices` carries optional `ThreatIntelPolicyContext` (Iteration 25, updated 27)

`DataPlaneServices` under `#[cfg(feature = "mesh")]` now carries an optional
`ThreatIntelPolicyContext`, and the worker root exposes
`apply_threat_intel_policy_context()` to forward the stored context into
`ThreatIntelligenceManager`. A separate root-side helper can build the
context from explicit canonical/advisory handles, but the production worker
bootstrap still passes `None` because canonical trust state (Raft consensus,
`EdgeReplicaManager`) is owned by the Supervisor and workers are data-planes
without access to a root-owned `SnapshotCanonicalTrustReader`. The default
remains `None`; this pass does not migrate proxy, YARA/WASM, routing, WAF
enforcement, DHT sync, ingestion, or Raft behavior.

**Next step**: Expose canonical snapshots from the Supervisor to workers
(e.g. via IPC or startup snapshot) without introducing globals or test-only
static readers.

### `UnifiedServer::with_serverless_manager()` — server-level wiring

**Location**: `src/server/mod.rs:467`

`UnifiedServer::with_serverless_manager()` is the server-level builder method
that wires the serverless manager into the HTTP server stack. This is separate
from `DataPlaneServicesBuilder` — the builder bundles service handles for
cross-wiring, while the server method injects into the request pipeline.

### Composition Boundary Guardrail (Iteration 60)

`src/worker/unified_server/` is actively scanned via `boundary_scan_roots()` in
the guardrail test. Unknown files under this directory fail closed with
`BoundaryRole::Unclassified`. Every `.rs` file must receive an explicit
classification. When adding new files to `src/worker/unified_server/`, add a
corresponding entry to `classify_unified_server_file()` in the guardrail test.

Boundary exceptions (pass-through types, trait-object delegation) must be
live-audited. The `boundary_exceptions_are_live_and_audited` test verifies each
exception token appears in at least one matching source file.

## Worker Task Lifecycle (Iteration 62)

The `task_registry` module provides structured concurrency management:

- **WorkerTaskRegistry**: register named tasks with classification (CriticalService, RestartableBackground, etc.), cooperative cancellation via `child_token()`, bounded shutdown with `shutdown_and_join()`
- **Panic detection**: All spawn methods wrap futures with `catch_unwind` for panic capture and classification as `TaskExitReason::Panic`
- **Immediate supervision**: `subscribe_exits()` returns a `broadcast::Receiver<NamedTaskExit>` for real-time critical-task exit notifications — no need to await `shutdown_and_join`
- **Deduplication**: `record_exit_metrics()` records metrics in the task wrapper and tracks exits in `reported_exits` map; `shutdown_and_join` checks this map to avoid double-counting
- **`is_shutdown_started()`**: Check whether `shutdown()` has been called without a watch channel
- **`NamedTaskExit`**: struct with `id`, `name`, `class`, `reason`, `expected_during_shutdown` fields
- **`TaskExitReason::UnexpectedCompletion`** variant for tasks that finish before shutdown without being cancelled
- **`TaskId`** type for deduplication in exit records
- **ManagedService trait**: `name()`, `shutdown()` (idempotent), `join()` (after shutdown)
- **cancellation_loop()**: helper for periodic work with cooperative shutdown
- **Spawn helpers**: `spawn_critical_result()` and `spawn_background_result()` for `Result<(), E>`-returning futures
- **ThreatFeedClient**: uses `select!` with `shutdown_tx` watch channel; `is_running()` checks `!handle.is_finished()`; `join_with_timeout()` provides bounded join with abort
- **IPC loop, heartbeat, and bandwidth persist** are now registry-owned (Iteration 62)

### Iteration 63: Supervision Corrections

- **Subscribe-before-spawn invariant**: `subscribe_exits()` is called before any tasks are spawned (Phase 12) to ensure no exit event is missed.
- **Supervision loop with `is_fatal_exit` classification**: The Phase 15 supervision loop uses `is_fatal_exit(exit, shutdown_started)` to decide whether a task exit triggers worker shutdown. CriticalService is fatal before shutdown for `UnexpectedCompletion`/`Panic`/`Error`/`Cancelled`; during shutdown, only `UnexpectedCompletion`/`Panic`/`Error` are fatal. RestartableBackground is never immediately fatal.
- **`UnexpectedCompletion` semantics**: Pre-shutdown `Ok(())` from a non-cancelled CriticalService is `UnexpectedCompletion`. Post-shutdown `Ok(())` is `CleanCompletion`.
- **`WorkerShutdownCause` enum**: Primary shutdown cause classification (`ServerExited`, `CriticalTaskExit`, `SupervisorShutdown`, `SupervisorDisconnected`, `RegistryExitChannelClosed`, `ExternalStop`, `RunningFlagCleared`, `MeshServiceExit(MeshTaskExit)`).
- **IPC loop typed completion**: `IpcLoopExit` (expected: `MasterShutdown`, `WorkerResize`, `RegistryShutdown`, `RunningFlagCleared`) and `IpcLoopError` (failure: `ConnectionLost`, `Unexpected`) provide typed completion signals. `IpcLoopExitCause` communicates the specific exit path via shared `Arc<RwLock>`.
- **Bandwidth persistence final flush**: `persist_global_bandwidth_tracker()` called unconditionally after the persist loop breaks on every shutdown cause.
- **Server run task now registry-owned**: Registered via `spawn_critical_result("server_run", ...)` as CriticalService. Old `spawn_server_run_task` function removed.
- **Broadcast lag/closure policy**: `Lagged` = conservative shutdown (`RegistryExitChannelClosed`); `Closed` during shutdown = expected (`SupervisorShutdown`); `Closed` while active = lifecycle failure (`RegistryExitChannelClosed`).

### Iteration 64: Coordinated Shutdown Intent

- **`begin_shutdown()` vs `broadcast_shutdown()`**: The registry now separates shutdown intent (atomic flag) from task cancellation (watch channel). `begin_shutdown()` marks coordinated shutdown intent immediately, changing task completion classification. `broadcast_shutdown()` sends the cancel signal to tasks.
- **`WorkerShutdownCause` is authoritative**: `exit_code()` method derives the process exit code. `worker_exit_code` field removed. `ServerExited` split into `ServerExitedUnexpectedly` (exit 1) and `ServerStoppedForShutdown` (exit 0). `WorkerResize { worker_threads }` uses exit code 100.
- **Bandwidth persistence ownership**: The background task owns periodic and final flush. No double-flush from composition root.

### Iteration 65: Lifecycle Event Channel and Acknowledgement

- **Lifecycle event channel**: The IPC task communicates lifecycle events via `tokio::sync::mpsc::channel<LifecycleRequest>` instead of `Arc<RwLock<Option<WorkerLifecycleEvent>>>`. `LifecycleRequest` carries the event and a `oneshot::Sender<()>` for acknowledgement.
- **Coordinator acknowledgement handshake**: The IPC task waits for the composition root to acknowledge before returning. The composition root calls `begin_shutdown()` then sends acknowledgement via the oneshot channel. This ensures the IPC task's exit is classified as `CleanCompletion`, not `UnexpectedCompletion`.
- **Supervision loop selects lifecycle events**: The supervision loop `tokio::select!` over both `lifecycle_rx.recv()` (IPC lifecycle events) and `exit_rx.recv()` (task exits). Lifecycle events arrive before the IPC critical task returns.
- **Removed `IpcLoopExitCause` and `IpcLoopExit`**: These types were a shared-state side channel, now redundant with the lifecycle event channel.
- **Dedicated resize acknowledgement**: `WorkerResize` sends `UnifiedServerWorkerResizeAck` instead of `UnifiedServerWorkerShutdownComplete`. `ShutdownComplete` is reserved for actual supervisor shutdown.
- **Legacy handle abort-and-await**: Legacy `state.task_handles` are aborted **and awaited** before shutdown completion. `std::mem::take` empties the vector; each handle is `abort()`ed then `await`ed.
- **Fatal supervisor notification**: Fatal causes (`CriticalTaskExit`, `ServerExitedUnexpectedly`, `RegistryExitChannelClosed`) send `WorkerError` when IPC remains available. `SupervisorDisconnected` is a no-op.
- **Explicit acknowledgement routing**: The composition root uses a `match` on `WorkerShutdownCause` to route to the correct IPC message: `ShutdownComplete`, `ResizeAck`, or `WorkerError`.

### Iteration 66 — Supervision cause preservation cleanup

The supervision loop returns `SupervisionOutcome` (Lifecycle | DirectCause) instead of `(WorkerLifecycleEvent, Option<oneshot::Sender>)`. This preserves the original failing subsystem through final notification.

**Cause mapping helpers** (`task_registry.rs`):
- `map_task_exit_to_shutdown_cause(NamedTaskExit)` → server_run → ServerExitedUnexpectedly, others → CriticalTaskExit
- `map_exit_recv_error_to_shutdown_cause(RecvError, bool)` → Lagged → RegistryExitChannelClosed, Closed → RegistryExitChannelClosed (if active)
- `map_lifecycle_channel_closed(bool)` → active → RegistryExitChannelClosed, shutting down → None

**IPC lifecycle send** (`lifecycle.rs`):
- `request_lifecycle_transition()` replaces ignored `let _ = lifecycle_tx.send()` / `let _ = ack_rx.await`
- Returns `IpcLoopError::Unexpected` on channel closure or dropped acknowledgement

**Notification routing**:
- `should_notify_supervisor()`: SupervisorDisconnected → false (channel unavailable), ServerExitedUnexpectedly → true
- Direct causes bypass lifecycle event re-mapping

**Tests**: 15 new in `worker_supervision_control_flow.rs`, 8 new guardrail checks in `background_task_ownership_guard.rs`

### Iteration 67 — Shutdown intent and lifecycle error cleanup

**Lifecycle transition error propagation**: All terminal `request_lifecycle_transition()` calls in the IPC loop use `?` instead of `let _ = ...`. Lifecycle coordination failures produce explicit `IpcLoopError::Unexpected` task errors.

**Supervision loop side-effect free**: The supervision loop selects causes only — no `state.running.stop()` before returning. All teardown happens in the composition root.

**`begin_coordinated_shutdown()` helper**: `lifecycle.rs` exports `begin_coordinated_shutdown(registry, lifecycle_ack)` which calls `begin_shutdown()` then acknowledges the lifecycle request. Called before any stop signals in the composition root.

**`ServerExitedUnexpectedly(NamedTaskExit)`**: The variant now carries `NamedTaskExit` for diagnostic detail. Supervisor `WorkerError` messages include the task name and exit reason.

**Secondary exit classification**: Exits after primary cause selection are expected cleanup. They do not increment `tasks_unexpectedly_completed` and cannot replace the primary cause.

### Iteration 82 — Mesh Transport Polish and Worker Supervision

**Mesh transport polish** (Part A):
- `parse_http_response_framing()` now rejects malformed header lines (no colon separator) with `MalformedHeaderLine` instead of silently skipping them
- `read_http_response_sequence()` rejects non-empty `body_prefix` for 204/304 responses (`UnexpectedBodyBytesForNoBodyResponse`)
- `try_parse_http_response_head()` enforces `max_header_bytes` internally (not just in callers)
- All `duration_since` calls use saturating arithmetic with explicit deadline checks
- `spawn_auxiliary_task()` reordered: admission checks happen before spawning the gated wrapper
- Auxiliary metrics renamed from `edge_refresh_*` to `mesh_auxiliary_*` for task-kind correctness
- `AuxiliarySubmissionTestHooks` (cfg(test)) provides deterministic barrier-based race testing

**Worker mesh supervision** (Parts B-H):
- `src/worker/mesh_supervision.rs` — new module with policy types, status tracking, event/decision types, and pure classification logic
  - `MeshSupervisionPolicy` — configurable failure response with `required()` and `optional()` presets
  - `MeshFailureAction` — `Ignore`/`Degrade`/`RestartMesh`/`ShutdownWorker`
  - `WorkerMeshPhase`/`WorkerMeshStatus` — worker-side mesh status projection
  - `MeshSupervisionEvent` — events from mesh observer to coordinator
  - `MeshSupervisorDecision` — decisions from coordinator to composition root
  - `decide_mesh_action()` — pure, unit-testable classifier
  - `RestartBudget` — bounded restart tracking with sliding window
  - `compute_backoff()` — exponential backoff with jitter
  - `MeshShutdownDisposition`/`classify_mesh_shutdown_report()` — shutdown report classifier
  - `create_supervision_pipeline()` — creates channels and coordinator (composition root spawns both)
  - `run_mesh_exit_observer()` — async task receiving mesh exit events

- `WorkerShutdownCause` extended with:
  - `MeshStartupFailed(String)` — mesh startup failure
  - `MeshShutdownIncomplete(String)` — mesh shutdown did not complete cleanly

- Worker composition root integration (`src/worker/unified_server/mod.rs`):
  - Subscribe to mesh exits before starting mesh (subscribe-before-start invariant)
  - Mesh exit observer registered in `WorkerTaskRegistry` as `RestartableBackground`
  - Mesh supervision coordinator registered in `WorkerTaskRegistry` as `RestartableBackground`
  - Supervision `tokio::select!` loop includes mesh decision branch
  - `UnifiedServerWorkerState` carries `mesh_status` and `mesh_policy` fields

- **Ownership invariant**: The mesh service reports facts; the worker decides policy. Mesh internals never directly terminate the process.

### Iteration 83 — Mesh Supervision Pipeline Refinements

**Single authoritative status allocation**: The supervision pipeline uses `state.mesh_status.clone()` (an `Arc<RwLock<WorkerMeshStatus>>`) as the single allocation shared between the observer, coordinator, and composition root. No separate status copies exist.

**Coordinator event-before-policy ordering**: `MeshSupervisionCoordinator::run()` applies event-level status transitions (`apply_mesh_event_to_status`) *before* calling `decide_mesh_action()`. The phase snapshot used for classification reflects the post-transition state.

**`decide_mesh_action()` signature**: Takes `&WorkerMeshPhase` (the phase enum, not `&WorkerMeshStatus`). Pure function — all state needed for the decision is passed in, no I/O.

**`mesh_failure_to_worker_cause()`**: Converts `MeshFailureCause` → `WorkerShutdownCause` preserving typed information (`MeshServiceExit`, `MeshStartupFailed`, `MeshShutdownIncomplete`).

**`merge_worker_shutdown_cause()`**: Priority-based cause merging (highest priority wins). Infrastructure failures > mesh failures > restart exhaustion > incomplete shutdown > expected shutdown. Used by composition root to accumulate causes from mesh supervision and task registry.

**No outer timeout on mesh startup**: `start_with_policy()` is spawned without an outer `tokio::time::timeout`. Cancellation-safe via mesh-internal stage deadlines; outer timeout would bypass rollback.

**Real shutdown deadline**: The composition root computes `remaining_budget()` closure from `shutdown_started_at + drain_timeout` — not `state.start_time.elapsed()`. Incomplete mesh shutdown accumulates into final cause via `merge_worker_shutdown_cause()`.

**`MeshRestartExhausted` variant**: `WorkerShutdownCause::MeshRestartExhausted { attempts, last_error }` — raised when restart budget is exhausted. Classified as fatal (`is_fatal_exit()` returns true). Budget tracked via `RestartBudget` with sliding window.

**`allow_degraded_readiness` field**: `MeshSupervisionPolicy::allow_degraded_readiness` (bool). When `required()` preset: `false` (mesh must be fully running for readiness). When `optional()` preset: `true` (degraded mesh still satisfies readiness). Gated by readiness check in `UnifiedServerWorkerState::is_ready()`.

### Iteration 84 — Config-Driven Mesh Supervision

**Config-driven policy**: `MeshSupervisionConfig` in `crates/synvoid-config/src/mesh.rs` provides TOML-deserializable supervision settings. `build_mesh_supervision_policy()` derives `MeshSupervisionPolicy` from config + `mesh_enabled` flag; returns `None` when mesh disabled (no pipeline created).

**OneShot task class**: `TaskClass::OneShot` added to `TaskClass` enum for tasks that run once during initialization and complete (not restarted, dropped after completion).

**Structured ownership**: All bare `tokio::spawn()` calls eliminated from `init_mesh.rs`. `MeshInit` returns DNS registries, YARA broadcast components, and DHT routing manager for composition root to spawn. Background tasks registered in `WorkerTaskRegistry` after mesh startup.

### Iteration 85 — Worker Mesh Supervision Corrective Pass

**Disabled mesh construction-free**: `MeshInit::disabled()` returns no runtime resources (all `None`/empty). `init_mesh_and_threat_intel()` returns early for absent config or `enabled=false` without constructing topology, routing, transport, DNS, YARA, or DHT objects. Policy is `Option<MeshSupervisionPolicy>` — `None` for disabled, no required fallback.

**Restart disabled**: `restart_enabled` overridden to `false` at policy-build time with warning. `RestartMesh` unreachable in production policy. No restart metrics increment.

**Topology/DHT construction-only**: `topology.start_background_tasks()` and `routing_manager.start_background_tasks()` removed from construction. Topology and DHT returned in `MeshInit` for composition root to start after mesh startup. They use internal shutdown signals.

**YARA broadcast JoinSet**: Per-message detached `tokio::spawn()` replaced with local `JoinSet<()>` for child ownership. Bounded concurrency via semaphore, drain-or-abort on shutdown.

**Required startup failure direct**: Composition root handles `Result<(), MeshFailureCause>` directly — status transitions once, `DirectCause` set, no ready message, no coordinator round-trip.

**Singular status ownership**: `start_mesh_generation()` returns facts only (`Result<(), MeshFailureCause>`); caller transitions `WorkerMeshStatus`. Coordinator handles runtime event transitions.

**Guard test**: `tests/worker_mesh_supervision_boundary_guard.rs` — disabled-config, restart-disabled, construction-no-start, YARA-joinset, direct-failure, and status-ownership tests.

### How to add a new long-lived task
1. Determine task class (CriticalService, RestartableBackground, BoundedChild, CpuOffload, Detached)
2. For CriticalService/RestartableBackground: use WorkerTaskRegistry.spawn_critical() or spawn_background()
3. Use child_token() with tokio::select! for cooperative cancellation
4. For Detached: add explicit allowlist entry in tests/background_task_ownership_guard.rs

### Iteration 89 — Worker Mesh Composition-Root Final Closure

**`MeshGenerationSupport::empty(generation)`**: Constructor for empty support bundles with no tasks. Used for degraded-mode fallback where optional mesh support must not block readiness.

**`stop_mesh_generation_support()`**: Now `pub` (was `pub(crate)`). Accepts `SupportStopContext`, returns `MeshSupportStopReport`. Public for integration testing of composition-root dataflow.

**`MeshConfigurationInvariant(String)`**: New `MeshFailureCause` variant for transport/policy configuration mismatches during init. Maps to `WorkerShutdownCause::MeshConfigurationInvariant(String)` in `mesh_failure_to_worker_cause()`. Fatal exit.

**Optional startup race**: `pending_optional_failure` flag prevents stale degradation signals from being dropped if mesh support failure arrives before optional startup completes. Mesh decisions polled alongside `optional_startup_rx` via `tokio::select!`.

**Stop report accounting**: `cooperative` count now correctly includes `CleanCompletion + Cancelled` only (not `total - aborted`). `failed` counts `Panic + Error + UnexpectedCompletion`.

**Public re-exports**: `MeshGenerationSupport`, `MeshSupportStopReport`, `SupportStopContext`, `stop_mesh_generation_support` are re-exported from `worker/mod.rs`.

**Composition root tests**: 12 integration tests in `tests/composition_root_behavioral.rs` (Phases 21-23) covering support failure, cleanup, classification, and readiness. 17 unit tests in `composition_root_tests` module in `mod.rs`.

**`#[cfg(test)]` gate bug**: Library crates compiled as dependencies do NOT have `cfg(test)` set during integration test builds. `check_startup_failure_hook` call sites were gated with `#[cfg(test)]` in mesh crate — hook calls were compiled out during integration tests. Fix: removed all `#[cfg(test)]` gates from call sites in `transport.rs`.

### Iteration 90 — Forced Abort-Join Ownership Cleanup

**`cancel_then_join_tasks()` no longer wraps aborted handles in timeout** (Part A): After `abort()`, the handle is awaited directly without a second timeout. The `forced_timeout` parameter is retained for API compatibility but not applied after abort. A handle that is dropped after timeout would lose ownership without proof the task ended — the new code preserves the ownership invariant: every extracted handle is joined before the function returns.

**`MeshSupportStopReport` gains `not_found` field** (Part B): The report now includes `not_found: usize` for task IDs not found in the registry. `MeshSupportStopReport::clean()` returns `false` when `not_found > 0`, because missing IDs during first teardown can indicate lost ownership bookkeeping.

**Ownership invariant (final)**:
> `cancel_then_join_tasks` performs cooperative waiting to a deadline. Remaining tasks are then aborted and awaited without a second timeout, preserving handle ownership. A future hard-deadline variant must return explicit unjoined residue rather than dropping handles.
