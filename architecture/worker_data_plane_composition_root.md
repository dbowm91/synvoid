# Worker/Data-Plane Composition Root Ownership

**Established**: Iteration 58
**Updated**: Iteration 98
**Guardrail**: `tests/data_plane_composition_boundary_guard.rs`

## Invariant

> Composition roots own concrete infrastructure; request-path modules consume capabilities.

## Composition Root Files

These files construct and wire concrete infrastructure:

| File | Role |
|------|------|
| `src/worker/unified_server/mod.rs` | Primary composition root for UnifiedServerWorker |
| `src/worker/unified_server/init_mesh.rs` | Mesh transport, threat intelligence, YARA init |
| `src/worker/unified_server/init_waf.rs` | WAF background tasks, upload validation |
| `src/worker/unified_server/init_apps.rs` | Granian app servers, serverless manager |
| `src/worker/unified_server/services.rs` | Data-plane service assembly boundary: builds `DataPlaneServices`, cross-wires mesh services, owns `RequestServices` construction |
| `src/worker/unified_server/lifecycle.rs` | IPC message loop, canonical trust snapshot |
| `src/worker/unified_server/state.rs` | IPC connection, config loading |
| `src/worker/unified_server/init_runtime.rs` | Re-exports of state.rs runtime helpers |
| `src/worker/unified_server/init_config.rs` | Re-exports of state.rs config helpers |
| `src/worker/unified_server/startup_plan.rs` | Worker startup orchestration (identity through mesh pipeline) |
| `src/worker/unified_server/mesh_attachment.rs` | Worker-side mesh attachment orchestration (Iteration 95, polished Iteration 96, ordering corrected Iteration 97) |
| `src/worker/unified_server/supervision_loop.rs` | Supervision select loop (lifecycle events, task exits, mesh decisions) |
| `src/worker/unified_server/shutdown_executor.rs` | Ordered shutdown procedure + `WorkerShutdownPlan` outcome mapping (Iteration 94) |
| `src/worker/unified_server/supervisor_notify.rs` | Supervisor IPC notification and exit-code mapping |
| `src/worker/connection.rs` | Legacy worker WAF init |
| `src/worker/task_registry.rs` | Task lifecycle management (CriticalService, RestartableBackground, etc.) |
| `src/worker/cpu_task/mod.rs` | CPU offload worker composition |
| `src/supervisor/process.rs` | Supervisor process composition |
| `src/supervisor/mesh.rs` | Mesh agent composition |
| `src/server/mod.rs` | UnifiedServer struct (holds block_store) |
| `src/main.rs` | Process dispatcher |

## Request-Path Modules

These modules handle live HTTP/HTTPS requests and must consume narrow traits:

| Directory | Purpose |
|-----------|---------|
| `src/waf/` | WAF request evaluation (uses `BlockListStore` trait) |
| `src/proxy/` | Proxy re-export shim (clean) |
| `src/http/` | HTTP server request handling |
| `src/http3/` | HTTP/3 re-export shim (clean) |
| `crates/synvoid-waf/` | WAF engine (clean, uses trait abstractions) |
| `crates/synvoid-proxy/` | Proxy engine (clean, uses trait abstractions) |
| `crates/synvoid-http3/` | HTTP/3 engine (clean, uses trait abstractions) |
| `crates/synvoid-http-client/` | HTTP client (clean, uses trait abstractions) |
| `crates/synvoid-http/` | HTTP request dispatch (some concrete types pass through) |

## Dependency Rules

### Composition Roots May Own

- Concrete `BlockStore`
- Concrete `ThreatIntelligenceManager`
- Mesh transport / DHT / Raft handles
- IPC manager/client/server handles
- Metrics providers, config objects
- WAF engine implementation
- HTTP/3 adapter implementation
- Supervisor/worker synchronization channels

### Request Path Must Consume

- `Arc<dyn BlockListStore>` / `Arc<dyn WafProcessor>` / trait objects
- Immutable config snapshots
- Local blocklist query capability traits
- Request context objects populated at the boundary
- Telemetry emitter traits

### Request Path Must Not Import/Own

- Mesh transport concrete types (`MeshTransportManager`, `MeshBackendPool`)
- DHT record store types (`RecordStoreManager`)
- Raft client/state-machine types
- Admin handlers (`verify_admin_token`)
- Concrete `BlockStore` or `ThreatIntelligenceManager`
- Concrete `ThreatIntelligenceManager` (removed from WAF in Iteration 59)
- Raft/DHT module imports (`crate::raft::`, `openraft::`, `crate::dht::`)
- Supervisor IPC manager internals
- Snapshot/catchup/gossip APIs

## Concrete Type Threading

Some concrete types (mesh transport, IPC stream, serverless manager) are threaded through request-path dispatch contexts (`HttpServerRuntime`, `BackendDispatchContext`, `HttpRequestPostludeContext`) as pass-through data from the composition root. This is architecturally acceptable — the types are received, not constructed or owned.

## Known Pass-Through Types

These concrete types flow through request-path dispatch but are owned by the composition root:

| Type | Origin | Usage |
|------|--------|-------|
| `MeshTransportManager` | Mesh init | Threaded for serverless routing |
| `MeshBackendPool` | Mesh init | Threaded for backend routing |
| `MeshConfig` | Config | Threaded for mesh features |
| `AsyncIpcStream` | IPC init | Threaded for request logging |
| `WorkerId` | IPC init | Threaded for request logging |
| `ServerlessManager` | App init | Threaded for WASM dispatch |
| `GranianSupervisor` | App init | Threaded for app-server dispatch |

## Adding New Capabilities

To add a new capability to the request path:

1. Define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`
2. Implement the trait on a concrete type in a composition root
3. Pass `Arc<dyn YourTrait>` to request-path modules
4. Never pass the concrete type directly to request-path code

## WAF Blocklist No-Op Shims (Iteration 59)

The following `WafCore` methods are **API-compatibility shims** — they do not mutate block store state:

| Method | Behavior |
|--------|----------|
| `check_early()` | Always returns `WafDecision::Pass` |
| `block_ip_for_honeypot()` | No-op (empty body) |
| `block_ip_with_threat_intel()` | No-op (empty body) |

These methods are retained only for trait compatibility (`EarlyWafHooks`, `ChallengePathWaf`, `UploadValidationWaf`). Blocklist writes occur via dedicated local/control-plane enforcement paths, not through the WAF request path.

`check_dht_threat_lookup()` and `get_threat_intel()` were removed in Iteration 59 — they were dead code referencing concrete `ThreatIntelligenceManager` on the request path.

## Guardrail (Iteration 60)

`tests/data_plane_composition_boundary_guard.rs` enforces the composition boundary with role-based file classification and three token groups:

- **`BoundaryRole` enum**: Classifies files as `CompositionRoot`, `RequestPath`, `ControlPlane`, `Admin`, `SharedTypes`, `TestOnly`, or `Unclassified`. Each file under `src/worker/unified_server/` is classified individually. Unknown files under mixed-role directories fail closed as `Unclassified`.
- **`boundary_scan_roots()`**: Mixed-role scan roots that include `src/worker/unified_server/` alongside pure request-path directories. Every `.rs` file in these roots is traversed and classified.
- **`CONSTRUCTION_TOKENS`**: Catches concrete infrastructure construction (`BlockStore::new`, `ThreatIntelligenceManager::new`, etc.)
- **`TYPE_IMPORT_TOKENS`**: Catches concrete type imports (`crate::block_store::BlockStore`, `crate::raft::`, etc.)
- **`CONTROL_PLANE_OP_TOKENS`**: Catches control-plane operations (`export_blocklist_snapshot`, `lookup_threat_indicator_in_dht`, etc.)

Pass-through types in HTTP dispatch (`MeshTransportManager`, `MeshBackendPool`) have scoped `BoundaryException` entries with documented reasons. The guardrail also runs focused tests for BlockStore types, ThreatIntelligenceManager types, and Raft/DHT imports specifically.

**Exception liveness**: Every `BoundaryException` must correspond to a current, audited source occurrence. A liveness test verifies each exception token is present in at least one matching file, preventing stale exceptions from silently authorizing regressions.

**Fail-closed classification**: New files added under mixed-role directories (e.g., `src/worker/unified_server/`) must receive an explicit `BoundaryRole` classification. The default for unknown unified-server files is `Unclassified`, which causes the guardrail test to fail with instructions to classify the file explicitly.

## Mesh Readiness, Restart, and Process-Exit Policy (Iteration 84, updated Iteration 85)

The worker composition root (`src/worker/unified_server/mod.rs`) is the **sole owner** of three policy domains:

### 1. Mesh Readiness

- **Required mesh**: Startup is awaited inline before the worker ready message is sent. The composition root controls the exact sequencing: construct → subscribe → register observer/coordinator → await startup → send ready.
- **Optional mesh**: Startup is registered as a one-shot task in `WorkerTaskRegistry`. The worker ready message is sent immediately; mesh startup completion is non-fatal.
- **Disabled mesh**: `MeshInit::disabled()` returns no runtime resources. No topology, routing, transport, DNS, YARA, or DHT objects are created. No supervision pipeline exists. No observer, coordinator, startup task, or decision channel exists.

### 2. Mesh Restart

- Restart is **disabled** (`restart_enabled` is overridden to `false` at policy-build time with a warning — restart is not implemented).
- `MeshSupervisorDecision::RestartMesh` is unreachable in production policy. If it somehow arrives, the composition root maps it to `MeshRestartExhausted` and shuts down the worker.
- Restart execution (`execute_mesh_restart`) is not implemented. No restart metrics increment in supported configurations.

### 3. Process-Exit Policy

- The composition root derives the exit code from the authoritative `WorkerShutdownCause` via `shutdown_cause.exit_code()`.
- IPC notification routing (Step 10) is determined by the cause variant.
- No other module may call `std::process::exit()` or send worker-error IPC messages.

### Background Task Ownership (Iteration 84 Part F, updated Iteration 85, Iteration 86, Iteration 87, Iteration 88)

All mesh-adjacent background tasks are owned by the `WorkerTaskRegistry`:

| Task | Registry Class | Start Phase | Stop Signal |
|------|---------------|-------------|-------------|
| DNS verification loops | `RestartableBackground` | after mesh startup | registry shutdown |
| YARA broadcast loop | `RestartableBackground` | after mesh startup | channel close + `JoinSet` drain |
| Optional mesh startup | `OneShot` | Phase 14.5 | completes on startup |
| Mesh exit observer | `CriticalService` | Phase 14.5 | registry shutdown |
| Mesh supervision coordinator | `CriticalService` | Phase 14.5 | registry shutdown |

Topology background tasks are returned in `MeshInit` as component handles (`topology`). The composition root calls `build_background_tasks()` on each component after mesh startup succeeds, then registers them in `WorkerTaskRegistry` via `MeshTaskGroup::register_background_specs()`. DHT routing initialization is now part of the MeshTransport transactional startup (Iteration 87) and no longer returned in `MeshInit`. Support tasks (DNS, YARA) are registered AFTER mesh startup succeeds (Iteration 86), not before. YARA broadcast uses a local `JoinSet` for per-message child ownership (Iteration 85), with deadline-bounded drain via `run_yara_broadcast_loop()` (Iteration 86).

No bare `tokio::spawn()` calls remain in `init_mesh.rs`. The `MeshInit` struct returns components (registries, broadcast receivers) for the composition root to spawn and register.

### Configuration Validation (Iteration 86)

`validate_mesh_runtime_inputs()` is called during mesh init to validate configuration before constructing transport/topology/DHT objects. On validation failure, a `MeshConfigurationInvariant(String)` cause is returned on `WorkerShutdownCause`. This catches configuration invariant violations early, before any runtime objects are created.

### Mesh Restart (updated Iteration 86)

- Restart is **disabled** (`restart_enabled = true` is now rejected with an error by `build_mesh_supervision_policy()`, not just overridden).
- `MeshSupervisorDecision::RestartMesh` is unreachable in production policy. If it somehow arrives, the composition root maps it to `MeshRestartExhausted` and shuts down the worker.
- Restart execution (`execute_mesh_restart`) is not implemented. No restart metrics increment in supported configurations.

## Data-Plane Service Boundary (Iteration 98)

### Service Assembly Boundary

`services.rs` is the **data-plane assembly boundary**. It owns:

- Construction of `DataPlaneServices` and embedded `RequestServices`
- Cross-wiring of mesh-dependent services (serverless ↔ mesh, honeypot ↔ mesh)
- Threat-intel policy context build/apply/update path

### Field Ownership

`DataPlaneServices` fields are grouped by ownership:

| Group | Fields | Consumed By |
|-------|--------|-------------|
| Request-path handle | `request_services` | WAF/request dispatch |
| Runtime services | `serverless_manager`, `port_honeypot_runner` | Composition root, request path |
| Mesh/threat-intel | `mesh_transport_manager`, `threat_intel`, `threat_intel_policy`, `record_store` | Composition root (IPC updates) |

### Narrow Request-Path Handle

`RequestServices` (`src/worker/context.rs`) is the narrow request-path handle. It must:

- Not import worker startup, supervision, or shutdown modules
- Not carry mesh transport, IPC, or task registry handles
- Contain only request-execution services

### Centralized Cross-Wiring

`DataPlaneServicesBuilder::build_and_cross_wire()` is the single entry point for startup code. It:

1. Builds `DataPlaneServices` and embedded `RequestServices`
2. Applies threat-intel policy context to the manager
3. Cross-wires mesh-dependent services

Startup plan delegates service assembly through this narrow API. Manual inline cross-wiring is forbidden.

### Boundary Guards (Iteration 98)

The guard test file adds three new assertions:

- `request_services_must_not_import_worker_lifecycle_modules`: `context.rs` must not import startup/supervision/shutdown modules
- `startup_plan_delegates_data_plane_cross_wiring`: `startup_plan.rs` must use `build_and_cross_wire()` not manual inline cross-wiring
- `mesh_attachment_does_not_own_request_services`: `mesh_attachment.rs` must not import `RequestServices` or `DataPlaneServices`

## HTTP Request Pipeline Normalization (Iteration 99)

Both HTTP/1 and HTTP/3 request pipelines now use shared stage vocabulary documented in
`architecture/http_request_pipeline.md`. The stages are:

1. Request metadata normalization
2. Route resolution
3. Body policy (collect, stream, reject, tarpit)
4. WAF evaluation (early, streaming, buffered)
5. Terminal response handling
6. Upstream/app dispatch
7. Accounting (bandwidth, metrics, logs)

### Context Structs

HTTP/3 dispatch uses two context groups:
- `Http3RequestMetadata` — per-request fields (start, route_result, path, method, headers, host, query, user_agent, client_ip)
- `Http3DispatchDeps` — service handles (max_request_size, streaming_waf scanners, connection_limiter, main_config, client, upstream_client_registry, bandwidth, metrics)

HTTP/1 has equivalent stage mapping via `RequestFrontdoorContext`, `PreparedRequest`, and `RequestMetricsAdapter`.

### Boundary Invariant

Request dispatch consumes `RequestServices` or narrower handles. Neither protocol imports
`UnifiedServerWorkerState` or worker lifecycle modules. Guard tests in
`tests/http_request_pipeline_boundary_guard.rs` enforce this.

### Body/Streaming Semantics

Body and streaming behavior is intentionally NOT unified between HTTP/1 and HTTP/3. Different stream types,
flow-control, and backpressure semantics require protocol-specific implementations.
