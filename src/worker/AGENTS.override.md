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
// Old (deprecated)
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
                      handling loop, server run task, initial blocklist request

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

## Architecture Boundary Cleanup (Iteration 2)

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
