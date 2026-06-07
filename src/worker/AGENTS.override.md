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
- `init_runtime.rs`- re-exports from `state` (CPU affinity, shared-conn heartbeat)
- `init_config.rs` - re-exports from `state` (config, bandwidth, port check)
- `init_apps.rs`   - Granian supervisors, serverless manager, ACME wiring
- `init_waf.rs`    - WAF background tasks, UploadValidator, port honeypot
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
