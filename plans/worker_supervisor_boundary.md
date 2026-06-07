# Worker/Supervisor Boundary Notes

> Last updated by MDM-W01 (Wave W, 2026-06).
> This file documents actual coupling between the worker/supervisor
> orchestration layers and the rest of the codebase, as measured by
> `rg` against `src/worker/` and `src/supervisor/`.
>
> The supervisor was consolidated from `src/overseer/`, `src/master/`,
> and `src/startup/master.rs` into `src/supervisor/` (per AGENTS.md).
> References to those old paths in older code are stale; current
> code lives only in `src/supervisor/`.

## 1. Layout

```text
src/worker/                       ~10,400 lines across 30+ files
  mod.rs                          submodule root + panic handler
  common.rs                       IpcConnection + collect_current_process_usage
  connect.rs                      IPC retry helpers
  connection.rs                   legacy WorkerState (pub(super))
  context.rs                      RequestServices DI struct
  drain_adapter.rs                small drain adapter
  drain_state.rs                  WorkerDrainState, RequestType
  extension.rs                    ExtensionRuntime / ExtensionRegistry
  image_rights.rs                 mark_image_rights_sync helper
  metrics.rs                      re-export of synvoid_metrics
  response_builder.rs             per-task minify response helper
  traits.rs                       BaseWorkerState / WorkerLifecycle
  cpu_task/                       CPU offload worker (~2,500 lines)
    mod.rs, state.rs, metrics.rs, payload.rs, dispatch.rs,
    connection.rs, yara.rs
  unified_server/                 UnifiedServerWorker (~1,500 lines)
    mod.rs, state.rs, init_runtime.rs, init_config.rs,
    init_apps.rs, init_waf.rs, init_mesh.rs, lifecycle.rs

src/supervisor/                   ~2,700 lines across 9 files
  mod.rs                          re-exports
  api.rs                          gRPC control plane (tonic)
  cli_commands.rs                 CLI handlers (status/stop/reload/...)
  commands.rs                     IPC command dispatch
  drain_manager.rs                DrainManager / DrainProtocol
  ipc.rs                          worker IPC connection handler
  mesh.rs                         mesh-agent mode + MeshControlPlane
  process.rs                      SupervisorProcess lifecycle
  state.rs                        SupervisorState struct
```

## 2. Which concrete subsystems worker constructs

The `UnifiedServerWorker` (in `src/worker/unified_server/`) directly
constructs or owns:

- `WafCore` (root-owned; see plan §2 "Do not move WafCore into synvoid-waf")
- `Router` (root-owned at `src/router.rs`)
- `WorkerMetrics` (re-exported from `synvoid_metrics`)
- `WorkerDrainState` (root-owned in `src/worker/drain_state.rs`,
  distinct from the legacy `src/drain::WorkerDrainState`)
- `UpstreamClientRegistry` (root-owned)
- `FloodProtector` (root-owned in `src/waf/flood`)
- `RequestSanitizer` (root-owned in `src/waf/adapter`)
- `StreamingWafCore` (root-owned)
- `ProxyCache` (in `synvoid_proxy_cache`)
- `PluginManager` (root-owned in `src/plugin`)
- `StaticFileHandler` (in `synvoid_static_files`)
- `MinifierClient` / `AsyncMinifierClient` (in `synvoid_static_files`)
- `UnifiedServer` (root-owned in `src/server`)
- `Arc<ConfigManager>` (in `synvoid_config`)
- `ExtensionRegistry` with `MeshExtensionRuntime`, `DnsExtensionRuntime`,
  `ServerlessExtensionRuntime`, `HoneypotExtensionRuntime`
  (`src/worker/extension.rs`)

The `CpuWorker` (in `src/worker/cpu_task/`) constructs:

- `CpuWorkerState` (private to the cpu_task module)
- `YaraScanner` (via `synvoid_upload::yara_scanner`)
- Minifier caches backed by `synvoid_static_files::minifier`
- `Arc<ConfigManager>` (in `synvoid_config`)

## 3. Which concrete subsystems supervisor constructs

The `SupervisorProcess` (in `src/supervisor/process.rs`) constructs or
manages:

- `DrainManager` / `DrainProtocol` (`src/supervisor/drain_manager.rs`)
- `ProcessManager` (in `synvoid_ipc`; the supervisor IS the lifecycle
  owner)
- `IpcListener` (in `synvoid_ipc`)
- `SupervisorState` with `ProbeTracker`, `SuspiciousWordTracker`,
  `UpstreamErrorTracker`, `ThreatLevelManager`,
  `RuleFeedManagerForWaf`, `ThreatIntelligenceManager` (mesh),
  `YaraRulesManager` (mesh), `BlockStore`, `MeshTransportManager`
  (mesh), `OrgKeyManager` (mesh) — see `src/supervisor/state.rs`
- `ControlPlaneService` (tonic gRPC) — `src/supervisor/api.rs`
- Shared connection table and rate-limit table
  (`crate::upstream::shared_state`)
- Granian supervisor (in `synvoid_app_server`)

`src/supervisor/mesh.rs` constructs `MeshControlPlane` with
`MeshTransportManager`, `ThreatIntelligenceManager`,
`YaraRulesManager` (mesh-gated).

## 4. Legitimate orchestration dependencies

These are concrete types the orchestration layer must construct
because it owns their lifecycle:

- `WafCore` — worker constructs and configures the WAF engine.
- `Router` — worker builds routing tables from `ConfigManager`.
- `WorkerMetrics` — worker owns its metrics atomics.
- `WorkerDrainState` (in `src/worker/drain_state.rs`) — worker owns
  per-process drain tracking.
- `UpstreamClientRegistry`, `FloodProtector`, `RequestSanitizer`,
  `StreamingWafCore`, `ProxyCache`, `PluginManager`,
  `StaticFileHandler`, `MinifierClient` / `AsyncMinifierClient`,
  `UnifiedServer` — all constructed by the unified server bootstrap.
- `DrainManager`, `DrainProtocol` — supervisor owns cross-worker
  drain coordination.
- `ProcessManager` — supervisor owns worker process lifecycle.
- `IpcListener` — supervisor owns the supervisor IPC socket.
- `SupervisorState` with all trackers and managers — supervisor
  owns these.
- `ControlPlaneService` — supervisor owns the gRPC control plane.
- `MeshControlPlane` (when mesh feature is on).

The trait/seam pattern (already in place) lets downstream code
(proxy, HTTP pipeline) use traits instead of concrete types, but
the orchestration layer itself must construct the concrete types.

## 5. Accidental dependencies that are pure re-exports of extracted crates

These import paths are re-exports of types that are already owned by
an extracted crate. The orchestration layer would still construct
the same type; only the import path is more direct.

| Current import | True owner | Suggested replacement |
|----------------|------------|----------------------|
| `crate::config::ConfigManager` | `synvoid_config` | `synvoid_config::ConfigManager` |
| `crate::config::MainConfig` | `synvoid_config` | `synvoid_config::MainConfig` |
| `crate::config::ProcessManagerConfig` | `synvoid_config` | `synvoid_config::ProcessManagerConfig` |
| `crate::config::site::SiteStaticConfig` | `synvoid_config` | `synvoid_config::site::SiteStaticConfig` |
| `crate::process::{ProcessManager, WorkerId, Message, IpcStream, ...}` | `synvoid_ipc` | `synvoid_ipc::{...}` |
| `crate::process::ipc_signed::IpcSigner` | `synvoid_ipc` | `synvoid_ipc::IpcSigner` |
| `crate::process::ipc_transport::IpcStream` | `synvoid_ipc` | `synvoid_ipc::IpcStream` |
| `crate::process::ipc_transport::IpcEndpoint` | `synvoid_ipc` | `synvoid_ipc::IpcEndpoint` |
| `crate::metrics::WorkerMetrics` | `synvoid_metrics` | `synvoid_metrics::WorkerMetrics` |
| `crate::metrics::TimingStatsPayload` | `synvoid_metrics` | `synvoid_metrics::TimingStatsPayload` |
| `crate::metrics::payloads::HealthStatus` | `synvoid_metrics` | `synvoid_metrics::payloads::HealthStatus` |
| `crate::block_store::BlockStore` | `synvoid_block_store` | `synvoid_block_store::BlockStore` |
| `crate::mesh::threat_intel::ThreatIntelligenceManager` | `synvoid_mesh` (feature-gated) | `synvoid_mesh::threat_intel::ThreatIntelligenceManager` |
| `crate::mesh::transports::MeshTransportManager` | `synvoid_mesh` (feature-gated) | `synvoid_mesh::transports::MeshTransportManager` |
| `crate::mesh::protocol::MeshMessageSigner` | `synvoid_mesh` (feature-gated) | `synvoid_mesh::protocol::MeshMessageSigner` |
| `crate::mesh::yara_rules::YaraRulesManager` | `synvoid_mesh` (feature-gated) | `synvoid_mesh::yara_rules::YaraRulesManager` |
| `crate::mesh::org_key_manager::OrgKeyManager` | `synvoid_mesh` (feature-gated) | `synvoid_mesh::org_key_manager::OrgKeyManager` |
| `crate::static_files::minifier` | `synvoid_static_files` | `synvoid_static_files::minifier` |
| `crate::static_files::client::*` | `synvoid_static_files` | `synvoid_static_files::client::*` |
| `crate::upload::*` | `synvoid_upload` | `synvoid_upload::*` |
| `crate::serverless::*` | `synvoid_serverless` | `synvoid_serverless::*` |
| `crate::app_server::*` | `synvoid_app_server` | `synvoid_app_server::*` |
| `crate::tls::config::InternalTlsConfig` | `synvoid_tls` | `synvoid_tls::config::InternalTlsConfig` |

The following imports are **not** accidental re-exports and should
NOT be replaced:

- `crate::waf::*` — `WafCore`, `Router`, `RequestSanitizer`,
  `FloodProtector`, `StreamingWafCore`, `ThreatLevelManager`,
  `RuleFeedManagerForWaf`, `ProbeTracker`, `SuspiciousWordTracker`,
  `UpstreamErrorTracker`, `YaraRulesManager` (via `src/waf/`) are
  root-owned. Per plan §2, WafCore stays root-owned.
- `crate::drain::*` — `DrainStatus`, `WorkerDrainState` (the legacy
  shared-drain struct) live in `src/drain/`; there is no extracted
  crate for this. Note: this is a different `WorkerDrainState` from
  `src/worker/drain_state.rs` and from `synvoid_http::WorkerDrainState`.
- `crate::platform::*` — `PlatformPaths` lives in `src/platform/fs.rs`
  and is re-exported by `synvoid_platform`, but the root module
  has its own `pub use` and is the primary entry point.
- `crate::server::UnifiedServer` — root-owned; no extracted crate.
- `crate::plugin::*` — root-owned; no extracted crate.
- `crate::honeypot_port::*` — root-owned.
- `crate::mesh::*` paths that reference root-owned types via the
  root re-export of `synvoid_mesh::mesh::*` are valid, but the
  replacement with `synvoid_mesh::*` works because the synvoid-mesh
  crate also does `pub use mesh::*`.

## 6. Are worker/supervisor frequent edit paths?

Both layers are large and have multiple subdirectories, but they
are not on a hot iteration loop:

- `src/worker/` totals ~10,400 lines across 30+ files. The two
  large worker files were split into `cpu_task/` and
  `unified_server/` subdirectories in 2026-06 specifically to keep
  each file focused on a single architectural phase (see
  `src/worker/AGENTS.override.md`).
- `src/supervisor/` totals ~2,700 lines across 9 files. The
  `DrainManager` and `DrainProtocol` types were extracted to
  `src/supervisor/drain_manager.rs`; the supervisor consolidation
  in 2026 folded `overseer/`, `master/`, and `startup/master.rs`
  into one directory.
- Per the plan thesis (§1), neither layer is on a measured hot
  rebuild path; the priority is keeping them stable orchestration
  surfaces, not extracting further.

## 7. MDM-W02 import replacements

All replacements below are mechanical `use`-statement rewrites; no
construction flow, generics, or behavior was touched. The original
import path is on the left, the new one is on the right.

### Worker files

| File:line (before) | File:line (after) | Before | After |
|--------------------|-------------------|--------|-------|
| `src/worker/common.rs:8-13` | `src/worker/common.rs:8-13` | `use crate::config::ConfigManager;`<br>`use crate::process::{connect_to_supervisor, current_timestamp, IpcStream, Message, RequestLogPayload, WorkerId, WorkerMetricsPayload};`<br>`use crate::{DrainFlag, RunningFlag};` | `use crate::{DrainFlag, RunningFlag};`<br>`use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::{connect_to_supervisor, current_timestamp, IpcStream, Message, RequestLogPayload, WorkerId, WorkerMetricsPayload};` |
| `src/worker/connect.rs:5-8` | `src/worker/connect.rs:5-8` | `use crate::process::ipc_signed::IpcSigner;`<br>`use crate::process::ipc_transport::IpcEndpoint;`<br>`use crate::process::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use crate::process::{connect_to_supervisor, IpcStream};` | `use synvoid_ipc::ipc_signed::IpcSigner;`<br>`use synvoid_ipc::ipc_transport::IpcEndpoint;`<br>`use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use synvoid_ipc::{connect_to_supervisor, IpcStream};` |
| `src/worker/connection.rs:8-12` | `src/worker/connection.rs:8-13` | `use crate::config::ConfigManager;`<br>`use crate::metrics::WorkerMetrics;`<br>`use crate::process::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use crate::process::WorkerId;`<br>`use crate::{DrainFlag, RunningFlag};` | `use crate::{DrainFlag, RunningFlag};`<br>`use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use synvoid_ipc::WorkerId;`<br>`use synvoid_metrics::WorkerMetrics;` |
| `src/worker/context.rs:3-9` | `src/worker/context.rs:3-9` | `use crate::mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated)<br>`use crate::mesh::yara_rules::YaraRulesManager;` (mesh-gated) | `use synvoid_mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated)<br>`use synvoid_mesh::yara_rules::YaraRulesManager;` (mesh-gated) |
| `src/worker/cpu_task/mod.rs:19-26` | `src/worker/cpu_task/mod.rs:19-27` | `use crate::config::ConfigManager;`<br>`use crate::process::ipc_signed::IpcSigner;`<br>`use crate::process::{CpuTaskPayload, Message};`<br>`use crate::static_files::minifier;` | `use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::ipc_signed::IpcSigner;`<br>`use synvoid_ipc::{CpuTaskPayload, Message};`<br>`use synvoid_static_files::minifier;` |
| `src/worker/cpu_task/state.rs:9-13` | `src/worker/cpu_task/state.rs:9-14` | `use crate::config::ConfigManager;`<br>`use crate::process::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use crate::static_files::minifier;` | `use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use synvoid_static_files::minifier;` |
| `src/worker/cpu_task/dispatch.rs:8-12` | `src/worker/cpu_task/dispatch.rs:8-12` | `use crate::process::{CpuTaskErrorCode, CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, CpuTaskResult, Message};` | `use synvoid_ipc::{CpuTaskErrorCode, CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, CpuTaskResult, Message};` |
| `src/worker/cpu_task/payload.rs:10` | `src/worker/cpu_task/payload.rs:10` | `use crate::process::{CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, Message};` | `use synvoid_ipc::{CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, Message};` |
| `src/worker/cpu_task/connection.rs:6` | `src/worker/cpu_task/connection.rs:6` | `use crate::process::{IpcStream, Message};` | `use synvoid_ipc::{IpcStream, Message};` |
| `src/worker/cpu_task/metrics.rs:10-11` | `src/worker/cpu_task/metrics.rs:10-11` | `use crate::metrics::TimingStatsPayload;`<br>`use crate::process::{CpuOffloadStats, CpuTaskKind};` | `use synvoid_ipc::{CpuOffloadStats, CpuTaskKind};`<br>`use synvoid_metrics::TimingStatsPayload;` |
| `src/worker/cpu_task/yara.rs:8` | `src/worker/cpu_task/yara.rs:8` | `main_config: &crate::config::MainConfig,` | `main_config: &synvoid_config::MainConfig,` |
| `src/worker/response_builder.rs:8-9` | `src/worker/response_builder.rs:8-9` | `use crate::process::CpuTaskResult;`<br>`use crate::static_files::minifier;` | `use synvoid_ipc::CpuTaskResult;`<br>`use synvoid_static_files::minifier;` |
| `src/worker/drain_state.rs:13-14` | `src/worker/drain_state.rs:13-14` | `use crate::DrainFlag;` | `use synvoid_utils::DrainFlag;` |
| `src/worker/traits.rs:1-2` | `src/worker/traits.rs:1-2` | `use crate::process::WorkerId;` | `use synvoid_ipc::WorkerId;` |
| `src/worker/extension.rs:3` | `src/worker/extension.rs:3` | `use crate::metrics::payloads::HealthStatus;` | `use synvoid_metrics::payloads::HealthStatus;` |
| `src/worker/unified_server/state.rs:16-23` | `src/worker/unified_server/state.rs:16-23` | `use crate::app_server::GranianSupervisor;`<br>`use crate::common::setup_panic_handler;`<br>`use crate::config::ConfigManager;`<br>`use crate::platform::fs::PlatformPaths;`<br>`use crate::process::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use crate::process::{check_ports_available, WorkerId};`<br>`use crate::server::UnifiedServer;`<br>`use crate::{DrainFlag, RunningFlag};` | `use crate::app_server::GranianSupervisor;`<br>`use crate::common::setup_panic_handler;`<br>`use crate::platform::fs::PlatformPaths;`<br>`use crate::server::UnifiedServer;`<br>`use crate::{DrainFlag, RunningFlag};`<br>`use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use synvoid_ipc::{check_ports_available, WorkerId};` |
| `src/worker/unified_server/init_apps.rs:10-14` | `src/worker/unified_server/init_apps.rs:10-14` | `use crate::app_server::{GranianConfig, GranianSupervisor};`<br>`use crate::config::ConfigManager;`<br>`use crate::plugin::get_global_plugin_manager;`<br>`use crate::process::WorkerId;`<br>`use crate::server::UnifiedServer;` | `use crate::app_server::{GranianConfig, GranianSupervisor};`<br>`use crate::plugin::get_global_plugin_manager;`<br>`use crate::server::UnifiedServer;`<br>`use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::WorkerId;` |
| `src/worker/unified_server/init_mesh.rs:12-18` | `src/worker/unified_server/init_mesh.rs:12-18` | `use crate::mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated)<br>`use crate::mesh::transports::MeshTransportManager;` (mesh-gated)<br>`use crate::config::ConfigManager;`<br>`use crate::server::UnifiedServer;` | `use synvoid_mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated)<br>`use synvoid_mesh::transports::MeshTransportManager;` (mesh-gated)<br>`use crate::server::UnifiedServer;`<br>`use synvoid_config::ConfigManager;` |
| `src/worker/unified_server/init_waf.rs:6-10` | `src/worker/unified_server/init_waf.rs:6-10` | `use crate::config::ConfigManager;`<br>`use crate::honeypot_port::{PortHoneypotConfig, PortHoneypotRunner};`<br>`use crate::server::UnifiedServer;`<br>`use crate::upload::UploadValidator;` | `use crate::honeypot_port::{PortHoneypotConfig, PortHoneypotRunner};`<br>`use crate::server::UnifiedServer;`<br>`use crate::upload::UploadValidator;`<br>`use synvoid_config::ConfigManager;` |
| `src/worker/unified_server/lifecycle.rs:12-14` | `src/worker/unified_server/lifecycle.rs:12-14` | `use crate::process::{current_timestamp, Message};`<br>`use crate::static_files::client::get_global_async_cpu_offload_stats;` | `use synvoid_ipc::{current_timestamp, Message};`<br>`use synvoid_static_files::client::get_global_async_cpu_offload_stats;` |
| `src/worker/unified_server/mod.rs:32-35` | `src/worker/unified_server/mod.rs:32-36` | `use crate::plugin::get_global_plugin_manager;`<br>`use crate::process::WorkerId;`<br>`use crate::server::UnifiedServer;`<br>`use crate::{DrainFlag, RunningFlag};` | `use crate::plugin::get_global_plugin_manager;`<br>`use crate::server::UnifiedServer;`<br>`use crate::{DrainFlag, RunningFlag};`<br>`use synvoid_ipc::WorkerId;` |
| `src/worker/common.rs:253` (mid-file `use`) | `src/worker/common.rs:253` | `use crate::process::ipc_transport::IpcStream as AsyncIpcStream;` | `use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;` |
| `src/worker/context.rs:4-5` | `src/worker/context.rs:4-5` | `use crate::serverless::registry::ServerlessRegistry;`<br>`use crate::upload::UploadValidator;` | `use synvoid_serverless::registry::ServerlessRegistry;`<br>`use synvoid_upload::UploadValidator;` |
| `src/worker/cpu_task/yara.rs:5` | `src/worker/cpu_task/yara.rs:5` | `use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};` | `use synvoid_upload::yara_scanner::{YaraRulesSource, YaraScanner};` |
| `src/worker/cpu_task/state.rs:12` | `src/worker/cpu_task/state.rs:13` | `use crate::upload::yara_scanner::YaraScanner;` | `use synvoid_upload::yara_scanner::YaraScanner;` |
| `src/worker/unified_server/state.rs:16` | `src/worker/unified_server/state.rs:16` | `use crate::app_server::GranianSupervisor;` | `use synvoid_app_server::GranianSupervisor;` |
| `src/worker/unified_server/init_apps.rs:10` | `src/worker/unified_server/init_apps.rs:10` | `use crate::app_server::{GranianConfig, GranianSupervisor};` | `use synvoid_app_server::{GranianConfig, GranianSupervisor};` |
| `src/worker/unified_server/init_waf.rs:9` | `src/worker/unified_server/init_waf.rs:9` | `use crate::upload::UploadValidator;` | `use synvoid_upload::UploadValidator;` |

### Supervisor files

| File:line (before) | File:line (after) | Before | After |
|--------------------|-------------------|--------|-------|
| `src/supervisor/state.rs:4-14` | `src/supervisor/state.rs:4-15` | `use crate::block_store::BlockStore;`<br>`use crate::config::ConfigManager;`<br>`use crate::mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated) | `use synvoid_block_store::BlockStore;`<br>`use synvoid_config::ConfigManager;`<br>`use synvoid_mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated) |
| `src/supervisor/process.rs:7-16` | `src/supervisor/process.rs:7-17` | `use crate::block_store::BlockStore;`<br>`use crate::config::ConfigManager;`<br>`use crate::process::{IpcEndpoint, IpcListener, Message, PidFileManager, ProcessEvent, ProcessManager, ProcessManagerConfig, WorkerId};` | `use synvoid_block_store::BlockStore;`<br>`use synvoid_config::ConfigManager;`<br>`use synvoid_ipc::{IpcEndpoint, IpcListener, Message, PidFileManager, ProcessEvent, ProcessManager, ProcessManagerConfig, WorkerId};` |
| `src/supervisor/drain_manager.rs:11-12` | `src/supervisor/drain_manager.rs:11-12` | `use crate::process::{IpcStream, Message, WorkerId};` | `use synvoid_ipc::{IpcStream, Message, WorkerId};` |
| `src/supervisor/ipc.rs:4-5` | `src/supervisor/ipc.rs:4-5` | `use crate::process::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use crate::process::{ErrorCode, ErrorSeverity, Message, ProcessManager, WorkerId};` | `use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use synvoid_ipc::{ErrorCode, ErrorSeverity, Message, ProcessManager, WorkerId};` |
| `src/supervisor/ipc.rs:10` (test) | `src/supervisor/ipc.rs:10` (test) | `use crate::metrics::WorkerMetricsPayload;` | `use synvoid_metrics::WorkerMetricsPayload;` |
| `src/supervisor/commands.rs:1-6` | `src/supervisor/commands.rs:1-6` | `use crate::process::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use crate::process::{CommandResponse, ProcessManager, StatusStats, SupervisorCommand, SupervisorStatus, ThreatSummary};` | `use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;`<br>`use synvoid_ipc::{CommandResponse, ProcessManager, StatusStats, SupervisorCommand, SupervisorStatus, ThreatSummary};` |
| `src/supervisor/api.rs:4-6` | `src/supervisor/api.rs:4-6` | `use crate::process::ProcessManager;`<br>`use crate::tls::config::InternalTlsConfig;` | `use synvoid_ipc::ProcessManager;`<br>`use synvoid_tls::config::InternalTlsConfig;` |
| `src/supervisor/cli_commands.rs:5-10` | `src/supervisor/cli_commands.rs:5-10` | `use crate::config::MainConfig;`<br>`use crate::mesh::protocol::MeshMessageSigner;` (mesh-gated)<br>`use crate::mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated)<br>`use crate::process::{CommandClient, PidFileManager, SupervisorCommand};` | `use synvoid_config::MainConfig;`<br>`use synvoid_mesh::protocol::MeshMessageSigner;` (mesh-gated)<br>`use synvoid_mesh::threat_intel::ThreatIntelligenceManager;` (mesh-gated)<br>`use synvoid_ipc::{CommandClient, PidFileManager, SupervisorCommand};` |
| `src/supervisor/mesh.rs:4-17` | `src/supervisor/mesh.rs:4-17` | `use crate::block_store::BlockStore;` (mesh-gated)<br>`use crate::config::{ConfigManager, MainConfig};` (mesh-gated)<br>`use crate::mesh::threat_intel::{ThreatIntelligenceConfig, ThreatIntelligenceManager};` (mesh-gated)<br>`use crate::mesh::{backend::create_record_store, backend::MeshBackendPool, ...};` (mesh-gated) | `use synvoid_block_store::BlockStore;` (mesh-gated)<br>`use synvoid_config::{ConfigManager, MainConfig};` (mesh-gated)<br>`use synvoid_mesh::threat_intel::{ThreatIntelligenceConfig, ThreatIntelligenceManager};` (mesh-gated)<br>`use synvoid_mesh::{backend::create_record_store, backend::MeshBackendPool, ...};` (mesh-gated) |

### Stop conditions hit

- **None that block replacement.** All candidate imports in §5 were
  mechanical: the extracted crate already owned the type, the
  replacement path resolved to the same item via `pub use
  synvoid_*::*` at the root, and no behavior or construction flow
  was changed. The mesh-gated imports remain `#[cfg(feature =
  "mesh")]` exactly as before; `synvoid-mesh` is an optional
  dependency of the root crate that is enabled by the same feature
  flag, so the feature gate is preserved.

- **Out-of-scope inline paths** (e.g. `crate::mesh::X` or
  `crate::process::X` written inline in function bodies in
  `src/worker/unified_server/init_mesh.rs`,
  `src/worker/unified_server/mod.rs`,
  `src/supervisor/ipc.rs`, and `src/supervisor/process.rs`) were
  intentionally left as `crate::*`. The plan rule says to replace
  *imports* (`use` statements) only. These inline paths still
  resolve correctly and can be cleaned up in a future pass if
  desired.

- **Imports that were intentionally NOT replaced:**
  - `crate::waf::*` — root-owned (WafCore and the WAF subsystem
    stay root by plan §2).
  - `crate::drain::*` — `DrainStatus` / `WorkerDrainState` live in
    `src/drain/` and have no extracted crate.
  - `crate::platform::*` — `PlatformPaths` is in `src/platform/`
    and is the primary entry point; not an extracted-crate re-export.
  - `crate::plugin::*` — root-owned.
  - `crate::server::UnifiedServer` — root-owned.
  - `crate::honeypot_port::*` — root-owned.

### Validation

- `cargo check --lib --no-default-features` — clean (no errors).
- `cargo check --no-default-features --features mesh,dns` — clean
  (no errors).
- `cargo fmt` — clean.
- `cargo check -p synvoid-waf`, `cargo check -p synvoid-proxy`,
  `cargo check -p synvoid-http` — clean.

**Pre-existing issues, NOT introduced by MDM-W02:**

- `cargo check --no-default-features --features mesh` fails with
  `error[E0425]: cannot find value 'backend_pool'/'signer_for_mesh'
  in this scope` at `src/worker/unified_server/init_mesh.rs:311`
  and `:313`. Verified to be present on `main` before any
  MDM-W02 edits (tested via `git stash`); the variables are
  declared as `_backend_pool` / `_signer_for_mesh` and later
  referenced without the leading underscore. Not an import
  problem and not in scope for this wave.
- `cargo test --lib --no-run` fails for unrelated pre-existing
  reasons (`src/challenge/mesh_pow.rs:270` and
  `src/http/server.rs:370`); verified to be present on `main`
  before any MDM-W02 edits. Not an import problem and not in
  scope for this wave.

## 8. Historical notes

- `src/overseer/`, `src/master/`, and `src/startup/master.rs` were
  consolidated into `src/supervisor/` in 2026. Any reference to
  the old paths in older code or comments is stale.
- `src/worker/cpu_task/connection.rs` and `src/worker/connection.rs`
  are different modules despite the shared name — see the
  override file `src/worker/AGENTS.override.md` for the distinction.
- `src/worker/drain_state.rs::WorkerDrainState` is distinct from
  `src/drain::WorkerDrainState` and from `synvoid_http::WorkerDrainState`.
  They are not interchangeable.
