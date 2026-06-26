# Phase 2 Plan: UnifiedServer Startup Plan and Runtime Handle Ownership

Status: detailed handoff plan.

Roadmap position: Phase 2 of `plans/roadmap.md`.

Primary goal: split the large `UnifiedServer` composition root into explicit startup validation, resource construction, and runtime handle ownership. This phase should reduce half-constructed runtime states and eliminate unmanaged long-lived handles.

## Architectural Context

`src/server/mod.rs` currently acts as a large root composition point. It owns or wires HTTP, HTTPS, HTTP/3, TCP, UDP, TLS, tunnels, drain state, mesh handles, metrics, IPC, block store, serverless manager, app servers, DNS, and ACME-related state.

That is acceptable for a root-owned composition module, but the constructor and `run()` currently mix several concerns:

- reading config,
- deriving addresses and feature state,
- constructing WAF and listener pools,
- loading TLS certificates,
- constructing tunnel/DNS resources,
- loading plugins,
- enabling plugin hot reload,
- spawning runtime tasks,
- storing shared request/server state.

This phase introduces typed boundaries so validation, resource creation, and runtime ownership are testable separately.

## Non-Goals

Do not redesign HTTP request handling in this phase.

Do not move `UnifiedServer` out of the root crate.

Do not rewrite worker startup. This phase is focused on `src/server/mod.rs` and immediately related runtime handles.

Do not change public behavior unless correcting unmanaged lifecycle ownership requires a controlled shutdown behavior change.

## Deliverables

1. `UnifiedServerStartupPlan`: mostly pure validated startup state.
2. `UnifiedServerResources`: constructed runtime resources before tasks are spawned.
3. `UnifiedServerRuntimeHandles`: owned long-lived task/watch handles with shutdown/drain behavior.
4. Replacement for plugin hot-reload `std::mem::forget(lifecycle)` with owned lifecycle storage.
5. Startup validation tests for ports, feature combinations, worker scaling, and missing/invalid resource configuration.
6. A guard or focused test rejecting unmanaged lifecycle leaks in server/plugin startup code.
7. Documentation update in `architecture/worker_data_plane_composition_root.md` or a new `architecture/unified_server_startup.md`.

## Proposed Module Layout

Prefer splitting `src/server/mod.rs` into focused submodules without changing the public `UnifiedServer` type all at once.

Suggested layout:

```text
src/server/
  mod.rs                  # public UnifiedServer facade and high-level run()
  startup_plan.rs          # pure/mostly pure validation and derived config
  resources.rs             # constructed resources bundle
  runtime_handles.rs       # task/watch/lifecycle handle ownership
  plugin_runtime.rs        # plugin load/hot-reload ownership helpers
  listeners.rs             # TCP/UDP/HTTP address/listener config helpers, if useful
  tls_runtime.rs            # cert resolver/ACME setup helpers, if useful
  dns_runtime.rs            # DNS resource setup under feature gate, if useful
```

Do not over-split in one pass. If time is constrained, implement only:

- `startup_plan.rs`,
- `resources.rs`,
- `runtime_handles.rs`,
- `plugin_runtime.rs`.

## Step 1: Add `UnifiedServerStartupPlan`

Create `src/server/startup_plan.rs`.

The plan should contain derived, validated state that can be produced without opening sockets or spawning background tasks.

Initial fields:

```rust
use std::net::SocketAddr;
use synvoid_config::{ConfigManager, Http3Config, TunnelConfig};

#[derive(Debug, Clone)]
pub struct UnifiedServerStartupPlan {
    pub http_addr: SocketAddr,
    pub http_addr_v6: Option<SocketAddr>,
    pub https_addr: Option<SocketAddr>,
    pub https_addr_v6: Option<SocketAddr>,
    pub http3_addr: Option<SocketAddr>,
    pub http3_addr_v6: Option<SocketAddr>,
    pub tls_enabled: bool,
    pub dns_enabled: bool,
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
    pub tunnel_enabled: bool,
    pub tunnel_config: Option<TunnelConfig>,
    pub http3_config: Http3Config,
    pub worker_count: usize,
    pub scaled_rate_limits: ScaledRateLimits,
}

#[derive(Debug, Clone)]
pub struct ScaledRateLimits {
    pub ip_per_second: u32,
    pub ip_per_minute: u32,
    pub global_per_second: u32,
    pub global_per_minute: u32,
}
```

Use existing config types where possible. If importing `synvoid_config` creates path churn, use current `crate::config::*` first and convert later.

Add an error enum rather than returning stringly typed errors:

```rust
#[derive(Debug, thiserror::Error)]
pub enum UnifiedServerStartupPlanError {
    #[error("invalid HTTP bind address: {0}")]
    InvalidHttpAddress(String),
    #[error("invalid HTTPS bind address: {0}")]
    InvalidHttpsAddress(String),
    #[error("invalid HTTP/3 bind address: {0}")]
    InvalidHttp3Address(String),
    #[error("listener conflict: {0}")]
    ListenerConflict(String),
    #[error("invalid feature combination: {0}")]
    InvalidFeatureCombination(String),
}
```

Then add:

```rust
impl UnifiedServerStartupPlan {
    pub fn from_config_snapshot(
        cfg: &crate::config::ConfigManager,
        worker_count: usize,
    ) -> Result<Self, UnifiedServerStartupPlanError> {
        // Move address parsing and worker-count scaling here.
        // Keep this mostly pure. Do not load certificates, create pools, spawn tasks, or touch disk.
    }
}
```

Validation to include in this phase:

- HTTP bind address parses.
- IPv6 bind address parses when present.
- HTTPS address parses when TLS enabled.
- HTTP/3 address parses when HTTP/3 enabled.
- HTTP/HTTPS/HTTP3 listener conflicts are detected when protocol and address/port combinations collide.
- `worker_count` is normalized to at least 1.
- rate limits are scaled by worker count in one place.
- tunnel QUIC config is not accessed with `unwrap()` unless tunnel config exists and is valid.

Move the existing worker-count scaling logic from `create_waf()` into this plan or into a helper used by the plan. `create_waf()` should consume the already-scaled values to avoid duplicated semantics.

## Step 2: Add `UnifiedServerResources`

Create `src/server/resources.rs`.

This struct owns constructed resources that do not themselves represent spawned runtime tasks.

Initial sketch:

```rust
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

pub struct UnifiedServerResources {
    pub waf: Arc<crate::waf::WafCore>,
    pub tcp_pool: Option<crate::tcp::listener::TcpListenerPool>,
    pub udp_pool: Option<crate::udp::listener::UdpListenerPool>,
    pub flood_protector: Option<Arc<crate::waf::FloodProtector>>,
    pub cert_resolver: Option<Arc<crate::tls::cert_resolver::CertResolver>>,
    pub tunnel_manager: Option<Arc<crate::tunnel::TunnelManager>>,
    pub tunnel_router: Option<Arc<Mutex<crate::tunnel::TunnelRouter>>>,
    pub app_servers: Arc<RwLock<std::collections::HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
    #[cfg(feature = "dns")]
    pub dns: Option<UnifiedServerDnsResource>,
}
```

Add a constructor:

```rust
impl UnifiedServerResources {
    pub async fn build(
        config: Arc<RwLock<crate::config::ConfigManager>>,
        plan: &UnifiedServerStartupPlan,
        #[cfg(feature = "mesh")]
        mesh_transport: Option<Arc<crate::mesh::transport::MeshTransportManager>>,
    ) -> Result<Self, UnifiedServerResourceError> {
        // Construct WAF, TCP/UDP pools, TLS resolver, tunnel manager/router, DNS server.
    }
}
```

This builder may read config, touch disk for cert loading, and construct pools. It must not spawn long-lived tasks or leak handles.

Suggested error enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum UnifiedServerResourceError {
    #[error("failed to create WAF: {0}")]
    Waf(String),
    #[error("failed to create TCP listener pool: {0}")]
    TcpPool(String),
    #[error("failed to create UDP listener pool: {0}")]
    UdpPool(String),
    #[error("failed to initialize TLS resources: {0}")]
    Tls(String),
    #[error("failed to initialize tunnel resources: {0}")]
    Tunnel(String),
    #[cfg(feature = "dns")]
    #[error("failed to initialize DNS resources: {0}")]
    Dns(String),
}
```

Be conservative about behavior changes. Existing code logs warnings and continues in some cases, such as TLS certificate loading failure. Preserve those semantics initially by returning `Ok` with missing optional resources where current behavior degrades gracefully.

## Step 3: Add `UnifiedServerRuntimeHandles`

Create `src/server/runtime_handles.rs`.

This struct owns handles for long-lived runtime tasks, watchers, and lifecycle state. It should support graceful shutdown and bounded drain.

Initial sketch:

```rust
use std::time::Duration;

pub struct UnifiedServerRuntimeHandles {
    handles: Vec<NamedRuntimeHandle>,
}

pub struct NamedRuntimeHandle {
    pub name: &'static str,
    pub class: RuntimeHandleClass,
    join: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHandleClass {
    CriticalServer,
    ProtocolListener,
    Maintenance,
    HotReloadWatcher,
    BestEffort,
}

impl UnifiedServerRuntimeHandles {
    pub fn new() -> Self { Self { handles: Vec::new() } }

    pub fn register(&mut self, handle: NamedRuntimeHandle) {
        self.handles.push(handle);
    }

    pub async fn shutdown_and_join(mut self, timeout: Duration) -> UnifiedServerRuntimeShutdownReport {
        // Abort or signal through owned shutdown channels where available.
        // Join with timeout.
        // Report completed/aborted/failed/timeouts by class and name.
    }
}
```

Do not force every existing `tokio::spawn` into this struct in one patch. Start with plugin hot-reload and any server-owned maintenance tasks introduced or touched by this phase. Then add a guardrail with an allowlist for remaining known spawns.

## Step 4: Replace Plugin Hot-Reload Lifecycle Leak

Current server startup loads plugins, creates `PluginManagerLifecycle`, enables hot reload, then uses `std::mem::forget(lifecycle)` so the watcher thread remains alive. Replace this with an owned handle.

Create `src/server/plugin_runtime.rs`.

Suggested model:

```rust
pub struct PluginRuntimeOwner {
    manager: Arc<crate::plugin::PluginManager>,
    lifecycle: Option<crate::plugin::PluginManagerLifecycle>,
}

impl PluginRuntimeOwner {
    pub fn new(manager: Arc<crate::plugin::PluginManager>) -> Self {
        Self { manager, lifecycle: None }
    }

    pub fn load_configured_plugins(
        &mut self,
        main_config: &crate::config::MainConfig,
    ) -> PluginRuntimeReport {
        // Move existing configured plugin loading logic here.
    }

    pub fn enable_hot_reload_if_configured(
        &mut self,
        plugin_dir: &std::path::Path,
    ) -> Result<(), String> {
        let mut lifecycle = crate::plugin::PluginManagerLifecycle::new(self.manager.clone());
        lifecycle.load_plugins_from_dir(plugin_dir).map_err(|e| e.to_string())?;
        lifecycle.enable_hot_reload(plugin_dir).map_err(|e| e.to_string())?;
        self.lifecycle = Some(lifecycle);
        Ok(())
    }
}
```

If `PluginManagerLifecycle` lacks a clean shutdown/drop behavior, inspect it and add one. The owner should not need `mem::forget`. If the watcher currently depends on `Drop` stopping the watcher, then storing the lifecycle owner in `ServerSharedState` or `UnifiedServer` is enough to preserve it for server lifetime and stop on drop.

Store `PluginRuntimeOwner` in `ServerSharedState` or a resource/runtime struct. If it must be accessed only to keep it alive, name the field explicitly:

```rust
_plugin_runtime_owner: Option<Arc<PluginRuntimeOwner>>,
```

Prefer not to hide it if future shutdown calls are needed.

## Step 5: Refactor `UnifiedServer::new()` Incrementally

Target shape:

```rust
pub async fn new(...) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
    let plan = {
        let cfg = config.read().await;
        UnifiedServerStartupPlan::from_config_snapshot(&cfg, worker_count)?
    };

    let resources = UnifiedServerResources::build(config.clone(), &plan, mesh_transport.clone()).await?;

    Ok(Self::from_plan_and_resources(config, plan, resources, ...))
}
```

Do not attempt a giant one-shot rewrite. Use a staged approach:

1. Extract pure helper functions from `new()` into `startup_plan.rs` while keeping call sites mostly unchanged.
2. Introduce `UnifiedServerStartupPlan` and use it for addresses and scaled rate limits.
3. Extract resource construction for WAF/TCP/UDP/TLS/tunnel/DNS into `resources.rs`.
4. Update `UnifiedServer` fields from plan/resources.
5. Only then remove duplicated old helper code.

## Step 6: Add Startup Plan Tests

Add tests in `src/server/startup_plan.rs` or `tests/unified_server_startup_plan.rs`.

Test cases:

- `worker_count_zero_normalizes_to_one`.
- `rate_limits_scale_by_worker_count`.
- `invalid_http_host_returns_typed_error`.
- `invalid_https_host_returns_typed_error_when_tls_enabled`.
- `http3_disabled_does_not_parse_http3_addr`.
- `http3_enabled_invalid_addr_returns_typed_error`.
- `listener_conflict_detected_for_same_addr_port_protocols`.
- `tunnel_router_not_constructed_when_tunnel_disabled`.

Use minimal config builders. If config construction is heavy, add a small test helper under `test_utils` or local helper functions.

## Step 7: Add Lifecycle Leak Guard

Add `tests/unified_server_lifecycle_ownership_guard.rs`.

Minimum guard:

- Scan `src/server/` and `src/plugin/` for `std::mem::forget` and `mem::forget`.
- Allow only documented exceptions if absolutely necessary. Prefer no allowlist.
- Optionally scan for bare `tokio::spawn` in `src/server/` and require an allowlist entry with reason.

Skeleton:

```rust
#[test]
fn server_runtime_does_not_leak_lifecycle_handles() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = [repo.join("src/server"), repo.join("src/plugin")];
    let mut offenders = Vec::new();

    for file in rust_files_under(&roots) {
        let text = std::fs::read_to_string(&file).unwrap();
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") { continue; }
            if trimmed.contains("std::mem::forget") || trimmed.contains("mem::forget") {
                offenders.push(format!("{}:{}: {}", file.display(), idx + 1, trimmed));
            }
        }
    }

    assert!(offenders.is_empty(), "server/plugin lifecycle handles must be owned, not leaked:\n{}", offenders.join("\n"));
}
```

## Step 8: Documentation

Add `architecture/unified_server_startup.md` or update `architecture/worker_data_plane_composition_root.md` with:

- Startup plan/resource/runtime split.
- Which files own validation vs resource construction vs task handles.
- Rule: no long-lived task/watch handle without an owner.
- Rule: plugin hot reload must be owned by `PluginRuntimeOwner` or equivalent.
- Remaining known exceptions, if any.

## Verification Commands

Run:

```bash
cargo fmt
cargo test -p synvoid server::startup_plan
cargo test --test unified_server_lifecycle_ownership_guard
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo check
```

If tests are added under integration tests rather than module tests, adjust names accordingly.

## Acceptance Criteria

This phase is complete when:

- Address parsing and worker-count rate-limit scaling are owned by `UnifiedServerStartupPlan` or equivalent.
- Runtime resource construction is separated from pure startup validation.
- Plugin hot-reload lifecycle is owned; `std::mem::forget(lifecycle)` is removed.
- At least one guard/test prevents lifecycle leaks in server/plugin runtime code.
- Startup validation has focused tests.
- Existing runtime behavior is preserved unless explicitly documented.
- Feature profile checks pass.

## Handoff Notes for Smaller Models

Start by extracting pure code, not by changing runtime behavior.

Avoid touching request handlers unless the compiler forces import updates.

Do not replace all server spawns in one pass. Removing the plugin lifecycle leak and creating the ownership pattern is enough for the first implementation pass.

Use typed errors for new validation code. Avoid adding more `Box<dyn Error>` internally.
