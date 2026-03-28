# Plugin System Improvement Plan

## Overview

This document outlines the improvements needed for the MaluWAF plugin system to properly support:

1. **WASM filter plugins** - Request/response filtering via WebAssembly
2. **Axum dynamic plugins** - Running Axum-based webapps as origin servers via dynamically loaded shared libraries

The current implementation has critical bugs and incomplete integration.

---

## Current State Analysis

### Existing Components

| File | Purpose | Status |
|------|---------|--------|
| `src/plugin/mod.rs` | PluginManager orchestrator | Bug: discards loaded router |
| `src/plugin/wasm_runtime.rs` | WASM execution via wasmtime | Stub implementation only |
| `src/plugin/axum_loader.rs` | Loads .so plugins | Functional but unused |
| `examples/dynamic-plugin-example/` | Example plugin code | Works, needs updates |
| `src/config/plugins.rs` | WASM plugin config | Defined but not used |
| `src/router.rs` | RouteTarget with backend_plugin | Stores path, never uses it |
| `src/http/handler.rs` | Request proxying | Has proxy_appserver_request but no AxumDynamic case |

### Critical Issues

1. **Bug in PluginManager** (`src/plugin/mod.rs:110-112`):
   ```rust
   // CURRENT - loads router but then throws it away:
   let wrapper = AxumPluginWrapper {
       router: Router::new(),  // <-- Empty! Should be `router`
       name: wrapper_name,
   };
   ```

2. **AxumDynamic falls through to wrong proxy method** (`src/http/handler.rs:987`):
   - `BackendType::AxumDynamic` uses the `_` catch-all which calls `proxy_http_request`
   - But the upstream URL is set to `http://{socket}` which doesn't work for Unix sockets
   - The handler needs a case for `BackendType::AxumDynamic` that calls `proxy_appserver_request`
   - Note: `proxy_appserver_request` already handles Unix sockets via `is_unix_socket_url()`

3. **backend_plugin is never used**: `RouteTarget.backend_plugin` stores the plugin path but nothing actually loads/executes the plugin.

4. **WASM filters are stubs**: `filter_request()` always returns `Pass`.

5. **No process lifecycle**: Axum plugins need to be spawned as processes/tasks with proper start/stop handling.

6. **No hot-reload**: Plugins don't reload when .so files change.

---

## Architecture

### Unified Plugin System

Both WASM filters and Axum serverless apps share the same architectural pattern:

```
Request → [WASM Filters] → [Axum App Router] → Response
              │                    │
              ▼                    ▼
         Block/Challenge    Serve HTTP response
                            (via Unix socket proxy)
```

### Component Structure

```
src/plugin/
├── mod.rs          # PluginManager (orchestrator, bug fix here)
├── axum_loader.rs  # Load .so plugins (working, extend for hot-reload)
├── wasm_runtime.rs # WASM execution (implement filters)
├── app_manager.rs  # NEW: Process lifecycle, hot-reload, routing
└── wasi_host.rs    # NEW: WASI host functions for filters
```

---

## Implementation Plan

### Phase 1: Critical Bug Fix

**Task**: Fix the discarded router bug in PluginManager

**File**: `src/plugin/mod.rs`

**Change**:
```rust
// Line 105-118 - Fix the load_axum_plugin function
pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, AxumPluginError> {
    let (router, wrapper_name) = axum_loader::load_plugin(path)?;
    let wrapper_name_for_log = wrapper_name.clone();
    
    // FIX: Use the loaded router, not an empty one
    let wrapper = AxumPluginWrapper {
        router: router.clone(),  // Use the actual router
        name: wrapper_name,
    };
    
    self.axum_plugins.write().push(Arc::new(wrapper));
    tracing::info!("Loaded Axum plugin: {}", wrapper_name_for_log);
    
    Ok(Arc::new(router))  // Return the actual router
}
```

**Verification**: Check that returned router has actual routes.

---

### Phase 2: PluginAppManager (New Component)

**New File**: `src/plugin/app_manager.rs`

**Purpose**: Manage lifecycle of both WASM filters and Axum apps

```rust
// In PluginAppManager
pub struct AxumAppHandle {
    pub router: Router<()>,
    pub socket_path: PathBuf,
    pub plugin_path: PathBuf,
    pub loaded_at: Instant,
    pub routes: Vec<RouteInfo>,
}

pub struct RouteInfo {
    pub path: String,
    pub method: String,
}

impl PluginAppManager {
    pub fn new() -> Self { ... }
    
    // Axum app management
    pub fn load_axum_app(&self, site_id: &str, plugin_path: &Path, socket_path: Option<PathBuf>) -> Result<AxumAppHandle, AxumPluginError> { ... }
    pub fn reload_axum_app(&self, site_id: &str) -> Result<(), AxumPluginError> { ... }
    pub fn unload_axum_app(&self, site_id: &str) { ... }
    pub fn get_socket_path(&self, site_id: &str) -> Option<PathBuf> { ... }
    
    // WASM filter management  
    pub fn load_wasm_filter(&self, path: &Path) -> Result<Arc<WasmFilter>, WasmPluginError> { ... }
    pub fn apply_filters(&self, request: Request<Bytes>) -> Result<WasmFilterResult, WasmPluginError> { ... }
    
    // Hot reload
    pub fn start_watching(&self, site_id: &str, plugin_path: PathBuf) -> Result<(), AxumPluginError> { ... }
}
```

**Key behaviors**:
- `load_axum_app()`: Loads .so, determines routes, assigns socket path
- `reload_axum_app()`: Re-loads .so, updates router (zero-downtime)
- `unload_axum_app()`: Cleanup on site deactivation

---

### Phase 3: WASM Filter Implementation

**File**: `src/plugin/wasm_runtime.rs`

**Enhancement**: Implement actual filtering using WASI

```rust
use wasmtime::*;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, Stdout};

// Add to WasmRuntime:
pub struct WasmFilter {
    instance: Instance,
    memory: Memory,
    name: String,
}

impl WasmFilter {
    pub fn instantiate(&self, wasi_ctx: WasiCtx) -> Result<WasmInstance, WasmPluginError> { ... }
    
    pub fn filter_request(
        &self,
        request: Request<Bytes>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        // 1. Serialize request to WASM memory
        // 2. Call filter_request export
        // 3. Parse result (block/challenge/pass)
        // 4. Return appropriate result
    }
}

// Host functions exposed to WASM:
mod host_functions {
    #[wasmtime::function]
    pub fn get_header(cx: &mut Caller, name_ptr: i32, name_len: i32) -> i32 { ... }
    
    #[wasmtime::function]
    pub fn set_header(cx: &mut Caller, name_ptr: i32, name_len: i32, value_ptr: i32, value_len: i32) -> i32 { ... }
    
    #[wasmtime::function]
    pub fn get_method(cx: &mut Caller) -> i32 { ... }
    
    #[wasmtime::function]
    pub fn block(cx: &mut Caller, reason_ptr: i32, reason_len: i32) { ... }
    
    #[wasmtime::function]
    pub fn challenge(cx: &mut Caller, challenge_type_ptr: i32, challenge_type_len: i32) { ... }
}
```

**Config extension** (`src/config/plugins.rs`):

```rust
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WasmPluginInstanceConfig {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub max_memory_mb: Option<usize>,
    #[serde(default)]
    pub max_cpu_fuel: Option<u64>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub filter_rules: Vec<WasmFilterRule>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum WasmFilterRule {
    #[serde(rename = "path_prefix")]
    PathPrefix { prefix: String },
    #[serde(rename = "path_regex")]
    PathRegex { pattern: String },
    #[serde(rename = "always")]
    Always,
}
```

---

### Phase 4: Axum App Process Integration

**Purpose**: Actually spawn Axum apps as HTTP servers that the WAF can proxy to

**Two approaches**:

#### Approach A: Spawn as Tokio Task (In-process)

The Axum router runs in the same tokio runtime as the WAF. Simpler, lower latency.

```rust
// In PluginAppManager::load_axum_app
pub fn load_axum_app(&self, site_id: &str, plugin_path: &Path, socket_path: Option<PathBuf>) -> Result<AxumAppHandle, AxumPluginError> {
    let (router, name) = axum_loader::load_plugin(plugin_path)?;
    
    // Determine socket path
    let socket = socket_path.unwrap_or_else(|| {
        PathBuf::from(format!("/run/maluwaf/axum-{}.sock", site_id))
    });
    
    // Start Axum server on Unix socket
    let listener = tokio::net::UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    
    // Clone router for the spawned task
    let router_for_task = router.clone();
    
    // Spawn server task (owns router_for_task)
    tokio::spawn(async move {
        axum::serve(UnixListenerStream::new(listener), router_for_task)
            .await
    });
    
    // Return handle with original router
    Ok(AxumAppHandle {
        router,  // Original router kept in handle
        socket_path: socket,
        plugin_path: plugin_path.to_path_buf(),
        loaded_at: Instant::now(),
        routes: extract_routes(&router),
    })
}
```

#### Approach B: Spawn as Separate Process (Recommended for isolation)

Similar to how FastCGI/PHP-FPM works - separate process that the WAF proxies to.

```rust
pub fn spawn_axum_process(&self, plugin_path: &Path, socket: &Path) -> Result<Child> {
    let mut cmd = std::process::Command::new("axum-runner");
    cmd.arg("--plugin").arg(plugin_path)
       .arg("--socket").arg(socket);
    // ... set up environment, working directory ...
    cmd.spawn()
}
```

**Decision**: Use Approach A (in-process) for simplicity. Can add process spawning later if isolation is needed.

---

### Phase 5: Hot Reload Implementation

**File**: `src/plugin/app_manager.rs`

```rust
impl PluginAppManager {
    pub fn start_watching(&self, site_id: &str, plugin_path: PathBuf) -> Result<(), AxumPluginError> {
        let site_id = site_id.to_string();
        let plugin_path = plugin_path.clone();
        
        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() {
                    // Trigger reload
                    // Use event_tx to notify manager
                }
            }
        })?;
        
        watcher.watch(&plugin_path, RecursiveMode::NonRecursive)?;
        
        self.watchers.write().insert(site_id, watcher);
        Ok(())
    }
    
    pub async fn handle_reload(&self, site_id: &str) -> Result<(), AxumPluginError> {
        let plugin_path = {
            let apps = self.axum_apps.read();
            apps.get(site_id).map(|h| h.plugin_path.clone())
        }?;
        
        let (router, name) = axum_loader::load_plugin(&plugin_path)?;
        
        let mut apps = self.axum_apps.write();
        if let Some(handle) = apps.get_mut(site_id) {
            handle.router = router;
            handle.loaded_at = Instant::now();
        }
        
        Ok(())
    }
}
```

**Configuration option** (`src/config/site.rs`):
```rust
AxumDynamic {
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    socket: Option<String>,
    #[serde(default = "default_true")]
    auto_reload: bool,  // NEW: Enable/disable hot reload
}
```

---

### Phase 4B: WASM Serverless Runtime (Alternative to Axum)

**Purpose**: Allow WASM modules to serve as full HTTP origin servers using WASI-HTTP

**Rationale**: Some use cases prefer WASM's sandboxing and portability over full Axum apps. WASI-HTTP (`wasi:http@0.2.0`) provides a standard interface for HTTP handling in WASM.

**Architecture**:
```
Request → [WASM Filters] → [WASM HTTP Handler] → Response
              │                    │
              ▼                    ▼
         Block/Challenge    WASI-HTTP incoming-handler
                            (via wasmtime-wasi-http)
```

#### WASI-HTTP Integration

**Cargo.toml addition**:
```toml
wasmtime-wasi-http = { version = "36", features = ["component-model-async"] }
```

**WASM module requirements**:
```wit
// wasi:http proxy world
world proxy {
  import wasi:http/incoming-handler;
  export wasi:http/outgoing-handler;
}
```

**Implementation** (`src/plugin/wasm_server.rs` - new file):

```rust
use wasmtime::*;
use wasmtime_wasi_http::WasiHttp;

pub struct WasmServer {
    engine: Engine,
    component: Component,
    instance: wasmtime_wasi_http::WasmHttp,
    socket_path: PathBuf,
}

impl WasmServer {
    pub fn load_wasm(
        module_path: &Path,
        socket_path: PathBuf,
    ) -> Result<Self, WasmPluginError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        
        let engine = Engine::new(&config)?;
        
        // Load as component (WASI-HTTP requires component model)
        let component = Component::from_file(&engine, module_path)?;
        
        // Create WASI-HTTP context
        let mut store = Store::new(&engine, ());
        let wasi_http = WasiHttp::new();
        
        let (instance, _) = wasmtime_wasi_http::instantiate(
            &mut store,
            &component,
            &wasi_http,
        )?;
        
        Ok(Self {
            engine,
            component,
            instance,
            socket_path,
        })
    }
    
    pub fn serve(&self) {
        // Bind to Unix socket and handle incoming HTTP requests
        // Using wasmtime-wasi-http's incoming-handler
    }
}
```

**Config addition** (`src/config/site.rs`):

```rust
#[serde(rename = "wasm-dynamic")]
WasmDynamic {
    #[serde(default)]
    module: Option<String>,      // Path to .wasm file
    #[serde(default)]
    socket: Option<String>,      // Socket path
    #[serde(default = "default_true")]
    auto_reload: bool,
}
```

**Router integration** (`src/router.rs`):

```rust
BackendConfig::WasmDynamic { module, socket, auto_reload } => {
    let socket = socket.unwrap_or_else(|| format!("/run/maluwaf/wasm-{}.sock", site_id));
    let module = module.ok_or_else(|| "WASM module required".to_string())?;
    
    // Load and spawn WASM server
    let server = plugin_app_manager.load_wasm_server(
        &site_id, 
        Path::new(&module),
        PathBuf::from(&socket),
    )?;
    
    return RouteResult::Found(RouteTarget {
        backend_type: BackendType::WasmDynamic,
        backend_socket: Some(Arc::from(socket)),
        // ...
    });
}
```

#### WASM Serverless Handler Interface

The WASM module can use one of:

1. **WASI-HTTP (recommended)** - Standard `wasi:http/incoming-handler` export
2. **Custom handler** - Export a custom `handle_request` function

**Example: WASI-HTTP Rust code**:
```rust
use wasmrs:: incoming_handler;

#[wasmrs::async]
pub async fn handle(
    request: wasmrs::IncomingRequest,
) -> wasmrs::IncomingResponse {
    // Process request
    wasmrs::IncomingResponse::new(
        200,
        vec![("content-type", "text/plain")],
        "Hello from WASM serverless!".bytes(),
    )
}
```

**Example: Custom handler (simpler)**:
```rust
#[no_mangle]
pub extern "C" fn handle_request(
    method_ptr: *const u8,
    method_len: usize,
    uri_ptr: *const u8,
    uri_len: usize,
    body_ptr: *const u8,
    body_len: usize,
) -> i32 {
    // Return response via shared memory or return code
    // 0 = success, negative = error
}
```

#### Comparison: Axum .so vs WASM Serverless

| Aspect | Axum .so | WASM Serverless |
|--------|----------|-----------------|
| Flexibility | Full Rust/Axum ecosystem | Limited to WASI APIs |
| Performance | Native speed | Near-native (JIT) |
| Portability | Platform-specific .so | Cross-platform .wasm |
| Sandboxing | None (same process) | Full WASM sandbox |
| Memory | Unlimited | Configurable limit |
| Startup | Instant (loaded) | Fast (no process) |
| Use case | Complex apps | Simple handlers |

---

### Phase 6: Router Integration

**File**: `src/router.rs`

**Changes**: Wire up the PluginAppManager during route resolution

```rust
// In RouteTarget construction for AxumDynamic
BackendConfig::AxumDynamic { socket, plugin, auto_reload } => {
    let socket = socket.unwrap_or_else(|| format!("/run/maluwaf/axum-{}.sock", site_id));
    let plugin = plugin.unwrap_or_else(|| "/opt/maluwaf/plugins/app.so".to_string());
    
    // NEW: Actually load the plugin via PluginAppManager
    let app_handle = plugin_app_manager.load_axum_app(&site_id, Path::new(&plugin), Some(PathBuf::from(&socket)))?;
    
    // NEW: Start hot reload watcher if enabled
    if auto_reload.unwrap_or(true) {
        plugin_app_manager.start_watching(&site_id, PathBuf::from(&plugin))?;
    }
    
    // NOTE: backend_socket is used by proxy_appserver_request, not upstream
    return RouteResult::Found(RouteTarget {
        site_id: Arc::from(site_id),
        upstream: Arc::from(""),  // Not used for AxumDynamic
        site_config: site_config.clone(),
        static_handler: None,
        backend_type: BackendType::AxumDynamic,
        backend_socket: Some(Arc::from(socket)),  // This is what proxy_appserver_request uses
        backend_plugin: None,
        tunnel_peer: None,
        tunnel_port: None,
    });
}
```

**Also need to add the handler case** (`src/http/handler.rs:984`):
```rust
match target.backend_type {
    BackendType::AppServer => {
        self.proxy_appserver_request(client_ip, target, method, path, body).await
    }
    BackendType::AxumDynamic => {  // ADD THIS CASE
        self.proxy_appserver_request(client_ip, target, method, path, body).await
    }
    // ... rest
}
```

Note: `proxy_appserver_request` already handles Unix sockets via `is_unix_socket_url()` - it extracts the path from `target.backend_socket` (not from `target.upstream`).

---

### Phase 7: Handler Integration

**File**: `src/http/handler.rs`

**Changes**: Add WASM filter application in request pipeline

```rust
// In handle_request - apply WASM filters before WAF rules
async fn handle_request(&self, ...) -> Response<Full<Bytes>> {
    // 1. Apply WASM filters first (they can block before WAF even sees request)
    if let Some(plugin_manager) = &self.plugin_manager {
        for filter in plugin_manager.get_wasm_filters() {
            match filter.filter_request(request.clone())? {
                WasmFilterResult::Block(status, msg) => {
                    return error_response(status, msg);
                }
                WasmFilterResult::Challenge(c) => {
                    return self.serve_challenge(c).await;
                }
                WasmFilterResult::Pass => continue,
            }
        }
    }
    
    // 2. Continue with existing WAF processing...
}
```

**Add to RequestHandler struct** (note: struct is `RequestHandler` not `HttpHandler`):
```rust
pub struct RequestHandler {
    // ... existing fields ...
    plugin_manager: Option<Arc<PluginAppManager>>,  // NEW
}
```

And in the `new()` constructor, add the plugin_manager parameter and initialization.

---

### Phase 8: Config Schema Updates

**File**: `src/config/site.rs`

```rust
#[serde(rename = "axum-dynamic")]
AxumDynamic {
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    socket: Option<String>,
    #[serde(default = "default_true")]
    auto_reload: bool,  // NEW
}
```

**File**: `src/config/main.rs`

Add plugin config to MainConfig:

```rust
pub struct MainConfig {
    // ... existing fields ...
    pub plugins: PluginConfig,  // NEW - already defined in config/plugins.rs
}
```

---

### Phase 9: Update Example Plugin

**File**: `examples/dynamic-plugin-example/src/lib.rs`

**Critical fix required**: The example exports `rustwaf_abi_version` but `axum_loader.rs:110` looks for `maluwaf_abi_version`. This will cause plugin loading to fail.

```rust
// CURRENT (broken):
#[no_mangle]
pub static rustwaf_abi_version: AbiVersion = ...

// MUST CHANGE TO:
#[no_mangle]
pub static maluwaf_abi_version: AbiVersion = ...
```

The example should also be updated to demonstrate:
- More complex routes
- Request/response modification
- Integration with WAF context

---

## Detailed Implementation Order

| # | Phase | Task | Files Changed | Effort |
|---|-------|------|---------------|--------|
| 1 | Bug Fix | Fix load_axum_plugin router discard | `src/plugin/mod.rs` | Small |
| 2 | New Component | Create PluginAppManager | `src/plugin/app_manager.rs` (new) | Medium |
| 3 | Config | Add auto_reload to AxumDynamic + WasmDynamic | `src/config/site.rs` | Small |
| 4 | Router | Wire up PluginAppManager for Axum | `src/router.rs` | Medium |
| 5 | Handler | Add plugin_manager to RequestHandler | `src/http/handler.rs` | Medium |
| 6 | WASM Filters | Implement WASM filter functions | `src/plugin/wasm_runtime.rs` | Large |
| 7 | WASM Serverless | Add wasm-dynamic backend with WASI-HTTP | `src/plugin/wasm_server.rs` (new) | Large |
| 8 | Hot Reload | Add file watching | `src/plugin/app_manager.rs` | Medium |
| 9 | Config Main | Add plugins to MainConfig | `src/config/main.rs` | Small |
| 10 | Example | Fix ABI version name | `examples/dynamic-plugin-example/src/lib.rs` | Small |
| 11 | Testing | Integration tests | `tests/integration_test.rs` | Medium |

---

## Key Technical Decisions

### 1. In-process vs Separate Process for Axum Apps

**Decision**: In-process (tokio spawn) initially

**Rationale**:
- Lower latency (no inter-process overhead)
- Simpler lifecycle management
- Can evolve to separate process later if needed

### 2. WASM ABI (WASI vs Custom)

**Decision**: WASI (wasmtime-wasi)

**Rationale**:
- Standardized interface
- Better sandboxing (filesystem, network)
- Future-proof for potential guest execution

### 3. Hot Reload Strategy

**Decision**: notify crate with in-process swap

**Rationale**:
- Zero-downtime: new requests use new router
- Simple: no external file synchronization needed
- Works for in-process spawning

### 4. Socket Path Management

**Decision**: Auto-generate based on site_id

**Format**: `/run/maluwaf/axum-{site_id}.sock`

**Rationale**:
- Predictable, debuggable
- Doesn't conflict between sites
- Configurable override available

---

## Backward Compatibility

1. **Config**: Adding `auto_reload` with default `true` is backward compatible (existing configs work)

2. **ABI Version**: The `maluwaf_abi_version` symbol name is already established - don't change it

3. **Router Path**: Existing code that relied on `backend_plugin` in RouteTarget will need update

4. **WASM Filters**: Existing stub code will start actually filtering - may need to disable via config for existing deployments

---

## Testing Strategy

### Unit Tests
- PluginAppManager lifecycle (load/unload/reload)
- WASM filter serialization/deserialization
- Route extraction from Axum router

### Integration Tests
- End-to-end: Request → WASM filter → Axum app → Response
- Hot reload: Modify .so, verify reload
- Config: Load AxumDynamic config, verify socket created

### Example Tests
- Compile and load dynamic-plugin-example
- Verify routes work through WAF

---

## Dependencies Added

```toml
# Cargo.toml additions

# Hot reload (already in tree)
notify = "6"

# WASM sandbox and filters (already in tree)
wasmtime = "36"
wasmtime-wasi = "36"

# WASM serverless HTTP handling (NEW - needed for Phase 4B)
wasmtime-wasi-http = { version = "36", features = ["component-model-async"] }
```

---

## Open Questions

1. **WASM filters vs WASM serverless priority?**
   - Current: Filters first (Phase 3), Serverless second (Phase 4B)
   - Alternative: Combine both in single implementation

2. **Should WASM filters run before or after WAF rules?** 
   - Current plan: Before (can block before WAF inspection)
   - Alternative: After (complements WAF rules)

3. **Multiple Axum apps per site?**
   - Current plan: One app per site (simplified)
   - Could extend to multiple for microservice patterns

4. **Authentication between WAF and Axum app?**
   - Current plan: Unix socket permissions only
   - Could add token validation in future

5. **WASM serverless: WASI-HTTP vs custom handler?**
   - Current plan: WASI-HTTP (standard, future-proof)
   - Alternative: Custom simpler ABI (faster to implement)

---

## Summary

This plan transforms the plugin system from stub/unused to functional:

1. Fix critical bug in PluginManager
2. Create PluginAppManager for lifecycle management
3. Implement actual WASM filtering with WASI
4. Add WASM serverless runtime with WASI-HTTP
5. Wire Axum apps into routing/proxy pipeline
6. Add hot-reload capability
7. Update config schema and examples

The result is a unified system where:
- **WASM filters** provide request/response transformation (Phase 3)
- **WASM serverless** can serve as full origin servers (Phase 4B)
- **Axum .so plugins** serve as full origin servers (Phase 4)
- All integrate naturally into the existing WAF request flow

**User has two serverless options:**
1. **Axum .so** - Full Rust/Axum flexibility, best for complex apps
2. **WASM serverless** - Portable, sandboxed, best for simple handlers