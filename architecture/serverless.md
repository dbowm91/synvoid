# Serverless Module Architecture

## 1. Purpose and Responsibility

The Serverless module provides a **WASM-based serverless function execution platform** for the SynVoid proxy. It enables dynamic request handling through user-defined WASM functions that can process HTTP requests, apply filters, transform responses, and integrate with the mesh network for distributed execution.

**Core responsibilities:**
- Load and manage WASM-based serverless functions
- Provide low-latency function invocation with instance pooling
- Handle cold-start optimization through pre-warmed instances
- Route requests to appropriate functions based on path/method matching
- Integrate with the DHT (mesh feature) for distributed function lookup
- Enforce resource limits (memory, CPU fuel, timeouts) for sandboxed execution
- Support event-driven function invocations

## 2. Key Submodules and Their Responsibilities

### `serverless/` - Core Serverless Module

| File | Responsibility |
|------|----------------|
| `mod.rs` | Public exports for the serverless module |
| `manager.rs` | Central `ServerlessManager` - function lifecycle, invocation routing, mesh integration |
| `instance_pool.rs` | `InstancePool` - manages pre-warmed WASM instances with autoscaling |
| `async_compilation.rs` | `AsyncCompilationHandle/Manager` - async WASM compilation tracking |
| `registry.rs` | `ServerlessRegistry` - global function metadata and invocation statistics |
| `routing.rs` | `ServerlessRoute` - route matching (exact, prefix, suffix, regex, glob) |
| `scheduler.rs` | `ServerlessScheduler` - timer-based event scheduling for periodic function invocations |

### `plugin/` - WASM Plugin Runtime

| File | Responsibility |
|------|----------------|
| `mod.rs` | `PluginManager` for WASM/Axum plugins, lifecycle management with hot-reload |
| `wasm_runtime.rs` | `WasmRuntime` and `WasmPluginManager` - wasmtime-based execution engine |
| `instance_pool.rs` | `WasmInstancePool` - low-level WASM instance pooling for filters |
| `pool.rs` | `PooledInstance` and `WasmPool` trait - abstraction for instance pooling |
| `axum_loader.rs` | Native Axum plugin loader (separate from WASM) |
| `global.rs` | Global `PluginManager` singleton |
| `wasm_metrics.rs` | Prometheus metrics for WASM execution |

## 3. Major Data Structures and Types

### Serverless Core Types

```rust
// src/serverless/manager.rs

// Caller context for mesh-distributed invocations
pub struct CallerContext {
    pub node_id: String,
    #[cfg(feature = "mesh")]
    pub role: MeshNodeRole,
    pub org_id: Option<String>,
    pub tier: Option<u32>,
    pub is_local: bool,
}

// Represents a loaded serverless function
pub struct ServerlessFunction {
    pub definition: FunctionDefinition,       // Config definition
    pub runtime: Option<Arc<WasmRuntime>>,     // Compiled WASM runtime
    pub compilation_handle: Option<Arc<AsyncCompilationHandle>>,
}

// Response from serverless function execution
pub struct ServerlessResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub function_name: String,
    pub execution_time_ms: u64,
}

// Error types for serverless operations
pub enum ServerlessError {
    FunctionNotFound(String),
    WASMRuntimeError(String),
    ExecutionError(String),
    NoConfig,
    Disabled,
    NoMatchingRoute(String),
    RemoteExecutionRequired(String),
    PermissionDenied(String),
    CompilationInProgress(String),
    CompilationFailed(String),
}
```

### Instance Pool Types

```rust
// src/serverless/instance_pool.rs

// Configuration for instance pool behavior
pub struct InstancePoolConfig {
    pub min_instances: usize,              // Minimum pool size
    pub max_instances: usize,             // Maximum pool size
    pub idle_timeout_seconds: u64,        // Idle timeout before eviction
    pub scale_up_threshold: f64,         // Utilization threshold to scale up
    pub scale_down_threshold: f64,        // Utilization threshold to scale down
    pub scale_up_cooldown_seconds: u64,    // Cooldown between scale-up events
    pub scale_down_cooldown_seconds: u64, // Cooldown between scale-down events
    pub pre_warm_instances: usize,        // Instances to pre-warm at startup
    pub max_scale_up_per_tick: usize,     // Max instances to add per autoscaler tick
}

// A single serverless instance wrapper
pub struct ServerlessInstance {
    pub id: String,                      // Unique instance ID
    pub function_name: String,
    pub instance: Arc<WasmRuntime>,       // The WASM runtime handle
    pub metrics: RwLock<InstanceMetrics>, // Per-instance metrics
    pub created_at: Instant,
    pub state: RwLock<InstanceState>,     // Initializing/Ready/Busy/Evicted
}

// Instance pool operational mode
pub enum InstancePoolMode {
    Pool,     // Use pooled instances (default)
    Direct,   // Direct instantiation per request
    Hybrid,   // Mix of pooled and direct
}

// Per-instance execution metrics
pub struct InstanceMetrics {
    pub requests_handled: u64,
    pub total_duration_ms: u64,
    pub last_used: Instant,
    pub is_idle: bool,
    pub cold_starts: u64,
    pub last_cold_start_time: Option<Instant>,
    pub last_cold_start_duration_ms: u64,
}
```

### Routing Types

```rust
// src/serverless/routing.rs

// Path matching strategies
pub enum RouteMatch {
    Exact(String),           // Exact path match
    Prefix(String),         // Prefix match (e.g., /api/*)
    Suffix(String),         // Suffix match (e.g., *.json)
    Regex { pattern: String, compiled: Option<Arc<Regex>> },
    Glob(String),           // Glob pattern (supports **)
}

// HTTP method matching
pub enum MethodMatch {
    Any,                     // Any method
    Specific(Method),        // Specific HTTP method
    Multiple(Vec<Method>),   // Multiple allowed methods
}

// A serverless route entry
pub struct ServerlessRoute {
    pub matcher: RouteMatch,
    pub method: MethodMatch,
    pub priority: i32,       // Higher priority evaluated first
    pub function_name: String,
}
```

### Registry Types

```rust
// src/serverless/registry.rs

// Global registry singleton
pub fn get_global_serverless_registry() -> Arc<ServerlessRegistry>;

// Per-function metadata
pub struct FunctionMetadata {
    pub name: String,
    pub description: Option<String>,
    pub route_count: usize,
    pub allowed_methods: Vec<String>,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub registered_at: Instant,
    pub last_invoked: Option<Instant>,
    pub invocation_count: u64,
    pub error_count: u64,
}

// Per-function statistics
pub struct FunctionStats {
    pub invocation_count: u64,
    pub error_count: u64,
    pub avg_errors_per_invocation: f64,
}

// Global registry API
impl ServerlessRegistry {
    pub fn register(&self, def: &FunctionDefinition);
    pub fn unregister(&self, name: &str) -> bool;
    pub fn get(&self, name: &str) -> Option<FunctionMetadata>;
    pub fn list(&self) -> Vec<FunctionMetadata>;
    pub fn record_invocation(&self, name: &str);
    pub fn record_error(&self, name: &str);
    pub fn get_stats(&self, name: &str) -> Option<FunctionStats>;
}
```

### WASM Runtime Types

```rust
// src/plugin/wasm_runtime.rs

// Resource limits for WASM execution sandbox
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,           // Max memory in MB
    pub max_table_elements: Option<usize>,
    pub max_cpu_fuel: u64,              // CPU fuel budget (execution units)
    pub timeout_seconds: u64,           // Wall-clock timeout
    pub max_instances: usize,           // Max concurrent instances
    pub memory_budget_mb: Option<usize>,
    pub wasi_enabled: bool,             // WASI support flag
    pub allowed_dht_prefixes: Vec<String>, // DHT key prefixes allowed from WASM
}

// Per-request context passed to WASM store
pub(crate) struct RequestContext {
    pub(crate) start: Instant,          // Request start time
    pub(crate) timeout: Duration,       // Per-request timeout
    pub(crate) env: HashMap<String, String>,  // Environment variables
    pub(crate) allowed_dht_prefixes: Vec<String>,
    pub(crate) max_memory: usize,
    pub(crate) max_table_elements: usize,
    pub(crate) body_receiver: Option<tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>>,
}

// Resolved guest ABI function handles
pub(crate) struct GuestExports {
    pub(crate) filter_request: Option<FilterRequestFn>,
    pub(crate) transform_response: Option<TransformResponseFn>,
    pub(crate) handle_request: Option<HandleRequestFn>,
    pub(crate) guest_alloc: Option<GuestAllocFn>,
    pub(crate) guest_free: Option<GuestFreeFn>,
    pub(crate) memory: Option<Memory>,
}
```

### Plugin Manager Types

```rust
// src/plugin/mod.rs

// Result of a WASM filter execution
pub enum WasmFilterResult {
    Pass,                           // Request passes through
    Block(StatusCode, String),      // Request blocked
    Challenge(String),              // Challenge required
}

// WASM plugin errors
pub enum WasmPluginError {
    LoadFailed(String),
    FunctionNotFound(String),
    ExecutionFailed(String),
    SandboxError(String),
}

// Manages WASM and Axum plugins with lifecycle support
pub struct PluginManager {
    wasm_manager: Arc<WasmPluginManager>,
    axum_plugins: RwLock<Vec<Arc<AxumPluginWrapper>>>,
}

// Plugin lifecycle manager with hot-reload support
pub struct PluginManagerLifecycle {
    plugin_manager: Arc<PluginManager>,
    watch_dir: Option<PathBuf>,
    _watcher: Option<RecommendedWatcher>,
    plugin_dir: Option<PathBuf>,
}
```

## 4. Key APIs and Entry Points

### ServerlessManager (src/serverless/manager.rs)

```rust
impl ServerlessManager {
    /// Create a new ServerlessManager
    pub fn new() -> Self;

    /// Configure with a custom WASM runtime
    pub fn with_runtime(mut self, runtime: Arc<WasmPluginManager>) -> Self;

    /// Initialize from configuration - loads all functions
    pub fn initialize(&self, config: ServerlessConfig) -> Result<(), ServerlessError>;

    /// Check if serverless is enabled
    pub fn is_enabled(&self) -> bool;

    /// Get a function by name
    pub fn get_function(&self, name: &str) -> Option<ServerlessFunction>;

    /// Get all registered functions
    pub fn get_all_functions(&self) -> HashMap<String, ServerlessFunction>;

    /// Find function by path (simple matching)
    pub fn find_matching_function(&self, path: &str) -> Option<ServerlessFunction>;

    /// Find function and route by path and method
    pub fn find_matching_route(&self, path: &str, method: &Method)
        -> Option<(ServerlessFunction, ServerlessRoute)>;

    /// Get compilation status for a function
    pub fn get_compilation_status(&self, function_name: &str) -> Option<CompilationState>;

    /// Subscribe function to an event topic
    pub fn subscribe_to_event(&self, function_name: &str, topic: String);

    /// Unsubscribe from event topic
    pub fn unsubscribe_from_event(&self, function_name: &str, topic: &str);

    /// Publish event to subscribers
    pub fn publish_event(&self, topic: &str, payload: &[u8]);

    /// Graceful shutdown of all instance pools
    pub async fn shutdown(&self);

    // Mesh-only methods (requires feature="mesh")
    #[cfg(feature = "mesh")]
    pub fn set_record_store(&self, store: Arc<RecordStoreManager>);
    #[cfg(feature = "mesh")]
    pub fn set_routing_manager(&self, manager: Arc<HierarchicalRoutingManager>);
    #[cfg(feature = "mesh")]
    pub fn set_org_manager(&self, manager: Arc<OrganizationManager>);
    #[cfg(feature = "mesh")]
    pub fn set_revocation_list(&self, list: Arc<GlobalNodeRevocationList>);
    #[cfg(feature = "mesh")]
    pub fn set_transport(&self, transport: Arc<MeshTransport>);
    #[cfg(feature = "mesh")]
    pub fn verify_caller_permission(&self, function_name: &str, ...) -> Result<(), ServerlessError>;
}
```

### handle_serverless_function (mesh-only entry point)

**Note:** This function is only exported when `#[cfg(feature = "mesh")]`.

```rust
// src/serverless/manager.rs:1049
#[cfg(feature = "mesh")]
pub async fn handle_serverless_function(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    caller: CallerContext,
) -> Result<Response<Bytes>, ServerlessError>;
```

### Streaming Variant (handle_serverless_function_streaming)

For streaming request bodies, use the streaming variant:

```rust
// src/serverless/manager.rs:1224
#[cfg(feature = "mesh")]
pub async fn handle_serverless_function_streaming(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Box<dyn ErasedBody>,
    caller: CallerContext,
) -> Result<Response<Bytes>, ServerlessError>;
```

This variant accepts a `Box<dyn ErasedBody>` for streaming body chunks via `synvoid_read_body_chunk()` host function.

### InstancePool (src/serverless/instance_pool.rs)

```rust
impl InstancePool {
    /// Create new instance pool for a function
    pub fn new(config: InstancePoolConfig, function_definition: FunctionDefinition)
        -> Result<Self, InstancePoolError>;

    /// Pre-warm instances (called at startup)
    pub async fn initialize(&self) -> Result<(), InstancePoolError>;

    /// Get an instance from the pool (blocking)
    pub async fn get_instance(&self) -> Result<Arc<ServerlessInstance>, InstancePoolError>;

    /// Return instance to the pool
    pub fn return_instance(&self, instance_id: &str);

    /// Manually scale up instances
    pub async fn scale_up(&self, count: usize) -> Result<(), InstancePoolError>;

    /// Manually scale down instances
    pub async fn scale_down(&self, count: usize) -> Result<(), InstancePoolError>;

    /// Start the autoscaler background task
    pub async fn run_autoscaler(&self);

    /// Graceful shutdown with timeout
    pub async fn shutdown(&self, timeout_secs: u64);

    /// Get current metrics
    pub fn get_metrics(&self) -> InstancePoolMetrics;

    /// Health check for pool
    pub fn check_health(&self) -> PoolHealth;

    // Accessors
    pub fn get_instance_count(&self) -> usize;
    pub fn get_idle_count(&self) -> usize;
    pub fn get_active_count(&self) -> usize;
    pub fn get_mode(&self) -> InstancePoolMode;
    pub fn set_mode(&self, mode: InstancePoolMode);
    pub fn get_utilization(&self) -> f64;
}
```

### WasmRuntime (src/plugin/wasm_runtime.rs)

```rust
impl WasmRuntime {
    /// Load WASM module from file
    pub fn load(path: &Path, limits: WasmResourceLimits) -> Result<Self, WasmPluginError>;

    /// Load WASM module from bytes
    pub fn load_from_bytes(name: &str, bytes: &[u8], limits: WasmResourceLimits)
        -> Result<Self, WasmPluginError>;

    /// Load with priority for execution ordering
    pub fn load_with_priority(path: &Path, limits: WasmResourceLimits, priority: i32)
        -> Result<Self, WasmPluginError>;

    /// Filter request (for WAF-style plugins)
    pub fn filter_request(&self, request: Request<Bytes>, env: Arc<HashMap<String, String>>)
        -> Result<WasmFilterResult, WasmPluginError>;

    /// Transform response
    pub fn transform_response(&self, response: Response<Bytes>, env: Arc<HashMap<String, String>>)
        -> Result<Response<Bytes>, WasmPluginError>;

    /// Handle request (serverless function invocation)
    pub fn invoke_handler(&self, method: &str, uri: &str, headers: &str, body: &[u8],
        env: HashMap<String, String>) -> Result<Response<Bytes>, WasmPluginError>;

    /// Streaming request handler
    pub fn invoke_handler_streaming(&self, method: &str, uri: &str, headers: &str,
        body: Box<dyn ErasedBody>, env: HashMap<String, String>)
        -> Result<Response<Bytes>, WasmPluginError>;
}
```

### PluginManager (src/plugin/mod.rs)

```rust
impl PluginManager {
    pub fn new() -> Self;
    pub fn with_wasm_limits(limits: WasmResourceLimits) -> Self;

    /// Load WASM plugin from path
    pub fn load_wasm_plugin(&self, path: &Path) -> Result<(), WasmPluginError>;

    /// Load Axum plugin (.so/.dylib) from path
    pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, AxumPluginError>;

    /// Apply WASM filters to request
    pub fn apply_wasm_filters(&self, request: Request<Bytes>, env: HashMap<String, String>)
        -> Result<WasmFilterResult, WasmPluginError>;

    /// Apply WASM filters to specific plugins only
    pub fn apply_wasm_filters_with_plugins(&self, request: Request<Bytes>,
        plugin_names: &[String], env: HashMap<String, String>)
        -> Result<WasmFilterResult, WasmPluginError>;

    /// Transform response through WASM plugins
    pub fn apply_wasm_response_transforms(&self, response: Response<Bytes>, env: HashMap<String, String>)
        -> Result<Response<Bytes>, WasmPluginError>;

    pub fn wasm_manager(&self) -> &Arc<WasmPluginManager>;
}

impl PluginManagerLifecycle {
    pub fn new(plugin_manager: Arc<PluginManager>) -> Self;

    /// Load all plugins from directory
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, WasmPluginError>;

    /// Load all Axum plugins from directory
    pub fn load_axum_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, AxumPluginError>;

    /// Enable hot-reload file watching
    pub fn enable_hot_reload(&mut self, dir: &Path) -> Result<(), String>;

    /// Reload specific plugin
    pub fn reload_plugin(&self, path: &Path) -> Result<(), WasmPluginError>;

    /// Shutdown and cleanup
    pub fn shutdown(&self);
}
```

## 5. How WASM Function Execution Works

### Execution Flow

```
HTTP Request
    |
    v
ServerlessManager::find_matching_route()
    |  (matches path + method to ServerlessRoute)
    v
handle_serverless_function()
    |
    |- Verify caller permissions (mesh mode)
    |
    |- Get instance from InstancePool::get_instance()
    |       |
    |       |- Try idle_instances.pop()
    |       |
    |       `- If empty, scale_up() to create new instance
    |
    v
instance.invoke_handler(method, uri, headers_json, body, env)
    |
    |- WasmRuntime::invoke_handler()
    |       |
    |       |- create_store(env)  -> RequestContext with limits
    |       |
    |       |- instantiate()      -> Link module + resolve exports
    |       |
    |       |- write_to_guest_memory()
    |       |       |- guest_alloc() or fallback to offset 1024
    |       |       `- Copy serialized headers + body to WASM memory
    |       |
    |       |- handle_request.call()  -> Execute WASM guest function
    |       |
    |       |- Read output (status_code + body) from WASM memory
    |       |
    |       `- free_guest_memory() if guest_free available
    |
    v
Return instance to pool: pool.return_instance(instance_id)
    |
    |- If idle_duration > idle_timeout_seconds: evict
    `- Else: mark_idle() and push to idle_instances
```

### Guest ABI (WASM Plugin Interface)

A valid serverless WASM module must export one or more of these functions:

```rust
// filter_request - WAF-style request filtering
// Returns: 0=Pass, 1=Block, 2=Challenge, -1=Error
type FilterRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32), i32>;
// Args: (method_ptr, method_len, uri_ptr, uri_len, headers_ptr, headers_len, body_ptr, body_len)

// transform_response - Response transformation
// Returns: new body length, or -1 on error
type TransformResponseFn = TypedFunc<(i32, i32, i32, i32, i32), i32>;
// Args: (status_code, body_ptr, body_len, out_ptr, out_max)

// handle_request - Serverless function handler
// Returns: 0=success, -1=error; writes status/body to out_ptr
type HandleRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>;
// Args: (method_ptr, ..., body_ptr, body_len, out_status_ptr, out_body_ptr, out_body_max)

// Guest memory management (optional but recommended)
type GuestAllocFn = TypedFunc<i32, i32>;       // Allocate guest memory
type GuestFreeFn = TypedFunc<(i32, i32), ()>;  // Free guest memory
```

### Header Serialization Format

Headers are serialized to **JSON** for serverless/Spin WASM modules:

```json
{"header_name": "value", ...}
```

**Note**: Generic WASM plugins (via `WasmRuntime`) use a compact binary format:
```
[header_count: u16]
[for each header:]
  [name_len: u16][name bytes][value_len: u16][value bytes]
```

This distinction exists because Spin and serverless use `SpinHttpHandler` which calls `SpinRuntime::serialize_headers_spin()` returning JSON, while generic WASM filters use `WasmRuntime::serialize_headers()` returning binary.

### Host Functions (WASM guest can call)

```rust
// Memory access
"env", "guest_alloc"    // Allocate memory in guest
"env", "guest_free"     // Free allocated memory
"env", "get_env"        // Read environment variable

// Streaming body support
"env", "synvoid_read_body_chunk"  // Read next body chunk (streaming mode)

// Mesh integration
"env", "mesh_query_dht"    // Query DHT (with prefix restrictions)
"env", "mesh_check_threat" // Check IP threat status
"env", "mesh_emit_event"   // Emit event to mesh

// Utility
"env", "check_timeout"     // Check if request timed out
"env", "abort"            // Abort with message
```

### DHT Access Control

The `allowed_dht_prefixes` in `WasmResourceLimits` restricts what DHT keys a WASM module can query:

```rust
// Sensitive prefixes are blocked unless explicitly allowed
let sensitive_prefixes = [
    "threat_indicator:",
    "yara_rule:",
    "yara_rules_manifest:",
    "edge_attestation:",
    "dns_zone:",
    "dns_record:",
    "dns_domain_reg:",
];
```

## 6. Instance Pooling for Cold-Start Optimization

### Architecture

```
                          InstancePool
  +------------------+  +------------------+  +------------------+
  |    Instance 1    |  |    Instance 2    |  |    Instance N    |
  |      (idle)      |  |      (busy)      |  |      (idle)      |
  +------------------+  +------------------+  +------------------+

  active_instances: HashMap<String, Arc<ServerlessInstance>>
  idle_instances: Vec<Arc<ServerlessInstance>>
```

### Global Engine Pool

```rust
// instance_pool.rs:103-105
static SERVERLESS_ENGINE_POOL: LazyLock<RwLock<HashMap<String, Arc<WasmPluginManager>>>>
```

Keyed by `"function_name:memory_mb"` to share engines for functions with same memory configuration.

### Lifecycle States

```
Initializing --> Ready --> Busy --> Idle --> Evicted
                      ^        |
                      +--------+
```

### Pre-warming at Startup

```rust
// InstancePool::initialize()
pub async fn initialize(&self) -> Result<(), InstancePoolError> {
    let min_to_create = self.config.pre_warm_instances.min(self.config.max_instances);
    for i in 0..min_to_create {
        let instance = self.spawn_instance(...)?;
        instance.mark_ready();
        self.instances.push(instance);
        self.idle_instances.push(instance);
    }
}
```

### Autoscaler Background Task

```rust
// InstancePool::run_autoscaler() - runs every 10 seconds
loop {
    let utilization = self.get_utilization();

    if utilization >= scale_up_threshold {
        // Scale up: add 50% of current count, max 5 per tick
        let to_add = ((current * 0.5) as usize).max(1).min(max_scale_up_per_tick);
        self.scale_up(to_add).await?;
    } else if utilization <= scale_down_threshold {
        // Scale down: remove 30% of current count
        let to_remove = ((current * 0.3) as usize).max(1);
        self.scale_down(to_remove).await?;
    }

    self.evict_idle_instances();  // Remove instances idle > timeout
}
```

### Metrics Tracked Per Instance

- `requests_handled` - Total requests processed
- `total_duration_ms` - Cumulative execution time
- `last_used` - Last request timestamp
- `cold_starts` - Number of cold starts
- `last_cold_start_duration_ms` - Duration of last cold start

## 7. Plugin Sandboxing

### Resource Limiting

```rust
// RequestContext implements ResourceLimiter for wasmtime
impl ResourceLimiter for RequestContext {
    fn memory_growing(&mut self, current: usize, desired: usize, maximum: Option<usize>)
        -> Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_memory)  // Enforce max_memory_mb limit
    }

    fn table_growing(&mut self, current: usize, desired: usize, maximum: Option<usize>)
        -> Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_table_elements)
    }
}
```

### CPU Fuel

```rust
// Enable fuel consumption in engine config
config.consume_fuel(true);

// Set fuel budget per store
store.set_fuel(limits.max_cpu_fuel).ok();

// Track consumption
if let Ok(remaining) = store.get_fuel() {
    let consumed = limits.max_cpu_fuel.saturating_sub(remaining);
    record_wasm_fuel_consumed(plugin_name, consumed);
}
```

### Execution Timeout

```rust
// Per-request timeout tracked via start + duration check
pub(crate) struct RequestContext {
    start: Instant,
    timeout: Duration,
    // ...
}

// check_timeout() called before/after WASM execution
fn check_timeout(store: &Store<RequestContext>) -> Result<(), WasmPluginError> {
    let elapsed = store.data().start.elapsed();
    if elapsed > store.data().timeout {
        return Err(WasmPluginError::ExecutionFailed("WASM execution timed out"));
    }
    Ok(())
}
```

### Memory Bounds Checking

```rust
// write_to_guest_memory enforces MAX_WASM_DATA_SIZE (1MB)
const MAX_WASM_DATA_SIZE: usize = 1024 * 1024;

fn write_to_guest_memory(&self, store: &mut Store<RequestContext>, exports: &GuestExports, data: &[u8]) {
    if data.len() > MAX_WASM_DATA_SIZE {
        return Err(WasmPluginError::SandboxError("data size exceeds max"));
    }

    // Before write: check if memory growth needed
    let end = (ptr as usize) + data.len();
    if end > mem_size {
        // Try to grow, but respect max_memory limit
        memory.grow(&mut *store, pages_needed as u64)?;
    }
}
```

### Linker Security

Host function imports use strict typing and validation:

```rust
// All host functions wrapped with error handling
linker.func_wrap("env", "check_timeout", |caller: wasmtime::Caller<'_, RequestContext>| -> i32 {
    let elapsed = caller.data().start.elapsed();
    if elapsed > caller.data().timeout { 1 } else { 0 }
}).map_err(|e| WasmPluginError::LoadFailed(...))?;

// DHT access validated against sensitive prefix list
linker.func_wrap("env", "mesh_query_dht", |mut caller: wasmtime::Caller<'_, RequestContext>, ...| {
    // Check prefix before query
    let is_explicitly_allowed = caller.data().allowed_dht_prefixes.iter().any(|p| key.starts_with(p));
    if is_sensitive && !is_explicitly_allowed {
        return -2;  // Unauthorized
    }
    // ...
});
```

## 8. Feature Gates

### `mesh` Feature

When `--features mesh` is enabled:

| Component | Behavior |
|-----------|----------|
| `ServerlessManager` | Integrates with DHT for function registration/lookup |
| `CallerContext` | Includes `MeshNodeRole` field |
| `handle_serverless_function` | Can route to remote mesh nodes if function not local |
| `WasmRuntime::load_from_bytes_with_priority` | Can load from mesh WASM distribution manager |
| `mesh_query_dht` host function | Queries actual DHT record store |
| `mesh_check_threat` host function | Checks threat_indicator DHT records |
| `mesh_emit_event` host function | Stores events in DHT |
| Function registration | Announced to DHT via `record_store.store_and_announce()` |

### Default Compilation

Without `mesh` feature:

```rust
#[cfg(not(feature = "mesh"))]
pub use manager::{CallerContext, ServerlessError, ServerlessFunction, ServerlessManager};
```

The serverless module compiles and functions without mesh, but:
- DHT integration is disabled
- `CallerContext` lacks `role` field
- Remote execution via DHT not available
- Mesh host functions return 0/null

## 9. Configuration Schema

```rust
// From crates/synvoid-config/src/serverless.rs (implied structure)

pub struct ServerlessConfig {
    pub enabled: bool,
    pub default_memory_mb: usize,      // Default: 64
    pub default_cpu_fuel: u64,          // Default: 1,000,000
    pub default_timeout_seconds: u64,    // Default: 30
    pub functions: Vec<FunctionDefinition>,
}

pub struct FunctionDefinition {
    pub name: String,
    pub path: Option<String>,          // Simple path matching
    pub routes: Option<Vec<String>>,    // Advanced route definitions
    pub allowed_methods: Option<Vec<String>>,
    pub memory_mb: Option<usize>,
    pub cpu_fuel: Option<u64>,
    pub timeout_seconds: Option<u64>,
    pub min_instances: Option<usize>,
    pub max_instances: Option<usize>,
    pub idle_timeout_seconds: Option<u64>,
    pub pre_warm_instances: Option<usize>,
    pub env: HashMap<String, String>,
    pub public_function: Option<bool>,   // Allow public access without mesh auth
    pub require_trusted_caller: Option<bool>,
    pub allowed_callers: Option<Vec<String>>,
    pub allowed_orgs: Option<Vec<String>>,
    pub min_tier_level: Option<u32>,
    pub allowed_dht_prefixes: Option<Vec<String>>,
}
```

## 10. Usage Example

```rust
// Initialize serverless from config
let manager = ServerlessManager::new();
manager.initialize(config)?;

// Handle incoming HTTP request
let response = handle_serverless_function(
    &manager,
    &Method::POST,
    "/api/my-function",
    &request.headers(),
    Some(request.into_body()),
    CallerContext::local(),
).await?;

// Publish event to subscribed functions
manager.publish_event("user.created", &event_payload);

// Get function stats
let stats = get_global_serverless_registry().get_stats("my-function");
```

## 11. Relationship to Plugin System

The serverless module **extends** the plugin system:

```
Plugin System                    Serverless System
----------------                -----------------
WasmPluginManager    <-------->  WasmRuntime (shared)
     |                           |
     |-- filter_request()        |-- invoke_handler() (serverless entry)
     |-- transform_response()    |
     `-- apply_wasm_filters()    |
                                  |
                                  `-- InstancePool (manages serverless instances)
                                       |
                                       `-- Pre-warmed + autoscaled
```

- `WasmRuntime` is shared between plugin filtering and serverless invocation
- Serverless uses `InstancePool` for pooling; plugins use `WasmInstancePool` directly
- Both share the same wasmtime engine and linker configuration
- Serverless adds `handle_request` export support (plugins may not have it)

## 12. Thread Safety

- `ServerlessManager` uses `parking_lot::RwLock` for all internal state
- `InstancePool` uses `parking_lot::RwLock` for instance tracking
- `WasmPluginManager` uses `parking_lot::RwLock` for runtime collection
- Async operations use tokio synchronization (oneshot channels, watch)
- `AsyncCompilationManager` uses `std::sync::RwLock` (sync context)

## 13. Dependencies

- **wasmtime** - WASM runtime engine (pure Rust)
- **tokio** - Async runtime for instance pool operations
- **http** - HTTP types for request/response
- **bytes** - Efficient byte handling
- **parking_lot** - FastRwLock for internal state
- **uuid** - Instance ID generation
