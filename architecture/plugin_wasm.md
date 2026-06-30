# Plugin/WASM Module Architecture

## 1. Purpose and Responsibility

The Plugin/WASM module (`src/plugin/`) provides dynamic loading and secure sandboxed execution of WebAssembly (WASM) plugins for request filtering, response transformation, and extended functionality. It serves as the foundation for the Spin framework support (`src/spin/`) and serverless execution engine (`src/serverless/`).

**Core responsibilities:**
- Load and manage WASM plugin modules from files or memory (mesh distribution)
- Execute plugins in a secure sandbox with resource limits (memory, CPU fuel, execution time)
- Provide host function interface (ABI) for plugins to access request data, environment variables, and mesh/DHT capabilities
- Instance pooling to reduce instantiation overhead at high request rates
- DHT prefix access control to prevent unauthorized data exfiltration
- Hot-reload support for development and zero-downtime updates
- Both WASM (`.wasm`/`.wat`) and native plugin (`.so`/`.dylib`/`.dll`) loading

---

## 2. Key Submodules and Their Responsibilities

| File | Responsibility | Public API |
|------|---------------|------------|
| `mod.rs` | Public API entry point; `PluginManager` (WASM + Axum loading/unload), `PluginManagerLifecycle` (hot-reload, directory watching) | `PluginManager`, `PluginManagerLifecycle`, `WasmFilterResult`, `WasmPluginError` |
| `wasm_runtime.rs` | Core WASM execution engine using `wasmtime`. Loads modules, links host functions, executes filter/transform/handle handlers | `WasmPluginManager`, `WasmRuntime`, `WasmResourceLimits`, `PluginInfo` |
| `instance_pool.rs` | Per-runtime instance pooling with `WasmInstancePool` (reuses instantiated modules) | `WasmInstancePool` |
| `pool.rs` | Generic `PooledInstance` trait and struct for pooled WASM instances | `PooledInstance`, `WasmPool` trait |
| `axum_loader.rs` | Dynamic loading of native `.so`/`.dylib`/`.dll` plugins using `libloading` | `load_plugin()`, `validate_plugin_path()` |
| `global.rs` | Global singletons: `GlobalPluginManager` and `GlobalWasmMemoryBudget` | `GlobalPluginManager`, `GlobalWasmMemoryBudget`, `get_global_plugin_manager()` |
| `wasm_metrics.rs` | Atomic metrics collection for plugin invocations, decisions, fuel consumption | `WasmPluginMetrics`, `record_wasm_*` functions |

### Submodule Dependency Graph

```
PluginManager (mod.rs)
├── WasmPluginManager (wasm_runtime.rs)
│   ├── WasmRuntime
│   │   ├── WasmInstancePool (instance_pool.rs)
│   │   │   └── WasmPooledInstance
│   │   ├── PooledInstance (pool.rs)
│   │   └── WasmPool trait
│   └── WasmResourceLimits
├── AxumPluginWrapper (mod.rs internal)
├── GlobalPluginManager (global.rs)
│   └── GlobalWasmMemoryBudget
└── PluginManagerLifecycle (mod.rs)
```

---

## 3. Major Data Structures and Types

### Core Enums

```rust
// From mod.rs
pub enum WasmFilterResult {
    Pass,                      // Request passes through
    Block(StatusCode, String), // Request blocked with status and reason
    Challenge(String),          // Challenge required with challenge token
}

pub enum WasmPluginError {
    LoadFailed(String),        // Failed to load WASM module
    FunctionNotFound(String),  // Required function not exported
    ExecutionFailed(String),   // Execution error
    SandboxError(String),      // Resource limit violation
}

pub enum AxumPluginError {
    LoadFailed(String),
    AbiMismatch { plugin: String, expected: String },
    SymbolNotFound(String),
}
```

### WasmResourceLimits

Per-plugin resource constraints defined in `wasm_runtime.rs:51-76`:

```rust
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,           // Max linear memory (default: 64MB)
    pub max_table_elements: Option<usize>, // Max table elements (default: None/unlimited)
    pub max_cpu_fuel: u64,              // CPU fuel budget (default: 1,000,000)
    pub timeout_seconds: u64,           // Wall-clock timeout (default: 30s)
    pub max_instances: usize,           // Instance pool size (default: 1)
    pub memory_budget_mb: Option<usize>, // Per-plugin memory allocation
    pub wasi_enabled: bool,             // WASI support (default: false)
    pub allowed_dht_prefixes: Vec<String>, // DHT key prefix whitelist
}
```

**Default values:**
- `max_memory_mb`: 64
- `max_cpu_fuel`: 1,000,000
- `timeout_seconds`: 30
- `max_instances`: 1
- `wasi_enabled`: false
- `allowed_dht_prefixes`: empty (default deny)

### RequestContext

Per-request store data tracking execution context (`wasm_runtime.rs:514-523`):

```rust
pub(crate) struct RequestContext {
    pub(crate) start: Instant,           // Request start time for timeout tracking
    pub(crate) timeout: Duration,        // Per-request timeout
    pub(crate) env: HashMap<String, String>, // Environment variables
    pub(crate) allowed_dht_prefixes: Vec<String>, // DHT prefix whitelist (reset per request)
    pub(crate) max_memory: usize,        // Max memory in bytes
    pub(crate) max_table_elements: usize, // Max table elements
    pub(crate) body_receiver: Option<tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>>, // Streaming body
}
```

Implements `ResourceLimiter` trait for wasmtime memory/table growth control.

### GuestExports

Tracks which guest ABI functions are available in a loaded module (`wasm_runtime.rs:79-86`):

```rust
pub(crate) struct GuestExports {
    pub(crate) filter_request: Option<FilterRequestFn>,
    pub(crate) transform_response: Option<TransformResponseFn>,
    pub(crate) handle_request: Option<HandleRequestFn>,
    pub(crate) guest_alloc: Option<GuestAllocFn>,
    pub(crate) guest_free: Option<GuestFreeFn>,
    pub(crate) memory: Option<Memory>,
}
```

### PooledInstance and WasmPool

Generic pooled instance interface (`pool.rs:7-37`):

```rust
pub struct PooledInstance {
    pub instance: Instance,
    pub(crate) store: Store<RequestContext>,
    pub filter_name: String,
    pub max_cpu_fuel: u64,
    pub(crate) allowed_dht_prefixes: Vec<String>,
}

impl PooledInstance {
    pub fn prepare_for_request(
        &mut self,
        env: HashMap<String, String>,
        timeout_seconds: u64,
        allowed_dht_prefixes: Vec<String>,
    ) {
        self.store.data_mut().start = Instant::now();
        self.store.data_mut().timeout = Duration::from_secs(timeout_seconds);
        self.store.data_mut().env = env;
        self.store.data_mut().body_receiver = None;  // MUST reset to prevent leak
        self.store.data_mut().allowed_dht_prefixes = allowed_dht_prefixes; // MUST reset to prevent leak
        if self.max_cpu_fuel > 0 {
            self.store.set_fuel(self.max_cpu_fuel).ok();
        }
    }
}

pub trait WasmPool {
    fn get(&self, filter_name: &str) -> Option<PooledInstance>;
    fn return_instance(&self, instance: PooledInstance);
    fn max_size(&self) -> usize;
}
```

### WasmInstancePool

Per-runtime instance pool with stub host functions for warmup (`instance_pool.rs:11-38`):

```rust
pub struct WasmInstancePool {
    pool: Arc<Mutex<VecDeque<WasmPooledInstance>>>,
    engine: Arc<Engine>,
    max_size: usize,
    default_allowed_dht_prefixes: Vec<String>,
}

pub(crate) struct WasmPooledInstance {
    pub(crate) instance: Instance,
    pub(crate) store: Store<RequestContext>,
    pub(crate) filter_name: String,
    pub(crate) max_cpu_fuel: u64,
    pub(crate) default_allowed_dht_prefixes: Vec<String>,
}
```

### EffectivePluginPolicy

Resolved policy for a plugin after merging manifest defaults, site overrides, and platform constraints (`wasm_runtime.rs`):

```rust
pub struct EffectivePluginPolicy {
    pub name: String,                    // Plugin name
    pub version: String,                 // Manifest version string
    pub trust_tier: TrustTier,           // Trust level (e.g., Local, Remote, Federated)
    pub capabilities: Vec<String>,       // Declared capabilities (e.g., "dht:read", "http:outbound")
    pub limits: WasmResourceLimits,      // Effective runtime resource limits
    pub manifest_limits: WasmResourceLimits, // Raw limits from the manifest (before overrides)
    pub source: PluginSourceIdentity,    // Provenance of the loaded binary
}
```

The effective policy is the **single source of truth** for how a plugin is sandboxed at runtime. All runtime limits (memory, fuel, timeout, pool size, DHT prefixes) are derived from this struct, not from raw config or manifest values directly.

### PreparedPluginLoad

Canonical input to `WasmPluginManager::load_plugin()` — the only load path that applies manifest authority wiring:

```rust
pub struct PreparedPluginLoad {
    pub manifest: PluginManifest,         // Parsed and validated plugin manifest
    pub effective_limits: WasmResourceLimits, // Merged limits (manifest + site + platform)
    pub source: PluginSourceIdentity,     // Provenance metadata for the binary
}
```

All load paths (`load_plugin`, `load_plugin_from_memory`, etc.) must route through a `PreparedPluginLoad` to ensure manifest-derived limits and provenance are applied consistently. Raw `WasmResourceLimits` should never bypass this struct on the primary load path.

### PluginSourceIdentity

Cryptographic provenance of a loaded plugin binary:

```rust
pub struct PluginSourceIdentity {
    pub path: Option<PathBuf>,            // File path (None if loaded from memory/mesh)
    pub binary_sha256: [u8; 32],         // SHA-256 of the WASM binary
    pub manifest_sha256: [u8; 32],       // SHA-256 of the manifest file
    pub key_id: Option<String>,           // Signing key ID (if signature verified)
}
```

Used by `EffectivePluginPolicy.source` to record where a plugin came from and its integrity hashes. The `key_id` is populated only when the plugin was loaded from a signed distribution (e.g., mesh WASM dist or a verified filesystem path with a co-located `.sig` file).

### WasmRuntime

A single WASM module with its engine, module, pool, and linker (`wasm_runtime.rs:88-96`):

```rust
pub struct WasmRuntime {
    engine: Engine,
    module: Module,
    limits: WasmResourceLimits,
    name: String,
    priority: i32,
    pool: Arc<WasmInstancePool>,
    linker: Linker<RequestContext>,
}
```

### WasmPluginManager

Manages multiple `WasmRuntime` instances with priority-based ordering (`wasm_runtime.rs:104-112`):

```rust
pub struct WasmPluginManager {
    runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
    sorted_runtimes_cache: RwLock<Option<Vec<Arc<WasmRuntime>>>>,
    default_limits: WasmResourceLimits,
    pool: Arc<WasmInstancePool>,
    plugin_paths: RwLock<HashMap<String, PathBuf>>,
}
```

---

## 4. Key APIs and Entry Points

### PluginManager (mod.rs)

High-level plugin management combining WASM and Axum plugins:

```rust
impl PluginManager {
    pub fn new() -> Self
    pub fn with_wasm_limits(limits: WasmResourceLimits) -> Self
    
    // WASM plugin loading
    pub fn load_wasm_plugin(&self, path: &Path) -> Result<(), WasmPluginError>
    // On mesh-enabled builds, tries mesh WASM dist manager first, falls back to file
    
    // Axum plugin loading
    pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, AxumPluginError>
    
    // Router access
    pub fn get_axum_router(&self) -> Option<Arc<Router>>
    pub fn get_axum_router_by_name(&self, name: &str) -> Option<Arc<Router>>
    pub fn get_axum_routers(&self) -> Vec<Arc<Router>>
    pub fn unload_axum_plugin(&self, name: &str) -> bool
    
    // Filter/transform execution
    pub fn apply_wasm_filters(
        &self,
        request: Request<Bytes>,
        env: HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError>
    
    pub fn apply_wasm_filters_with_plugins(
        &self,
        request: Request<Bytes>,
        plugin_names: &[String],
        env: HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError>
    
    pub fn apply_wasm_response_transforms(
        &self,
        response: Response<Bytes>,
        env: HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError>
    
    pub fn apply_wasm_response_transforms_with_plugins(
        &self,
        response: Response<Bytes>,
        plugin_names: &[String],
        env: HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError>
    
    pub fn wasm_manager(&self) -> &Arc<WasmPluginManager>
}
```

### PluginManagerLifecycle (mod.rs)

Lifecycle management with hot-reload support:

```rust
impl PluginManagerLifecycle {
    pub fn new(plugin_manager: Arc<PluginManager>) -> Self
    
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, WasmPluginError>
    pub fn load_axum_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, AxumPluginError>
    
    // File watcher for .wasm, .wat, .so, .dylib, .dll files
    pub fn enable_hot_reload(&mut self, dir: &Path) -> Result<(), String>
    
    pub fn reload_plugin(&self, path: &Path) -> Result<(), WasmPluginError>
    pub fn shutdown(&self)
    pub fn plugin_manager(&self) -> &Arc<PluginManager>
}
```

### WasmPluginManager (wasm_runtime.rs)

Core WASM plugin management:

```rust
impl WasmPluginManager {
    pub fn new() -> Self
    pub fn with_limits(mut self, limits: WasmResourceLimits) -> Self
    pub fn get_default_limits(&self) -> WasmResourceLimits
    
    pub fn load_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError>
    pub fn load_plugin_from_memory(&self, name: &str, data: &[u8], limits: WasmResourceLimits) -> Result<Arc<WasmRuntime>, WasmPluginError>
    pub fn load_plugin_from_memory_with_priority(&self, name: &str, data: &[u8], limits: WasmResourceLimits, priority: i32) -> Result<Arc<WasmRuntime>, WasmPluginError>
    pub fn load_plugin_with_limits(&self, path: &Path, limits: WasmResourceLimits) -> Result<Arc<WasmRuntime>, WasmPluginError>
    
    pub fn unload_plugin(&self, name: &str) -> bool
    pub fn reload_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError>
    pub fn reload_plugin_by_name(&self, name: &str) -> Result<Arc<WasmRuntime>, WasmPluginError>
    
    pub fn list_plugins(&self) -> Vec<String>
    pub fn get_plugin_info(&self) -> Vec<PluginInfo>
    
    // M1 Phase 01: Manifest authority wiring
    pub fn prepare_plugin_load(&self, path: &Path, site_overrides: Option<&SitePluginConfig>) -> Result<PreparedPluginLoad, WasmPluginError>
    // Canonical load path entry point. Parses the manifest, merges limits (manifest defaults → site overrides → platform constraints),
    // computes binary/manifest SHA-256, and returns a PreparedPluginLoad ready for load_plugin().
    
    pub fn get_plugin_policy_info(&self, name: &str) -> Option<EffectivePluginPolicy>
    // Returns the EffectivePluginPolicy for a loaded plugin, including resolved limits, capabilities, trust tier, and provenance.
    
    // PluginInfo now includes manifest-derived metadata:
    // - version: String (from manifest)
    // - trust_tier: TrustTier (from manifest / site config)
    // - timeout_seconds: u64 (effective value after merge)
    // - max_memory_mb: usize (effective value after merge)
    // - max_cpu_fuel: u64 (effective value after merge)
    // - max_instances: usize (effective pool size after merge)
    // - capabilities_summary: Vec<String> (declared capabilities from manifest)
    
    // Filter/transform with priority ordering
    pub fn filter_request(&self, request: Request<Bytes>, env: HashMap<String, String>) -> Result<WasmFilterResult, WasmPluginError>
    pub fn filter_request_with_plugins(&self, request: Request<Bytes>, plugin_names: &[String], env: HashMap<String, String>) -> Result<WasmFilterResult, WasmPluginError>
    pub fn transform_response(&self, response: Response<Bytes>, env: HashMap<String, String>) -> Result<Response<Bytes>, WasmPluginError>
    pub fn transform_response_with_plugins(&self, response: Response<Bytes>, plugin_names: &[String], env: HashMap<String, String>) -> Result<Response<Bytes>, WasmPluginError>
}
```

### WasmRuntime (wasm_runtime.rs)

Individual WASM module execution:

```rust
impl WasmRuntime {
    pub fn load(path: &Path, limits: WasmResourceLimits) -> Result<Self, WasmPluginError>
    pub fn load_with_priority(path: &Path, limits: WasmResourceLimits, priority: i32) -> Result<Self, WasmPluginError>
    pub fn load_from_bytes(name: &str, bytes: &[u8], limits: WasmResourceLimits) -> Result<Self, WasmPluginError>
    pub fn load_from_bytes_with_priority(name: &str, bytes: &[u8], limits: WasmResourceLimits, priority: i32) -> Result<Self, WasmPluginError>
    
    pub fn filter_request(&self, request: Request<Bytes>, env: Arc<HashMap<String, String>>) -> Result<WasmFilterResult, WasmPluginError>
    pub fn transform_response(&self, response: Response<Bytes>, env: Arc<HashMap<String, String>>) -> Result<Response<Bytes>, WasmPluginError>
    
    // Serverless-style handlers
    pub fn invoke_handler(&self, method: &str, uri: &str, headers: &str, body: &[u8], env: HashMap<String, String>) -> Result<Response<Bytes>, WasmPluginError>
    pub fn invoke_handler_streaming(&self, method: &str, uri: &str, headers: &str, body: Box<dyn ErasedBody>, env: HashMap<String, String>) -> Result<Response<Bytes>, WasmPluginError>
    
    pub fn name(&self) -> &str
    pub fn priority(&self) -> i32
    pub fn engine(&self) -> &Engine
    pub fn module(&self) -> &Module
}
```

### GlobalPluginManager (global.rs)

Global singleton wrapper:

```rust
impl GlobalPluginManager {
    pub fn new() -> Self
    pub fn with_max_memory(mut self, max_bytes: usize) -> Self
    pub fn get_wasm_manager(&self) -> Arc<WasmPluginManager>
    pub fn memory_budget(&self) -> &Arc<GlobalWasmMemoryBudget>
    pub fn record_allocation(&self, bytes: usize)
    pub fn record_deallocation(&self, bytes: usize)
    pub fn current_memory_usage(&self) -> usize
    pub fn max_memory_bytes(&self) -> usize
}

pub fn get_global_plugin_manager() -> Arc<GlobalPluginManager>
```

### WasmMetrics (wasm_metrics.rs)

Metrics collection and retrieval:

```rust
#[derive(Debug, Clone, Default)]
pub struct WasmPluginMetrics {
    pub invocations: u64,
    pub decisions_pass: u64,
    pub decisions_block: u64,
    pub decisions_challenge: u64,
    pub errors: u64,
    pub fuel_consumed: u64,
    pub total_duration_ms: u64,
}

impl WasmPluginMetrics {
    pub fn get(plugin_name: &str) -> Self
    pub fn avg_duration_ms(&self) -> f64
    pub fn pass_rate(&self) -> f64
}

pub fn record_wasm_invocation(plugin_name: &str)
pub fn record_wasm_decision_pass(plugin_name: &str)
pub fn record_wasm_decision_block(plugin_name: &str)
pub fn record_wasm_decision_challenge(plugin_name: &str)
pub fn record_wasm_error(plugin_name: &str)
pub fn record_wasm_fuel_consumed(plugin_name: &str, fuel: u64)
pub fn record_wasm_duration(plugin_name: &str, duration_ms: u64)
pub fn get_wasm_metrics(plugin_name: &str) -> WasmPluginMetrics
pub fn get_all_wasm_metrics() -> HashMap<String, WasmPluginMetrics>
```

---

## 5. How WASM Plugin Sandboxing Works

### Overview

SynVoid uses **wasmtime** as the WASM runtime with multiple layers of sandboxing:

1. **Linear Memory Isolation** — Each plugin has its own memory space
2. **Resource Limits** — Memory growth, table growth, CPU fuel, wall-clock timeout
3. **Host Function Gating** — Plugins can only call explicitly linked host functions
4. **DHT Prefix Access Control** — Queries restricted to allowed prefixes

### wasmtime Engine Configuration

Engine creation in `wasm_runtime.rs:564-575` and `627-638`:

```rust
let mut config = Config::new();
config
    .cranelift_opt_level(OptLevel::SpeedAndSize)  // JIT optimization
    .max_wasm_stack(1 << 20)                      // 1MB stack limit
    .memory_init_cow(true);                       // Copy-on-write for faster instantiation

if limits.max_cpu_fuel > 0 {
    config.consume_fuel(true);                    // Fuel consumption enabled
}
```

### Host Function Linking

Host functions are pre-registered in the `Linker` during module loading (`wasm_runtime.rs:692-1013`). The linker provides a sandboxed interface between the WASM guest and the host environment.

**Available host functions:**

| Function | Signature | Purpose |
|----------|-----------|---------|
| `env::abort` | `(msg_ptr: i32, msg_len: i32)` | Abort execution with message |
| `env::check_timeout` | `() -> i32` | Returns 1 if wall-clock timeout exceeded |
| `env::get_env` | `(key_ptr, key_len, out_ptr, out_max) -> i32` | Read environment variable |
| `env::synvoid_read_body_chunk` | `(out_ptr, out_max) -> i32` | Read streaming body chunk |
| `env::mesh_query_dht` | `(key_ptr, key_len, out_ptr, out_max) -> i32` | DHT lookup with prefix filtering |
| `env::mesh_check_threat` | `(ip_ptr, ip_len) -> i32` | Threat intelligence lookup |
| `env::mesh_emit_event` | `(topic_ptr, topic_len, data_ptr, data_len) -> i32` | Publish event to mesh |

### Memory Management

Guest memory allocation via `guest_alloc` / `guest_free` or fallback to fixed offset:

```rust
fn write_to_guest_memory(...) -> Result<(i32, i32), WasmPluginError> {
    let ptr = if let Some(alloc_fn) = &exports.guest_alloc {
        alloc_fn.call(&mut *store, data_len as i32)?
    } else {
        1024i32  // Fallback: reserved header area
    };
    // Memory growth if needed (within limits)
    // Write data to linear memory
}
```

### ResourceLimiter Implementation

`RequestContext` implements `wasmtime::ResourceLimiter`:

```rust
impl ResourceLimiter for RequestContext {
    fn memory_growing(&mut self, current: usize, desired: usize, maximum: Option<usize>) -> Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_memory)  // Limit by max_memory_mb
    }
    
    fn table_growing(&mut self, current: usize, desired: usize, maximum: Option<usize>) -> Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_table_elements)  // Limit by max_table_elements
    }
}
```

### Execution Flow

1. **Module Loading**: Create Engine, compile Module, build Linker with host functions
2. **Store Creation**: Per-request Store with ResourceLimiter, fuel, timeout
3. **Instance Acquisition**: Get from pool or instantiate fresh
4. **Memory Write**: Serialize request data into guest memory
5. **Function Call**: Invoke guest function with pointers
6. **Result Parsing**: Read results from guest memory
7. **Cleanup**: Free memory if `guest_free` available, return instance to pool

### Guest ABI Function Signatures

```rust
// filter_request(method_ptr, method_len, uri_ptr, uri_len,
//                headers_ptr, headers_len, body_ptr, body_len) -> i32
// Returns: 0=pass, 1=block, 2=challenge, -1=error
type FilterRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32), i32>;

// transform_response(status_code, body_ptr, body_len, out_ptr, out_max) -> i32
// Returns: new body length, or -1 on error
type TransformResponseFn = TypedFunc<(i32, i32, i32, i32, i32), i32>;

// handle_request(method_ptr, method_len, uri_ptr, uri_len,
//                headers_ptr, headers_len, body_ptr, body_len,
//                out_status_ptr, out_body_ptr, out_body_max) -> i32
// Returns: 0=success, -1=error; out_status and out_body written to memory
type HandleRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>;
```

### Header Serialization Format

Headers are serialized to a compact binary format (`wasm_runtime.rs:1238-1256`):

```
[header_count: u16]
[for each header: [name_len: u16][name bytes][value_len: u16][value bytes]]
```

---

## 6. Instance Pooling

### Architecture

Each `WasmRuntime` owns a `WasmInstancePool` that maintains a `VecDeque<WasmPooledInstance>`. Pooled instances retain their compiled `Store` and instantiated `Instance` across requests.

### Pool Operations

```rust
impl WasmInstancePool {
    // Get instance from pool (pop from back)
    pub(crate) fn get(&self, filter_name: &str) -> Option<WasmPooledInstance> {
        let mut pool = self.pool.lock();
        pool.pop_back()
    }
    
    // Return instance to pool (push to back if under max_size)
    pub(crate) fn return_instance(&self, instance: WasmPooledInstance) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size {
            pool.push_back(instance);
        }
    }
}
```

### prepare_for_request Reset

**Critical**: Before each request, `prepare_for_request()` MUST reset all per-request state to prevent data leakage between requests:

```rust
impl WasmPooledInstance {
    pub(crate) fn prepare_for_request(
        &mut self,
        env: HashMap<String, String>,
        timeout_seconds: u64,
        allowed_dht_prefixes: Vec<String>,
    ) {
        self.store.data_mut().start = Instant::now();
        self.store.data_mut().timeout = Duration::from_secs(timeout_seconds);
        self.store.data_mut().env = env;
        self.store.data_mut().body_receiver = None;           // MUST reset
        self.store.data_mut().allowed_dht_prefixes = allowed_dht_prefixes; // MUST reset
        if self.max_cpu_fuel > 0 {
            self.store.set_fuel(self.max_cpu_fuel).ok();
        }
    }
}
```

**Known bugs (FIXED):**
- Previously, `body_receiver` and `allowed_dht_prefixes` were NOT reset, causing data leakage between requests
- Fixed in `pool.rs:16-31` and `instance_pool.rs:219-233`

### Warmup

`WasmInstancePool::warmup()` pre-populates the pool with instances using stub host functions:

```rust
pub async fn warmup(&self, modules: &[(String, Module)]) {
    // Creates instances with stub implementations:
    // - abort, check_timeout, get_env, synvoid_read_body_chunk
    // - mesh_query_dht, mesh_check_threat, mesh_emit_event
    // These stubs are replaced with real implementations on first actual request
}
```

### Manifest-Derived Limits (M1 Phase 01)

Pooled instances are initialized with limits derived from `EffectivePluginPolicy`, not raw config defaults. The flow is:

1. `prepare_plugin_load()` resolves the effective policy (manifest + site + platform)
2. `WasmInstancePool` receives the `WasmResourceLimits` from `effective_limits`
3. Pool warmup and instance creation use these manifest-authoritative values
4. `max_instances` from the effective policy controls the pool's `max_size`
5. `max_cpu_fuel` from the effective policy is set on each instance via `set_fuel()`

This ensures that plugin sandboxing is always governed by the manifest authority chain, not by ad-hoc runtime overrides.

### Request Flow with Pooling

```
filter_request(request)
  └─> pool.get(&name)           // Pop from pool
      └─> inst.prepare_for_request(env, timeout, dht_prefixes)
          └─> resolve_exports_from_instance()
              └─> do_filter_request_with_exports()
                  └─> pool.return_instance(inst)  // Push back to pool
```

---

## 7. DHT Prefix Access Control

### Security Model

WASM plugins can query the distributed hash table (DHT) via `mesh_query_dht()`, but **sensitive prefix restrictions** prevent unauthorized data exfiltration.

### Prefix Validation Logic

At `wasm_runtime.rs:849-872`:

```rust
let sensitive_prefixes = [
    "threat_indicator:",
    "yara_rule:",
    "yara_rules_manifest:",
    "edge_attestation:",
    "dns_zone:",
    "dns_record:",
    "dns_domain_reg:",
];

let is_sensitive = sensitive_prefixes.iter().any(|p| key.starts_with(p));
let is_explicitly_allowed = caller
    .data()
    .allowed_dht_prefixes
    .iter()
    .any(|p| key.starts_with(p));

if is_sensitive && !is_explicitly_allowed {
    tracing::error!("WASM plugin attempted unauthorized DHT query: key='{}'", key);
    return -2;  // Unauthorized
}
```

### Default Deny

- If `allowed_dht_prefixes` is **empty**, all DHT queries are blocked
- Plugins must be explicitly granted prefix access
- Even granted prefixes only allow access to specific key prefixes

### Per-Runtime Enforcement

Each `WasmRuntime` instance enforces its own `allowed_dht_prefixes` independently. The prefixes are stored in `WasmResourceLimits` and passed to `WasmInstancePool` during creation.

### Example Configuration

```rust
// Plugin A: Only threat indicators
WasmResourceLimits {
    allowed_dht_prefixes: vec!["threat_indicator:".to_string()],
    ..Default::default()
}

// Plugin B: YARA rules only
WasmResourceLimits {
    allowed_dht_prefixes: vec!["yara_rule:".to_string()],
    ..Default::default()
}

// Plugin C: No DHT access (default deny)
WasmResourceLimits {
    allowed_dht_prefixes: vec![],
    ..Default::default()
}
```

### Query Flow

```
Plugin A calls mesh_query_dht("threat_indicator:malware")
  └─> is_sensitive("threat_indicator:malware") = true
  └─> is_explicitly_allowed(["threat_indicator:"], "threat_indicator:malware") = true
  └─> Query succeeds, returns data

Plugin C calls mesh_query_dht("threat_indicator:malware")
  └─> is_sensitive("threat_indicator:malware") = true
  └─> is_explicitly_allowed([], "threat_indicator:malware") = false
  └─> Returns -2 (unauthorized), logged as error
```

---

## 8. Feature Gates

The plugin module has minimal feature gating. Most functionality is always available:

### `mesh` Feature Gate

Only three locations use `#[cfg(feature = "mesh")]`:

| Location | Purpose |
|----------|---------|
| `mod.rs:66` | `load_wasm_plugin` tries mesh WASM dist manager first |
| `wasm_runtime.rs:874` | `mesh_query_dht` actual DHT lookup |
| `wasm_runtime.rs:936` | `mesh_check_threat` actual threat lookup |
| `wasm_runtime.rs:998` | `mesh_emit_event` actual event publishing |

When `mesh` is disabled:
- `load_wasm_plugin` skips mesh lookup, loads directly from file
- `mesh_query_dht` returns 0 (empty/not found)
- `mesh_check_threat` returns 0 (clean)
- `mesh_emit_event` does nothing

### WASM Support

WASM plugin support is enabled by default (no feature gate). The `wasmtime` dependency is always included:

```toml
# Cargo.toml:195-196
wasmtime = { version = "42.0.2", features = ["component-model"] }
```

### Axum Plugin Loading

Native plugin loading via `libloading` is always available, no separate feature gate.

---

## 9. Integration Points

### HTTP Server Integration

WASM plugins integrate into the HTTP pipeline at `src/http/server.rs:3050-3060`:

```rust
// If site has wasm_plugins configured
if !site_config.wasm_plugins.is_empty() {
    match plugin_manager.apply_wasm_filters(request.clone(), env) {
        Ok(WasmFilterResult::Pass) => { /* continue */ }
        Ok(WasmFilterResult::Block(status, msg)) => { /* return error */ }
        Ok(WasmFilterResult::Challenge(token)) => { /* challenge response */ }
        Err(e) => { /* log error, pass through */ }
    }
}
// Response transforms applied via apply_wasm_response_transforms()
```

### Admin API

- `GET /api/plugins` — List loaded plugins
- `GET /api/plugins/metrics` — Per-plugin metrics
- `POST /api/plugins/reload` — Reload specific plugin

### Global Singleton

`get_global_plugin_manager()` provides process-wide access to plugin management.

---

## 10. Configuration

### WasmResourceLimits Defaults

```rust
impl Default for WasmResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_table_elements: None,
            max_cpu_fuel: 1_000_000,
            timeout_seconds: 30,
            max_instances: 1,
            memory_budget_mb: None,
            wasi_enabled: false,
            allowed_dht_prefixes: Vec::new(),
        }
    }
}
```

### Per-Site Configuration

Site configuration can override limits per plugin via `site_config.wasm_plugins`.

---

## 11. Related Documentation

- [`plugin_deep_dive.md`](plugin_deep_dive.md) — Detailed deep dive including Spin and serverless comparison
- [`skills/spin_wasm.md`](skills/spin_wasm.md) — Spin WASM runtime patterns
- [`skills/serverless_wasm.md`](skills/serverless_wasm.md) — Serverless WASM patterns
- [`skills/wasm_components.md`](skills/wasm_components.md) — WASM component model patterns
- [`src/plugin/AGENTS.override.md`](src/plugin/AGENTS.override.md) — Agent-specific guidance
