# Spin WASM Runtime Architecture

## Overview

The Spin module provides a serverless WASM runtime for the SynVoid proxy. It enables execution of Spin Framework-compatible WebAssembly modules within the proxy architecture, supporting HTTP-triggered serverless functions with built-in key-value store, environment variables, and instance caching for cold-start optimization.

**Module Location:** `src/spin/`

**Key Dependencies:**
- `wasmtime` (v42.0.2) - WebAssembly runtime
- `toml` - Manifest parsing

## 1. Purpose and Responsibility

The Spin module is responsible for:

1. **Spin Application Lifecycle Management** - Loading, instantiating, and managing Spin applications defined via `spin.toml` manifests
2. **HTTP Request Handling** - Routing incoming HTTP requests to appropriate Spin components based on URL routes
3. **WASM Execution Environment** - Providing a secure sandboxed environment for WASM module execution with resource limits
4. **Instance Caching** - Reusing warm WASM instances to minimize cold-start overhead
5. **Key-Value Store** - Providing a built-in Spin-compatible key-value store for serverless functions
6. **Environment Variable Injection** - Supplying per-component environment variables to WASM modules

## 2. Submodules and Responsibilities

### 2.1 `runtime.rs` - Core Runtime Implementation

**Responsibility:** Manages Spin application lifecycle, instance creation, caching, and request routing.

**Key Types:**

```rust
pub struct SpinRuntimeConfig {
    pub manifest_path: PathBuf,
    pub app_name: String,
    pub instance_id: String,
    pub max_instances: usize,
    pub default_timeout_seconds: u64,
    pub kv_store: Option<Arc<SpinKvStore>>,
    pub idle_timeout_seconds: u64,
}
```

```rust
pub struct SpinRuntime {
    pub config: SpinRuntimeConfig,
    manifest: RwLock<Option<Manifest>>,
    instances: RwLock<HashMap<String, SpinAppInstance>>,        // Active instances
    cached_instances: RwLock<HashMap<String, SpinAppInstance>>,   // Cold-start cache
    compiled_runtimes: RwLock<HashMap<String, Arc<WasmRuntime>>>, // Compiled WASM cache
    engine: Engine,
}
```

```rust
pub struct SpinAppInstance {
    pub manifest: Manifest,
    pub wasm_runtime: Arc<WasmRuntime>,
    pub component_id: String,
    pub kv_store: Arc<SpinKvStore>,
    pub env: HashMap<String, String>,
    pub started_at: Instant,
    pub last_request: RwLock<Instant>,
    pub request_count: RwLock<u64>,
}
```

**Key Methods:**
- `SpinRuntime::new(config)` - Creates new runtime, loads manifest if exists
- `SpinRuntime::instantiate_app(component_id)` - Creates new app instance
- `SpinRuntime::get_or_create_instance(component_id)` - Returns cached instance or creates new (cold-start caching)
- `SpinRuntime::handle_http_request(...)` - Main entry point for HTTP handling
- `SpinRuntime::find_route(manifest, path)` - Longest-prefix-match routing

### 2.2 `manifest.rs` - Spin Manifest Parsing

**Responsibility:** Parses Spin v2 manifest files (`spin.toml`) into internal structures.

**Key Types:**

```rust
pub struct SpinManifest {
    pub spin_version: String,
    pub manifest_version: Option<String>,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub authors: Option<Vec<String>>,
    pub triggers: HashMap<String, TriggerConfig>,
    pub components: Vec<ManifestComponent>,
}
```

```rust
pub struct ManifestComponent {
    pub id: String,
    pub source: Option<String>,        // Path to .wasm file
    pub url: Option<String>,           // HTTP route
    pub files: Option<Vec<String>>,
    pub exclude_files: Vec<String>,
    pub build: Option<BuildConfig>,
    pub wasm: WasmConfig,
    pub env: HashMap<String, String>,
    pub wasi: Option<WasiConfig>,
}
```

**Key Methods:**
- `Manifest::load(path)` - Load and parse manifest from file
- `Manifest::parse(content)` - Parse manifest from string content
- `Manifest::get_component(id)` - Get component by ID
- `Manifest::get_routes()` - Get all HTTP routes

**Validation:**
- HTTP trigger requires at least one component with a URL route defined

### 2.3 `handler.rs` - HTTP Handler and App Manager

**Responsibility:** HTTP request handling abstraction and global Spin app registry.

**Key Types:**

```rust
pub struct SpinRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
    pub env: HashMap<String, String>,
}
```

```rust
pub struct SpinResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}
```

```rust
pub struct SpinHttpHandler {
    runtime: Arc<SpinRuntime>,
}
```

```rust
pub struct SpinAppsManager {
    apps: Arc<parking_lot::RwLock<HashMap<String, Arc<SpinRuntime>>>>,
}
```

**Global Manager:**
```rust
static SPIN_APPS_MANAGER: LazyLock<Arc<SpinAppsManager>>
pub fn get_global_spin_apps_manager() -> Arc<SpinAppsManager>
```

### 2.4 `kv_store.rs` - Key-Value Store

**Responsibility:** Provides a Spin-compatible key-value store with TTL support.

**Key Types:**

```rust
pub struct SpinKvEntry {
    pub value: Vec<u8>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}
```

```rust
pub struct SpinKvStore {
    store: Arc<RwLock<HashMap<String, SpinKvEntry>>>,
}
```

**Key Methods:**
- `SpinKvStore::new()` - Create new store
- `SpinKvStore::get(key)` - Get value with TTL check
- `SpinKvStore::set(key, value, expires_at)` - Set value with optional TTL
- `SpinKvStore::delete(key)` - Delete key
- `SpinKvStore::exists(key)` - Check key existence with TTL
- `SpinKvStore::list_keys(prefix)` - List keys with optional prefix filter

**Timestamp:** Uses `crate::utils::safe_unix_timestamp()` for TTL checks (Unix timestamps as per AGENTS.md).

## 3. Major Data Structures

### 3.1 SpinRuntimeError

```rust
pub enum SpinRuntimeError {
    ManifestError(SpinManifestError),
    ManifestNotLoaded,
    ComponentNotFound(String),
    ModuleNotFound(String),
    MissingModule(String),
    RouteNotFound(String),
    WasmError(String),
    KvStoreError(String),
}
```

### 3.2 SpinHandlerError

```rust
pub enum SpinHandlerError {
    InvalidMethod(String),
    HandlerError(String),
    RuntimeError(String),
}
```

### 3.3 SpinManifestError

```rust
pub enum SpinManifestError {
    IoError(String),
    ParseError(String),
    MissingField(String),
    NoHttpRoutes,  // HTTP trigger requires at least one component with URL
}
```

## 4. Key APIs and Entry Points

### 4.1 Admin API Endpoints (src/admin/handlers/spin.rs)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/spin/apps` | GET | List all registered Spin applications |
| `/spin/apps` | POST | Create and register a new Spin app |
| `/spin/apps/{name}` | DELETE | Unregister and shutdown a Spin app |
| `/spin/apps/{name}/manifest` | GET | Get app manifest info |
| `/spin/apps/{name}/instances` | GET | List running instances |

**CreateSpinAppRequest:**
```rust
pub struct CreateSpinAppRequest {
    pub name: String,
    pub manifest_path: String,
    pub timeout_seconds: Option<u64>,
    pub max_instances: Option<usize>,
}
```

### 4.2 SpinRuntime Public API

```rust
// Create new runtime from config
pub fn new(config: SpinRuntimeConfig) -> Result<Self, SpinRuntimeError>

// Load manifest from path
pub fn load_manifest(&self, path: &Path) -> Result<(), SpinRuntimeError>

// Get current manifest
pub fn get_manifest(&self) -> Option<Manifest>

// Create/instantiate app instance
pub fn instantiate_app(&self, component_id: &str) -> Result<SpinAppInstance, SpinRuntimeError>

// Get existing instance by ID
pub fn get_instance(&self, instance_id: &str) -> Option<SpinAppInstance>

// List all instance IDs
pub fn list_instances(&self) -> Vec<String>

// Remove instance by ID
pub fn remove_instance(&self, instance_id: &str) -> bool

// Main HTTP request handler
pub fn handle_http_request(
    &self,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    env: HashMap<String, String>,
) -> Result<Response<Bytes>, SpinRuntimeError>

// Shutdown all instances
pub fn shutdown(&self)
```

### 4.3 SpinHttpHandler

```rust
impl SpinHttpHandler {
    pub fn new(runtime: Arc<SpinRuntime>) -> Self
    
    pub async fn handle_request(&self, request: SpinRequest) -> Result<SpinResponse, SpinHandlerError>
    
    pub fn handle_request_sync(&self, request: SpinRequest) -> Result<SpinResponse, SpinHandlerError>
}
```

## 5. How Spin WASM Runtime Works

### 5.1 Application Startup Flow

```
1. Admin API: POST /spin/apps with CreateSpinAppRequest
   |
   v
2. SpinAppsManager::register(name, runtime)
   |
   v
3. SpinRuntime::new(config)
   - Load manifest from spin.toml
   - Create wasmtime::Engine with optimized config
   - Initialize instance/cached_instance/compiled_runtimes HashMaps
```

### 5.2 Request Handling Flow

```
1. HTTP Request arrives at proxy
   |
   v
2. SpinHttpHandler::handle_request_sync(request)
   |
   v
3. SpinRuntime::handle_http_request(method, path, headers, body, env)
   |
   v
4. SpinRuntime::find_route(manifest, path) - longest prefix match
   |
   v
5. SpinRuntime::get_or_create_instance(component_id)
   - Check cached_instances for warm instance
   - If not idle (5 min timeout), return cached
   - Otherwise instantiate new
   |
   v
6. WasmRuntime::invoke_handler(...)
   - Write method/uri/headers/body to WASM memory
   - Call handle_request export
   - Read status/body from WASM memory
   |
   v
7. Return HTTP Response
```

### 5.3 WASM Module Loading and Execution

**WasmRuntime (src/plugin/wasm_runtime.rs)** provides the underlying WASM execution:

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

**Guest ABI Functions (Expected Exports):**
- `filter_request(method_ptr, method_len, uri_ptr, uri_len, headers_ptr, headers_len, body_ptr, body_len) -> i32`
- `transform_response(status_code, body_ptr, body_len, out_ptr, out_max) -> i32`
- `handle_request(method_ptr, method_len, uri_ptr, uri_len, headers_ptr, headers_len, body_ptr, body_len, out_status_ptr, out_body_ptr, out_body_max) -> i32`
- `guest_alloc(size) -> i32` (optional)
- `guest_free(ptr, size)` (optional)

**Host Functions Linked into WASM:**
- `env::abort` - WASM abort handler
- `env::check_timeout` - Timeout check
- `env::get_env` - Read environment variable from memory
- `env::synvoid_read_body_chunk` - Streaming body read
- `env::mesh_query_dht` - DHT query (mesh feature)
- `env::mesh_check_threat` - Threat check (mesh feature)
- `env::mesh_emit_event` - Emit event (mesh feature)

### 5.4 WasmResourceLimits

```rust
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,           // Default: 64
    pub max_table_elements: Option<usize>,
    pub max_cpu_fuel: u64,              // Default: 1,000,000
    pub timeout_seconds: u64,            // Default: 30
    pub max_instances: usize,            // Default: 1
    pub memory_budget_mb: Option<usize>,
    pub wasi_enabled: bool,             // Default: true for Spin
    pub allowed_dht_prefixes: Vec<String>,
}
```

## 6. Cold-Start Caching

Spin implements a two-tier instance caching strategy to minimize cold-start overhead:

### 6.1 Cached Runtimes (`compiled_runtimes`)

```rust
compiled_runtimes: RwLock<HashMap<String, Arc<WasmRuntime>>>
```

- Caches compiled `WasmRuntime` by component_id
- Reused across multiple `SpinAppInstance` creations
- Never evicted (until shutdown)

### 6.2 Cached Instances (`cached_instances`)

```rust
cached_instances: RwLock<HashMap<String, SpinAppInstance>>
```

- Caches `SpinAppInstance` by component_id
- 5-minute idle timeout (`idle_timeout_seconds: 300`)
- Evicted when idle timeout exceeded

### 6.3 Instance Reuse Flow

```rust
fn get_or_create_instance(&self, component_id: &str) -> Result<SpinAppInstance, SpinRuntimeError> {
    // Check if cached instance exists and is not idle
    if let Some(instance) = self.cached_instances.read().get(component_id).cloned() {
        if !instance.is_idle(Duration::from_secs(300)) {
            instance.reuse();  // Update last_request and request_count
            return Ok(instance);
        }
    }
    
    // Cache miss or idle - create new instance
    let instance = self.instantiate_app(component_id)?;
    self.cached_instances.write().insert(component_id.to_string(), instance.clone());
    Ok(instance)
}
```

### 6.4 SpinAppInstance Metrics

```rust
pub struct SpinAppInstance {
    pub started_at: Instant,              // Creation time
    pub last_request: RwLock<Instant>,   // Last request timestamp
    pub request_count: RwLock<u64>,      // Total requests served
}

impl SpinAppInstance {
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }
    
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_request.read().elapsed() > idle_timeout
    }
}
```

### 6.5 Instance Lifecycle

```
Request arrives
    |
    v
get_or_create_instance() checks cached_instances
    |
    +-- Instance exists & not idle --> reuse() called, return instance
    |
    +-- Instance idle or missing --> instantiate_app() creates new
        |
        v
    WasmRuntime loaded from compiled_runtimes cache (or created if first time)
    |
    v
    SpinAppInstance created with env vars
    |
    v
    Instance stored in both instances (active) and cached_instances (for reuse)
```

## 7. Feature Gates

The Spin module has no exclusive feature gates. However, some functionality is conditionally available:

### 7.1 Mesh-Dependent Features

These functions only operate when the `mesh` feature is enabled:

- `env::mesh_query_dht` - DHT key-value queries
- `env::mesh_check_threat` - Threat indicator lookups
- `env::mesh_emit_event` - Event publishing to DHT

Without `mesh`:
- `mesh_query_dht` returns 0 (empty result)
- `mesh_check_threat` returns 0 (clean)
- `mesh_emit_event` is no-op

### 7.2 WASI Support

WASI (WebAssembly System Interface) is enabled per-component:

```rust
let wasi_enabled = component.wasi.as_ref().map(|w| w.enabled).unwrap_or(true);
```

Default is `true` for Spin components.

### 7.3 WASMtime Configuration

```rust
let mut wasm_config = Config::new();
wasm_config
    .cranelift_opt_level(OptLevel::SpeedAndSize)  // Optimized JIT
    .max_wasm_stack(1 << 20)                      // 1MB stack
    .memory_init_cow(true)                        // Copy-on-write memory init
    .consume_fuel(true);                          // Fuel metering enabled
```

## 8. Configuration

### 8.1 SpinRuntimeConfig Defaults

```rust
impl Default for SpinRuntimeConfig {
    fn default() -> Self {
        Self {
            manifest_path: PathBuf::new(),
            app_name: String::new(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            max_instances: 10,
            default_timeout_seconds: 30,
            kv_store: None,
            idle_timeout_seconds: 300,
        }
    }
}
```

### 8.2 Admin API Registration

Via `POST /spin/apps`:
```rust
CreateSpinAppRequest {
    name: String,              // App identifier
    manifest_path: String,     // Path to spin.toml
    timeout_seconds: Option<u64>,  // Default: 30
    max_instances: Option<usize>,  // Default: 10
}
```

### 8.3 Spin Component Configuration (spin.toml)

```toml
spin_version = "2"
name = "my-app"
version = "1.0.0"

[triggers.http]
route = "/"
component = "main"

[[components]]
id = "main"
source = "target/wasm32-wasi/release/my_app.wasm"
url = "/"

[components.wasm]
module = "target/wasm32-wasi/release/my_app.wasm"

[components.env]
FOO = "bar"

[components.wasi]
enabled = true
```

## 9. Relationship to Other Modules

### 9.1 Plugin Module Integration

The Spin module reuses `WasmRuntime` from `src/plugin/wasm_runtime.rs` which provides:
- WASM module loading and compilation
- Instance pooling (`WasmInstancePool`)
- Guest ABI function resolution
- Memory management between host and guest

### 9.2 Admin API Integration

`src/admin/handlers/spin.rs` provides REST endpoints for:
- Spin app registration/deregistration
- App status and manifest querying
- Instance listing

### 9.3 Global Manager

`get_global_spin_apps_manager()` provides a process-wide registry of Spin runtimes, allowing any part of the codebase to access registered Spin applications.

## 10. Error Handling

### 10.1 Error Hierarchy

```
SpinRuntimeError
    |-- ManifestError(SpinManifestError)
    |       |-- IoError
    |       |-- ParseError
    |       |-- MissingField
    |       |-- NoHttpRoutes
    |-- ManifestNotLoaded
    |-- ComponentNotFound
    |-- ModuleNotFound
    |-- MissingModule
    |-- RouteNotFound
    |-- WasmError
    |-- KvStoreError

SpinHandlerError
    |-- InvalidMethod
    |-- HandlerError
    |-- RuntimeError
```

### 10.2 Common Failures

| Error | Cause | Handling |
|-------|-------|----------|
| `ManifestNotLoaded` | Manifest not loaded before request | Load manifest or return error |
| `ComponentNotFound` | Invalid component_id requested | Return 404 or route to error handler |
| `RouteNotFound` | No route matches request path | Return 404 |
| `ModuleNotFound` | WASM file doesn't exist | Return 500 with error details |
| `WasmError` | WASM execution failure | Return 500 with error details |

## 11. Testing

```bash
# Run Spin module tests
cargo test --lib spin

# Run Spin runtime tests
cargo test --lib spin::runtime

# Run Spin manifest tests
cargo test --lib spin::manifest

# Run WASM runtime tests
cargo test --lib plugin::wasm_runtime

# Run integration tests
cargo test --test integration_test
```

## 12. Security Considerations

### 12.1 Resource Limits

- Memory: 64MB default (configurable)
- CPU Fuel: 1,000,000 default (configurable)
- Timeout: 30s default (configurable)
- Max instances: 10 per app (configurable)

### 12.2 DHT Access Control

Sensitive DHT prefixes require explicit allowlisting:

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

// Access granted only if in allowed_dht_prefixes
```

### 12.3 File Permissions

WASM module files should have appropriate permissions (0o600 for private key files is standard practice, though WASM files may be 0o644).

## 13. File Structure Summary

```
src/spin/
├── mod.rs          # Module declarations (handler, kv_store, manifest, runtime)
├── handler.rs      # HTTP handler + SpinAppsManager (265 lines)
├── kv_store.rs     # Key-value store implementation (152 lines)
├── manifest.rs     # Manifest parsing (232 lines)
└── runtime.rs      # Core runtime (383 lines)
```

**Total:** ~1,032 lines across 4 modules.
