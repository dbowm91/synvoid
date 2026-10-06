# Serverless Deep Dive

SynVoid's serverless crate manages WASM serverless functions with compilation, instance pooling, route-based invocation, and mesh distribution.

## Architecture

### Core Components

```
ServerlessManager
├── Function Registry
├── Route Matching
├── Instance Pools (per-function)
├── Async Compilation
├── Mesh Distribution (feature-gated)
└── CPU Offload Invocation
```

### Function Registry

```rust
pub struct ServerlessManager {
    functions: RwLock<HashMap<String, ServerlessFunction>>,
    pools: RwLock<HashMap<String, Arc<InstancePool>>>,
    config: RwLock<Option<ServerlessConfig>>,
    runtime: Arc<WasmPluginManager>,
    routes: RwLock<Vec<ServerlessRoute>>,
    event_subscriptions: RwLock<HashMap<String, Vec<String>>>,
    compilation_manager: Arc<AsyncCompilationManager>,
}

pub struct ServerlessFunction {
    pub definition: FunctionDefinition,
    pub runtime: Option<Arc<WasmRuntime>>,
    pub compilation_handle: Option<Arc<AsyncCompilationHandle>>,
}
```

### Instance Pooling

```rust
pub struct InstancePool {
    config: InstancePoolConfig,
    function_definition: FunctionDefinition,
    runtime: Arc<WasmRuntime>,
    instances: RwLock<Vec<Arc<ServerlessInstance>>>,
    active_instances: RwLock<HashMap<String, Arc<ServerlessInstance>>>,
    idle_instances: RwLock<Vec<Arc<ServerlessInstance>>>,
    last_scale_up: RwLock<Instant>,
    last_scale_down: RwLock<Instant>,
    shutdown_tx: tokio::sync::watch::Sender<()>,
    mode: RwLock<InstancePoolMode>,
    last_mode_used: RwLock<InstancePoolMode>,
}

pub enum InstancePoolMode {
    Pool,       // Reuse instances (default)
    Direct,     // New instance per request
    Hybrid,     // Pool for hot, direct for cold
}
```

### Auto-Scaling

Scaling is built into `InstancePool` via `InstancePoolConfig`:

```rust
pub struct InstancePoolConfig {
    pub min_instances: usize,           // default: 1
    pub max_instances: usize,           // default: 10
    pub idle_timeout_seconds: u64,      // default: 300
    pub scale_up_threshold: f64,        // default: 0.7
    pub scale_down_threshold: f64,      // default: 0.3
    pub scale_up_cooldown_seconds: u64, // default: 30
    pub scale_down_cooldown_seconds: u64, // default: 60
    pub pre_warm_instances: usize,      // default: 2
    pub max_scale_up_per_tick: usize,   // default: 5
}
```

### Route-Based Invocation

```rust
// Canonical entry point (free function, mesh-gated in lib.rs).
pub async fn handle_serverless_function(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    caller: CallerContext,
) -> Result<Response<Bytes>, ServerlessError> {
    // 1. Match route pattern
    let (function, _route) = manager.find_matching_route(path, method)?;

    // 2. Verify caller permissions unless the function is public
    if !function.definition.public_function.unwrap_or(false) {
        manager.verify_caller_permission(&function_name, &caller.node_id, caller.role, ...)?;
    }

    // 3. Execute the WASM function through the per-function pool
    //    (the pool owns instance acquire/return internally)
    // 4. Return the response
}
```

### Mesh Distribution (Feature-Gated)

Mesh integration is provider-based, not a direct mesh dependency: the
`synvoid-serverless` crate defines narrow traits in
`crates/synvoid-serverless/src/mesh_integration.rs` and the root crate
implements and wires them at startup via `set_mesh_*` (`OnceLock` globals).

```rust
#[cfg(feature = "mesh")]
pub trait MeshWasmDistProvider: Send + Sync + 'static {
    fn get_module_data(&self, name: &str) -> Option<Vec<u8>>;
}

pub trait MeshDhtProvider: Send + Sync + 'static {
    fn store_function(&self, name: &str, data: Vec<u8>, ttl: u64);
    fn get_record(&self, key: &str) -> Option<Vec<u8>>;
}

pub trait MeshTransportProvider: Send + Sync + 'static {
    fn announce_serverless(&self);
    fn node_id(&self) -> String;
}

pub trait MeshOrganizationProvider: Send + Sync + 'static {
    fn validate_tier_claim(&self, tier: u32, org: &str) -> bool;
    fn is_node_revoked(&self, node_id: &str) -> Option<String>;
}

pub trait MeshRoutingProvider: Send + Sync + 'static {
    fn register_function(&self, name: &str, node_id: &str);
}
```

`ServerlessManager::initialize` calls these providers when the `mesh` feature
is on: DHT publication via `register_function_dht` (`dht.store_function(..., 3600)`),
route registration (`routing.register_function`), and
`transport.announce_serverless()`. Inbound mesh invocation is
`ServerlessManager::invoke_for_mesh(...)`, which delegates authorization to
`verify_caller_permission` (organization, role, tier, revocation) unless the
function is marked `public_function`.

### CPU Offload

```rust
// For CPU-intensive workloads
pub async fn invoke_for_cpu_offload(
    &self,
    function_name: &str,
    input: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, ServerlessError> {
    // Record the invocation, acquire an instance from the per-function pool,
    // execute, and return the raw output bytes.
}
```

The CPU-offload path executes in the calling process via the instance pool; it
does not take a `CpuWorkerClient` and performs no IPC serialization round-trip.

## Compilation States

```rust
pub enum CompilationState {
    Pending,                        // Awaiting compilation
    Compiling { started_at: Instant }, // WASM compilation in progress
    Ready,                          // Ready to execute
    Failed { error: String },       // Compilation failed
}

pub struct AsyncCompilationManager {
    handles: parking_lot::RwLock<std::collections::HashMap<String, Arc<AsyncCompilationHandle>>>,
}
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `ServerlessManager` | `crates/synvoid-serverless/src/manager.rs` | Central orchestrator |
| `InstancePool` | `crates/synvoid-serverless/src/instance_pool.rs` | Per-function pool |
| `ServerlessFunction` | `crates/synvoid-serverless/src/manager.rs` | Function metadata |
| `AsyncCompilationManager` | `crates/synvoid-serverless/src/async_compilation.rs` | Compilation tracking |
| `ServerlessRoute` | `crates/synvoid-serverless/src/routing.rs` | Route-based invocation |
| `ServerlessRegistry` | `crates/synvoid-serverless/src/registry.rs` | Global registry |
| `ServerlessScheduler` | `crates/synvoid-serverless/src/scheduler.rs` | Scheduling |
| `CallerContext` | `crates/synvoid-serverless/src/manager.rs` | Mesh caller metadata |
