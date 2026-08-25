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
impl ServerlessManager {
    pub async fn invoke(
        &self,
        path: &str,
        request: Request<Body>,
    ) -> Result<Response<Body>> {
        // 1. Match route pattern
        let function_name = self.match_route(path)?;
        
        // 2. Get or create instance from pool
        let instance = self.get_instance(&function_name).await?;
        
        // 3. Execute WASM function
        let response = instance.execute(request).await?;
        
        // 4. Return instance to pool
        self.return_instance(function_name, instance);
        
        Ok(response)
    }
}
```

### Mesh Distribution (Feature-Gated)

```rust
#[cfg(feature = "mesh")]
impl ServerlessManager {
    pub async fn publish_to_dht(&self, function: &ServerlessFunction) {
        // Register function in mesh DHT
        // Include: name, route_pattern, capabilities, caller_permissions
    }
    
    pub async fn handle_mesh_invocation(
        &self,
        request: MeshServerlessRequest,
    ) -> Result<MeshServerlessResponse> {
        // Verify caller permissions (org, tier, allowed callers)
        // Execute function
        // Return response
    }
}
```

### CPU Offload

```rust
// For CPU-intensive transforms
pub async fn invoke_with_cpu_offload(
    &self,
    function_name: &str,
    request: Request<Body>,
    cpu_worker: &CpuWorkerClient,
) -> Result<Response<Body>> {
    // Serialize request
    // Send to CPU worker via IPC
    // Receive response
}
```

## Compilation States

```rust
pub enum CompilationState {
    Pending,                        // Awaiting compilation
    Compiling { started_at: Instant }, // WASM compilation in progress
    Ready,                          // Ready to execute
    Failed { error: String },       // Compilation failed
}

pub struct AsyncCompilationManager {
    states: DashMap<String, CompilationState>,
    watchers: DashMap<String, watch::Receiver<CompilationState>>,
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
