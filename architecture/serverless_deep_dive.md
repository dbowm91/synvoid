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
    functions: DashMap<String, ServerlessFunction>,
    route_table: RwLock<Vec<(Regex, String)>>,  // (pattern, function_name)
    instance_pools: DashMap<String, Arc<InstancePool>>,
    compilation_manager: AsyncCompilationManager,
}

pub struct ServerlessFunction {
    name: String,
    wasm_path: PathBuf,
    route_pattern: Option<Regex>,
    config: FunctionConfig,
    state: FunctionState,  // Compiling, Ready, Failed
}
```

### Instance Pooling

```rust
pub struct InstancePool {
    min_instances: usize,
    max_instances: usize,
    idle_eviction: Duration,
    instances: Mutex<Vec<PooledInstance>>,
    active_count: AtomicUsize,
    auto_scaler: AutoScaler,
}

pub enum PoolMode {
    Pool,       // Reuse instances (default)
    Direct,     // New instance per request
    Hybrid,     // Pool for hot, direct for cold
}
```

### Auto-Scaling

```rust
pub struct AutoScaler {
    tick_interval: Duration,  // 10s
    scale_up_threshold: f64,  // 80% utilization
    scale_down_threshold: f64, // 20% utilization
    scale_up_step: usize,
    scale_down_step: usize,
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
    Compiling,  // WASM compilation in progress
    Ready,      // Ready to execute
    Failed(String),  // Compilation failed
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
| `InstancePool` | `crates/synvoid-serverless/src/pool.rs` | Per-function pool |
| `ServerlessFunction` | `crates/synvoid-serverless/src/function.rs` | Function metadata |
| `AsyncCompilationManager` | `crates/synvoid-serverless/src/compilation.rs` | Compilation tracking |
| `AutoScaler` | `crates/synvoid-serverless/src/autoscaler.rs` | Dynamic scaling |
