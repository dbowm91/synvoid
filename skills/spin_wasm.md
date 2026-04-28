# Spin WASM Runtime Skill

## Overview

This skill documents the Spin WASM runtime support added in Wave 11. Spin is a framework for building serverless functions with WebAssembly.

## Key Components

### SpinRuntime

Located at `src/spin/runtime.rs`, the Spin runtime manages Spin application lifecycle:

```rust
pub struct SpinRuntime {
    pub name: String,
    pub manifest: SpinManifest,
    pub components: HashMap<String, SpinComponent>,
    pub kv_store: Arc<SpinKeyValueStore>,
    pub idle_timeout: Duration,
}
```

### SpinManifest

Located at `src/spin/manifest.rs`, parses `spin.toml` manifest files:

```rust
pub struct SpinManifest {
    pub spin_version: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub components: Vec<SpinComponent>,
    pub triggers: Vec<TriggerConfig>,
}
```

### SpinComponent

Represents a runnable component:

```rust
pub struct SpinComponent {
    pub id: String,
    pub source: PathBuf,
    pub wasm_module: Vec<u8>,
    pub routes: Vec<RouteConfig>,
    pub allowed_http_hosts: Option<Vec<String>>,
    pub env: Vec<EnvVar>,
}
```

### SpinKeyValueStore

Built-in key-value store at `src/spin/kv_store.rs`:

```rust
pub struct SpinKeyValueStore {
    store: DashMap<String, KVEntry>,
}

pub struct KVEntry {
    value: Vec<u8>,
    expires_at: Option<u64>,
}
```

## Spin Apps Manager

Located at `src/spin/handler.rs`, manages global Spin application registry:

```rust
pub struct SpinAppsManager {
    apps: RwLock<HashMap<String, Arc<SpinRuntime>>>,
}
```

Admin endpoints:
- `GET /api/spin/apps` — List all Spin applications
- `POST /api/spin/apps` — Create and register a Spin app
- `GET /api/spin/apps/{name}` — Get app manifest
- `DELETE /api/spin/apps/{name}` — Unregister and shutdown
- `GET /api/spin/apps/{name}/instances` — List running instances

## Supervisor Pattern

The runtime uses a supervisor pattern for lifecycle management:

1. **Idle Eviction**: Background task evicts idle instances after `idle_timeout`
2. **Health Checks**: Periodic health checks on running instances
3. **Component Loading**: Manifest-based component loading with route matching

```rust
impl SpinRuntime {
    pub async fn supervise(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            self.evict_idle_instances().await;
            self.check_health().await;
        }
    }
}
```

## Integration with Existing WASM Runtime

Spin runtime integrates with the existing `WasmRuntime` via `load_with_priority`:

```rust
pub fn load_spin_app(
    manifest: SpinManifest,
    config: SpinAppConfig,
) -> Result<SpinRuntime, SpinError> {
    // Load each component via WasmRuntime::load_from_bytes_with_priority
}
```

## Testing

```bash
# Run Spin tests
cargo test --lib spin

# Run WASM runtime tests
cargo test --lib plugin::wasm_runtime

# Run integration tests
cargo test --test integration_test
```

## Common Patterns

### Loading a Spin App

```rust
let manifest = SpinManifest::from_file("spin.toml")?;
let runtime = SpinRuntime::new("my-app", manifest)?;
runtime.start().await;
```

### Route Matching

```rust
fn match_route(routes: &[RouteConfig], path: &str) -> Option<SpinComponent> {
    for route in routes {
        if path.starts_with(&route.route) {
            return Some(route.component.clone());
        }
    }
    None
}
```

### Key-Value Operations

```rust
// Store
runtime.kv_store().set("key", b"value".to_vec(), ttl_secs).await;

// Retrieve
if let Some(value) = runtime.kv_store().get("key").await {
    // use value
}
```

## Known Issue: HTTP Routing Gap

**Spin apps are NOT yet integrated into the HTTP request handling pipeline.**

- SpinRuntime is fully implemented in `src/spin/`
- Admin API endpoints work (registration, listing, deletion)
- SpinHttpHandler exists and can handle requests
- BUT: `src/http/server.rs:1869-1949` only checks `ServerlessManager` for routing
- Spin apps can be registered but are NOT reachable via live HTTP traffic

To complete integration, requests need to route to Spin apps based on `spin.toml` trigger configuration, similar to how `ServerlessManager` is integrated in the HTTP server dispatch.