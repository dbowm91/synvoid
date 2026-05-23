# Spin WASM Runtime Skill

## Overview

This skill documents the Spin WASM runtime support. Spin is a framework for building serverless functions with WebAssembly.

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

## HTTP Routing Integration

Spin apps are integrated into the HTTP request handling pipeline at `src/http/server.rs:2417-2489`.

### Integration Flow

1. **Configuration**: `BackendConfig::Spin { spin_app_name }` is parsed from site config
2. **Route Target**: `RouteTarget` has `spin_app_name: Option<Arc<str>>` field
3. **Dispatch**: HTTP server checks for `BackendType::Spin` and routes to `SpinHttpHandler`

### Route Matching

Spin routing uses longest-prefix-match at `src/spin/runtime.rs:271-285`:

```rust
fn find_route(routes: &[RouteConfig], path: &str) -> Option<(String, RouteConfig)> {
    let matches: Vec<_> = routes
        .iter()
        .filter_map(|r| {
            if path.starts_with(&r.route) {
                Some((r.route.clone(), r.clone()))
            } else {
                None
            }
        })
        .collect();
    matches.into_iter().max_by_key(|(route, _)| route.len())
}
```

## Manual Registration Required

**Spin requires manual app registration via the Admin API** before use. See `architecture/app_handlers.md:47-61` for setup instructions.

## Supervisor Pattern

The runtime uses a supervisor pattern for lifecycle management:

1. **Idle Eviction**: Background task evicts idle instances after `idle_timeout`
2. **Health Checks**: Periodic health checks on running instances
3. **Component Loading**: Manifest-based component loading with route matching

## Instance Reuse (2026-05-23)

`SpinRuntime` caches compiled `WasmRuntime` instances by component_id:

```rust
pub struct SpinRuntime {
    pub config: SpinRuntimeConfig,
    manifest: RwLock<Option<Manifest>>,
    instances: RwLock<HashMap<String, SpinAppInstance>>,
    compiled_runtimes: RwLock<HashMap<String, Arc<WasmRuntime>>>,  // Cache compiled WASM modules
    engine: Engine,
}
```

This eliminates the high cold-start overhead of recompiling WASM for every request. The `SpinAppInstance` (per-request state with `last_request`, `request_count`) is still created per request, but the expensive `WasmRuntime` compilation is cached and reused.

Key method: `SpinRuntime::instantiate_app()` checks the cache first before creating a new `WasmRuntime`.

## Testing

```bash
# Run Spin tests
cargo test --lib spin

# Run WASM runtime tests
cargo test --lib plugin::wasm_runtime

# Run integration tests
cargo test --test integration_test
```