# Plugin & Serverless Deep Dive

## Overview

This document covers three related modules: the generic WASM plugin runtime (`src/plugin/`), the Spin framework support (`src/spin/`), and the full-featured serverless execution engine (`src/serverless/`).

---

## 1. WASM Plugin Runtime (`src/plugin/`)

### Purpose

Provides dynamic loading and execution of WASM plugins for request filtering, response transformation, and extended functionality. This is the foundation that both `spin` and `serverless` modules rely on.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Public API: `PluginManager` (WASM + Axum plugin loading/unloading), `PluginManagerLifecycle` (hot-reload, directory watching) |
| `wasm_runtime.rs` | Core WASM execution engine using `wasmtime`. Loads modules, links host functions, executes filter/transform handlers |
| `instance_pool.rs` | Per-runtime instance pooling with `WasmInstancePool` (reuses instantiated modules) |
| `pool.rs` | Generic `PooledInstance` trait and struct for pooled WASM instances |
| `axum_loader.rs` | Dynamic loading of native `.so`/`.dylib`/`.dll` plugins using `libloading` |
| `global.rs` | Global singletons: `GlobalPluginManager` and `GlobalWasmMemoryBudget` |
| `wasm_metrics.rs` | Atomic metrics collection for plugin invocations, decisions, fuel consumption |

### Main Structs

- **`WasmPluginManager`** — Manages multiple `WasmRuntime` instances. Maintains sorted runtime cache by priority. Provides `filter_request()`, `transform_response()` methods.

- **`WasmRuntime`** — A single WASM module loaded from file or memory. Contains a `wasmtime::Engine`, compiled `Module`, instance pool, and `Linker` with pre-registered host functions.

- **`WasmResourceLimits`** — Resource constraints per plugin: `max_memory_mb`, `memory_budget_mb`, `max_table_elements`, `max_cpu_fuel`, `timeout_seconds`, `max_instances`, `wasi_enabled`, `allowed_dht_prefixes`.

- **`RequestContext`** — Per-request store data tracking wall-clock timeout, environment variables, DHT prefixes, memory limits, and optional body receiver for streaming.

### Plugin Loading Flow

1. **Loading**: `PluginManager::load_wasm_plugin(path)` calls `WasmRuntime::load()` which:
   - Creates a `wasmtime::Engine` with `cranelift_opt_level(SpeedAndSize)`
   - Loads the WASM binary via `Module::from_file()` or `Module::from_binary()`
   - Validates exports (must have at least `filter_request`, `transform_response`, or `handle_request`)
   - Creates a `WasmInstancePool` sized to `max_instances`
   - Builds a `Linker` with host functions

2. **Execution Flow** (request filtering):
   - `WasmPluginManager::filter_request()` iterates sorted runtimes by priority
   - Gets pooled instance or creates new one
   - Serializes request into WASM linear memory (method, URI, headers, body as binary format)
   - Calls `filter_request()` guest function with pointers
   - Returns `WasmFilterResult::Pass`, `Block(status, msg)`, or `Challenge(reason)`

### Guest ABI Host Functions

| Function | Purpose |
|----------|---------|
| `check_timeout()` | Wall-clock timeout enforcement |
| `get_env(key)` | Environment variable access |
| `mesh_query_dht(key)` | DHT lookups (with sensitive prefix restrictions) |
| `mesh_check_threat(ip)` | Threat intelligence lookups |
| `mesh_emit_event(topic, data)` | Event publishing |
| `synvoid_read_body_chunk()` | Streaming body reading |

### Instance Pooling

- **`WasmInstancePool`** uses a `VecDeque<WasmPooledInstance>` protected by `parking_lot::Mutex`
- `get()` pops from back, `return_instance()` pushes to back (if under `max_size`)
- Pooled instances retain their `Store` and instantiated `Instance`
- Before each request, `prepare_for_request()` resets timeout, fuel, env, and body_receiver
- Warmup pre-populates pool via `warmup(modules)` which creates instances with stub implementations (for fast pool population); real host functions are linked on first actual request

---

## 2. Spin Framework Runtime (`src/spin/`)

### Purpose

Implements a Spin framework runtime for executing Spin-compatible WASM modules. Manifest parsing and longest-prefix-match routing are implemented; requests are dispatched via `SpinHttpHandler` at `src/http/server.rs:2417-2489`.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Module declarations only |
| `runtime.rs` | `SpinRuntime`, `SpinAppInstance`, `SpinRuntimeConfig`. Manages Spin app lifecycle and HTTP handling |
| `manifest.rs` | `Manifest` and `SpinManifest` structs. Parses Spin v2 manifest format (TOML) |
| `handler.rs` | `SpinHttpHandler` (thin wrapper) and `SpinAppsManager` (global app registry) |
| `kv_store.rs` | `SpinKvStore` — in-memory key-value store with TTL support |

### Key Structs

- **`SpinRuntime`** — Owns a `wasmtime::Engine`, optional manifest, and `HashMap<String, SpinAppInstance>`. Runs a supervisor task for idle eviction and health checks.

- **`SpinAppInstance`** — Wraps a `WasmRuntime` (delegate pattern), manifest, component ID, KV store, environment variables, request count, last request time.

- **`SpinRuntimeConfig`** — Manifest path, app name, instance ID, max instances, default timeout, optional KV store.

- **`Manifest`** — Parsed Spin manifest with components, routes. Components have `id`, `source` (WASM path), `url` (route), `env`.

### Known Limitations

1. **Spin routing uses longest-prefix-match** — Component-to-URL routing is implemented via `find_route()` in `src/spin/runtime.rs:273-291` which selects the longest matching prefix
2. **Manual app registration required** — Spin apps must be registered via Admin API; no automatic discovery
3. **KV store is local-only** — No distribution via mesh/DHT
4. **No WASI socket support** — Only in-memory KV store; no outbound HTTP capability

---

## 3. Serverless Function Execution (`src/serverless/`)

### Purpose

Full-featured serverless function runtime with sophisticated instance pooling, autoscaling, async compilation, and mesh integration for distributed execution.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Public exports: `ServerlessManager`, `InstancePool`, `ServerlessRegistry`, routing types |
| `manager.rs` | `ServerlessManager` — function registry, initialization, invocation, permission verification, mesh integration |
| `instance_pool.rs` | `InstancePool` — sophisticated pooling with autoscaling, health checking, cold start metrics |
| `routing.rs` | `ServerlessRoute`, `RouteMatch`, `MethodMatch` — flexible route matching (exact/prefix/suffix/regex/glob) |
| `registry.rs` | `ServerlessRegistry` — function metadata, invocation stats, error tracking |
| `async_compilation.rs` | `AsyncCompilationManager` / `AsyncCompilationHandle` — non-blocking WASM compilation with state tracking |

### Key Structs

- **`ServerlessManager`** — Central coordinator. Owns `HashMap<String, ServerlessFunction>`, `HashMap<String, Arc<InstancePool>>`, routes, config. Integrates with mesh for DHT registration and hierarchical routing.

- **`InstancePool`** — Per-function instance pool with:
  - `min_instances` / `max_instances` bounds
  - `idle_timeout_seconds` before eviction
  - `scale_up_threshold` / `scale_down_threshold` for autoscaling
  - `pre_warm_instances` on startup
  - Dedicated autoscaler task running every 10s
  - Three modes: `Pool` (reuse instances), `Direct` (instantiate per request), `Hybrid`

- **`ServerlessInstance`** — Wraps `Arc<WasmRuntime>`, tracks state (`Initializing`, `Ready`, `Busy`, `Evicted`), `InstanceMetrics` (requests handled, total duration, cold starts, last used).

### Instance Pooling Mechanism

The `InstancePool` is the core of the serverless architecture:

1. **Initialization**: `initialize()` pre-warms `pre_warm_instances` instances
2. **Get Instance**: `get_instance()`:
   - First tries to pop from `idle_instances` stack
   - If empty, checks if under `max_instances` and scales up
   - If at max, returns `NoInstancesAvailable`
   - Marks instance `Busy` and adds to `active_instances`
3. **Return Instance**: `return_instance()`:
   - Moves from `active` to `idle` if `idle_duration < idle_timeout`
   - Otherwise evicts (removes from pool entirely)
4. **Autoscaling**: Every 10s `run_autoscaler()`:
   - If utilization >= `scale_up_threshold` and under max: scale up by 50% of current (capped at `max_scale_up_per_tick`)
   - If utilization <= `scale_down_threshold` and above min: scale down by 30%
   - Evicts instances idle beyond `idle_timeout_seconds`
5. **Cold Start Tracking**: Records duration from `spawn_instance()` to first use

### Routing

Flexible `ServerlessRoute` matching supporting:
- `RouteMatch::Exact`, `Prefix`, `Suffix`, `Regex`, `Glob`
- `MethodMatch::Any`, `Specific`, `Multiple`
- Priority-based sorting (lower priority number = higher precedence)

### Async Compilation

`AsyncCompilationManager` allows non-blocking function initialization:
- `get_or_create()` returns existing or new `AsyncCompilationHandle`
- State machine: `Pending` -> `Compiling` -> `Ready` / `Failed`
- `wait_for_completion()` blocks until compilation done
- Used during `ServerlessManager::initialize()` to spawn background compilation tasks

### WAF Integration

**Per-route WAF bypass** (not plugin integration):
- `ServerlessWafMode::Off` in function config skips WAF checks for that route
- WASM plugins work differently — they are loaded via `PluginManager` and applied separately from serverless execution
- Serverless functions run AFTER the WAF decision, not as part of the WAF pipeline

### Mesh Integration

`ServerlessManager` with `#[cfg(feature = "mesh")]`:
- Registers function in DHT via `RecordStoreManager::store_and_announce()`
- Announces via `MeshTransport::announce_serverless()`
- Registers in hierarchical routing as `serverless_function:{name}`
- `verify_caller_permission()` checks node revocation status, `require_trusted_caller`, `allowed_callers` list, `allowed_orgs` membership, `min_tier_level` with tier claim validation

---

## Cross-Cutting Concerns

### WAF Integration Summary

| Component | WAF Role |
|-----------|----------|
| `src/plugin/` | WASM filters are PART of the WAF — they intercept requests during WAF processing |
| `src/serverless/` | Serverless runs AFTER WAF; can optionally disable WAF per-route (`waf_mode=off`) |
| `src/spin/` | No WAF integration exists |

WASM plugin execution in HTTP server (`http/server.rs:3043-3086`):
1. Request enters WAF pipeline
2. If site has `wasm_plugins` configured, `PluginManager::apply_wasm_filters()` is called
3. Each plugin returns `WasmFilterResult::Pass`, `Block`, or `Challenge`
4. If blocked/challenged, request is handled accordingly
5. Otherwise, request proceeds to origin
6. Response transforms via `apply_wasm_response_transforms()` before returning

### Feature Comparison

| Aspect | `plugin` | `spin` | `serverless` |
|--------|----------|--------|-------------|
| Instance pooling | Per-runtime simple pool | None (ad-hoc instances) | Per-function sophisticated pool |
| Autoscaling | No | No | Yes (10s tick, up/down thresholds) |
| Cold start tracking | No | No | Yes |
| Routing | None | Manifest-only (incomplete) | Full route matching |
| Mesh integration | DHT queries | No | DHT + hierarchical routing |
| Hot reload | Yes (file watcher) | No | No |
| Metrics | Yes (fuel, duration, decisions) | No | Yes (per-instance) |

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [WAF Deep Dive](waf_deep_dive.md) - WAF pipeline and WASM plugin integration
- [Mesh Deep Dive](mesh_deep_dive.md) - DHT integration with serverless