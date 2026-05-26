# Plugin/WASM Architecture Review Plan

## Verified Correct

### WASM Plugin Runtime (`src/plugin/`)
- **File paths**: All files exist as documented
  - `mod.rs` - Public API with `PluginManager` and `PluginManagerLifecycle`
  - `wasm_runtime.rs` - Core WASM execution using `wasmtime`
  - `instance_pool.rs` - `WasmInstancePool` with `WasmPooledInstance`
  - `pool.rs` - `PooledInstance` trait and struct
  - `axum_loader.rs` - Native `.so`/`.dylib`/`.dll` loading via `libloading`
  - `global.rs` - `GlobalPluginManager` and `GlobalWasmMemoryBudget`
  - `wasm_metrics.rs` - Atomic metrics collection

- **Key structs verified**:
  - `WasmPluginManager` (line 104 in wasm_runtime.rs) - manages multiple `WasmRuntime` instances
  - `WasmRuntime` (line 88) - single WASM module with engine, module, pool, linker
  - `WasmResourceLimits` (line 52) - resource constraints including `allowed_dht_prefixes`
  - `RequestContext` (line 515) - per-request data with timeout, env, DHT prefixes, body_receiver

- **Guest ABI Host Functions** (wasm_runtime.rs:693-1013):
  - `guest_alloc` / `guest_free` - memory allocation
  - `check_timeout` - wall-clock timeout enforcement (line 716-728)
  - `get_env` - environment variable access (line 731-778)
  - `mesh_query_dht` - DHT lookups with prefix restrictions (line 825-912)
  - `mesh_check_threat` - Threat intelligence lookups (line 914-962)
  - `mesh_emit_event` - Event publishing (line 964-1011)
  - `synvoid_read_body_chunk` - Streaming body reading (line 780-823)

- **DHT Prefix Restrictions** (line 849-872):
  - Sensitive prefixes hardcoded: `threat_indicator:`, `yara_rule:`, `yara_rules_manifest:`, `edge_attestation:`, `dns_zone:`, `dns_record:`, `dns_domain_reg:`
  - Default deny when `allowed_dht_prefixes` is empty
  - Returns `-2` for unauthorized queries

- **Instance Pooling**:
  - `WasmInstancePool` uses `VecDeque` protected by `parking_lot::Mutex` (instance_pool.rs:11-12)
  - `get()` pops from back, `return_instance()` pushes to back if under max_size
  - `WasmPooledInstance::prepare_for_request` (instance_pool.rs:219-233) resets body_receiver AND allowed_dht_prefixes
  - `PooledInstance::prepare_for_request` (pool.rs:15-26) does NOT reset body_receiver or allowed_dht_prefixes
  - Warmup creates instances with stub host functions (instance_pool.rs:85-215)

### Spin Framework Runtime (`src/spin/`)
- **File paths** all exist as documented
- `SpinRuntime` (runtime.rs:114) - owns wasmtime::Engine, optional manifest, HashMap of SpinAppInstance
- `SpinAppInstance` (runtime.rs:41) - wraps WasmRuntime (delegate pattern), manifest, component_id, KV store
- `Manifest` / `SpinManifest` (manifest.rs) - parses Spin v2 TOML format
- **Longest-prefix-match routing** verified at runtime.rs:280-299 via `find_route()`
- **KV store** is local-only (kv_store.rs) - no distribution via mesh/DHT
- **No WASI socket support** - only in-memory KV store, no outbound HTTP capability

### Serverless Function Execution (`src/serverless/`)
- **File paths** all exist as documented
- `ServerlessManager` (manager.rs:96) - owns HashMap of functions, pools, routes, config
- `InstancePool` (instance_pool.rs:89) - sophisticated pooling with autoscaling
- `ServerlessInstance` (instance_pool.rs:64) - wraps Arc<WasmRuntime>, tracks state and metrics
- **AsyncCompilationManager** (async_compilation.rs:117) - state machine: Pending -> Compiling -> Ready / Failed
- **Routing** (routing.rs) - supports Exact, Prefix, Suffix, Regex, Glob matching with MethodMatch

### Instance Pooling - Serverless
- `InstancePool::initialize()` pre-warms `pre_warm_instances` (instance_pool.rs:209-229)
- `get_instance()` - tries idle pool first, then scales up if under max (instance_pool.rs:243-270)
- `return_instance()` - moves to idle or evicts if timeout exceeded (instance_pool.rs:272-285)
- **Autoscaler** runs every 10s (instance_pool.rs:415-453):
  - Scale up: 50% of current, capped at `max_scale_up_per_tick` (default 5)
  - Scale down: 30% of current
  - Evicts instances idle beyond `idle_timeout_seconds`

### WAF Integration
- Document accurately describes WASM plugin execution in HTTP server pipeline
- Serverless runs AFTER WAF decision; can disable WAF per-route via `ServerlessWafMode::Off`
- Spin has no WAF integration

### HTTP Server Integration
- SpinHttpHandler dispatch at server.rs:2420-2503 (document says 2420-2503 - CORRECT)
- Actual SpinHttpHandler::new at line 2426

## Discrepancies Found

### Minor Line Number Discrepancy
- **Document claims**: `SpinHttpHandler at src/http/server.rs:2420-2503`
- **Actual**: Spin dispatch block starts at line 2420, `SpinHttpHandler::new` called at line 2426
- **Impact**: Low - the range is approximately correct

### Feature Comparison Table - Minor Inaccuracy
- **Document claims**: `plugin` has "Hot reload: Yes (file watcher)" and `serverless` has "Hot reload: No"
- **Verification**: The `PluginManagerLifecycle::enable_hot_reload()` does implement file watching, but serverless does not have hot reload - CORRECT

## Bugs Identified

### High Severity

**BUG-PLUGIN-1: Spin Creates New Instance Per Request (Cold-Start Bug)**
- **Location**: `src/spin/runtime.rs:258` (`instantiate_app()` called on every request)
- **Issue**: `SpinRuntime::handle_http_request()` calls `instantiate_app()` which creates a new `SpinAppInstance` for EVERY request. No instance reuse is implemented.
- **Impact**: Significant cold-start overhead on every request; defeats instance pooling purpose
- **Confirmed**: Per `src/plugin/AGENTS.override.md:21-25` - "Spin Cold-Start Bug (UNFIXED)"
- **Fix**: Cache `SpinAppInstance` by component_id for reuse across requests

### Medium Severity

**BUG-PLUGIN-2: Generic PooledInstance Does Not Reset DHT Prefixes or Body Receiver**
- **Location**: `src/plugin/pool.rs:15-26` (`PooledInstance::prepare_for_request`)
- **Issue**: The generic `PooledInstance` trait's `prepare_for_request` only resets `start`, `timeout`, `env`, and `fuel`. It does NOT reset `body_receiver` or `allowed_dht_prefixes`.
- **Impact**: When `WasmPool` trait is used generically (not the concrete `WasmInstancePool`), DHT prefix restrictions may leak between requests
- **Note**: The concrete `WasmPooledInstance::prepare_for_request` at `instance_pool.rs:219-233` correctly resets all fields including DHT prefixes

## Suggested Improvements

### Documentation Improvements

1. **Clarify line number reference**: The `SpinHttpHandler` integration at server.rs:2420-2503 should note the range covers the entire Spin dispatch block, with handler creation at line 2426

2. **Add version compatibility note**: The Spin manifest parsing supports v2 format - should be documented

3. **Document async compilation timing**: The `AsyncCompilationManager` uses oneshot channels - if a caller awaits twice, the second await returns "Already awaited" error (async_compilation.rs:99)

### Architecture Improvements

1. **Spin instance caching**: Implement `SpinAppInstance` caching by component_id to avoid cold-start on every request (per BUG-PLUGIN-1)

2. **Consider generic trait improvement**: The `PooledInstance::prepare_for_request` could accept optional DHT prefixes and body_receiver to match the concrete implementation

3. **Serverless warmup consistency**: The serverless `InstancePool` has `initialize()` for pre-warming, but `ServerlessManager::initialize()` doesn't call it - this could be added to ensure pre_warm_instances works as documented

4. **Spin manifest validation**: Currently missing validation that at least one component exports `handle_request` - WASM modules without this export will fail at invocation time with unclear error

### Security Improvements

1. **DHT prefix audit logging enhancement**: The unauthorized DHT query returns `-2` at line 871 but logging is at warn level - consider elevating to security event for audit trail

2. **Spin WASI isolation**: Currently `wasi_enabled: true` is hardcoded for Spin components (runtime.rs:196) - consider making this configurable per-component
