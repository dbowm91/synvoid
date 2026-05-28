# WASM & Plugins Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/plugin_wasm.md`, `architecture/plugin_deep_dive.md`, `architecture/serverless.md`, `architecture/spin.md`

## Verified Correct Items

- **File structure**: All documented files exist (`src/plugin/{mod.rs, wasm_runtime.rs, instance_pool.rs, pool.rs, axum_loader.rs, global.rs, wasm_metrics.rs}`, `src/spin/{mod.rs, runtime.rs, manifest.rs, handler.rs, kv_store.rs}`, `src/serverless/{mod.rs, manager.rs, instance_pool.rs, async_compilation.rs, registry.rs, routing.rs, scheduler.rs}`)
- **WasmResourceLimits**: Struct definition and defaults match (max_memory_mb=64, max_cpu_fuel=1M, timeout_seconds=30, max_instances=1, wasi_enabled=false, allowed_dht_prefixes=empty) at `wasm_runtime.rs:52-76`
- **RequestContext**: Struct definition and ResourceLimiter impl match at `wasm_runtime.rs:514-543`
- **GuestExports**: Struct definition matches at `wasm_runtime.rs:79-86`
- **PooledInstance**: Struct definition and fields match at `pool.rs:7-13`
- **WasmInstancePool**: Struct definition matches at `instance_pool.rs:11-16`
- **WasmPooledInstance**: Struct definition matches at `instance_pool.rs:18-24`
- **WasmRuntime**: Struct definition matches at `wasm_runtime.rs:88-96`
- **WasmPluginManager**: Struct definition matches at `wasm_runtime.rs:104-112`
- **PluginManager**: Struct definition matches at `mod.rs:41-44`
- **PluginManagerLifecycle**: Struct definition matches at `mod.rs:202-207`
- **WasmPluginError**: Enum variants match at `mod.rs:28-37`
- **WasmFilterResult**: Enum variants match at `mod.rs:21-25`
- **AxumPluginError**: Enum variants match at `mod.rs:184-191`
- **GlobalPluginManager**: Struct definition and methods match at `global.rs:117-160`
- **GlobalWasmMemoryBudget**: Struct and methods match at `global.rs:24-109`
- **WasmPluginMetrics**: Struct and methods match at `wasm_metrics.rs:22-31`
- **WasmMetrics functions**: All `record_wasm_*` and `get_wasm_*` functions exist at `wasm_metrics.rs:100-166`
- **Engine config**: `cranelift_opt_level(SpeedAndSize)`, `max_wasm_stack(1 << 20)`, `memory_init_cow(true)`, `consume_fuel(true)` at `wasm_runtime.rs:564-572`
- **Host function signatures**: All documented host functions (`abort`, `check_timeout`, `get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event`) are linked at `wasm_runtime.rs:692-1013`
- **DHT prefix validation**: Sensitive prefix list and logic match at `wasm_runtime.rs:849-872`
- **Header serialization**: Binary format `[header_count: u16][name_len: u16][name][value_len: u16][value]` at `wasm_runtime.rs:1238-1256`
- **Guest ABI type signatures**: `FilterRequestFn`, `TransformResponseFn`, `HandleRequestFn`, `GuestAllocFn`, `GuestFreeFn` at `wasm_runtime.rs:30-49`
- **Feature gate locations**: `#[cfg(feature = "mesh")]` at `mod.rs:66`, `wasm_runtime.rs:874`, `wasm_runtime.rs:936`, `wasm_runtime.rs:998` — all verified correct
- **wasmtime version**: `42.0.2` with `component-model` feature at `Cargo.toml:196`
- **SpinRuntimeConfig**: Struct and defaults match at `runtime.rs:17-38` (max_instances=10, default_timeout_seconds=30, idle_timeout_seconds=300)
- **SpinAppInstance**: Struct definition matches at `runtime.rs:41-50`
- **SpinRuntime**: Struct definition matches at `runtime.rs:119-127`
- **SpinHttpHandler**: Struct definition matches at `handler.rs:117-119`
- **SpinAppsManager**: Struct definition matches at `handler.rs:177-179`
- **SpinRequest/SpinResponse**: Definitions match at `handler.rs:9-15`, `handler.rs:48-53`
- **SpinHandlerError**: Enum matches at `handler.rs:108-115`
- **SpinRuntimeError**: Enum matches at `runtime.rs:341-359`
- **SpinManifest**: Struct matches at `manifest.rs:7-22` (has `spin_version`, `manifest_version`, etc.)
- **SpinManifestError**: Enum matches at `manifest.rs:148-157`
- **SpinKvStore/SpinKvEntry**: Definitions match at `kv_store.rs:5-15`
- **SPIN_APPS_MANAGER global**: Matches at `handler.rs:236-241`
- **Admin API endpoints**: All documented endpoints exist in `admin/handlers/spin.rs` (list, create, delete, manifest, instances)
- **CreateSpinAppRequest**: Struct matches at `admin/handlers/spin.rs:43-48`
- **Spin WASM integration in http/server.rs**: Lines 2419-2503 (handler creation at 2425) match docs
- **WASM filter integration in http/server.rs**: Lines 3050-3060 match docs
- **ServerlessConfig**: Struct matches at `crates/synvoid-config/src/serverless.rs:6-19`
- **FunctionDefinition**: Core fields match at `crates/synvoid-config/src/serverless.rs:34-75`
- **CallerContext**: Struct matches at `manager.rs:22-30`
- **ServerlessError**: Enum matches at `manager.rs:57-78`
- **ServerlessFunction**: Struct matches at `manager.rs:81-85`
- **ServerlessResponse**: Struct matches at `manager.rs:87-94`
- **InstancePoolConfig**: Struct and defaults match at `instance_pool.rs:11-37`
- **InstanceMetrics**: Struct matches at `instance_pool.rs:40-48`
- **ServerlessInstance**: Struct matches at `instance_pool.rs:64-71`
- **InstanceState**: Enum matches at `instance_pool.rs:73-79`
- **InstancePoolMode**: Enum matches at `instance_pool.rs:82-87`
- **InstancePool**: Struct matches at `instance_pool.rs:89-101`
- **SERVERLESS_ENGINE_POOL**: Global matches at `instance_pool.rs:103-105`
- **RouteMatch**: Enum matches at `routing.rs:6-15`
- **FunctionMetadata/FunctionStats**: Structs match at `registry.rs:9-27`
- **ServerlessRegistry**: Struct and methods match at `registry.rs:29-80`
- **AsyncCompilationHandle/Manager**: Exist at `async_compilation.rs:34-39`
- **handle_serverless_function**: Signature matches at `manager.rs:1049-1056`
- **handle_serverless_function_streaming**: Signature matches at `manager.rs:1224-1231`
- **Spin cold-start instance reuse**: Fixed per AGENTS.md — `get_or_create_instance()` properly caches with 5-min idle timeout at `runtime.rs:289-302`
- **PooledInstance DHT prefix leak**: Fixed per AGENTS.md — both `pool.rs:25-26` and `instance_pool.rs:228-229` reset `body_receiver` and `allowed_dht_prefixes`
- **AGENTS.md cross-references**: All "Verified Already Fixed" items relevant to WASM/Plugins are accurate

## Discrepancies Found

1. **`spin.md` Section 2.2 `Manifest` struct is actually `SpinManifest`**: The doc shows `Manifest` with fields `spin_version`, `manifest_version`, `description`, `authors`, `triggers`, `components` (lines 81-91). This is the `SpinManifest` struct (`manifest.rs:7-22`). The actual `Manifest` struct (`manifest.rs:79-87`) has only `name`, `version`, `trigger_type`, `components`. The doc conflates these two types.

2. **`plugin_deep_dive.md` line 108 incorrect claim about `PooledInstance`**: States "the generic `PooledInstance::prepare_for_request` (in `pool.rs:15-26`) does NOT reset body_receiver or DHT prefixes." This is **false** — `pool.rs:25-26` clearly resets both `body_receiver` and `allowed_dht_prefixes`. The doc was written when only `WasmPooledInstance` had the fix, but both were fixed.

3. **`serverless.md` Section 12 `FunctionDefinition.require_trusted_caller`**: Doc shows `Option<bool>` but actual type is `bool` (`crates/synvoid-config/src/serverless.rs:68`). Similarly `allowed_dht_prefixes` is `Vec<String>` not `Option<Vec<String>>` (line 74).

4. **`serverless.md` `FunctionDefinition.path` is `String` not `Option<String>`**: Doc shows `pub path: Option<String>` but actual type is `pub path: String` (`crates/synvoid-config/src/serverless.rs:36`).

5. **`serverless.md` `handle_serverless_function_streaming` doc says `#[cfg(feature = "mesh")]`**: The actual function at `manager.rs:1224` has **no** `#[cfg(feature = "mesh")]` attribute. It's available in all builds.

6. **`serverless.md` missing `handler` field in `FunctionDefinition`**: Doc omits `pub handler: String` field (`crates/synvoid-config/src/serverless.rs:38`). This is the WASM export function name (default: `"handle_request"`).

7. **`plugin_wasm.md` Section 2 warmup stub count**: Doc says "7 stub host functions" but `instance_pool.rs:85-183` registers 7 stubs: `abort`, `check_timeout`, `get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event`. The doc at line 579 lists "stub host functions" correctly but `plugin_deep_dive.md` line 109 says "6 stub host functions" — should be 7.

## Bugs Identified

1. **Spin runtime has no idle instance eviction**: `SpinRuntime` has no supervisor task or background eviction despite `plugin_deep_dive.md` line 167 claiming "Runs a supervisor task for idle eviction and health checks." The `get_or_create_instance()` at `runtime.rs:289-302` checks `is_idle(Duration::from_secs(300))` but never removes the idle entry from the `cached_instances` HashMap — it just overwrites it. Old `instances` entries (tracked by UUID) are never cleaned up. This is a slow memory leak as every `instantiate_app()` call creates a new UUID-keyed entry in `self.instances` that is never removed.

2. **`ServerlessScheduler` not publicly exported**: `src/serverless/scheduler.rs` exists but `src/serverless/mod.rs` does not include `pub mod scheduler` or any `pub use` for it. The `serverless.md` doc references it but it's inaccessible outside the crate.

3. **`plugin_deep_dive.md` claims `SpinHttpHandler` is at `src/http/server.rs:2421-2503`**: The actual SpinHttpHandler dispatch block is at lines 2419-2502, but the handler *creation* is at line 2425. The doc says "handler creation at line 2426" but it's at 2425.

## Suggested Improvements

1. **Add Spin idle eviction**: Implement a background supervisor task (like serverless `InstancePool::run_autoscaler`) in `SpinRuntime` to periodically evict idle instances from both `cached_instances` and `instances` HashMaps. Without this, memory grows unbounded as old instances accumulate.

2. **Export `ServerlessScheduler`**: Add `pub mod scheduler` to `src/serverless/mod.rs` and re-export `ServerlessScheduler` if it's intended for external use.

3. **Clarify `Manifest` vs `SpinManifest` in docs**: The `spin.md` architecture doc should clearly separate `SpinManifest` (TOML deserialization target) from `Manifest` (parsed/runtime representation) and document both structs.

4. **Add `handler` field to `FunctionDefinition` documentation**: `serverless.md` Section 9 should document the `handler` field which specifies which WASM export to invoke (default: `handle_request`).

5. **Consider adding `#[cfg(feature = "mesh")]` to `handle_serverless_function_streaming`**: The streaming variant is mesh-only in practice (uses `CallerContext`), but the attribute is missing. Either add it for consistency or document why it's intentionally always available.

6. **Document Spin memory leak in `instances` HashMap**: The `instances` HashMap keyed by UUID grows indefinitely. Either use `remove_instance()` explicitly or implement background cleanup.

## Stale Content

1. **`plugin_deep_dive.md` line 108 about `PooledInstance` not resetting fields**: This was true before the fix but is now incorrect. Both `PooledInstance::prepare_for_request` and `WasmPooledInstance::prepare_for_request` reset `body_receiver` and `allowed_dht_prefixes`.

2. **`spin.md` Section 2.2 `Manifest` struct**: Describes `SpinManifest` fields but labels it `Manifest`. The actual `Manifest` struct is a simplified parsed form.

3. **`spin.md` Section 2.1 `SpinRuntime` description**: Claims "Runs a supervisor task for idle eviction and health checks" — no such task exists in the code.

4. **`plugin_deep_dive.md` line 109 stub count**: Says "6 stub host functions" but there are 7.

5. **`serverless.md` Section 9 `FunctionDefinition` schema**: Multiple field types are incorrect (`path` is `String` not `Option<String>`, `require_trusted_caller` is `bool` not `Option<bool>`, `allowed_dht_prefixes` is `Vec<String>` not `Option<Vec<String>>`, `handler` field missing).

## Cross-Reference Status

| AGENTS.md Item | Status |
|---------------|--------|
| Spin cold-start instance reuse | ✅ Verified — `get_or_create_instance()` at `runtime.rs:289-302` caches with 5-min idle timeout |
| PooledInstance DHT prefix leak | ✅ Verified — Both `pool.rs:25-26` and `instance_pool.rs:228-229` reset `body_receiver` and `allowed_dht_prefixes` |
| WASM plugin support always enabled | ✅ Verified — `Cargo.toml:196` has `wasmtime` with no feature gate |
| `mesh` feature gate locations | ✅ Verified — 4 locations: `mod.rs:66`, `wasm_runtime.rs:874,936,998` |
| Spin header serialization (JSON vs binary) | ✅ Verified — `SpinRuntime::serialize_headers_spin` uses JSON (`runtime.rs:325-333`), `WasmRuntime::serialize_headers` uses binary (`wasm_runtime.rs:1242-1256`) |
| `SpinAppsManager` location | ✅ Verified — `handler.rs:177` (doc says `handler.rs`, correct) |
| Spin Admin API endpoints | ✅ Verified — All 5 endpoints exist in `admin/handlers/spin.rs` |
| `SpinHandlerError` naming | ✅ Verified — Matches `spin.md` (not `SpinHandlerError` vs `SpinHandlerError`) |
| `ServerlessScheduler` mentioned in `serverless.md` | ⚠️ File exists but NOT publicly exported from `mod.rs` |
| `handle_serverless_function_streaming` mesh-only | ⚠️ Doc says `#[cfg(feature = "mesh")]` but code has no such attribute |
| `FunctionDefinition` config fields | ⚠️ Multiple type mismatches between docs and actual config struct |
