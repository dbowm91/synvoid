# Plugin/WASM Module - AGENTS.override.md

Specialized guidance for WASM plugin runtime.

## Hot Path

`src/plugin/wasm_runtime.rs` — WASM plugin filter/transform per request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools.

## Module-Specific Patterns

### WASM Instance Management

- Instance pooling reduces instantiation overhead
- Memory buffers should be reused across invocations

## Known Bugs

### Spin Cold-Start Bug (FIXED 2026-05-26)

`src/spin/runtime.rs:251` created new `SpinAppInstance` per request via `instantiate_app()`. No instance reuse was implemented, causing significant cold-start overhead on every request.

**Fix**: `SpinRuntime` now has `cached_instances` field (line 123) and `get_or_create_instance()` method (lines 288-295) that caches and reuses `SpinAppInstance` by component_id with 5-minute idle timeout. The `reuse()` method on `SpinAppInstance` (lines 103-105) updates request timestamps without creating new instances.

### DHT Prefix Propagation (FIXED previously)

`allowed_dht_prefixes` now correctly propagated to pooled instances.

### PooledInstance DHT/Body Leak (PLUGIN-2 - P1)

`src/plugin/pool.rs:15-26` - The generic `PooledInstance` trait's `prepare_for_request()` only resets:
- `start`, `timeout`, `env`, `fuel`

Missing resets for:
- `allowed_dht_prefixes`
- `body_receiver`

The concrete `WasmPooledInstance` at `src/serverless/instance_pool.rs:219` correctly resets all fields.

### Spin WASI Isolation (PLUGIN-11 - P1)

`src/spin/runtime.rs:196` - `wasi_enabled: true` is hardcoded for all Spin components. Should be configurable per-component in Spin manifest.

### Unauthorized DHT Query Logging (PLUGIN-10 - P1)

At `src/plugin/wasm_runtime.rs:871`, unauthorized DHT queries return `-2` but logging is at `warn` level. Should elevate to security event level for audit trail.

## Skills Reference

- `skills/spin_wasm.md` — Spin WASM runtime
- `skills/serverless_wasm.md` — Serverless WASM patterns
- `skills/wasm_components.md` — WASM component model patterns