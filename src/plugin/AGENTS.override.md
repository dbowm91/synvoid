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

### PooledInstance Lifecycle

The `PooledInstance` trait in `src/plugin/pool.rs:15-31` requires `prepare_for_request()` to reset all fields:
- `start`, `timeout`, `env`, `fuel` (basic resets)
- `allowed_dht_prefixes` - MUST be reset to prevent DHT prefix leakage between requests
- `body_receiver` - MUST be reset to `None` to prevent body receiver leakage

See `src/plugin/instance_pool.rs:219-233` for the correct pattern.

### Spin Manifest Validation

Spin manifest parsing (`src/spin/manifest.rs`) now validates:
- HTTP triggers require at least one component with a `url` route defined
- If not, returns `SpinManifestError::NoHttpRoutes`

### Spin WASI Configuration

Spin components can now configure WASI per-component via manifest:

```toml
[[components]]
id = "main"
source = "target/wasm32-wasi/release/my_app.wasm"

[components.wasi]
enabled = true  # or false to disable
```

Defaults to `true` if not specified (backward compatible).

## Known Bugs (Fixed)

### Spin Cold-Start Bug (FIXED 2026-05-26)

`src/spin/runtime.rs:251` created new `SpinAppInstance` per request via `instantiate_app()`. No instance reuse was implemented, causing significant cold-start overhead on every request.

**Fix**: `SpinRuntime` now has `cached_instances` field (line 123) and `get_or_create_instance()` method (lines 288-295) that caches and reuses `SpinAppInstance` by component_id with 5-minute idle timeout. The `reuse()` method on `SpinAppInstance` (lines 103-105) updates request timestamps without creating new instances.

### PooledInstance DHT/Body Leak (PLUGIN-2 - FIXED 2026-05-27)

`src/plugin/pool.rs:15-31` - The generic `PooledInstance` trait's `prepare_for_request()` now properly resets:
- `start`, `timeout`, `env`, `fuel` (basic resets)
- `allowed_dht_prefixes` - now properly reset
- `body_receiver` - now properly reset to `None`

### Spin WASI Isolation (PLUGIN-11 - FIXED 2026-05-27)

`src/spin/runtime.rs:196-209` - WASI is now configurable per-component via manifest. Defaults to `true` if not specified.

### Unauthorized DHT Query Logging (PLUGIN-10 - FIXED 2026-05-27)

At `src/plugin/wasm_runtime.rs:867`, unauthorized DHT queries now log at `error` level for security audit trail.

### Serverless Warmup (PLUGIN-8 - FIXED 2026-05-27)

`src/serverless/manager.rs:464-471` - `InstancePool::initialize()` is now called from `ServerlessManager::initialize()` to pre-warm instances before the autoscaler begins.

## Skills Reference

- `skills/spin_wasm.md` — Spin WASM runtime
- `skills/serverless_wasm.md` — Serverless WASM patterns
- `skills/wasm_components.md` — WASM component model patterns
