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

## Known Bugs (Still Present as of 2026-05-23)

### DHT Prefix Propagation Bug (UNFIXED)

Both `src/serverless/instance_pool.rs:186` and `src/plugin/instance_pool.rs:186` set `allowed_dht_prefixes: Vec::new()` during warmup, ignoring configured values. This is a **known bug** that affects pooled WASM instances.

Fix requires setting `allowed_dht_prefixes` from `WasmResourceLimits` during warmup (instance_pool.rs:79-209 warmup flow).

### Spin Cold-Start Bug (UNFIXED)

`src/spin/runtime.rs:251` creates new `SpinAppInstance` per request via `instantiate_app()`. No instance reuse is implemented, causing significant cold-start overhead on every request.

Workaround: Consider caching SpinAppInstance by component_id for reuse across requests.

## Skills Reference

- `skills/spin_wasm.md` — Spin WASM runtime
- `skills/serverless_wasm.md` — Serverless WASM patterns
- `skills/wasm_components.md` — WASM component model patterns