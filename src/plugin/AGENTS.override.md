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

## DHT Prefix Enforcement (2026-05-23)

DHT prefix restrictions (`allowed_dht_prefixes`) are now properly propagated to pooled instances:

- `prepare_for_request()` accepts `allowed_dht_prefixes` parameter
- `filter_request()` and `transform_response()` pass `self.limits.allowed_dht_prefixes.clone()`
- Warm instances no longer reset restrictions to empty

### Prior Bug (FIXED): DHT prefix propagation in pooled instances

The bug caused `default_allowed_dht_prefixes` to be `Vec::new()` from warmup, effectively disabling restriction enforcement for pooled instances. Fixed as above.

## Spin Runtime Updates (2026-05-23)

`SpinRuntime::run_supervisor()` was removed as dead code. The Spin runtime creates fresh instances per request (`handle_http_request` calls `instantiate_app` on every request), so instance pooling and idle eviction were never needed.

## Known Bugs (FIXED)

- BUG-2 (body_receiver reset): Fixed
- BUG-3 (warmup linking): Fixed
- Spin find_route(): Verified as longest-prefix-match

## Skills Reference

- `skills/spin_wasm.md` — Spin WASM runtime
- `skills/serverless_wasm.md` — Serverless WASM patterns
- `skills/wasm_components.md` — WASM component model patterns