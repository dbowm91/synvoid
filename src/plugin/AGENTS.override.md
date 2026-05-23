# Plugin/WASM Module - AGENTS.override.md

Specialized guidance for WASM plugin runtime.

## Hot Path

`src/plugin/wasm_runtime.rs` — WASM plugin filter/transform per request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### WASM Instance Management

- Instance pooling reduces instantiation overhead
- Memory buffers should be reused across invocations

## Known Bugs (2026-05-23)

### BUG-2: body_receiver not reset in pooled instance

`prepare_for_request()` in `src/plugin/instance_pool.rs:152-164` doesn't reset `body_receiver`. When a pooled instance is reused, `body_receiver` from the previous request may still be set, causing `synvoid_read_body_chunk()` to return `None` (EOF) immediately on subsequent requests that should have a body.

**Fix**: Add `self.store.data_mut().body_receiver = None;` in `prepare_for_request()`.

### BUG-3: warmup() doesn't link all required functions

`warmup()` at `src/plugin/instance_pool.rs:79-148` only links `abort` and `check_timeout`. The following functions are NOT linked during warmup, making them unavailable on warm instances:
- `get_env`
- `synvoid_read_body_chunk`
- `mesh_query_dht`
- `mesh_check_threat`
- `mesh_emit_event`

Note: `mesh_check_threat` IS properly implemented at `wasm_runtime.rs:946-960` with DHT integration when the `mesh` feature is enabled, but it's unavailable on warm instances because `warmup()` doesn't link it.

### Spin find_route() - Longest Prefix Match Not Implemented

`src/spin/runtime.rs:271-285` returns the first matching route, not the longest-prefix-match. More specific routes can be shadowed by less specific ones if defined earlier in the manifest.

## Skills Reference

- `skills/spin_wasm.md` — Spin WASM runtime
- `skills/serverless_wasm.md` — Serverless WASM patterns
- `skills/wasm_components.md` — WASM component model patterns