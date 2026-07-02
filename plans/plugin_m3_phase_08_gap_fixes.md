# Plugin M3 Phase 8: Gap Fixes

## Goal
Close the ~60% gap between the implemented Phase 8 code and the plan requirements.

## Priority 1 — Critical Security
1. **Production gate enforcement** — `load_plugin()` must check `is_production`, `allow_in_production`, `risk_acknowledgement`, `allowed_dirs` before proceeding. Error variants exist but are dead code.
2. **FFI panic catching** — Wrap `factory()` and `Box::from_raw()` in `std::panic::catch_unwind` to prevent UB from native panics crossing FFI boundary.
3. **Hot-reload gating** — `enable_hot_reload()` must check `hot_reload_enabled` config before watching native extensions.

## Priority 2 — Correctness
4. **Fix overly strict permission check** — Current code rejects `0o644`/`0o744`. Plan says "reject world-writable" only. Remove the `0o755`/`0o500` exact-match check.
5. **Reload generation semantics** — Add `generation: u64` field to `UnsafeNativeExtension`. Increment on reload. Include in status.

## Priority 3 — Missing Features
6. **Deprecated config alias** — `native_plugins_enabled` → `unsafe_native_enabled` with deprecation warning.
7. **Metrics counters** — Add `synvoid_unsafe_native_extension_{loaded_total,load_failed_total,reloaded_total}` counters in `wasm_metrics.rs`.
8. **`last_load_error` in status** — Track last load failure in `PluginManager`.
9. **Audit logging** — Structured audit event on load/reject/unload.

## Priority 4 — Low
10. **`ExternalPluginClient` placeholder trait** — Add trait in `unsafe_native_loader.rs`.

## Priority 5 — Tests
11. **Write all 24 plan tests** across WS1, WS2, WS4, WS6.

## Validation
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p synvoid-plugin-runtime
```
