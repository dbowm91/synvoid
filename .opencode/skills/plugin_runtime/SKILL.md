---
name: plugin_runtime
description: Sandboxed WASM plugin runtime — trust tiers, ABI frames, instance pooling, generation-aware hot-reload, native-extension boundary. Use when adding plugins, touching the ABI, or changing load/reload paths.
---

# Skill: Plugin Runtime

## Context

Canonical implementation lives in `crates/synvoid-plugin-runtime`;
`src/plugin/` is a re-export facade (do not add logic there). Serverless
WASM functions are a separate consumer (see `serverless_wasm` skill).
Full reference: `architecture/plugin_deep_dive.md`,
`architecture/plugin_runtime_sandbox.md`, `architecture/plugin_wasm.md`,
`architecture/plugin_loader_trust_audit.md`,
`architecture/unsafe_native_extensions.md`.

## When to Use

- Adding or modifying a WASM plugin hook or capability
- Touching ABI frame serialization or guest-memory access
- Changing plugin load / hot-reload / unload paths
- Working on the native-extension boundary

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-plugin-runtime/src/plugin_manager.rs` | `PluginManager`: load/unload across WASM, Axum, and native-extension paths |
| `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` | wasmtime engine, `WasmResourceLimits`, trust tiers |
| `crates/synvoid-plugin-runtime/src/instance_pool.rs`, `pool.rs` | Instance pooling |
| `crates/synvoid-plugin-runtime/src/abi_frame.rs` | Canonical frame serialization (`serialize_headers_canonical`, `build_request_frame`) — the ONLY frame path |
| `crates/synvoid-plugin-runtime/src/sandbox/` | Capability enforcement |
| `crates/synvoid-native-extension/src/loader.rs` | Native loader behind `NativeExtensionBackend` (never raw `Library` handles) |

## Non-Negotiables

1. **Own hot-reload watchers with `PluginRuntimeOwner`, never
   `std::mem::forget`.** Reload is prepare-then-commit: a failed reload
   must never replace a working plugin.
2. **Guest pointer ops require `guest_alloc`/`guest_free` +
   `checked_guest_range`.** Frame serialization only via
   `abi_frame::serialize_headers_canonical` / `build_request_frame`.
3. **Empty `binary_sha256`/`manifest_sha256` rejected in production.**
4. **Native extensions are doubly gated**: compile feature
   `unsafe-native-extensions` (off by default) PLUS runtime gates (disabled
   by default; production needs explicit risk acknowledgement + path
   allowlist). NOT sandboxed; `catch_unwind` catches Rust panics only.
   Retain the `Library` handle via `Arc` for the lifetime of derived values.
5. Implement in the crate, never the root shim (`src/plugin/`).

## Verification

```bash
cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci
cargo nextest run -p synvoid-native-extension --cargo-profile ci --profile ci
```
