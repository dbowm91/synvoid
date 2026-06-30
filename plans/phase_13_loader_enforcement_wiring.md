# Plan: Wire enforce_plugin_load_policy into All Loader Paths

Status: completed.

## Problem

`enforce_plugin_load_policy` exists in `sandbox/types.rs` but is never called from any loader path. All 16+ loader entry points bypass trust-tier enforcement.

## Approach: Manager-Level Enforcement

Add `PluginLoadConfig` to `WasmPluginManager`. Before every `WasmRuntime::load*` call inside the manager, look up the manifest and call `enforce_plugin_load_policy`. This catches all loader paths (WASM, hot-reload, serverless) with only 4 enforcement sites.

## Changes

### 1. `crates/synvoid-plugin-runtime/src/wasm_runtime.rs`

- Add `load_config: PluginLoadConfig` field to `WasmPluginManager`
- Add `with_load_config(config)` builder and `set_load_config(config)` setter
- Add private helper `fn enforce_before_load(path, manifest, binary_bytes)` that calls `enforce_plugin_load_policy`
- Add private helper `fn discover_manifest(path)` that looks for `synvoid-plugin.toml` alongside the `.wasm` file; returns default `LocalSandboxed` manifest if not found
- Wire enforcement into: `load_plugin`, `load_plugin_from_memory_with_priority`, `load_plugin_with_limits`, `reload_plugin`

### 2. `crates/synvoid-plugin-runtime/src/plugin_manager.rs`

- Wire `PluginLoadConfig` through `PluginManager` (store on `wasm_manager` via `with_load_config`)
- Add `set_load_config` on `PluginManager` that delegates to `wasm_manager`

### 3. `src/plugin/mod.rs` (root-level PluginManager)

- Wire `PluginLoadConfig` through the root-level `PluginManager`
- Pass config to `WasmPluginManager` on construction

### 4. `src/server/plugin_runtime.rs`

- Construct `PluginLoadConfig` from app config in `PluginRuntimeOwner::new` or `load_configured_plugins`
- Pass to `PluginManager`

### 5. `tests/plugin_signature_policy_guard.rs`

- Harden `all_load_paths_call_enforcement` from soft to hard

## Backward Compatibility

- `WasmPluginManager::new()` gets a default `PluginLoadConfig` (dev_mode=false, allow_local_trusted=false, no trusted_keys) — matches production defaults
- Plugins without a `synvoid-plugin.toml` get a default `LocalSandboxed` manifest — no behavior change for existing unsigned plugins
- `SignedSandboxed` plugins without a TOML will fail closed (no signature to verify) — this is the correct security behavior

## Verification

```bash
cargo test --test plugin_signature_policy_guard
cargo test -p synvoid-plugin-runtime
cargo fmt --all -- --check
```
