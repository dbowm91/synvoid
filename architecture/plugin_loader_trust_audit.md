# Plugin Loader Trust Audit (Phase 13)

Status: Audit complete. Enforcement implemented in Phase 13.

Scope: Every code path that loads, reloads, or hot-reloads a plugin. Verifies trust-tier enforcement, signature verification, and dev-mode gating.

## Loader Inventory

| # | Loader path | File | Trust tier source | Signature behavior | Dev-mode behavior | Production behavior | Status |
|---|-------------|------|-------------------|--------------------|-------------------|---------------------|--------|
| 1 | `WasmPluginManager::load_plugin(path)` | wasm_runtime.rs | None | No check | No check | Loads any WASM | Enforced |
| 2 | `WasmPluginManager::load_plugin_from_memory(name, data, limits)` | wasm_runtime.rs | None | No check | No check | Loads any WASM | Enforced |
| 3 | `WasmPluginManager::load_plugin_from_memory_with_priority` | wasm_runtime.rs | None | No check | No check | Loads any WASM | Enforced |
| 4 | `WasmPluginManager::load_plugin_with_limits(path, limits)` | wasm_runtime.rs | None | No check | No check | Loads any WASM | Enforced |
| 5 | `WasmPluginManager::reload_plugin(path)` | wasm_runtime.rs | None | No check | No check | Loads any WASM | Enforced |
| 6 | `WasmPluginManager::reload_plugin_by_name(name)` | wasm_runtime.rs | None | Delegates to #5 | Delegates to #5 | Delegates to #5 | Enforced |
| 7 | `axum_loader::load_plugin(path)` (crate) | axum_loader.rs | None | No check | No check | Loads .so/.dylib/.dll | Enforced |
| 8 | `PluginManager::load_wasm_plugin(path)` (root) | src/plugin/mod.rs | None | Delegates | Delegates | Delegates | Enforced |
| 9 | `PluginManager::load_wasm_plugin_from_bytes(name, bytes)` | plugin_manager.rs | None | Delegates | Delegates | Delegates | Enforced |
| 10 | `PluginManager::load_axum_plugin(path)` | plugin_manager.rs | None | Delegates | Delegates | Delegates | Enforced |
| 11 | `PluginManagerLifecycle::load_plugins_from_dir(dir)` | plugin_manager.rs | None | Delegates per file | Delegates per file | Delegates per file | Enforced |
| 12 | `PluginManagerLifecycle::load_axum_plugins_from_dir(dir)` | plugin_manager.rs | None | Delegates per file | Delegates per file | Delegates per file | Enforced |
| 13 | `PluginManagerLifecycle::enable_hot_reload(dir)` | plugin_manager.rs | None | No check | No check | Loads on file change | Enforced |
| 14 | `PluginManagerLifecycle::reload_plugin(path)` | plugin_manager.rs | None | Delegates | Delegates | Delegates | Enforced |
| 15 | `PluginRuntimeOwner::load_configured_plugins` | src/server/plugin_runtime.rs | Config entries | Delegates per entry | Delegates per entry | Delegates per entry | Enforced |
| 16 | `PluginRuntimeOwner::enable_hot_reload_if_configured` | src/server/plugin_runtime.rs | None | Delegates | Delegates | Delegates | Enforced |
| 17 | Admin POST `/plugins/{name}/reload` | src/admin/handlers/plugins.rs | None | Delegates | Delegates | Delegates | Enforced |
| 18 | `ServerlessFunctionManager::load_function_wasm` (mesh) | serverless/manager.rs | None | Delegates | Delegates | Delegates | Enforced |
| 19 | `ServerlessFunctionManager::load_function_wasm` (file) | serverless/manager.rs | None | Delegates | Delegates | Delegates | Enforced |
| 20 | `SpinRuntime::instantiate_app(component_id)` | spin/runtime.rs | Spin manifest | No check | No check | Loads WASM from Spin manifest | Enforced |
| 21 | `InstancePool::new` (serverless) | serverless/instance_pool.rs | None | Delegates | Delegates | Delegates | Enforced |

## Enforcement Architecture

All loader paths converge on `enforce_plugin_load_policy()` which enforces:

```
match trust_tier {
    Disabled => Err(Disabled),
    SignedSandboxed => verify_plugin_signature()?,
    DevelopmentHotReload if !config.dev_mode => Err(DevHotReloadNotAllowed),
    LocalTrusted if !config.allow_local_trusted => Err(LocalTrustedNotAllowed),
    _ => Ok(()),
}
```

### Signature Verification (SignedSandboxed)

1. Manifest must contain a `[signature]` block with `binary_sha256`, `manifest_sha256`, `key_id`, `algorithm`, and `signature`.
2. Binary SHA-256 is computed and compared to manifest hash.
3. Canonical manifest signing payload is computed (excludes signature field).
4. Trusted public key is resolved by `key_id` from config.
5. Ed25519 signature is verified against the canonical payload.
6. Unknown key ID, malformed key, or mismatched hash → fail closed.

### DevelopmentHotReload Gating

- `DevelopmentHotReload` trust tier requires `dev_mode = true` in plugin config.
- In production (default), `DevelopmentHotReload` is rejected.
- Hot-reload watcher uses the same trust policy as initial load.

### Fail-Closed Behavior

- Missing signature on `SignedSandboxed` → rejected.
- Unknown key ID → rejected.
- Binary hash mismatch → rejected.
- Manifest hash mismatch → rejected.
- `VerificationUnavailable` (crypto lib missing) → rejected for `SignedSandboxed`.
- New loader paths → fail closed until classified.

## Trusted Key Configuration

Trusted public keys are configured in the plugin config:

```toml
[plugins]
dev_mode = false
allow_local_trusted = false

[[plugins.trusted_keys]]
key_id = "operator-key-1"
algorithm = "ed25519"
public_key = "base64-url-no-pad..."

[[plugins.trusted_keys]]
key_id = "ci-key-1"
algorithm = "ed25519"
public_key = "base64-url-no-pad..."
```

Rules:
- Missing key file → fail closed for `SignedSandboxed`.
- Unknown key ID → fail closed.
- Malformed key → fail closed.
- Development/test keys accepted only when `dev_mode = true`.
- Plugin manifests cannot specify arbitrary key paths.

## Known Historical Gaps (Pre-Phase 13)

Before Phase 13, the trust-tier and signing infrastructure existed but was never invoked from any loading path:

- `PluginTrustTier` enum was defined but not checked at load time.
- `verify_signing_policy()` was implemented and tested but never called.
- `DevelopmentHotReload` docstring required `dev_mode` but no caller checked it.
- All WASM files were loaded regardless of declared trust tier.
- `PluginManifest::from_file()` was never called from runtime code.
- Mesh-distributed WASM was loaded without signature verification.
