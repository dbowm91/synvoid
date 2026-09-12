# Unsafe Native Extensions

## Overview

SynVoid distinguishes between two plugin models with fundamentally different security properties:

1. **WASM Plugins** — Sandboxed WebAssembly modules with trust tiers, capability manifests, signing, fuel/epoch limits, and failure isolation. This is the production-safe plugin model.

2. **Unsafe Native Extensions** — Shared libraries loaded via `libloading` that run with full SynVoid process authority. These are NOT sandboxed and must only be loaded from trusted sources.

## Capability Isolation (Phase 28)

Loading authority for native extensions is isolated from the ordinary
sandboxed plugin-runtime dependency surface:

- `synvoid-plugin-runtime`: sandboxed WASM/plugin manifests/capabilities/ABI/lifecycle only. Its default dependency graph contains **no** `libloading` (`cargo tree -p synvoid-plugin-runtime | grep libloading` is empty).
- `synvoid-native-extension`: the explicit unsafe native loader — ABI/version checks, path/hash/permission validation, library lifetime/reload generation, native-specific metrics/status DTOs, and the narrow `NativeExtensionBackend` interface.
- Root composition (`synvoid` crate): chooses whether native support is compiled in via the `unsafe-native-extensions` feature (**off by default**) and wires a backend into `PluginManager` via `with_native_backend`.

Three distinct states, never conflated:

| Layer | Meaning |
|-------|---------|
| Compile-time capability | Is the `unsafe-native-extensions` feature compiled in? Default builds answer no. |
| Runtime enablement | Is `[plugins.unsafe_native] enabled = true` plus all production gates satisfied? Disabled by default in all modes. |
| Sandbox status | Always **unsandboxed** for in-process native code, regardless of the above two. |

## Why "Unsafe"?

Native shared libraries loaded into the Synvoid process can:
- Read or write process memory through unsafe code
- Call libc/syscalls directly
- Spawn threads or block executor resources
- Crash the process through UB or panics across FFI
- Bypass WASM manifest capabilities
- Bypass fuel, epoch interruption, guest ABI limits, and host API sub-capabilities

The `unsafe` classification makes this authority explicit rather than implicit.

`catch_unwind` around the `create_router` factory call catches Rust panics
only so a Rust panic does not unwind across the FFI boundary. It is NOT a
sandbox: arbitrary undefined behavior, memory corruption, or
process-aborting faults in native code can still corrupt or crash the host
process.

## Configuration Model

See `UnsafeNativePluginConfig` in `crates/synvoid-config/src/plugins.rs`.

```toml
[plugins.unsafe_native]
enabled = false                    # Disabled by default
allow_in_production = false        # Must be true in production
risk_acknowledgement = "..."       # Required in production
allowed_dirs = [...]               # Path-scoped loading
hot_reload_enabled = false         # Separate from WASM hot-reload
allowed_libraries = [...]          # Optional hash allowlist
```

### Production Gate

In production mode, all of these must be satisfied:
- `enabled = true`
- `allow_in_production = true`
- `risk_acknowledgement` is set and matches `RISK_ACKNOWLEDGEMENT` (`"I understand native extensions run with full Synvoid process authority"`)
- `allowed_dirs` is non-empty

### Compiled-Out Behavior

A configuration that enables native extensions cannot take effect in a binary
built without the `unsafe-native-extensions` feature. Startup logs an
explicit error (`src/server/service_assembly.rs`) and every load attempt
reports `UnsafeNativePluginError::Unsupported` — never a silent success.
Guard: `native_production_config_requires_compiled_support` plus
`native_disabled_build_reports_unsupported` in `tests/plugin_guard.rs`.

## Architecture

### Loader

The canonical loader lives in `crates/synvoid-native-extension/src/loader.rs`
(extracted from the plugin runtime in Phase 28; the
`crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs` module is now a
feature-gated compatibility facade, and `src/plugin/unsafe_native_loader.rs`
is a pure re-export shim).

Every load path reaches all applicable gates — production gate → path
validation → hash verification — before the first `Library::new` call, which
exists exactly once in the canonical loader. Guard:
`native_gates_precede_first_library_new` in `tests/plugin_guard.rs`.

Key type:
```rust
pub struct UnsafeNativeExtension {
    pub name: String,
    pub path: PathBuf,
    pub canonical_path: PathBuf,
    pub library: Arc<Library>,      // Retained for lifetime safety
    pub router: Arc<Router<()>>,
    pub abi_version: String,
    pub loaded_at: SystemTime,
    pub sha256: String,
    pub generation: u64,            // Incremented on reload for safe drain
}
```

`PluginManager` never owns this struct directly. It consumes the narrow
`NativeExtensionBackend` trait (`crates/synvoid-native-extension/src/backend.rs`):
load by validated local path, unload by name/generation, resolve routers
through the opaque `NativeExtensionHandle` (type-erased keep-alive, no
`Library`/pointer/symbol surface), and query bounded status metadata.

### Library Handle Lifetime

`UnsafeNativeExtension` retains an `Arc<Library>` handle. This prevents the shared library from being unloaded while any router, handler, or value derived from the library may still execute. On reload, the old generation stays alive via `Arc` reference counting until all in-flight requests complete.

Additionally, every derived router carries its own `Arc<Library>` keep-alive
inside its middleware layer, so cloned routers keep the library mapped even
after the backend unloads the named generation.

### Path Enforcement

1. Canonicalize the plugin path
2. Reject symlinks (unless explicitly permitted)
3. Reject world-writable files and parent directories (Unix)
4. Require .so/.dylib/.dll extension
5. Enforce `allowed_dirs` path prefix
6. Optional SHA-256 hash verification against `allowed_libraries`

### Observability

Native extension status is exposed separately from WASM plugin status via `PluginManager::unsafe_native_status()`.

Metrics (owned by `synvoid-native-extension`, names unchanged):
- `synvoid_unsafe_native_extension_loaded_total`
- `synvoid_unsafe_native_extension_load_failed_total`
- `synvoid_unsafe_native_extension_reloaded_total`
- `synvoid_unsafe_native_extension_request_total`

## Out-of-Process Alternative (Recommended for Production)

For production deployments requiring native extensibility, the recommended architecture is an out-of-process extension:

- UDS or loopback HTTP/gRPC service
- Explicit request/response schema
- Timeout and concurrency limits at the client boundary
- Separate process user, seccomp/AppArmor/systemd restrictions

In-process native extensions should be treated as a development convenience or trusted operator tool.

## External-Host Seam (Phase 28, Non-Executing)

Phase 28 does not implement out-of-process hosting and adds no generic
remote-execution IPC API. The previous `ExternalPluginClient` placeholder —
which claimed a `filter_request` execution method without an implementation —
is removed. Its replacement is the concrete follow-up seam in
`crates/synvoid-native-extension/src/external_seam.rs`: versioned
`ExternalHostRequest`/`ExternalHostDecision` DTOs, size/deadline/concurrency
bounds (`EXTERNAL_HOST_CONTRACT_VERSION`, 64 KiB headers, 256 KiB body, 50 ms
default deadline), explicit capability grants with no inherited secrets, and
local validation with tests asserting the seam claims no execution.

## Mesh / Distributed Native Load Path (Deferred)

Native extension loading via the mesh (DHT-based plugin distribution) is **not implemented**. Mesh peers distribute signed WASM plugins, not native libraries; native extensions requiring mesh distribution must run in a separate process per-node.

**Rationale:** In-process native code loaded from mesh-distributed binaries poses unacceptable security risks — it grants full process authority to code originating from potentially untrusted peers.

## Migration from "Axum Plugins"

Phase 8 renamed the concept from "Axum plugins" or "native plugins" to "unsafe native extensions" to make the security boundary unambiguous. The `AxumPluginError` type alias is retained for backward compatibility.
