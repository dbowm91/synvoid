# Unsafe Native Extensions

## Overview

SynVoid distinguishes between two plugin models with fundamentally different security properties:

1. **WASM Plugins** — Sandboxed WebAssembly modules with trust tiers, capability manifests, signing, fuel/epoch limits, and failure isolation. This is the production-safe plugin model.

2. **Unsafe Native Extensions** — Shared libraries loaded via `libloading` that run with full SynVoid process authority. These are NOT sandboxed and must only be loaded from trusted sources.

## Why "Unsafe"?

Native shared libraries loaded into the Synvoid process can:
- Read or write process memory through unsafe code
- Call libc/syscalls directly
- Spawn threads or block executor resources
- Crash the process through UB or panics across FFI
- Bypass WASM manifest capabilities
- Bypass fuel, epoch interruption, guest ABI limits, and host API sub-capabilities

The `unsafe` classification makes this authority explicit rather than implicit.

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
- `risk_acknowledgement` is set and matches the expected string
- `allowed_dirs` is non-empty

## Architecture

### Loader

The canonical loader lives in `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`.

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

### Library Handle Lifetime

`UnsafeNativeExtension` retains an `Arc<Library>` handle. This prevents the shared library from being unloaded while any router, handler, or value derived from the library may still execute. On reload, the old generation stays alive via `Arc` reference counting until all in-flight requests complete.

### Path Enforcement

1. Canonicalize the plugin path
2. Reject symlinks (unless explicitly permitted)
3. Reject world-writable files and parent directories (Unix)
4. Require .so/.dylib/.dll extension
5. Enforce `allowed_dirs` path prefix
6. Optional SHA-256 hash verification against `allowed_libraries`

### Observability

Native extension status is exposed separately from WASM plugin status via `PluginManager::unsafe_native_status()`.

Metrics:
- `synvoid_unsafe_native_extension_loaded_total`
- `synvoid_unsafe_native_extension_load_failed_total`
- `synvoid_unsafe_native_extension_reloaded_total`

## Out-of-Process Alternative (Recommended for Production)

For production deployments requiring native extensibility, the recommended architecture is an out-of-process extension:

- UDS or loopback HTTP/gRPC service
- Explicit request/response schema
- Timeout and concurrency limits at the client boundary
- Separate process user, seccomp/AppArmor/systemd restrictions

In-process native extensions should be treated as a development convenience or trusted operator tool.

## Migration from "Axum Plugins"

Phase 8 renamed the concept from "Axum plugins" or "native plugins" to "unsafe native extensions" to make the security boundary unambiguous. The `AxumPluginError` type alias is retained for backward compatibility.
