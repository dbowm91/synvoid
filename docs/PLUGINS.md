# Plugins

SynVoid supports two plugin systems for extending functionality:

1. **WASM Plugins** - Sandboxed WebAssembly modules for request filtering and response transformation
2. **Unsafe Native Extensions** - Shared library plugins with full process authority (NOT sandboxed)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      SynVoid                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Plugin Runtime                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────┐    │   │
│  │  │WASM     │  │WASM     │  │  Unsafe     │    │   │
│  │  │Plugin 1 │  │Plugin 2 │  │  Native     │    │   │
│  │  │(Sandbox)│  │(Sandbox)│  │  Extension  │    │   │
│  │  └─────────┘  └─────────┘  └─────────────┘    │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## WASM Plugins

WebAssembly plugins run in a sandboxed environment for safe execution of custom logic.

## Configuration

### Global WASM Plugin Limits

```toml
[plugins.wasm]
max_memory_mb = 64
max_cpu_fuel = 1000000
timeout_seconds = 30
```

### Per-Instance Overrides

```toml
[[plugins.wasm.plugins]]
name = "my_plugin"
path = "/etc/synvoid/plugins/my_plugin.wasm"
max_memory_mb = 128      # optional override
max_cpu_fuel = 500000    # optional override
timeout_seconds = 10     # optional override
priority = 100           # optional execution order (lower runs first)
on_error = "fail_closed" # optional: "fail_open" (default) or "fail_closed"
allowed_dht_prefixes = ["site:example.com"]  # optional DHT scoping
```

### Configuration Options

#### `[plugins.wasm]` — Global Defaults

| Option | Default | Description |
|--------|---------|-------------|
| `max_memory_mb` | `64` | Max memory per plugin instance (MB) |
| `max_cpu_fuel` | `1000000` | Wasmtime fuel budget per execution |
| `timeout_seconds` | `30` | Execution timeout |

#### `[[plugins.wasm.plugins]]` — Per-Instance Overrides

| Option | Default | Description |
|--------|---------|-------------|
| `name` | *(required)* | Plugin name (must be unique) |
| `path` | *(required)* | Path to `.wasm` file |
| `max_memory_mb` | `None` | Override global memory limit |
| `max_cpu_fuel` | `None` | Override global fuel budget |
| `timeout_seconds` | `None` | Override global timeout |
| `priority` | `None` | Execution order (lower runs first) |
| `on_error` | `None` | `"fail_open"` or `"fail_closed"` on plugin error (`WasmOnError`, snake_case) |
| `allowed_dht_prefixes` | `[]` | Restrict DHT access to these prefixes |

There is no `[plugins] wasm_enabled` toggle. `PluginConfig` has exactly three fields — `wasm`, `unsafe_native`, and the deprecated alias `native_plugins_compat`. A plugin runs because it is listed in `[[plugins.wasm.plugins]]`; the per-site `[proxy] wasm_plugins` list is what selects which of those run for a given site.

## Writing a Plugin

### Rust Implementation

```rust
use wasmtime::*;

pub struct MyPlugin {
    store: Store<()>,
    filter: Func,
}

impl MyPlugin {
    pub fn new() -> Result<Self> {
        let mut engine = Engine::default();
        let mut store = Store::new(&engine, ());
        
        // Load WASM module
        let module = Module::from_file(&engine, "my_plugin.wasm")?;
        
        // Get filter function
        let filter = module.get_export(&mut store, "filter_request")
            .and_then(|e| e.into_func())
            .ok_or("filter_request not found")?;
        
        Ok(Self { store, filter })
    }
    
    pub fn filter(&mut self, request: &[u8]) -> Result<FilterResult> {
        // Call WASM function
        // Return: Pass, Block, or Challenge
    }
}
```

### WASM Interface

Your WASM module must export:

```rust
// Required: Memory allocator (production requires both; development allows alloc-only)
export fn guest_alloc(len: i32) -> i32;
export fn guest_free(ptr: i32, len: i32);   // BOTH args — GuestFreeFn = TypedFunc<(i32, i32), ()>

// Required: Filter incoming requests
// Signature: (method_ptr, method_len, uri_ptr, uri_len,
//             headers_ptr, headers_len, body_ptr, body_len) -> i32
// Returns: 0 = Pass, 1 = Block, 2 = Challenge
export fn filter_request(m: i32, m_len: i32, u: i32, u_len: i32,
                         h: i32, h_len: i32, b: i32, b_len: i32) -> i32;

// Optional: Transform response
// Signature: (status_ptr, status_len, body_ptr, body_len,
//             out_ptr, out_max) -> i32
// Returns: new body length, or -1 on error
export fn transform_response(s: i32, s_len: i32, b: i32, b_len: i32,
                             out: i32, out_max: i32) -> i32;
```

**Pointer safety:** the host never trusts a guest pointer. Frames are serialized only through `abi_frame::serialize_headers_canonical` and `abi_frame::build_request_frame`, and every guest pointer range is checked with `checked_guest_range` before use.

**Production requirements:**
- Both `guest_alloc` and `guest_free` exports are **required** in production (`SignedSandboxed` / `LocalSandboxed` tiers).
- Development mode allows `guest_alloc` only (no `guest_free`) via `DevelopmentAllowMissingFree` policy.

### Example WASM (Rust)

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn filter_request(m_ptr: i32, m_len: i32, u_ptr: i32, u_len: i32,
                      _h_ptr: i32, _h_len: i32, _b_ptr: i32, _b_len: i32) -> i32 {
    // 0 = Pass, 1 = Block, 2 = Challenge

    let read = |ptr: i32, len: i32| -> String {
        if len <= 0 || ptr <= 0 { return String::new(); }
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(ptr as *const u8, len as usize)).into_owned() }
    };
    let (method, uri) = (read(m_ptr, m_len), read(u_ptr, u_len));

    // Custom blocking logic
    if uri.contains("/admin") && method != "GET" {
        return 1; // Block
    }

    0 // Pass
}
```

### Build Plugin

```toml
# plugin/Cargo.toml
[package]
name = "my-waf-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
```

```bash
cd plugin
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/my_waf_plugin.wasm /etc/synvoid/plugins/
```

The WASI preview-1 target is `wasm32-wasip1` on Rust 1.98.1 (the pinned toolchain); the legacy `wasm32-wasi` target name was renamed upstream and will not resolve.

## Plugin API

### Request Filter

```rust
pub enum WasmFilterResult {
    Pass,                      // Allow request through
    Block(StatusCode, String), // Block with status code
    Challenge(String),         // Return challenge (e.g., CAPTCHA)
}
```

### Response Transformer

```rust
pub fn transform_response(
    &self,
    response: Response<Bytes>
) -> Result<Response<Bytes>, WasmPluginError>;
```

## Built-in Plugin Examples

### Rate Limiting Plugin

```toml
# plugins/rate_limit.wasm
# Custom rate limiting with different rules
```

### Auth Plugin

```toml
# plugins/jwt_auth.wasm
# JWT token validation
```

### WAF Plugin

```toml
# plugins/custom_rules.wasm
# Custom detection rules
```

## Loading Plugins

### Automatic Loading

Place `.wasm` files in plugins directory:

```
/etc/synvoid/plugins/
├── my_plugin.wasm
├── auth_plugin.wasm
└── rate_limit.wasm
```

### Per-Site Plugins

There is no `[site.plugins]` section. A site selects plugins by **name** through `[proxy] wasm_plugins` in its site file (`SiteProxyConfig::wasm_plugins`), which matches against the names declared in `[[plugins.wasm.plugins]]`:

```toml
# config/sites/example.com.toml
[proxy]
wasm_plugins = ["auth_plugin", "rate_limit_plugin"]
```

### Plugin Order

Order comes from the `priority` field on each `[[plugins.wasm.plugins]]` entry (lower runs first), not from a separate list:

```toml
[[plugins.wasm.plugins]]
name = "ip_check"     # Runs first
path = "/etc/synvoid/plugins/ip_check.wasm"
priority = 10

[[plugins.wasm.plugins]]
name = "auth"         # Runs second
path = "/etc/synvoid/plugins/auth.wasm"
priority = 20

[[plugins.wasm.plugins]]
name = "rate_limit"   # Runs third
path = "/etc/synvoid/plugins/rate_limit.wasm"
priority = 30
```

## Security

### Sandbox

WASM plugins run in a sandboxed environment:

- No filesystem access (except configured paths)
- No network access
- Memory limits enforced
- Execution timeout enforced with millisecond precision (manifest `timeout_ms` maps directly to `Duration::from_millis`)
- Sandboxed plugins (`SignedSandboxed`, `LocalSandboxed`) require a non-zero fuel budget to enforce execution limits
- Production ABI requires both `guest_alloc` and `guest_free` exports

### Signed Plugins

Plugin signing is managed through manifest trust tiers (`SignedSandboxed`, `LocalSandboxed`, `Development`) rather than a global config toggle. See `architecture/plugin_runtime_sandbox.md` for trust tier details and `HotReloadConfig.require_signed_wasm` for hot-reload signature enforcement.

`verify_plugin_signature` (`crates/synvoid-plugin-runtime/src/sandbox/types.rs:1550`) rejects an **empty** `binary_sha256` or `manifest_sha256` in the signature block outright — an empty hash is a `BinaryHashMismatch` / `ManifestHashMismatch`, never a bypass. The manifest hash is computed over the manifest itself, so editing the manifest after signing breaks verification.

## ABI Frame Serialization

The WASM plugin ABI uses a canonical binary serialization for request metadata. All plugins receive request data through a single contiguous frame in WASM memory.

### Request Input Frame

Request data is serialized as:

| Field | Format |
|-------|--------|
| Method | Raw HTTP method bytes (e.g., `GET`, `POST`) |
| URI | Raw URI bytes (origin-form or absolute-form) |
| Authority | URI authority or `Host` header value |
| Scheme | `http` or `https` from URI/listener state |
| Headers | Binary: `[count: u16 LE] [name_len: u16 LE][name][val_len: u16 LE][val]...` |
| Body | Raw body bytes |

### Policy Bounds

All fields are bounded by `RequestFramePolicy` (`abi_frame.rs:134`). Defaults:

- Method: max 256 bytes
- URI: max 8192 bytes
- Authority: max 256 bytes
- Header count: max 128
- Header name: max 256 bytes
- Header value: max 8192 bytes
- Total serialized headers: max 65536 bytes (64 KiB)
- Body: max 262144 bytes (256 KiB)
- Total frame: max 1048576 bytes (1 MiB)

`request_frame_policy_from_limits(max_input_bytes)` overrides only three of these: body and total frame become `max_input_bytes`, and total serialized headers becomes `max(max_input_bytes / 2, 4096)`. The method/URI/authority/count/name/value bounds are not scaled. `ResponseFramePolicy` mirrors the same numbers, with status codes constrained to 100-599.

Exceeding any bound causes a rejection — metadata is never silently truncated.

### Response Transform Validation

Plugin response transforms are validated before application:
- Status code must be 100-599
- Body must be within `max_output_bytes`
- Security-sensitive headers (`set-cookie`, `content-length`, `transfer-encoding`, etc.) are denied by default
- `x-plugin-*` prefix headers are always allowed

### Failure Metrics

Serialization rejections emit `synvoid_plugin_serialization_rejection_total` with bounded labels (plugin name, hook type, failure class, trust tier). No raw header values or body content appears in metrics.

## Troubleshooting

### Plugin Not Loading

```bash
# Check plugin file
ls -la /etc/synvoid/plugins/

# Validate WASM
wasm-validate /etc/synvoid/plugins/my_plugin.wasm
```

### Execution Timeout

Increase timeout in config:

```toml
[plugins.wasm]
timeout_seconds = 60
```

### Memory Issues

Reduce memory limit:

```toml
[plugins.wasm]
max_memory_mb = 32
```

## Metrics

### Pool & Execution Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `synvoid_plugin_pool_hit_total` | `plugin` | Pooled instance reused (warm start) |
| `synvoid_plugin_pool_miss_total` | `plugin` | No pooled instance available; fresh instance created |
| `synvoid_plugin_pool_dropped_total` | `plugin` | Poisoned/failed instance discarded |
| `synvoid_plugin_concurrency_limit_exceeded_total` | `plugin` | Execution denied due to concurrency cap |
| `synvoid_plugin_invoke_total` | `plugin`, `capability`, `status` | Total invocation attempts |
| `synvoid_plugin_load_total` | `tier`, `status` | Plugin load events |
| `synvoid_plugin_hot_reload_total` | `status` | Hot-reload attempts |
| `synvoid_plugin_state_transition_total` | `from`, `to`, `reason` | Lifecycle state transitions |

### Capability & Host API Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `synvoid_plugin_capability_violation_total` | `capability` | Capability check denials |
| `synvoid_plugin_host_call_failure_total` | `plugin`, `host_function`, `failure_class` | Host call failures (timeout, capability denied, etc.) |
| `synvoid_plugin_serialization_rejection_total` | `plugin`, `hook`, `failure_class`, `trust_tier` | ABI frame serialization rejections |

### Unsafe Native Extension Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `synvoid_unsafe_native_extension_loaded_total` | `name` | Extensions loaded |
| `synvoid_unsafe_native_extension_load_failed_total` | `name` | Failed load attempts |
| `synvoid_unsafe_native_extension_reloaded_total` | `name` | Hot-reload successes |
| `synvoid_unsafe_native_extension_request_total` | `name` | Requests routed to extensions |

## Best Practices

1. **Minimal Plugins** - Keep logic simple
2. **Fail Open** - Default to pass on errors
3. **Log Everything** - Add detailed logging
4. **Test Thoroughly** - Unit test WASM code
5. **Version Control** - Track plugin versions
6. **Monitor Performance** - Watch execution time
7. **Prefer Out-of-Process** - For unsafe native extensions, prefer out-of-process (UDS/HTTP/gRPC) over in-process loading in production

---

## Unsafe Native Extensions

> **SECURITY WARNING:** Unsafe native extensions run in the same process as SynVoid with **full process authority** — memory access, arbitrary syscalls, panic/UB potential, allocator interaction, thread spawning, and access to all linked process state. They are **NOT sandboxed**. Only load extensions from fully trusted sources.

The WASM plugin runtime is the **only sandboxed production plugin model**. Unsafe native extensions are a separate, explicitly-unsafe path for trusted operator extensions.

### Supported Formats

| Platform | Extension |
|----------|-----------|
| Linux | `.so` |
| macOS | `.dylib` |
| Windows | `.dll` |

### Required Exports

Your native extension must export:

```rust
use axum::{Router, routing::get};

// ABI version symbol (required for compatibility check)
#[no_mangle]
pub static synvoid_abi_version: *const std::ffi::c_char = 
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::ffi::c_char;

// Factory function that creates the router
#[no_mangle]
pub extern "C" fn create_router() -> *mut Router<()> {
    let router = Router::new()
        .route("/", get(|| async { "Hello from extension!" }))
        .route("/api/custom", get(my_handler));
    Box::into_raw(Box::new(router))
}
```

### Configuration

Unsafe native extensions are **disabled by default** at both layers: the
`unsafe-native-extensions` compile feature is off by default (default builds
carry no shared-library loader for plugins — the sandboxed WASM runtime
links no `libloading`), and runtime loading is disabled by default in all
modes. To use in-process native extensions, rebuild with
`--features unsafe-native-extensions` AND enable them at runtime. In
production, loading additionally requires explicit operator risk
acknowledgement. A config that enables native extensions in a binary built
without the feature fails closed: startup logs an explicit error and every
load reports `Unsupported`.

```toml
# There is no [plugins] `wasm_enabled` / `unsafe_native_enabled` toggle.
# `PluginConfig` holds `wasm`, `unsafe_native`, and the deprecated alias
# `native_plugins_compat` only.
[plugins.unsafe_native]
enabled = false
allow_in_production = false
hot_reload_enabled = false
allowed_dirs = ["/opt/synvoid/native-extensions"]
# Required verbatim in production:
# risk_acknowledgement = "I understand native extensions run with full Synvoid process authority"

# Optional: explicit library allowlist with hash verification
[[plugins.unsafe_native.allowed_libraries]]
path = "/opt/synvoid/native-extensions/foo.so"
sha256 = "abc123..."
```

#### Production Requirements

In production mode, all of the following must be true:
- `enabled = true`
- `allow_in_production = true`
- `risk_acknowledgement` set to exactly `"I understand native extensions run with full Synvoid process authority"` (the `RISK_ACKNOWLEDGEMENT` constant, `crates/synvoid-native-extension/src/loader.rs:17`)
- Non-empty `allowed_dirs` configured

### Security Validations

SynVoid performs the following checks when loading unsafe native extensions:

1. **Symlink Prevention** - Rejects files that are symlinks
2. **World-Writable Rejection** - Rejects world-writable files and parent directories (Unix)
3. **Permission Check** - Requires permissions 755 or 500 (Unix)
4. **Extension Validation** - Only accepts .so, .dylib, or .dll
5. **Dangerous Name Check** - Rejects filenames matching known system libraries
6. **Path Allowlist** - Restricts loading to configured `allowed_dirs`
7. **SHA-256 Hash Verification** - Optional hash allowlist for library integrity
8. **ABI Version Check** - Validates `synvoid_abi_version` matches SynVoid version

### Security Considerations

- Native extensions are **NOT sandboxed**
- They can access files, network, and system calls directly
- A crashing extension can crash the entire process
- Memory corruption in an extension affects the host process
- They bypass WASM manifest capabilities, fuel limits, epoch interruption, and host API sub-capabilities

### Recommended Production Model: Out-of-Process

For production native extensibility, the **recommended approach** is an out-of-process extension:

- UDS or loopback HTTP/gRPC service
- Explicit request/response schema
- Timeout and concurrency limits at the client boundary
- Separate process user, seccomp/AppArmor/systemd restrictions
- Same capability policy concepts as WASM host APIs

In-process native extensions should be treated as a development convenience or trusted operator tool, not a production deployment pattern.

### Lifecycle and Library Handle Safety

The `UnsafeNativeExtension` struct retains an `Arc<libloading::Library>` handle for the lifetime of the extension, and every derived router carries its own keep-alive. This prevents use-after-free: the shared library cannot be unloaded while any plugin-derived router or handler may still execute.

Panic containment is limited: `catch_unwind` around the factory call catches Rust panics only. Arbitrary native undefined behavior can still corrupt or crash the host process — in-process native code is never sandboxed.

Hot-reload for native extensions is **gated separately** from WASM hot-reload via `hot_reload_enabled`. When a native extension is reloaded, the old library stays loaded until all in-flight references are dropped.

### Observability

Native extension status is exposed separately from WASM plugin status:

| Field | Description |
|-------|-------------|
| name | Extension name (from library filename) |
| path | Canonical file path |
| sha256 | SHA-256 hash of the loaded library |
| abi_version | ABI version reported by the extension |
| loaded_at | Unix timestamp of load |

Metrics: `synvoid_unsafe_native_extension_loaded_total`, `synvoid_unsafe_native_extension_load_failed_total`, `synvoid_unsafe_native_extension_reloaded_total`.

## Runtime Lifecycle and Guarantees

### Plugin State Models

Each plugin is configured with a `state_model` that controls instance reuse and isolation guarantees:

| Model | Instance Reuse | Guest Globals | Host Context Reset | Use Case |
|-------|---------------|---------------|-------------------|----------|
| `HostContextIsolated` | Pooled (same store/instance) | Persist across requests | Yes — env, body, caps, DHT, fuel, timeout | Default for `SignedSandboxed` and `LocalSandboxed` |
| `FreshInstancePerRequest` | No — instantiated fresh, dropped after use | Reset per request | Yes | Strict isolation, no guest state leakage |
| `StatefulPooled` | Pooled | Persist across requests | Yes | Explicit stateful plugins (counters, caches) |

**Important**: `HostContextIsolated` was previously named `RequestIsolated`. The name was changed to precisely reflect the guarantee: host-side context is reset, but guest linear memory and globals may persist due to Wasmtime instance reuse. Manifest files using `"request_isolated"` are automatically mapped to `HostContextIsolated`.

### Lifecycle Hardening (Phase 9)

#### Generation Tracking

Every plugin load/reload creates a new `LoadedPluginGeneration` with a monotonically increasing `PluginGenerationId`. Generation IDs are never reused within process lifetime. In-flight requests hold a stable `Arc<WasmRuntime>` reference to their generation.

| Type | Purpose |
|------|---------|
| `PluginGenerationId` | Monotonic generation identifier (`u64`) |
| `LoadedPluginGeneration` | Generation metadata (hash, trust tier, timestamps, previous generation) |
| `PluginReloadOutcome` | Structured reload result: `Replaced`, `Unchanged`, or `Failed` |
| `PluginReplacePolicy` | Duplicate name handling: `RejectExisting`, `ReplaceSameSource`, `ReplaceAnyWithOperatorOverride` |
| `LifecycleTransition` | Audit trail record for state transitions |

#### Atomic Reload Pipeline

Reload follows a prepare-then-commit pattern:

1. `prepare_reload_candidate(path)` — validates candidate without touching the active generation
2. `commit_reload_candidate(name, runtime, generation)` — atomically swaps under lock

Failed reloads **never** replace the active generation. The `PluginReloadOutcome` enum provides structured results.

#### File Stability Detection

`FileStabilityPolicy` prevents loading partially written files during hot-reload:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `debounce` | `300ms` | Initial delay before stability check |
| `stable_checks` | `3` | Consecutive identical observations required |
| `stable_interval` | `100ms` | Interval between stability checks |
| `max_wait` | `5s` | Maximum time to wait for file to stabilize |

#### Lifecycle State Machine

`PluginLifecycleState` defines explicit states with validated transitions:

```
Loading ──→ Active ──→ Reloading ──→ Active
  │            │                        │
  ↓            ↓                        ↓
FailedLoad   Disabled ←────────────── Quarantined
                 │                        │
                 ↓                        ↓
              Active ──→ Unloading ──→ Removed
```

Valid transitions:
- `Loading` → `Active` | `FailedLoad`
- `Active` → `Reloading` | `Disabled` | `Quarantined` | `Unloading`
- `Reloading` → `Active` | `FailedLoad`
- `Disabled` → `Active`
- `Quarantined` → `Disabled` | `Active` | `Removed`
- `Unloading` → `Removed`

All transitions are recorded in the lifecycle audit trail.

#### Production/Development Hot Reload Gates

`HotReloadConfig` separates WASM and native hot-reload gates:

| Field | Description |
|-------|-------------|
| `enabled` | Master toggle for hot reload |
| `production_enabled` | Required for production mode hot reload |
| `unsafe_native_enabled` | Separate gate for native extension hot reload |
| `require_signed_wasm` | Optional signature enforcement for WASM reload |
| `watch_dirs` | Directories to watch for plugin changes |
| `stability_policy` | `FileStabilityPolicy` for debounce configuration |

#### Operator Lifecycle APIs

The `WasmPluginManager` provides operator-facing lifecycle controls:

| API | Description |
|-----|-------------|
| `disable_plugin(name, reason)` | Transitions `Active` → `Disabled` |
| `reset_plugin(name)` | Transitions `Disabled`/`Quarantined` → `Active` |
| `remove_plugin(name)` | Transitions `Active` → `Unloading` → `Removed` |
| `quarantine_plugin(name, reason)` | Transitions `Active` → `Quarantined` |

Each operation records audit events with generation, hashes, and reasons.

### Epoch Interruption Lifecycle

WASM plugins execute with epoch-based interruption to enforce CPU time limits. The epoch incrementer is a background Tokio task managed by `PluginRuntimeOwner`.

- `PluginRuntimeOwner` starts the epoch incrementer on construction and stops it on drop.
- `WasmPluginManager::validate_execution_containment_runtime()` rejects production configs where sandboxed plugins have `epoch_deadline_enabled = true` but no incrementer is running.
- Dev/test mode may skip the incrementer when no sandboxed plugins are loaded.

### Body Chunk Timeout

The `synvoid_read_body_chunk` host function enforces a timeout (`body_chunk_timeout`) when waiting for upstream body data. If no data arrives within the timeout, the host returns `ABI_ERR_TIMEOUT` (-3) to the guest.

- Timeout uses `tokio::time::timeout` inside the synchronous Wasmtime host callback.
- Multi-thread Tokio runtime is required for timeout enforcement (timer workers need separate threads).
- Chunks exceeding `max_body_chunk_bytes` are clamped to the limit.

### Pool Metrics

Plugin pool metrics use distinct counters with precise semantics:

| Metric | Meaning |
|--------|---------|
| `pool_hit` | A pooled instance was reused (warm start) |
| `pool_miss` | No pooled instance was available; a fresh instance was created |
| `pool_drop` | A poisoned or failed instance was discarded |
| `concurrency_limit_exceeded` | Execution denied due to concurrency/instance cap exhaustion |
| `fresh_instance_created` | A `FreshInstancePerRequest` invocation bypassed the pool |

`pool_miss` and `concurrency_limit_exceeded` are semantically separate: a miss means no warm instance was available but execution continued successfully; a limit exceeded means execution was denied due to backpressure.

### Guardrails

There is no `plugin-runtime-guardrails` CI job — `.github/workflows/ci.yml` has no plugin-specific job. Plugin boundary tests live in the root integration suite and in `tools/synvoid-repo-guards`:

```bash
# Local verification
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard     # root guard suite
cargo test --test plugin_guard                  # root guard suite
cargo test --test admin_plugin_boundary_guard   # root guard suite
```

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Plugin configuration
- [DEVELOPER.md](./DEVELOPER.md) - Plugin development guide
- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Custom attack detection plugins
