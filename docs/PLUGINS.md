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
memory_mb = 128          # optional override
cpu_fuel = 500000        # optional override
timeout_seconds = 10     # optional override
priority = 100           # optional execution order
on_error = "block"       # optional: "pass" or "block"
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
| `memory_mb` | `None` | Override global memory limit |
| `cpu_fuel` | `None` | Override global fuel budget |
| `timeout_seconds` | `None` | Override global timeout |
| `priority` | `None` | Execution order (lower runs first) |
| `on_error` | `None` | `"pass"` or `"block"` on plugin error |
| `allowed_dht_prefixes` | `None` | Restrict DHT access to these prefixes |

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
export fn guest_free(ptr: i32);

// Required: Filter incoming requests
// Returns: 0 = Pass, 1 = Block, 2 = Challenge
export fn filter_request(method: i32, uri: *const u8, uri_len: i32) -> i32;

// Optional: Transform response
// Returns: 0 = Pass, 1 = Modified
export fn transform_response(status_code: i32, body: *const u8, body_len: i32) -> i32;
```

**Production requirements:**
- Both `guest_alloc` and `guest_free` exports are **required** in production (`SignedSandboxed` / `LocalSandboxed` tiers).
- Development mode allows `guest_alloc` only (no `guest_free`) via `DevelopmentAllowMissingFree` policy.

### Example WASM (Rust)

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn filter_request(method: i32, uri: ptr, uri_len: i32) -> i32 {
    // 0 = Pass, 1 = Block, 2 = Challenge
    
    // Read URI from WASM memory
    let uri = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(uri, uri_len as usize))
            .unwrap_or("")
    };
    
    // Custom blocking logic
    if uri.contains("/admin") && method != 0 {
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
cargo build --release --target wasm32-wasi
cp target/wasm32-wasi/release/my_waf_plugin.wasm /etc/synvoid/plugins/
```

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

```toml
# config/sites/example.com.toml
[site.plugins]
enabled = true

[site.plugins.load]
- "auth_plugin.wasm"
- "rate_limit.wasm"
```

### Plugin Order

Plugins execute in order defined in config:

```toml
[site.plugins.load]
- "ip_check.wasm"     # Runs first
- "auth.wasm"         # Runs second
- "rate_limit.wasm"   # Runs third
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

All fields are bounded by `RequestFramePolicy` derived from plugin limits:
- Method: max 256 bytes
- URI: max 8192 bytes
- Header count: max 128
- Header name: max 256 bytes
- Header value: max 8192 bytes
- Total serialized headers: max 64KB
- Body: max 256KB (from `max_input_bytes`)
- Total frame: max 1MB (from `max_input_bytes`)

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

Unsafe native extensions are **disabled by default**. In production, loading requires explicit operator risk acknowledgement.

```toml
[plugins]
wasm_enabled = true
unsafe_native_enabled = false

[plugins.unsafe_native]
enabled = false
allow_in_production = false
hot_reload_enabled = false
allowed_dirs = ["/opt/synvoid/native-extensions"]

# Optional: explicit library allowlist with hash verification
[[plugins.unsafe_native.allowed_libraries]]
path = "/opt/synvoid/native-extensions/foo.so"
sha256 = "abc123..."
```

#### Production Requirements

In production mode, all of the following must be true:
- `enabled = true`
- `allow_in_production = true`
- `risk_acknowledgement` set to the required acknowledgement string
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

The `UnsafeNativeExtension` struct retains an `Arc<libloading::Library>` handle for the lifetime of the extension. This prevents use-after-free: the shared library cannot be unloaded while any plugin-derived router or handler may still execute.

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

### CI Guardrails

Plugin runtime changes are validated by the `plugin-runtime-guardrails` CI job:

```bash
# Local verification (mirrors CI steps)
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test plugin_lifecycle_guard
```

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Plugin configuration
- [DEVELOPER.md](./DEVELOPER.md) - Plugin development guide
- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Custom attack detection plugins
