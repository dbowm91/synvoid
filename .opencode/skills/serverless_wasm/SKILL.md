---
name: serverless_wasm
description: Serverless WASM runtime with instance pooling, mesh serverless integration, and function execution.
---

# Serverless & WASM Runtime Skill

## Overview

This skill documents the serverless function architecture in SynVoid, including the WASM runtime, instance pooling, and mesh serverless integration.

## Key Components

### ServerlessManager

The `ServerlessManager` at `src/serverless/manager.rs` manages serverless function lifecycle:

```rust
pub struct ServerlessManager {
    pub functions: RwLock<HashMap<String, ServerlessFunction>>,
    pub instance_pools: RwLock<HashMap<String, Arc<InstancePool>>>,
    pub scheduler: Arc<ServerlessScheduler>,
    pub event_consumer_enabled: bool,
    pub last_event_poll: RwLock<Option<Instant>>,
}
```

### InstancePool

The `InstancePool` at `src/serverless/instance_pool.rs` manages pooled WASM instances:

```rust
pub struct InstancePool {
    runtime: Arc<WasmRuntime>,
    function_definition: FunctionDefinition,
    // ...
}
```

### FunctionDefinition

Defines function metadata at `crates/synvoid-config/src/serverless.rs`:

```rust
pub struct FunctionDefinition {
    pub name: String,
    pub wasm_path: Option<String>,
    pub version: Option<u64>,           // Added in Wave 3.9
    pub checksum: Option<String>,          // Added in Wave 3.9
    pub signature: Option<String>,       // Added in Wave 3.9
    pub signer_public_key: Option<String>, // Added in Wave 3.9
    pub wasi_enabled: bool,              // Added in Wave 4.6
    pub wasi_config: Option<WasiConfig>, // Added in Wave 4.6
    // ...
}
```

## Key Features Implemented

### Hot Reload (Wave 3.10)

The `ServerlessManager` supports hot reloading:

```rust
pub fn reload_function(&self, function_name: &str, wasm_bytes: Vec<u8>) -> Result<()>
pub fn deploy_function(&self, definition: FunctionDefinition) -> Result<()>
pub fn load_function_wasm(&self, name: &str, wasm_bytes: &[u8]) -> Result<Arc<WasmRuntime>>
```

### Pre-warming

Instance pools are now initialized on creation (Wave 4.2):

```rust
pub async fn initialize(&self) -> Result<(), InstancePoolError> {
    // Pre-warm with min_instances
}
```

### Async Compilation (P11.2)

Serverless functions support async WASM compilation to avoid blocking startup:

```rust
// AsyncCompilationHandle tracks compilation state
use crate::serverless::async_compilation::{AsyncCompilationHandle, AsyncCompilationManager, CompilationState};

pub struct AsyncCompilationHandle {
    state: Arc<RwLock<CompilationState>>,
    completion_sender: Arc<Mutex<Option<oneshot::Sender<Result<(), WasmPluginError>>>>>,
    completion_receiver: Arc<Mutex<Option<oneshot::Receiver<Result<(), WasmPluginError>>>>>,
}

#[derive(Debug, Clone)]
pub enum CompilationState {
    Pending,
    Compiling { started_at: Instant },
    Ready,
    Failed { error: String },
}
```

Usage in `ServerlessManager::initialize`:

```rust
let compilation_manager = self.compilation_manager.clone();
let (tx, rx) = tokio::sync::oneshot::channel();
tokio::spawn(async move {
    let result = tokio::task::spawn_blocking(move || {
        // blocking WASM compilation work
    }).await;
    let _ = tx.send((func_name.clone(), result));
});
compilation_manager.mark_compiling(&func_name);
```

Check status with `poll_state()`:

```rust
if let Some(ref handle) = function.compilation_handle {
    match handle.poll_state() {
        CompilationState::Compiling { started_at } => { /* wait */ }
        CompilationState::Ready => { /* use runtime */ }
        CompilationState::Failed { error } => { /* handle error */ }
        CompilationState::Pending => { /* not started */ }
    }
}
```

### State Isolation (Wave 4.8)

Memory is cleared between requests via `_reset()` export or re-instantiation. For WASM plugins, `PluginStateModel` controls cross-request state behavior: `HostContextIsolated` resets host-side context only (guest memory/globals may persist), `FreshInstancePerRequest` instantiates a fresh instance per invocation, and `StatefulPooled` reuses instances with guest state preserved.

### WASI Support (Wave 4.6)

WASI context is wired up via `wasmtime_wasi::WasiCtxBuilder`:

```rust
fn prepare_wasi_context(
    linker: &mut wasmtime::Linker<WasmRuntimeState>,
    config: &WasiConfig,
) -> Result<wasmtime::WasiCtx> {
    let mut ctx = wasmtime_wasi::WasiCtxBuilder::new()
        .args(&config.args)
        .envs(&config.env_vars)
        .build();
    Ok(ctx)
}
```

## Mesh Serverless

### Invocation Flow (Wave 3.2)

```
Edge receives request for serverless function
    ↓
extract_upstream_id() → "serverless:{function_name}"
    ↓
MeshTransport detects "serverless:" prefix
    ↓
handle_serverless_invoke_request() verifies signature
    ↓
invoke_for_mesh() executes function
    ↓
Returns WASM response as HTTP response
```

### Handler Implementation

```rust
async fn handle_serverless_invoke_request(
    &self,
    function_name: &str,
    request: Request<Body>,
    caller_context: CallerContext,
) -> Result<ServerlessInvokeResponse, ServerlessError> {
    // Verify timestamp (reject if older than 5 minutes)
    // Get ServerlessManager from transport
    // Build CallerContext from peer node info
    // Call invoke_for_mesh()
    // Sign response if mesh_signer available
    // Return ServerlessInvokeResponse
}
```

### Mesh Routing

The mesh routing now uses weighted provider selection (Wave 3.10):

```rust
let providers = self.weighted_shuffle_providers(providers, scores);
```

## Scheduler Support (Wave 3.13)

The `ServerlessScheduler` at `src/serverless/scheduler.rs` provides cron-like scheduling:

```rust
pub struct ServerlessScheduler {
    timers: RwLock<HashMap<String, TimerEntry>>,
}

pub struct TimerEntry {
    pub interval_secs: u64,
    pub function_name: String,
    pub topic: String,
    pub last_fired: Instant,
}
```

Usage:

```rust
scheduler.add_timer(interval_secs, function_name, topic);
scheduler.remove_timer(function_name);
let timers = scheduler.list_timers();
```

## Event Consumer (Wave 3.12)

Background task polls for `event:*` records in DHT:

```rust
async fn start_event_consumer(&self) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Poll event: prefixed records
        // Dispatch to subscribed functions
    }
}
```

## DHT Watcher (Wave 3.11)

`RecordWatcher` trait enables DHT record change notifications:

```rust
pub trait RecordWatcher: Send + Sync {
    fn on_record_stored(&self, key: &str, value: &[u8]);
    fn on_record_removed(&self, key: &str);
    fn watch_prefix(&self) -> &str;
}
```

## Testing

```bash
# Run serverless tests
cargo test --lib serverless

# Run serverless integration tests
cargo test --test integration_test -- serverless

# Run WASM runtime tests
cargo test --lib plugin::wasm_runtime
```

## Common Issues

### Cold Start on First Request

**Cause**: `InstancePool::initialize()` not called after pool creation.

**Solution**: Wave 4.2 fixed this - call `.initialize().await` after pool creation.

### State Leakage Between Requests

**Cause**: WASM linear memory NOT cleared between requests.

**Solution**: Require guest `_reset()` export or re-instantiate on return-to-pool.

### Body Lost in AxumDynamic

**Cause**: `body(axum::body::Body::empty())` discards request body.

**Solution**: Use `axum::body::Body::from(body)` instead.

## Plugin Sandbox (Phase 7)

The plugin runtime sandbox hardening (Phase 7) adds a default-deny capability manifest, trust tiers, resource limits, and failure isolation to WASM plugins. All types live in `crates/synvoid-plugin-runtime/src/sandbox/types.rs`.

### Types Module

```rust
use synvoid_plugin_runtime::sandbox::types::{
    PluginManifest, PluginCapabilities, PluginCapability, PluginLimits,
    PluginTrustTier, PluginRuntimeState, PluginInvocationGuard,
    SigningPolicy, PluginSignatureConfig,
    // Phase 7: Sub-capability policies
    PluginMeshPolicy, PluginFilesystemPolicy, PluginNetworkPolicy,
    PluginPersistencePolicy, PluginMetricsPolicy, HostApiFailureClass,
};
```

### PluginManifest

Loaded from `synvoid-plugin.toml` next to the WASM binary. Use `PluginManifest::from_file()` or `PluginManifest::parse_toml()`:

```rust
let manifest = PluginManifest::from_file(Path::new("plugin_dir/synvoid-plugin.toml"))?;
// or from a string
let manifest = PluginManifest::parse_toml(toml_content, Path::new("synvoid-plugin.toml"))?;
```

Manifest parse errors return `ManifestError` (Io, Parse, Validation) and fail plugin load, not server startup.

### PluginCapabilities (Default-Deny)

All capabilities default to `false` / empty. A plugin must explicitly declare every capability it needs:

```rust
let mut caps = PluginCapabilities::default(); // everything denied
caps.request_inspect = true;                  // grant read-only inspection
caps.filesystem_read = vec!["/tmp/cache/*".to_string()]; // grant path-scoped read

// Check at call sites
caps.require(PluginCapability::RequestInspect)?; // Ok
caps.require(PluginCapability::RequestMutate)?;  // Err(CapabilityViolation)
```

`permits()` returns `bool`. `require()` returns `Result<(), CapabilityViolation>`. `iter_flags()` returns all 11 capabilities and their enabled state.

### Phase 7: Sub-Capability Policies

The top-level `PluginCapability::Mesh` gate must be `true` for any mesh operation. The `mesh_policy` sub-struct then narrows which specific operations are allowed:

```rust
let caps = PluginCapabilities {
    mesh: true,
    mesh_policy: PluginMeshPolicy {
        allow_threat_check: true,
        dht_read_prefixes: vec!["threat_indicator:".into()],
        event_emit_topics: vec!["plugin.audit".into()],
        ..Default::default()
    },
    ..Default::default()
};

// Sub-capability checks
caps.check_mesh_dht_read("threat_indicator:1.2.3.4")?;  // Ok
caps.check_mesh_dht_read("dns_zone:example.com")?;       // Err
caps.check_mesh_threat_check()?;                          // Ok
caps.check_mesh_event_emit("plugin.audit.blocked")?;     // Ok
caps.check_mesh_event_emit("mesh.admin")?;               // Err
```

Other sub-capability policies (filesystem, network, persistence, metrics) follow the same default-deny pattern and are ready before their respective host APIs become broad.

### HostApiFailureClass

Stable error classification for host API denials:

```rust
use synvoid_plugin_runtime::sandbox::types::HostApiFailureClass;

// Used in host functions to classify denials
match failure {
    HostApiFailureClass::CapabilityDenied => // top-level cap missing
    HostApiFailureClass::PrefixDenied => // DHT key prefix not in allowlist
    HostApiFailureClass::TopicDenied => // event topic not in allowlist
    HostApiFailureClass::PathDenied => // filesystem path not in allowlist
    HostApiFailureClass::HostDenied => // network dest not in allowlist
    HostApiFailureClass::QuotaExceeded => // quota/size limit exceeded
    HostApiFailureClass::PayloadTooLarge => // payload exceeds limit
    HostApiFailureClass::Timeout => // host call timed out
    HostApiFailureClass::InvalidPointer => // invalid guest pointer
    HostApiFailureClass::BackendUnavailable => // backend unavailable
    HostApiFailureClass::InternalError => // internal host error
}
```

### PluginInvocationGuard

Wraps capability checks, resource limits, concurrency, and state into a single per-plugin guard:

```rust
let guard = PluginInvocationGuard::new(caps, limits, max_concurrency);
assert!(guard.is_invocable()); // Loaded by default

// On failure
guard.record_failure(threshold);
// At threshold → state becomes DisabledByRuntimeFailure, is_invocable() → false

// On capability violation
guard.disable_for_violation();

// Manual recovery
guard.reset_failures();
```

### Signing Policy

> **Phase 13**: `verify_plugin_signature()` now performs full Ed25519 cryptographic verification (binary hash, manifest hash, signature). See `architecture/plugin_runtime_sandbox.md` for details.

```rust
use synvoid_plugin_runtime::sandbox::types::{SigningPolicy, verify_signing_policy};

// In production
verify_signing_policy(
    SigningPolicy::RequireSigned,
    PluginTrustTier::LocalSandboxed,
    None,       // no signature
    true,       // is_production
)?; // → Err(SigningViolation::UnsignedInProduction)

// In development — signing is never enforced
verify_signing_policy(
    SigningPolicy::RequireSigned,
    PluginTrustTier::LocalSandboxed,
    None,
    false,      // is_production = false
)?; // → Ok(())
```

### Trust Tier Semantics

| Tier | Use Case |
|------|----------|
| `Disabled` | Safest default for unknown configs; plugin cannot load. |
| `LocalTrusted` | Operator explicitly trusts; still bounded by declared capabilities. |
| `LocalSandboxed` | **Default.** Unsigned local, sandbox enforced. |
| `SignedSandboxed` | Signature present, full sandbox. |
| `DevelopmentHotReload` | Dev-only; production requires explicit override. |

### Resource Limits

```rust
let limits = PluginLimits {
    timeout_ms: 50,
    max_input_bytes: 262_144,   // 256 KB
    max_output_bytes: 262_144,
    max_concurrency: 4,
    memory_pages: Some(64),     // optional
    fuel: Some(1_000_000),      // optional
};

limits.check_input(100)?;   // Ok
limits.check_output(300_000)?; // Err(ResourceLimitError::OutputTooLarge)
```

### Related Tests

```bash
cargo test --test plugin_capability_boundary_guard
cargo test -p synvoid-plugin-runtime -- test_mesh_policy
cargo test -p synvoid-plugin-runtime -- test_capabilities_mesh
cargo test -p synvoid-plugin-runtime -- test_capabilities_check_metrics
cargo test -p synvoid-plugin-runtime -- test_host_api_failure_class
cargo test -p synvoid-plugin-runtime -- test_manifest_toml_parses_mesh
cargo test -p synvoid-plugin-runtime -- test_signing_payload_includes
cargo test -p synvoid-plugin-runtime -- test_manifest_validate_trust
```

### Signed Byte Loading (Phase 2)

File-based plugin loading reads WASM bytes once, verifies those bytes, and instantiates from the same verified byte slice. This closes TOCTOU races between policy enforcement and instantiation.

```rust
pub struct PreparedPluginLoad {
    pub manifest: PluginManifest,
    pub effective_limits: WasmResourceLimits,
    pub source: PluginSourceIdentity,
    pub wasm_bytes: bytes::Bytes,              // Phase 2: verified bytes
    pub verified_signature: Option<VerifiedPluginSignature>, // Phase 2: crypto metadata
}
```

`WasmRuntime::load_with_policy()` uses `Module::from_binary()` with verified bytes when available.

### Strict SignedSandboxed (Phase 2)

For `SignedSandboxed` trust tier:
- `binary_sha256` must be non-empty and must match actual bytes
- `manifest_sha256` must be non-empty and must match manifest payload hash
- Empty hash fields are rejected in production

### VerifiedPluginSignature (Phase 2)

```rust
pub struct VerifiedPluginSignature {
    pub key_id: String,
    pub binary_sha256: String,
    pub manifest_sha256: String,
    pub algorithm: PluginSignatureAlgorithm,
}
```

### Memory/Mesh Loads (Phase 2)

`load_plugin_from_memory_with_manifest()` is the production path for mesh/memory loaded plugins:

```rust
pub fn load_plugin_from_memory_with_manifest(
    &self,
    name: &str,
    data: &[u8],
    manifest: &PluginManifest,
    limits: WasmResourceLimits,
) -> Result<Arc<WasmRuntime>, WasmPluginError>
```

The existing `load_plugin_from_memory()` defaults to `LocalSandboxed` with all-deny capabilities.

## Plugin Lifecycle Hardening (Phase 9)

Phase 9 hardened how plugins are loaded, reloaded, replaced, disabled, quarantined, and unloaded over time. The key types and patterns relevant to serverless WASM are:

### Generation Tracking

Every plugin load creates a `LoadedPluginGeneration` with a monotonically increasing `PluginGenerationId`. Generation IDs are never reused within process lifetime. In-flight requests hold a stable `Arc<WasmRuntime>` reference to their generation, preventing use-after-reload.

```rust
pub struct LoadedPluginGeneration {
    pub generation_id: PluginGenerationId,
    pub binary_sha256: String,
    pub manifest_sha256: String,
    pub trust_tier: PluginTrustTier,
    pub loaded_at: u64,
}
```

### Atomic Reload Pipeline

Reload follows a prepare-then-commit pattern:
1. `prepare_reload_candidate(path)` — validates the candidate without touching the active generation
2. `commit_reload_candidate(name, runtime, generation)` — atomically swaps under lock

Failed reloads never replace the active generation. The `PluginReloadOutcome` enum provides structured results: `Replaced`, `Unchanged`, or `Failed`.

### File Stability Detection

`FileStabilityPolicy` prevents loading partially written files during hot-reload:

```rust
pub struct FileStabilityPolicy {
    pub debounce: Duration,        // Initial delay (default: 300ms)
    pub stable_checks: usize,      // Consecutive identical observations (default: 3)
    pub stable_interval: Duration,  // Time between checks (default: 100ms)
    pub max_wait: Duration,         // Maximum wait time (default: 5s)
}
```

### Lifecycle State Machine

`PluginLifecycleState` defines explicit states with validated transitions:

```
Loading -> Active | FailedLoad
Active -> Reloading | Disabled | Quarantined | Unloading
Reloading -> Active | FailedLoad
Disabled -> Active (operator reset)
Quarantined -> Disabled | Removed
Unloading -> Removed
```

All transitions are recorded in the lifecycle audit trail via `LifecycleTransition` records.

### Hot Reload Configuration

`HotReloadConfig` separates WASM and native hot-reload gates:
- `enabled` — master toggle
- `production_enabled` — required for production mode
- `unsafe_native_enabled` — separate gate for native extensions
- `require_signed_wasm` — optional signature enforcement

### Operator Lifecycle APIs

Manager provides: `disable_plugin()`, `reset_plugin()`, `remove_plugin()`, `quarantine_plugin()`. Each records audit events with generation, hashes, and reasons.

### Usage Pattern

```rust
use synvoid_plugin_runtime::sandbox::types::{
    PluginGenerationId, LoadedPluginGeneration, PluginLifecycleState,
    PluginReloadOutcome, FileStabilityPolicy, HotReloadConfig,
};

// Check lifecycle state before invoking
let state = manager.get_plugin_lifecycle_state("my-plugin");
if state == PluginLifecycleState::Active {
    // safe to invoke
}

// Reload with generation awareness
match manager.reload_plugin("my-plugin").await? {
    PluginReloadOutcome::Replaced(gen) => { /* new generation active */ }
    PluginReloadOutcome::Unchanged => { /* candidate identical to active */ }
    PluginReloadOutcome::Failed(e) => { /* active generation untouched */ }
}

// Configure hot-reload for production
let config = HotReloadConfig {
    enabled: true,
    production_enabled: true,
    unsafe_native_enabled: false,
    require_signed_wasm: true,
};
```

## ABI Frame Serialization (M2 Phase 05)

The `abi_frame` module provides canonical request/response serialization for the WASM plugin ABI:

- `serialize_headers_canonical()` — single authoritative header encoder with policy bounds
- `build_request_frame()` — canonical request frame builder validating all fields against `RequestFramePolicy`
- `validate_response_transform_output()` — canonical response validator with mutation policy
- `PluginResponseMutationPolicy` — controls response mutation authority (security headers denied by default)
- `SerializationFailureClass` — 13-variant enum for bounded metrics labels

All serialization rejections are metric-recorded without raw payload data. The `WasmRuntime::serialize_headers` function delegates to `serialize_headers_canonical`.