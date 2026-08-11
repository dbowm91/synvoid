# Plugin/WASM Runtime Deep Dive

SynVoid's plugin runtime provides a secure WASM sandbox for running plugins with trust tiers, fine-grained capabilities, ABI validation, and hot-reload support.

## Trust Tiers

| Tier | Description | Sandbox |
|------|-------------|---------|
| `Disabled` | Plugin cannot load | N/A |
| `LocalTrusted` | Operator explicit trust | None |
| `LocalSandboxed` (default) | Unsigned; sandbox enforced | Fuel + epoch + memory |
| `SignedSandboxed` | Ed25519 signature verified | Fuel + epoch + memory |
| `DevelopmentHotReload` | Dev-only; requires `dev_mode` | Permissive |

## Capability Model (Default-Deny)

```rust
pub struct PluginCapabilities {
    pub request_inspect: bool,      // Read request data
    pub request_mutate: bool,       // Modify request
    pub response_inspect: bool,     // Read response data
    pub response_mutate: bool,      // Modify response
    pub metrics: bool,              // Emit metrics
    pub persistence: bool,          // Key-value storage
    pub filesystem_read: bool,      // Read files
    pub filesystem_write: bool,     // Write files
    pub network: bool,              // HTTP requests
    pub mesh: bool,                 // DHT queries
    pub admin_events: bool,         // Admin notifications
}
```

Each capability has sub-capability policies (e.g., mesh has DHT read/write prefixes).

## ABI Interface

### Guest Exports

```rust
// Request filtering
filter_request(
    method_ptr: i32, method_len: i32,
    uri_ptr: i32, uri_len: i32,
    headers_ptr: i32, headers_len: i32,
    body_ptr: i32, body_len: i32,
) -> i32  // 0=pass, 1=block, 2=challenge, -1=error

// Response transformation
transform_response(
    status_code: i32,
    body_ptr: i32, body_len: i32,
    out_ptr: i32, out_max: i32,
) -> i32

// Memory management
guest_alloc(size: i32) -> i32
guest_free(ptr: i32, size: i32)
```

### Host Functions

```rust
abort(msg_ptr: i32, msg_len: i32)
check_timeout() -> i32  // Returns 1 if timed out
get_env(key_ptr: i32, key_len: i32, val_ptr: i32, val_max: i32) -> i32
synvoid_read_body_chunk(buf_ptr: i32, buf_max: i32) -> i32
mesh_query_dht(key_ptr: i32, key_len: i32, out_ptr: i32, out_max: i32) -> i32
mesh_check_threat(ip_ptr: i32, ip_len: i32) -> i32
mesh_emit_event(topic_ptr: i32, topic_len: i32, data_ptr: i32, data_len: i32) -> i32
```

### Canonical Header Serialization

Binary format: `[u16 header_count | per entry: u16 name_len | name | u16 val_len | val]`

Single authoritative serializer — ad-hoc encoding forbidden.

## Sandbox Mechanisms

### Fuel Metering

Primary CPU budget for synchronous guest execution. Production tiers **require non-zero fuel**.

```rust
let fuel = 1_000_000;  // Configurable
store.add_fuel(fuel)?;
// Guest execution consumes fuel
// When fuel exhausted → trap
```

### Epoch Interruption

Wall-clock backstop via background task:

```rust
// Background task increments Wasmtime epoch every 10ms
tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        engine.increment_epoch();
    }
});
```

### Memory Containment

```rust
impl ResourceLimiter for RequestContext {
    fn memory_growing(&self, current: usize, desired: usize, max: Option<usize>) -> bool {
        desired <= self.max_memory
    }
    
    fn table_growing(&self, current: u32, desired: u32, max: Option<u32>) -> bool {
        desired <= self.max_table_elements
    }
}
```

## Hot-Reload

```rust
// 1. File watcher detects .wasm change
// 2. Wait for file stability (300ms debounce + 3 checks × 100ms)
// 3. Prepare new instance (never touches active generation)
// 4. Atomic swap: remove old, push new, update generation
// 5. Generation ID: monotonic AtomicU64, never reused
```

## Lifecycle State Machine

```
Loading → Active → Reloading → Active|FailedLoad
Active → Disabled|Quarantined|Unloading
Quarantined → Disabled|Active|Removed
Unloading → Removed
```

All transitions validated by `is_valid_transition()`.

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `WasmRuntime` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` | Loaded WASM instance |
| `WasmPluginManager` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` | Runtime registry |
| `WasmInstancePool` | `crates/synvoid-plugin-runtime/src/instance_pool.rs` | Instance pooling |
| `PluginManager` | `crates/synvoid-plugin-runtime/src/plugin_manager.rs` | Public API |
| `PluginManifest` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs` | TOML manifest |
| `PluginCapabilities` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs` | Default-deny capabilities |
| `EffectivePluginPolicy` | `crates/synvoid-plugin-runtime/src/sandbox/policy.rs` | Runtime policy |
| `RequestFrame` | `crates/synvoid-plugin-runtime/src/abi_frame.rs` | Canonical request frame |
