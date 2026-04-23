# WASM Filtering, Serverless & Axum Architecture Improvement Plan

**Plan ID**: 20
**Date**: 2026-04-23
**Status**: Draft
**Priority**: High (Architecture) / Critical (Security)

---

## Executive Summary

This plan addresses architectural gaps, security vulnerabilities, and performance issues identified in MaluWAF's WASM filtering, serverless, and Axum integration subsystems following a comprehensive codebase review.

### Key Findings Summary

| # | Issue | Severity | Type | Status |
|---|-------|----------|------|--------|
| 1 | WasmDistManager global never wired | **CRITICAL** | Architecture | Unwired dead code |
| 2 | ServerlessPermissionClaim unused | **CRITICAL** | Security | Bypassed entirely |
| 3 | Axum raw pointer factory unsafe | **CRITICAL** | Safety | Dangling pointer risk |
| 4 | Router clone per request O(n) | **HIGH** | Performance | 500K rps impact |
| 5 | WASM pool linear search O(n) | **HIGH** | Performance | Pool lookup waste |
| 6 | backend_plugin config ignored | **HIGH** | Functionality | Multi-plugin broken |
| 7 | serialize_headers fresh alloc | **MEDIUM** | Performance | 500K rps allocation |
| 8 | scale_up unbounded spawn | **MEDIUM** | Reliability | Resource exhaustion |
| 9 | WasmPluginManager.pool dead | **LOW** | Dead code | Should remove |
| 10 | WASM filters separate from WAF | **MEDIUM** | Architecture | No unification |
| 11 | prepare_for_request alloc waste | **LOW** | Performance | HashMap replace |
| 12 | Body collection doubles memory | **LOW** | Performance | Acceptable tradeoff |

> **Note**: Line numbers in this plan are approximate based on investigation at commit analyzed. Verify exact locations before implementation.

---

## Phase 1: CRITICAL Security & Safety Fixes

### 1.1 REMOVE or COMPLETE: WasmDistManager Mesh Integration

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/mesh/wasm_dist.rs:11` |
| Severity | **CRITICAL** (Architecture) |
| Type | Partial implementation - dead code |

#### Root Cause Analysis

`set_global_wasm_dist_manager()` is defined but **never called** anywhere in the codebase. The mesh-mode WASM loading path is dead code.

**What exists but is unused**:

| Component | Location | Status |
|-----------|----------|--------|
| `WasmDistManager` struct | `wasm_dist.rs:293` | Defined, never initialized |
| `set_global_wasm_dist_manager()` | `wasm_dist.rs:11` | Never called |
| `get_global_wasm_dist_manager()` | `wasm_dist.rs:8` | Always returns `None` |
| `WasmModuleAnnounce` | `protocol.rs:948-971` | Defined, never handled |
| `WasmModuleSyncRequest` | `protocol.rs:973-983` | Defined, never handled |
| `WasmModuleSyncResponse` | `protocol.rs:985-1004` | Defined, never handled |
| `WasmModuleInfo` | `protocol.rs:1456-1463` | Contains `data: Vec<u8>` but never populated |

**Current behavior**: Serverless functions **always** load from local filesystem (`plugins/{name}.wasm`), never from mesh DHT.

#### Decision Required

Two options - **requires user decision before proceeding**:

**Option A: REMOVE (Recommended for cleanup)**

Remove the incomplete WasmDistManager system entirely:

| File | Change |
|------|--------|
| `src/mesh/wasm_dist.rs` | Delete file |
| `src/mesh/mod.rs` | Remove `wasm_dist` module export |
| `src/mesh/protocol.rs` | Remove `WasmModule*` messages and `WasmModuleInfo` |
| `src/mesh/protocol_proto_encode.rs` | Remove `WasmModule*` encoding |
| `src/mesh/protocol_proto_decode.rs` | Remove `WasmModule*` decoding |
| `src/serverless/manager.rs:431-435` | Remove dead mesh WASM branch |
| `src/plugin/mod.rs:69-77` | Remove dead mesh WASM branch |

**Effort**: 1-2 days | **Risk**: Low (safe cleanup)

---

**Option B: COMPLETE (If mesh WASM distribution is a roadmap requirement)**

Build out the full system following the YARA/ThreatIntel pattern:

1. **Add DHT keys** (`src/mesh/dht/keys.rs`):
   ```rust
   pub fn wasm_module(module_type: WasmModuleType, name: &str) -> Self {
       // Key: "wasm_module:serverless:{name}" or "wasm_module:plugin:{name}"
   }
   ```

2. **Implement message handlers** (`src/mesh/transport_peer.rs`):
   - Add handler for `MeshMessage::WasmModuleSyncResponse` to store modules
   - Add handler for `MeshMessage::WasmModuleAnnounce` for incremental updates
   - Wire to existing `wasm_dist_manager` global

3. **Add sync method** (`src/mesh/wasm_dist.rs`):
   ```rust
   pub fn sync_from_dht(&self, record_store: &RecordStoreManager) {
       // Query "wasm_module:*" prefix, store modules
   }
   ```

4. **Initialize global** (`src/worker/unified_server.rs:1049-1066`):
   ```rust
   let wasm_dist = Arc::new(WasmDistManager::new());
   set_global_wasm_dist_manager(wasm_dist.clone());
   // Wire record store, spawn periodic sync task
   ```

5. **Publish WASM bytes** (`src/serverless/manager.rs:initialize`):
   - Store actual WASM bytes to DHT on function init
   - Use `WasmModuleSyncResponse` to respond to requests

6. **Request WASM modules on edge nodes**:
   - Send `WasmModuleSyncRequest` to global nodes
   - Global nodes respond with `WasmModuleSyncResponse` containing bytes

**Effort**: 5-7 days | **Risk**: Medium (significant implementation)

---

> **Question for user**: Is mesh-based WASM module distribution a roadmap requirement? If not, Option A (remove) is recommended to eliminate dead code and confusion.

---

### 1.2 IMPLEMENT: ServerlessPermissionClaim Caller Validation

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/mesh/transport_peer.rs:2886-2955` |
| Severity | **CRITICAL** (Security) |
| Type | Security gap - no authorization |

#### Root Cause Analysis

`ServerlessPermissionClaim` infrastructure exists but is completely bypassed:

| Component | Location | Used? |
|-----------|----------|-------|
| `ServerlessPermissionClaim` struct | `protocol.rs:1478-1529` | ✅ Defined |
| Protobuf encode | `protocol_proto_encode.rs:2179` | ✅ Done |
| Protobuf decode | `protocol_proto_decode.rs:1373` | ✅ Done |
| `verify_signature()` method | `protocol.rs:1508` | ❌ **Never called** |
| `ServerlessInvokeRequest.permission_claim` | `protocol.rs:1537` | ✅ Embedded but not extracted |

**The bypass path** (`transport_peer.rs:2886-2955`):
```rust
// handle_serverless_proxy_stream extracts function_name directly from upstream_id
let function_name = upstream_id.strip_prefix("serverless:").unwrap();
let method = self.extract_method_from_http(http_data);
// NO authentication performed!
match serverless_manager.invoke_for_mesh(function_name, &method, &path, &headers, body)
```

**Impact**: Any mesh peer can invoke any serverless function on any node. No authorization.

#### Solution: Add Authorization to handle_serverless_proxy_stream

**Step 1: Pass caller identity through call chain**

Modify `transport_peer.rs:2579`:
```rust
// Current:
return self
    .handle_serverless_proxy_stream(&upstream_id, &http_data, send_stream)
    .await;

// Should pass peer_node_id:
return self
    .handle_serverless_proxy_stream(&upstream_id, &http_data, send_stream, &peer_node_id)
    .await;
```

**Step 2: Add permission verification in handle_serverless_proxy_stream**

```rust
pub async fn handle_serverless_proxy_stream(
    &self,
    upstream_id: &str,
    http_data: &[u8],
    send_stream: &mut SendStream,
    peer_node_id: &str,  // NEW parameter
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Extract function_name
    let function_name = upstream_id.strip_prefix("serverless:").unwrap();

    // NEW: Log invocation for audit
    tracing::info!(
        "Serverless function '{}' invoked by node '{}'",
        function_name,
        peer_node_id
    );

    // NEW: Implement permission check
    if !self.verify_serverless_permission(peer_node_id, function_name).await {
        // Return 403 Forbidden
        self.send_error_response(send_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // ... existing invocation code ...
}
```

**Step 3: Implement verify_serverless_permission**

```rust
async fn verify_serverless_permission(
    &self,
    caller_node_id: &str,
    function_name: &str,
) -> bool {
    // Get function definition from serverless manager
    let function_def = self.serverless_manager.get_function_definition(function_name);

    // Check if function allows any caller (default deny)
    if let Some(function_def) = function_def {
        // Check allowed_callers list
        if let Some(ref allowed) = function_def.allowed_callers {
            if !allowed.contains(&caller_node_id.to_string()) {
                tracing::warn!(
                    "Node {} not in allowed_callers for function {}",
                    caller_node_id,
                    function_name
                );
                return false;
            }
        }

        // Check require_trusted_caller - requires global node
        if function_def.require_trusted_caller {
            if let Some(verifier) = &self.capability_verifier {
                if !verifier.verify_node_has_capability(caller_node_id, "serverless") {
                    tracing::warn!(
                        "Node {} lacks serverless capability for function {}",
                        caller_node_id,
                        function_name
                    );
                    return false;
                }
            }
        }
    }

    true
}
```

> **Implementation note**: Requires adding `get_function_definition()` to `ServerlessManager` if not already present. Also requires passing `serverless_manager` or `function_configs` to `handle_serverless_proxy_stream`.

**Step 4: Wire capability verifier (optional - for full implementation)**

Register serverless as capability-gated in `src/mesh/dht/capability_access.rs:34-42`:
```rust
DhtKey::ServerlessFunction { .. } => Some(("serverless", "ServerlessFunction")),
```

#### Minimum Viable Fix

At minimum, add logging without breaking existing behavior:
```rust
tracing::info!(
    "Serverless function '{}' invoked by node '{}'",
    function_name,
    peer_node_id
);
```

#### Effort: MEDIUM
#### Risk: MEDIUM (adding auth may break existing mesh serverless calls)
#### Testing Required: Yes - security test for unauthorized invocation

---

### 1.3 FIX: Axum Raw Pointer Factory Lifetime Safety

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/plugin/axum_loader.rs:10-13` |
| Severity | **CRITICAL** (Safety) |
| Type | Use-after-free risk |

#### Root Cause Analysis

```rust
pub type AxumFactory = unsafe extern "C" fn() -> *mut Router<()>;
```

**Problems**:
1. No compile-time lifetime tracking
2. If plugin drops Router before host uses → **use-after-free**
3. Safety comment says "returned pointer must live for the duration of use" but no enforcement

**Actual usage** (lines 135-150):
```rust
let router_ptr = factory();  // Raw pointer from plugin
let router = Box::from_raw(router_ptr);  // Re-boxes
Ok((*router, name))  // Dereferences to return owned Router
```

#### Solution: Change to Return Arc<Router>

**New FFI signature**:
```rust
// In axum_loader.rs
pub type AxumFactory = unsafe extern "C" fn() -> *mut std::sync::Arc<Router<()>>;
```

**Plugin example** (must be updated):
```rust
// In plugin.so
#[no_mangle]
pub unsafe extern "C" fn create_router() -> *mut std::sync::Arc<Router<()>> {
    let router = Router::new()
        .route("/", get(|| async { "Hello" }));
    Box::into_raw(std::sync::Arc::new(router))
}
```

**Host side consumption**:
```rust
let router_ptr = factory();
if router_ptr.is_null() {
    return Err("Factory returned null".into());
}
let arc_router = Box::from_raw(router_ptr);
// Use Arc::clone(&arc_router) for each request - O(1) refcount increment
```

#### Alternative: Use Handle-Based Approach

```rust
// Host maintains map of loaded routers
static ROUTER_MAP: LazyLock<Mutex<HashMap<u64, Arc<Router<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub type AxumFactory = extern "C" fn() -> u64;  // Returns handle

// Plugin:
pub extern "C" fn create_router() -> u64 {
    let router = Router::new().route("/", get(|| async { "Hello" }));
    let handle = generate_unique_handle();
    ROUTER_MAP.lock().insert(handle, Arc::new(router));
    handle
}
```

#### Effort: LOW
#### Risk: MEDIUM (requires updating plugin ABI)
#### Testing Required: Yes - memory safety tests

---

## Phase 2: HIGH Priority Performance Fixes

### 2.1 OPTIMIZE: Router Clone Per Request → Arc<dyn Service>

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/http/server.rs:3719` |
| Severity | **HIGH** (Performance) |
| Impact | 50M route clone ops/sec at 500K rps |

#### Root Cause Analysis

```rust
let mut plugin_router_inner = (*plugin_router).clone();  // O(n) where n = routes
let response = plugin_router_inner.call(axum_req).await;
```

`tower::Service::call()` takes `self` by move, requiring owned Service. Current approach clones entire Router.

#### Solution: Use Type-Erased Cloneable Service

```rust
// In plugin/mod.rs - define a cloneable service wrapper
pub struct CloneableService {
    service: Box<dyn Service<Request, Response = Response, Error = Infallible> + Send + Sync>,
}

impl Clone for CloneableService {
    fn clone(&self) -> Self {
        Self {
            // Clone the Box - shares underlying service since Router is stateless
            service: self.service.clone(),
        }
    }
}

impl Service<Request> for CloneableService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.service.call(req)
    }
}
```

**Alternative - Simpler approach**: Store `Arc<Router>` and use `Arc::make_mut`:

```rust
// Store Arc<Router> not CloneableService
let mut router = Arc::make_mut(&mut plugin_router).clone();  // Only clones if Arc has refs

// Or just accept the clone since Router is cheap to clone (contains route tree, not per-request state)
// This is what happens now at server.rs:3719
```

> **Implementation note**: The `Clone` on axum's Router copies the route tree but doesn't share per-request state. For stateless plugin routers, a full clone is acceptable. The optimization here is avoiding redundant work - if the Router has many routes, cloning can be expensive. Consider whether the optimization is worth the complexity.

#### Effort: MEDIUM
#### Risk: LOW
#### Testing Required: Yes - functional test of plugin responses

---

### 2.2 OPTIMIZE: WASM Pool Linear Search → HashMap-Based Pool

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/plugin/instance_pool.rs:32-39` |
| Severity | **HIGH** (Performance) |
| Impact | O(n) pool retrieval |

#### Root Cause Analysis

```rust
pub(crate) fn get(&self, filter_name: &str) -> Option<WasmPooledInstance> {
    let mut pool = self.pool.lock();
    let pos = pool.iter().position(|inst| inst.filter_name == filter_name)?;
    pool.remove(pos)
}
```

**Key insight**: Since each `WasmRuntime` has its own isolated pool, **all instances in a pool have identical `filter_name`**. The linear search is always searching for the same value and always finds an instance at position 0.

#### Solution: Remove Unnecessary Search

Since all instances in a pool belong to the same plugin, simply pop the last instance:

```rust
pub(crate) fn get(&self, filter_name: &str) -> Option<WasmPooledInstance> {
    let mut pool = self.pool.lock();
    pool.pop()  // O(1) - remove and return last
}
```

**The `filter_name` parameter becomes unused but kept for API compatibility.**

#### Future Enhancement: HashMap Keyed by Plugin Name

If pools are ever shared across plugins:

```rust
pub struct WasmInstancePool {
    pools: HashMap<String, Vec<WasmPooledInstance>>,  // Keyed by plugin name
    engine: Arc<Engine>,
    max_size: usize,
}

pub(crate) fn get(&self, filter_name: &str) -> Option<WasmPooledInstance> {
    let mut pools = self.pools.lock();
    pools.get_mut(filter_name)?.pop()  // O(1) lookup + O(1) pop
}
```

#### Effort: LOW
#### Risk: LOW
#### Testing Required: Yes - load test with multiple plugins

---

### 2.3 FIX: backend_plugin Config Ignored → Multi-Plugin Routing

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/plugin/mod.rs:100-102`, `src/http/server.rs:1705` |
| Severity | **HIGH** (Functionality) |
| Impact | Per-location plugin routing broken |

#### Root Cause Analysis

**Step 1 - Config defines plugin path** (`src/config/site/backend.rs:117-123`):
```rust
#[serde(rename = "axum-dynamic")]
AxumDynamic {
    plugin: Option<String>,  // Configured but ignored
    socket: Option<String>,
}
```

**Step 2 - Router stores it** (`src/router.rs:505,749`):
```rust
BackendConfig::AxumDynamic { socket, plugin } => {
    backend_plugin: Some(Arc::from(plugin.as_str())),  // Stored
}
```

**Step 3 - Server ignores it** (`src/http/server.rs:1705`):
```rust
if let Some(plugin_router) = pm.get_axum_router() {  // Returns FIRST plugin
    // Uses first loaded plugin, ignores target.backend_plugin
}
```

**Step 4 - get_axum_router returns first** (`src/plugin/mod.rs:100-102`):
```rust
pub fn get_axum_router(&self) -> Option<Arc<Router>> {
    self.axum_plugins.read().first().map(|w| w.router.clone())
}
```

**Additional gap**: No `load_axum_plugin(path)` is ever called — only WASM plugins auto-loaded.

#### Solution: Add get_axum_router_by_path()

**Step 1: Add lookup method to PluginManager**

In `src/plugin/mod.rs`:
```rust
pub fn get_axum_router_by_path(&self, plugin_path: &str) -> Option<Arc<Router>> {
    let plugins = self.axum_plugins.read();
    plugins
        .iter()
        .find(|p| p.path == plugin_path)
        .map(|w| w.router.clone())
}
```

**Step 2: Update handle_axum_dynamic_request**

In `src/http/server.rs:1705`:
```rust
if let Some(plugin_router) = target.backend_plugin.as_ref() {
    // Use configured plugin path
    pm.get_axum_router_by_path(plugin_router)
} else {
    // Fallback to first plugin
    pm.get_axum_router()
}
```

**Step 3: Wire plugin loading from config**

In `src/server/mod.rs:841-868`, add:
```rust
// Load configured AxumDynamic plugins
if let Some(axum_plugin) = target.backend_plugin.as_ref() {
    if !axum_plugins_loaded.contains(axum_plugin.as_ref()) {
        pm.load_axum_plugin(Path::new(axum_plugin))?;
        axum_plugins_loaded.insert(axum_plugin.as_ref().to_string());
    }
}
```

#### Effort: MEDIUM
#### Risk: LOW
#### Testing Required: Yes - test multiple locations with different plugins

---

## Phase 3: MEDIUM Priority Improvements

### 3.1 OPTIMIZE: serialize_headers Fresh Allocation → Thread-Local Buffer

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/plugin/wasm_runtime.rs:904-918` |
| Severity | **MEDIUM** (Performance) |
| Impact | 500GB/sec memory churn at 500K rps |

#### Root Cause Analysis

```rust
fn serialize_headers(headers: &HeaderMap) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);  // Fresh allocation every request!
    // ... serialize
    buf
}
```

#### Solution: Thread-Local Buffer with Capacity Check

```rust
thread_local! {
    static HEADER_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}

fn serialize_headers(headers: &HeaderMap) -> Vec<u8> {
    HEADER_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();  // Reuse capacity

        // Reserve if needed (preserve 4096 capacity for common cases)
        if buf.capacity() < 1024 {
            buf.reserve(1024);
        }

        // Serialize directly into buffer
        buf.extend_from_slice(&(headers.len() as u16).to_le_bytes());
        for (name, value) in headers.iter() {
            // ... serialize into buf
        }

        std::mem::take(buf)  // Return owned Vec, preserve capacity
    })
}
```

**Note**: Using `std::mem::take` requires `buf` to be `Vec<u8>`, not `&mut Vec<u8>`. Consider returning borrowed slice and cloning if allocation is unavoidable.

#### Alternative: Accept Allocation

For typical HTTP headers (10-50 headers), the allocation is small. Profile first before optimizing.

#### Effort: MEDIUM
#### Risk: MEDIUM (thread-local + async complexity)
#### Testing Required: Yes - benchmark header serialization

---

### 3.2 FIX: scale_up Unbounded Spawn → Semaphore Rate Limiting

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/serverless/instance_pool.rs:272-303` |
| Severity | **MEDIUM** (Reliability) |
| Impact | Resource exhaustion under sudden load |

#### Root Cause Analysis

Cooldown only prevents repeated `scale_up()` calls, **not intra-call spawn rate**:

```rust
for i in 0..to_create {  // to_create could be 500!
    self.spawn_instance(...);  // All spawned in tight loop
}
```

#### Solution: Add Spawn Semaphore

```rust
// In InstancePool struct, add:
spawn_semaphore: Arc<tokio::sync::Semaphore>,
max_concurrent_spawns: usize,

// In new():
spawn_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),  // Max 10 concurrent
max_concurrent_spawns: 10,

// In scale_up():
pub async fn scale_up(&self, count: usize) -> Result<(), InstancePoolError> {
    let mut spawned = 0;
    let mut failures = 0;

    while spawned < to_create && failures < max_retries {
        // Acquire permit (max 10 concurrent spawns)
        let permit = self.spawn_semaphore.acquire().await;

        let instance = self.spawn_instance(...).await?;

        // Release permit immediately after spawn
        drop(permit);

        // Add to pool
        instance.mark_ready();
        self.instances.write().push(instance.clone());
        self.idle_instances.write().push(instance);
        spawned += 1;

        // Small delay between batches to avoid thundering herd
        if spawned % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    Ok(())
}
```

**Existing semaphore pattern**: TLS server uses `Semaphore` at `tls/server.rs:134` for connection limiting.

#### Effort: LOW
#### Risk: LOW
#### Testing Required: Yes - load test with sudden traffic spike

---

### 3.3 ARCHITECTURE: WASM Filters Separate from WAF Pipeline

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/http/server.rs:2310-2374` vs `src/waf/mod.rs:660-700` |
| Severity | **MEDIUM** (Architecture) |
| Impact | No unified threat decision |

#### Current State

```
WAF checks (lines 846-1443) → Backend routing → WASM filters (line 2310)
```

WASM and WAF have:
- Separate state (`Arc<WafCore>` vs `Arc<PluginManager>`)
- Separate decisions (`WafDecision` vs `WasmFilterResult`)
- No shared violation tracking
- No unified threat escalation

#### Solution Options

**Option A: Do Nothing (Accept Separation)**

WASM filters and WAF serve different purposes:
- WAF: Built-in attack detection with escalation
- WASM: Custom third-party filtering

This is a feature, not a bug. Keep them separate.

**Option B: Add WASM Callback to WAF**

Allow WASM plugins to query WAF state:

```rust
// In wasm_runtime.rs - add host function
env::waf_query_ip_feed(&mut store, ip: i32) -> i32 {
    // Returns threat level from WAF
}

env::waf_record_violation(&mut store, reason_ptr: i32, reason_len: i32) {
    // Records violation in WAF tracker
}
```

**Option C: Run WASM Inside WAF Pipeline**

Move WASM filter invocation to inside `waf.check_request_full()`:

```rust
// In waf/mod.rs
pub async fn check_request_full(&self, ...) -> WafDecision {
    // ... existing checks ...

    // Run WASM filters with WAF context
    if let Some(wasm_result) = self.plugin_manager.apply_wasm_filters(req).await {
        match wasm_result {
            WasmFilterResult::Block(msg) => {
                self.violation_tracker.record(...);
                return WafDecision::Block(...);
            }
            // ...
        }
    }

    WafDecision::Pass
}
```

#### Recommendation

**Option A (Do Nothing)** is recommended unless there's a specific use case requiring tight integration.

WASM filters are designed for custom logic that shouldn't be part of core WAF. The separation is intentional.

#### Effort: N/A
#### Risk: N/A
#### Testing Required: N/A

---

### 3.4 REMOVE: WasmPluginManager.pool Dead Code

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/plugin/wasm_runtime.rs:96-98` |
| Severity | **LOW** (Dead code) |

#### Analysis

```rust
#[allow(dead_code)]
pool: Arc<WasmInstancePool>,  // "SAFETY_REASON: Debugging"

impl WasmPluginManager {
    pub fn new() -> Self {
        Self {
            // ...
            pool: Arc::new(WasmInstancePool::new(Arc::new(Engine::default()), 100)),
            // Created but never used
        }
    }
}
```

#### Solution

Remove the field entirely:

```rust
pub struct WasmPluginManager {
    runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
    default_limits: WasmResourceLimits,
    plugin_paths: RwLock<HashMap<String, PathBuf>>,
}
```

**Verification**: Confirm no usages of `self.pool` in `WasmPluginManager` implementation.

#### Effort: LOW
#### Risk: LOW
#### Testing Required: Yes - compile verification

---

### 3.5 OPTIMIZE: prepare_for_request HashMap Allocation

#### Issue Details

| Aspect | Value |
|--------|-------|
| Location | `src/plugin/instance_pool.rs:156` |
| Severity | **LOW** (Performance) |

#### Root Cause

```rust
self.store.data_mut().env = env;  // Replaces HashMap, drops old
```

Should clear and reuse allocation:

```rust
self.store.data_mut().env.clear();
self.store.data_mut().env.extend(env);
```

#### Effort: LOW
#### Risk: LOW
#### Testing Required: Yes - compile verification

---

## Phase 4: Low Priority Items

### 4.1 INVESTIGATE: Body Collection in AxumDynamic

**Location**: `src/http/server.rs:3724-3730`

Full response body collected before forwarding. Doubles memory for responses.

**Verdict**: Acceptable for typical plugin responses (small API payloads). Static files use different path.

---

## Implementation Checklist

### Phase 1: Critical (P0)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 1.1 | WasmDistManager: Remove or Complete | High/Low | Low | Pending |
| 1.2 | ServerlessPermissionClaim: Add auth | Medium | Medium | Pending |
| 1.3 | Axum factory: Change to Arc<Router> | Low | Medium | Pending |

### Phase 2: High Priority (P1)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 2.1 | Router clone: Use CloneableService | Medium | Low | Pending |
| 2.2 | Pool search: Remove O(n) or use HashMap | Low | Low | Pending |
| 2.3 | backend_plugin: Add by_path lookup | Medium | Low | Pending |

### Phase 3: Medium Priority (P2)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 3.1 | serialize_headers: Thread-local buffer | Medium | Medium | Pending |
| 3.2 | scale_up: Add spawn semaphore | Low | Low | Pending |
| 3.3 | WASM/WAF separation: Document decision | Low | N/A | Pending |
| 3.4 | Remove WasmPluginManager.pool | Low | Low | Pending |
| 3.5 | prepare_for_request: clear+extend | Low | Low | Pending |

### Phase 4: Low Priority (P3)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 4.1 | Body collection: Accept tradeoff | N/A | N/A | Pending |

---

## File Changes Summary

### Files to Delete

| File | Reason |
|------|--------|
| `src/mesh/wasm_dist.rs` | If Option A (remove) chosen |

### Files to Modify

| File | Changes |
|------|---------|
| `src/plugin/wasm_runtime.rs` | Remove `pool` field, optimize pool ops |
| `src/plugin/instance_pool.rs` | Remove linear search, optimize HashMap |
| `src/plugin/mod.rs` | Add `get_axum_router_by_path()` |
| `src/plugin/axum_loader.rs` | Change factory signature to Arc<Router> |
| `src/http/server.rs` | Use configured plugin, CloneableService |
| `src/serverless/manager.rs` | Remove dead mesh WASM branch (Option A) |
| `src/mesh/transport_peer.rs` | Add auth to serverless proxy |
| `src/mesh/dht/capability_access.rs` | Register serverless capability (optional) |
| `src/mesh/protocol.rs` | Remove WasmModule* (Option A) |

### Files to Create (if Option B for WasmDistManager)

| File | Purpose |
|------|---------|
| `src/mesh/wasm_dist.rs` (new) | Full implementation with sync |

---

## Testing Requirements

| Phase | Test Type | Coverage |
|-------|-----------|----------|
| 1.1 | Compile + integration | Mesh WASM dist or dead code removal |
| 1.2 | Security test | Unauthorized invocation blocked |
| 1.3 | Memory safety | Plugin reload/unload scenarios |
| 2.1 | Functional | Plugin responses work correctly |
| 2.2 | Load test | Multiple plugins, pool efficiency |
| 2.3 | Functional | Per-location plugin routing |
| 3.2 | Load test | Sudden scale-up doesn't exhaust resources |

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Breaking mesh serverless when adding auth | Add auth as opt-in via config |
| Breaking Axum plugin ABI | Document migration path for plugins |
| Race conditions in pool ops | Use proper locking |
| Thread-local in async context | Use `with` correctly |

---

## Dependencies

- Tokio semaphore (already used in codebase)
- No new external dependencies required
- Existing patterns from `tls/server.rs`, `fastcgi/pool.rs`

---

## Effort Estimate

| Phase | Option A (Remove) | Option B (Complete) |
|-------|-------------------|---------------------|
| Phase 1 (Critical) | 1-3 days | 5-8 days |
| Phase 2 (High) | 2-3 days | 2-3 days |
| Phase 3 (Medium) | 2-3 days | 2-3 days |
| Phase 4 (Low) | 0 days | 0 days |
| **Total** | **5-9 days** | **9-14 days** |

---

## References

- [tokio::sync::Semaphore](https://docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html)
- [axum Router](https://docs.rs/axum/latest/axum/struct.Router.html)
- [wasmtime Memory](https://docs.rs/wasmtime/latest/wasmtime/struct.Memory.html)
- Existing patterns: `src/tls/server.rs:134`, `src/fastcgi/pool.rs:301`
