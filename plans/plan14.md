# Plan 14: Serverless Architecture - Mesh Integration & Standalone Enhancements

**Status**: Planning
**Created**: 2026-04-27
**Last Updated**: 2026-04-27 (review)
**Priority**: High
**Estimated Duration**: 4-6 weeks (phased)

---

## Executive Summary

The MaluWAF codebase has a solid serverless foundation using WASM-based functions with instance pooling, auto-scaling, and event-driven invocation. However, the serverless architecture currently only works as **direct HTTP dispatch** - it cannot be routed through the mesh network to origin/serverless nodes. This plan addresses the gaps needed to enable:

1. **Mesh mode serverless**: Distributed serverless execution where edge nodes can proxy requests to origin/serverless nodes
2. **Standalone enhancements**: Cold-start improvements, async invocation, and multi-region routing

---

## Current Architecture Analysis

### What's Working

| Component | Location | Status |
|-----------|----------|--------|
| `ServerlessManager` | `src/serverless/manager.rs` | ✅ Core orchestration complete |
| `InstancePool` (WASM pooling) | `src/serverless/instance_pool.rs` | ✅ Auto-scaling, pre-warming |
| `BackendType::Serverless` | `src/router.rs:55-66` | ✅ Direct HTTP dispatch works |
| `ServerlessFunctionAnnounce` | `src/mesh/protocol.rs:1558` | ✅ DHT announcement works |
| `ServerlessInvokeRequest/Response` | `src/mesh/protocol.rs:1625-1655` | ⚠️ Defined but incomplete |
| `SERVERLESS_ORIGIN` role | `src/mesh/config.rs:33` | ❌ Defined but never used |
| `WasmDistManager` | `src/mesh/wasm_dist.rs` | ⚠️ Exists but not initialized |
| `MeshBackendPool` | `src/mesh/backend.rs:204-299` | ⚠️ Exists but not wired to HTTP |
| `BackendType::Mesh` | `src/router.rs:55-66` | ❌ Defined but never dispatched |

### Critical Bugs Found

1. **`ServerlessInvokeResponse` never sent** (`transport_peer.rs:2527-2539`)
   - Handler logs result but doesn't construct/send response
   - Caller hangs indefinitely waiting for response

2. **`ServerlessInvokeRequest` never sent**
   - No code creates and sends request to remote nodes
   - Announcement/discovery works, invocation doesn't

3. **`BackendType::Mesh` never dispatched**
   - Enum variant exists but no match case in HTTP server
   - `mesh_backend_pool` not passed to `HttpServer`

4. **`SERVERLESS_ORIGIN` role is dead code**
   - Only used in `CallerContext::local()`
   - `is_serverless_origin()` is never called anywhere

5. **Serverless DHT storage missing provenance**
   - No signatures, no origin tracking, no expiration
   - `node_id` not stored in DHT value (bug)

---

## Implementation Phases

### Phase 1: Critical Bug Fixes

**Duration**: 3-5 days
**Risk**: Low

#### 1.1 Fix `ServerlessInvokeResponse` Handling

**File**: `src/mesh/transport_peer.rs` (stream handler call site + handler)

**Problem**: `handle_serverless_invoke_request` executes the function but has no access to `send_stream` to send the response. The response must be sent at the call site in the stream message handler.

**Current flow** (broken):
```rust
// In stream handler (line 2428-2434):
MeshMessage::ServerlessInvokeRequest(req) => {
    self.handle_serverless_invoke_request(&req).await?;
    // Handler logs result but cannot send response - send_stream not available here!
}
```

**Solution** - Modify `handle_serverless_invoke_request` to return result and send at call site:

```rust
// New signature returns result for caller to handle
pub(crate) async fn handle_serverless_invoke_request(
    &self,
    req: &crate::mesh::protocol::ServerlessInvokeRequest,
) -> Result<ServerlessInvokeResponse, ServerlessError> {
    // ... existing execution logic ...

    result.map(|response| {
        ServerlessInvokeResponse {
            function_name: function_name.clone(),
            caller_node_id: req.caller_node_id.clone(),
            timestamp: crate::utils::safe_unix_timestamp(),
            response_data: response.body.to_vec(),
            success: true,
            error_message: String::new(),
            execution_time_ms: start.elapsed().as_millis() as u64,
            response_signature: Vec::new(),
        }
    })
}

// Call site in stream handler:
MeshMessage::ServerlessInvokeRequest(req) => {
    match self.handle_serverless_invoke_request(&req).await {
        Ok(response) => {
            let msg = MeshMessage::ServerlessInvokeResponse(response);
            let encoded = msg.encode()?;
            let len = (encoded.len() as u32).to_be_bytes();
            let _ = send_stream.write_all(&len).await;
            let _ = send_stream.write_all(&encoded).await;
        }
        Err(e) => {
            // Send error response
            let response = ServerlessInvokeResponse {
                function_name: req.function_name.clone(),
                caller_node_id: req.caller_node_id.clone(),
                timestamp: crate::utils::safe_unix_timestamp(),
                response_data: Vec::new(),
                success: false,
                error_message: e.to_string(),
                execution_time_ms: start.elapsed().as_millis() as u64,
                response_signature: Vec::new(),
            };
            let msg = MeshMessage::ServerlessInvokeResponse(response);
            // ... send response ...
        }
    }
}
```

**Verification**:
- Add integration test that sends `ServerlessInvokeRequest` and receives response
- Test error path when function fails

#### 1.2 Add `ServerlessInvokeRequest` Sender

**New File**: `src/mesh/transport_serverless.rs` (or add to existing transport)

**Components needed**:
1. `create_serverless_invoke_request()` - Construct signed request
2. `send_serverless_invoke()` - Send to remote node via bidirectional stream
3. `handle_serverless_invoke_response()` - Handle async response with correlation

**Flow**:
```
Edge Node                           Origin Node
    │                                     │
    │  1. Discover function via DHT        │
    │  2. Create ServerlessInvokeRequest  │
    │────────────────────────────────────► │
    │                                     │
    │                         3. Execute WASM
    │                         4. Send ServerlessInvokeResponse
    │ ◄────────────────────────────────────│
    │                                     │
    5. Process response                   │
```

**Key implementation details**:
- Use existing `send_route_query_stream()` pattern from proxy.rs
- Include `permission_claim` for authorization
- Add correlation ID for tracking

#### 1.3 Initialize `WasmDistManager`

**Location**: Mesh initialization in `src/mesh/transport.rs`

**Problem**: `WasmDistManager` exists and `get_global_wasm_dist_manager()` is used by `src/serverless/manager.rs:469` and `src/plugin/mod.rs:69`, but `set_global_wasm_dist_manager()` is never called.

**Solution**:
```rust
// During mesh transport initialization in transport.rs:
let wasm_dist_manager = Arc::new(WasmDistManager::new());
crate::mesh::set_global_wasm_dist_manager(wasm_dist_manager.clone());

// This enables serverless functions and plugins to fetch WASM from mesh
```

**Additional Requirement**: Add `ServerlessFunction` to `SignedRecordType` enum in `src/mesh/dht/signed.rs` to enable proper DHT record signing and TTL configuration for serverless announcements.

---

### Phase 2: Protocol Enhancement

**Duration**: 5-7 days
**Risk**: Medium

#### 2.1 Add `ServerlessOriginAnnounce` Message

**File**: `src/mesh/protocol.rs`

**Purpose**: Analogous to `UpstreamAnnounce` for serverless function registration in mesh.

**Struct design**:
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerlessOriginAnnounce {
    pub serverless_id: ArcStr,           // Unique function identifier
    pub function_name: String,
    pub routes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub action: AnnounceAction,
    pub signature: Vec<u8>,               // Global node signature
    pub origin_ed25519_pubkey: ArcStr,
    pub origin_signature: Vec<u8>,
    pub org_id: Option<String>,
    pub priority: i32,
    pub geo: Option<String>,
}
```

**Protobuf**: Add to `mesh.proto` and implement encode/decode

**Signature pattern** (must include receiving peer_id to prevent replay):
```rust
let sign_data = format!("{}:{:?}:{}", serverless_id, action, peer_id);
```

#### 2.2 Wire `SERVERLESS_ORIGIN` Role Into Routing

**Files**: `src/mesh/config.rs`, `src/serverless/manager.rs`

**Problem**: `is_serverless_origin()` is never called.

**Solution**:

1. In `verify_caller_permission()` - allow `SERVERLESS_ORIGIN` nodes to invoke:
```rust
if function.definition.require_trusted_caller.unwrap_or(false) {
    if !caller_role.is_global() && !caller_role.is_serverless_origin() {
        return Err(ServerlessError::PermissionDenied(...));
    }
}
```

2. Add routing checks for serverless-origin capability:
```rust
// When routing requests, check if target requires serverless origin
if target.requires_serverless_origin() && !self.node_role.is_serverless_origin() {
    return Err(MeshProxyError::InsufficientRole);
}
```

#### 2.3 Fix Serverless DHT Storage

**File**: `src/mesh/transport_peer.rs:handle_serverless_function_announce`

**Problems**:
1. `node_id` not stored in DHT value
2. No signature verification
3. No expiration tracking

**Solution** - Store proper record with provenance:
```rust
let value = serde_json::json!({
    "function_name": announce.function_name,
    "version": announce.version,
    "checksum": announce.checksum,
    "routes": announce.routes,
    "allowed_methods": announce.allowed_methods,
    "memory_mb": announce.memory_mb,
    "timeout_seconds": announce.timeout_seconds,
    "priority": announce.priority,
    "node_id": announce.node_id,  // FIX: Actually store this
    "org_id": announce.org_id,
    "registered_at": crate::mesh::safe_unix_timestamp(),
    "expires_at": crate::mesh::safe_unix_timestamp() + 3600,
});
```

**Add signature verification**:
```rust
// Verify origin signature against sign_data
let signature_valid = verify_origin_signature(&announce, peer_id);
if !signature_valid {
    tracing::warn!("ServerlessFunctionAnnounce rejected: invalid signature");
    return;
}
```

---

### Phase 3: Mesh Routing Integration

**Duration**: 7-10 days
**Risk**: High

#### 3.1 Wire `mesh_backend_pool` to `HttpServer`

**Files**: `src/server/mod.rs`, `src/http/server.rs`

**Problem**: `mesh_backend_pool` exists in `UnifiedServer` but is never passed to `HttpServer`.

**Solution**:
```rust
// In src/server/mod.rs where HttpServer is created:
HttpServer::new(
    // ... existing args ...
    mesh_backend_pool.clone(),  // NEW: pass pool
)
```

**In `src/http/server.rs`**:
```rust
pub struct HttpServer {
    // ... existing fields ...
    mesh_backend_pool: Option<Arc<MeshBackendPool>>,  // NEW
}

// Add dispatch case for BackendType::Mesh
if matches!(target.backend_type, crate::router::BackendType::Mesh) {
    if let Some(ref pool) = mesh_backend_pool {
        if let Some(backend) = pool.get_backend(&target.upstream) {
            return backend.proxy_request(req).await;
        }
    }
    return Ok(build_502_response("Mesh backend not available"));
}
```

#### 3.2 Add `BackendConfig::Mesh` Variant

**File**: `src/config/site/backend.rs`

**Solution**:
```rust
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(tag = "type")]
pub enum BackendConfig {
    // ... existing variants ...

    #[serde(rename = "mesh")]
    Mesh {
        #[serde(default)]
        upstream_id: Option<String>,
        #[serde(default)]
        serverless_function: Option<String>,
    },
}
```

#### 3.3 Extend `MeshProxy` for Serverless

**File**: `src/mesh/proxy.rs`

**Problem**: `serverless_function:*` upstream IDs need special handling.

**Solution** in `extract_upstream_id()`:
```rust
pub fn extract_upstream_id(req: &Request<Incoming>) -> Option<String> {
    // Check Host header, Authority, etc.
    let host = // ... existing logic ...

    // Check for serverless routing
    if host.starts_with("serverless_function:") {
        return Some(host);
    }

    // ... existing upstream extraction ...
}
```

**Add `route_serverless_request()` method**:
```rust
pub async fn route_serverless_request(
    &self,
    function_name: &str,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError> {
    // 1. Get providers via DHT
    let providers = self.get_providers_for_upstream(
        &format!("serverless_function:{}", function_name)
    ).await?;

    // 2. Filter to serverless-capable peers (by role check, not capability flag)
    let serverless_providers: Vec<_> = providers
        .into_iter()
        .filter(|p| {
            // Check via peer capabilities - peers with serverless functions
            // will have this in their role/announcement
            true  // Filter based on DHT announcement matching function_name
        })
        .collect();

    // 3. Use weighted shuffle to select provider
    let shuffled = self.weighted_shuffle_providers(serverless_providers);

    // 4. Proxy to selected peer
    self.proxy_to_peer_with_fallback(
        &format!("serverless_function:{}", function_name),
        shuffled,
        req,
    ).await
}
```

**Note**: Unlike what I initially wrote, there's no `can_serverless` capability flag. Provider selection is based on:
- DHT route query results (`ProviderInfo`)
- Peer capabilities via `MeshTopology::get_peer().capabilities`
- Role-based filtering via `MeshNodeRole`

#### 3.4 Update `MeshBackend` for Serverless Selection

**File**: `src/mesh/backend.rs`

**Enhancement** - Add serverless-aware selection:
```rust
pub struct ServerlessScore {
    pub warm_instance_score: f64,
    pub capacity_score: f64,
    pub stability_score: f64,
    pub total: f64,
}

impl MeshBackendPool {
    pub async fn select_serverless_backend(
        &self,
        function_name: &str,
    ) -> Option<Arc<MeshBackend>> {
        // Filter backends to those with the function
        let available: Vec<_> = self.backends.read()
            .iter()
            .filter(|b| b.has_function(function_name) && b.is_healthy())
            .cloned()
            .collect();

        // Score based on serverless metrics
        // Prefer backends with warm instances (low cold start risk)
        // Prefer backends with lower utilization
    }
}
```

---

### Phase 4: Standalone Enhancements

**Duration**: 7-10 days
**Risk**: Low

#### 4.1 Enable Async WASM Compilation

**File**: `src/plugin/wasm_runtime.rs`

**Problem**: `Module::from_file` is synchronous, causing 50-500ms cold-start delay.

**Solution**:
```rust
// Enable async feature in Cargo.toml:
// wasmtime = { version = "22", features = ["async"] }

// Use async compilation:
pub async fn load_async(
    path: &Path,
    limits: WasmResourceLimits,
) -> Result<Self, WasmPluginError> {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::SpeedAndSize);
    config.with_module_caching(true);  // Enable compilation cache

    let engine = Engine::new_async(&config).await?;
    let module = Module::from_file_async(&engine, path).await?;

    // ... rest of loading
}

// Alternative: Pre-compile during pool initialization
pub async fn precompile_module(
    engine: &Engine,
    path: &Path,
) -> Result<Module, WasmPluginError> {
    Module::from_file_async(engine, path).await
}
```

#### 4.2 Actually Call `warmup()` in InstancePool

**File**: `src/serverless/instance_pool.rs`

**Problem**: `WasmInstancePool::warmup()` exists but is never called.

**Solution** in `InstancePool::initialize()`:
```rust
pub async fn initialize(&self) -> Result<(), InstancePoolError> {
    // Pre-warm with actual WASM instantiation
    let wasm_path = std::path::Path::new(&self.function_definition.name)
        .with_extension("wasm");

    if wasm_path.exists() {
        // Use precompiled module
        let module = wasmtime::Module::from_file(wasm_path)?;
        self.pool.warmup(&[(self.function_definition.name.clone(), module)]).await;
    }

    // ... rest of initialization
}
```

#### 4.3 Fix Cold-Start Metric

**File**: `src/serverless/instance_pool.rs:214-224`

**Problem**: `spawn_instance` only times Arc wrapper creation (~microseconds).

**Solution** - Measure true cold-start (WASM compilation + instantiation):
```rust
fn spawn_instance(&self, id: String) -> Result<Arc<ServerlessInstance>, InstancePoolError> {
    let start = Instant::now();

    // Actually compile and instantiate WASM (if not using pre-compiled)
    let instance = Arc::new(ServerlessInstance::new(
        id,
        self.function_name.clone(),
        Arc::new(self.create_wasm_instance().await?),  // REAL initialization
        RwLock::new(InstanceMetrics::default()),
        Instant::now(),
        RwLock::new(InstanceState::Initializing),
    ));

    let duration_ms = start.elapsed().as_millis() as u64;
    instance.record_cold_start(duration_ms);  // Now measures real time

    Ok(instance)
}
```

#### 4.4 Add Async Invocation with Correlation IDs

**Pattern**: Use `tokio::sync::oneshot` like `pending_key_requests` in KeyExchange.

**New File**: `src/serverless/async_invoke.rs`

**Components**:
```rust
pub struct AsyncInvokeRequest {
    pub correlation_id: String,
    pub function_name: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Bytes>,
    pub caller: CallerContext,
    pub callback: oneshot::Sender<ServerlessResponse>,
}

pub struct AsyncInvokeManager {
    pending: RwLock<HashMap<String, oneshot::Sender<ServerlessResponse>>>,
    timeout_secs: u64,
}

impl AsyncInvokeManager {
    pub async fn invoke(
        &self,
        request: AsyncInvokeRequest,
    ) -> Result<ServerlessResponse, ServerlessError> {
        let correlation_id = request.correlation_id.clone();

        // Spawn async task that does mesh lookup + invoke
        let handle = tokio::spawn(async move {
            // 1. Discover function via DHT
            // 2. Send ServerlessInvokeRequest
            // 3. Wait for response or timeout
        });

        // Timeout handling
        tokio::time::timeout(
            Duration::from_secs(self.timeout_secs),
            handle,
        ).await?
    }
}
```

#### 4.5 Multi-Region Routing Support

**Leverage existing geo-routing** in `src/mesh/dht/routing/`

**Enhancement** to serverless function announcement:
```rust
// In ServerlessOriginAnnounce
pub struct ServerlessOriginAnnounce {
    // ... existing fields ...
    pub geo: Option<String>,      // e.g., "US-WEST", "EU-CENTRAL"
    pub priority_tier: u32,
}

pub async fn select_closest_serverless_region(
    &self,
    function_name: &str,
    client_geo: &GeoInfo,
) -> Option<String> {
    // 1. Query DHT for all instances of function_name
    // 2. Score by geo_distance + latency
    // 3. Return best match
}
```

---

## File Changes Summary

| File | Phase | Changes |
|------|-------|---------|
| `src/mesh/transport_peer.rs` | 1, 2 | Fix response handling, add role extraction, fix DHT storage |
| `src/mesh/transport.rs` | 1, 3 | Initialize WasmDistManager, add serverless invoke sender |
| `src/mesh/protocol.rs` | 2 | Add `ServerlessOriginAnnounce` message |
| `src/mesh/config.rs` | 2 | Use `SERVERLESS_ORIGIN` in routing decisions |
| `src/mesh/proxy.rs` | 3 | Extend for serverless upstream handling |
| `src/mesh/backend.rs` | 3, 4 | Serverless-aware backend selection, scoring |
| `src/mesh/dht/signed.rs` | 1, 2 | Add `ServerlessFunction` to `SignedRecordType` enum |
| `src/serverless/manager.rs` | 2, 4 | Mesh announcement, async invoke support |
| `src/serverless/instance_pool.rs` | 4 | Fix cold-start measurement, call warmup() |
| `src/plugin/wasm_runtime.rs` | 4 | Add async compilation support |
| `src/router.rs` | 3 | Add `BackendType::Mesh` dispatch |
| `src/http/server.rs` | 3 | Add `mesh_backend_pool` field and dispatch |
| `src/server/mod.rs` | 3 | Wire `mesh_backend_pool` to `HttpServer` |
| `src/config/site/backend.rs` | 3 | Add `BackendConfig::Mesh` variant |
| `src/mesh/dht/keys.rs` | 2 | Add serverless DHT key proper handling |

---

## Testing Strategy

### Unit Tests
- `ServerlessInvokeRequest/Response` encoding/decoding
- `ServerlessOriginAnnounce` signature construction/verification
- Serverless DHT key parsing
- Backend selection scoring

### Integration Tests
- **Phase 1**: Remote serverless invocation (two nodes)
  - Send request from edge, receive response from origin
- **Phase 2**: Function announcement and discovery
  - Announce function, verify in DHT, discover
- **Phase 3**: Mesh routing for serverless
  - Route `serverless_function:*` request through mesh
- **Phase 4**: Cold-start measurement
  - Verify timing reflects actual WASM compilation

### Test Files
```bash
# Run serverless-specific tests
cargo test --lib serverless
cargo test --test integration_test serverless

# Run mesh tests
cargo test --lib mesh
cargo test --test integration_test mesh
```

---

## Verification Commands

```bash
# Verify test compilation
cargo test --lib --no-run

# Run serverless tests
cargo test --lib serverless

# Run mesh integration tests
cargo test --test integration_test

# Verify compilation with all features
cargo check --all-features

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

---

## Dependencies

### External Crates
- `wasmtime` with `async` feature (for async compilation)
- `tokio` (already in use)

### Internal Dependencies
- `MeshTransport` for DHT and peer communication
- `MeshTopology` for peer scoring
- `WasmRuntime` for WASM execution
- `InstancePool` for instance management

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| WASM async compilation breaking existing sync code | Medium | Medium | Add feature-gated async support, keep sync fallback |
| DHT schema changes breaking existing records | Low | High | Version field in stored records, migration path |
| Mesh routing complexity causing performance issues | Medium | Medium | Benchmark before/after, optimize hot paths |
| Breaking change to existing serverless API | Low | Medium | Maintain backward compatibility with `BackendType::Serverless` |

---

## Rollback Plan

If issues arise:
1. **Phase 1 fixes** can be reverted without breaking existing serverless (local dispatch continues to work)
2. **Phase 2 protocol changes** - DHT records are TTL-based, old format expires automatically
3. **Phase 3 routing changes** - `BackendType::Serverless` continues to work as fallback
4. **Phase 4 enhancements** - Feature-gated, disabled by default

---

## Success Criteria

1. ✅ Edge node can discover serverless functions via DHT
2. ✅ Edge node can send `ServerlessInvokeRequest` to origin
3. ✅ Origin node responds with `ServerlessInvokeResponse`
4. ✅ Request routed through mesh using weighted provider selection
5. ✅ Cold-start time accurately measured (50-500ms reflects actual WASM compilation)
6. ✅ Async invocation with correlation IDs works
7. ✅ All existing tests pass
8. ✅ New tests cover the complete invocation flow