# Serverless Architecture - Mesh Mode Implementation Plan

## Overview

This plan addresses the implementation of serverless function support in MaluWAF that operates seamlessly in both standalone mode and mesh mode (as origin servers). The goal is to create a production-ready serverless platform with WASM-based function execution, distributed function discovery, and secure cross-node invocation.

## Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **WASM Distribution** | Hybrid via global nodes | Global nodes act as CDN for WASM modules; most scalable for edge-heavy topologies |
| **Security Model** | Secure by default | All serverless functions protected by default; explicit `public_function = true` to bypass |
| **Instance Pooling** | Local only | Origins run instances; edges proxy requests - simpler, more predictable latency |
| **Discovery** | DHT-based | Functions discoverable via DHT keys; topology-based routing as fallback |

---

## Review Summary

| Component | Current State | Target State | Priority |
|-----------|--------------|--------------|----------|
| Core Manager | ✅ Working | ✅ Working | - |
| Instance Pooling | ✅ Working | ✅ Working | - |
| Local WASM Loading | ✅ Working | ✅ Working | - |
| HTTP/TLS Integration | ✅ Working | ✅ Working | - |
| DHT Discovery | ⚠️ Broken (key mismatch) | ✅ Working | HIGH |
| Origin Registration | ⚠️ Partial | ✅ Complete | HIGH |
| WASM Distribution | ⚠️ Infrastructure only | ✅ Working | HIGH |
| Remote Execution | ⚠️ Missing caller context | ✅ Working | HIGH |
| Security Verification | ⚠️ Not integrated | ✅ Working | HIGH |
| Mesh Health Broadcast | ❌ Missing | ✅ Working | MEDIUM |
| Event System | ⚠️ Stub only | ✅ Working | MEDIUM |
| Cold Start Optimization | ✅ Working | ✅ Enhanced | LOW |

---

## Phase 1: Critical Fixes (~12 hours)

### Issue #1: DHT Key Mismatch

**Priority**: HIGH

#### Problem

The DHT stores function metadata under key `serverless_function:{name}` (via `DhtKey::serverless_function()`), but lookups use `serverless:{name}` in two places.

**Affected Files**:
- `src/serverless/manager.rs:723-725` - lookup for `RemoteExecutionRequired`
- `src/http/server.rs:1900` - lookup for `peer_node_id`

**Storage** (correct):
```rust
// manager.rs:354 - Stores under CORRECT key
let key = crate::mesh::dht::keys::DhtKey::serverless_function(&func_def.name);
// Produces: "serverless_function:{name}"
```

**Lookups** (incorrect):
```rust
// manager.rs:723-725 - LOOKS UP WRONG KEY
let upstream_id = format!("serverless:{}", function_name);
if rs.get_record(&upstream_id).is_some() {  // Checks "serverless:{name}"
```

```rust
// http/server.rs:1900 - ALSO LOOKS UP WRONG KEY
rs.get_record(&format!("serverless:{}", function_name))  // Checks "serverless:{name}"
```

**Fix Required** (Option A - Use correct key):
```rust
// Option A: Use correct DHT key in lookups
let dht_key = crate::mesh::dht::keys::DhtKey::serverless_function(function_name);
if rs.get_record(dht_key.as_str()).is_some() {
    // ...
}

// And update the error to include correct key for HTTP server lookup
rs.get_record(&crate::mesh::dht::keys::DhtKey::serverless_function(function_name).as_str())
```

**Fix Required** (Option B - Use consistent key everywhere):
```rust
// Option B: Change storage to use "serverless:{name}" everywhere
let key = format!("serverless:{}", func_def.name);
```

#### Recommendation

**Option A is preferred** because:
1. Uses the existing `DhtKey::serverless_function()` enum variant
2. Maintains consistency with `discover_serverless_functions()` which queries `serverless_function:` prefix
3. Easier to find all usages via `grep serverless_function:`

#### Action Items

- [ ] Fix DHT key lookup in `serverless/manager.rs:723-725`
- [ ] Fix DHT key lookup in `http/server.rs:1900`
- [ ] Add integration test for function discovery

---

### Issue #2: Missing Node ID in DHT Records

**Priority**: HIGH

#### Problem

DHT records store function metadata but not the `node_id` of the provider. Edge nodes cannot determine where to route requests for functions not present locally. The HTTP server lookup at `http/server.rs:1900-1903` expects `node_id` in the record, but the storage at `manager.rs:354-364` doesn't include it.

**Location**: `src/serverless/manager.rs:354-368` (storage) vs `src/http/server.rs:1900-1903` (lookup)

**Current Storage**:
```rust
let value = serde_json::json!({
    "function_name": func_def.name,
    "version": 1,
    "routes": func_def.routes,
    "allowed_methods": func_def.allowed_methods,
    "memory_mb": func_def.memory_mb,
    "timeout_seconds": func_def.timeout_seconds,
    "priority": 100,
    "announced_at": chrono::Utc::now().timestamp(),
    // NO node_id! - http/server.rs:1902 expects this field
});
```

**Expected by HTTP Server**:
```rust
// http/server.rs:1899-1903
rs.get_record(&format!("serverless_function:{}", function_name))
    .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.value).ok())
    .and_then(|v| v.get("node_id").and_then(|n| n.as_str()).map(|s| s.to_string()))
```

**Fix Required**:
```rust
// Get node_id from transport (ServerlessManager has transport access)
let node_id = self.transport
    .read()
    .as_ref()
    .map(|t| t.get_node_id())
    .unwrap_or_else(|| "unknown".to_string());

let value = serde_json::json!({
    "function_name": func_def.name,
    "version": 1,
    "node_id": node_id,  // ADD THIS - expected by http/server.rs:1902
    "routes": func_def.routes,
    "allowed_methods": func_def.allowed_methods,
    "memory_mb": func_def.memory_mb,
    "timeout_seconds": func_def.timeout_seconds,
    "priority": 100,
    "announced_at": chrono::Utc::now().timestamp(),
});
```

**Note**: This fix MUST be done together with Issue #1 (DHT key mismatch), since the HTTP server already looks up `serverless_function:{name}` (correct key) but expects `node_id` in the value.

#### Action Items

- [ ] Add `node_id` field to DHT record in `serverless/manager.rs`
- [ ] Test edge node can extract node_id from record
- [ ] Verify DHT key consistency (Issue #1 prerequisite)

---

### Issue #3: Security Verification Not Integrated

**Priority**: HIGH

#### Problem

The `verify_caller_permission()` function exists in `serverless/manager.rs:190-282` but is never called. All mesh invocations execute without permission checks.

**Location**: `src/mesh/transport_peer.rs:2953-2954`

**Current Code**:
```rust
match serverless_manager
    .invoke_for_mesh(function_name, &method, &path, &headers, body)
    .await
// NO permission check!
```

#### Implementation

**Step 1**: Add caller context to invocation

Create a `CallerContext` struct to pass identity information:

```rust
// In src/serverless/manager.rs
pub struct CallerContext {
    pub node_id: String,
    pub role: crate::mesh::config::MeshNodeRole,
    pub org_id: Option<String>,
    pub tier: Option<u32>,
}

pub async fn invoke_for_mesh_with_context(
    &self,
    function_name: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    caller: CallerContext,
) -> Result<ServerlessResponse, ServerlessError> {
    // Verify permissions first
    self.verify_caller_permission(
        function_name,
        &caller.node_id,
        caller.role,
        caller.org_id.as_deref(),
        caller.tier,
    )?;

    // Then execute
    self.invoke_for_mesh(function_name, method, path, headers, body).await
}
```

**Step 2**: Wire into mesh transport

```rust
// In src/mesh/transport_peer.rs:2953
let caller = CallerContext {
    node_id: self.node_id.clone(),
    role: self.role,
    org_id: self.org_id.clone(),
    tier: self.tier_level,
};

match serverless_manager
    .invoke_for_mesh_with_context(function_name, &method, &path, &headers, body, caller)
    .await
```

**Step 3**: Add config option for public functions (secure by default)

```rust
// In src/config/serverless.rs:FunctionDefinition
#[serde(default = "default_public_function")]
pub public_function: bool,

fn default_public_function() -> bool {
    false  // Secure by default
}
```

#### Action Items

- [ ] Create `CallerContext` struct
- [ ] Add `invoke_for_mesh_with_context()` method
- [ ] Wire caller context in mesh transport
- [ ] Add `public_function` config option
- [ ] Set `public_function = true` only when explicitly intended
- [ ] Add integration tests for permission enforcement

---

## Phase 2: Mesh Integration (~24 hours)

### Issue #4: Missing `announce_serverless()` Method

**Priority**: HIGH

#### Problem

HTTP upstreams use `MeshTransport::announce_upstream()` for mesh-wide registration, but there's no equivalent for serverless functions. Functions only get DHT storage, not topology announcement. Also, `ServerlessFunctionAnnounce` struct is missing the `node_id` field needed for edge routing.

**Location**: `src/mesh/transport.rs` - should add similar method

**Current `ServerlessFunctionAnnounce` struct** (`protocol.rs:1466-1475`):
```rust
pub struct ServerlessFunctionAnnounce {
    pub function_name: String,
    pub version: u64,
    pub checksum: String,
    pub routes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub priority: i32,
    // MISSING: node_id - needed for edge to route requests
}
```

**Missing Fields in `discover_serverless_functions()`** (`transport.rs:637-684`):
- Does NOT extract or store `node_id` from DHT record
- Edge cannot determine which node hosts the function

#### Implementation

**Step 1**: Add `node_id` to `ServerlessFunctionAnnounce`:
```rust
// In src/mesh/protocol.rs
pub struct ServerlessFunctionAnnounce {
    pub function_name: String,
    pub version: u64,
    pub checksum: String,
    pub routes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub priority: i32,
    pub node_id: String,  // ADD THIS
}
```

**Step 2**: Update `discover_serverless_functions()`:
```rust
// Extract node_id from DHT record value
let node_id = value
    .get("node_id")
    .and_then(|v| v.as_str())
    .unwrap_or("")
    .to_string();

// Include in returned struct
functions.push(crate::mesh::protocol::ServerlessFunctionAnnounce {
    function_name,
    version,
    checksum,
    routes,
    allowed_methods,
    memory_mb,
    timeout_seconds,
    priority,
    node_id,  // ADD THIS
});
```

**Step 3**: Create `announce_serverless()` method in `MeshTransport`:
```rust
// In src/mesh/transport.rs - new method
pub async fn announce_serverless(
    &self,
    function: &FunctionDefinition,
    node_id: &str,
) -> Result<(), ServerlessError> {
    let upstream_id = format!("serverless:{}", function.name);

    // 1. Register in local topology
    self.topology.add_local_upstream(
        &upstream_id,
        &format!("http://127.0.0.1:{}", self.port), // Local backend
        100,
        1.0,
        Some(vec!["serverless".to_string()]),
    ).await;

    // 2. Create signed announcement
    let announcement = crate::mesh::protocol::ServerlessFunctionAnnounce {
        function_name: function.name.clone(),
        version: 1,
        checksum: String::new(),  // TODO: Add WASM checksum
        routes: function.routes.clone(),
        allowed_methods: function.allowed_methods.clone(),
        memory_mb: function.memory_mb,
        timeout_seconds: function.timeout_seconds,
        priority: 100,
        node_id: node_id.to_string(),
    };

    // 3. Broadcast to global nodes via mesh message
    self.broadcast_to_global_nodes(announcement).await?;

    Ok(())
}
```

#### Action Items

- [ ] Add `node_id` field to `ServerlessFunctionAnnounce` in `protocol.rs`
- [ ] Update `discover_serverless_functions()` to extract and return `node_id`
- [ ] Create `announce_serverless()` method in `MeshTransport`
- [ ] Integrate into `ServerlessManager::initialize()`
- [ ] Add signature support for announcements
- [ ] Test multi-node function discovery

---

### Issue #5: Edge Discovery Not Integrated

**Priority**: HIGH

#### Problem

`MeshTransport::discover_serverless_functions()` exists but is never called. Edge nodes don't automatically discover functions available from origin nodes. Additionally, the `register_function_routing()` method in `ServerlessManager` is dead code (`#[allow(dead_code)]`).

**Location**: `src/mesh/transport.rs:625-693` (discovery exists but not called)

**Dead Code**:
```rust
// src/serverless/manager.rs:414-425
#[allow(dead_code)]  // MARKED DEAD CODE
async fn register_function_routing(&self, func_def: &FunctionDefinition) {
    // This is never called from anywhere
}
```

#### Implementation

1. Add discovery trigger on mesh connection
2. Wire `discover_serverless_functions()` into mesh startup
3. Cache discovered functions locally
4. Update cache periodically

```rust
// In src/mesh/transport.rs - on mesh connect (new method)
pub async fn on_mesh_connected(&self) {
    // Discover available serverless functions
    let functions = self.discover_serverless_functions();

    // Store in local cache for fast lookup
    let mut cache = self.serverless_function_cache.write();
    for func in functions {
        cache.insert(func.function_name.clone(), func);
    }

    tracing::info!("Cached {} serverless functions from mesh", cache.len());
}

// Call this from mesh connection handler
pub async fn start_serverless_discovery_loop(&self) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 min refresh
    loop {
        interval.tick().await;
        self.on_mesh_connected().await;
    }
}
```

#### Action Items

- [ ] Wire `discover_serverless_functions()` into mesh connection
- [ ] Add local cache field to `MeshTransport` for discovered functions
- [ ] Implement periodic refresh loop
- [ ] Remove or implement `register_function_routing()` dead code
- [ ] Test edge can route to origin serverless function

---

### Issue #6: Remote Execution Caller Context

**Priority**: HIGH

#### Problem

When edge proxies requests to origin, the caller's identity is not propagated. Origin cannot verify who initiated the request. The existing `ServerlessInvokeRequest` struct has `caller_node_id` but it's not being used for permission verification.

**Location**: `src/mesh/transports/manager.rs:534` (proxy call)

**Existing Protocol Structs** (`protocol.rs:1532-1577`):
```rust
pub struct ServerlessInvokeRequest {
    pub function_name: String,
    pub caller_node_id: String,  // Already exists!
    pub timestamp: u64,
    pub call_signature: Vec<u8>,
    pub permission_claim: Option<ServerlessPermissionClaim>,
}

pub struct ServerlessInvokeResponse {
    pub function_name: String,
    pub caller_node_id: String,
    pub timestamp: u64,
    pub response_data: Vec<u8>,
    pub success: bool,
    pub error_message: String,
    pub execution_time_ms: u64,
    pub response_signature: Vec<u8>,
}
```

#### Implementation

The struct already exists. Need to:

1. Wire caller identity into the request when proxying
2. Use `caller_node_id` in `verify_caller_permission()` on origin
3. Add `caller_role`, `caller_org_id`, `caller_tier` to the request (or derive from node record)

```rust
// Step 1: In src/mesh/transports/manager.rs - add caller context to proxy
pub async fn proxy_serverless_request<B>(
    &self,
    function_name: &str,
    peer_node_id: &str,
    request: http::Request<B>,
    caller_context: CallerContext,  // NEW param
) -> Result<...> {
    let invoke_request = ServerlessInvokeRequest {
        function_name: function_name.to_string(),
        caller_node_id: caller_context.node_id.clone(),
        timestamp: current_timestamp(),
        call_signature: vec![],
        permission_claim: None,
    };
    // ... serialize and send
}
```

```rust
// Step 2: In src/mesh/transport_peer.rs - pass caller context from edge
let caller = CallerContext {
    node_id: self.node_id.clone(),
    role: self.role,
    org_id: self.org_id.clone(),
    tier: self.tier_level,
};

match serverless_manager
    .invoke_for_mesh_with_context(function_name, &method, &path, &headers, body, caller)
    .await
```

#### Action Items

- [ ] Add `CallerContext` struct to `serverless/manager.rs`
- [ ] Wire caller context into `proxy_serverless_request()`
- [ ] Call `verify_caller_permission()` in `invoke_for_mesh()`
- [ ] Add `public_function` config to bypass permission check
- [ ] Test end-to-end permission enforcement

---

## Phase 3: WASM Distribution via Global Nodes (~24 hours)

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GLOBAL NODE                                  │
│  ┌──────────────────┐                                               │
│  │  WasmDistManager │◄── Stores WASM binaries + metadata            │
│  └────────┬─────────┘                                               │
│           │                                                           │
│           │ Announce / Sync                                          │
└───────────┼───────────────────────────────────────────────────────────┘
            │ QUIC
    ┌───────┴───────┐
    ▼               ▼
┌─────────┐   ┌─────────┐
│ ORIGIN  │   │  EDGE   │
│ - Runs  │   │ - Proxies│
│   instances│  │ - Caches│
│ - Publishes │ │   WASM  │
│   WASM   │   │         │
└─────────┘   └─────────┘
```

### Issue #7: WASM Publisher on Origin

**Priority**: HIGH

#### Problem

`WasmDistManager` and `WasmModuleAnnounce` message types exist but:
1. `WasmDistManager` is never initialized (no call to `set_global_wasm_dist_manager()`)
2. `WasmModuleAnnounce` message is decoded but has no handler that acts on it
3. Nothing populates the WASM distribution store

**Locations**: 
- `src/mesh/wasm_dist.rs` - manager exists but never initialized
- `src/mesh/protocol.rs:948-971` - message type defined
- `src/mesh/protocol_proto_decode.rs:1283` - decodes but doesn't handle

#### Current State

```rust
// WasmDistManager exists but is never initialized
pub fn get_global_wasm_dist_manager() -> Option<Arc<WasmDistManager>> {
    WASM_DIST_MANAGER.read().as_ref().cloned()
}

// WasmModuleAnnounce is decoded but handler just returns it - no processing
proto::mesh_message::Payload::WasmModuleAnnounce(r) => {
    Ok(MeshMessage::WasmModuleAnnounce { ... })  // Just returns the message
}
```

#### Implementation

**Step 1**: Initialize `WasmDistManager` in mesh startup:
```rust
// In src/mesh/transport.rs - during initialization
let wasm_dist = Arc::new(WasmDistManager::new());
crate::mesh::set_global_wasm_dist_manager(wasm_dist.clone());
```

**Step 2**: Add handler for `WasmModuleAnnounce` in mesh transport:
```rust
// In src/mesh/transport.rs - new handler method
pub async fn handle_wasm_module_announce(
    &self,
    msg: crate::mesh::protocol::WasmModuleAnnounce,
) -> Result<(), MeshTransportError> {
    let wasm_dist = crate::mesh::get_global_wasm_dist_manager()
        .ok_or_else(|| MeshTransportError::Internal("No WASM dist manager".into()))?;

    // Store module metadata (binary data fetched separately via sync)
    wasm_dist.store_versioned(WasmModuleInfo {
        module_name: msg.module_name,
        module_type: msg.module_type,
        version: msg.version,
        size_bytes: msg.size_bytes,
        checksum: msg.checksum,
        data: vec![],  // Data fetched via WasmModuleSyncRequest
        timestamp: msg.timestamp,
        source_node_id: msg.source_node_id,
        signature: msg.signature,
        signer_public_key: msg.signer_public_key,
    });

    tracing::info!("Received WASM module announcement: {} v{}", msg.module_name, msg.version);
    Ok(())
}
```

**Step 3**: Implement publisher on origin (called during function initialization):
```rust
// In src/serverless/manager.rs - on function load
pub fn publish_wasm_to_mesh(&self, function_name: &str) -> Result<(), ServerlessError> {
    let wasm_dist = crate::mesh::get_global_wasm_dist_manager()
        .ok_or_else(|| ServerlessError::WasmError("No WASM dist manager".into()))?;

    let wasm_path = std::path::PathBuf::from("plugins").join(function_name).with_extension("wasm");
    let data = std::fs::read(&wasm_path)
        .map_err(|e| ServerlessError::WasmError(format!("Failed to read WASM: {}", e)))?;

    let checksum = sha256::digest(&data);

    let info = WasmModuleInfo {
        module_name: function_name.to_string(),
        module_type: WasmModuleType::Serverless,
        version: 1,
        size_bytes: data.len() as u64,
        checksum: checksum.clone(),
        data,  // Store the actual binary
        timestamp: current_timestamp(),
        source_node_id: self.transport.read().as_ref().map(|t| t.get_node_id()).unwrap_or_default(),
        signature: vec![],
        signer_public_key: vec![],
    };

    wasm_dist.store(info)?;

    // Announce to mesh (via MeshTransport)
    if let Some(t) = self.transport.read().as_ref() {
        t.announce_wasm_module(function_name, 1, &checksum).await?;
    }

    Ok(())
}
```

**Step 4**: Create `announce_wasm_module()` method in MeshTransport:
```rust
// In src/mesh/transport.rs - new method
pub async fn announce_wasm_module(
    &self,
    module_name: &str,
    version: u64,
    checksum: &str,
) -> Result<(), MeshTransportError> {
    let wasm_dist = crate::mesh::get_global_wasm_dist_manager()
        .unwrap();

    let info = wasm_dist.get_module_info(module_name, WasmModuleType::Serverless)
        .ok_or_else(|| MeshTransportError::NotFound)?;

    let announcement = crate::mesh::protocol::MeshMessage::WasmModuleAnnounce {
        request_id: uuid::Uuid::new_v4().to_string(),
        module_name: module_name.to_string(),
        module_type: WasmModuleType::Serverless,
        version,
        size_bytes: info.size_bytes,
        checksum: checksum.to_string(),
        timestamp: current_timestamp(),
        source_node_id: self.node_id.clone(),
        signature: vec![],  // TODO: Sign with node key
        signer_public_key: vec![],
    };

    self.broadcast_to_global_nodes(announcement).await?;
    Ok(())
}
```

#### Action Items

- [ ] Initialize `WasmDistManager` in mesh transport startup
- [ ] Add `WasmModuleAnnounce` handler in mesh transport
- [ ] Implement `publish_wasm_to_mesh()` in ServerlessManager
- [ ] Implement `announce_wasm_module()` in MeshTransport
- [ ] Call publisher during function initialization
- [ ] Add Ed25519 signing for announcements
- [ ] Add integration test for WASM distribution

---

### Issue #8: Global Node Caching

**Priority**: HIGH

#### Problem

Global nodes receive WASM announcements but don't cache them for distribution to edges.

#### Implementation

```rust
// In src/mesh/transport.rs - WasmModuleAnnounce handler
pub async fn handle_wasm_module_announce(
    &self,
    announce: crate::mesh::protocol::WasmModuleAnnounce,
) -> Result<(), MeshTransportError> {
    // Verify signature from origin/global
    self.verify_wasm_announce_signature(&announce)?;

    // Store in local WasmDistManager
    let wasm_dist = crate::mesh::get_global_wasm_dist_manager().unwrap();
    wasm_dist.store_versioned(WasmModuleInfo {
        module_name: announce.module_name,
        module_type: announce.module_type,
        version: announce.version,
        size_bytes: announce.size_bytes,
        checksum: announce.checksum,
        data: vec![],  // Data fetched via sync request
        timestamp: announce.timestamp,
        source_node_id: announce.source_node_id,
        signature: announce.signature,
        signer_public_key: announce.signer_public_key,
    });

    // Track for sync requests
    self.pending_wasm_modules.write().insert(
        (announce.module_name.clone(), announce.version),
        announce,
    );

    Ok(())
}
```

#### Action Items

- [ ] Add `WasmModuleAnnounce` handler in mesh transport
- [ ] Implement signature verification
- [ ] Add `pending_wasm_modules` tracking map
- [ ] Global node caches module metadata

---

### Issue #9: Edge Fetch-on-Demand

**Priority**: HIGH

#### Problem

Edges need to fetch WASM modules from global nodes when first encountering a function.

#### Implementation

```rust
// In src/serverless/manager.rs - fetch missing WASM
pub async fn fetch_wasm_for_function(&self, function_name: &str) -> Result<(), ServerlessError> {
    let wasm_dist = crate::mesh::get_global_wasm_dist_manager()
        .ok_or_else(|| ServerlessError::WasmError("No WASM dist manager".into()))?;

    // Check if we already have it
    if wasm_dist.get_module_data(function_name, WasmModuleType::Serverless).is_some() {
        return Ok(());
    }

    // Request from mesh
    if let Some(transport) = self.transport.read().as_ref() {
        transport.request_wasm_module(function_name).await?;
    }

    Ok(())
}
```

#### Action Items

- [ ] Add `request_wasm_module()` to MeshTransport
- [ ] Add `WasmModuleSyncRequest/Response` handlers
- [ ] Implement retry logic for failed fetches
- [ ] Add module version checking

---

## Phase 4: Polish & Observability (~16 hours)

### Issue #10: Mesh Health Broadcast

**Priority**: MEDIUM

#### Problem

Health status is not published to mesh. Edge nodes cannot query function health.

#### Implementation

```rust
// In src/serverless/manager.rs - periodic health broadcast
pub async fn health_broadcast_loop(&self) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        interval.tick().await;

        let health = self.get_health_status();
        let key = crate::mesh::dht::keys::DhtKey::serverless_health(&self.node_id);

        if let Some(rs) = self.record_store.read().as_ref() {
            let value = serde_json::to_vec(&health).unwrap();
            rs.store_and_announce(key.as_str().to_string(), value, 60); // Short TTL
        }
    }
}

pub struct ServerlessHealthStatus {
    pub node_id: String,
    pub functions: Vec<FunctionHealth>,
    pub timestamp: u64,
}

pub struct FunctionHealth {
    pub name: String,
    pub healthy: bool,
    pub invocations: u64,
    pub errors: u64,
    pub avg_duration_ms: f64,
    pub active_instances: usize,
    pub cold_starts: u64,
}
```

#### Action Items

- [ ] Create health status structs
- [ ] Implement health broadcast loop
- [ ] Add `serverless_health:{node_id}` DHT key
- [ ] Add edge-side health querying
- [ ] Add health-based routing (avoid unhealthy origins)

---

### Issue #11: Event System Implementation

**Priority**: MEDIUM

#### Problem

Event system is stubbed - `subscribe_to_event()` and `publish_event()` exist but event handling is not integrated with mesh.

#### Implementation

Events should flow through mesh message protocol:

```rust
// In src/mesh/protocol.rs - new message type
ServerlessEvent {
    request_id: String,
    topic: String,
    payload: Vec<u8>,
    source_node_id: String,
    timestamp: u64,
}

// Handler in mesh transport
pub async fn handle_serverless_event(&self, event: ServerlessEvent) {
    // Route to local subscribers
    let functions = self.serverless_manager.get_subscribed_functions(&event.topic);

    for func_name in functions {
        self.serverless_manager.publish_event(&event.topic, &event.payload);
    }

    // Forward to other mesh nodes if hub mode
    if self.is_hub() {
        self.broadcast_event_to_edges(event).await;
    }
}
```

#### Action Items

- [ ] Add `ServerlessEvent` message type
- [ ] Implement mesh event routing
- [ ] Connect to existing subscription system
- [ ] Add event delivery confirmation

---

### Issue #12: Cold Start Optimization

**Priority**: LOW

#### Current State

Already implemented:
- `pre_warm_instances` (default: 2)
- `idle_timeout_seconds` (default: 300s)
- `cranelift_opt_level(SpeedAndSize)`
- `memory_init_cow(true)`

#### Potential Improvements

| Optimization | Impact | Complexity |
|-------------|--------|------------|
| **`InstancePre`** | 20-40% faster | Low - wasmtime API |
| **Wizer pre-initialization** | 1.35-6x faster startup | Low - build-time tool |
| **Pre-compiled `.cwasm`** | Eliminates JIT | Medium - cache |

#### Action Items

- [ ] Research wasmtime `InstancePre` API
- [ ] Add as config option
- [ ] Benchmark before/after

---

## New Files Required

| File | Purpose | Phase |
|------|---------|-------|
| `src/mesh/wasm_dist_integration.rs` | WASM distribution logic | 3 |
| `src/mesh/serverless_health.rs` | Health broadcast | 4 |
| `src/mesh/serverless_event.rs` | Event handling | 4 |

---

## Modified Files Summary

| File | Changes | Phase |
|------|---------|-------|
| `src/serverless/manager.rs` | DHT key fix, node_id, caller context, publisher | 1-3 |
| `src/mesh/transport.rs` | announce_serverless, announce handlers, discovery | 2-3 |
| `src/mesh/transport_peer.rs` | Caller context, serverless proxy | 1-2 |
| `src/http/server.rs` | DHT key fix | 1 |
| `src/config/serverless.rs` | public_function, health config | 1, 4 |
| `src/mesh/wasm_dist.rs` | Initialization, signature verification | 3 |
| `src/mesh/protocol.rs` | Add node_id to ServerlessFunctionAnnounce | 2 |

---

## Testing Plan

### Test #1: DHT Key Discovery

```rust
#[tokio::test]
async fn test_function_discovery_via_dht() {
    // Setup: Origin with serverless function
    let origin = create_test_node(NodeRole::Origin);
    origin.serverless_manager.initialize(config.clone()).unwrap();

    // Setup: Edge with no local function
    let edge = create_test_node(NodeRole::Edge);

    // Act: Edge queries DHT for function
    let providers = edge.transport.discover_serverless_functions().await;

    // Assert: Found origin node
    assert!(providers.iter().any(|p| p.function_name == "test_function"));
    assert!(providers.iter().any(|p| p.node_id == origin.node_id));
}
```

### Test #2: Permission Enforcement

```rust
#[tokio::test]
async fn test_unauthorized_access_blocked() {
    // Setup: Origin with protected function
    let origin = create_test_node(NodeRole::Origin);
    origin.serverless_manager.initialize(protected_config());

    // Setup: Untrusted edge node
    let edge = create_test_node(NodeRole::Edge);

    // Act: Edge attempts to invoke
    let result = edge.transport.proxy_serverless_request("test_function", request()).await;

    // Assert: Blocked
    assert!(matches!(result, Err(ServerlessError::PermissionDenied(_))));
}
```

### Test #3: WASM Distribution

```rust
#[tokio::test]
async fn test_wasm_distribution_flow() {
    // Setup: Global node
    let global = create_test_node(NodeRole::Global);

    // Setup: Origin publishes function
    let origin = create_test_node(NodeRole::Origin);
    origin.serverless_manager.publish_wasm_to_mesh("test_function").unwrap();

    // Setup: Edge with no local WASM
    let edge = create_test_node(NodeRole::Edge);

    // Act: Edge fetches WASM
    edge.serverless_manager.fetch_wasm_for_function("test_function").await;

    // Assert: WASM available locally
    let wasm_data = global.wasm_dist.get_module_data("test_function", Serverless).unwrap();
    assert!(!wasm_data.is_empty());
}
```

---

## Risk Assessment

| Change | Risk | Mitigation |
|--------|------|-----------|
| DHT key fix | Low - bug fix | Add integration test |
| Node ID in records | Low - adds routing info | Backwards compatible |
| Security wiring | Low - secure by default | Allowlist for public functions |
| WASM distribution | Medium - bandwidth | Global node caching, version diffs |
| Event system | Low - additive | Fallback to local-only |

---

## Success Criteria

- [ ] Edge nodes can discover and route to origin serverless functions via DHT
- [ ] Serverless functions are protected by caller permission checks by default
- [ ] WASM modules are distributed via global nodes
- [ ] Health status is broadcast and queryable
- [ ] Event system works across mesh nodes
- [ ] All integration tests pass
- [ ] Documentation complete

---

## Open Questions

1. **WASM Versioning**: Should we support multiple WASM versions simultaneously, or always use latest?

2. **Cold Storage**: Should older WASM versions be stored for rollback, or discarded?

3. **Event Delivery Guarantees**: Should events be at-least-once or at-most-once?

4. **Health Threshold**: What error rate triggers "unhealthy" status?

5. **Instance Pool Limits**: Should pool limits be configurable per-function or global?

---

## Appendix: Reference

### DHT Key Patterns

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `serverless_function:{name}` | Function metadata + node_id | 3600s |
| `serverless_health:{node_id}` | Runtime health status | 60s |
| `wasm_module:{name}:{version}` | WASM binary reference | 86400s |

### Mesh Message Types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `ServerlessFunctionAnnounce` | Origin → Mesh | Register function |
| `ServerlessInvoke` | Edge → Origin | Invoke function |
| `ServerlessEvent` | Any → Any | Publish event |
| `WasmModuleAnnounce` | Origin/Global → Mesh | New WASM available |
| `WasmModuleSyncRequest` | Edge → Global | Fetch WASM |
| `WasmModuleSyncResponse` | Global → Edge | WASM binary |

### Configuration Options

```toml
[serverless]
enabled = true
default_memory_mb = 64
default_cpu_fuel = 1000000
default_timeout_seconds = 30

[serverless.functions]
name = "my_function"
path = "/api/my-function"
handler = "handle_request"
memory_mb = 128
timeout_seconds = 30
public_function = false  # Default: secure by default
pre_warm_instances = 2
min_instances = 1
max_instances = 10
idle_timeout_seconds = 300
routes = ["GET /api/my-function", "POST /api/my-function"]
allowed_callers = []  # Empty = any trusted caller
allowed_orgs = []  # Empty = any org
require_trusted_caller = true
min_tier_level = 1
event_subscriptions = ["user.created", "order.completed"]
```