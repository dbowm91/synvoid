# Plan 26: Serverless Mesh Architecture Implementation

## Context

MaluWAF currently has a serverless/WASM function architecture that supports local invocation, but the mesh integration for distributed serverless deployment is incomplete. This plan addresses the gaps needed to make serverless functions fully operable in mesh mode (as origins) and standalone.

**Design decisions** (confirmed with user):
- Site-namespacing uses internal UUID (not domain name) to avoid leaking internal naming
- Edges cache WASM bytes locally after first fetch for faster subsequent invocations
- Global nodes re-announce functions (not all origins) — establishes the trust vector

---

## Phase 1: Critical Bug Fixes (Blocking Mesh Operation)

### 1.1: Fix Unreachable `handle_serverless_proxy_stream()` — CRITICAL BUG

**Problem**: The entire serverless mesh proxy path in `transport_peer.rs:2539-2581` is unreachable. When an edge proxies a serverless request via QUIC, the origin node constructs `upstream_id = "http://serverless:func"` (from the Host header), then calls `get_upstream_info()` which returns `None` → returns 502 early. The `starts_with("serverless:")` check at line 2577 is never reached.

**Root cause chain**:
1. `handle_http_proxy_stream()` extracts host from HTTP data → `http://{host}`
2. For serverless requests, host = `serverless:func` → `upstream_id = "http://serverless:func"`
3. `topology.get_upstream_info("http://serverless:func")` returns `None` (not in `local_upstreams`)
4. Returns 502 Bad Gateway immediately
5. The `serverless:` prefix check is after this early return

**Fix**: Reorder checks so `serverless:` prefix is checked BEFORE the `get_upstream_info()` lookup.

**File**: `src/mesh/transport_peer.rs`
**Lines**: ~2539-2581

```rust
// CURRENT (broken):
let upstream_info = topology.get_upstream_info(&upstream_id).await;
let backend_url = match upstream_info {
    Some(info) => info.upstream_url,
    None => {
        // BUG: Returns 502 for serverless before reaching serverless check
        return Ok(());
    }
};
if upstream_id.starts_with("serverless:") { ... }  // UNREACHABLE

// FIXED:
if upstream_id.starts_with("serverless:") {
    return self.handle_serverless_proxy_stream(&upstream_id, &http_data, send_stream).await;
}
let upstream_info = topology.get_upstream_info(&upstream_id).await;
// ... rest of the logic
```

---

### 1.2: Wire Missing Topology Registration

**Problem**: Serverless functions are announced to DHT but never registered in mesh topology's `local_upstreams` HashMap. Unlike regular upstreams (which call `add_local_upstream()` then `announce_upstream()`), serverless functions only update hierarchical routing and DHT.

**Current state in `ServerlessManager::initialize()` (lines 371-383)**:
```rust
let routing_manager = self.routing_manager.read().clone();
if let Some(routing) = routing_manager {
    let upstream_id = format!("serverless:{}", func_def.name);
    // register_local_upstream() is LOCAL ONLY - doesn't integrate with mesh topology
    routing_clone.register_local_upstream(&upstream_id).await;
}
// MISSING: No call to transport.announce_upstream()
```

**Fix**: Call `transport.announce_upstream()` after DHT registration:

```rust
// In ServerlessManager::initialize(), after DHT registration:
// Call mesh topology announcement
if let Some(transport) = self.transport.read().as_ref() {
    let upstream_id = format!("serverless:{}", func_def.name);
    transport.announce_upstream(
        &upstream_id,
        crate::mesh::protocol::AnnounceAction::Add
    ).await?;
}
```

**Note**: For serverless upstreams, `upstream_url` should be set equal to `upstream_id` (i.e., `serverless:{name}`) since there's no separate local backend URL — the serverless runtime IS the backend. The `announce_upstream()` implementation currently looks up `local_upstreams` config for the `upstream_url`; a separate code path is needed for serverless where the URL is derived from the upstream_id itself.

**File**: `src/serverless/manager.rs:initialize()`
**Lines**: ~370-390

**Side note for Phase 2.1**: Once site-namespaced naming is implemented (item 2.1), the `upstream_id` format becomes `serverless:{site_id}:{function_name}`, which provides natural isolation between sites' functions.

---

### 1.3: Implement Dynamic Checksum & Version Tracking

**Problem**: `ServerlessFunctionAnnounce` has hardcoded `version: 1` and empty `checksum` in DHT. No mechanism exists to track function versions across updates.

**Current state** (`manager.rs:355-364`):
```rust
let value = serde_json::json!({
    "function_name": func_def.name,
    "version": 1,           // HARDCODED!
    "checksum": "",          // ALWAYS EMPTY!
    "routes": func_def.routes,
    // ...
});
```

**Solution**: Compute SHA-256 from loaded WASM bytes and track version per function.

**Changes**:

1. **Add version tracking to `ServerlessManager`**:
```rust
struct ServerlessManager {
    // ... existing fields
    versions: RwLock<HashMap<String, u64>>,  // function_name -> version
}
```

2. **Add checksum computation in `load_function_wasm()`**:
```rust
use sha2::{Digest, Sha256};

fn load_function_wasm(&self, func_def: &FunctionDefinition) -> Result<(Arc<WasmRuntime>, Vec<u8>, String), ServerlessError> {
    // ... existing loading logic ...

    // Return bytes + checksum
    let checksum = {
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        hex::encode(hasher.finalize())
    };
    Ok((runtime, wasm_bytes, checksum))
}
```

3. **Update DHT announcement with real values**:
```rust
let wasm_bytes = ...;  // from load_function_wasm
let checksum = compute_wasm_checksum(&wasm_bytes);
let version = *self.versions.read().unwrap().get(&func_def.name).unwrap_or(&1);

let value = serde_json::json!({
    "function_name": func_def.name,
    "version": version,
    "checksum": checksum,
    // ...
});
```

**File**: `src/serverless/manager.rs`

---

## Phase 2: High Priority — Mesh Discovery & Routing

### 2.1: Site-Namespaced Function Naming

**Problem**: Two sites can define functions with the same name (e.g., `my-func`). They share the same `serverless_function:my-func` DHT key and `serverless:my-func` upstream ID, causing collisions.

**Solution**: Use site UUID in function namespacing: `site:{uuid}:{function_name}`

**Changes required**:

1. **`DhtKey::ServerlessFunction`** — add `site_id` field:
```rust
// src/mesh/dht/keys.rs
pub enum DhtKey {
    ServerlessFunction {
        site_id: String,       // NEW: internal UUID
        function_name: String,
    },
}
```

2. **Update DHT key format**:
```rust
// keys.rs:422-424
DhtKey::ServerlessFunction { site_id, function_name } => {
    format!("serverless_function:{}:{}", site_id, function_name)
}
```

3. **Update `from_str` parsing** — parse 4-part keys:
```rust
// keys.rs:542
"serverless_function" if parts.len() >= 4 => DhtKey::ServerlessFunction {
    site_id: parts[1..parts.len()-1].join(":"),  // handles embedded colons
    function_name: parts.last().unwrap().to_string(),
}
```

4. **`ServerlessManager::initialize()`** — accept and use site context:
```rust
pub fn initialize_for_site(&self, site_id: &str, config: ServerlessConfig) -> Result<(), ServerlessError> {
    // Register functions with site_id prefix
    let upstream_id = format!("serverless:{}:{}", site_id, func_def.name);
    // DHT key: serverless_function:{site_id}:{function_name}
}
```

5. **`RouteTarget.serverless_function`** — carry site context:
```rust
// src/router.rs
pub struct RouteTarget {
    // ...
    pub serverless_function: Option<ServerlessFunctionRef>,  // changed from Arc<str>
}

pub struct ServerlessFunctionRef {
    pub site_id: Arc<str>,
    pub function_name: Arc<str>,
}
```

6. **Pool map keys** — use site_id:function_name for isolation:
```rust
// manager.rs pools HashMap key
let pool_key = format!("{}:{}", site_id, function_name);
```

**File**: `src/mesh/dht/keys.rs`, `src/serverless/manager.rs`, `src/router.rs`

---

### 2.2: WASM Byte Transfer for Edge Caching

**Problem**: Edges cannot cache serverless function bytes — `WasmModuleAnnounce/SyncRequest/SyncResponse` message types exist but have no handlers implemented. Edges always proxy invocations to origins, adding latency.

**Solution**: Implement two mechanisms:

#### 2.2.1: On-Demand Fetch via QUIC Stream (simpler)

When an edge discovers a serverless function not in local cache:

1. Edge sends HTTP request to origin via QUIC: `GET /__serverless__/{site_id}/{function_name}`
2. Origin responds with raw WASM bytes + metadata headers
3. Edge caches in `WasmDistManager`

**Implementation in `transport_peer.rs`**:
```rust
// In handle_http_proxy_stream(), add:
if path.starts_with("/__serverless__/") {
    return self.handle_serverless_wasm_fetch(path, send_stream).await;
}
```

**Implementation in `serverless/manager.rs`**:
```rust
pub async fn serve_wasm_module(&self, site_id: &str, function_name: &str)
    -> Result<(Vec<u8>, String, u64), ServerlessError> {
    // Return WASM bytes, checksum, version
}
```

#### 2.2.2: Formal WasmModuleSyncRequest/SyncResponse (full protocol)

Implement handlers for existing (but unused) `WasmModuleSyncRequest` message type:

**In `transport_peer.rs`**:
```rust
// Route in handle_peer_message()
MeshMessage::WasmModuleSyncRequest(req) => {
    self.handle_wasm_module_sync_request(req).await
}
```

**Handler logic**:
```rust
async fn handle_wasm_module_sync_request(
    &self,
    req: WasmModuleSyncRequest,
) -> Result<WasmModuleSyncResponse, MeshTransportError> {
    let mut modules = Vec::new();
    for module_name in &req.module_names {
        if let Some((data, info)) = wasm_dist_manager.get_module_info(module_name) {
            modules.push(info);  // contains data: Vec<u8>
        }
    }
    Ok(WasmModuleSyncResponse {
        request_id: req.request_id,
        node_id: self.node_id.clone(),
        modules,
        timestamp: current_timestamp(),
    })
}
```

#### 2.2.3: Edge Caching Integration

When edge receives `ServerlessFunctionAnnounce` or discovers a function:

1. Check local `WasmDistManager` for module
2. If not cached and `auto_fetch_wasm = true` (config), fetch from origin
3. Store in `WasmDistManager` with TTL
4. On subsequent invocations, use local WASM runtime

**Config additions** in `ServerlessConfig`:
```rust
pub struct ServerlessConfig {
    // ... existing fields ...
    pub auto_fetch_wasm: bool,           // default: true
    pub wasm_cache_ttl_secs: u64,        // default: 3600
}
```

**Files**:
- `src/mesh/transport_peer.rs` — new handlers
- `src/serverless/manager.rs` — `serve_wasm_module()`
- `src/mesh/wasm_dist.rs` — caching integration
- `src/config/serverless.rs` — new config fields

---

### 2.3: Function Re-Announcement Mechanism

**Problem**: Serverless functions are announced once at initialization with 1-hour TTL. Entries expire from DHT if not refreshed, causing peers to lose discovery.

**Solution**: Follow YARA/ThreatIntel pattern — **global nodes** re-announce functions periodically to establish the trust vector. Origins announce once to global nodes; global nodes verify, store, and periodically re-announce to the wider mesh.

**Design decision** (confirmed with user): Global nodes re-announce (not all origins) — this establishes the trust vector.

**Changes**:

1. **Add `re_announce_interval_secs` to `ServerlessConfig`**:
```rust
// src/config/serverless.rs
pub struct ServerlessConfig {
    // ... existing fields ...
    pub re_announce_interval_secs: u64,  // default: 300 (5 min)
}
```

2. **Origins announce to global nodes on function update** (already partially implemented via `announce_upstream()`):

3. **Global nodes implement re-announcement task** (similar to `yara_rules.rs:2051-2065`):
```rust
// In MeshTransport or GlobalNodeLogic, add background task:
async fn start_serverless_re_announcer(manager: Arc<ServerlessManager>, interval_secs: u64) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;
        // Re-announce all serverless functions this global node has verified
        for (site_id, name) in manager.get_verified_functions() {
            manager.re_announce_function(site_id, name).await;
        }
    }
}
```

4. **Re-announcement flow**:
   - Origin announces `ServerlessFunctionAnnounce` to global nodes (via QUIC)
   - Global node verifies signature (Phase 3.2), stores in DHT
   - Global node's background task re-announces via `store_and_announce()` every `re_announce_interval_secs`
   - Edge nodes discover via `discover_serverless_functions()` or mesh sync

**Files**: `src/config/serverless.rs`, `src/serverless/manager.rs`, `src/mesh/transport.rs`

---

## Phase 3: High Priority — Security & Access Control

### 3.1: Wire `verify_caller_permission()` — CRITICAL SECURITY GAP

**Problem**: `verify_caller_permission()` exists at `manager.rs:190-282` with full implementation of `allowed_callers`, `allowed_orgs`, `require_trusted_caller`, and `min_tier_level` checks — but it is NEVER called from any entry point. All four access control fields are dead code.

**Current state**: `invoke_for_mesh()` at line 560 does not check caller permissions.

**Fix**: Add `CallerContext` struct and wire permission verification.

**Changes**:

1. **Add `CallerContext` struct** in `manager.rs`:
```rust
pub struct CallerContext {
    pub node_id: String,
    pub role: MeshNodeRole,
    pub org_id: Option<String>,
    pub tier: Option<u32>,
}
```

2. **Modify `invoke_for_mesh()` signature**:
```rust
// Before:
pub async fn invoke_for_mesh(
    &self,
    function_name: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
) -> Result<ServerlessResponse, ServerlessError>

// After:
pub async fn invoke_for_mesh(
    &self,
    site_id: &str,           // NEW
    function_name: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    caller: CallerContext,    // NEW
) -> Result<ServerlessResponse, ServerlessError>
```

3. **Call `verify_caller_permission()` at start**:
```rust
self.verify_caller_permission(
    function_name,
    &caller.node_id,
    caller.role,
    caller.org_id.as_deref(),
    caller.tier,
)?;  // Returns ServerlessError::CallerNotAuthorized if denied
```

4. **Wire caller context from `transport_peer.rs`**:
```rust
// In handle_serverless_proxy_stream(), around line 2953:
let caller = CallerContext {
    node_id: self.config.node_id(),
    role: self.role,
    org_id: self.org_id.clone(),
    tier: self.tier_level,
};

serverless_manager
    .invoke_for_mesh(site_id, function_name, &method, &path, &headers, body, caller)
    .await
```

**Files**: `src/serverless/manager.rs`, `src/mesh/transport_peer.rs`

---

### 3.2: Add Origin Signature to `ServerlessFunctionAnnounce`

**Problem**: `ServerlessFunctionAnnounce` lacks `origin_signature` and `origin_ed25519_pubkey` fields — no cryptographic proof of origin ownership. Global nodes cannot verify the announcement came from the actual function owner.

**Solution**: Add signature fields and implement signing/verification.

**Changes**:

1. **Update `ServerlessFunctionAnnounce` struct** in `protocol.rs`:
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerlessFunctionAnnounce {
    // ... existing fields ...
    pub origin_signature: Vec<u8>,           // NEW
    pub origin_ed25519_pubkey: ArcStr,       // NEW
}
```

2. **Update `mesh.proto` and regenerate code**:
```protobuf
message ServerlessFunctionAnnounce {
    // ... existing fields 1-8 ...
    string origin_ed25519_pubkey = 9;   // NEW
    bytes origin_signature = 10;         // NEW
}
```

3. **Sign announcements in `serverless/manager.rs`**:
```rust
// In initialize() when creating announcement:
let sign_content = format!("{}:{}:{}", func_def.name, version, self.node_id);
let (signature, pubkey) = self.origin_signer
    .as_ref()
    .map(|s| (
        s.sign(sign_content.as_bytes()).into_bytes(),
        ArcStr::from(hex::encode(s.verifying_key().to_bytes())),
    ))
    .unwrap_or((Vec::new(), ArcStr::from("")));

let announce = ServerlessFunctionAnnounce {
    // ... existing fields ...
    origin_signature: signature,
    origin_ed25519_pubkey: pubkey,
};
```

4. **Verify signature in `handle_serverless_function_announce()`** (`transport_peer.rs:2422`):
```rust
// Similar to UpstreamAnnounce verification at line 1108-1146
let sign_data = format!("{}:{}:{}", announce.function_name, announce.version, peer_id);
let signature_valid = verify_ed25519_signature(
    &announce.origin_signature,
    &announce.origin_ed25519_pubkey,
    sign_data.as_bytes(),
)?;

if !signature_valid {
    tracing::warn!("ServerlessFunctionAnnounce from {} rejected: invalid signature", peer_id);
    return Ok(());
}
```

**Files**: `src/mesh/protocol.rs`, `mesh.proto`, `src/mesh/transport_peer.rs`, `src/serverless/manager.rs`

---

## Phase 4: Medium Priority — Config & Policy

### 4.1: Add `announce_to_mesh` Config Flag

**Problem**: All functions are announced to mesh regardless of intent — no way to disable mesh announcement for private/internal functions.

**Solution**: Add `announce_to_mesh: Option<bool>` to `FunctionDefinition`.

```rust
// src/config/serverless.rs
pub struct FunctionDefinition {
    // ... existing fields ...
    #[serde(default = "default_announce_to_mesh")]
    pub announce_to_mesh: Option<bool>,  // default: true
}

fn default_announce_to_mesh() -> bool { true }
```

**Usage in `initialize()`**:
```rust
if func_def.announce_to_mesh.unwrap_or(true) {
    // ... do DHT and mesh announcement ...
}
// Otherwise: load locally only, don't announce
```

**Files**: `src/config/serverless.rs`, `src/serverless/manager.rs`

---

### 4.2: Add `public_function` Config Flag

**Problem**: Some functions may be truly public (no auth needed) but `verify_caller_permission()` requires all fields to be None/empty to allow anyone.

**Solution**: Add `public_function: bool` to bypass permission checks.

```rust
pub struct FunctionDefinition {
    // ... existing fields ...
    pub public_function: bool,  // default: false — if true, bypasses caller auth
}
```

**Usage in `verify_caller_permission()`**:
```rust
if function.definition.public_function {
    return Ok(());  // Skip all permission checks
}
```

**Files**: `src/config/serverless.rs`, `src/serverless/manager.rs`

---

## Phase 5: Low Priority — Standalone & Integration

### 5.1: Per-Location Serverless Standalone Support

**Problem**: Per-location serverless config (`LocationConfig.serverless`) works via router but configuration discovery and site-context passing to serverless manager needs verification.

**Investigation findings**: The global `ServerlessManager` (initialized in `UnifiedServerWorker`) handles all sites. Per-location serverless config is matched in `router.rs` but the `serverless_function` Arc only carries the bare function name, not site context.

**Required changes**:
1. `RouteTarget.serverless_function` should carry `(site_id, function_name)` tuple
2. `handle_serverless_function()` in `http/server.rs:1854` should pass site context
3. Ensure `invoke_for_mesh()` is called with proper site_id when routing to mesh origin

**Files**: `src/router.rs`, `src/http/server.rs`, `src/serverless/manager.rs`

---

### 5.2: Wire `ServerlessManager` to Per-Site Initialization

**Problem**: Currently `ServerlessManager` is initialized once from `config.main.serverless` (global) in `UnifiedServerWorker`. Per-site serverless configs (`site.serverless`) are only matched at runtime via router — they don't register separate function pools.

**Solution**: Modify initialization to support both global and per-site configs:

```rust
// In UnifiedServerWorker:
// 1. Initialize global serverless manager for global functions
// 2. For each site with serverless config, call manager.initialize_for_site(site_id, config)
```

This allows site-namespaced functions to share a manager but have isolated pools and DHT keys.

**Files**: `src/worker/unified_server.rs`, `src/serverless/manager.rs`

---

## Phase 6: Low Priority — Documentation

### 6.1: Create Example TOML Configs

**Files to create**:
- `docs/examples/serverless-standalone.toml` — single-node deployment
- `docs/examples/serverless-mesh-origin.toml` — mesh origin with functions
- `docs/examples/serverless-mesh-edge.toml` — edge proxying to origin serverless

**Example: standalone**:
```toml
[serverless]
enabled = true
default_memory_mb = 64
default_timeout_seconds = 30

[[serverless.functions]]
name = "auth-validator"
path = "/functions/auth"
handler = "handle_request"
routes = ["GET /validate", "POST /auth"]
env = { NODE_ENV = "production" }
```

**Example: mesh-origin**:
```toml
[serverless]
enabled = true
announce_to_mesh = true
re_announce_interval_secs = 300

[[serverless.functions]]
name = "auth-validator"
path = "/functions/auth"
allowed_callers = ["edge-node-1", "edge-node-2"]
require_trusted_caller = false
```

**Example: mesh-edge**:
```toml
[serverless]
enabled = true  # For local caching of WASM
auto_fetch_wasm = true
wasm_cache_ttl_secs = 3600
```

---

## Implementation Order Summary

| Order | Item | Phase | Priority |
|-------|------|-------|----------|
| 1 | Fix unreachable serverless proxy path | 1 | BLOCKING |
| 2 | Wire topology registration | 1 | BLOCKING |
| 3 | Dynamic checksum + version | 1 | BLOCKING |
| 4 | Site-namespaced naming | 2 | HIGH |
| 5 | Wire caller permissions | 3 | HIGH |
| 6 | Re-announcement mechanism | 2 | HIGH |
| 7 | WASM byte transfer | 2 | HIGH |
| 8 | Origin signature | 3 | MEDIUM |
| 9 | announce_to_mesh flag | 4 | MEDIUM |
| 10 | Per-location standalone | 5 | LOW |
| 11 | Per-site initialization | 5 | LOW |
| 12 | Example configs | 6 | LOW |

---

## File Change Summary

| File | Changes |
|------|---------|
| `src/mesh/transport_peer.rs` | Fix ordering bug (line ~2539); wire caller context to invoke_for_mesh; add signature verification in handle_serverless_function_announce |
| `src/serverless/manager.rs` | Wire announce_upstream; checksum computation; version tracking; CallerContext struct; serve_wasm_module(); announce_to_mesh check |
| `src/mesh/dht/keys.rs` | Add site_id to ServerlessFunction DHT key variant; update from_str parsing |
| `src/mesh/protocol.rs` | Add origin_signature, origin_ed25519_pubkey fields to ServerlessFunctionAnnounce |
| `src/config/serverless.rs` | Add announce_to_mesh, public_function, auto_fetch_wasm, wasm_cache_ttl_secs, re_announce_interval_secs fields |
| `src/router.rs` | Update RouteTarget with site-namespaced ServerlessFunctionRef; pass site_id in serverless_function |
| `src/http/server.rs` | Pass site context to handle_serverless_function() and invoke_for_mesh() |
| `src/worker/unified_server.rs` | Support per-site serverless init via initialize_for_site() |
| `src/mesh/wasm_dist.rs` | Add serve_module handler; integrate with edge serverless fetch |
| `mesh.proto` | Add origin_ed25519_pubkey (field 9), origin_signature (field 10) to ServerlessFunctionAnnounce |

---

## Testing Requirements

### Unit Tests
- `test_serverless_checksum_computation` — verify SHA-256 matches expected
- `test_version_increment` — verify version increases on update
- `test_site_namespace_collision` — two sites same function name don't collide
- `test_caller_permission_allowed` — verify allowed_callers works
- `test_caller_permission_denied` — verify unauthorized caller rejected
- `test_origin_signature_verify` — valid/invalid signature detection

### Integration Tests
- `test_serverless_mesh_proxy` — edge → origin serverless invocation via mesh
- `test_serverless_wasm_fetch` — edge fetches and caches WASM bytes
- `test_serverless_re_announce` — function survives DHT TTL expiry
- `test_serverless_site_isolation` — two sites with same function name remain isolated
