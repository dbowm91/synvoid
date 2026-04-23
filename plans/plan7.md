# WASM Plugin Architecture Improvement Plan

**Last updated**: 2026-04-23
**Status**: 📋 PENDING IMPLEMENTATION
**Parent Review**: WASM Plugin Architecture Deep Dive Review

## Overview

This document details improvements to the WASM filtering and serverless function architecture, including standalone execution and mesh-mode distributed function execution. The goal is to address critical security gaps, improve resource enforcement, and enhance performance to support 500K+ requests/second.

**Total improvement categories**: 9
**Priority**: Critical → Low

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          HTTP/TLS Server (Axum)                       │
│                    src/http/server.rs | src/tls/server.rs             │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────────┐ ┌────────────────────┐
│  WASM Filter  │ │ Serverless Manager │ │    Remote Mesh     │
│ src/plugin/   │ │ src/serverless/    │ │  (Mesh Transport)   │
│               │ │                   │ │                    │
│ filter_request│ │ handle_request    │ │ proxy_serverless   │
│ transform_    │ │ instance_pool      │ │ _request()         │
│ response      │ │ routing           │ │                    │
└───────┬───────┘ └─────────┬───────────┘ └─────────┬──────────┘
        │                   │                       │
        ▼                   ▼                       ▼
┌───────────────┐ ┌───────────────────┐ ┌────────────────────┐
│ WasmRuntime   │ │  ServerlessPool   │ │   WasmDistManager  │
│ (wasmtime)    │ │  (autoscaling)    │ │ (mesh distribution) │
│               │ │                   │ │                    │
│ - limits      │ │ - min/max         │ │ - plugins          │
│ - host fns    │ │ - pre-warm        │ │ - serverless       │
│ - pool        │ │ - idle timeout    │ │ - versioning       │
│ (WasmInstPool)│ │                   │ │                    │
└───────────────┘ └───────────────────┘ └────────────────────┘
```

---

## Critical Issues Summary

| # | Issue | Severity | Location | Status |
|---|-------|----------|----------|--------|
| 1 | `verify_caller_permission()` never called - dead code | 🔴 Critical | `manager.rs:190` | UNWIRED |
| 2 | DHT reads unbounded from WASM plugins | 🔴 Critical | `wasm_runtime.rs:587` | NO AC |
| 3 | Resource limits bypass via direct `memory.grow` | 🔴 Critical | `wasm_runtime.rs:820` | NO RL |
| 4 | Regex compiled on every match call | 🟡 High | `routing.rs:22` | NO CACHE |
| 5 | No retries for remote execution | 🟡 High | `transport.rs` | NO RETRY |
| 6 | Host function rate limiting missing | 🟡 High | `wasm_runtime.rs` | NO RL |

---

## Items Requiring Improvement

### Category 1: Wire Security Checks (Caller Permission Verification)

**Severity**: 🔴 CRITICAL
**Impact**: All permission checks (trusted_caller, allowed_callers, allowed_orgs, min_tier_level) are completely bypassed
**Location**: `src/serverless/manager.rs:190-282`

**Problem**: The `verify_caller_permission()` function is defined but **never called** from any entry point.

**Current callers** (none exist):
```bash
$ rg "verify_caller_permission\(" src/
src/serverless/manager.rs:190   # Function definition only - NEVER CALLED
```

**Impact**: Any node can invoke any serverless function without authorization.

**Callers that need to invoke it**:
1. `handle_serverless_function()` at line 695
2. `invoke_for_mesh()` at line 560
3. HTTP server entry at `http/server.rs:1854`
4. TLS server entry at `tls/server.rs:1077`

**Recommended Fix**:

1. Add caller context struct:
```rust
// src/serverless/manager.rs
pub struct CallerContext {
    pub node_id: String,
    pub role: MeshNodeRole,
    pub org_id: Option<String>,
    pub tier: Option<u32>,
}

impl ServerlessManager {
    pub async fn handle_serverless_function_with_auth(
        manager: &ServerlessManager,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        caller: CallerContext,
    ) -> Result<Response<Bytes>, ServerlessError> {
        // Extract function name from path
        let function_name = /* ... */;

        // THIS IS THE MISSING CALL:
        manager.verify_caller_permission(
            &function_name,
            &caller.node_id,
            caller.role,
            caller.org_id.as_deref(),
            caller.tier,
        )?;

        // Then proceed with execution...
        handle_serverless_function(manager, method, path, headers, body).await
    }
}
```

2. Update HTTP/TLS handlers to extract caller context from mesh connection:
```rust
// In http/server.rs or tls/server.rs
let caller = CallerContext {
    node_id: peer_info.node_id.clone(),
    role: peer_info.role,
    org_id: peer_info.org_id.clone(),
    tier: peer_info.tier,
};
```

3. Fix the TierClaim creation (lines 265-271) to use actual caller identity:
```rust
// WRONG - creates fake identity:
let claim = TierClaim::new(
    min_tier,
    format!("tier_{}", min_tier),       // Fake key_id
    caller_org_id.unwrap_or("default").to_string(),
    "mesh".to_string(),               // Hardcoded fake mesh_id
    uuid::Uuid::new_v4().to_string(), // Random nonce
);

// CORRECT - use verified caller claims:
let claim = caller.verified_tier_claim.clone()
    .ok_or_else(|| ServerlessError::PermissionDenied("No tier claim provided"))?;
```

**Implementation complexity**: Medium
**Risk**: Medium - requires understanding of mesh identity propagation
**Estimated time**: 2-3 days

---

### Category 2: DHT Access Control for WASM Plugins

**Severity**: 🔴 CRITICAL
**Impact**: WASM plugins can read ANY DHT key including sensitive records
**Location**: `src/plugin/wasm_runtime.rs:563-621`

**Problem**: `mesh_query_dht()` directly reads from DHT without capability verification:

```rust
// Line 587-611 - NO access control
if let Some(rs) = crate::mesh::get_global_record_store() {
    if let Some(record) = rs.get_record(&key) {  // Direct access - no capability check
        let value = &record.value;
        // ... copies data to WASM memory
    }
}
```

**Accessible sensitive keys**:
- `global_node_public_key:*` - Signing keys
- `node_info:*` - Node metadata
- `capability_attestation:*` - Authorization tokens
- `member_certificate:*` - Identity certificates

**Also problematic: `mesh_emit_event()`** (lines 663-711):
- Writes arbitrary DHT records with host node's identity
- No capability verification on writes
- Fixed TTL of 300s limits abuse slightly

**Recommended Fix**:

1. Define allowed keys per plugin:
```rust
// src/plugin/mod.rs
pub struct WasmPluginConfig {
    pub name: String,
    pub allowed_dht_keys: Vec<DhtKeyPattern>,
    pub allowed_threat_types: Vec<ThreatType>,
    pub max_events_per_request: usize,
}

impl WasmPluginManager {
    fn check_dht_access(&self, plugin_name: &str, key: &str) -> bool {
        // Load plugin's allowed keys config
        let allowed = self.plugin_config.get(plugin_name);
        match allowed {
            Some(config) => config.allowed_dht_keys.iter().any(|p| p.matches(key)),
            None => false,  // Default deny
        }
    }
}
```

2. Add capability verification:
```rust
// In mesh_query_dht linker function
linker.func_wrap("env", "mesh_query_dht", |mut caller: ...| -> i32 {
    // ... read key from memory ...

    // ADD THIS CHECK:
    if !caller.data().plugin_config.check_dht_access(&key) {
        tracing::warn!(
            "Plugin {} denied DHT access to key '{}'",
            caller.data().plugin_name,
            key
        );
        return -2;  // Access denied
    }

    // ... proceed with read ...
});
```

3. Rate limit host function calls:
```rust
// src/plugin/mod.rs
static WASM_HOST_RATE_LIMITER: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(100, Duration::from_secs(1))  // 100 calls/sec per plugin
});

fn check_host_rate_limit(plugin_name: &str) -> Result<(), WasmPluginError> {
    if WASM_HOST_RATE_LIMITER.check(plugin_name).is_err() {
        return Err(WasmPluginError::RateLimited);
    }
    Ok(())
}
```

**Implementation complexity**: Medium
**Risk**: Medium - may break existing plugins that rely on DHT access
**Estimated time**: 2 days

---

### Category 3: Resource Limiter Implementation

**Severity**: 🔴 CRITICAL
**Impact**: WASM modules can bypass memory limits via direct `memory.grow`
**Location**: `src/plugin/wasm_runtime.rs:820-838`

**Problem**: Memory limits enforced manually in `write_to_guest_memory()` only:

```rust
// Line 820-838 - Only path that checks memory
fn write_to_guest_memory(...) -> Result<(i32, i32), WasmPluginError> {
    // ...
    if end > mem_size {
        let pages_needed = (end - mem_size).div_ceil(65536);
        let max_pages = (self.limits.max_memory_mb * 1024 * 1024) / 65536;
        let current_pages = mem_size / 65536;
        if current_pages + pages_needed > max_pages {
            return Err(WasmPluginError::SandboxError(...));
        }
        memory.grow(&mut *store, pages_needed as u64).map_err(...)?;
    }
}
```

**What's missing**:
1. `ResourceLimiter` trait not implemented
2. WASM can call `memory.grow` directly
3. No epoch-based interruption for CPU timeout
4. Fuel exhaustion causes trap, not clean termination

**Recommended Fix**:

1. Implement wasmtime `ResourceLimiter`:
```rust
// src/plugin/wasm_runtime.rs
use wasmtime::{ResourceLimiter, ResourceLimiterAsync};

struct WasmResourceLimiter {
    max_memory_pages: u64,
    max_instances: usize,
    current_instances: AtomicUsize,
}

impl ResourceLimiter for WasmResourceLimiter {
    fn memory_growing(
        &mut self,
        current: u64,
        desired: u64,
        max: u64,
    ) -> bool {
        let max_pages = self.max_memory_pages;
        let current_pages = current / 65536;
        let needed = (desired - current) / 65536;

        // Check if growth would exceed limit
        current_pages + needed <= max_pages
    }

    fn instances_growing(&mut self) -> bool {
        let current = self.current_instances.load(Ordering::Relaxed);
        current < self.max_instances
    }

    fn instance_count(&mut self) -> usize {
        self.current_instances.load(Ordering::Relaxed)
    }
}
```

2. Enable epoch-based interruption:
```rust
// In WasmRuntime::load_from_bytes
let mut config = Config::new();
// ...
config.epoch_interruption(true);

let engine = Engine::new(&config)?;
engine.set_epoch_deadline(1, self.limits.timeout_seconds);
```

3. Add background task for epoch increment:
```rust
// In WasmRuntime or ServerlessManager
pub async fn run_epoch_incrementor(engine: Arc<Engine>, timeout_secs: u64) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        engine.increment_epoch();
    }
}
```

4. Track fuel consumption per instance:
```rust
fn track_fuel_consumption(store: &Store<RequestContext>, plugin_name: &str) {
    if let Ok(remaining) = store.get_fuel() {
        let consumed = INITIAL_FUEL.saturating_sub(remaining);
        record_wasm_fuel_consumed(plugin_name, consumed);
    }
}
```

**Implementation complexity**: Medium
**Risk**: Low - additive improvements
**Estimated time**: 1-2 days

---

### Category 4: Route Matching Performance

**Severity**: 🟡 HIGH
**Impact**: Regex patterns compiled on every match call - massive GC pressure at 500K rps
**Location**: `src/serverless/routing.rs:22-26`

**Problem**:
```rust
// Line 22-26 - Regex compiled EVERY call
RouteMatch::Regex(pattern) => {
    if let Ok(re) = regex::Regex::new(pattern) {  // NEW Regex compiled!
        re.is_match(path)
    } else {
        false
    }
}
```

**Impact at 500K rps**: If 10% of requests hit regex routes = 50K regex compilations/sec.

**Also identified**:
1. No route caching
2. Priority inversion (later defined = lower priority)
3. Glob recursion without memoization

**Recommended Fix**:

1. Pre-compile regex on route registration:
```rust
// src/serverless/routing.rs
pub struct ServerlessRoute {
    pub matcher: RouteMatch,
    pub method: MethodMatch,
    pub priority: i32,
    pub function_name: String,
    pub compiled_regex: Option<regex::Regex>,  // ADD THIS
}

impl RouteMatch {
    pub fn compile(&self) -> CompiledRouteMatch {
        match self {
            RouteMatch::Regex(pattern) => {
                CompiledRouteMatch::Regex {
                    regex: regex::Regex::new(pattern).expect("Invalid regex"),
                }
            }
            // ... other variants
        }
    }
}
```

2. Fix priority calculation:
```rust
// Current (WRONG - later = lower):
priority: default_priority - idx as i32,

// Correct (later = higher):
priority: default_priority + idx as i32,

// Or explicit:
// Routes defined first have LOWER priority (can be overridden)
```

3. Add route caching layer:
```rust
// In ServerlessManager
struct RouteCache {
    cache: DashMap<String, (String, ServerlessRoute)>,  // path -> (function, route)
    // Or use a trie for prefix matching
}

impl RouteCache {
    fn lookup(&self, path: &str, method: &Method) -> Option<(String, ServerlessRoute)> {
        // Fast path: exact match
        if let Some(result) = self.cache.get(path) {
            return Some(result.clone());
        }

        // Fall back to full route matching
        None
    }
}
```

4. Fix glob recursion:
```rust
// Replace recursive glob_match with iterative with memoization
fn glob_match(pattern: &str, path: &str) -> bool {
    let mut seen = HashSet::<(usize, usize)>::new();
    glob_match_iter(pattern.as_bytes(), path.as_bytes(), 0, 0, &mut seen)
}
```

**Implementation complexity**: Low-Medium
**Risk**: Low - performance improvement only
**Estimated time**: 1 day

---

### Category 5: Remote Execution Improvements

**Severity**: 🟡 HIGH
**Impact**: No retries, no load balancing, single provider
**Location**: `src/http/server.rs:1854-1917`, `src/mesh/transports/manager.rs:511-541`

**Problems**:

1. **No retries**: Single attempt only
```rust
// http/server.rs:1910-1916
Err(proxy_err) => {
    tracing::warn!("Serverless mesh proxy failed for {}: {}", function_name, proxy_err);
    // Falls through to 502 - NO RETRY
}
```

2. **No load balancing**: Only first provider used
```rust
// Extracts only first node_id from DHT
let peer_node_id = record.value
    .get("node_id")
    .as_str();  // Takes first only
```

3. **No timeout enforcement**: `timeout_seconds` not applied to mesh call

**Recommended Fix**:

1. Add exponential backoff retry:
```rust
// src/serverless/manager.rs
pub async fn invoke_with_retry(
    manager: &ServerlessManager,
    function_name: &str,
    request: Request,
    max_retries: u32,
) -> Result<Response<Bytes>, ServerlessError> {
    let mut attempt = 0;
    let base_delay = Duration::from_millis(100);

    loop {
        match manager.invoke_remote(function_name, request.clone()).await {
            Ok(response) => return Ok(response),
            Err(e) if attempt < max_retries => {
                attempt += 1;
                let delay = base_delay * 2_u32.pow(attempt - 1);
                tracing::warn!(
                    "Remote invocation attempt {} failed, retrying in {:?}",
                    attempt, delay
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}
```

2. Add multi-provider load balancing:
```rust
// Query all providers, select by weighted random
async fn select_provider(
    record_store: &RecordStoreManager,
    function_name: &str,
) -> Result<ProviderInfo, ServerlessError> {
    let key = format!("serverless:{}", function_name);
    let all_providers = record_store.get_records_with_prefix(&key);

    if all_providers.is_empty() {
        return Err(ServerlessError::NoProviderFound);
    }

    // Weight by health score and latency (if available)
    let weighted: Vec<_> = all_providers
        .iter()
        .map(|p| {
            let health = p.health_score.unwrap_or(1.0);
            let weight = (health * 1000.0) as u32;
            (p, weight)
        })
        .collect();

    // Weighted random selection
    weighted_selection(&weighted)
}
```

3. Apply timeout to mesh invocation:
```rust
pub async fn invoke_remote_with_timeout(
    manager: &ServerlessManager,
    function_name: &str,
    request: Request,
    timeout: Duration,
) -> Result<Response<Bytes>, ServerlessError> {
    tokio::time::timeout(
        timeout,
        manager.invoke_remote(function_name, request),
    )
    .await
    .map_err(|_| ServerlessError::Timeout)?
}
```

**Implementation complexity**: Medium
**Risk**: Medium - changes retry behavior
**Estimated time**: 2 days

---

### Category 6: Instance Pool Performance

**Severity**: 🟡 MEDIUM
**Impact**: O(n) eviction, 10s autoscaler interval too slow for burst traffic
**Location**: `src/serverless/instance_pool.rs` (ServerlessInstance pool), `src/plugin/instance_pool.rs` (WASM plugin pool)

**Note**: There are TWO separate pools:
- **ServerlessInstancePool** (`src/serverless/instance_pool.rs`): Manages WASM module instances for serverless functions with autoscaling
- **WasmInstancePool** (`src/plugin/instance_pool.rs`): Manages filter plugin instances (max_size: 100 for filter plugins, 4 for tests)

**Problems**:

1. **O(n) eviction in ServerlessInstancePool**: `instances.retain()` on line 269 of `instance_pool.rs`
2. **Slow autoscaler**: 10s interval (run_autoscaler loop)
3. **Pool modes dead code**: Direct/Hybrid not implemented in ServerlessInstancePool
4. **LIFO selection**: May keep hot instances busy
5. **WasmInstancePool uses O(n) search**: Linear search through Vec by filter_name (line 34-37)

**Recommended Fix**:

1. **ServerlessInstancePool**: Replace Vec with HashMap for O(1) eviction:
```rust
// Current (O(n)):
struct InstancePool {
    instances: RwLock<Vec<Arc<ServerlessInstance>>>,
}

// Improved (O(1)):
struct InstancePool {
    instances: RwLock<HashMap<String, Arc<ServerlessInstance>>>,
    idle_order: RwLock<VecDeque<String>>,  // For FIFO ordering
}
```

2. **WasmInstancePool**: Replace Vec with HashMap by filter_name:
```rust
// Current (O(n) linear search):
pub(crate) fn get(&self, filter_name: &str) -> Option<WasmPooledInstance> {
    let mut pool = self.pool.lock();
    let pos = pool.iter().position(|inst| inst.filter_name == filter_name)?;
    let inst = pool.remove(pos);
    Some(inst)
}

// Improved (O(1)):
struct WasmInstancePool {
    pools: Arc<DashMap<String, Vec<WasmPooledInstance>>>,  // Per-filter pools
    engine: Arc<Engine>,
    max_size: usize,
}
```

3. Reduce autoscaler interval:
```rust
const AUTOSCALER_INTERVAL: Duration = Duration::from_secs(2);  // Was 10s

// Or make configurable:
let interval = config.autoscaler_interval_seconds.unwrap_or(2);
```

3. Implement Direct pool mode:
```rust
// For truly stateless functions
pub async fn get_instance_direct(&self) -> Result<ServerlessInstance, PoolError> {
    self.runtime.instantiate().await
}
```

4. Consider predictive scaling:
```rust
// Track request rate over sliding window
struct RequestRateTracker {
    window: SlidingWindowCounter,
    last_scale_action: Instant,
}

impl InstancePool {
    fn should_predict_scale_up(&self) -> bool {
        let rate = self.rate_tracker.current_rate();
        let utilization = self.current_utilization();

        // Scale up if rate is increasing AND we're above threshold
        rate.increasing() && utilization > self.config.scale_up_threshold
    }
}
```

**Implementation complexity**: Medium
**Risk**: Medium - affects instance lifecycle
**Estimated time**: 2 days

---

### Category 7: Module Distribution Persistence

**Severity**: 🟡 MEDIUM
**Impact**: No disk persistence
**Location**: `src/mesh/wasm_dist.rs`

**Current state**:
- ✅ Checksum validation via SHA-256 (`store()` validates checksum at line 51-57)
- ✅ Version tracking (multiple versions stored, `gc_old_versions()` for cleanup)
- ❌ No disk persistence - in-memory only, lost on restart
- ❌ No signature verification (checksum vs Ed25519 signing)

**Recommended Fix**:

1. Add disk persistence:
```rust
// src/mesh/wasm_dist.rs
pub struct PersistentWasmStore {
    cache_dir: PathBuf,
    memory_cache: Arc<DashMap<String, WasmModule>>,
}

impl PersistentWasmStore {
    pub fn load(&self, name: &str) -> Option<WasmModule> {
        // Check memory first
        if let Some(module) = self.memory_cache.get(name) {
            return Some(module.clone());
        }

        // Load from disk
        let path = self.cache_dir.join(format!("{}.wasm", name));
        if let Ok(data) = std::fs::read(&path) {
            let module = WasmModule::from_bytes(&data);
            self.memory_cache.insert(name.to_string(), module.clone());
            return Some(module);
        }

        None
    }

    pub fn persist(&self, name: &str, module: &WasmModule) -> Result<(), Error> {
        let path = self.cache_dir.join(format!("{}.wasm", name));
        std::fs::write(&path, module.bytes())?;
        self.memory_cache.insert(name.to_string(), module.clone());
        Ok(())
    }
}
```

2. Add Ed25519 signature verification (beyond checksum):
```rust
// Verify signer is authorized global node
pub fn verify_module_signature(module: &WasmModule) -> Result<(), Error> {
    // Module already has checksum - add Ed25519 signature verification
    // to prove the module came from an authorized global node
    let signature = module.signature();
    let public_key = module.signer_public_key();

    if !public_key.verify(&module.content_hash(), signature) {
        return Err(Error::InvalidSignature);
    }

    // Check signer is authorized global node
    if !is_authorized_signer(&public_key) {
        return Err(Error::UnauthorizedSigner);
    }

    Ok(())
}
```

**Implementation complexity**: Medium
**Risk**: Medium - adds persistence layer
**Estimated time**: 1-2 days

---

### Category 8: Plugin Lifecycle Improvements

**Severity**: 🟡 MEDIUM
**Impact**: No graceful degradation on reload failure
**Location**: `src/plugin/mod.rs:281-370`

**Problems**:
1. Old plugin stays in memory if reload fails
2. In-flight requests during reload may use old plugin
3. No graceful shutdown period

**Recommended Fix**:

1. Add graceful reload with drain period:
```rust
pub struct PluginReloadStrategy {
    drain_duration: Duration,
    old_plugin_ttl: Duration,
}

impl PluginManagerLifecycle {
    pub async fn reload_with_grace(&self, path: &Path) -> Result<(), Error> {
        // 1. Start loading new plugin
        let new_plugin = self.plugin_manager.load_plugin(path)?;

        // 2. Mark old plugin as draining
        self.mark_draining(&current_plugin);

        // 3. Wait for in-flight requests to complete (or timeout)
        let deadline = Instant::now() + self.drain_duration;
        while Instant::now() < deadline {
            if self.plugin_manager.active_request_count(&current_plugin) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // 4. Swap plugins
        self.plugin_manager.swap_plugin(&current_plugin, &new_plugin);

        // 5. Keep old plugin alive briefly for any stragglers
        let old_plugin = current_plugin.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(old_plugin);
        });

        Ok(())
    }
}
```

2. Add reload status API:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReloadStatus {
    Stable,
    Loading { new_version: String },
    Draining { remaining_requests: u32 },
    Reloaded { version: String },
}
```

**Implementation complexity**: Medium
**Risk**: Low - additive improvement
**Estimated time**: 1 day

---

### Category 9: ABI Standardization Consideration

**Severity**: 🟢 LOW
**Impact**: Informational only
**Location**: `src/plugin/wasm_runtime.rs:24-43`

**Current state**: Custom linear-memory ABI with pointer/length conventions.

**Comparison**:
| Aspect | Current | WASI Preview 2 (wasi-http) |
|--------|---------|---------------------------|
| Type system | i32/i64 primitives | WIT-defined record/variant |
| HTTP types | Raw bytes + manual parsing | `incoming-request`, `outgoing-response` |
| Streams | Single buffer copies | `input-stream`/`output-stream` |
| Error handling | i32 return codes | `result` types |
| Interop | Proprietary | Standardized, composable |

**Recommendation**: Consider adopting WASI Preview 2 HTTP proxying for future-proofing, but current ABI is functional for existing plugins.

**Status**: No immediate action needed - informational only.

---

## Implementation Phases

### Phase 1: Critical Security Fixes

| # | Category | Effort | Risk | Est. Impact |
|---|----------|--------|------|-------------|
| 1.1 | Wire verify_caller_permission | Medium | Medium | Security |
| 1.2 | DHT access control for WASM | Medium | Medium | Security |
| 1.3 | Implement ResourceLimiter | Medium | Low | Security |

### Phase 2: High-Priority Performance

| # | Category | Effort | Risk | Est. Impact |
|---|----------|--------|------|-------------|
| 2.1 | Pre-compile regex routes | Medium | Low | Performance |
| 2.2 | Remote execution retry/LB | Medium | Medium | Reliability |
| 2.3 | Instance pool O(1) eviction (both pools) | Medium | Medium | Performance |

### Phase 3: Medium-Priority Improvements

| # | Category | Effort | Risk | Est. Impact |
|---|----------|--------|------|-------------|
| 3.1 | Module distribution persistence | Medium | Medium | Reliability |
| 3.2 | Plugin lifecycle graceful reload | Medium | Low | Reliability |
| 3.3 | Route caching | Low | Low | Performance |

---

## Implementation Checklist

### Phase 1: Security Critical

- [ ] **S1.1**: Define `CallerContext` struct with node_id, role, org_id, tier
- [ ] **S1.2**: Update `handle_serverless_function` signature to accept caller context
- [ ] **S1.3**: Call `verify_caller_permission()` at entry points
- [ ] **S1.4**: Extract caller identity from mesh transport connection
- [ ] **S1.5**: Fix TierClaim creation to use actual caller identity
- [ ] **S1.6**: Add plugin capability config for DHT access
- [ ] **S1.7**: Implement capability check in `mesh_query_dht`
- [ ] **S1.8**: Add rate limiting to WASM host functions
- [ ] **S1.9**: Implement `ResourceLimiter` trait for memory limits
- [ ] **S1.10**: Enable epoch interruption for CPU timeout
- [ ] **S1.11**: Add fuel consumption tracking per instance

### Phase 2: Performance

- [ ] **P2.1**: Add `compiled_regex` field to `ServerlessRoute`
- [ ] **P2.2**: Pre-compile regex patterns on route registration
- [ ] **P2.3**: Fix route priority calculation
- [ ] **P2.4**: Add route caching DashMap
- [ ] **P2.5**: Implement exponential backoff retry for remote execution
- [ ] **P2.6**: Add multi-provider selection (weighted random)
- [ ] **P2.7**: Apply timeout to mesh invocation
- [ ] **P2.8**: Replace Vec with HashMap for instance eviction (ServerlessInstancePool)
- [ ] **P2.8b**: Replace Vec with HashMap for filter lookup (WasmInstancePool)
- [ ] **P2.9**: Reduce autoscaler interval to 2s
- [ ] **P2.10**: Implement Direct pool mode

### Phase 3: Polish

- [ ] **L3.1**: Add disk persistence to WasmDistManager
- [ ] **L3.2**: Add signature verification for distributed modules
- [ ] **L3.3**: Implement graceful reload with drain period
- [ ] **L3.4**: Add reload status API endpoint
- [ ] **L3.5**: Add glob_match memoization
- [ ] **L3.6**: Document WASM plugin ABI in developer guide

---

## Testing Recommendations

### Security Testing

1. **Permission bypass**: Verify unauthorized callers are rejected
2. **DHT access**: Verify plugins can only access allowed keys
3. **Rate limiting**: Verify DoS via host function calls is prevented

### Performance Testing

1. **Regex routes**: Profile at 500K rps with regex patterns
2. **Instance pool**: Verify autoscaling under burst traffic
3. **Remote execution**: Test retry logic with provider failures

### Integration Testing

1. **Mesh distribution**: Test plugin loading from mesh store
2. **Graceful reload**: Verify no requests fail during reload
3. **Remote invocation**: Test multi-provider fallback

---

## Estimated Timeline

| Phase | Duration | Total |
|-------|----------|-------|
| Phase 1: Security | 5-7 days | 5-7 days |
| Phase 2: Performance | 4-5 days | 9-12 days |
| Phase 3: Polish | 3-4 days | 12-16 days |

**Total estimated time**: 12-16 days

---

## References

- `src/plugin/wasm_runtime.rs` - Core WASM execution
- `src/plugin/mod.rs` - Plugin manager
- `src/plugin/instance_pool.rs` - WASM plugin instance pool (filter plugins)
- `src/serverless/manager.rs` - Serverless manager
- `src/serverless/instance_pool.rs` - Serverless instance pool (serverless functions)
- `src/serverless/routing.rs` - Route matching
- `src/mesh/wasm_dist.rs` - Module distribution
- `src/mesh/transports/manager.rs` - Remote execution
- WASI Preview 2: https://github.com/WebAssembly/WASI/blob/preview2/design/http.md
- wasmtime ResourceLimiter: https://docs.rs/wasmtime/latest/wasmtime/trait.ResourceLimiter.html

---

## Appendix: WASM Plugin Guest ABI Reference

### Current Function Signatures

```rust
// filter_request - Filter incoming request
// Returns: 0=pass, 1=block, 2=challenge, -1=error
type FilterRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32), i32>;

// transform_response - Transform response body
// Returns: new body length
type TransformResponseFn = TypedFunc<(i32, i32, i32, i32, i32), i32>;

// handle_request - Full request handling (serverless)
// Returns: 0=success, -1=error; writes status/body to memory
type HandleRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>;

// Guest memory helpers
type GuestAllocFn = TypedFunc<i32, i32>;
type GuestFreeFn = TypedFunc<(i32, i32), ()>;
```

### Memory Passing Convention

1. Call `guest_alloc(size)` to get pointer
2. Host copies data to memory at pointer
3. Pass pointer/length to WASM function
4. WASM calls `guest_free(ptr, size)` when done

### Header Serialization Format

```
[header_count: u16 LE]
[(name_len: u16)(name)(value_len: u16)(value)]...
```