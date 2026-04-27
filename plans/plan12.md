# MaluWAF Implementation Plan - Wave 12

**Plugin Architecture WASM & Serverless Improvements**

**Status**: Reviewed - Pending Implementation
**Last Updated**: 2026-04-27 (reviewed)
**Source Investigation**: Comprehensive code review of WASM filtering, serverless (standalone + mesh mode), and Axum integration

---

## Investigation Summary

This plan addresses findings from a comprehensive review of the plugin architecture covering:
- **WASM filtering** (`src/plugin/wasm_runtime.rs`, `src/plugin/instance_pool.rs`)
- **WASM serverless** (`src/serverless/manager.rs`, `src/serverless/instance_pool.rs`)
- **Axum integration** (`src/plugin/axum_loader.rs`, `src/http/server.rs`)
- **Mesh serverless** (`src/mesh/transport.rs`, `src/mesh/transport_peer.rs`)

---

## Review Notes (2026-04-27)

During review, the following items were verified and corrected:

1. **Rate limit bypass flow verified**: WASM filters at line 2317 run AFTER `waf.check_request_full()` at line 1431 which includes rate limit checking. The attack vector is confirmed.

2. **AxumDynamic WAF bypass clarified**: AxumDynamic returns early at line 1728 BEFORE reaching line 2317 (WASM filters). This is different from the rate limit issue — it's not about ordering but about entire WAF sections being skipped.

3. **12.1.4 added**: WASM Filters Never Run for AxumDynamic — new finding documenting the scope of WASM filter application.

4. **BumpAllocator doesn't exist**: The plan references `BumpAllocator` but it doesn't exist in the codebase. Implementation will need to create this type or use an alternative approach (e.g., a simple bump arena).

5. **Implementation options for each item are more precise**: Code locations verified against actual source.

---

## Wave 12.1: Critical Security Fixes

**Target**: P0 - Security vulnerabilities requiring immediate attention

### 12.1.1: Rate Limit Bypass via WASM Filters

**Status**: PENDING
**Priority**: CRITICAL
**File**: `src/http/server.rs:1431` (rate limit) and `src/http/server.rs:2317-2347` (WASM filters)

**Issue**: WASM filters execute AFTER rate limit checks pass, allowing clients to exhaust rate limit budget with requests that are ultimately blocked by WASM plugins before reaching the upstream.

**Attack Vector**:
```
Client → Rate Limit (counted as 1) → WAF check (Pass) → WASM Filter (BLOCKED)
                                                    ↑ Never reaches upstream
Result: Client uses up rate limit budget on blocked requests → denial of service
```

**Current Code Flow** (verified in code):
1. Line 1418-1443: `waf.check_request_full()` — **INCLUDES rate limiting** at lines 984-991 in waf/mod.rs
2. Line 1445-1644: WAF decision handling (Drop, Stall, Block, Challenge, Pass)
3. Line 1645: `crate::proxy::WafDecision::Pass` branch enters SECTION 15
4. Line 1702-1741: AxumDynamic handled (returns early)
5. Line 1743-1854: Static/Serverless handled
6. **Line 2317-2347**: `apply_wasm_filters()` runs here for upstream proxy

**Key Finding**: The flow is:
- Rate limit counted at step 1 (before WASM)
- WASM filters run at step 6 (after rate limit counted)
- If WASM blocks, upstream never sees the request but rate limit budget is consumed

**Implementation Options**:

**Option A (Recommended) - Run WASM filters BEFORE rate limit**:
```rust
// In handle_http_request(), move lines 2317-2347 BEFORE check_request_full() at line 1431
// This ensures only requests that pass WASM filters count toward rate limits

// Move this block:
if let Some(pm) = router.plugin_manager() {
    let wasm_result = pm.apply_wasm_filters(filter_req, HashMap::new())?;
    match wasm_result {
        WasmFilterResult::Block(status, msg) => { return Ok(build_block_response(...)); }
        WasmFilterResult::Challenge(reason) => { return Ok(build_challenge_response(...)); }
        WasmFilterResult::Pass => {} // Continue to rate limit check
    }
}

// Then run rate limit check at line 1431
waf.check_request_full(...).await
```

**Option B - Add pre-check hook in rate limiter**:
```rust
// In check_request_full(), add WASM pre-check before rate limiting
// Requires passing plugin_manager and site_config into WAF module
```

**Verification**:
```bash
cargo test --test integration_test
# Manual test: Send requests that pass rate limit but blocked by WASM
# Verify rate limit counter only increments for requests that pass WASM
```

---

### 12.1.2: AxumDynamic WAF Bypass

**Status**: PENDING
**Priority**: CRITICAL
**File**: `src/http/server.rs:1702-1741`, line 1725

**Issue**: AxumDynamic backend skips all WAF checks by returning early at line 1728. Security checks skipped:
- WAF attack detection (line 1431) — **NOT REACHED** for AxumDynamic
- WASM request filters (line 2317) — **NOT REACHED** for AxumDynamic  
- Upload YARA scanning (line 2448) — **NOT REACHED** for AxumDynamic

Additionally, request body is discarded at line 1725 (`Body::empty()`).

**Verified Code Flow**:
```
Line 1418-1443: WAF check (but for Pass path only)
Line 1645: WafDecision::Pass branch
Line 1702-1741: AxumDynamic check → returns at line 1728
    ↑ EARLY RETURN — never reaches line 2317 (WASM filters) or line 2442 (upload scan)
```

**Current Code** (lines 1702-1741):
```rust
// Check for AxumDynamic plugin backend
if matches!(target.backend_type, BackendType::AxumDynamic) {
    if let Some(pm) = router.plugin_manager() {
        let plugin_router = pm.get_axum_router_by_name(...);
        if let Some(plugin_router) = plugin_router {
            // ... build plugin_req ...
            let plugin_req = plugin_req_builder
                .body(axum::body::Body::empty())  // BUG: discards body at line 1725
                .unwrap_or_else(|_| ...);

            return Self::handle_axum_dynamic_request(  // Line 1728: EARLY RETURN
                plugin_req,
                plugin_router,
                &alt_svc,
                &main_config,
            ).await;
        }
    }
}
// Continues to Static, Serverless, Upstream paths...
```

**Note**: For AxumDynamic, the issue is NOT about rate limit order — the entire WAF check at line 1431 IS reached because WAF decision must be Pass to reach line 1702. However, the AxumDynamic path returns early and never reaches the WASM filter section.

**Implementation**:

**Step 1: Fix body discard bug** (line 1725):
```rust
// Change from:
let plugin_req = plugin_req_builder
    .body(axum::body::Body::empty())  // BUG: discards body

// To:
let plugin_req = plugin_req_builder
    .body(axum::body::Body::from(full_body_arc.clone()))  // Forward body
```

**Step 2: Add WAF integration before plugin call**:
```rust
// Add WAF check before calling handle_axum_dynamic_request
let waf_decision = waf.check_request_full(
    client_ip,
    method_str.as_str(),
    &path,
    query_string,
    &parts.headers,
    &full_body_arc,  // Use full body
    user_agent.as_deref(),
    None,
    Some(&target.site_config.bot),
).await;

match waf_decision {
    crate::proxy::WafDecision::Block(status, msg) => {
        let body = waf.error_page_manager.render_page(status.as_u16(), Some(&msg));
        return Ok(Self::build_response_with_alt_svc(status.as_u16(), body, "text/html", &alt_svc, &main_config));
    }
    crate::proxy::WafDecision::Pass => {} // Continue to plugin
    // ... handle other decisions ...
}

// Then call handle_axum_dynamic_request with body_bytes included
```

**Step 3: Add response transform support**:
```rust
// In handle_axum_dynamic_request, after plugin returns:
// Apply WASM response transforms
if let Some(pm) = router.plugin_manager() {
    let wasm_resp = http::Response::builder()
        .status(response.status())
        .body(body_from_plugin).unwrap();
    let transformed = pm.apply_wasm_response_transforms(wasm_resp, ...)?;
}
```

**Verification**:
```bash
cargo test --lib --no-run
# Send request with body to AxumDynamic endpoint
# Verify body reaches plugin
# Send malicious payload
# Verify WAF blocks it
```

---

### 12.1.3: AxumDynamic Body Discard (Standalone Bug)

**Status**: PENDING
**Priority**: CRITICAL (subset of 12.1.2)
**File**: `src/http/server.rs:1725`

**Issue**: `Body::empty()` discards the request body, sending empty body to AxumDynamic backend.

**Fix**: Covered in 12.1.2 Step 1.

---

### 12.1.4: WASM Filters Never Run for AxumDynamic (Deep Dive)

**Status**: PENDING  
**Priority**: CRITICAL
**File**: `src/http/server.rs:2315-2347`

**Finding**: The WASM filter block at line 2317 is labeled "FastCGI, PHP, CGI, and AppServer backends fall through to upstream proxy". This block only runs for upstream proxy-type backends, NOT for AxumDynamic which returns at line 1728.

**Current Scope of WASM Filters**:
| Backend Type | WASM Filters? | Location |
|--------------|---------------|----------|
| FastCGI | Yes | Line 2317 (falls through from line 1854) |
| PHP | Yes | Line 2317 |
| CGI | Yes | Line 2317 |
| AppServer | Yes | Line 2317 |
| Upstream | Yes | Line 2317 |
| AxumDynamic | **NO** | Returns early at line 1728 |
| Serverless | **NO** | Returns at line 1885 |
| Static | **NO** | Falls through to upstream at line 1854 |

**Recommendation**: This is a design gap. AxumDynamic should be able to participate in WASM filtering if configured.

---

## Wave 12.2: Performance Optimizations at 500K rps

**Target**: P1 - High impact for scalability goals

### 12.2.1: Per-Request guest_alloc Overhead

**Status**: PENDING
**Priority**: HIGH
**File**: `src/plugin/wasm_runtime.rs:840-900`, `src/plugin/instance_pool.rs`

**Issue**: Filter path makes up to 4 `guest_alloc` calls per request (method, uri, headers, body) at 500K rps = 2B+ function calls/sec.

**Current Flow** (`filter_request` → `do_filter_request_with_exports`):
```rust
// Up to 4 allocations per request:
method_ptr = write_to_guest_memory(store, exports, method_bytes);  // guest_alloc
uri_ptr    = write_to_guest_memory(store, exports, uri_bytes);     // guest_alloc
hdr_ptr    = write_to_guest_memory(store, exports, headers_meta);  // guest_alloc
body_ptr   = write_to_guest_memory(store, exports, body_bytes);   // guest_alloc
```

**Memory Model Issue**:
- Pooled instance reuses `Store<RequestContext>` but memory is NOT reset between requests
- WASM linear memory retains data from previous requests
- `guest_alloc` may return previously-used regions

**Implementation - Pre-allocated Bump Allocator**:

```rust
// src/plugin/wasm_runtime.rs

// Add to RequestContext
pub struct PreallocatedBuffers {
    method_buf: Bytes,
    uri_buf: Bytes,
    headers_buf: Bytes,
    body_buf: Bytes,
    // Arenas for allocation
    method_arena: BumpAllocator,
    uri_arena: BumpAllocator,
    headers_arena: BumpAllocator,
    body_arena: BumpAllocator,
}

impl RequestContext {
    fn new() -> Self {
        Self {
            // ... existing fields ...
            preallocated: PreallocatedBuffers {
                method_buf: Bytes::mut_with_capacity(4096),
                uri_buf: Bytes::mut_with_capacity(8192),
                headers_buf: Bytes::mut_with_capacity(16384),
                body_buf: Bytes::mut_with_capacity(65536),
                method_arena: BumpAllocator::new(4096),
                uri_arena: BumpAllocator::new(8192),
                headers_arena: BumpAllocator::new(16384),
                body_arena: BumpAllocator::new(65536),
            },
        }
    }

    fn reset_arenas(&mut self) {
        self.method_arena.reset();
        self.uri_arena.reset();
        self.headers_arena.reset();
        self.body_arena.reset();
    }
}

// Modify write_to_guest_memory to use bump allocation
fn write_to_guest_memory_bump(
    &self,
    store: &mut Store<RequestContext>,
    exports: &GuestExports,
    data: &[u8],
    arena: &mut BumpAllocator,
) -> Result<i32, WasmPluginError> {
    // Check if data fits in pre-allocated buffer
    if data.len() <= arena.capacity() - arena.used() {
        let ptr = arena.allocate(data.len())?;
        // Write directly to WASM memory via bump
        store.data_mut().memory.get()
            .write(ptr, data)
            .map_err(|_| WasmPluginError::MemoryAccess)?;
        Ok(ptr as i32)
    } else {
        // Fall back to guest_alloc for large data
        self.write_to_guest_memory(store, exports, data)
    }
}
```

**Add to instance_pool.rs prepare_for_request()**:
```rust
pub fn prepare_for_request(&self, env: HashMap<String, String>, timeout: Duration) {
    // ... existing code ...
    // NEW: Reset arenas for fresh allocation
    self.store.data_mut().reset_arenas();
}
```

**Verification**:
```bash
# Add metrics first
cargo build --release
# Run benchmarks
./target/release/bench_wasm --filter pooled_instance
# Check WASM_ALLOC_COUNT and WASM_ALLOC_BYTES metrics
```

---

### 12.2.2: Serverless Fresh Instantiation Per Call

**Status**: PENDING
**Priority**: HIGH
**File**: `src/plugin/wasm_runtime.rs:1247-1373`, `src/serverless/instance_pool.rs`

**Issue**: `invoke_handler()` creates a fresh `Store` every call, bypassing instance pooling entirely. No warmup, no reuse.

**Current Code** (line 1267-1268):
```rust
// In invoke_handler():
let mut store = self.create_store(env);  // FRESH every call
let exports = self.instantiate(&mut store)?;  // Also fresh
```

**Implementation - Add Serverless Instance Pooling**:

```rust
// src/serverless/instance_pool.rs

// Add to ServerlessInstance
pub struct ServerlessInstance {
    // ... existing fields ...
    wasm_runtime: Arc<WasmRuntime>,       // NEW: reference to runtime
    store: Store<RequestContext>,         // NEW: persistent store
    exports: GuestExports,                // NEW: pre-resolved exports
    last_used: Instant,                   // for idle tracking
}

// Modify InstancePool to support WASM reuse
impl InstancePool {
    pub async fn get_instance(&self) -> Result<Arc<ServerlessInstance>, ServerlessError> {
        // ... existing code ...

        // NEW: Try to get warmed instance first
        if let Some(mut inst) = self.idle_instances.pop() {
            inst.last_used = Instant::now();
            // Reset timeout/fuel but keep compiled module
            inst.prepare_for_request();
            return Ok(Arc::new(inst));
        }

        // Fall back to creating new instance
        self.create_instance().await
    }

    // Add prepare_for_request to ServerlessInstance
    fn prepare_for_request(&mut self) {
        self.store.data_mut().start = Instant::now();
        self.store.data_mut().env = self.function_definition.env.clone();
        // Reset fuel if configured
        self.store.set_fuel(self.function_definition.cpu_fuel.unwrap_or(1000000));
    }
}
```

**Alternative: Use shared WasmRuntime pool**:
```rust
// In invoke_handler(), check runtime pool first
let pooled = self.wasm_runtime.get_pooled_instance()?;
if let Some(mut inst) = pooled {
    inst.prepare_for_request(env);
    return self.do_invoke_with_instance(inst, ...);
}
// Fall back to fresh instantiation only if pool empty
```

**Verification**:
```bash
cargo test --lib serverless
# Run load test, measure cold start reduction
```

---

### 12.2.3: Serverless Env HashMap Clones

**Status**: PENDING
**Priority**: MEDIUM
**File**: `src/serverless/manager.rs:662`, `src/config/serverless.rs`

**Issue**: `function.definition.env.clone()` clones static config HashMap per invocation at 500K rps = 2M clones/sec.

**Current**:
```rust
// manager.rs:662
let env = function.definition.env.clone();  // Clones entire HashMap
instance.instance.invoke_handler(..., env)
```

**Implementation**:

```rust
// src/config/serverless.rs - Change FunctionDefinition
pub struct FunctionDefinition {
    // ... existing fields ...
    // Change from:
    // pub env: HashMap<String, String>,
    // To:
    pub env: Arc<HashMap<String, String>>,  // Arc-wrapped for cheap clone
}

// src/serverless/manager.rs - Update invocation
pub async fn invoke_for_mesh(&self, ...) -> Result<ServerlessInvokeResponse, ServerlessError> {
    // ... existing code ...
    let env = function.definition.env.clone();  // Now Arc::clone is ~0.5ns
    instance.instance.invoke_handler(..., env).await
}

// src/serverless/manager.rs:825,863 - Same change
let env = function.definition.env.clone();  // Arc::clone
```

**Important**: If plugins modify env, need copy-on-write:
```rust
// If plugin mutates env, we need owned copy
fn invoke_handler(&self, ..., mut env: Arc<HashMap<...>>) {
    // Check if mutation needed
    let owned_env = if needs_write {
        let mut new_env = (*env).clone();  // Clone only if needed
        Arc::new(new_env)
    } else {
        env  // Share without clone
    };
}
```

**Verification**:
```bash
cargo test --lib serverless
# Measure allocation reduction via metrics
```

---

## Wave 12.3: Reliability Improvements

**Target**: P2 - Medium priority for production resilience

### 12.3.1: Response Transform Instance Pooling

**Status**: PENDING
**Priority**: MEDIUM
**File**: `src/plugin/wasm_runtime.rs:1158-1159`, `src/plugin/mod.rs`

**Issue**: Response transforms use fresh `Store` each time (no pooling), unlike request filters which use pooled instances.

**Asymmetry Summary**:
| Aspect | Request Filter | Response Transform |
|--------|---------------|-------------------|
| Instance pooling | Yes | **No** |
| Body truncation | 1MB via `body_slice` | **No truncation** |
| Header filtering | All headers to WASM | **Filtered before WASM** |
| Error behavior | Fail-closed | **Fail-open** |

**Implementation**:

```rust
// src/plugin/wasm_runtime.rs

// Add transform_response_with_pool method
pub fn transform_response_with_pool(
    &self,
    response: Response<Bytes>,
    env: HashMap<String, String>,
) -> Result<Response<Bytes>, WasmPluginError> {
    // Get pooled instance
    let pooled = self.instance_pool.get("transform")  // Use "transform" as filter name
        .ok_or(WasmPluginError::NoInstanceAvailable)?;

    let mut store = pooled.store;
    let exports = pooled.exports;

    // Reset for transform
    store.data_mut().start = Instant::now();
    store.data_mut().env = env;

    // Proceed with transform
    self.do_transform_with_exports(response, store, exports)
}

// Modify transform_response to try pooling first
pub fn transform_response(
    &self,
    response: Response<Bytes>,
    env: HashMap<String, String>,
) -> Result<Response<Bytes>, WasmPluginError> {
    // Try pooled first, fall back to fresh
    if let Ok(result) = self.transform_response_with_pool(response, env.clone()) {
        return result;
    }
    // Fall back to fresh (existing code)
    self.transform_response_fresh(response, env)
}
```

**Also address body truncation**:
```rust
// In http/server.rs:2748, add truncation for consistency
let body_for_transform = if body.len() > MAX_WASM_DATA_SIZE {
    body.slice(0..MAX_WASM_DATA_SIZE)  // Truncate to 1MB like request path
} else {
    body
};
```

**Verification**:
```bash
cargo test --lib wasm
# Benchmark: transform_response_with_pool vs transform_response_fresh
```

---

### 12.3.2: Mesh Graceful Degradation

**Status**: PENDING
**Priority**: MEDIUM
**File**: `src/serverless/manager.rs:787-799`, `src/mesh/transport.rs`

**Issue**: No structured fallback when DHT/mesh unavailable. Returns 502 with no distinction between "function not found" vs "mesh error".

**Current Behavior**:
| Scenario | Current | Expected |
|----------|---------|----------|
| DHT unavailable | 502 Bad Gateway | 503 with retry-after |
| Peer unreachable | Blocks indefinitely | Timeout + fallback |
| Local function | Works | Works |

**Implementation**:

```rust
// src/serverless/error.rs - Add structured errors
#[derive(Error, Debug)]
pub enum ServerlessError {
    // ... existing ...

    // NEW: Mesh degradation errors
    #[error("Mesh unavailable: {0}")]
    MeshUnavailable(String),

    #[error("Function not found locally")]
    FunctionNotFound,

    #[error("Remote execution failed: {0}")]
    RemoteExecutionFailed(String),
}

// src/config/serverless.rs - Add config
pub struct ServerlessConfig {
    // ... existing fields ...

    #[serde(default = "default_mesh_fallback_mode")]
    pub mesh_fallback_mode: MeshFallbackMode,

    #[serde(default = "default_mesh_timeout_ms")]
    pub mesh_timeout_ms: u64,

    #[serde(default = "default_mesh_retry_count")]
    pub mesh_retry_count: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum MeshFallbackMode {
    Local,      // Only use local functions
    Error,      // Return error if mesh required
    Retry,      // Retry with backoff
}

// src/serverless/manager.rs - Implement fallback
pub async fn handle_serverless_function(&self, ...) -> Result<Response<Bytes>, ServerlessError> {
    // ... existing code up to mesh proxy attempt ...

    match self.config.mesh_fallback_mode {
        MeshFallbackMode::Local => {
            // Only allow local execution
            if has_local_runtime {
                return self.invoke_local(...).await;
            }
            return Err(ServerlessError::FunctionNotFound);
        }
        MeshFallbackMode::Error => {
            return Err(ServerlessError::MeshUnavailable(
                "Mesh mode required but unavailable".to_string()
            ));
        }
        MeshFallbackMode::Retry => {
            // Retry with backoff
            let mut last_err = ServerlessError::MeshUnavailable("Initial".to_string());
            for attempt in 0..self.config.mesh_retry_count {
                if let Some(rs) = self.record_store.read().as_ref() {
                    if rs.get_record(&upstream_id).is_some() {
                        match mt.proxy_serverless_request(...).await {
                            Ok(resp) => return Ok(resp),
                            Err(e) => last_err = ServerlessError::RemoteExecutionFailed(e.to_string()),
                        }
                    }
                }
                // Backoff: 100ms, 200ms, 400ms
                tokio::time::sleep(Duration::from_millis(100 * 2_u64.pow(attempt))).await;
            }
            return Err(last_err);
        }
    }
}
```

**Add mesh availability tracking**:
```rust
// src/mesh/mod.rs - Add MeshAvailability enum
pub enum MeshAvailability {
    LocalOnly,   // Mesh disabled or unavailable
    Degraded,    // Some peers reachable, DHT incomplete
    Full,        // All mesh features operational
}

// Track in MeshTransportManager
pub struct MeshTransportManager {
    // ... existing fields ...
    availability: RwLock<MeshAvailability>,
}
```

**Verification**:
```bash
cargo test --test integration_test
# Test with mesh disabled, verify local-only mode works
```

---

### 12.3.3: Autoscaler Event-Driven Improvements

**Status**: PENDING
**Priority**: MEDIUM
**File**: `src/serverless/instance_pool.rs:398-436`

**Issue**: Time-based polling (10s) is reactive, not proactive. Scale-up calculation may be too slow for bursty traffic at 500K rps.

**Current Scaling Behavior**:
- Adds `max(50% of current, 1)` instances per poll, max 5 per tick
- At 100 instances, scale-up = 5 per 10s = 0.5/sec
- To scale from 10 to 200 instances: 38 polls = **6+ minutes**

**Implementation**:

```rust
// src/serverless/instance_pool.rs

// Make polling interval configurable
pub struct InstancePoolConfig {
    // ... existing fields ...
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,  // NEW: default 10
}

// Add immediate scale-up on exhaustion
pub async fn get_instance(&self) -> Result<Arc<ServerlessInstance>, ServerlessError> {
    let idle = self.idle_instances.lock().await.pop();
    if idle.is_some() {
        // ... existing code ...
    }

    // NEW: Immediate scale-up trigger
    let current = self.instances.read().len();
    let active = self.active_instances.read().len();
    let pending = self.pending_request_count.load(Ordering::Relaxed);

    // If pool exhausted and below max, trigger immediate scale
    if idle.is_none() && current < self.config.max_instances {
        if active >= current.saturating_sub(1) || pending > active {
            // Pool is saturated - trigger scale-up
            let to_spawn = self.calculate_scale_up_amount().await;
            if to_spawn > 0 {
                let _ = self.scale_up(to_spawn).await;
            }
        }
    }

    // If still no instance, create one (blocking but necessary)
    self.create_instance().await
}

// Add rate-of-change tracking
pub struct InstancePool {
    // ... existing fields ...
    request_rate_history: RwLock<VecDeque<(Instant, usize)>>,  // NEW
}

fn get_request_rate(&self) -> f64 {
    let history = self.request_rate_history.read();
    // Calculate requests/sec over last 30 seconds
    // If rate increasing > threshold, preemptively scale
}

// Modify run_autoscaler for preemptive scaling
async fn run_autoscaler(&self) {
    let mut interval = tokio::time::interval(
        Duration::from_secs(self.config.poll_interval_secs)  // Now configurable
    );

    loop {
        interval.tick().await;

        // Existing utilization check
        let utilization = self.get_utilization();

        // NEW: Rate-of-change check
        let rate = self.get_request_rate();
        let rate_change = self.get_rate_of_change();

        if rate_change > 0.5 && utilization > 0.5 {
            // Requests/sec increasing >50% and >50% utilized
            // Preemptively scale
            let preemptive = ((current as f64 * 0.3) as usize).max(3);
            self.scale_up(preemptive).await;
        }

        // Existing scale logic
        if utilization >= self.config.scale_up_threshold {
            // ... existing scale up ...
        }
    }
}
```

**Add pending request tracking**:
```rust
// In InstancePool
pending_request_count: AtomicUsize,

// Increment on get_instance() call start
// Decrement on return_instance() call end
// Scale when pending > active_instances * 2
```

**Verification**:
```bash
cargo test --lib serverless
# Load test: burst traffic, measure scale-up latency
```

---

## Wave 12.4: Consistency & Stability

**Target**: P2 - Code quality and future-proofing

### 12.4.1: Native Plugin ABI Stability

**Status**: PENDING
**Priority**: MEDIUM (Experimental Feature)
**File**: `src/plugin/axum_loader.rs`

**Issue**: Native plugins have critical issues preventing production use:
1. Library dropped immediately after `load_plugin()` returns
2. No `destroy_router` cleanup called
3. Exact version matching prevents plugin ecosystem growth

**Current Flow**:
```rust
pub fn load_plugin(path: &Path) -> Result<(Arc<Router<()>>, String), AxumPluginError> {
    let lib = Library::new(path)?;  // Handle created
    // ... extract symbols ...
    let router = Box::from_raw(router_ptr);
    // lib goes out of scope HERE - library may unload!
    Ok((Arc::new(*router), name))
}
```

**Implementation**:

```rust
// src/plugin/mod.rs - Update AxumPluginWrapper
pub struct AxumPluginWrapper {
    pub router: Arc<Router<()>>,
    pub name: String,
    pub library: Library,  // NEW: Keep library loaded
    pub path: PathBuf,     // For reload tracking
}

// src/plugin/axum_loader.rs - Update load_plugin
pub fn load_plugin(path: &Path) -> Result<(Arc<Router<()>>, String), AxumPluginError> {
    let lib = Library::new(path)
        .map_err(|e| AxumPluginError::LoadFailed(e.to_string()))?;

    // ... existing symbol loading ...

    // NEW: Call destroy_router if available
    if let Ok(destroy) = lib.get::<Symbol<unsafe extern "C" fn(*mut Router<()>)>>(b"destroy_router") {
        // Don't call here - we'll call on unload
        // Store for later
    }

    Ok((Arc::new(*router), name, lib))  // Include lib in return
}

// src/plugin/mod.rs - Update AxumPluginWrapper construction
impl PluginManager {
    pub fn load_axum_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        let (router, name, library) = axum_loader::load_plugin(path)?;
        let wrapper = AxumPluginWrapper {
            router,
            name: name.clone(),
            library,  // NOW STORED
            path: path.to_path_buf(),
        };
        // ... rest of loading ...
    }

    // NEW: Cleanup on unload
    pub fn unload_axum_plugin(&self, name: &str) -> Option<()> {
        let wrapper = self.axum_plugins.write().remove(name)?;
        // Call destroy_router if plugin supports it
        if let Ok(destroy) = wrapper.library.get::<...>(b"destroy_router") {
            unsafe { destroy(Arc::as_ptr(&wrapper.router) as *mut _) };
        }
        // library automatically dropped here when wrapper goes out of scope
        Some(())
    }
}
```

**Consider semantic versioning**:
```rust
// Instead of exact match:
if plugin_version != AXUM_ABI_VERSION { ... }

// Use semantic version comparison:
let plugin_ver = Version::parse(plugin_version).ok();
let host_ver = Version::parse(AXUM_ABI_VERSION).ok();
if plugin_ver.major != host_ver.major || plugin_ver.minor != host_ver.minor {
    return Err(AxumPluginError::AbiMismatch { ... });
}
// Patch version difference is OK
```

**Verification**:
```bash
cargo test --lib plugin
# Load plugin, verify library stays loaded
# Unload plugin, verify cleanup called
```

---

### 12.4.2: Header Handling Consistency

**Status**: PENDING
**Priority**: LOW
**File**: `src/http/server.rs:2740-2741`

**Issue**: Response headers are filtered via `filter_response_headers_buf()` BEFORE being passed to WASM transform. This is asymmetric with request filters which receive all headers.

**Current Response Transform Flow**:
```rust
// Line 2740-2741
let filtered_headers = filter_response_headers_buf(&resp.headers, &headers_to_filter);
let mut headers: http::HeaderMap = filtered_headers;  // Already filtered
```

**Question for Design Decision**: Should WASM response transforms see all headers (including Server, X-Powered-By) or only the filtered set?

**Option A**: Pass original headers, let WASM decide
**Option B**: Document as intentional (security through removal before plugin execution)

**Recommendation**: Document as intentional design if that's the case. Add comment explaining why.

**Implementation** (if Option A):
```rust
// Pass original headers to WASM for transforms
let wasm_resp = http::Response::builder()
    .status(status)
    .header("Server", resp.headers.get("Server").unwrap())  // Original headers
    // ... all headers ...
    .body(body.clone())

// Then apply filter_response_headers_buf AFTER transform returns
// OR have WASM plugin return filtered headers in response
```

---

## Implementation Order Recommendation

| Wave | Item | Priority | Risk | Effort |
|------|------|----------|------|--------|
| 12.1 | Security fixes (rate limit, AxumDynamic) | CRITICAL | High | Medium |
| 12.2 | Performance (guest_alloc, instantiation) | HIGH | Medium | High |
| 12.2 | Env HashMap optimization | MEDIUM | Low | Low |
| 12.3 | Response transform pooling | MEDIUM | Low | Medium |
| 12.3 | Mesh graceful degradation | MEDIUM | Medium | Medium |
| 12.3 | Autoscaler improvements | MEDIUM | Low | Medium |
| 12.4 | Native plugin stability | LOW | Medium | Medium |

---

## Verification Commands

```bash
# Build and test
cargo test --lib --no-run
cargo test --lib <test_name>
cargo test --test integration_test

# Lint and format
cargo fmt
cargo clippy -- -D warnings

# Benchmarks
cargo bench --bench bench_wasm

# Specific feature tests
cargo test --test integration_test -- serverless
cargo test --lib plugin
```

---

## Notes

1. **Experimental Feature Warning**: Native plugins (axum_loader) are experimental. Consider adding runtime detection for Rust ABI compatibility or documenting as only for development use.

2. **Breaking Changes**: The `Arc<HashMap>` change for FunctionDefinition.env is a breaking change for configuration. Add migration path.

3. **Metrics Addition**: Before implementing optimizations, add allocation metrics (`WASM_ALLOC_COUNT`, `WASM_ALLOC_BYTES`) to validate improvements.

4. **Documentation**: Each fix should update relevant documentation in `docs/PLUGINS.md` and `skills/serverless_wasm.md`.

---

## Deferred Items

The following are identified but not addressed in this plan (for future consideration):

- **WASM Plugin SDK crate**: Create `maluwaf-plugin` crate for type-safe plugin development
- **Predictive scaling**: ML-based demand prediction for autoscaling
- **Plugin signing**: Cryptographic verification of plugin authenticity
- **WASM to Axum bridging**: Allow WASM plugins to serve dynamic Axum routes

---

*Plan created: 2026-04-27*
*Reviewed: 2026-04-27*
*Status: Reviewed - Ready for implementation*