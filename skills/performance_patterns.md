# Performance Optimization Patterns

This skill documents the performance optimization patterns used in the SynVoid codebase.

## Core Principles

1. **Pre-computation over repeated computation**: Compute expensive operations once at initialization
2. **O(1) lookups over O(n) search**: Use HashSet/HashMap for exact matches
3. **Lock-free data structures**: Use atomic operations where possible
4. **Eviction-on-access over periodic cleanup**: Let caches self-manage via LRU/Moka
5. **VecDeque over Vec for queue operations**: Use `pop_front()` for O(1) removal

## Pattern Reference

### Pre-computed Lowercased Words

**Before**: Call `to_lowercase()` on every request
```rust
for word in &config.words {
    if input.to_lowercase().contains(&word.to_lowercase()) { // allocations per request
    }
}
```

**After**: Pre-compute once at initialization
```rust
struct SuspiciousWordTracker {
    words: Vec<String>,
    words_lower: Vec<String>, // pre-computed
}

impl SuspiciousWordTracker {
    fn new(config: &Config) -> Self {
        let words_lower = config.words.iter().map(|w| w.to_lowercase()).collect();
        Self { words: config.words, words_lower }
    }
    
    fn check(&self, input: &str) {
        for (word, word_lower) in self.words.iter().zip(self.words_lower.iter()) {
            if input.contains(word_lower) { // no allocation per request
            }
        }
    }
}
```

**Location**: `src/waf/probe_tracker.rs:475-513`

---

### O(1) Exact Match Lookups

**Before**: Linear search through Vec
```rust
for exact in &guard.exact_matches {
    if path == exact {
        return Some(exact.clone());
    }
}
```

**After**: HashSet for O(1) lookup
```rust
if let Some(exact) = guard.exact_matches.get(path) {
    return Some(exact.clone());
}
```

**Location**: `src/waf/endpoints.rs:135-193`

---

### VecDeque for Queue Operations

**Before**: `Vec::remove(0)` is O(n)
```rust
if pending_announces.len() >= MAX {
    pending_announces.remove(0); // shifts all elements
}
pending_announces.push(record);
```

**After**: `VecDeque::pop_front()` is O(1)
```rust
if pending_announces.len() >= MAX {
    pending_announces.pop_front(); // no shift
}
pending_announces.push_back(record);
```

**Location**: `src/mesh/dht/record_store.rs:208`

---

### Postcard over JSON Serialization

**Before**: JSON serialization for distributed state
```rust
let value = serde_json::json!({ "id": 1, "data": "foo" });
let bytes = serde_json::to_vec(&value)?; // High overhead
```

**After**: Postcard with typed structs
```rust
#[derive(Serialize, Archive, RkyvSerialize, RkyvDeserialize)]
struct MyRecord { id: u32, data: String }
let bytes = crate::serialization::serialize(&MyRecord { id: 1, data: "foo".into() })?; // Stable, efficient
```

**Benefits**:
- **30-50% smaller payloads** (important for DHT/Mesh)
- **Faster serialization/deserialization** (postcard vs string-based JSON)
- **Zero-copy support** via `rkyv` for read-only access in high-performance paths

**Location**: `src/mesh/dht/record_store_dns.rs`, `src/mesh/dht/record_store_crud.rs`

---

### u64 Unix Timestamps over Instant

**Before**: `Instant` for persisted state
```rust
struct PeerState {
    last_seen: Instant, // Cannot be serialized or compared across reloads
}
```

**After**: `u64` Unix timestamps
```rust
struct PeerState {
    last_seen: u64, // Stable, serializable, comparable across processes
}

// In code:
let now = crate::mesh::safe_unix_timestamp();
let idle_secs = now.saturating_sub(state.last_seen);
```

**Benefits**:
- **Serializable**: `Instant` has no stable binary format across reloads/reboots
- **Consistent**: Comparisons are reliable across different processes via safe_unix_timestamp()
- **Memory**: `u64` is smaller and faster to compare than `Instant` wrapper

**Location**: `src/mesh/topology/types.rs`, `src/mesh/dht/mod.rs`

---

### Lock-Free Rate Limiting

**Before**: Mutex-protected HashSet with retain
```rust
let mut slots = self.dirty_slots.lock().unwrap();
slots.retain(|_, v| now.duration_since(*v) < self.window);
```

**After**: Atomic bitset with fetch_or
```rust
// Atomic operations - no locks
self.dirty_slots.fetch_or(1 << slot, Ordering::Relaxed);
let was_dirty = (self.dirty_slots.swap(0, Ordering::Relaxed) & (1 << slot)) != 0;
```

**Location**: `src/waf/ratelimit/core.rs`

---

### Moka Cache for Bounded Caches

**Before**: Unbounded DashMap
```rust
let client_cache = Arc::new(DashMap::new());
```

**After**: Moka with max_capacity
```rust
let client_cache = Arc::new(moka::sync::Cache::new(moka::sync::Cache::builder()
    .max_capacity(100)
    .build()));
```

**Location**: `src/http_client/mod.rs:34-41`

**Important**: When using Moka with weighted entries (via `weigher` callback) AND time-to-live expiration, `entry_count()` may return 0 even when entries exist. Use `iter().count()` instead for accurate count, or `weighted_size()` for the total weight.

---

### Direct Entry Return for SWR Cache

**Before**: Insert then get (redundant lock)
```rust
self.entries.insert(key.clone(), updated_inner);
return self.entries.get(key).map(|i| i.entry.clone());
```

**After**: Return entry directly from entry API
```rust
return Some(
    self.entries
        .entry(key.clone())
        .or_insert(updated_inner)
        .into_value()
        .entry,
);
```

**Location**: `src/proxy_cache/store.rs:240-255`

---

### Cow<str> for Zero-Copy Lowercasing

**Before**: Allocate String on every call
```rust
let lower = input.to_lowercase();
```

**After**: Use Cow for conditional allocation
```rust
let lower: Cow<str> = if input.bytes().any(|b| b.is_ascii_uppercase()) {
    Cow::Owned(input.to_lowercase())
} else {
    Cow::Borrowed(input)
};
```

**Location**: `src/waf/attack_detection/ssrf.rs:356-361`

---

### CSRF Token Bounded Storage

**Before**: Unbounded insert
```rust
csrf_tokens.write().insert(token, data);
```

**After**: Bounded with oldest removal
```rust
const MAX_CSRF_TOKENS_PER_SESSION: usize = 10;

fn generate_csrf_token(&self, session_id: String) -> String {
    let mut tokens = self.csrf_tokens.write();
    let count = tokens.iter().filter(|(_, v)| v.session_id == session_id).count();
    if count >= MAX_CSRF_TOKENS_PER_SESSION {
        // Remove oldest tokens to make room
        let mut to_remove: Vec<_> = tokens
            .iter()
            .filter(|(_, v)| v.session_id == session_id)
            .map(|(k, v)| (k.clone(), v.created))
            .collect();
        to_remove.sort_by_key(|(_, created)| *created);
        for (key, _) in to_remove.into_iter().take(count - MAX_CSRF_TOKENS_PER_SESSION + 1) {
            tokens.remove(&key);
        }
    }
    tokens.insert(token, data);
}
```

**Location**: `src/admin/state.rs:633-657`

---

### Shared InputNormalizer with Optional Arc

**Before**: Create new normalizer on every call
```rust
pub fn detect(input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
    let normalized = InputNormalizer::new().normalize(std::str::from_utf8(input).unwrap_or(""));
    // ...
}
```

**After**: Accept shared Arc normalizer, with fallback for backward compatibility
```rust
pub fn detect(
    input: &[u8],
    location: InputLocation,
    normalizer: Option<&InputNormalizer>,
) -> Option<AttackDetectionResult> {
    let normalized = if let Some(n) = normalizer {
        n.normalize(std::str::from_utf8(input).unwrap_or(""))
    } else {
        InputNormalizer::new().normalize(std::str::from_utf8(input).unwrap_or(""))
    };
    // ...
}
```

**Location**: `src/waf/attack_detection/sqli.rs`, `xss.rs`

---

### Batch Lock Acquisition Pattern

**Before**: N+1 lock acquisitions in loop
```rust
let app_servers = heartbeat_state.app_servers.read().await;
for (site_id, supervisor) in app_servers.iter() {
    let mut ipc = heartbeat_state.ipc.lock().await; // Lock acquired N times
    ipc.send(&Message::AppServerHealth { ... }).await;
}
```

**After**: Collect data first (read-only), then single lock for batch send
```rust
let app_health: Vec<(String, bool)> = {
    let app_servers = heartbeat_state.app_servers.read().await;
    app_servers
        .iter()
        .map(|(site_id, supervisor)| (site_id.clone(), supervisor.is_healthy()))
        .collect()
};

let mut ipc = heartbeat_state.ipc.lock().await;
for (site_id, healthy) in app_health {
    ipc.send(&Message::AppServerHealth { ... }).await;
}
```

**Location**: `src/worker/unified_server.rs:1087-1098`

---

## Testing Performance Changes

```bash
# Verify compilation
cargo clippy --lib -- -D warnings

# Run integration tests
cargo test --test integration_test

# Profile specific functionality
cargo bench --bench bench_waf_detection
```

## Common Pitfalls

1. **Don't wrap moka::Cache in Mutex/RwLock** - moka is already thread-safe
2. **Use `checked_sub` for atomic counter decrement** - prevents underflow
3. **Prefer single-shard operations** - over full iteration in sharded stores
4. **Use `std::time::Instant`** - for timeout comparisons, not `Duration::from_secs`

---

## Performance Fixes

### Cache Invalidation with Secondary Index

**Location**: `src/proxy_cache/store.rs:451-511`

**Issue**: `invalidate_by_host()` scanned all entries - O(n).

**Pattern**: Maintain secondary index for O(1) host lookups:
```rust
pub struct ProxyCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    by_host: RwLock<HashMap<Host, Vec<CacheKey>>>,  // Secondary index
}

impl ProxyCache {
    pub fn insert(&self, key: CacheKey, entry: CacheEntry) {
        // ... insert into main map ...
        self.by_host.write().entry(entry.host.clone())
            .or_insert_with(Vec::new)
            .push(key);
    }
    
    pub fn invalidate_by_host(&self, host: &str) {
        if let Some(keys) = self.by_host.write().remove(host) {
            for key in keys {
                self.entries.write().remove(&key);
            }
        }
    }
}
```

---

### Concurrent HTTP Proxy with First-Success-Wins

**Location**: `src/mesh/proxy.rs:785-853`

**Issue**: Serial provider requests - waited for each to fail before trying next.

**Pattern**: Fire all concurrently, race to first success:
```rust
async fn proxy_to_peer_with_fallback(
    &self,
    providers: Vec<PeerProvider>,
    request: Request,
) -> Result<Response, ProxyError> {
    let (tx, mut rx) = mpsc::channel(providers.len());
    
    for provider in providers {
        let tx = tx.clone();
        tokio::spawn(async move {
            match provider.proxy_request(request.clone()).await {
                Ok(resp) => let _ = tx.send(Ok(resp)).await,
                Err(e) => let _ = tx.send(Err(e)).await,
            }
        });
    }
    drop(tx);  // Drop original sender
    
    // First success wins
    rx.recv().await.unwrap_or_else(|| Err(ProxyError::NoProviders))
}
```

---

### Mesh Broadcast Bounded Concurrency

**Location**: `src/worker/unified_server.rs:729-740`

**Issue**: Unbounded `tokio::spawn()` for every broadcast - could exhaust resources.

**Pattern**: Semaphore for backpressure:
```rust
const MAX_CONCURRENT_BROADCASTS: usize = 10;

pub struct UnifiedServerWorkerState {
    broadcast_semaphore: Arc<Semaphore>,
}

async fn broadcast_to_mesh(&self, message: MeshMessage) {
    let permit = self.broadcast_semaphore
        .acquire()
        .await
        .expect("semaphore closed");
    
    let _permit = permit;  // Held until drop
    
    // Perform broadcast
    self.mesh.broadcast(message).await;
}
```

---

### Background Cleanup for Unbounded Trackers

**Location**: `src/mesh/topology.rs:1528-1543`

**Issue**: `cleanup_stale_metrics()` defined but never called.

**Pattern**: Spawn background task with periodic cleanup:
```rust
pub fn start_background_tasks(&self) {
    let topology = self.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            topology.cleanup_stale_metrics(10000);
        }
    });
}
```

---

### Metrics Bounded with LRU Eviction

**Location**: `src/metrics/mod.rs:900`

**Issue**: `per_site` HashMap grew unbounded.

**Pattern**: Max capacity with eviction:
```rust
const MAX_PER_SITE_ENTRIES: usize = 10000;

struct SiteMetricsCollector {
    per_site: Mutex<HashMap<String, SiteMetrics>>,
}

impl SiteMetricsCollector {
    fn record_request(&self, site: &str) {
        let mut sites = self.per_site.lock();
        
        // Evict if at capacity
        if sites.len() >= MAX_PER_SITE_ENTRIES && !sites.contains_key(site) {
            // Remove least recently used entry
            if let Some(oldest) = /* find LRU entry */ {
                sites.remove(&oldest);
            }
        }
        
        sites.entry(site.to_string()).or_insert_with(SiteMetrics::new);
    }
}
```

---

### Threat Intel Indicators Bounded with VecDeque

**Location**: `src/mesh/threat_intel.rs:153-154`

**Issue**: `pending_announces` Vec grew unbounded.

**Pattern**: VecDeque with max size:
```rust
const MAX_PENDING_INDICATORS: usize = 10000;

struct ThreatIntelState {
    pending_announces: Mutex<VecDeque<ThreatIndicator>>,
}

impl ThreatIntelState {
    fn add_pending_indicator(&self, indicator: ThreatIndicator) {
        let mut pending = self.pending_announces.lock();
        if pending.len() >= MAX_PENDING_INDICATORS {
            pending.pop_front();  // Remove oldest
        }
        pending.push_back(indicator);
    }
}
```

---

### YARA Submissions TTL Cleanup

**Location**: `src/mesh/yara_rules.rs:235-236`

**Issue**: `submissions` HashMaps never cleaned up.

**Pattern**: Background task with TTL:
```rust
const SUBMISSION_TTL_SECS: u64 = 7 * 24 * 3600;  // 7 days
const MAX_SUBMISSIONS: usize = 1000;

pub fn cleanup_expired_submissions(&self) {
    let now = Instant::now();
    let mut submissions = self.submissions.write();
    let mut expired = Vec::new();
    
    for (id, submission) in submissions.iter() {
        if now.duration_since(submission.timestamp) > Duration::from_secs(SUBMISSION_TTL_SECS) {
            expired.push(id.clone());
        }
    }
    
    for id in expired {
        submissions.remove(&id);
    }
    
    // Also enforce size limit
    while submissions.len() > MAX_SUBMISSIONS {
        if let Some(oldest) = submissions.iter()
            .min_by_key(|(_, s)| s.timestamp)
            .map(|(k, _)| k.clone())
        {
            submissions.remove(&oldest);
        }
    }
}
```

---

### NonceCache O(log n) Eviction

**Location**: `src/process/ipc_signed.rs:40-55`

**Issue**: `evict_oldest()` was O(n) with Vec.

**Pattern**: HashMap + BTreeMap for O(log n):
```rust
use std::collections::{HashMap, BTreeSet};

struct NonceEntry {
    nonce: String,
    timestamp: Instant,
    node_id: Option<String>,
}

struct NonceCache {
    by_nonce: HashMap<String, NonceEntry>,
    by_time: BTreeSet<(Instant, String)>,  // (timestamp, nonce)
}

impl NonceCache {
    fn evict_oldest(&mut self) {
        if let Some((oldest_time, oldest_nonce)) = self.by_time.iter().next() {
            self.by_time.remove(&(*oldest_time, oldest_nonce.clone()));
            self.by_nonce.remove(&oldest_nonce);
        }
    }
}
```

---

### Atomic Connection Tracker Updates

**Location**: `src/overseer/connection_tracker.rs:79-98` (legacy code, Supervisor uses `src/process/manager.rs` instead)

**Issue**: Non-atomic update of worker counts and totals.

**Pattern**: Atomic delta updates:
```rust
impl ConnectionTracker {
    fn update_worker_connections(&self, worker_id: &str, delta: i32) {
        let mut workers = self.workers.write();
        let entry = workers.entry(worker_id.to_string()).or_insert(0i32);
        *entry = entry.saturating_add(delta);  // Atomic-like with interior mutability

        // Update total atomically
        self.total_connections.fetch_add(delta, Ordering::Relaxed);
    }
}
```

---

## Performance & Observability

### HTTP Request Latency Tracking

**Location**: `src/metrics/mod.rs:70-71,372-382`, `src/http/server.rs:2652`

**Issue**: No HTTP request latency metrics for observability.

**Pattern**: VecDeque-based latency histogram:
```rust
static HTTP_REQUEST_LATENCIES: LazyLock<Mutex<VecDeque<u64>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

const LATENCY_SAMPLE_SIZE: usize = 1000;

pub fn record_http_request_latency(latency_ms: u64) {
    let mut latencies = HTTP_REQUEST_LATENCIES.lock();
    if latencies.len() >= LATENCY_SAMPLE_SIZE {
        latencies.pop_front();  // O(1) removal from front
    }
    latencies.push_back(latency_ms);
}

pub fn get_http_request_latencies() -> Vec<u64> {
    HTTP_REQUEST_LATENCIES.lock().iter().copied().collect()
}
```

**Recording point**: Called in HTTP server at request completion.

---

### WAF Stall/Tarpit Concurrency Safety (Wave P1)

**Location**: `src/http/server.rs:1522-1544`, `src/tls/server.rs:859-878`, `src/http3/server.rs:377-387`

**Issue**: At high traffic, unbounded stalled requests could consume worker tasks/connections and become a resource-exhaustion amplifier.

**Pattern**: Bounded stall concurrency with metrics:
```rust
// Config: max_stalled_requests (default 100)
let current_stalled = crate::metrics::get_active_stalled_requests();
if current_stalled >= http_config.max_stalled_requests as u64 {
    crate::metrics::record_stall_rejected();
    return Ok(build_response(429, "Too many requests", "text/plain"));
}
crate::metrics::record_stall_start();

// ... stall handling ...

crate::metrics::record_stall_end(); // On timeout
```

**Metrics added** (`src/metrics/collection.rs`):
- `ACTIVE_STALLED_REQUESTS` - current stalled request count
- `STALL_REJECTED_CONCURRENCY_CAP` - rejected due to cap
- `STALL_TIMEOUTS` - completed stall timeouts

**Behavior**:
- When stall cap reached, returns 429 instead of stalling
- Prevents unbounded sleeping tasks at high traffic
- Protects against resource exhaustion amplification attacks

---

### Global Node Liveness Monitoring

**Location**: `src/metrics/mod.rs:87-89,535-549`, `src/mesh/topology.rs:1559-1617`

**Issue**: Global node heartbeats exist but no alerting when quorum goes offline.

**Pattern**: Periodic liveness check with quorum loss detection:
```rust
static GLOBAL_NODE_LIVENESS_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static GLOBAL_NODE_QUORUM_LOST_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub async fn check_global_node_liveness(&self) {
    let heartbeat_ttl: u64 = 90;  // Must match heartbeat TTL
    let mut live_count: u64 = 0;

    let heartbeat_records = record_store.get_by_prefix("global_node_heartbeat:");
    for record in heartbeat_records {
        if let Ok(heartbeat) = serde_json::from_slice::<GlobalNodeHeartbeat>(&record.value) {
            let age = now.saturating_sub(heartbeat.timestamp);
            if age <= heartbeat_ttl {
                live_count += 1;
            }
        }
    }

    record_global_node_liveness_count(live_count);

    // Warn if quorum lost
    let expected = self.config.connection.reconnection_priority.global_nodes;
    if expected > 0 && live_count < expected as u64 {
        let previously_live = get_global_node_liveness_count();
        if previously_live > 0 && previously_live >= expected as u64 && live_count < previously_live {
            tracing::warn!(
                "Global node quorum potentially lost: expected={} alive={}",
                expected, live_count
            );
            record_global_node_quorum_lost();
        }
    }
}
```

**Background task**: Runs every 60 seconds via `start_background_tasks()`.

---

### IPv6 Zone ID SSRF Rejection

**Location**: `src/waf/attack_detection/ssrf.rs:260-273`

**Issue**: Zone IDs (`%eth0`, `%1`) were stripped before analysis, potentially bypassing localhost detection.

**Pattern**: Reject inputs containing zone IDs:
```rust
fn has_ipv6_zone_id(input: &str) -> bool {
    input.contains('%')
}

fn contains_private_ip_or_localhost(input: &str) -> bool {
    let input_lower: Cow<str> = /* ... */;

    // Reject zone IDs - they should not appear in legitimate URLs
    if Self::has_ipv6_zone_id(&input_lower) {
        return true;
    }

    // ... rest of checks
}
```

**Why rejection over stripping**: Zone IDs are Linux-specific interface specifiers that shouldn't appear in URLs applications process. Allowing them creates an obfuscation vector.

---

### ACME Config Validation

**Location**: `src/config/tls.rs:106-151`

**Issue**: No validation that cache_dir is writable; no warning for terms_of_service_agreed=false.

**Pattern**: Validate at startup with helpful error messages:
```rust
impl AcmeConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.email.is_none() {
            return Err(ConfigValidationError { field: "tls.acme.email".to_string(), message: "ACME enabled but no email provided".to_string() });
        }
        if self.domains.is_empty() {
            return Err(ConfigValidationError { field: "tls.acme.domains".to_string(), message: "ACME enabled but no domains specified".to_string() });
        }

        // Validate cache_dir is writable
        if let Some(ref cache_dir) = self.cache_dir {
            let path = std::path::Path::new(cache_dir);
            if !path.exists() {
                std::fs::create_dir_all(path).map_err(|e| ConfigValidationError {
                    field: "tls.acme.cache_dir".to_string(),
                    message: format!("Could not create cache_dir: {}", e),
                })?;
            }
            // Write test file
            let test_file = path.join(".synvoid_acme_write_test");
            std::fs::write(&test_file, b"").map_err(|e| ConfigValidationError {
                field: "tls.acme.cache_dir".to_string(),
                message: format!("cache_dir is not writable: {}", e),
            })?;
            let _ = std::fs::remove_file(&test_file);
        }

        // Warn if ToS not agreed
        if self.enabled && !self.terms_of_service_agreed {
            tracing::warn!("ACME is enabled but terms_of_service_agreed is false. Set to true after reviewing ACME terms of service.");
        }
            Ok(())
        }
    }
}
```

---

## Performance & Security Fixes

### HotHashMap Type Alias

**Location**: `src/utils.rs`

**Issue**: SipHash (std HashMap) is 3-5x slower than Ahash for non-cryptographic workloads.

**Pattern**: Create a type alias for hot path HashMaps:
```rust
use ahash::AHashMap;
pub type HotHashMap<K, V> = AHashMap<K, V>;
pub mod collections {
    pub use ahash::{AHashMap, AHashSet};
}
```

**Files migrated**:
- `src/waf/ratelimit/core.rs` - dirty_slots tracking
- `src/proxy_cache/store.rs` - host index
- `src/block_store.rs` - IP blocking storage
- `src/http/server.rs` - app_servers and WASM transforms

---

### Cow<str> for Zero-Copy HTTP Parsing

**Location**: `src/http/server.rs:777-792`

**Issue**: 3 heap allocations per request for path, host, user_agent.

**Pattern**: Use `Cow<'_, str>` to avoid allocations when possible:
```rust
use std::borrow::Cow;

let path = parts
    .uri
    .path_and_query()
    .map(|pq| Cow::Owned(pq.to_string()))
    .unwrap_or_else(|| Cow::Borrowed("/"));

let host = parts
    .headers
    .get("host")
    .and_then(|v| v.to_str().ok())
    .map(Cow::Borrowed)
    .unwrap_or_else(|| Cow::Borrowed(""));

let user_agent = parts
    .headers
    .get("user-agent")
    .and_then(|v| v.to_str().ok())
    .map(|s| Cow::Owned(s.to_string()));
```

---

### Power-of-2 Bitmask Optimization

**Location**: `src/utils.rs:481-513`

**Issue**: Modulo operation is slow; bitmask is ~10x faster for power-of-2 slot counts.

**Pattern**: Use bitmask only when `num_slots.is_power_of_two()`:
```rust
pub fn ip_to_slot(ip: IpAddr, num_slots: usize) -> usize {
    if num_slots.is_power_of_two() {
        let mask = num_slots - 1;
        // Use & mask instead of % num_slots
    } else {
        // Fallback to modulo for non-power-of-2
    }
}
```

---

### Shared NormalizedInputs for WAF Detectors

**Location**: `src/waf/attack_detection/mod.rs:202-212`

**Issue**: sqli, xss, ssti detectors each iterated over headers independently (3 iterations).

**Pattern**: Parse headers once via `NormalizedInputs::normalize_all()` before any detector checks:
```rust
// At start of check_request()
let inputs = NormalizedInputs::normalize_all(&headers, &path, &query, &body);

// All 11 detectors now share the same pre-normalized inputs
let sqli_result = detector.check_sqli(&inputs, ...);
let xss_result = detector.check_xss(&inputs, ...);
```

---

### InstancePool Shared WasmRuntime

**Location**: `src/serverless/instance_pool.rs`

**Issue**: Each `spawn_instance()` created new `WasmPluginManager` → unbounded memory.

**Pattern**: Share `Arc<WasmRuntime>` across all instances:
```rust
pub struct InstancePool {
    // ...
    runtime: Arc<WasmRuntime>,
}

impl InstancePool {
    pub fn new(config: InstancePoolConfig, function_definition: FunctionDefinition) -> Result<Self, InstancePoolError> {
        let runtime = Arc::new(crate::plugin::WasmPluginManager::new());
        Ok(Self { runtime, ... })
    }

    fn spawn_instance(&self, id: String) -> Result<Arc<ServerlessInstance>, InstancePoolError> {
        let runtime = self.runtime.clone();
        // Pass cloned runtime to instance
        let instance = Arc::new(ServerlessInstance::new(id, name, runtime));
        Ok(instance)
    }
}
```

---

## Metrics Module Split (W1.1)

**Location**: `src/metrics/mod.rs` → `src/metrics/payloads.rs` + `src/metrics/collection.rs`

**Issue**: "God module" at ~2000+ lines with complex trait bounds.

**Pattern**: Split into focused modules:
```rust
// src/metrics/mod.rs - re-exports for backward compatibility
pub mod bandwidth;
pub use bandwidth::{BandwidthTracker, BandwidthPayload, BandwidthProtocol, EgressDirection};
pub use payloads::*;  // Re-export all payload structs
pub use collection::*; // Re-export collection functions

// src/metrics/payloads.rs - pure data structures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerMetricsPayload { ... }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteMetricsPayload { ... }

// src/metrics/collection.rs - atomic counter collections
pub struct MetricsCollector { ... }

impl MetricsCollector {
    pub fn record_waf_check(&self, site_id: &str, result: &AttackDetectionResult) { ... }
    pub fn record_request_latency(&self, site_id: &str, latency_ms: u64) { ... }
}
```

**Verification**:
```bash
cargo test --lib --no-run  # Verify all re-exports work
cargo clippy --lib -- -D warnings  # No new warnings
```

---

## DNS Zone Store O(k) Suffix Lookup

**Location**: `src/dns/server/sharded_store.rs`, `src/dns/server/query.rs`

**Issue**: DNSSEC NODATA/NXDOMAIN checks used O(n) `find()` iterating all 64 shards.

**Pattern**: Use suffix index for O(k) lookup + filter:
```rust
// Instead of O(n) full scan:
ctx.zones.find(|origin, zone| {
    let origin_lower = origin.to_lowercase();  // Allocation per zone!
    (qname_lower.ends_with(&origin_lower) || qname_lower == origin_lower)
        && (zone.nsec_enabled || zone.nsec3_enabled)
        && Self::is_nodata(zone, &qname, record_type)
})

// Use O(k) suffix index + inline filter:
ctx.zones.find_by_suffix_with_filter(&qname, |zone| {
    (zone.nsec_enabled || zone.nsec3_enabled)
        && Self::is_nodata(zone, &qname, record_type)
})
```

**New API**:
```rust
pub fn find_by_suffix(&self, qname: &str) -> Option<Zone>
pub fn find_by_suffix_with_filter<P: Fn(&Zone) -> bool>(
    &self,
    qname: &str,
    filter: P,
) -> Option<Zone>
```

The suffix index is pre-built at `rebuild_suffix_index()` during zone insert/remove. For DNSSEC validation where you need longest-match suffix plus zone flags, `find_by_suffix_with_filter` provides O(k) instead of O(n) lookup.

---

## TLS Response Header Filtering

**Location**: `src/tls/server.rs:1405-1406,1551-1552`

**Issue**: `filter_response_headers()` allocates a new `Vec` on every proxied HTTPS response.

**Pattern**: Use `filter_response_headers_buf` with pre-allocated buffer:
```rust
// BEFORE: allocates Vec on every response
let filtered_headers = filter_response_headers(&parts.headers, &headers_to_filter);

// AFTER: reuses pre-allocated buffer
let mut filtered_headers_buf = Vec::new();
filter_response_headers_buf(&parts.headers, &headers_to_filter, &mut filtered_headers_buf);
for (key, value) in filtered_headers_buf.drain(..) {
    builder = builder.header(&key, &value);
}
```

The buffer is cleared and reused on each call, avoiding per-response heap allocation in the hot path.

---

## Async Retry with Correct Boundary

**Location**: `src/proxy/mod.rs:860,886,906`

**Issue**: Retry loop used `attempt <= max_retries` but incremented attempt before check, causing max_retries+1 attempts.

**Pattern**: Use `<` not `<=`:
```rust
// BEFORE (off-by-one): runs max_retries+1 times
while attempt <= max_retries {
    attempt += 1;
    // ...
}

// AFTER (correct): runs exactly max_retries times
while attempt < max_retries {
    attempt += 1;
    // ...
}
```

---

## BytesMut for Body Collection

**Location**: `src/http/shared_handler.rs`

**Issue**: Using `Vec<u8>` for body accumulation causes reallocations for large uploads.

**Pattern**: Use `BytesMut` which has better growth strategy:
```rust
use bytes::BytesMut;

// Before
let mut accumulated = Vec::new();
accumulated.reserve(content_length.unwrap_or(0));
// ... extend from slices

// After
let mut accumulated = BytesMut::new();
if let Some(cl) = content_length {
    accumulated.reserve(cl);
}
// ... extend works the same
Bytes::from(accumulated.freeze())  // O(1) conversion
```

---

## DHT RoutingTable LRU Cache

**Location**: `src/mesh/dht/routing/table.rs`

**Issue**: `find_closest` was O(k * bucket_count) with repeated bucket iteration.

**Pattern**: Moka-based LRU cache for O(1) hot path lookups:
```rust
const ROUTING_CACHE_SIZE: u64 = 1000;
const ROUTING_CACHE_TTL: Duration = Duration::from_secs(60);

pub struct RoutingTable {
    // ...
    closest_cache: Cache<u64, Vec<PeerContact>>,
}

impl RoutingTable {
    pub fn new(local_node_id: NodeId, local_node_id_string: String) -> Self {
        let closest_cache = Cache::builder()
            .max_capacity(ROUTING_CACHE_SIZE)
            .time_to_live(ROUTING_CACHE_TTL)
            .build();
        // ...
    }

    pub fn find_closest(&self, target: &NodeId, k: usize) -> Vec<PeerContact> {
        let cache_key = Self::cache_key(target);

        if let Some(cached) = self.closest_cache.get(&cache_key) {
            let mut result = cached.clone();
            result.truncate(k);
            return result;
        }

        // ... existing O(k * bucket_count) logic ...

        self.closest_cache.insert(cache_key, result.clone());
        result
    }

    fn cache_key(target: &NodeId) -> u64 {
        let bytes = target.as_bytes();
        u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}
```

**Cache Invalidation**: Invalidate on peer insert/remove:
```rust
fn try_insert(&mut self, peer: PeerContact) -> Result<Option<PeerContact>, InsertError> {
    // ... existing logic ...
    match bucket.insert(peer) {
        Ok(evicted) => {
            self.closest_cache.invalidate_all();
            Ok(evicted)
        }
        Err(_) => Ok(None),
    }
}

fn remove(&mut self, node_id: &NodeId) -> Option<PeerContact> {
    let removed = /* ... */;
    if removed.is_some() {
        self.closest_cache.invalidate_all();
    }
    removed
}
```

---

## QUIC Stream Pooling

**Location**: `src/tunnel/quic/client.rs`

**Issue**: Opening/closing QUIC streams per message adds latency overhead.

**Pattern**: Reuse streams via pool:
```rust
const MAX_STREAM_POOL_SIZE: usize = 8;

pub(crate) struct StreamPool {
    streams: Vec<(SendStream, RecvStream)>,
    connection: Option<Connection>,
    max_size: usize,
}

impl StreamPool {
    fn new(connection: Option<Connection>) -> Self {
        Self {
            streams: Vec::new(),
            connection,
            max_size: MAX_STREAM_POOL_SIZE,
        }
    }

    async fn acquire(
        &mut self,
    ) -> Result<(SendStream, RecvStream), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(stream) = self.streams.pop() {
            return Ok(stream);
        }

        let connection = self.connection.as_ref().ok_or("No connection available")?;
        connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e).into())
    }

    fn release(&mut self, stream: (SendStream, RecvStream)) {
        if self.streams.len() < self.max_size {
            self.streams.push(stream);
        }
        // Connection handle dropped if pool is full - stream closes naturally
    }
}
```

**Usage in MeshPeerConnection**:
```rust
let mut stream_pool = self.stream_pool.lock().await;
let (send, recv) = stream_pool.acquire().await?;
let result = /* use streams */;
stream_pool.release((send, recv));
```

---

## Lock-Free Buffer Pool (Treiber Stack + TLS Cache)

For high-throughput HTTP proxying at 1000K+ RPS, buffer allocation becomes a bottleneck. The lock-free buffer pool minimizes contention.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Thread 1                                 │
│  ┌─────────────┐    ┌──────────────────────────────────┐   │
│  │ TLS Cache   │───▶│ 16 slots per tier                │   │
│  │ (hot path)  │    │ No atomics needed                │   │
│  └─────────────┘    └──────────────────────────────────┘   │
│         │                                                      │
│         │ (if full)                                            │
│         ▼                                                      │
│  ┌─────────────┐    ┌──────────────────────────────────┐   │
│  │ Global Pool │───▶│  Treiber Stack (lock-free)       │   │
│  │             │    │  compare_exchange on AtomicPtr    │   │
│  └─────────────┘    └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Treiber Stack Implementation

```rust
struct TreiberStack {
    head: AtomicPtr<StackNode>,
    len: AtomicUsize,
}

struct StackNode {
    buf: BytesMut,
    next: *mut StackNode,
}

impl TreiberStack {
    fn push(&self, buf: BytesMut) {
        let node = Box::into_raw(Box::new(StackNode {
            buf,
            next: std::ptr::null_mut(),
        }));

        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            unsafe { (*node).next = head; }
            match self.head.compare_exchange_weak(
                head,
                node,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.len.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(h) => head = h,
            }
        }
    }

    fn pop(&self) -> Option<BytesMut> {
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            if head.is_null() { return None; }
            match self.head.compare_exchange_weak(
                head,
                unsafe { (*head).next },
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.len.fetch_sub(1, Ordering::Relaxed);
                    let node = unsafe { Box::from_raw(head) };
                    return Some(node.buf);
                }
                Err(h) => head = h,
            }
        }
    }
}
```

### Hot Path Optimization

**Acquire (fast path)**:
```rust
fn acquire_inner(&self, size: usize) -> PooledBuf {
    // Check TLS cache first (zero atomics)
    let tls_result = TLS_CACHE.with(|cache| {
        if let Some(buf) = cache.pop(tier) {
            let mut buf = buf;
            buf.resize(size, 0);
            self.metrics.record_acquire(tier, true);
            return Some(PooledBuf { buf: Some(buf), tier, requested_size: size });
        }
        None
    });

    if let Some(buf) = tls_result {
        return buf;
    }

    // Fall through to global Treiber stack
    let (buf, tier) = shard.tier.arena.acquire(size);
    // ...
}
```

**Release (fast path)**:
```rust
impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            TLS_CACHE.with(|cache| {
                // Push to TLS first (no atomics)
                if cache.len(self.tier) < TLS_CACHE_SIZE {
                    cache.push(buf, self.tier);
                } else {
                    // Drain TLS to global when full
                    POOL.with(|pool| pool.release_to_global(buf, self.tier));
                }
            });
        }
    }
}
```

### Key Benefits

1. **TLS cache hit**: ~2 pointer indirections, zero atomic operations
2. **Global pool access**: Only when TLS is full, uses lock-free CAS
3. **Reduced contention**: Different threads rarely hit same shard
4. **Memory locality**: Threads tend to reuse their own buffers

### Location

`src/buffer/pool.rs:75-165` (TreiberStack)
`src/buffer/pool.rs:187-264` (ThreadLocalCache)
`src/buffer/pool.rs:385-435` (acquire_inner with TLS fast path)
