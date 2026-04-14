# Performance Optimization Patterns

This skill documents the performance optimization patterns used in the MaluWAF codebase.

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

## Wave 4 Performance Fixes (2026-04-14)

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

**Location**: `src/overseer/connection_tracker.rs:79-98`

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
