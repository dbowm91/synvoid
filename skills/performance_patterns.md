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
