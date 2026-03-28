# DHT System Improvements Plan (Phase 2)

This plan documents improvements to the DHT/Kademlia system based on code review findings.

## Priority 1: Valid Issues Requiring Fixes

### 1.1 Unbounded PoW Nonce Search Loop (EXISTING - HIGH PRIORITY)

**Location:** `src/mesh/dht/routing/node_id.rs:138-154`

**Issue:** The `find_pow_nonce` function iterates from 0 to u64::MAX with no iteration limit.

**Status:** Already documented in `plan_dht.md` - still valid.

---

## Priority 2: Testing Gaps

### 2.1 Missing Integration Tests for DHT Bootstrap and Lookups

**Location:** `src/mesh/dht/routing/`

**Problem:** No integration tests exist for:
- Iterative FindNode algorithm
- Regional hub failover
- Concurrent record writes achieving quorum

**Files to add tests:**
- `src/mesh/dht/routing/table.rs` - add integration tests for bucket operations
- `src/mesh/dht/routing/query.rs` - add integration tests for lookup
- `tests/dht_test.rs` (new) - architecture-level DHT tests

**Implementation:**

```rust
// Example: tests/dht_test.rs
#[test]
fn test_iterative_find_node() {
    // Setup 3 nodes with known distances
    // Execute iterative find node
    // Verify closest peers returned
}

#[test]
fn test_regional_hub_failover() {
    // Setup regional hub
    // Mark hub offline
    // Verify fallback to next-best regional peer
}

#[test]
fn test_write_quorum() {
    // Spawn 11 replicas
    // Write record to all
    // Verify quorum achieved
}
```

**Effort:** Medium - requires test infrastructure setup

---

### 2.2 Missing Unit Tests for Regional Hub Selection

**Location:** `src/mesh/dht/routing/regional_hubs.rs`

**Problem:** `meets_reputation_threshold()` logic at lines 222-236 has no unit tests:
- Global nodes always pass
- Trusted nodes pass threshold >= 30
- Non-global/non-trusted nodes require threshold < 30

**Implementation:** Add tests to existing test module in `regional_hubs.rs:425-478`

**Effort:** Low

---

## Priority 3: Code Quality Improvements

### 3.1 Bucket Split Never Invoked

**Location:** `src/mesh/dht/routing/table.rs:448-477`

**Problem:** `split_bucket()` function exists but is never called. In standard Kademlia, buckets split when they reach K-size with peers sharing the same prefix bit.

**Current behavior:** With 256 fixed buckets and K=20, the routing table cannot dynamically adjust to network size.

**Recommendation:** Document the design decision, OR implement bucket splitting if needed for larger networks.

**If implementing:**
```rust
// In RoutingTable::insert(), after bucket is full:
if bucket.is_full() && bucket.index < BUCKET_COUNT - 1 {
    // Check if bucket contains peers with differing prefix bits
    // If so, split the bucket
    self.split_bucket(bucket_index);
}
```

**Effort:** Medium - requires careful testing

---

### 3.2 PoW Not Persisted with Routing Table

**Location:** `src/mesh/dht/routing/table.rs:539-570`

**Problem:** `from_persisted()` restores contacts but doesn't re-verify PoW. A malicious actor could modify persisted state to insert peers without valid PoW.

**Current code:**
```rust
pub fn from_persisted(data: PersistedRoutingTable, local_node_id: NodeId) -> Self {
    // ... restores contacts without PoW verification
}
```

**Recommendation:** Store PoW nonce in `PersistedContact` and verify on restore:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
pub struct PersistedContact {
    pub node_id: String,
    pub address: String,
    pub port: u16,
    pub geo: Option<GeoInfo>,
    pub latency_ms: Option<u32>,
    pub last_seen: u64,
    pub is_global: bool,
    pub is_trusted: bool,
    pub pow_nonce: Option<u64>,        // ADD THIS
    pub public_key: Option<Vec<u8>>,   // ADD THIS
}
```

Then in `from_persisted()`:
```rust
if contact.requires_pow() && !contact.verify_pow() {
    tracing::warn!("Rejecting persisted peer {} - PoW verification failed", ...);
    continue;
}
```

**Effort:** Low - add fields and verify

---

### 3.3 Lookup Query Can Return Duplicate Peers

**Location:** `src/mesh/dht/routing/query.rs:50-72`

**Problem:** `next_peers_to_query()` can return the same peer via both `pending` and `closest` paths if a peer is in both lists.

**Current code:**
```rust
for peer in &self.pending {           // First: pending peers
    if !self.contacted.contains(&peer.node_id) {
        to_query.push(peer);
    }
}
if to_query.len() < self.alpha {      // Then: closest peers
    for peer in &self.closest {
        if !self.contacted.contains(&peer.node_id) && to_query.len() < self.alpha {
            to_query.push(peer);
        }
    }
}
```

If a peer is in both `pending` and `closest`, it could be added twice to `to_query`.

**Fix:**
```rust
pub fn next_peers_to_query(&self) -> Vec<&PeerContact> {
    if self.completed {
        return Vec::new();
    }

    let mut to_query: Vec<&PeerContact> = Vec::new();
    let mut seen: HashSet<&NodeId> = HashSet::new();

    for peer in &self.pending {
        if !self.contacted.contains(&peer.node_id) && seen.insert(&peer.node_id) {
            to_query.push(peer);
        }
    }

    if to_query.len() < self.alpha {
        for peer in &self.closest {
            if !self.contacted.contains(&peer.node_id) 
                && to_query.len() < self.alpha 
                && seen.insert(&peer.node_id) {
                to_query.push(peer);
            }
        }
    }

    to_query
}
```

**Effort:** Low - add HashSet deduplication

---

### 3.4 Inconsistent Bucket Index Convention

**Location:** `src/mesh/dht/routing/node_id.rs:109-112`

**Problem:** The bucket index formula `255 - prefix_len.min(255)` inverts standard Kademlia convention where bucket 0 = furthest nodes.

**Current:**
- Close node (255 prefix): bucket 0
- Far node (0 prefix): bucket 255

**Standard Kademlia:**
- Close node (255 prefix): bucket 255
- Far node (0 prefix): bucket 0

**Impact:** None - the code is internally consistent. Just differs from textbook Kademlia.

**Recommendation:** Add comment documenting this design choice.

**Effort:** Trivial - add documentation comment

---

### 3.5 Timestamp Window Not Configurable

**Location:** `src/mesh/dht/signed.rs:9`

**Problem:** Hardcoded to 300 seconds.

**Status:** Already documented in `plan_dht.md` as low priority.

**Effort:** Low - add config option

---

## Priority 4: Documentation

### 4.1 Document Regional Hub Purpose in AGENTS.md

**Status:** ✅ COMPLETED - Added to AGENTS.md in the "Global Nodes as Trust Anchors" section:

> The `RegionalHub` system in `src/mesh/dht/routing/regional_hubs.rs` is for routing optimization only — it selects **preferred peers** for low-latency routing, NOT trust decisions. Global nodes are ALWAYS selected first when available.

---

## Summary

| ID | Item | Priority | Effort | Status |
|----|------|----------|--------|--------|
| 1.1 | Unbounded PoW nonce search | High | Low | Existing (plan_dht.md) |
| 2.1 | DHT integration tests | Medium | Medium | New - needs implementation |
| 2.2 | Regional hub unit tests | Medium | Low | New - needs implementation |
| 3.1 | Bucket split never invoked | Low | Medium | Document or implement |
| 3.2 | PoW not persisted | Low | Low | New - needs implementation |
| 3.3 | Duplicate peers in lookup | Low | Low | New - needs implementation |
| 3.4 | Bucket index convention | Info | Trivial | Document |
| 3.5 | Timestamp window config | Low | Low | Existing (plan_dht.md) |
| 4.1 | Document regional hubs | Done | Done | ✅ COMPLETED |

## Recommended Next Steps

1. **Immediate:** Fix 3.3 (duplicate peers) - low effort, improves correctness
2. **Soon:** Add 2.1 (integration tests) - validates system behavior
3. **Later:** Consider 3.1 (bucket splitting) if network grows beyond ~1000 nodes