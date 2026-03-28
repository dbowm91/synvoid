# DHT & Mesh System Review — Findings and Remediation Plan

## Date: 2026-03-27

## Summary

Three areas of concern were identified in the mesh/Kademlia DHT subsystem and investigated in depth. This document presents verified findings with exact file:line references and a prioritized remediation plan.

---

## Issue 1: Geo-Aware Routing Weight Imbalance (Correctness Risk)

### Finding 1a: XOR Distance Is Effectively Ignored in Weighted Scoring

**File:** `src/mesh/dht/routing/geo_distance.rs:117-137`

The `xor_distance_score()` function has two branches based on leading zero bytes in the XOR distance:
- `leading_zeros == 0` (most common, ~99.6% of random pairs): `1.0 - (first_byte / 256.0)`, range ≈ 0.004–0.996
- `leading_zeros > 0` (same-prefix pairs): `(leading_zeros / 31.0)`, range ≈ 0.032–0.968

The score range is adequate, but the **granularity** is poor:
- When `leading_zeros == 0`, the entire 256-bit XOR distance is collapsed to 255 discrete values (the first byte only). Two nodes with the same first byte but completely different remaining 31 bytes receive identical scores.
- When `leading_zeros > 0`, there are only 30 possible values (1–30 leading zeros).
- Geo distance uses Haversine (essentially continuous), and latency uses a smooth formula — both have far finer granularity.

With default weights (`xor=0.2, geo=0.5, latency=0.3`), the XOR component's coarse granularity means small geo or latency differences can easily dominate over significant XOR distance differences. A node that is XOR-distant but geographically close (and has similar latency) will typically outscore an XOR-close but geographically distant node, because the geo score (range 0.3–1.0 with continuous granularity) contributes 2.5x more weight AND has 256x finer discrimination.

**Severity:** Medium. The 3x candidate expansion (`find_closest(target, k*3)` at `table.rs:331`) partially mitigates this — you'd need >67% of candidates to be geo-far for XOR-close nodes to be dropped. However, for DHT storage correctness, replication should prioritize XOR-close nodes, and the coarse XOR granularity means the weighted re-sort can easily flip the ordering of candidates that differ only slightly in geo distance.

### Finding 1b: `target_geo` Is Always `None` in Production Callers

**File:** `src/mesh/dht/record_store_sync.rs:560, 615, 665`

All three production call sites of `find_closest_peers_hybrid()` pass `target_geo: None`:
```rust
// record_store_sync.rs:560
let target_geo = None;
let peers = rm.find_closest_peers_hybrid(&self.node_id, target_geo, replication_factor).await;

// record_store_sync.rs:615
let target_geo = None;
let closest_peers = rm.find_closest_peers_hybrid(key, target_geo, 8).await;

// record_store_sync.rs:665
let target_geo = None;
let closest_peers = rm.find_closest_peers_hybrid(&record.key, target_geo, replication_factor).await;
```

This means `geo_distance_score()` at `geo_distance.rs:113` always returns `0.5` (the `None` fallback) when computing target distance, and the hub selection in `find_closest_via_hubs()` at `regional_hubs.rs:306` operates without knowing the target's region.

**Severity:** Low. The geo-aware weighting is partially neutered but this also means it can't cause the correctness issues from Finding 1a as severely.

### Finding 1c: Regional Hub `_target` Parameter Is Unused

**File:** `src/mesh/dht/routing/regional_hubs.rs:308`

```rust
pub fn find_closest_via_hubs(
    &self,
    _target: &NodeId,       // <-- unused
    target_geo: Option<&GeoInfo>,
    k: usize,
) -> Vec<PeerContact> {
```

The hub selection is purely region-based and does not respect Kademlia's XOR topology. The final re-sort by XOR distance at `table.rs:378-382` partially corrects this, but 50% of results (the hub portion from `table.rs:358`) could be XOR-distant from the target.

**Severity:** Low. Combined with Finding 1b, the hub path is already partially neutered.

### Finding 1d: Local Region Detection Uses Non-Deterministic HashMap Iteration

**File:** `src/mesh/dht/routing/regional_hubs.rs:316-333`

```rust
let local_region: String = {
    let all_peers = self.all_peers_by_region.read();
    let mut region_found = None;
    for peers in all_peers.values() {  // HashMap iteration order is non-deterministic
        for p in peers {
            region_found = Some(match &p.geo {
                Some(geo) => region_key(geo),
                None => "unknown".to_string(),
            });
            break;
        }
        if region_found.is_some() {
            break;
        }
    }
    region_found.unwrap_or_else(|| "unknown".to_string())
};
```

The `#[allow(clippy::never_loop)]` suppression at line 319 acknowledges this is a hack. The "local region" could change between calls, causing inconsistent hub selection.

**Severity:** Low (cosmetic/reliability). Hub selection is already partially neutered by Finding 1b.

### Finding 1e: Dead Geo-Aware Methods in `DhtRoutingManager`

**File:** `src/mesh/dht/routing/manager.rs:295, 311`

`find_closest_peers_geo()` and `find_closest_peers_geo_weighted()` have zero external callers. Only `find_closest_peers_hybrid()` and `find_closest_peers()` (pure XOR) are used.

**Severity:** Informational (dead code).

---

## Issue 2: Transport Architecture — Not a Migration, a Layered System

### Finding 2a: Legacy `MeshTransport` Is the Active Implementation

**Files:** `src/mesh/transport.rs` (1,889 lines) + 8 extension files (4,864 lines) = 6,753 lines total

The legacy `MeshTransport` is **not deprecated**. It is the actual implementation:
- `QuicMeshTransport` (`transports/quic.rs:13`) wraps `Arc<MeshTransport>` and delegates every call
- The data plane (proxy HTTP at `proxy.rs:937`, route queries at `proxy.rs:598`, DHT operations) uses legacy `MeshTransport`
- 4 external consumers depend on it: `main.rs`, `admin/state.rs`, `admin/mod.rs`, `dns/anycast_sync.rs`

The newer `MeshTransportManager` (`transports/manager.rs:79`) handles control-plane concerns: transport selection, config caching, fallback logic.

**No TODOs, FIXMEs, or deprecation markers** exist in any transport file.

### Finding 2b: Dual Transport References in `MeshProxy`

**File:** `src/mesh/proxy.rs:54-55`

```rust
transport: Arc<RwLock<Option<Arc<MeshTransport>>>>,           // legacy
transport_manager: Arc<RwLock<Option<Arc<MeshTransportManager>>>, // newer
```

Both are stored, both are used — legacy for data plane, newer for config lookups.

**Severity:** Informational. This is an intentional layered architecture, not a migration-in-progress.

---

## Issue 3: Test Coverage Gaps (Risk)

### Finding 3a: Overall Coverage

| Category | Files with tests | Files without | Test count |
|----------|-----------------|---------------|------------|
| DHT routing | 7 of 8 | `manager.rs` | 38 |
| DHT core | 5 of 12 | `record_store.rs`, `record_store_crud.rs`, `record_store_sync.rs`, `record_store_message.rs`, `record_store_dns.rs`, `mod.rs`, `network_policy.rs` | 16 |
| Transport | 0 of 16 | All | 0 |
| Protocol | 0 of 5 | All | 0 |
| Security | 0 of 6 | All | 0 |
| Discovery/Topology/Proxy | 0 of 3 | All | 0 |
| **Totals** | **17 of 55** | **38 files** | **97 tests** |

### Finding 3b: Critical Untested Components

| Component | Lines | Risk |
|-----------|-------|------|
| `record_store_sync.rs` | 778 | Anti-entropy sync, gossip, Merkle diff — completely untested |
| `record_store_crud.rs` | 618 | Record storage/retrieval/replication — completely untested |
| `record_store_message.rs` | 498 | DHT message handling — completely untested |
| `dht/mod.rs` | 584 | `DhtRateLimiter`, `DhtAccessControl` — completely untested |
| All 16 transport files | ~6,753 | Transport layer — zero tests |
| `protocol_proto_encode.rs` | 1,989 | Protobuf encoding — zero tests |
| `protocol_proto_decode.rs` | 1,222 | Protobuf decoding — zero tests |

### Finding 3c: No Mock/Test Infrastructure

There are no mock transports, test harnesses, or test utility modules for the mesh subsystem. All existing tests are pure unit tests on data structures (NodeId, KBucket, MerkleTree, etc.).

**Severity:** High. The DHT record store (the core data layer) and transport layer have zero test coverage.

---

## Remediation Plan

### Priority 1: Fix XOR Distance Scoring Granularity (Correctness)

**File:** `src/mesh/dht/routing/geo_distance.rs:117-137`

The `xor_distance_score()` function should use more of the XOR distance bytes to improve granularity. The current approach collapses the 256-bit distance to 255 values (first byte only) when `leading_zeros == 0`, losing discrimination power. Replace with a bit-prefix approach:

```rust
// Current: uses only first byte when leading_zeros==0, only count when >0
fn xor_distance_score(&self, xor_dist: &NodeId) -> f64 {
    let bytes = xor_dist.as_bytes();
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    if leading_zeros >= 31 { 1.0 }
    else if leading_zeros == 0 {
        1.0 - (bytes[0] as f64 / 256.0)
    } else {
        (leading_zeros as f64) / 31.0
    }
}

// Proposed: bit-prefix length gives 256 distinguishable values
fn xor_distance_score(&self, xor_dist: &NodeId) -> f64 {
    let bytes = xor_dist.as_bytes();
    // Count leading zero BITS (not bytes) for finer granularity
    let mut leading_zero_bits: u32 = 0;
    for &b in bytes.iter() {
        if b == 0 {
            leading_zero_bits += 8;
        } else {
            leading_zero_bits += b.leading_zeros();
            break;
        }
    }
    // 0 leading zero bits = max distance (score ~0), 256 = min distance (score 1.0)
    leading_zero_bits as f64 / 256.0
}
```

This gives XOR 256 distinguishable values (matching the first-byte granularity from the current code) but correctly extends to all bytes, so two nodes with the same first byte but different second byte now get different scores.

**Alternative:** Rebalance weights to `xor=0.4, geo=0.35, latency=0.25` if the logarithmic change is too risky.

### Priority 2: Pass Actual `target_geo` to Hybrid Lookup (Correctness)

**File:** `src/mesh/dht/record_store_sync.rs:558-562, 615-616, 665-666`

The callers should supply the local node's geo info instead of `None`. This requires plumbing the local node's `GeoInfo` through `RecordStoreManager`:

1. Add `local_geo: Option<GeoInfo>` field to `RecordStoreManager` (set during construction from `MeshConfig`)
2. Replace `let target_geo = None;` with `let target_geo = self.local_geo.as_ref();` in all three call sites

### Priority 3: Fix Regional Hub Local Region Detection (Reliability)

**File:** `src/mesh/dht/routing/regional_hubs.rs:316-333`

Replace the HashMap-iteration hack with an explicit `local_region` field on `RegionalHub`:

1. Add `local_region: String` to `RegionalHub` struct
2. Set it during construction from the local node's `GeoInfo`
3. Use `self.local_region` directly instead of iterating `all_peers_by_region`

### Priority 4: Use Target NodeId in Hub Selection (Correctness)

**File:** `src/mesh/dht/routing/regional_hubs.rs:306-386`

The `_target` parameter should be used to filter hub candidates by XOR proximity, not just region. This ensures the hub portion of `find_closest_hybrid()` results respects Kademlia topology.

### Priority 5: Add DHT Record Store Unit Tests (Risk Mitigation)

Create test modules for the untested core DHT components:

1. **`record_store_crud.rs`** — Test `store_record`, `get_record`, `remove_record` with mock transport
2. **`record_store_sync.rs`** — Test anti-entropy request/response generation, Merkle diff logic
3. **`record_store_message.rs`** — Test message handling for each DHT message variant
4. **`dht/mod.rs`** — Test `DhtRateLimiter` (sliding window, reset) and `DhtAccessControl` (key-prefix permissions)

### Priority 6: Add Protocol Encode/Decode Roundtrip Tests (Risk Mitigation)

**Files:** `src/mesh/protocol_proto_encode.rs`, `src/mesh/protocol_proto_decode.rs`

For each `MeshMessage` variant, test:
1. Construct message
2. Encode to protobuf bytes
3. Decode back
4. Assert equality

This is the highest-value test addition per line of code — 3,211 lines of encoding/decoding logic with zero coverage.

### Priority 7: Clean Up Dead Code (Housekeeping)

1. Remove `find_closest_peers_geo()` and `find_closest_peers_geo_weighted()` from `DhtRoutingManager` (zero callers)
2. Either wire `_target` in `find_closest_via_hubs()` or remove the parameter
3. Document the transport architecture: legacy `MeshTransport` is the implementation layer, `MeshTransportManager` is the selection/caching layer

### Priority 8: Evaluate Geo Routing Defaults (Design Review)

With the XOR scoring fix from Priority 1, evaluate whether the default weights are appropriate:
- If geo-awareness is primarily for latency optimization (not correctness), consider `xor=0.5, geo=0.3, latency=0.2`
- If the hybrid path is intentionally best-effort (not replication-critical), document this and keep current weights
- Consider adding a `strict_kademlia` config flag that disables geo-aware sorting for replication, using it only for peer selection

---

## Verification Steps

After implementing fixes:

```bash
# Run existing tests
cargo test --lib

# Run clippy
cargo clippy -- -D warnings

# Run integration tests
cargo test --test integration_test

# Verify no regressions in DHT routing
cargo test --lib -- dht::routing
```

---

## Files Referenced

| File | Lines | Relevance |
|------|-------|-----------|
| `src/mesh/dht/routing/geo_distance.rs` | 269 | XOR scoring (Finding 1a) |
| `src/mesh/dht/routing/regional_hubs.rs` | 478 | Hub selection (Findings 1c, 1d) |
| `src/mesh/dht/routing/table.rs` | 669 | Hybrid lookup (Finding 1a mitigation) |
| `src/mesh/dht/routing/manager.rs` | 674 | Dead methods (Finding 1e), iterative lookup |
| `src/mesh/dht/routing/query.rs` | 327 | Pure XOR lookup (verified correct) |
| `src/mesh/dht/record_store_sync.rs` | 778 | target_geo=None (Finding 1b) |
| `src/mesh/transport.rs` | 1,889 | Legacy transport (Finding 2a) |
| `src/mesh/transports/quic.rs` | 135 | Wraps legacy (Finding 2a) |
| `src/mesh/proxy.rs` | 1,262 | Dual transport refs (Finding 2b) |
| `src/mesh/dht/record_store_crud.rs` | 618 | Untested (Finding 3b) |
| `src/mesh/dht/record_store_message.rs` | 498 | Untested (Finding 3b) |
| `src/mesh/protocol_proto_encode.rs` | 1,989 | Untested (Finding 3b) |
| `src/mesh/protocol_proto_decode.rs` | 1,222 | Untested (Finding 3b) |
