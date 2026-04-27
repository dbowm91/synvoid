# Mesh and DHT Architecture Review - Implementation Plan

**Status**: Active - Planning Complete
**Last Updated**: 2026-04-27
**Review Scope**: Mesh and DHT architecture, scalability, robustness, and security model

---

## Executive Summary

The mesh and DHT system provides a solid architectural foundation with K-bucket routing, quorum-based consensus, capability attestation, and multi-role node support. However, several critical issues were identified that could impact scalability, security, and robustness at the 500K+ req/sec target.

**Use Case Context**:
- Global nodes = primary source of truth/CA, run by the same entity
- Edge nodes = may be run by third parties
- All nodes can carry different flags/capabilities (work as edge, host multiple origins, global)
- Roles are not mutually exclusive
- DNS server capability restricted to global nodes (enforced at multiple layers)

---

## P0 Security Fixes (Critical - Require Immediate Attention)

### P0.1: Time-Based Challenge Solution Verification Bypass

**File**: `src/mesh/security_challenge.rs:159-190`

**Issue**: The `verify_time_based_challenge()` function ignores the solution parameter entirely and always returns `true` if the challenge exists and hasn't expired.

**Root Cause**: The `_solution` parameter (underscore prefix = intentional unused) is never validated. The function sets `verified = true` without checking anything.

**Challenge Format**: `target_node:time_window:challenge_id` where `time_window = (elapsed_secs / 30) % 100`

**Fix**: Parse challenge_data, extract expected time_window, validate solution matches:
```rust
// Parse expected time_window from challenge_data
let parts: Vec<&str> = challenge_str.split(':').collect();
let expected_time_window = parts[1];

// Validate the solution matches the expected time_window
if solution != expected_time_window {
    tracing::warn!("Time-based challenge {} failed: expected '{}', got '{}'",
        challenge_id, expected_time_window, solution);
    return false;
}
```

**Test Coverage**: None exists - `security_challenge.rs` has no `#[cfg(test)]` module.

**Complexity**: Low (~2 hours)

---

### P0.2: Threat Intel Trusted Signer Bypass

**File**: `src/mesh/threat_intel.rs:1550-1630, 1681-1684`

**Issue**: `check_trusted_signer()` is called in `sync_from_dht()` (line 1296) but NOT in:
1. Direct `ThreatAnnounce` handling at line 1607 (condition skips when `trusted_signers` empty)
2. `ThreatSyncResponse` handler at line 1681 (directly calls `handle_incoming_threat` without check)

**Attack Vector**: Malicious node sends `ThreatAnnounce` with any valid Ed25519 signature. On non-global nodes with default empty `trusted_signers`, validation is skipped entirely.

**Fix**: Add fallback check when `trusted_signers` is empty (same pattern as `sync_from_dht`):
```rust
if !self.node_role.is_global() {
    let is_trusted = if !self.config.trusted_signers.is_empty() {
        self.check_trusted_signer(source_node_id, signer_public_key)
    } else {
        // Fallback: accept only if source is known global node
        self.is_global_node(source_node_id)
    };
    if !is_trusted { /* reject */ }
}
```

**Complexity**: Medium (~4 hours including testing)

---

### P0.3: Pass-Over Key Exchange Fallback Signing Violation

**File**: `src/mesh/passover_key_exchange.rs:469-534`

**Issue**: When origin is unreachable, gRPC handler falls back to signing with origin's configured private key. Violates "GLOBAL NODE IS UNTRUSTED FOR ORIGIN SIGNING" invariant.

**HTTP Handler**: Correctly returns `BAD_GATEWAY` error when origin fails (lines 621-632)

**gRPC Handler**: Incorrectly proceeds to fallback signing (line 476)

**Fix**: Remove fallback in gRPC handler, return error like HTTP handler:
```rust
match self.proxy_key_request_to_origin(&mesh_id, &client_x25519_pubkey, &nonce).await {
    Ok(key_offer) => Ok(Response::new(key_offer)),
    Err(e) => {
        // SECURITY: Return error instead of fallback signing
        Err(Status::unavailable(format!(
            "Origin unreachable for mesh_id: {}. Cannot complete key exchange.",
            mesh_id
        )))
    }
}
```

**Missing Test**: No test for origin-unreachable scenario. Add test to verify error is returned.

**Complexity**: Low (~1 hour)

---

### P0.4: RecordStoreManager Clone Creates Empty Store

**File**: `src/mesh/dht/record_store.rs:468-519`

**Issue**: Clone implementation creates fresh empty `ShardedRecordStore::new()` instead of copying records.

**Call Sites**:
| Location | Usage | Impact |
|----------|-------|--------|
| `start_broadcast_timer()` | Reads `pending_announces` (cloned correctly) | Works |
| `store_record()` | Uses routing/transport, not local records | Works |
| `start_pruning_task()` | Reads `records` | **BUG - silently fails to prune** |
| quorum request | Uses routing state only | Works |

**Fix**: Implement `Clone` for `ShardedRecordStore`:
```rust
impl Clone for ShardedRecordStore {
    fn clone(&self) -> Self {
        let shards: Vec<_> = self.shards.iter().map(|shard| {
            RwLock::new(shard.read().clone())
        }).collect();
        Self { shards }
    }
}
```

**Severity**: Low-Medium

**Complexity**: Low (~2 hours)

---

## P1 High Priority Fixes

### P1.1: Clock Skew / Conflict Resolution for Network Partitions

**Files**: `src/mesh/dht/record_store_crud.rs:318-333`, `src/mesh/protocol.rs:1447-1457`

**Issue**: Timestamp-based LWW without CRDT or vector clocks. Vulnerable to clock skew causing split-brain. Sequence number is hollow (not incremented on update).

**Current Logic**:
```rust
let should_replace = new_key > existing_key;  // Tuple comparison
// (timestamp, sequence_number, source_node_id)
```

**Recommendations**:
1. **Short-term**: Add `clock_offset` tracking per peer to detect skew and adjust before comparison
2. **Medium-term**: Implement Hybrid Logical Clocks (HLC):
```rust
pub struct HybridClock {
    wall_time: u64,    // Physical time
    logical: u64,       // Monotonic logical counter
    node_id: u64,       // Tiebreaker
}
```

**Complexity**: Medium-High

---

### P1.2: Message Cache Severely Undersized at 500K rps

**File**: `src/mesh/transport.rs:239-244`

**Issue**: `seen_messages` LRU cache has 10,000 entries. At 500K rps, fills in ~1 second. Effective deduplication window: ~1 second.

**Current Config**:
```rust
LruCache::with_expiry_duration_and_capacity(
    Duration::from_secs(300),  // 5 min TTL
    10000,                     // SEVERELY UNDERSIZED
)
```

**Recommended Fix**: Use Moka cache:
```rust
let seen_messages = Cache::builder()
    .max_capacity(500_000)           // 500K for 1 sec at 500K rps
    .time_to_live(Duration::from_secs(30))  // 30 sec retry window
    .build();
```

| Aspect | Current | Recommended |
|--------|---------|-------------|
| Cache size | 10,000 | 500,000 |
| TTL | 300 sec | 30 sec |
| Memory | ~1 MB | ~50 MB |
| Dedup window | ~1 sec | ~30 sec |

**Complexity**: Low (~2 hours)

---

### P1.3: Unbounded Proxy Task Spawn

**File**: `src/mesh/proxy.rs:962-997`

**Issue**: `tokio::spawn()` called in loop without bounds. R requests x P providers = unbounded tasks.

**Fix**: Semaphore-based limiting:
```rust
const MAX_CONCURRENT_PROVIDER_ATTEMPTS: usize = 8;

let semaphore = Arc::new(tokio::sync::Semaphore::new(
    MAX_CONCURRENT_PROVIDER_ATTEMPTS
));

for provider in &providers {
    let permit = semaphore.clone().acquire_owned().await?;
    tokio::spawn(async move {
        // ... proxy work ...
        drop(permit);
    });
}
```

**Note**: Codebase already uses semaphores in `unified_server.rs:830-847` and `tls/server.rs:176`.

**Complexity**: Low (~2 hours)

---

### P1.4: Attestation Expiration and Revocation Not Checked

**Files**: `src/mesh/dht/capability_access.rs:47-83`, `src/mesh/dht/capability_attestation.rs`

**Issue**: `verify_capability_for_key()` doesn't check:
1. Whether attesting global node is still authorized
2. Whether attestation has expired (no `expires_at` field)
3. Whether global node appears in revocation list

**Window of Vulnerability**: Up to 24 hours after global node revocation, its attestations still work.

**Fix Required**:
1. Add `expires_at` field to `CapabilityAttestation`
2. Add `is_expired()` method
3. Add expiration check in `verify_capability_for_key()`
4. Check revocation status (requires architecture change to pass revocation_list)

**Complexity**: Medium (~4 hours)

---

## P2 Medium Priority Improvements

### P2.1: O(k×n) DHT Lookup Complexity

**File**: `src/mesh/dht/routing/bucket.rs:233-278`

**Issue**: `find_closest()` iterates all buckets with O(k×n) complexity.

**Recommendation**: Optimize to O(log n) using bucket-level indexing.

**Complexity**: High

---

### P2.2: Quorum Timeout Hardcoded to 10 Seconds

**File**: `src/mesh/dht/quorum.rs:113`

**Issue**: `deadline: now + 10` is hardcoded.

**Recommendation**: Make configurable.

**Complexity**: Low

---

### P2.3: Veto Abuse Score Never Applied

**File**: `src/mesh/dht/quorum.rs:293`

**Issue**: `get_veto_abuse_score()` calculates but never uses.

**Recommendation**: Apply veto limits.

**Complexity**: Medium

---

## Summary Table

| ID | Issue | Priority | Complexity | Files |
|----|-------|----------|------------|-------|
| P0.1 | Time-based challenge ignores solution | Critical | Low | security_challenge.rs:159-190 |
| P0.2 | Threat intel trusted signer bypass | Critical | Medium | threat_intel.rs:1550-1630, 1681 |
| P0.3 | Pass-over fallback signs as origin | Critical | Low | passover_key_exchange.rs:469-534 |
| P0.4 | Clone creates empty record store | Critical | Low | record_store.rs:468-519 |
| P1.1 | Timestamp LWW vulnerable to clock skew | High | Medium-High | record_store_crud.rs:318-333 |
| P1.2 | Message cache 10K too small at 500K rps | High | Low | transport.rs:239-244 |
| P1.3 | Unbounded proxy task spawn | High | Low | proxy.rs:962-997 |
| P1.4 | Attestation no expiration check | Medium | Medium | capability_access.rs |
| P2.1 | O(k×n) DHT lookup | Medium | High | bucket.rs:233-278 |
| P2.2 | Hardcoded quorum timeout | Low | Low | quorum.rs:113 |
| P2.3 | Veto abuse score unused | Low | Medium | quorum.rs:293 |

---

## Security Model Assessment

### Correctly Implemented

| Security Pattern | Location |
|-----------------|----------|
| Edge nodes blocked from DNS capability | `transport.rs:882-896` |
| DNS mesh mode only for non-global | `dns/server/startup.rs:543` |
| Genesis key default deny (empty list = reject) | `config_identity.rs:222` |
| Composite role validates both components | `peer_auth.rs:196-225` |
| Global node MUST NOT sign for origin | `passover_key_exchange.rs:6` |
| Privileged keys require global node | `record_store_crud.rs:122` |
| Trusted signer for threat intel DHT sync | `threat_intel.rs:1298` |
| Pass-over key exchange (HTTP handler) | `passover_key_exchange.rs:621-632` |

### Vulnerabilities Found

| System | Issue | Severity |
|--------|-------|----------|
| Sec Challenge | `verify_time_based_challenge` ignores solution | High |
| Threat Intel | `check_trusted_signer` not called in `handle_incoming_threat` | Medium |
| Pass-Over | Fallback signing when origin unreachable violates protocol | High |
| Attestation | No expiration check on capability attestations | Medium |
| Clone | RecordStoreManager Clone creates empty store | Medium |

---

## Scalability Assessment

### Critical Bottlenecks at 500K rps

1. **Message cache**: 10K entries fills in ~1 second at moderate mesh message rate
2. **O(k×n) DHT lookup**: Linear search through buckets per request
3. **Single write lock**: All DHT writes serialize on `record_state.write()`
4. **Unbounded task spawn**: Proxy spawns unlimited tasks per request

### Architectural Strengths

- K-bucket routing (256 buckets x 20 peers = 5,120 capacity)
- 64-shard record store (some concurrency improvement)
- Tiered caching (L1 DashMap 500, L2 Moka 2000)
- 2/3 Byzantine fault tolerance for quorum

---

## Recommended Implementation Order

1. **P0.1 + P0.3** (both low complexity, critical security)
2. **P0.2** (medium complexity, critical security)
3. **P0.4** (low complexity, correctness bug)
4. **P1.2** (low complexity, scalability at 500K rps)
5. **P1.3** (low complexity, resource protection)
6. **P1.4** (medium complexity, trust model integrity)
7. **P1.1** (medium-high complexity, partition handling)

---

## Verification Commands

```bash
# Verify tests compile
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```
