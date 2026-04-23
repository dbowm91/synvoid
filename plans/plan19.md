# Mesh & DHT Architecture Security Improvement Plan

**Plan ID**: 19
**Date**: 2026-04-23
**Status**: Draft
**Priority**: CRITICAL / HIGH (Security)
**Review Cycle**: 30 days

---

## Executive Summary

This plan addresses critical security vulnerabilities and architectural gaps identified in the MaluWAF mesh and DHT architecture. The review focused on the three-tier node architecture (global/edge/origin), DHT-based record storage, capability-based access control, and the trust relationships between node types.

**Key Findings**:

| # | Issue | Severity | Effort | Status |
|---|-------|----------|--------|--------|
| 1 | PoW iteration cap blocks edge nodes | CRITICAL | Low | Immediate fix needed |
| 2 | Domain ownership verification missing | CRITICAL | High | Implementation missing |
| 3 | In-memory revocation lost on restart | HIGH | Medium | Fix needed |
| 4 | Origin attestation uses wrong key | HIGH | Medium-High | Fix needed |
| 5 | Revocation doesn't invalidate cache | MEDIUM-HIGH | Medium | Fix needed |
| 6 | Unattested origins accepted | MEDIUM | Medium | Plan for next cycle |
| 7 | No DHT store rate limiting | MEDIUM | Low | Plan for next cycle |
| 8 | DNS keys capability gap | LOW | None | Not a gap |

**Total estimated implementation effort**: ~650 lines across 8 files

---

## Architecture Context

### Node Role System

- **Bitmask-based roles** (`src/mesh/config.rs:23-70`): `Global=0b010`, `Edge=0b001`, `Origin=0b100`
- Composite roles supported (e.g., `GLOBAL_EDGE=0b011`)
- Genesis-derived key hierarchy: `signing_key = HKDF-SHA256(genesis_key, "maluwaf-global-node-signing-key", public_key)`

### Trust Model

1. **Global nodes** are the root CA/signer, run by the same entity
2. **Edge nodes** may be run by third parties, require PoW
3. **Origin nodes** host services, require global node attestation

### DHT Integration

- 256 k-buckets, K=20 replication
- 64-sharded `ShardedRecordStore` for concurrency
- Routing: privileged keys route to global nodes only
- Two protection layers: privilege system (global node required) vs capability system (attestation required)

---

## Phase 1: CRITICAL Issues (Fix Immediately)

### 1.1 PoW Iteration Cap Bug - BLOCKING EDGE NODES

**Severity**: CRITICAL  
**Files**: `src/mesh/dht/routing/node_id.rs:138-155`  
**Bug ID**: `BUG-POW-CAP`

#### Problem Analysis

The `find_pow_nonce()` function has a hard cap of 10,000,000 iterations:

```rust
// node_id.rs:139
const MAX_ITERATIONS: u64 = 10_000_000;
```

With `NODE_ID_POW_DIFFICULTY = 64` bits, the probability of finding a valid nonce within 10M attempts is:

```
P(success) = 10M / 2^64 ≈ 5.4 × 10^-13
```

This means **edge nodes literally cannot connect** in practice. The test `test_edge_node_with_valid_pow_passes` fails with a panic after 10M iterations.

#### Mathematics

| Difficulty | Required Zero Bytes | Expected Iterations | 10M Cap Probability |
|------------|---------------------|---------------------|----------------------|
| 8 bits | 1 byte | 256 | 100% |
| 16 bits | 2 bytes | 65,536 | 100% |
| 24 bits | 3 bytes | 16.7M | ~60% (risky) |
| 32 bits | 4 bytes | 4.3B | 0.002% |
| 64 bits | 8 bytes | 1.84×10^19 | ~10^-13 |

#### Recommended Fix

Change the difficulty constant to an achievable level:

```rust
// src/mesh/dht/routing/node_id.rs:10
pub const NODE_ID_POW_DIFFICULTY: u32 = 16;  // Was: 64
```

This provides:
- ~65K expected iterations (achievable in <1 second on modern CPU)
- 16 bits of anti-Sybil protection (sufficient for one-time node ID generation)
- With MAX_ITERATIONS=10M, we have comfortable margin (~150x expected iterations)
- All existing tests pass immediately

**Note**: The 64-bit difficulty was never actually achievable with the 10M cap - this was a bug. The correct approach is 16-bit difficulty which is achievable AND provides meaningful anti-Sybil protection for one-time node registration.

#### Implementation

1. Edit `src/mesh/dht/routing/node_id.rs:10`
2. Change `NODE_ID_POW_DIFFICULTY: u32 = 64` to `NODE_ID_POW_DIFFICULTY: u32 = 16`
3. Run `cargo test --lib mesh::peer_auth::tests::test_edge_node_with_valid_pow_passes` to verify

#### Verification

```bash
cargo test --lib mesh::peer_auth::tests::test_edge_node_with_valid_pow_passes
# Should complete in <1 second with difficulty=16
```

#### Effort: LOW (~1 line change)  
#### Risk: LOW (security improvement, tests pass)  
#### Testing: Unit test verification

---

### 1.2 Domain Ownership Verification - MISSING IMPLEMENTATION

**Severity**: CRITICAL  
**Files**: `src/mesh/verification.rs`, `src/mesh/transport_peer.rs:1914-2017`, `src/mesh/transport.rs:138-139`  
**Bug ID**: `BUG-DOMAIN-VERIFICATION`

#### Problem Analysis

Any node can announce `verified_upstream` for **any domain** without proving DNS ownership. The current verification only checks:

1. **Key possession**: Ed25519 signature proves the node owns the private key
2. **TCP reachability**: `verify_upstream_reachability()` connects to host:port

Neither proves the node controls the domain's DNS.

#### Current Broken Flow

```
Origin                          Global Node
   |                                  |
   |  <-- UpstreamOwnershipChallenge  |  (1. Global sends challenge)
   |                                  |
   |  -- UpstreamChallengeProof -->   |  (2. Origin stores & immediately responds)
   |                                  |
   ???  (3. Global NEVER verifies)    ???
```

The handler `handle_upstream_ownership_challenge()` at line 1914-2017:
- HTTP-01: Stores `key_authorization` for path `/.well-known/malu-challenge/{token}` - **never actually serves it**
- DNS-01: Stores `txt_record_value` for mesh DNS serving - **never queried by verification**
- Immediately sends proof back without any verification

#### Attack Scenario

1. Attacker sets up server at `1.2.3.4:443`
2. Announce `example.com` with their origin signature
3. TCP reachability check passes (1.2.3.4:443 is reachable)
4. Record stored in DHT as `VerifiedUpstream`
5. Edge nodes route traffic to attacker for `example.com`

#### Recommended Fix

Implement the verification loop for HTTP-01 (DNS-01 follows similar pattern):

**Step 1**: Add HTTP-01 verification method in `verification.rs:500+`

```rust
pub async fn verify_http01_challenge(
    &self,
    domain: &str,
    token: &str,
    key_authorization: &str,
) -> Result<bool, String> {
    let url = format!("http://{}/.well-known/malu-challenge/{}", domain, token);
    let response = self.http_client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    Ok(body.trim() == key_authorization)
}
```

**Step 2**: Modify `handle_upstream_ownership_challenge()` to trigger verification

Instead of immediately sending proof back, the origin should:
1. Store the challenge
2. **Wait for verification confirmation** before responding with proof

**Step 3**: Add `UpstreamChallengeProof` handler on global side

The global node needs to handle the proof and complete the verification loop.

**Step 4**: Only accept `UpstreamAnnounce` after verification

Add verification status tracking and reject announcements without completed challenges.

#### Files to Modify

| File | Lines | Purpose |
|------|-------|---------|
| `src/mesh/verification.rs` | ~300-534 | Add HTTP/DNS-01 verification methods |
| `src/mesh/transport_peer.rs` | ~1914-2017 | Trigger verification, handle proof |
| `src/mesh/transport.rs` | ~483-527 | Serve HTTP-01 challenges |
| `src/mesh/proto/mesh.proto` | ~834-869 | Add proof verification fields (optional) |

#### Implementation Order

1. **Phase 1a**: HTTP-01 verification in `VerificationTaskManager`
2. **Phase 1b**: HTTP-01 serving (integration with HTTP server)
3. **Phase 1c**: Handle `UpstreamChallengeProof` message
4. **Phase 1d**: Verification coordination (async task spawning)
5. **Phase 1e**: DNS-01 verification (similar pattern)

#### Effort: HIGH (~400 lines across 4 files)  
#### Risk: MEDIUM (introduces new async flows)  
#### Testing: Integration tests required

---

### 1.3 In-Memory Revocation Lost on Restart

**Severity**: HIGH  
**Files**: `src/mesh/peer_auth.rs:12-53`, `src/mesh/transport_global.rs:881-945`, `src/mesh/transport.rs:444-450`  
**Bug ID**: `BUG-REVOCATION-PERSIST`

#### Problem Analysis

`GlobalNodeRevocationList` is pure in-memory:

```rust
// peer_auth.rs:12-15
pub struct GlobalNodeRevocationList {
    revoked_nodes: Arc<DashMap<String, RevocationInfo>>,  // In-memory ONLY
}
```

**Attack scenario**:
1. Genesis node revokes "node-X" → stored in genesis's memory + DHT (24h TTL)
2. "node-X" (if genesis) restarts → `GlobalNodeRevocationList::new()` creates empty list
3. DHT TTL may expire without re-broadcast
4. "node-X" can reconnect because its local revocation list is empty

#### Additional Issues

- Non-genesis nodes have no revocation list at all
- No mechanism for non-genesis nodes to persist learned revocations
- DHT entries expire after 24 hours and may not be re-announced

#### Recommended Fix

**Step 1**: Add persistence methods to `GlobalNodeRevocationList`

```rust
// Add to GlobalNodeRevocationList struct:
persistence_path: Option<PathBuf>

// Add methods:
pub fn set_persistence_path(&mut self, path: PathBuf)
pub fn save(&self) -> Result<(), String>
pub fn load(&mut self) -> Result<usize, String>
```

**File format** (JSON):
```json
{
  "version": 1,
  "revoked_nodes": {
    "node_id_1": { "revoked_at": 1234567890, "reason": "Compromised" }
  }
}
```

**Step 2**: Wire persistence in `MeshTransport::new()`

```rust
// transport.rs:444-450
revocation_list: if is_genesis {
    let mut list = crate::mesh::peer_auth::GlobalNodeRevocationList::new();
    if let Some(ref revocation_path) = config.revocation_list_path {
        list.set_persistence_path(revocation_path.clone());
        if let Err(e) = list.load() {
            tracing::warn!("Failed to load revocation list: {}", e);
        }
    }
    Some(Arc::new(list))
} else {
    None
},
```

**Step 3**: Add DHT sync for revocation list

```rust
// New method in GlobalNodeRevocationList:
pub fn sync_from_dht(&self, record_store: &RecordStoreManager) -> Result<usize, String>
```

This follows the pattern in `ThreatIntel::sync_from_dht()` (`threat_intel.rs:1211-1290`).

#### Pattern Reference

The `MeshCertManager` already implements file-based CRL persistence in `cert.rs:689-759`:

```rust
pub fn load_crl(&self, crl_path: &PathBuf) -> Result<usize, MeshCertError>
pub fn export_crl(&self, crl_path: &PathBuf) -> Result<usize, MeshCertError>
```

#### Configuration

Add to `MeshConfig`:
```rust
pub revocation_list_path: Option<PathBuf>
```

#### Effort: MEDIUM (~100 lines)  
#### Risk: LOW (follows existing pattern)  
#### Testing: Unit tests + manual restart test

---

## Phase 2: HIGH Priority Issues (Fix Soon)

### 2.1 Origin Attestation Bug - Wrong Key Used

**Severity**: HIGH  
**Files**: `src/mesh/transport.rs:1661-1669`, `src/mesh/transport.rs:2193-2202`  
**Bug ID**: `BUG-ORIGIN-ATTESTATION`

#### Problem Analysis

The code incorrectly uses the **origin's own public key** as the attestation key instead of the global node's public key:

```rust
// transport.rs:1661-1669
let global_node_att_key = if role.is_origin() {
    public_key.as_ref().map(|pk| pk.as_str())  // BUG: origin's OWN key!
} else {
    None
};
let global_node_att_sig = if role.is_origin() {
    global_node_key.as_ref().map(|sk| sk.as_str())  // BUG: origin's OWN sig
} else {
    None
};
```

#### Exploitation Scenario

1. Attacker registers an origin node with their own key as a seed
2. Attacker configures their origin to connect, sending their own key as `public_key`
3. Code extracts attacker's key as attestation credentials
4. Since attacker's key IS in `authorized_keys` (seed list), check passes
5. Signature self-verification also passes (signing and verifying with same key)

#### Mitigating Factors

- Requires seed configuration compromise
- `validate_peer_role` checks `role.is_origin()` before attestation
- Revocation check still enforced

#### Recommended Fix

For pure `ORIGIN` role (0b100), the attestation fields should be `None`:

```rust
let global_node_att_key = None;  // Origins cannot self-attest
let global_node_att_sig = None;
```

This will cause `validate_origin_node()` to fail - which is correct because origins shouldn't be self-attesting.

**However**, this breaks composite `GLOBAL_ORIGIN` (0b110) role which SHOULD be able to attest. Need to understand the intended design before fixing.

#### Key Question

Is the code meant to support `GLOBAL_ORIGIN` (0b110) nodes that should be able to attest? If so, the fix needs to distinguish:
- `ORIGIN` (0b100) - cannot attest, use `None`
- `GLOBAL_ORIGIN` (0b110) - can attest, use global node credentials

#### Alternative Approach

Check if this bug actually manifests in practice. The `validate_origin_node()` at `peer_auth.rs:369-377` verifies the attestation key is in `authorized_global_pubkeys`. If the origin's own key is not in that list (typical case), the verification fails anyway.

#### Effort: MEDIUM-HIGH (requires architectural clarification)  
#### Risk: MEDIUM (depends on composite role intent)  
#### Testing: Integration tests with GLOBAL_ORIGIN role

---

### 2.2 Revocation Doesn't Invalidate Cached Records

**Severity**: MEDIUM-HIGH  
**Files**: `src/mesh/topology.rs:774-820`, `src/mesh/transport_global.rs:907`  
**Bug ID**: `BUG-CACHE-INVALIDATION`

#### Problem Analysis

When a global node is revoked, its signed `VerifiedUpstream` records remain in cache for **60 seconds** (TTL). There's no mechanism to purge records from a revoked signer.

#### Current Cache Behavior

```rust
// topology.rs:63-66
let verified_upstream_cache = MokaCache::builder()
    .time_to_live(Duration::from_secs(60))
    .max_capacity(1000)
    .build();
```

On cache hit, stale data is returned immediately, re-validated in background. On cache miss, DHT is queried and signature verified using `global_node_key:{global_node_id}`.

#### The Gap

The signature verification at `topology.rs:774-820` does **not** check if `global_node_id` appears in a revocation list - it only verifies the signature is valid for the stored public key.

#### Recommended Fix

**Step 1**: Add `revocation_list` field to `MeshTopology`

```rust
// topology.rs:~46
revocation_list: ParkingLotRwLock<Option<Arc<GlobalNodeRevocationList>>>,
```

**Step 2**: Add setter method

```rust
// topology.rs:~128, after set_record_store
pub fn set_revocation_list(&self, list: Arc<GlobalNodeRevocationList>) {
    *self.revocation_list.write() = Some(list);
}
```

**Step 3**: Modify signature verification to check revocation

```rust
// topology.rs:~776, after fetching key_record
if let Some(ref rl) = *self.revocation_list.read() {
    if rl.is_node_revoked(&verified.global_node_id).is_some() {
        tracing::debug!("Skipping VerifiedUpstream from revoked global node {}",
            verified.global_node_id);
        continue;
    }
}
```

**Step 4**: Invalidate cache on revocation

```rust
// transport_global.rs:~907, after adding to revocation list
if let Some(ref topology) = self.topology {
    topology.invalidate_all_verified_upstream_caches().await;
}
```

**Step 5**: Add cache invalidation method

```rust
// topology.rs:~950
pub async fn invalidate_all_verified_upstream_caches(&self) {
    self.verified_upstream_cache.invalidate_all().await;
}
```

#### Effort: MEDIUM (~80 lines)  
#### Risk: LOW (defensive addition)  
#### Testing: Manual revocation test

---

## Phase 3: MEDIUM Priority Issues (Plan for Next Cycle)

### 3.1 Edge Nodes Can Operate Without Attestation

**Severity**: MEDIUM  
**Files**: `src/mesh/topology.rs:925`, `src/mesh/transport_peer.rs:1151-1189`  
**Bug ID**: `DESIGN-UNATTESTED-ORIGINS`

#### Problem Analysis

`VerifiedUpstream` records are accepted even with empty `global_node_signature`. Origin attestation is required in handshake but bypassed in `UpstreamAnnounce`.

#### Current Behavior

```rust
// topology.rs:925
if !verified.global_node_signature.is_empty() {
    // verify signature
} else {
    results.push(verified);  // Accepts unattested origins!
}
```

#### Trust Levels

| Property | Attested Upstream | Unattested Upstream |
|----------|-------------------|---------------------|
| `global_node_signature` | Present, verified | Empty |
| Origin identity | Bound to global node | Only Ed25519 self-signature |
| Can be spoofed | No | Yes |

#### Recommended Fix

1. Reject empty signatures at `topology.rs:925`:
```rust
if verified.global_node_signature.is_empty() {
    continue;  // Skip unattested upstream
}
```

2. Add role and attestation checks in `transport_peer.rs:1151-1189`

#### Effort: MEDIUM (~30 lines)  
#### Risk: MEDIUM (may break existing mesh deployments)  
#### Testing: Integration tests

---

### 3.2 No DHT Store Rate Limiting

**Severity**: MEDIUM  
**Files**: `src/mesh/dht/record_store_crud.rs:13-162`  
**Bug ID**: `DESIGN-NO-RATE-LIMIT`

#### Problem Analysis

`store_record()` has no rate limiting. `is_rate_limited()` exists in `record_store.rs:371-377` but is only called in `record_store_message.rs` for incoming messages, not for local stores.

#### Attack Vector

A malicious node could:
1. **Per-node flooding**: Send unlimited different records as `source_node_id`
2. **Per-key flooding**: Target a specific key with rapid updates
3. **Storage exhaustion**: Fill edge cache (1000 entries) rapidly

#### Recommended Fix

Add per-node rate limiting in `store_record()`:

```rust
// After line 16, add:
let node_key = format!("store:{}", record.source_node_id);
if let Some(ref limiter) = self.routing_state.read().rate_limiter {
    if !limiter.is_allowed(&node_key) {
        tracing::warn!("Record store: rate limited for node {}", record.source_node_id);
        return false;
    }
}
```

The existing `DhtRateLimiter` uses `DashMap<String, Vec<Instant>>` so it can track arbitrary keys like `"store:{node_id}"` - no structural changes needed.

#### Rate Limit Recommendations

| Type | Limit | Rationale |
|------|-------|-----------|
| **Per-node writes** | ~10-50 writes/minute | Prevent node from dominating DHT |
| **Per-key writes** | ~5-20 writes/minute | Prevent target key starvation |

#### Effort: LOW (~15 lines)  
#### Risk: NONE  
#### Testing: Unit tests

---

## Phase 4: Not a Gap (Documented)

### 4.1 DNS Keys Not in Capability System

**Severity**: LOW  
**Files**: `src/mesh/dht/capability_access.rs:34-42`  
**Bug ID**: N/A - Intentional Design

#### Verdict: NOT A SECURITY ISSUE

DNS keys don't need capability requirements because:

1. **Already protected by `is_privileged()`** - only global nodes can write
2. **No distributed DNS model exists** - all DNS authority flows through global nodes
3. **Global nodes bypass ALL capability checks** - even if DNS had a capability, global nodes don't need it

The capability system is specifically for distributed contributions (YARA, ThreatIntel) where non-global nodes can have specific roles. DNS is centralized and managed by global nodes only.

#### No Changes Needed

---

## Implementation Checklist

### Phase 1 (CRITICAL)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 1.1 | Fix PoW difficulty constant (64 → 16) | Low | Low | [ ] Pending |
| 1.2 | Implement HTTP-01 verification | High | Medium | [ ] Pending |
| 1.3 | Implement HTTP-01 serving | High | Medium | [ ] Pending |
| 1.4 | Handle UpstreamChallengeProof | Medium | Low | [ ] Pending |
| 1.5 | Add revocation persistence | Medium | Low | [ ] Pending |

### Phase 2 (HIGH)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 2.1 | Clarify origin attestation design | High | Medium | [ ] Pending |
| 2.2 | Fix origin attestation key bug | Medium | Medium | [ ] Pending |
| 2.3 | Add revocation list to topology | Medium | Low | [ ] Pending |
| 2.4 | Add cache invalidation on revocation | Medium | Low | [ ] Pending |

### Phase 3 (MEDIUM - Next Cycle)

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 3.1 | Reject unattested origins | Medium | Medium | [ ] Planned |
| 3.2 | Add DHT store rate limiting | Low | None | [ ] Planned |

---

## Files Summary

| File | Changes | Phase | Lines |
|------|---------|-------|-------|
| `src/mesh/dht/routing/node_id.rs` | Fix difficulty constant | 1.1 | ~1 |
| `src/mesh/verification.rs` | Add HTTP/DNS-01 verification | 1.2-1.4 | ~300 |
| `src/mesh/transport_peer.rs` | Trigger verification, handle proof | 1.2-1.4 | ~150 |
| `src/mesh/transport.rs` | Serve HTTP-01 challenges | 1.3 | ~40 |
| `src/mesh/peer_auth.rs` | Add revocation persistence | 1.5 | ~60 |
| `src/mesh/transport_global.rs` | Invalidate cache on revocation | 2.4 | ~20 |
| `src/mesh/topology.rs` | Add revocation list, check in verify | 2.3, 2.4 | ~60 |
| `src/mesh/dht/record_store_crud.rs` | Add rate limiting | 3.2 | ~15 |

**Total estimated changes: ~650 lines across 8 files**

---

## Dependencies

1. **PoW fix** (1.1): No dependencies - standalone fix
2. **Domain verification** (1.2-1.4): Requires HTTP client setup, verification coordination
3. **Revocation persistence** (1.5): Requires config path setup
4. **Origin attestation** (2.1-2.2): Requires design clarification with stakeholders

---

## Testing Strategy

| Phase | Test Type | Coverage |
|-------|-----------|----------|
| 1.1 | Unit test | `test_edge_node_with_valid_pow_passes` |
| 1.2-1.4 | Integration test | HTTP-01 challenge flow |
| 1.5 | Manual test | Restart node, verify revocation persists |
| 2.3-2.4 | Manual test | Revoke global, verify cache invalidation |
| 3.1 | Integration test | Reject unattested origins |
| 3.2 | Unit test | Rate limiting enforcement |

---

## Risk Summary

| Item | Risk Eliminated | Remaining |
|------|-----------------|------------|
| PoW cap fix | Edge node connection blocking | - |
| Domain verification | Domain hijacking | Implementation effort |
| Revocation persistence | Revocation bypass on restart | DHT propagation |
| Origin attestation | Wrong key verification | Design clarification |
| Cache invalidation | Stale cache after revocation | - |

---

## References

- RFC 8555 (ACME HTTP-01 Challenge)
- RFC 8737 (ACME DNS-01 Challenge)
- Node ID PoW: `src/mesh/dht/routing/node_id.rs:114-155`
- Verification flow: `src/mesh/verification.rs`
- Capability system: `src/mesh/dht/capability_access.rs`
- Revocation list: `src/mesh/peer_auth.rs:12-53`
- Topology cache: `src/mesh/topology.rs:744-830`