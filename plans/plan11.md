# MaluWAF Mesh and DHT Architecture Review - Implementation Plan 11

**Status**: Active - Planning Phase
**Last Updated**: 2026-04-27
**Review Scope**: Mesh and DHT architecture, scalability, robustness, and security model

---

## Background

This plan addresses findings from a comprehensive review of the mesh and DHT system architecture. The review identified critical security vulnerabilities, scalability concerns, and robustness issues that need to be addressed to meet the 500K+ req/sec target and maintain strong security guarantees.

**Use Case Context** (per stakeholder requirements):
- Global nodes = primary source of truth/CA, run by the same entity
- Edge nodes = may be run by third parties
- All nodes can carry different flags/capabilities (edge, origin host, global)
- Roles are NOT mutually exclusive
- DNS server capability is restricted to global nodes only (enforced at multiple layers)

---

## Current Architecture Assessment

### Confirmed Security Model Strengths

The following security patterns are **correctly implemented** and should be preserved:

| Security Pattern | Implementation | Location |
|-----------------|-----------------|-----------|
| Edge nodes blocked from DNS serving | `can_serve_dns` returns false for non-global | `transport.rs:882-896` |
| DNS mesh mode enforcement | Non-global skips DNS binding when `dns_mesh_mode_only=true` | `dns/server/startup.rs:543` |
| Genesis key default deny | Empty `authorized_genesis_keys` = reject all | `config_identity.rs:222-233` |
| Composite role validation | Both role components validated for GLOBAL_EDGE, etc. | `peer_auth.rs:196-225` |
| Global-Origin signing separation | HTTP handler returns error when origin unreachable | `passover_key_exchange.rs:621-632` |
| Privileged key access control | Global node required for DnsZone, DnsRecord, etc. | `record_store_crud.rs:122-130` |
| Trusted signer for DHT-synced threats | Validated in `sync_from_dht()` | `threat_intel.rs:1296-1306` |

### Identified Issues Summary

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Security | 4 | 1 | 1 | 0 |
| Scalability | 0 | 3 | 1 | 1 |
| Robustness | 1 | 1 | 1 | 2 |
| **Total** | **5** | **5** | **3** | **3** |

---

## Phase 1: P0 Critical Security Fixes

**Target**: Complete within 1 week

### 1.1: Time-Based Challenge Solution Verification Bypass

**Severity**: Critical (Security)
**Complexity**: Low (~2 hours)
**File**: `src/mesh/security_challenge.rs:159-190`

**Issue**:
```rust
pub fn verify_time_based_challenge(&self, challenge_id: &str, _solution: &str) -> bool {
    // _solution is IGNORED - always returns true if challenge exists and not expired
    if let Some(c) = challenges.get_mut(challenge_id) {
        c.verified = true;
    }
    true
}
```

**Root Cause**: The `_solution` parameter (underscore prefix = intentionally unused) is never validated. The function sets `verified = true` and returns `true` for any non-expired challenge regardless of the solution provided.

**Expected Behavior**: Challenge format is `target_node:time_window:challenge_id` where `time_window = (elapsed_secs / 30) % 100`. The client must compute the same time_window and provide it as the solution.

**Impact**: Anyone can pass any non-empty string as a solution and have the challenge verified. The time-based challenge system provides zero security.

**Implementation Steps**:
1. Read the `challenge_data` field from the stored challenge
2. Parse the challenge string (format: `target_node:time_window:challenge_id`)
3. Extract `expected_time_window` from position [1]
4. Compare `solution` parameter against `expected_time_window`
5. Only set `verified = true` if they match
6. Log warning with actual vs expected on mismatch

**Verification**:
- Write unit tests for:
  - Valid solution matching time_window → returns true
  - Invalid solution → returns false
  - Expired challenge → returns false
  - Non-existent challenge → returns false
- Run `cargo test --lib security_challenge` after implementation

---

### 1.2: Threat Intel Trusted Signer Bypass

**Severity**: Critical (Security)
**Complexity**: Medium (~4 hours including testing)
**Files**: 
- `src/mesh/threat_intel.rs:1550-1630` (ThreatAnnounce handler)
- `src/mesh/threat_intel.rs:1681-1684` (ThreatSyncResponse handler)

**Issue 1 - ThreatAnnounce Handler (line 1607)**:
```rust
// Condition skips check if trusted_signers is empty
if !self.node_role.is_global() && !self.config.trusted_signers.is_empty() {
    // Only runs if trusted_signers is NON-empty
}
```

When `trusted_signers` is empty (the default configuration), the entire validation block is skipped, and no fallback check is performed.

**Issue 2 - ThreatSyncResponse Handler (line 1681)**:
```rust
MeshMessage::ThreatSyncResponse { indicators, .. } => {
    for indicator in indicators {
        self.handle_incoming_threat(indicator.clone(), from_node, from_role, signer);
    }
    None
}
```

No trusted signer validation is performed at all - directly calls `handle_incoming_threat`.

**Attack Vector**: A malicious node can send crafted `ThreatAnnounce` or `ThreatSyncResponse` messages to block/throttle arbitrary IP addresses on non-global nodes with default (empty) `trusted_signers` configuration. The attacker needs only a valid Ed25519 signature format - the content doesn't matter for the bypass.

**Correct Pattern (from `sync_from_dht()`, line 1296)**:
```rust
// Always runs for non-global nodes, has fallback when trusted_signers is empty
if !self.is_global_node() {
    let is_trusted = if !self.config.trusted_signers.is_empty() {
        self.check_trusted_signer(source_node_id, signer_public_key)
    } else {
        // Fallback: check if source is a known global node
        self.is_global_node(source_node_id)
    };
    // ... rejection if not trusted
}
```

**Implementation Steps**:
1. In `handle_mesh_message()` for `ThreatAnnounce`:
   - Add fallback check when `trusted_signers` is empty
   - When empty, verify source_node_id is a known global node
2. In `ThreatSyncResponse` handler:
   - Add trusted signer validation before calling `handle_incoming_threat`
   - Use same fallback pattern as ThreatAnnounce fix
3. Add integration test for ThreatAnnounce with empty trusted_signers

**Verification**:
- Write tests for:
  - ThreatAnnounce from non-global with empty trusted_signers and non-global source → rejected
  - ThreatAnnounce from non-global with empty trusted_signers but global source → accepted
  - ThreatAnnounce from non-global with populated trusted_signers and non-trusted signer → rejected
  - ThreatSyncResponse from non-global with non-trusted signer → rejected

---

### 1.3: Pass-Over Key Exchange Fallback Signing Violation

**Severity**: Critical (Security)
**Complexity**: Low (~1 hour)
**File**: `src/mesh/passover_key_exchange.rs:469-534`

**Issue**:
When the origin is unreachable, the gRPC handler falls back to signing with the origin's configured private key:

```rust
// Lines 481-534: FALLBACK SIGNING WITH ORIGIN'S KEY
let pending_signature = if let Some(ref signer_config) = self.config.origin_signing_key {
    if let Some(ref private_key) = signer_config.private_key {
        let signing_key = SigningKey::from_bytes(private_key);  // <-- USES ORIGIN'S KEY
        let signature = signing_key.sign(sign_message.as_bytes());
        // ...
    }
}
```

**Security Violation**: This violates the documented security invariant at line 6:
> "**GLOBAL NODE IS UNTRUSTED FOR ORIGIN SIGNING**"
> The global node MUST NOT sign on behalf of the origin.

**Correct Behavior** (HTTP handler, lines 621-632):
```rust
let origin_response = state.proxy_key_request_to_origin(...).await;
match origin_response {
    Ok(resp) => resp,
    Err(e) => {
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("Origin unavailable: {}. The global node cannot proxy to the origin.", e),
        ));
    }
};
```

Returns error to client instead of fallback signing.

**Implementation Steps**:
1. Remove the fallback signing block (lines 476-534)
2. Keep only the `proxy_key_request_to_origin` call
3. Return `Status::unavailable` if proxy fails
4. Add test for origin-unreachable scenario

**Verification**:
- Write test: Origin unreachable → gRPC returns unavailable error
- Existing tests for successful key exchange should still pass

---

### 1.4: RecordStoreManager Clone Creates Empty Store

**Severity**: Critical (Robustness)
**Complexity**: Low (~2 hours)
**File**: `src/mesh/dht/record_store.rs:468-519`

**Issue**:
```rust
impl Clone for RecordStoreManager {
    fn clone(&self) -> Self {
        let rs = self.record_state.read();
        let record_state = RecordStoreState {
            mesh_signer: rs.mesh_signer.clone(),
            record_signer: rs.record_signer.clone(),
            local_version: rs.local_version,
            records: ShardedRecordStore::new(),  // <-- BUG: Creates EMPTY store!
            pending_announces: rs.pending_announces.clone(),
            // ...
        };
    }
}
```

**Call Sites and Impact**:
| Location | Usage Pattern | Impact |
|----------|---------------|--------|
| `start_broadcast_timer()` (line 390) | Reads `pending_announces` (cloned correctly) | Works correctly |
| `store_record()` (line 836) | Uses routing/transport, not local records | Works correctly |
| `start_pruning_task()` (line 171) | Reads `self.record_state.read().records.iter()` | **Silently fails to find records to prune** |
| quorum request (line 240) | Uses routing state only | Works correctly |

**Root Cause**: Developer correctly cloned `pending_announces`, `merkle_tree`, etc., but accidentally used `ShardedRecordStore::new()` (empty) instead of `self.records.clone()`.

**Implementation Steps**:
1. Add `Clone` implementation for `ShardedRecordStore`:
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
2. Change `records: ShardedRecordStore::new()` to `records: self.records.clone()` in `RecordStoreManager::clone()`
3. Add test for Clone behavior

**Verification**:
- Write test: Clone should have identical records to original
- `start_pruning_task` on cloned manager should find records

---

## Phase 2: P1 High Priority Fixes

**Target**: Complete within 2 weeks

### 2.1: Message Cache Severely Undersized at 500K rps

**Severity**: High (Scalability)
**Complexity**: Low (~2 hours)
**File**: `src/mesh/transport.rs:239-244`

**Issue**:
```rust
LruCache::with_expiry_duration_and_capacity(
    Duration::from_secs(300),  // 5 min TTL
    10000,                     // SEVERELY UNDERSIZED
)
```

**Analysis at 500K rps**:
- At 10,000 mesh messages/sec, cache fills in ~1 second
- Effective deduplication window: ~1 second
- After that, retransmitted messages (QUIC retries, path flooding) are seen as "new"
- Duplicate detection hit rate drops to ~0% after cache churn

**Recommended Fix** - Use Moka cache:
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
| Hit rate at 500K rps | ~0% after 1s | ~99%+ |

**Implementation Steps**:
1. Add `moka` to `Cargo.toml` if not present: `moka = { version = "0.12", features = ["sync"] }`
2. Replace `use lru_time_cache::LruCache` with `use moka::sync::Cache`
3. Update `MeshTransport::new()` to use `Cache::builder()`
4. Add `get_message_cache_stats()` for monitoring
5. Apply same fix to `MeshTransportConnection` (line 47-51)

**Verification**:
- Load test at 500K rps with message retransmission
- Verify cache hit rate > 95%

---

### 2.2: Unbounded Proxy Task Spawn

**Severity**: High (Scalability/Resource Protection)
**Complexity**: Low (~2 hours)
**File**: `src/mesh/proxy.rs:962-997`

**Issue**:
```rust
for provider in &providers {
    tokio::spawn(async move {
        // ... proxy to peer ...
    });
}
```

No limit on concurrent spawned tasks. R concurrent requests × P providers = unbounded tasks.

**Worst Case**: 500K RPS with 10 providers = 5M concurrent tasks

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

**Note**: Codebase already uses semaphores in `unified_server.rs:830-847` (limit 10) and `tls/server.rs:176` (limit 10000).

**Implementation Steps**:
1. Add constant `MAX_CONCURRENT_PROVIDER_ATTEMPTS = 8`
2. Create semaphore at start of `proxy_to_peer_with_fallback()`
3. Acquire permit before spawning, release after completion
4. Add metrics for semaphore wait time

**Verification**:
- Load test with high provider count
- Verify max concurrent tasks stays bounded

---

### 2.3: Attestation Expiration and Revocation Not Checked

**Severity**: Medium (Trust Model Integrity)
**Complexity**: Medium (~4 hours)
**Files**: 
- `src/mesh/dht/capability_access.rs:47-83`
- `src/mesh/dht/capability_attestation.rs`

**Issue**:
`verify_capability_for_key()` doesn't check:
1. Whether the attesting global node is still authorized
2. Whether the attestation has expired (no `expires_at` field exists)
3. Whether the global node appears in any revocation list

**Window of Vulnerability**: Up to 24 hours after a global node is revoked, its previously-issued capability attestations can still be used.

**Current Attestation Structure**:
```rust
pub struct CapabilityAttestation {
    pub node_id: String,
    pub capability: String,
    pub attested_by_global_node: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    // NO expires_at field!
}
```

**Implementation Steps**:
1. Add `expires_at: u64` field to `CapabilityAttestation`
2. Add `is_expired()` method:
```rust
impl CapabilityAttestation {
    pub fn is_expired(&self) -> bool {
        let now = crate::mesh::safe_unix_timestamp();
        now > self.expires_at
    }
}
```
3. In `attest_capability()` (transport.rs:775-874), set expiration:
```rust
const ATTESTATION_VALIDITY_SECS: u64 = 86400 * 7; // 7 days
let expires_at = timestamp + ATTESTATION_VALIDITY_SECS;
```
4. Add expiration check in `verify_capability_for_key()`:
```rust
if att.is_expired() {
    tracing::warn!("Capability attestation for node {} expired at {}", node_id, att.expires_at);
    return false;
}
```
5. (Future) Check revocation list - requires architecture change to pass revocation_list

**Verification**:
- Write test: expired attestation → rejected
- Write test: valid attestation → accepted

---

### 2.4: Clock Skew / Conflict Resolution for Network Partitions

**Severity**: High (Robustness)
**Complexity**: Medium-High
**Files**: 
- `src/mesh/dht/record_store_crud.rs:318-333`
- `src/mesh/protocol.rs:1447-1457`

**Issue**: Timestamp-based Last-Write-Wins without CRDT or vector clocks.

**Current Conflict Resolution**:
```rust
let should_replace = match rs.records.get(&record.key) {
    None => true,
    Some(existing_entry) => {
        let existing_key = (
            existing_entry.record.timestamp,    // Wall-clock, vulnerable to skew
            existing_entry.record.sequence_number,  // Hollow - not incremented
            existing_entry.record.source_node_id.clone(),
        );
        let new_key = (record.timestamp, record.sequence_number, record.source_node_id.clone());
        new_key > existing_key  // Last-Write-Wins
    }
};
```

**Vulnerabilities**:
1. Clock skew can cause incorrect winner in split-brain scenarios
2. No causal ordering - concurrent updates from different nodes cannot be distinguished
3. `sequence_number` appears to be passed by caller but not actually incremented on update
4. No history retention - losing value is discarded entirely

**Recommendations**:

**Short-term - Clock Offset Tracking**:
Track clock offsets per peer and adjust timestamps before comparison:
```rust
pub struct PeerClockState {
    peer_id: String,
    offset_ms: i64,  // My time - peer time
    last_updated: u64,
}
```

**Medium-term - Hybrid Logical Clocks (HLC)**:
```rust
pub struct HybridClock {
    wall_time: u64,    // Physical time
    logical: u64,       // Monotonic counter for same-node events
    node_id: u64,       // Node identifier for tiebreaker
}

impl HybridClock {
    pub fn now(node_id: u64) -> Self;
    pub fn tick(&mut self) -> Self;  // Same node, concurrent event
    pub fn receive(&mut self, other: &HybridClock) -> Self;  // Update on receive
}
```

**Implementation Steps** (Short-term):
1. Add `PeerClockState` struct to track clock offsets
2. Collect offset samples during peer health checks
3. Use median offset to adjust timestamps before conflict resolution
4. Log warning when clock skew exceeds threshold

**Verification**:
- Simulate clock skew in test
- Verify correct winner selection

---

## Phase 3: P2 Medium Priority Improvements

**Target**: Complete within 1 month

### 3.1: O(k×n) DHT Lookup Complexity

**Severity**: Medium (Scalability)
**Complexity**: High
**File**: `src/mesh/dht/routing/bucket.rs:233-278`

**Issue**: `find_closest()` iterates all buckets with O(k×n) complexity:
```rust
let mut candidates: Vec<(PeerContact, NodeId)> = Vec::with_capacity(k * 2);
// ... O(n) iteration with manual max tracking
candidates.retain(|(_, d)| d != &max_dist); // O(n) operation!
```

**Recommendation**: Optimize to O(log n) using bucket-level indexing.

**Defer Rationale**: At current scale (256 buckets × 20 peers = 5,120 max entries), the overhead is acceptable. This becomes critical at 10x or 100x scale.

---

### 3.2: Quorum Timeout Hardcoded to 10 Seconds

**Severity**: Low (Operational)
**Complexity**: Low
**File**: `src/mesh/dht/quorum.rs:113`

**Issue**: `deadline: now + 10` is hardcoded with no configuration option.

**Recommendation**: Make configurable via `MeshDhtConfig`.

**Defer Rationale**: 10 second default is reasonable for most deployments. Can be made configurable when users report issues.

---

### 3.3: Veto Abuse Score Never Applied

**Severity**: Low (Robustness)
**Complexity**: Medium
**File**: `src/mesh/dht/quorum.rs:293`

**Issue**: `get_veto_abuse_score()` calculates a score but it's never used to reject future requests from abusive nodes.

**Recommendation**: Apply veto limits based on abuse score. Nodes exceeding threshold cannot issue vetoes for a cooldown period.

**Defer Rationale**: Veto abuse not currently observed in production. Can implement when abuse is detected.

---

## Summary Table

| ID | Issue | Priority | Complexity | Est. Time | Files |
|----|-------|----------|------------|-----------|-------|
| 1.1 | Time-based challenge ignores solution | Critical | Low | ~2 hrs | security_challenge.rs:159-190 |
| 1.2 | Threat intel trusted signer bypass | Critical | Medium | ~4 hrs | threat_intel.rs:1550-1630,1681 |
| 1.3 | Pass-over fallback signs as origin | Critical | Low | ~1 hr | passover_key_exchange.rs:469-534 |
| 1.4 | Clone creates empty record store | Critical | Low | ~2 hrs | record_store.rs:468-519 |
| 2.1 | Message cache 10K too small at 500K rps | High | Low | ~2 hrs | transport.rs:239-244 |
| 2.2 | Unbounded proxy task spawn | High | Low | ~2 hrs | proxy.rs:962-997 |
| 2.3 | Attestation no expiration check | Medium | Medium | ~4 hrs | capability_access.rs, attestation |
| 2.4 | Timestamp LWW vulnerable to clock skew | High | Medium-High | ~8 hrs | record_store_crud.rs:318-333 |
| 3.1 | O(k×n) DHT lookup | Medium | High | Deferred | bucket.rs:233-278 |
| 3.2 | Hardcoded quorum timeout | Low | Low | Deferred | quorum.rs:113 |
| 3.3 | Veto abuse score unused | Low | Medium | Deferred | quorum.rs:293 |

---

## Implementation Order Recommendation

### Week 1
1. **1.1 + 1.3** (both Critical, both Low complexity = ~3 hours total)
2. **1.2** (Critical, Medium complexity = ~4 hours)
3. **1.4** (Critical, Low complexity = ~2 hours)

### Week 2
4. **2.1** (High, Low complexity = ~2 hours) - immediate scalability improvement
5. **2.2** (High, Low complexity = ~2 hours) - resource protection
6. **2.3** (Medium, Medium complexity = ~4 hours) - trust model integrity

### Week 3-4
7. **2.4** (High, Medium-High complexity = ~8 hours) - partition handling

### Deferred (Phase 3)
- 3.1, 3.2, 3.3 when scale warrants or issues observed

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib security_challenge
cargo test --lib threat_intel
cargo test --lib passover_key_exchange
cargo test --lib record_store

# Run integration tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

---

## Dependencies and Risks

### Dependencies
- P0 fixes are independent of each other
- P1.2 (cache) depends on moka crate availability
- P1.4 (clock skew) is independent

### Risks
- P1.2: Moka cache may have different eviction characteristics - test thoroughly
- P1.4: Clock offset tracking may add latency to conflict resolution - benchmark after implementation

---

## References

- Mesh DHT Review: `plans/mesh_dht_review.md`
- Main Plan: `plans/plan.md`
- Security Model: AGENTS.md sections on Trusted Signer Verification, Composite Role Validation, Genesis Key Default Deny, DNS Mesh Mode Enforcement

---

## Appendix A: Line Number Caveats

Line numbers in this plan were accurate as of 2026-04-27 based on code exploration. They may become stale if files are modified. Use the following search patterns to locate code:

| Item | Search Pattern | File |
|------|---------------|------|
| 1.1 | `fn verify_time_based_challenge` | security_challenge.rs |
| 1.2 | `ThreatAnnounce` handler in `handle_mesh_message` | threat_intel.rs |
| 1.2 | `ThreatSyncResponse` handler | threat_intel.rs |
| 1.3 | `GLOBAL NODE IS UNTRUSTED` comment | passover_key_exchange.rs |
| 1.4 | `impl Clone for RecordStoreManager` | record_store.rs |
| 2.1 | `seen_messages` field | transport.rs |
| 2.2 | `proxy_to_peer_with_fallback` | proxy.rs |
| 2.3 | `verify_capability_for_key` | capability_access.rs |
| 2.4 | `should_replace` in conflict resolution | record_store_crud.rs |

---

## Appendix B: Test Infrastructure Gaps

The following modules have NO test coverage and need tests added:

| Module | Current Test Status | Priority |
|--------|--------------------|----------|
| `security_challenge.rs` | No tests exist | High (required for 1.1) |
| `threat_intel.rs` | Partial (DHT sync tests) | High (required for 1.2) |
| `passover_key_exchange.rs` | Has tests but missing origin-unreachable case | Medium |
| `record_store.rs` | Has tests for DhtRecordStore, not RecordStoreManager | Medium |

---

## Appendix C: Security Review Scope Details

### Files Explored
- `src/mesh/` - All modules (70+ modules)
- `src/mesh/dht/` - All DHT modules
- `src/mesh/dht/routing/` - K-bucket routing table
- `src/mesh/transports/` - QUIC transport
- `src/dns/trust_anchor.rs` - RFC 5011 implementation

### Security Patterns Verified (Correct)
1. Edge nodes blocked from DNS serving - `transport.rs:882-896`
2. DNS mesh mode only for global - `dns/server/startup.rs:543`
3. Genesis key default deny - `config_identity.rs:222`
4. Composite role validation - `peer_auth.rs:196-225`
5. Global-Origin signing separation (HTTP) - `passover_key_exchange.rs:621-632`
6. Privileged keys require global - `record_store_crud.rs:122-130`
7. Trusted signer for DHT threats - `threat_intel.rs:1296-1306`

### Security Vulnerabilities Found (Need Fix)
1. Time-based challenge ignores solution - `_solution` parameter unused
2. Threat intel trusted signer bypass - Empty `trusted_signers` skips check
3. Pass-over fallback signs as origin - gRPC handler fallback violation
4. Attestation has no expiration - Revoked global attestations persist 24h

---

## Appendix D: Architectural Decisions Made

### Why DNS Capability is Restricted to Global Nodes
- DNS serving requires trust anchor management (RFC 5011)
- Trust anchors are managed by global nodes (same entity)
- Edge nodes are potentially run by third parties
- Multiple layers of enforcement: transport capability check + startup binding check

### Why Composite Roles Validate Both Components
- GLOBAL_EDGE node must satisfy BOTH global AND edge validation
- Prevents hybrid nodes from bypassing either role's security requirements
- Example: GLOBAL_EDGE still requires PoW validation for edge portion

### Why Quorum is 2/3 + 1
- Standard Byzantine fault tolerance threshold
- With N global nodes, can tolerate floor((N-1)/3) faulty nodes
- 2/3 required ensures majority agreement

---

## Appendix E: Glossary

| Term | Definition |
|------|------------|
| LWW | Last-Write-Wins - Conflict resolution strategy |
| CRDT | Conflict-free Replicated Data Type |
| HLC | Hybrid Logical Clock - Clock that maintains causality |
| Quorum | Minimum number of nodes required to approve an operation |
| DHT | Distributed Hash Table |
| K-bucket | Kademlia bucket - routing table structure with K entries |
| PoW | Proof-of-Work - Anti-spam mechanism for edge node registration |
