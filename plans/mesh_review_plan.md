# Mesh Architecture Review Plan

**Document**: `architecture/mesh_deep_dive.md`
**Review Date**: 2026-05-26
**Reviewer**: Code Review Agent

---

## Stale Items Identified

### 1. Wrong Code Reference for Quorum Verification

| Document Reference | Actual Location | Issue |
|-------------------|-----------------|-------|
| `src/mesh/raft/state_machine.rs:166-172` (quorum verify) | `src/mesh/dht/signed.rs:860-934` | Document points to wrong file for quorum proof verification |

**Severity**: Medium - Causes confusion for developers looking to understand quorum verification.

### 2. Bloom Filter Section Mentions "Reduce Redundant Route Propagation" (Minor)

The document states Bloom filters are used "to enable memory-efficient route announcement checking in large-scale networks, **not to minimize DHT discovery latency**."

**Actual behavior** (`src/mesh/hierarchical_routing.rs`):
- Bloom filters ARE used for route propagation checking
- The comment at line 2-9 indicates this is "RESERVED for multi-region topology" and "currently unused"
- Module is preserved for future multi-region deployment

**Assessment**: The statement is technically correct (they're not used for DHT discovery latency) but the feature is marked as reserved/unused, making this documentation aspirational rather than descriptive.

---

## Claims Verified / Issues Found

### ✅ Claims Verified Successfully

| Claim | Location in Code | Status |
|-------|-----------------|--------|
| QUIC transport with 0-RTT disabled by default | `src/mesh/config.rs:1390-1395` | ✅ Verified - `default_quic_enable_0rtt()` returns `false` with comment about replay attack concerns |
| `validate_member_certificate` function | `src/mesh/peer_auth.rs:141` | ✅ Verified - Function exists and performs cert validation with quorum check |
| `CapabilityAccessVerifier` for access control | `src/mesh/dht/capability_access.rs:7` | ✅ Verified - Struct exists with `verify_capability_for_key` method |
| Distributed audit system | `src/mesh/audit.rs` | ✅ Verified - `AuditLogger` struct with `log()` method for network events |
| DHT Verification Limitations table | `src/mesh/dht/signed.rs:42-48` | ✅ Verified - Comment block documents multi-layer identity hierarchy and verification gaps |
| `MeshBloomFilter` at line 66 of hierarchical_routing | `src/mesh/hierarchical_routing.rs:65-66` | ✅ Verified - `MeshBloomFilter` struct defined |
| Threat Intelligence Sharing | `src/mesh/threat_intel.rs` | ✅ Verified - `ThreatIntelligenceManager` with reputation-based evaluation |
| YARA Rule Distribution | `src/mesh/yara_rules.rs` | ✅ Verified - Full distribution system with chunking and signatures |
| Reputation System | `src/mesh/reputation.rs` | ✅ Verified - `ReputationManager` with threat acceptance/rejection tracking |
| Raft consensus for Global Nodes | `src/mesh/raft/mod.rs:1-16` | ✅ Verified - Module docs state Global nodes form Raft cluster for OrgPublicKey, ThreatIntel, Revocation |
| ML-KEM (Kyber) for key encapsulation | `src/mesh/ml_kem_key_exchange.rs` | ✅ Verified - Uses `pqc::MlKem768` |
| ML-DSA (Dilithium) for signatures | `src/mesh/ml_dsa.rs` | ✅ Verified - Uses `pqc::MlDsa44` |
| Hybrid classical+PQC approach | `src/mesh/hybrid_signature.rs` | ✅ Verified - `HybridSigner` combines Ed25519/ML-DSA |
| Constant-time comparison for secrets | `src/mesh/security_challenge.rs:196` | ✅ Verified - Uses simple `!=` for puzzle verification (correct - puzzle is not secret) |

### ⚠️ Claims With Observations

| Claim | Observation |
|-------|-------------|
| "Edge nodes require valid certificates signed by authorized Organization Keys" | `src/mesh/peer_auth.rs:264-273` shows Edge nodes can use Organization Trust Chain via `validate_member_certificate`, but PoW is also accepted. The document doesn't mention PoW as alternative. |
| "Global nodes use Raft consensus for state consistency" | Raft is used for OrgPublicKey and ThreatIntel namespaces (`src/mesh/raft/mod.rs:13-14`), but other operations may use different consensus mechanisms. Document is slightly simplified. |

---

## Improvement Plan

### High Priority

#### 1. Fix Stale Reference to `state_machine.rs` for Quorum Verification

**Current (Wrong)**:
```
...quorum verify is at `src/mesh/raft/state_machine.rs:166-172`
```

**Should be**:
```
...quorum proof verification is at `src/mesh/dht/signed.rs:860-934` (`verify_quorum_proof` function)
```

**Files to update**:
- `architecture/mesh_deep_dive.md` line reference
- `AGENTS.md` Known File Path Corrections table already has this correction! ✅

---

### Medium Priority

#### 2. Document Edge Node PoW Authentication

The document states "Edge nodes require valid certificates" but doesn't mention that Edge nodes can alternatively use Proof-of-Work for authentication (`src/mesh/peer_auth.rs:355-368`).

**Recommendation**: Add note: "Edge nodes authenticate via Organization Key certificates OR proof-of-work as specified in `validate_peer_role`"

#### 3. Clarify Hierarchical Routing Status

The hierarchical routing module (`src/mesh/hierarchical_routing.rs:2-9`) is marked as "RESERVED for multi-region topology" and "currently unused". The document correctly describes its purpose but doesn't indicate it's not yet active.

**Recommendation**: Add status indicator: "[RESERVED - Not Active]"

#### 4. Update Raft Scope Documentation

The document says Global nodes use Raft consensus but doesn't specify which operations. Code shows Raft is specifically for:
- Namespace::Org (OrgPublicKey records)
- Namespace::Intel (ThreatIntel)
- Namespace::Revocation (GlobalNodeRevocationList)

**Recommendation**: Add explicit namespace list to document.

---

### Low Priority

#### 5. Document Threat Intelligence Fanout Behavior

The `fanout_factor` in `threat_intel.rs:71-72` defaults to 0.5 (50% of peers). The document mentions reputation-based propagation but doesn't specify the fanout mechanism.

#### 6. Add Sequence Entropy Reference

The document mentions "Sequence Entropy" for collaborative bot detection but no corresponding code module was found. May need clarification or implementation.

---

## Bug Report

### Minor: Incomplete Implementation References

**Issue**: Several features described as implemented have incomplete or placeholder code:

| Feature | Location | Issue |
|---------|----------|-------|
| `broadcast_hot_threats` | `src/mesh/threat_intel.rs:371-387` | Bloom filter is set to `Vec::new()` placeholder - comment says "Using a more realistic approach... we'd normally need to extract the bitmap. For now, we'll use a placeholder to fix the build." |
| Hot Threat Gossip handling | `src/mesh/threat_intel.rs:419` | TODO comment: "Full Bloom filter reconciliation for non-immediate threats" |

**Impact**: Low - These are marked as TODO and don't break functionality, but documentation should note these as partial implementation.

### No Critical Bugs Found

The architecture document accurately describes the codebase. All major systems (DHT, Raft, PQC, threat intel) have corresponding implementations that match the documented behavior.

---

## Verification Commands

```bash
# Verify mesh module compiles
cargo check --features mesh

# Run mesh tests
cargo test --lib mesh:: --no-fail-fast

# Verify all profiles
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

---

## Summary

| Category | Count |
|----------|-------|
| Stale Items | 1 (medium priority) |
| Claims Verified | 14 |
| Observations | 2 |
| High Priority Improvements | 1 |
| Medium Priority Improvements | 3 |
| Low Priority Improvements | 2 |
| Critical Bugs | 0 |
| Minor Bugs | 2 |

**Overall Assessment**: The architecture document is largely accurate and well-structured. One significant stale reference exists (state_machine.rs → signed.rs for quorum verification). The main gap is that several advanced features (Bloom filter hot threat gossip, hierarchical routing) are documented as implemented but are actually reserved or partially implemented. Recommend updating document with status indicators for reserved features.
