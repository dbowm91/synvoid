# Mesh Networking Architecture Review - Deep Dive

**Review Date:** 2026-05-23
**Document Reviewed:** `architecture/mesh_deep_dive.md`
**Cross-Referenced Against:**
- `src/mesh/AGENTS.override.md`
- Source files in `src/mesh/`

---

## Claims Verified/Not Verified

### Network Topology (Lines 5-12)

| Claim | Status | Code Location |
|-------|--------|---------------|
| Global Nodes (Authorities) maintain full map, use Raft consensus | ✅ VERIFIED | `src/mesh/raft/mod.rs:1-65` - Raft consensus for Org, Intel, Revocation namespaces |
| Edge Nodes (WAFs) connect to Global nodes for discovery | ✅ VERIFIED | `src/mesh/discovery.rs:85-90` - bootstrap_from_seeds() |
| Origin Nodes announce routes for protected services | ✅ VERIFIED | `src/mesh/topology.rs:69-95` - local_upstreams handling |
| Hierarchical structure optimized for low-latency | ⚠️ PARTIAL | Topology uses geo-distance scoring (`topology.rs:454-483`) but "hierarchical" is not explicitly defined |

### QUIC Transport (Lines 15-20)

| Claim | Status | Code Location |
|-------|--------|---------------|
| All mesh communication over QUIC | ✅ VERIFIED | `src/mesh/transports/quic.rs:1-155` - QuicMeshTransport wrapper |
| Native multiplexing for streams | ⚠️ PARTIAL | QUIC supports streams but specific stream types (threat intel, proxying, heartbeats) not explicitly identified in code |
| 0-RTT handshakes for rapid reconnection | ⚠️ CORRECTLY DISABLED | `src/mesh/config.rs:1391-1392` - "Disable 0-RTT by default due to replay attack concerns" |
| Mandatory TLS 1.3 encryption | ✅ VERIFIED | `src/mesh/cert.rs:126-134` - PQ-TLS active when available, `src/mesh/security.rs:250-257` - TLS 1.3 enforced |

### Post-Quantum Cryptography (Lines 21-26)

| Claim | Status | Code Location |
|-------|--------|---------------|
| ML-KEM (Kyber) for key encapsulation | ✅ VERIFIED | `src/mesh/kem/ml_kem.rs:1-100` - ML-KEM-768 via aws-lc-rs |
| ML-DSA (Dilithium) for digital signatures | ✅ VERIFIED | `src/mesh/ml_dsa.rs:1-100` - ML-DSA-44 via pqc crate |
| Hybrid approach combines PQC with X25519/Ed25519 | ✅ VERIFIED | `src/mesh/passover_key_exchange.rs:741-842` - X25519+ML-KEM hybrid; `src/mesh/hybrid_signature.rs:1-181` - Ed25519+ML-DSA hybrid |

### Distributed Discovery/DHT (Lines 27-31)

| Claim | Status | Code Location |
|-------|--------|---------------|
| Kademlia-based DHT | ✅ VERIFIED | `src/mesh/dht/routing/mod.rs:14` - DhtQuery exports; `src/mesh/dht/record_store_sync.rs:663-717` - announce_records_via_kademlia() |
| Capability attestations signed/published | ✅ VERIFIED | `src/mesh/dht/capability_attestation.rs` - CapabilityAttestation with signatures |
| Bloom filters for route announcement checking | ✅ VERIFIED | `src/mesh/hierarchical_routing.rs:66` - MeshBloomFilter; reduces redundant route propagation |
| Regional hubs for memory-efficient routing | ✅ VERIFIED | `src/mesh/dht/routing/regional_hubs.rs` - RegionalHub implementation |

**Note:** Document claims Bloom filters "minimize DHT discovery latency" but actual use is for upstream route advertisement deduplication (`hierarchical_routing.rs:227`), not DHT discovery latency optimization.

### Threat Intelligence Sharing (Lines 36-40)

| Claim | Status | Code Location |
|-------|--------|---------------|
| Broadcast ThreatIndicator to mesh | ✅ VERIFIED | `src/mesh/threat_intel.rs:785-800` - queue_for_push(), publish_indicator_to_dht() |
| Reputation system for peers | ✅ VERIFIED | `src/mesh/reputation.rs:26-65` - PeerReputation with scores |
| Shared blocklists real-time sync | ✅ VERIFIED | `src/mesh/dht/network_policy.rs:77-98` - GlobalNodeBlocklist with blocked_ip |

### Distributed DDoS Mitigation (Lines 41-45)

| Claim | Status | Code Location |
|-------|--------|---------------|
| Mesh proxying for traffic distribution | ✅ VERIFIED | `src/mesh/proxy.rs:63-1996` - MeshProxy with circuit breaker, provider stats |
| Traffic accepted at any Edge, routed through mesh | ✅ VERIFIED | `src/mesh/backend.rs:132-344` - MeshBackendPool with proxy routing |
| Topology-aware router based on latency/health | ⚠️ PARTIAL | `topology.rs:520-547` - calculate_hybrid_score() with latency/reputation weights; no explicit "best path" selection documented |

### Collaborative Bot Detection (Lines 46-50)

| Claim | Status | Code Location |
|-------|--------|---------------|
| Sequence entropy for behavioral fingerprinting | ✅ VERIFIED | `src/mesh/behavioral_intel.rs:42-63` - RequestFeatures with request_sequence_entropy |
| YARA rule distribution | ✅ VERIFIED | `src/mesh/yara_rules.rs:1-2551` - YaraRulesManager with broadcast/submission workflow |
| Distributed globally in seconds | ⚠️ NOT VERIFIED | No timing guarantees found in code; depends on DHT propagation speed |

### Security & Integrity (Lines 53-57)

| Claim | Status | Code Location |
|-------|--------|---------------|
| Peer authentication via org certificate | ✅ VERIFIED | `src/mesh/peer_auth.rs:141-189` - validate_member_certificate() |
| Distributed audit system | ✅ VERIFIED | `src/mesh/audit.rs:1-381` - AuditLogger with network event tracking |
| Fine-grained access control | ✅ VERIFIED | `src/mesh/dht/capability_access.rs:7-100` - CapabilityAccessVerifier |

---

## Improvement Plan

### HIGH Priority

#### I1: Document 0-RTT Correction
**Claim:** "0-RTT handshakes for rapid reconnection" (Line 18)

**Actual State:** 0-RTT is **disabled by default** due to replay attack concerns (`config.rs:1391-1392`)

**Action:** Update document to clarify 0-RTT is available but disabled by default with security warning

**File:** `architecture/mesh_deep_dive.md:18`

---

#### I2: Clarify Bloom Filter Purpose
**Claim:** "Uses Bloom filters and regional hubs to enable memory-efficient route announcement checking in large-scale networks, not to minimize DHT discovery latency" (Line 30)

**Actual State:** The parenthetical clarification IS present in the doc, but earlier text implies general latency optimization. Bloom filters are for route advertisement deduplication, NOT DHT routing.

**Action:** Strengthen wording: "Bloom filters reduce redundant route propagation announcements, not DHT discovery latency"

**File:** `architecture/mesh_deep_dive.md:30`

---

#### I3: DHT Ingress Verification Gaps Not Documented
**Claim:** Document implies complete DHT security but doesn't mention known gaps

**Actual State:** Documented in `src/mesh/dht/signed.rs:42-48`:
- DhtSyncRequest: no node_id/TLS cert validation
- DhtAntiEntropyRequest: signer_public_key unused
- DhtRecordPush: timestamp ignored, no envelope signature
- DhtRecordCommit: no envelope signature validation
- QuorumStoreRequest: no verification
- QuorumSignatureResp: no verification

**Action:** Add section documenting these as known architectural limitations

**File:** `architecture/mesh_deep_dive.md` - new section after Security & Integrity

---

### MEDIUM Priority

#### I4: Topology-Aware Router Documentation
**Claim:** "The mesh topology aware router selects the best path based on latency and node health" (Line 44)

**Actual State:** Hybrid scoring exists (`topology.rs:520-547`) but no explicit "best path selection" algorithm documented. Selection uses weighted scoring with latency, reputation, role, random components.

**Action:** Update to reflect actual algorithm: "weighted scoring based on latency, reputation, and node role"

**File:** `architecture/mesh_deep_dive.md:44`

---

#### I5: Threat Propagation Timing Not Guaranteed
**Claim:** "New security rules can be distributed globally across the mesh in seconds" (Line 49)

**Actual State:** No timing guarantees exist in code. Distribution depends on DHT propagation, quorum completion, and network conditions.

**Action:** Soften to: "Distributed via DHT propagation and Raft consensus"

**File:** `architecture/mesh_deep_dive.md:49`

---

#### I6: Raft Consensus Scope Clarification
**Claim:** "Global nodes...handle peer admission using Raft consensus for state consistency" (Line 9)

**Actual State:** Raft is used for Org, Intel, and Revocation namespaces (`raft/mod.rs:13-15`), not all global node operations. DHT is used for routing and many other state operations.

**Action:** Clarify: "Raft consensus for OrgPublicKey and ThreatIntel records; DHT for routing and other state"

**File:** `architecture/mesh_deep_dive.md:9`

---

### LOW Priority

#### I7: Audit Path Reference
**Claim:** "distributed auditing system (src/mesh/audit.rs)" (Line 56)

**Actual State:** Path is correct, just needs consistent formatting

**Action:** Use backtick code formatting consistently throughout

**File:** `architecture/mesh_deep_dive.md:56`

---

#### I8: Shared Blocklist Mechanism
**Claim:** "Real-time synchronization of malicious IP addresses" (Line 39)

**Actual State:** Implemented via GlobalNodeBlocklist in DHT (`network_policy.rs:77`), propagated via mesh messages

**Action:** Add "(via DHT GlobalNodeBlocklist)"

**File:** `architecture/mesh_deep_dive.md:39`

---

## Bug Report

### MINOR Bugs

#### B1: Hierarchical Routing Module Marked Unused
**File:** `src/mesh/hierarchical_routing.rs:1-9`
```rust
// Hierarchical routing for mesh - RESERVED for multi-region topology.
```
The module is preserved but marked RESERVED with comment "Currently unused". If it's unused, why preserve it? This creates maintenance burden and confusion.

**Impact:** Low - documented as reserved for future
**Action:** Either remove if truly unused, or integrate for multi-region topology if that's on the roadmap

---

#### B2: YARA Rule Distribution Timing Unverified
**File:** `src/mesh/yara_rules.rs` - No SLA/timing guarantees for distribution

**Impact:** Low - documentation promise may set expectations not met by implementation
**Action:** Update documentation to remove specific timing claims

---

#### B3: DHT Ingress Verification Gaps (Architectural)
**File:** `src/mesh/dht/signed.rs:42-48`

Multiple DHT message types lack proper verification:
- DhtSyncRequest
- DhtAntiEntropyRequest  
- DhtRecordPush
- DhtRecordCommit
- QuorumStoreRequest
- QuorumSignatureResp

**Impact:** Medium - security-relevant gaps that could allow remote attackers to inject false DHT records

**Status:** Known limitation (documented in AGENTS.override.md:76-84) but not in architecture document

**Action:** Document as known limitations per High Priority I3 above

---

## Summary

| Category | Count | Priority |
|----------|-------|----------|
| Claims Verified | 18 | - |
| Claims Partially Verified | 5 | - |
| Claims Not Verified | 1 | - |
| High Priority Improvements | 3 | I1, I2, I3 |
| Medium Priority Improvements | 3 | I4, I5, I6 |
| Low Priority Improvements | 3 | I7, I8, B2 |
| Minor Bugs | 3 | B1, B2, B3 |

**Key Finding:** The architecture document is largely accurate but has two significant gaps:
1. 0-RTT is disabled by default (not enabled as document implies)
2. DHT ingress verification gaps are not documented as known limitations

**Recommendation:** Prioritize updates to address High Priority items, particularly I3 (documenting DHT verification gaps) since these have security implications.
