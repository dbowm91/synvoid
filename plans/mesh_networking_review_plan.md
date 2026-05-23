# Mesh & Networking Architecture Review - Improvement Plan

**Review Date:** 2026-05-23
**Documents Reviewed:**
- `architecture/mesh_deep_dive.md`
- `architecture/networking_deep_dive.md`
**Cross-Referenced Against:**
- `AGENTS.md` (root)
- `src/mesh/AGENTS.override.md`

---

## Verified Correct Items

### Mesh Document
| Claim | Status | Notes |
|-------|--------|-------|
| QUIC transport for mesh | ✅ Verified | `src/mesh/transports/quic.rs` + `src/mesh/transport.rs` use quinn |
| PQC: ML-KEM (Kyber) | ✅ Verified | `pqc/src/kem.rs`, `src/mesh/kem/ml_kem.rs` |
| PQC: ML-DSA (Dilithium) | ✅ Verified | `pqc/src/dsa.rs`, `src/mesh/ml_dsa.rs` |
| Hybrid Ed25519+ML-DSA | ✅ Verified | `src/mesh/hybrid_signature.rs` |
| DHT via Kademlia | ✅ Verified | `src/mesh/dht/routing/mod.rs:14` references DhtQuery, Kademlia mention at `record_store_sync.rs:673` |
| Bloom filters for routing | ✅ Verified | `src/mesh/hierarchical_routing.rs:66` MeshBloomFilter |
| Regional hubs | ✅ Verified | `src/mesh/dht/routing/regional_hubs.rs` |
| Audit system | ✅ Verified | `src/mesh/audit.rs` exists with AuditEvent types |
| Distributed auditing | ✅ Verified | `audit.rs` supports network events |
| Reputation system | ✅ Verified | `src/mesh/reputation.rs` with PeerReputation |
| Raft consensus for Global nodes | ✅ Verified | `src/mesh/raft/mod.rs`, `instance.rs`, `state_machine.rs` |
| Threat intelligence sharing | ✅ Verified | `src/mesh/threat_intel.rs` ThreatIntelligenceManager |
| YARA rule distribution | ✅ Verified | `src/mesh/yara_rules.rs` YaraRulesManager |
| Behavioral fingerprints | ✅ Verified | `src/mesh/behavioral_intel.rs` |
| Sequence entropy | ✅ Verified | `behavioral_intel.rs:43` `request_sequence_entropy` field |
| TLS 1.3 mandatory | ✅ Verified | Rustls with TLS 1.3 only |
| Constant-time comparison for secrets | ✅ Verified | AGENTS.md:27-38 documents pattern |
| Edge/Origin/Global node roles | ✅ Verified | `src/mesh/config.rs:23-33` |

### Networking Document
| Claim | Status | Notes |
|-------|--------|-------|
| Hyper for HTTP/1.1 & HTTP/2 | ✅ Verified | `src/http/server.rs`, `src/http_client/mod.rs` use hyper |
| HTTP/3 via Quinn | ✅ Verified | `src/http3/server.rs` uses quinn |
| TLS via Rustls | ✅ Verified | Throughout codebase - `src/tls/server.rs`, `rustls` in Cargo.toml |
| ACME integration | ✅ Verified | `src/tls/acme/` exists, `AcmeManager` found in `server/mod.rs` |
| X25519MLKEM768 hybrid | ✅ Verified | `src/startup/master.rs:211`, `Cargo.toml:30` post-quantum feature |
| post-quantum feature flag | ✅ Verified | `Cargo.toml:30` |
| pqc-mesh feature flag | ✅ Verified | `Cargo.toml:37` |
| BufferPool | ✅ Verified | `crates/synvoid-utils/src/buffer/pool.rs:211` |
| ConnectionLimiter | ✅ Verified | `src/waf/traffic_shaper/limiter.rs:12` |
| aws-lc-rs crypto provider | ✅ Verified | `Cargo.toml:153`, `pqc/src/kem.rs:5` |

---

## Discrepancies Found

### D1: `audit.rs` Location Mismatch
**Document:** `mesh_deep_dive.md:57`
> "The mesh includes a distributed auditing system (`audit.rs`)"

**Actual Location:** `src/mesh/audit.rs` ✅ EXISTS - but document shows path relative without `src/` prefix

**Severity:** Low (documentation path format issue)
**Priority:** Low
**Action:** Update path reference in document to `src/mesh/audit.rs`

---

### D2: Hierarchical Routing - "Bloom Filters for Regional Routing"
**Document:** `mesh_deep_dive.md:30`
> "Uses Bloom filters and regional hubs to minimize discovery latency"

**Actual State:**
- Bloom filters exist in `src/mesh/hierarchical_routing.rs:66` (MeshBloomFilter)
- Used for upstream route checking, NOT for DHT discovery latency

**Analysis:** Bloom filters are used for `MeshBloomFilter::with_bloom_filter()` on route announcements, not specifically for "regional discovery latency reduction." The hierarchical routing uses geo-distance based regional hubs (`regional_hubs.rs`), not Bloom filter-based discovery.

**Severity:** Medium (implication that Bloom filters optimize DHT routing is misleading)
**Priority:** Medium
**Action:** Clarify in documentation that Bloom filters are used for upstream route announcements, not DHT discovery optimization

---

### D3: ACME Documentation Inconsistency
**Document:** `networking_deep_dive.md:31`
> "ACME Integration: Built-in support for Let's Encrypt and other ACME-based CAs"

**Actual State:** ACME is implemented but requires explicit configuration. No automatic Let's Encrypt enrollment without proper config setup.

**Severity:** Low (technically accurate but could imply automatic behavior)
**Priority:** Low
**Action:** Add clarification: "Requires explicit configuration with email and domain list"

---

### D4: Post-Quantum Key Exchange References
**Document:** `networking_deep_dive.md:37`
> "X25519MLKEM768: A hybrid key exchange"

**Document:** `mesh_deep_dive.md:25`
> "Hybrid Approach: Combines PQC with classical algorithms (X25519/Ed25519)"

**Actual State:**
- TLS hybrid uses X25519MLKEM768 (`src/startup/master.rs:211`)
- Mesh message signing uses Ed25519+ML-DSA hybrid (`src/mesh/hybrid_signature.rs`)
- ML-KEM768 for key encapsulation (`pqc/src/kem.rs`)

**Issue:** Document mentions Ed25519 alongside X25519 for hybrid key exchange, but Ed25519 is for signatures, not key exchange. X25519 is the correct classical pairing for ML-KEM.

**Severity:** Low (technically confusing but not wrong)
**Priority:** Low
**Action:** Clarify that X25519 is for key exchange, Ed25519 is for message signatures

---

### D5: Kademlia "Hierarchical Routing" Description
**Document:** `mesh_deep_dive.md:28`
> "Peer and service discovery are handled via a Kademlia-based Distributed Hash Table (DHT)"

**Actual State:** The DHT implementation is Kademlia-like but includes significant customizations:
- Geo-distance based regional routing (`regional_hubs.rs`)
- KBucket routing (`dht/routing/bucket.rs`)
- Not pure Kademlia - hybrid approach

**Severity:** Low (oversimplification)
**Priority:** Low
**Action:** Note that it's "Kademlia-inspired with geo-distance enhancements"

---

## Known Architectural Limitations (Not Bugs)

### L1: DHT Ingress Verification Gaps
**Document:** `mesh_deep_dive.md` does NOT mention this

**Actual State:** Documented in `src/mesh/dht/signed.rs:42-48`:
- DhtSyncRequest: node_id not validated against peer_id/TLS cert
- DhtAntiEntropyRequest: signer_public_key present but not used
- DhtRecordPush: timestamp ignored, lacks envelope signature
- DhtRecordCommit: has timestamp but lacks envelope signature validation
- QuorumStoreRequest: no verification performed
- QuorumSignatureResp: no verification performed

**Reference:** `src/mesh/AGENTS.override.md:76-84` (Wave 14)

**Severity:** Medium (security-relevant architectural gap)
**Priority:** Medium
**Action:** Document these as known limitations in the architecture document

---

## Potential Improvements

### I1: Document QUIC Stream Multiplexing Benefits
**Document:** `mesh_deep_dive.md:17-18`
> "Native Multiplexing: Multiple streams (threat intel, proxying, heartbeats) can coexist..."

**Actual State:** QUIC transport exists, but claim about threat intel/proxying/heartbeats streams should be verified. Current implementation uses QUIC for mesh transport but internal stream multiplexing details are not documented in code comments.

**Severity:** Low
**Priority:** Low
**Action:** Add implementation note referencing the actual stream type constants

---

### I2: Zero-Copy IO Documentation
**Document:** `networking_deep_dive.md:54-55`
> "SynVoid leverages Rust's ownership model to minimize data copying"

**Actual State:** BufferPool exists (`crates/synvoid-utils/src/buffer/pool.rs`) but "zero-copy" is aspirational. Most HTTP handlers still copy data between layers. This claim is aspirational marketing, not implementation fact.

**Severity:** Medium (could be misleading)
**Priority:** Medium
**Action:** Either:
- (a) Document actual zero-copy paths with specific examples, OR
- (b) Soften claim to "ownership-based buffer reuse" which is more accurate

---

### I3: ConnectionLimiter Per-Site/IP Documentation
**Document:** `networking_deep_dive.md:58-61`
> "Per-Site Limit: Limits the impact of a surge in traffic to a single domain"
> "Per-IP Limit: Prevents connection exhaustion attacks from a single source"

**Actual State:** `ConnectionLimiter` is in `src/waf/traffic_shaper/limiter.rs:12` but the documented per-site and per-IP limits are implemented via separate `SiteConnectionLimiter` at `limiter.rs:306`.

**Severity:** Low
**Priority:** Low
**Action:** Add configuration references to clarify implementation

---

### I4: PQC Feature Flag Cross-Reference
**Document:** `networking_deep_dive.md:38`
> "Feature-Gated: PQ key exchange can be enabled via the `post-quantum` feature flag"

**Actual State:** Correct, but incomplete. Missing:
- `pqc-mesh` feature flag for ML-DSA mesh signatures
- `verify-pq` feature flag for PQC verification

**Severity:** Low
**Priority:** Low
**Action:** Add `pqc-mesh` and `verify-pq` to the feature flags list

---

## Security Considerations

### S1: Documentation vs Implementation一致性
The architecture documents describe security properties but don't link to implementation references. For example:
- "Peer Authentication: All nodes must have a valid certificate" - implemented at `src/mesh/peer_auth.rs`
- "Access Control: Fine-grained policies" - implemented at `src/mesh/dht/capability_access.rs`

**Recommendation:** Add inline code references in documentation for security-critical claims.

---

## Summary

| Category | Count | Priority |
|----------|-------|----------|
| Verified Correct | 25+ items | - |
| Discrepancies | 5 | Low-Medium |
| Known Limitations | 1 | Medium |
| Improvements | 4 | Low-Medium |
| Security Notes | 1 | Medium |

**High Priority Items:**
1. I2: Zero-copy IO claim is misleading - needs clarification
2. L1: DHT ingress verification gaps should be documented
3. D2: Bloom filter routing claim needs clarification

**Medium Priority Items:**
1. S1: Add security implementation references to documents
2. I4: Complete PQC feature flag documentation

**Low Priority Items:**
1. D1, D3, D4, D5: Documentation polish and path corrections

---

## Recommendations

1. **Create architecture doc template** with mandatory sections:
   - Implementation References (file:line)
   - Known Limitations
   - Feature Flag Requirements
   - Security Properties with code pointers

2. **Add architectural decision records (ADRs)** for:
   - PQC hybrid approach (X25519MLKEM768 vs pure PQC)
   - DHT vs Raft tradeoffs for different record types
   - Regional quorum design decisions

3. **Cross-reference AGENTS.md lessons** into relevant architecture docs to prevent historical drift