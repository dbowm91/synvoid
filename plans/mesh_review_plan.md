# Mesh Networking Architecture Review Plan

## Verified Correct

### Core Topology & Technologies
- **Network Topology**: Hierarchical structure (Global/Edge/Origin nodes) is correctly implemented in `src/mesh/config.rs:23-33` with all role variants (GLOBAL, EDGE, ORIGIN, and composites)
- **QUIC Transport**: Implemented in `src/mesh/transports/quic.rs` with full TLS1.3 encryption
- **0-RTT Configuration**: Default is `false` at `src/mesh/config.rs:1390-1392` with replay attack warning comment, confirmed correct
- **Post-Quantum Cryptography**:
  - ML-KEM-768 in `src/mesh/ml_kem_key_exchange.rs` and `src/mesh/kem/`
  - ML-DSA-44 in `src/mesh/ml_dsa.rs`
  - Hybrid approach combines classical (X25519/Ed25519) with PQC

### DHT Implementation
- **Kademlia-based DHT**: Referenced via `announce_records_via_kademlia()` in `src/mesh/dht/record_store_sync.rs:663-717`
- **Capability Attestations**: `CapabilityAccessVerifier` in `src/mesh/dht/capability_access.rs:7` and `CapabilityAttestation` in `src/mesh/dht/capability_attestation.rs`
- **Hierarchical Routing**: `MeshBloomFilter` at `src/mesh/hierarchical_routing.rs:66` for route advertisement deduplication
- **Regional Hubs**: Implemented in `src/mesh/dht/routing/regional_hubs.rs` with `RegionalHub` and `RegionalHubConfig`

### Raft Consensus
- **Namespace Definitions**: Org, Intel, Revocation in `src/mesh/raft/state_machine.rs:27-42`
- **Quorum Requirements**: Uses `(node_count * 2 / 3) + 1` formula at `src/mesh/dht/quorum.rs:257`, correctly implementing 2/3+1 threshold
- **Leader Election & Log Replication**: Via `openraft` crate in `src/mesh/raft/instance.rs`

### Security & Integrity
- **Peer Authentication**: `validate_member_certificate` at `src/mesh/peer_auth.rs:141`
- **Audit System**: Distributed audit in `src/mesh/audit.rs`
- **CapabilityAccessVerifier**: Located at `src/mesh/dht/capability_access.rs:7`
- **Genesis Key Default Deny**: Empty `authorized_genesis_keys` denies at `src/mesh/dht/mod.rs:734-738`

### MeshProxy Component
- **Location**: `src/mesh/proxy.rs` (1996 lines confirmed)
- **Active Connections**: `DashMap<String, MeshConnection>` at line 70
- **Policy Cache**: `Cache<String, CachedPolicy>` at line 71
- **Provider Stats**: `DashMap<String, ProviderStats>` at line 73
- **Organization Manager**: `Arc<TokioRwLock<OrganizationManager>>` at line 74
- **TieredTransformCache**: Defined at lines 260-306, instantiated at line 325

### DHT Ingress Verification Table (from `src/mesh/dht/signed.rs:42-48`)
| Message Type | Verification Status | Code Location |
|--------------|---------------------|--------------|
| `DhtRecordAnnounce` | Full verification | `DhtRecord.verify_for_ingress()` |
| `DhtSyncRequest` | None | Gap documented |
| `DhtSyncResponse` | Full verification | `DhtRecord.verify_for_ingress()` |
| `DhtAntiEntropyRequest` | Partial (pk unused) | Gap documented |
| `DhtAntiEntropyResponse` | Full verification | `DhtRecord.verify_for_ingress()` |
| `DhtRecordPush` | Partial (no timestamp) | Gap documented |
| `DhtRecordCommit` | Partial (no envelope sig) | Gap documented |
| `QuorumStoreRequest` | None | Gap documented |
| `QuorumSignatureResp` | None | Gap documented |

---

## Discrepancies Found

### 1. Hierarchical Routing Module is "Unused but Preserved"
**Documentation states**: "Hierarchical Routing: Uses Bloom filters and regional hubs to enable memory-efficient route announcement checking"
**Code reality**: The module header in `src/mesh/hierarchical_routing.rs:2-9` explicitly states:
```rust
// Hierarchical routing for mesh - RESERVED for multi-region topology.
// This module implements regional hub discovery and bloom-filter based route advertisements.
// Currently unused but preserved for future multi-region deployment where:
```
This is a **reserved feature**, not an active implementation.

**Recommendation**: Update documentation to clarify this is a reserved/planned feature, or add timeline for implementation.

### 2. ThreatAcknowledgement Pattern Documentation Mismatch
**Documentation states** (line 78-79): "Peer Authentication: All nodes must have a valid certificate signed by an authorized Organization Key (see validate_member_certificate)"
**Code reality**: The `validate_member_certificate` is indeed at `peer_auth.rs:141`, but it validates certificates against org public keys and authorized global pubkeys, not directly against an "Organization Key" as a signing key.

### 3. File Path: AGENTS.md raft/state_machine reference
**AGENTS.md states**: `src/mesh/raft/state_machine.rs:166-172` for quorum verify
**Correct path**: `src/mesh/dht/signed.rs:874-1092` (as noted in the "Known File Path Corrections" table)
**Status**: Already corrected in AGENTS.md - correctly documented as a known correction.

---

## Bugs Identified

### High Severity
**None identified** - All critical bugs from AGENTS.md are marked as FIXED:
- BUG-L3 (ML-KEM proof-of-possession): FIXED per `confirm_key()` now verifies client can decapsulate
- MESH-15 (Quorum Deadlock Risk): Documented as deferred architectural issue

### Medium Severity
**MESH-14: No Source Node ID Binding Validation in All Ingress Paths**
- **Location**: Multiple DHT message types lack full verification per `src/mesh/dht/signed.rs:42-48`
- **Issue**: `DhtSyncRequest`, `QuorumStoreRequest`, `QuorumSignatureResp` have NO node_id verification
- **Impact**: An attacker could potentially claim records from a different node_id
- **Status**: Known architectural constraint, deferred

### Low Severity
**Reserved Feature Not Marked in Documentation**
- **Location**: `src/mesh/hierarchical_routing.rs` - Bloom filter hierarchical routing
- **Issue**: Documented as active functionality but code is explicitly marked "Currently unused but preserved"
- **Impact**: Documentation implies active feature that is not operational

---

## Suggested Improvements

### Documentation Improvements
1. **Clarify Hierarchical Routing Status**: Add explicit note that Bloom filter-based hierarchical routing is a **reserved/planned** feature
2. **Clarify "Organization Key" Terminology**: Change to "authorized Organization Public Key" to match actual implementation
3. **Cross-Reference DHT Verification Table**: The verification table in `src/mesh/dht/signed.rs:42-48` is thorough but not linked from architecture documentation

### Code Quality Improvements
1. **Consider Implementing DhtSyncRequest Verification**: Currently has no auth - could be a security risk if TLS transport is compromised
2. **Unused Module Cleanup**: If not on roadmap, consider adding `#[allow(dead_code)]` explicitly

### Architecture Improvements
1. **MESH-14 Source Node ID Binding**: Consider adding integration tests for ingress path verification
2. **Regional Quorum Scaling**: Document expected scale limits for Regional quorum mode

---

## Summary
The Mesh Networking architecture documentation is **largely accurate** with only one significant discrepancy (hierarchical routing being reserved/unused) and a few minor terminological differences. The security patterns are correctly implemented, and the known DHT verification gaps are properly documented. All critical bugs from AGENTS.md are marked as FIXED.

The most important action item is clarifying the status of hierarchical routing in the documentation.
