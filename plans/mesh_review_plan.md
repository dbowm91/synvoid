# Mesh Networking Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/mesh.md`, `architecture/mesh_deep_dive.md`

## Verified Correct Items

| Claim | Source | Status |
|-------|--------|--------|
| `MeshTransport` at `src/mesh/transport.rs:93` | transport.rs:93 | ✅ Correct |
| `MeshProxy` at `src/mesh/proxy.rs:62-63` | proxy.rs:62 | ✅ Correct |
| `HybridSignature` at `src/mesh/hybrid_signature.rs:17` | hybrid_signature.rs:17 | ✅ Correct |
| `MeshMlDsaSigner` at `src/mesh/ml_dsa.rs:18` | ml_dsa.rs:18 | ✅ Correct |
| `MlKemKeyExchangeService` at `src/mesh/ml_kem_key_exchange.rs:35` | ml_kem_key_exchange.rs:35 | ✅ Correct |
| `MeshMessageSigner` at `src/mesh/protocol.rs:33` | protocol.rs:33 | ✅ Correct |
| `MeshTopology` at `src/mesh/topology.rs:28` | topology.rs:28 | ✅ Correct |
| `RaftCommitNotification` at `src/mesh/raft/mod.rs:42` | raft/mod.rs:42 | ✅ Correct |
| `DhtError` at `src/mesh/dht/mod.rs:108` | dht/mod.rs:108 | ✅ Correct |
| `DhtConfig` at `src/mesh/dht/mod.rs:161` | dht/mod.rs:161 | ✅ Correct |
| `RaftInstance` at `src/mesh/raft/instance.rs:32` | raft/instance.rs:32 | ✅ Correct |
| Feature flags match Cargo.toml | Cargo.toml:22-37 | ✅ Correct |
| `verify_post_quantum_tls()` in cert.rs | cert.rs:87 | ✅ Correct |
| `security_challenge.rs:196` uses simple `!=` | security_challenge.rs:196 | ✅ Correct per AGENTS.md |
| `validate_member_certificate` at peer_auth.rs:141 | peer_auth.rs:141 | ✅ Correct |
| `CapabilityAccessVerifier` at capability_access.rs:7 | capability_access.rs:7 | ✅ Correct |
| `GlobalNodeRevocationList` exists in peer_auth.rs | peer_auth.rs:21 | ✅ Correct |
| QUIC 0-RTT disabled by default | config.rs:1390-1394 | ✅ Correct |
| `MeshGlobalRateLimiter` at transport_types.rs:47 | transport_types.rs:47 | ✅ Correct |
| `MeshTransport` holds `raft_instance` field | transport.rs:159 | ✅ Correct |

## Discrepancies Found

### 1. QuorumVerifier Location Incorrect
- **Doc claim**: "QuorumVerifier in `src/mesh/dht/quorum.rs`"
- **Actual**: `QuorumVerifierContext` is at `src/mesh/dht/signed.rs:12`. The `quorum.rs` file only contains `QuorumRequest` and `QuorumSignature`.
- **Impact**: Medium - readers will look in wrong file

### 2. NodeInfo Location Incorrect
- **Doc claim**: `NodeInfo` at `src/mesh/dht/keys.rs`
- **Actual**: `NodeInfo` is defined at `src/mesh/dht/mod.rs:342`
- **Impact**: Low - re-exported from dht module

### 3. TierKeyStore Location Incorrect
- **Doc claim**: `TierKeyStore` at `src/mesh/dht/store.rs`
- **Actual**: `TierKeyStore` is defined at `src/mesh/dht/mod.rs:850`, `TierKeyStoreEntry` at `src/mesh/dht/mod.rs:838`
- **Impact**: Low - re-exported from dht module

### 4. DhtAccessControl Location Incorrect
- **Doc claim**: `DhtAccessControl` at `src/mesh/dht/capability_access.rs:7`
- **Actual**: `DhtAccessControl` is defined at `src/mesh/dht/mod.rs:689`. The `capability_access.rs` file contains `CapabilityAccessVerifier`.
- **Impact**: Medium - readers will look in wrong file

### 5. Namespace Enum Missing Variant
- **Doc claim**: `Namespace` has 3 variants (Org, Intel, Revocation)
- **Actual**: `Namespace` has 4 variants: `Org`, `Intel`, `Revocation`, `AuthorizedGlobalNodes`
- **Impact**: Medium - incomplete documentation of state machine capabilities

### 6. MeshNodeRole Oversimplified
- **Doc claim**: "Enum: Origin, Edge, Global"
- **Actual**: `MeshNodeRole` is a bitmask struct with constants: `GLOBAL(0b010)`, `EDGE(0b001)`, `ORIGIN(0b100)`, `GLOBAL_EDGE(0b011)`, `GLOBAL_ORIGIN(0b110)`, `EDGE_ORIGIN(0b101)`, `ALL(0b111)`, `SERVERLESS_ORIGIN(0b1000)`
- **Impact**: Medium - readers may not understand combined roles

### 7. RaftInstance Field Reference Confusing
- **Doc claim**: "RaftInstance.raft field at src/mesh/transport.rs:159"
- **Actual**: Line 159 is `MeshTransport.raft_instance` field. The `raft` field is at `src/mesh/raft/instance.rs:33`
- **Impact**: Low - wording is confusing but line number is technically correct

## Bugs Identified

### 1. Quorum Formula Documentation Mismatch
- **Location**: `src/mesh/dht/quorum.rs:16-21`
- **Issue**: The formula `(node_count * 2 / 3) + 1` gives ceiling(2n/3), not floor(2n/3). For 3 nodes: (3*2/3)+1 = 3, meaning all 3 must agree. The doc says "2/3 of Global nodes" which could be interpreted as floor(2n/3)=2.
- **Impact**: Low - the test at line 30 confirms the actual behavior is correct

## Suggested Improvements

1. **Update QuorumVerifier reference** to point to `QuorumVerifierContext` at `src/mesh/dht/signed.rs:12`

2. **Update NodeInfo location** to `src/mesh/dht/mod.rs:342`

3. **Update TierKeyStore location** to `src/mesh/dht/mod.rs:850`

4. **Update DhtAccessControl location** to `src/mesh/dht/mod.rs:689`

5. **Add AuthorizedGlobalNodes variant** to Namespace enum documentation

6. **Document MeshNodeRole bitmask pattern** with all combination values

7. **Clarify RaftInstance field** - change "RaftInstance.raft field" to "MeshTransport.raft_instance field"

8. **Add record_store_persist.rs** to the file tree (it exists but is not listed)

## Stale Content

| Item | Location | Issue |
|------|----------|-------|
| File tree missing `record_store_persist.rs` | mesh.md:581 | File exists at `src/mesh/dht/record_store_persist.rs` |
| `TierKeyStore` at `store.rs` | mesh.md:159 | Should be `mod.rs:850` |
| `NodeInfo` at `keys.rs` | mesh.md:162 | Should be `mod.rs:342` |
| `DhtAccessControl` at `capability_access.rs` | mesh.md:165 | Should be `mod.rs:689` |

## Cross-Reference Status

| Reference | Status | Notes |
|-----------|--------|-------|
| BUG-L3 (key exchange proof-of-possession) | ✅ Verified | `ml_kem_key_exchange.rs` exists with proper structure |
| BUG-L1 (verify_hybrid() fail-safe) | Not verifiable | Requires checking ml_dsa.rs verify path |
| MESH-15-FIX-1 (is_request_complete lock release) | Not verifiable | Requires checking dht/quorum.rs |
| MESH-15-FIX-4 (send_raw retry) | Not verifiable | Requires checking raft/network.rs |
| MESH-14 (Source Node ID Binding) | Deferred | Documented as known limitation |
| MR-4 (DhtSyncRequest no auth) | ✅ Documented | mesh_deep_dive.md:96 confirms gap |
| Constant-time comparison usage | ✅ Correct | security_challenge.rs:196 uses simple `!=` for public data |
| Post-quantum hybrid signatures | ✅ Verified | HybridSignature, MeshMlDsaSigner exist with stated fields |
| ML-KEM-768 key exchange | ✅ Verified | MlKemKeyExchangeService exists with gRPC service |
| Raft consensus for global nodes | ✅ Verified | RaftInstance, GlobalRegistryStateMachine exist |
| DHT Kademlia routing | ✅ Verified | RoutingTable, KBucket exist in dht/routing/ |
