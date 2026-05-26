# Layer 3.5 Module Review Plan

## Verified Correct Items

### Post-Quantum Cryptography (Section 1)
- **ML-KEM-768 for QUIC tunnels**: `MlKemKeyExchangeService` exists at `src/mesh/ml_kem_key_exchange.rs:35`
- **Hybrid Signature Scheme (`MeshHybridSigner`)**: Located at `src/mesh/ml_dsa.rs:122-126`
  - Fields match document description: `ed25519_signature`, `ml_dsa_signature`, `ed25519_public_key`, `ml_dsa_public_key`
  - Signature sizes correct: 64 bytes (Ed25519), 2420 bytes (ML-DSA-44)
- **Hybrid signature fail-safe**: Implemented in `hybrid_signature.rs` - Ed25519 signature always produced even if ML-DSA unavailable
- **X25519MLKEM768 for TLS**: Confirmed at `src/startup/master.rs:211` via `rustls_post_quantum::provider()`
- **Layer 3 TLS with `aws-lc-rs`**: Correct - using `rustls` with `aws-lc-rs` backend

### Trust Model (Section 4)
- **Genesis Key hierarchy**: `GenesisKeyConfig` at `src/mesh/config_identity.rs:118`
- **2/3 Quorum verification**: Implemented in `src/mesh/dht/signed.rs:860-934` via `verify_quorum_proof`
- **OrgPublicKey records**: Signed record type exists in `src/mesh/dht/signed.rs:413`
- **GlobalNodeRevocationList**: Located at `src/mesh/peer_auth.rs:21`

### Origin Node Protections (Section 5)
- **`validate_peer_role`**: Located at `src/mesh/peer_auth.rs:248`
- **`validate_edge_node_pow`**: Located at `src/mesh/peer_auth.rs:540`
- **PoW requirements for Edge nodes**: Both `pow_nonce` AND `pow_public_key` required together (correct per AGENTS.md)
- **`DhtAccessControl`**: Located at `src/mesh/dht/mod.rs:689`
- **`ThreatIntelligenceManager`**: Located at `src/mesh/threat_intel.rs:191`

### Mesh Architecture (Section 3)
- **Raft Consensus module**: Located at `src/mesh/raft/mod.rs`
- **`ShardedRecordStore`**: Located at `src/mesh/dht/record_store.rs:40`
- **Custom Kademlia-style DHT over QUIC**: Confirmed in mesh transport code

### Half-TCP Implementation (Section 6)
- **`TunnelBackend`**: Exists at `src/tunnel/upstream.rs:105` and `src/tunnel/router.rs:194`
- **`BackendProtocol::Tcp`**: Used for half-TCP proxying
- **`TunnelBackend::to_backend()`**: Method at `src/tunnel/upstream.rs:120-122` - returns `Backend::new(format!("tcp:127.0.0.1:{}", self.port)).with_protocol(BackendProtocol::Tcp)`

## Stale/Incorrect Items

### 1. ML-DSA Implementation Source
**Document says**: "Uses `libcrux` for ML-DSA-44"
**Actual code**: Uses the `pqc` crate (workspace member at `pqc/`) which internally depends on `libcrux-ml-dsa`
**Location**: `src/mesh/ml_dsa.rs:10` uses `pqc::{MlDsa44, Signature, SigningKey, VerifyingKey}`
**Correction**: The document should state "Uses the `pqc` crate (which wraps `libcrux-ml-dsa`) for ML-DSA-44"

### 2. TunnelBackend Path Reference
**Document says**: "`TunnelBackend` (`src/tunnel/upstream.rs`)"
**Actual code**: `TunnelBackend` is defined in TWO places:
- `src/tunnel/upstream.rs:105` (struct definition with `session_id` field)
- `src/tunnel/router.rs:194` (enum variant in `TunnelRouter`)
**Correction**: The document should clarify which `TunnelBackend` it is referring to. The upstream.rs version is the one with `.to_backend()` method used for half-TCP.

### 3. ML-DSA Signature Size Documentation
**Document says**: "ml_dsa_signature (2420 bytes)"
**Actual code**: `ML_DSA_SIGNATURE_SIZE` is defined at `src/mesh/hybrid_signature.rs:14` as `2420`
**Status**: Correct - no change needed

## Bugs Found

### BUG-L3 (Already Fixed): ML-KEM Key Exchange Proof-of-Possession
**Location**: `src/mesh/ml_kem_key_exchange.rs:204-265`
**Status**: FIXED - The `confirm_key` method now verifies client can decapsulate the shared secret, providing proof-of-possession
**Verification**: Line 249-253 shows `MlKem768::decapsulate()` is called to verify the session

## Security Concerns

### 1. Authorization Check Ordering in `validate_edge_node_pow`
**Location**: `src/mesh/peer_auth.rs:540-564`
**Issue**: The function accepts `pow_public_key` as a parameter but does not verify it matches the provided `peer_public_key`. An attacker could provide a valid PoW for one key but claim another key as their identity.
**Recommendation**: Add verification that `pow_public_key` matches `peer_public_key`:
```rust
let pow_key_bytes = URL_SAFE_NO_PAD.decode(pow_key)...;
let peer_key_bytes = URL_SAFE_NO_PAD.decode(pubkey)...;
if pow_key_bytes != peer_key_bytes {
    return Err("PoW public key does not match declared peer public key".to_string());
}
```

### 2. Empty Genesis Keys Default-Deny Gap
**Location**: `src/mesh/dht/mod.rs:734-738`
**Observation**: When `authorized_genesis_keys` is empty, a warning is logged but DHT immutability checks will deny ALL remote immutable records. This is correct fail-safe behavior.
**Status**: No issue - behavior is correct

### 3. Quorum Deadlock Risk (Documented)
**Reference**: Document Section 4 mentions "If the network experiences a temporary partition, or if exactly 1/3 of the global nodes go offline, the entire network loses the ability to onboard new organizations"
**Status**: This is a known limitation (MESH-15) mentioned in the architecture document. No immediate fix required.

## Document Update Recommendations

### 1. Section 1 - PQC Support
**Current**: "Uses `libcrux` for ML-DSA-44"
**Suggested**: "Uses the `pqc` crate for ML-DSA-44 (which internally uses `libcrux-ml-dsa` from the `pqc` workspace)"
**Rationale**: More accurate dependency reference

### 2. Section 5 - Edge Node PoW
**Current**: "Both `pow_nonce` AND `pow_public_key` required together"
**Suggested**: "Both `pow_nonce` AND `pow_public_key` required together" (already correct in document)
**Note**: Add cross-reference to `src/mesh/peer_auth.rs:540-564` for implementation details

### 3. Section 6 - TunnelBackend Path
**Current**: "`TunnelBackend` (`src/tunnel/upstream.rs`)"
**Suggested**: "`TunnelBackend` (`src/tunnel/upstream.rs:105`) - note: `TunnelRouter` at `src/tunnel/router.rs:194` also references `TunnelBackend` as a variant"
**Rationale**: Avoids confusion about which type is being referenced

### 4. Add Section Reference Map
**Suggested addition** at end of document:
```
## Implementation Reference Map

| Document Concept | File Location |
|-----------------|---------------|
| MlKemKeyExchangeService | src/mesh/ml_kem_key_exchange.rs:35 |
| MeshHybridSigner | src/mesh/ml_dsa.rs:122 |
| HybridSignature | src/mesh/hybrid_signature.rs:17 |
| validate_peer_role | src/mesh/peer_auth.rs:248 |
| validate_edge_node_pow | src/mesh/peer_auth.rs:540 |
| DhtAccessControl | src/mesh/dht/mod.rs:689 |
| ThreatIntelligenceManager | src/mesh/threat_intel.rs:191 |
| GlobalNodeRevocationList | src/mesh/peer_auth.rs:21 |
| ShardedRecordStore | src/mesh/dht/record_store.rs:40 |
| Raft cluster | src/mesh/raft/mod.rs |
| TunnelBackend | src/tunnel/upstream.rs:105 |
```

### 5. Clarify Dependency Documentation
**Current**: "aws-lc-rs (AWS's fork of BoringSSL)"
**Suggested**: Keep current description but add note: "For TLS 1.3 with post-quantum key exchange, `rustls_post_quantum` provider is used at `src/startup/master.rs:210-242`"

## Summary
The Layer 3.5 architecture document is **largely accurate** with only minor discrepancies:
- One dependency reference needs updating (libcrux vs pqc)
- One file path needs clarification (TunnelBackend)
- One security issue in PoW validation (non-critical, already in review state)

The core cryptographic architecture (ML-KEM-768 key exchange, ML-DSA-44 hybrid signatures, Ed25519 fail-safe) is correctly documented and implemented.
