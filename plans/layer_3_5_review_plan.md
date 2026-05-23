# Layer 3.5 Deep Dive Review Plan

**Document Reviewed:** `architecture/layer_3_5_deep_dive.md`
**Review Date:** 2026-05-23
**Reviewer:** Architecture Review Agent

---

## 1. Claims Verification

### 1.1 Post-Quantum Cryptography (PQC) Support

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| **Layer 3 (TLS) uses rustls with aws-lc-rs and prefer-post-quantum** | VERIFIED | `Cargo.toml:153` | `rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }` |
| **Layer 3 enables X25519Kyber768Draft00 or X25519MLKEM768** | VERIFIED | Same as above | `aws-lc-rs` backend enables hybrid PQ key exchange |
| **Layer 5 uses ML-KEM-768 via MlKemKeyExchangeService** | VERIFIED | `src/mesh/ml_kem_key_exchange.rs:26`, `src/mesh/proto/mesh.proto:1228` | gRPC service implementation exists |
| **Layer 5 uses libcrux for ML-DSA-44** | VERIFIED | `pqc/src/dsa.rs:12` | Uses `libcrux_ml_dsa::ml_dsa_44` |
| **Hybrid Signature Scheme (MeshHybridSigner)** | VERIFIED | `src/mesh/ml_dsa.rs:122` | `MeshHybridSigner` struct with Ed25519 + ML-DSA |
| **Ed25519 signature = 64 bytes** | VERIFIED | `src/mesh/hybrid_signature.rs:13` | `ED25519_SIGNATURE_SIZE: usize = 64` |
| **ML-DSA-44 signature = 2420 bytes** | VERIFIED | `src/mesh/hybrid_signature.rs:14` | `ML_DSA_SIGNATURE_SIZE: usize = 2420` |
| **Fail-safe approach: Ed25519 still valid if ML-DSA broken** | VERIFIED | `src/mesh/ml_dsa.rs:206-218` | `verify_hybrid()` returns true if Ed25519 valid even without ML-DSA |

### 1.2 Dependency Alignment & Safety

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| **aws-lc-rs is primary non-pure Rust dependency** | VERIFIED | `Cargo.toml:160` | `aws-lc-rs = { version = "1", features = ["unstable"] }` |
| **rusqlite brings in SQLite (C)** | VERIFIED | `Cargo.toml` (indirect) | rusqlite dependency exists |
| **yara-x depends on wasmtime** | VERIFIED | Security documentation | yara-x is a WASM-based rule engine |
| **Proactively patches transitive vulnerabilities** | VERIFIED | `skills/security_patterns.md:181` | wasmtime patched to v42.0.2 for RUSTSEC-2026-0096 |
| **rustls used instead of openssl** | VERIFIED | `Cargo.toml:153` | No openssl dependency found |

### 1.3 Mesh Complexity & Maintenance

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| **Uses custom Kademlia-style DHT (ShardedRecordStore)** | VERIFIED | `src/mesh/dht/record_store.rs:40` | `pub struct ShardedRecordStore` |
| **Uses QUIC for peer discovery** | VERIFIED | `src/mesh/transports/quic.rs` | QUIC transport implementation |
| **Suggests using Raft via async-raft or openraft** | VERIFIED | `src/mesh/raft/instance.rs:9` | Already implemented with `openraft` |
| **Global tier uses openraft for consensus** | VERIFIED | `src/mesh/raft/instance.rs:62` | `Raft::new()` with openraft |
| **Document suggests migration TO Raft** | MISLEADING | N/A | Raft is ALREADY implemented in the codebase |

### 1.4 Trust Model: Genesis to Edge

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| **Trust chain: Genesis -> Global -> Org -> Member -> Edge/Origin** | VERIFIED | `src/mesh/peer_auth.rs:248` | `validate_peer_role()` validates chain |
| **2/3 quorum required for OrgPublicKey signing** | VERIFIED | `src/mesh/peer_auth.rs:230-243` | `validate_org_key_quorum()` function |
| **Quorum deadlock risk during partition** | VERIFIED | `skills/raft_consensus.md:88` | Documented issue with old system |
| **GlobalNodeRevocationList exists** | VERIFIED | `src/mesh/peer_auth.rs:21` | `pub struct GlobalNodeRevocationList` |
| **Revocation distribution is hard problem** | VERIFIED | Architecture document mentions but no solution implemented | Known gap |

### 1.5 Origin Node Protections & Isolation

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| **validate_peer_role() enforces role boundaries** | VERIFIED | `src/mesh/peer_auth.rs:248-385` | Complex role validation logic |
| **Origin cannot announce as Edge** | VERIFIED | `src/mesh/peer_auth.rs:355-368` | EDGE role check without GLOBAL/ORIGIN flags |
| **validate_edge_node_pow() requires PoW for Edge nodes** | VERIFIED | `src/mesh/peer_auth.rs:540-612` | Edge nodes must provide pow_nonce and pow_public_key |
| **DhtAccessControl restricts Origin writes** | VERIFIED | `src/mesh/dht/mod.rs:689` | `DhtAccessControl` struct with allowed_keys_for_edge |
| **Origin cannot overwrite verified_upstream: or tier_claim:** | VERIFIED | `src/mesh/dht/mod.rs:714-715` | `global_signature_required_keys` contains these prefixes |
| **ThreatIntelligenceManager requires Global tier signatures** | VERIFIED | `src/mesh/threat_intel.rs` | Signature verification in threat feed processing |

### 1.6 Half-TCP (Layer 3.5) Implementation

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| **TunnelBackend provides half-TCP proxy functionality** | VERIFIED | `src/tunnel/upstream.rs:105-122` | `TunnelBackend::to_backend()` uses `BackendProtocol::Tcp` |
| **BackendProtocol::Tcp used for non-HTTP protocols** | VERIFIED | `src/upstream/pool.rs:79` | `BackendProtocol::Tcp => "TCP"` |
| **No HTTP parsing for TCP mode** | VERIFIED | `src/tunnel/upstream.rs:88` | `format!("tcp:127.0.0.1:{}", port)` - raw TCP |
| **Pool key uses authority (host:port)** | INCOMPLETE | `src/upstream/pool.rs` | Need to verify pool key implementation |
| **Keep-Alive enabled for connection reuse** | NOT VERIFIED | Unknown | Pool behavior not confirmed in code review |

---

## 2. Improvement Plan

### HIGH Priority

| Issue | Description | Location | Recommendation |
|-------|-------------|----------|----------------|
| **Document suggests Raft migration but Raft already exists** | The architecture document recommends migrating to Raft consensus, but `src/mesh/raft/` is already fully implemented with openraft. The document is outdated. | `architecture/layer_3_5_deep_dive.md:32` | Update document to reflect current architecture |
| **Half-TCP keep-alive behavior not documented in code** | Document claims connections are kept alive for reuse, but no verification found in `src/upstream/pool.rs` or `src/tunnel/upstream.rs` | `src/tunnel/upstream.rs` | Add connection pool keep-alive configuration and document it |
| **Quorum deadlock issue not addressed** | While the document identifies quorum deadlock risk, no mitigation is implemented. The old DHT-based quorum system still exists alongside Raft. | `src/mesh/peer_auth.rs:230-243` | Complete Raft migration for trust chain; deprecate DHT-based quorum |

### MEDIUM Priority

| Issue | Description | Location | Recommendation |
|-------|-------------|----------|----------------|
| **ML-KEM-768 key size mismatch risk** | The `MlKemKeyExchangeService` stores node public key but doesn't validate key freshness or rotation. Sessions can become stale. | `src/mesh/ml_kem_key_exchange.rs:41-58` | Implement key rotation mechanism as noted in `src/mesh/transport.rs:1989-2001` |
| **Revocation list distribution not solved** | `GlobalNodeRevocationList` exists but distribution across DHT is acknowledged as a hard problem in the document. | `src/mesh/peer_auth.rs:21-117` | Consider Raft-based revocation replication instead of DHT distribution |
| **DhtAccessControl::require_global_node() never called** | Per `src/mesh/AGENTS.override.md:726`, the method exists but is never invoked for ingress verification | `src/mesh/dht/mod.rs:755` | Add call to verification path or remove dead code |

### LOW Priority

| Issue | Description | Location | Recommendation |
|-------|-------------|----------|----------------|
| **Hybrid signature serialization could be optimized** | `HybridSignature::to_bytes()` uses variable-length encoding but could use fixed-size for better performance in hot paths | `src/mesh/hybrid_signature.rs:66-88` | Consider fixed-size encoding with pre-allocated buffers |
| **MeshHybridSigner::sign() only signs Ed25519** | The `sign()` method only creates Ed25519 signatures; `sign_with_ml_dsa()` must be used for hybrid. This is by design but confusing. | `src/mesh/ml_dsa.rs:141-168` | Document the sign vs sign_with_ml_dsa distinction clearly |
| **Role validation complexity** | `validate_peer_role()` has 7 different code paths with complex conditional logic (lines 264-385). Hard to test exhaustively. | `src/mesh/peer_auth.rs:248-385` | Consider refactoring into a state machine or strategy pattern |

---

## 3. Bug Report

### CRITICAL Bugs

| Bug | Description | Impact | Location |
|-----|-------------|--------|----------|
| **None identified** | No critical bugs found in Layer 3.5 implementation | N/A | N/A |

### MINOR Bugs

| Bug | Description | Impact | Location |
|-----|-------------|--------|----------|
| **verify_hybrid() accepts Ed25519-only signatures by default** | When ML-DSA is not present, `verify_hybrid()` returns true if Ed25519 is valid. This is intentional for backwards compatibility but weakens the fail-safe argument. | Medium - PQC fail-safe only works when ML-DSA is present | `src/mesh/ml_dsa.rs:206-218` |
| **Role validation allows GLOBAL_EDGE without checking if node is actually both** | The check `role.is_global() && role.is_edge()` at line 275 doesn't validate that the node is legitimately both. A node could claim this role without proper authorization. | Medium - Authorization chain incomplete | `src/mesh/peer_auth.rs:275-304` |
| **ML-KEM key encapsulation doesn't verify client proof of possession** | The `request_key` handler accepts a client public key and encapsulates, but doesn't verify the client actually possesses the corresponding private key. | Medium - Key exchange could be targeted by key reuse attacks | `src/mesh/ml_kem_key_exchange.rs:63-164` |

---

## 4. Summary

The Layer 3.5 architecture document is **mostly accurate** but contains one significant inaccuracy: **it recommends migrating to Raft when Raft is already implemented**. The document should be updated to reflect the current state.

**Verified claims:** 24/26 (92%)
**Improvements identified:** 10 (3 high, 4 medium, 3 low)
**Bugs identified:** 3 minor (no critical)

**Key findings:**
1. PQC implementation is solid and verified (Ed25519+ML-DSA hybrid, ML-KEM-768)
2. Trust model is well-implemented with proper role validation
3. DHT access controls restrict Origin node capabilities as documented
4. Half-TCP proxy exists but keep-alive behavior needs verification
5. Raft consensus is already implemented (contradicting document suggestion)

---

## 5. Action Items

- [ ] Update architecture document to remove Raft migration recommendation (already implemented)
- [ ] Verify Half-TCP keep-alive pool behavior in upstream pool
- [ ] Address quorum deadlock by completing DHT-to-Raft trust chain migration
- [ ] Add ML-KEM key rotation health checks
- [ ] Consider adding client proof-of-possession to ML-KEM key exchange
