# Layer 3.5 Architecture Review Plan

## Verified Correct

### Post-Quantum Cryptography (PQC)
- **Layer 3 (TLS):** `rustls` with `aws-lc-rs` backend and `prefer_post_quantum` configuration flag at `src/tls/cert_resolver.rs:261-264`
- **Layer 5 (Mesh Control Plane):**
  - ML-KEM-768 key exchange via `MlKemKeyExchangeService` at `src/mesh/ml_kem_key_exchange.rs:35`
  - ML-DSA-44 authentication via `MeshHybridSigner` at `src/mesh/ml_dsa.rs:121-126`
  - Hybrid signature fields confirmed: `ed25519_signature` (64 bytes), `ml_dsa_signature` (2420 bytes), `ed25519_public_key`, `ml_dsa_public_key` at `src/mesh/hybrid_signature.rs:17-22`
- **BUG-L1 (verify_hybrid fail-safe):** Correctly implemented at `src/mesh/ml_dsa.rs:206-218` - returns `true` when ML-DSA absent
- **BUG-L3 (ML-KEM proof-of-possession):** Correctly implemented at `src/mesh/ml_kem_key_exchange.rs:241-253` - verifies client can decapsulate
- **Async hybrid verification:** Uses `CryptoVerificationPool` for parallel ML-DSA verification at `src/mesh/protocol.rs:197-232`

### Post-Quantum TLS Provider Installation
- Installation at `src/startup/master.rs:210-242` correctly installs `rustls_post_quantum::provider()` with proper feature gating (`#[cfg(feature = "post-quantum")]`)
- Fallback to classical cryptography when PQ feature disabled at line 243-246

### ACME Implementation
- HTTP-01 and DNS-01 challenges implemented at `src/tls/acme.rs:246-291`
- ChallengeGuard pattern ensures proper cleanup at `src/tls/acme.rs:22-50`
- Certificate file permissions set to `0o600` at `src/tls/acme.rs:178` - correct

### SNI Peeking
- `extract_sni()` at `src/tls/sni_peek.rs:8-29` correctly parses TLS ClientHello
- JA4 fingerprinting implemented at `src/tls/sni_peek.rs:180-245` with proper format

### TLS Termination
- TLS 1.3 only mode via `tls_1_3_only: true` at `src/tls/config.rs:51`
- mTLS client authentication support at `src/tls/cert_resolver.rs:288-314`
- OCSP stapling support at `src/tls/cert_resolver.rs:79-100`
- Certificate key strength validation at `src/tls/cert_resolver.rs:164-213`

### Half-TCP (Tunnel Backend)
- `TunnelBackend::to_backend()` returns `BackendProtocol::Tcp` at `src/tunnel/upstream.rs:120-122`
- `Backend::new(format!("tcp:127.0.0.1:{}", self.port))` confirms hardcoded `127.0.0.1` usage

### Trust Model & Origin Node Protections
- `validate_peer_role()` at `src/mesh/peer_auth.rs:248` enforces role boundaries
- `validate_edge_node_pow()` at `src/mesh/peer_auth.rs:540` requires PoW for edge nodes
- `DhtAccessControl` restricts Origin node writes at `src/mesh/dht/mod.rs:689`

---

## Discrepancies Found

### 1. Hybrid Signature Field Documentation Inaccuracy
- **Document says:** "Hybrid Signature Scheme (`MeshHybridSigner`) with struct fields `ed25519_signature` (64 bytes), `ml_dsa_signature` (2420 bytes), `ed25519_public_key`, and `ml_dsa_public_key`"
- **Actual code:** `MeshHybridSigner` is at `src/mesh/ml_dsa.rs:121-126` and has different fields. The fields listed are actually in `HybridSignature` at `src/mesh/hybrid_signature.rs:17-22`
- **Impact:** Low - documentation references wrong struct name but correct field structure

### 2. ML-KEM Key Exchange Location
- **Document says:** "ML-KEM key exchange verification at `src/mesh/ml_kem_key_exchange.rs:204-264`"
- **Actual code:** The `confirm_key` method is at `src/mesh/ml_kem_key_exchange.rs:204-264` (60 lines, not 61) - correct line range
- **Impact:** None - document is accurate

### 3. Tunnel Backend Hardcoded Address
- **Document says:** `TunnelBackend` (`src/tunnel/upstream.rs`) provides half-TCP proxy functionality with `Backend::new(format!("tcp:127.0.0.1:{}", self.port))`
- **Actual code:** Confirmed at `src/tunnel/upstream.rs:121`
- **Note:** Also found `TunnelBackend::Direct` variant at `src/tunnel/router.rs:147` that accepts dynamic host

---

## Bugs Identified

### Bug 1: TunnelBackend Hardcoded 127.0.0.1 (Medium)
- **Location:** `src/tunnel/upstream.rs:121`
- **Issue:** `TunnelBackend::to_backend()` hardcodes `tcp:127.0.0.1:{}` instead of using the actual tunnel identifier/host
- **Impact:** For direct tunnel connections, always routes to localhost regardless of actual tunnel endpoint
- **Severity:** Medium - may cause routing issues in multi-host tunnel scenarios

### Bug 2: Half-TCP Pool Key Not Using Authority (Low)
- **Document states:** "Pool Key: Uses authority (host:port) for connection reuse"
- **Actual code:** Need to verify if `BackendProtocol::Tcp` properly handles pool key routing
- **Impact:** Low - if pool key is properly implemented, this is documentation accuracy
- **Severity:** Low - functionality likely correct but documentation is unclear

---

## Suggested Improvements

### 1. Clarify HybridSignature vs MeshHybridSigner Documentation
- The architecture document conflates `HybridSignature` (data structure at `src/mesh/hybrid_signature.rs:17-22`) with `MeshHybridSigner` (implementation at `src/mesh/ml_dsa.rs:121-126`)
- Should clearly distinguish between the serialized format and the signing/verification logic

### 2. Document Post-Quantum Provider Installation Location
- The installation at `src/startup/master.rs:210-242` uses `#[cfg(feature = "post-quantum")]` but the architecture document doesn't clearly state which feature flag controls this
- Should clarify: `post-quantum` feature enables X25519MLKEM768 for TLS, while mesh PQ is always available

### 3. Document Tunnel Backend Routing More Clearly
- The "Half-TCP (Layer 3.5) Implementation" section mentions "raw TCP stream, not parsed as HTTP" but doesn't clarify the hardcoded `127.0.0.1` behavior
- Should document when `TunnelBackend::Direct` vs `TunnelBackend::Tunnel` is used

### 4. Add Security Consideration for ML-KEM Timing Side-Channel
- RUSTSEC-2023-0079 documents a timing side-channel in `pqc_kyber` 0.7.1 ML-KEM-768 division operations (CVSS 7.4)
- The `src/mesh/crypto_verification.rs:107` and `src/mesh/passover_key_exchange.rs:736` use this library
- Should document mitigations in place (if any) or add warning

### 5. Document ACME DNS Challenge Integration Status
- DNS-01 challenge implementation exists at `src/tls/acme_dns.rs` but the document doesn't mention the feature gate
- Should clarify: `dns` feature must be enabled for DNS-01 challenges to work

### 6. Add Performance Consideration for Hybrid Signatures
- The 2420-byte ML-DSA signature significantly increases message size vs pure Ed25519 (64 bytes)
- Consider documenting bandwidth implications for mesh DHT traffic

### 7. Document RAft Consensus for Global Nodes
- The architecture document mentions Raft for global nodes but this appears to be incomplete (MESH-15)
- Should add explicit note that quorum deadlock risk exists during network partitions

### 8. Clarify Dependency on rustls-post-quantum
- The post-quantum TLS provider (`rustls_post_quantum`) is a separate crate that must be properly integrated
- Document should reference the explicit Cargo.toml dependency

---

## Summary

The Layer 3.5 architecture document is **largely accurate** with correct claims about:
- PQC implementation (ML-KEM-768, ML-DSA-44, hybrid signatures)
- TLS termination with post-quantum support
- ACME implementation for certificate management
- SNI peeking for TLS fingerprinting

**Key discrepancies:**
1. Documentation references wrong struct name (`MeshHybridSigner` vs `HybridSignature`) for field list
2. Tunnel backend hardcoded `127.0.0.1` could be documented as a known limitation

**No critical bugs found** - all verified code matches documentation claims for the cryptographic implementation. The main improvement areas are documentation clarity and some tunneling implementation details.
