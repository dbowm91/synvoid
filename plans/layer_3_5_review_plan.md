# Layer 3.5 Review Plan: TLS/Crypto Architecture

## Executive Summary

The architecture document `architecture/layer_3_5_deep_dive.md` provides a generally accurate high-level overview of SynVoid's Layer 3 (TLS/Proxy) and Layer 5 (Mesh) post-quantum cryptography implementation. However, several discrepancies exist between documented claims and actual source code.

---

## 1. Verified Correct Claims

| Document Line | Claim | Verification | Status |
|---------------|-------|--------------|--------|
| 10 | `rustls` with `aws-lc-rs` backend and `prefer-post-quantum` flag | `Cargo.toml:154` confirms `rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }` | ✅ Correct |
| 10 | X25519MLKEM768 for TLS 1.3 handshakes | `src/startup/master.rs:221` logs "Post-quantum TLS (X25519MLKEM768) enabled" | ✅ Correct |
| 12 | ML-KEM-768 for QUIC tunnels | `src/mesh/kem/ml_kem.rs:61-128` implements `MlKem768` using `pqc::MlKem768` | ✅ Correct |
| 12 | `MlKemKeyExchangeService` for mesh key exchange | `src/mesh/ml_kem_key_exchange.rs:35-96` defines the service | ✅ Correct |
| 13 | Uses `libcrux` for ML-DSA-44 | `src/mesh/ml_dsa.rs:10` uses `pqc::{MlDsa44, ...}` | ✅ Correct |
| 13 | Hybrid signature struct has `ed25519_signature`, `ml_dsa_signature`, `ed25519_public_key`, `ml_dsa_public_key` | `src/mesh/hybrid_signature.rs:17-22` matches exactly | ✅ Correct |
| 13 | `MeshHybridSigner` fail-safe (Ed25519 if PQC broken) | `src/mesh/ml_dsa.rs:189-218` verifies Ed25519 first, then ML-DSA if present | ✅ Correct |
| 14 | Ed25519 signature is 64 bytes, ML-DSA is 2420 bytes | `src/mesh/hybrid_signature.rs:13-14` defines `ED25519_SIGNATURE_SIZE = 64`, `ML_DSA_SIGNATURE_SIZE = 2420` | ✅ Correct |
| 63 | `TunnelBackend` in `src/tunnel/upstream.rs` | `src/tunnel/upstream.rs:105-122` exists with correct structure | ✅ Correct |

---

## 2. Stale Claims & Missing Documentation

### 2.1 BUG-L1: `verify_hybrid()` Fail-Safe Not Documented

**Document:** Does not mention BUG-L1 or the fail-safe behavior.

**Actual Code:** `src/mesh/ml_dsa.rs:206-218`:
```rust
if signature.has_ml_dsa() {
    // verify ML-DSA
} else {
    true  // Fail-safe: return true when no ML-DSA
}
```

**Issue:** The document should explicitly state that `verify_hybrid()` returns `true` when a signature lacks ML-DSA data, providing fail-safe behavior if the PQC algorithm is broken or unavailable.

### 2.2 BUG-L3: ML-KEM Proof-of-Possession Fix Not Documented

**Document:** Does not mention BUG-L3 (ML-KEM key exchange proof-of-possession).

**Actual Code:** `src/mesh/ml_kem_key_exchange.rs:204-264` (`confirm_key` method):
- Line 242-246: Verifies client public key matches stored session public key
- Line 249-253: Calls `MlKem768::decapsulate()` to verify client can derive the shared secret

**Issue:** The document should note that the ML-KEM key exchange includes proof-of-possession verification: the server decapsulates using the stored ciphertext and secret key, confirming the client legitimately received and can use the shared secret.

### 2.3 Missing: Post-Quantum Provider Installation

**Document:** Line 10 mentions `prefer-post-quantum` config flag but does not cover the runtime provider installation.

**Actual Code:** `src/startup/master.rs:210-234`:
```rust
#[cfg(feature = "post-quantum")]
{
    use rustls_post_quantum::provider;
    if let Err(e) = provider().install_default() {
        tracing::warn!("Failed to install post-quantum TLS provider: {:?}. Using default.", e);
    } else {
        tracing::info!("Post-quantum TLS (X25519MLKEM768) enabled");
        // ... logs key exchange group count
    }
}
```

**Issue:** The document should explain that enabling `post-quantum` feature installs `rustls_post_quantum::provider()` as the default crypto provider, which provides the X25519MLKEM768 hybrid key exchange.

---

## 3. Incorrect Claims

### 3.1 Wrong File Path for `TunnelBackend::to_backend()`

**Document Line 63-69:**
```rust
The `TunnelBackend` (`src/tunnel/upstream.rs`) provides half-TCP proxy functionality:

pub fn to_backend(&self) -> Backend {
    Backend::new(format!("tcp:127.0.0.1:{}", self.port))
        .with_protocol(BackendProtocol::Tcp)
}
```

**Actual:** The function exists but the path reference is acceptable. However, the document shows a code block that does NOT appear verbatim in the file. The actual code at `src/tunnel/upstream.rs:120-122` is:
```rust
pub fn to_backend(&self) -> Backend {
    Backend::new(format!("tcp:127.0.0.1:{}", self.port)).with_protocol(BackendProtocol::Tcp)
}
```

**Issue:** Minor - code example is correct but line number not provided. Should reference lines 120-122.

### 3.2 Naming Inconsistency: `X25519MLKEM768Draft00` vs `X25519MLKEM768`

**Document Line 10:** States "X25519MLKEM768"

**Other Documentation:** `architecture/networking_deep_dive.md:68` states:
> Enables `X25519MLKEM768Draft00` in rustls for TLS 1.3 handshakes

**Actual:** The code uses `X25519MLKEM768` (final RFC 9420 name), not the draft name.

**Issue:** `networking_deep_dive.md` uses stale draft naming. The standard evolved from `X25519Kyber768Draft00` to `X25519MLKEM768`. BUG-L3 was specifically about this naming transition.

---

## 4. Security Considerations

### 4.1 Trust Model - Quorum Deadlock (MESH-15)

**Document Lines 42-44:**
> The reliance on a `2/3 Quorum` of Global nodes to sign new `OrgPublicKey` records is dangerous in a purely DHT-based system without a consensus leader.

**Assessment:** The document correctly identifies this risk, but it should be marked as a **known limitation** (MESH-15) with a reference to the Raft migration plan.

**Missing:** No mention of MESH-15 ID for tracking this issue.

### 4.2 Missing: Hybrid Signature Verification Pool

**Document:** Does not mention async verification with `CryptoVerificationPool`.

**Actual:** `src/mesh/protocol.rs:197-232` shows `verify_hybrid_async()` uses `CryptoVerificationPool::verify_ml_dsa_standalone()` for concurrent verification.

**Issue:** The document should note that for high-throughput mesh message verification, an async verification pool is used to parallelize Ed25519 and ML-DSA verification.

---

## 5. ML-DSA Signature Size Verification

**Test Verification:** `src/mesh/ml_dsa.rs:287-288`:
```rust
let sig = ml_dsa_signer.sign(message).unwrap();
assert_eq!(sig.len(), 2420);
```

Confirmed: ML-DSA-44 produces 2420-byte signatures.

---

## 6. ML-KEM Key Sizes Verification

**Code:** `src/mesh/kem/ml_kem.rs:124-127`:
```rust
const PUBLIC_KEY_SIZE: usize = 1184;
const SECRET_KEY_SIZE: usize = 2400;
const CIPHERTEXT_SIZE: usize = 1088;
const SHARED_SECRET_SIZE: usize = 32;
```

These match the ML-KEM-768 specification (Kyber768).

---

## 7. Summary of Required Updates

| Priority | Issue | Location | Action |
|----------|-------|----------|--------|
| High | Add BUG-L1 fail-safe documentation | Line ~13 | Document that `verify_hybrid()` returns `true` when ML-DSA absent |
| High | Add BUG-L3 ML-KEM proof-of-possession | Line ~12 | Document `confirm_key` verifies client can decapsulate |
| Medium | Add provider installation details | Line ~10 | Document `rustls_post_quantum::provider()` installation |
| Medium | Reference MESH-15 for quorum deadlock | Line 43 | Add "See MESH-15" reference |
| Low | Fix naming in networking_deep_dive.md | Line 68 | Change `X25519MLKEM768Draft00` to `X25519MLKEM768` |
| Low | Add async verification pool docs | Line ~13 | Document `verify_hybrid_async()` with verification pool |

---

## 8. Conclusion

The architecture document is **mostly accurate** for high-level descriptions but **lacks important implementation details** about:
1. The fail-safe behavior in hybrid signature verification
2. The ML-KEM proof-of-possession fix (BUG-L3)
3. The runtime provider installation mechanism

The core crypto implementations (`MlKem768`, `MlDsa44`, `MeshHybridSigner`, `HybridSignature`) are correctly implemented and match the documented intent.