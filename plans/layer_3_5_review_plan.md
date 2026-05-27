# Layer 3.5 (TLS/Crypto) Architecture Review Plan

**Review Date:** 2026-05-27
**Document:** `architecture/layer_3_5_deep_dive.md`
**Reviewer:** AI Agent

---

## Verified Correct Items

### 1. HybridSignature Struct ✅
**Doc:** `src/mesh/hybrid_signature.rs:36-58`
**Actual:** Lines 16-22 in `src/mesh/hybrid_signature.rs`
- `ed25519_signature: Vec<u8>` (64 bytes)
- `ml_dsa_signature: Vec<u8>` (2420 bytes)
- `ed25519_public_key: String`
- `ml_dsa_public_key: Option<String>`
**Status:** MATCHES - Struct fields exactly as documented.

### 2. MeshHybridSigner ✅
**Doc:** `src/mesh/ml_dsa.rs:122`
**Actual:** Line 122 in `src/mesh/ml_dsa.rs`
**Status:** MATCHES - Concrete mesh signer using Ed25519 + ML-DSA-44.

### 3. HybridSigner Trait ✅
**Doc:** `src/mesh/hybrid_signature.rs:190`
**Actual:** Line 190 in `src/mesh/hybrid_signature.rs`
**Status:** MATCHES - Generic trait with `sign_hybrid()` / `verify_hybrid()`.

### 4. verify_hybrid() Fail-Safe Behavior (BUG-L1) ✅
**Doc:** `src/mesh/ml_dsa.rs:189-219`
**Actual:** Lines 189-219 in `src/mesh/ml_dsa.rs`
**Status:** MATCHES - Ed25519 verified first, ML-DSA optional, returns `true` when ML-DSA absent.

### 5. Post-Quantum TLS Provider Installation ✅
**Doc:** `src/startup/master.rs:210-234`
**Actual:** Lines 212-242 in `src/startup/master.rs`
**Status:** MATCHES - `rustls_post_quantum::provider().install_default()` with fallback warning.

### 6. Hybrid Signature Sizes ✅
**Doc:** `ED25519_SIGNATURE_SIZE = 64`, `ML_DSA_SIGNATURE_SIZE = 2420`
**Actual:** Lines 13-14 in `src/mesh/hybrid_signature.rs`
**Status:** MATCHES.

### 7. pqc-mesh Feature Flag ✅
**Doc:** Mitigation via `pqc-mesh` feature flag
**Actual:** `Cargo.toml:37` - `pqc-mesh = []`
**Status:** MATCHES.

### 8. TunnelBackend Enum ✅
**Doc:** `src/tunnel/router.rs:200`
**Actual:** Lines 200-208 in `src/tunnel/router.rs`
**Status:** MATCHES - `Direct { host, port }` and `Tunnel { session_id, identifier }` variants.

### 9. resolve_tunnel_backend() Uses Configured Host ✅
**Doc:** L35-1 fix - uses configured `upstream_host` from `server_mappings`
**Actual:** Lines 159-165 in `src/tunnel/router.rs`
**Status:** MATCHES - Falls back to `127.0.0.1` only if upstream_host not set.

### 10. CryptoVerificationPool ✅
**Doc:** `src/mesh/crypto_verification.rs`
**Actual:** `src/mesh/crypto_verification.rs` (245 lines)
**Status:** EXISTS - `verify_ml_dsa_standalone()` at lines 65-89 matches usage in protocol.rs.

### 11. verify_hybrid_async() ✅
**Doc:** `src/mesh/protocol.rs:197-232`
**Actual:** Lines 197-233 in `src/mesh/protocol.rs`
**Status:** MATCHES - Uses CryptoVerificationPool for parallel verification.

### 12. MlKem768 Constants ✅
**Doc:** ML-KEM-768 sizes
**Actual:** Lines 124-127 in `src/mesh/kem/ml_kem.rs`
**Status:** MATCHES - `PUBLIC_KEY_SIZE = 1184`, `SECRET_KEY_SIZE = 2400`, `CIPHERTEXT_SIZE = 1088`.

### 13. rustls prefer-post-quantum ✅
**Doc:** Uses `aws-lc-rs` backend with `prefer-post-quantum`
**Actual:** `Cargo.toml:155` - `rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }`
**Status:** MATCHES.

### 14. MlKemKeyExchangeService gRPC Service ✅
**Doc:** `src/mesh/ml_kem_key_exchange.rs:35`
**Actual:** Line 35 in `src/mesh/ml_kem_key_exchange.rs`
**Status:** MATCHES.

---

## Discrepancies Found

### D1: ACME DNS Provider Path Incorrect
**Doc:** `architecture/layer_3_5_deep_dive.md:176` - `src/dns/provider.rs`
**Actual:** Does not exist. ACME DNS-01 challenge is at `src/tls/acme_dns.rs`
**Severity:** Documentation error
**Impact:** Low - ACME DNS integration exists but at different path.

### D2: Hybrid Signature Verification Pool Fallback
**Doc:** `src/mesh/protocol.rs:213` - uses `CryptoVerificationPool::verify_ml_dsa_standalone()` when pool available
**Actual:** Lines 213-229 show pool check but falls back to `self.verify_hybrid()` which is synchronous
**Severity:** Minor - Works correctly but less efficient when pool unavailable.

---

## Bugs Identified

### BUG-L3: ML-KEM Proof-of-Possession Incomplete
**Location:** `src/mesh/ml_kem_key_exchange.rs:249-263`
**Severity:** MEDIUM
**Issue:** `confirm_key()` verifies decapsulation succeeds but does NOT verify the derived secret matches what the client should have computed.

**Current Code (lines 249-263):**
```rust
let decapsulated_secret =
    MlKem768::decapsulate(&session.ciphertext, &session.local_secret_key)
        .map_err(|e| {
            tracing::warn!("ML-KEM decapsulation failed during confirm: {}", e);
            Status::internal("Decapsulation failed")
        })?;

// Missing: comparison of decapsulated_secret with session.session_key
tracing::debug!("ML-KEM key confirm verified: session_id={}, shared_secret_present=true", session_id);
Ok(Response::new(MlKemKeyConfirmResponse { success: true, ... }))
```

**Gap:** The Session struct stores `session_key` (line 59 in `session/manager.rs`) which is the original shared secret computed during encapsulation. After `decapsulate()` succeeds, the code returns success without checking if `decapsulated_secret` equals `session.session_key`.

**Attack Scenario:** A rogue server could complete key exchange with a client but in `confirm_key`, even if decapsulation returns a different value (indicating something went wrong), the function still returns success. It only checks that decapsulation didn't error, not that the result is correct.

**Fix Required:** Add after line 253:
```rust
if decapsulated_secret.as_ref() != session.session_key.as_ref() {
    return Ok(Response::new(MlKemKeyConfirmResponse {
        success: false,
        error: "Shared secret mismatch".to_string(),
    }));
}
```

**AGENTS.md Note:** States BUG-L3 is FIXED (`src/mesh/ml_kem_key_exchange.rs:204-265`) but the actual implementation only verifies decapsulation succeeds, not that the derived secret matches. The "fix" appears incomplete.

---

## Suggested Improvements

### SI-1: Add Shared Secret Verification to BUG-L3 Fix
After decapsulating in `confirm_key()`, compare the result with `session.session_key` to ensure the client and server derived the same key.

### SI-2: Update Documentation Path for ACME DNS
Change `architecture/layer_3_5_deep_dive.md:176` from `src/dns/provider.rs` to `src/tls/acme_dns.rs`.

### SI-3: Document MESH-15 Quorum Deadlock in Correct Location
The architecture document references MESH-15 in section 4 (Trust Model) but the issue is in DHT quorum handling at `src/mesh/dht/quorum.rs`. Consider cross-referencing `skills/raft_consensus.md` for full context.

### SI-4: Add verify_post_quantum_tls() to cert.rs Documentation
The `verify-pq` feature flag is mentioned but the actual verification function at `src/mesh/cert.rs` is not documented.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 14 |
| Discrepancies | 2 |
| Bugs (Medium) | 1 |
| Suggested Improvements | 4 |

**Key Finding:** BUG-L3 (ML-KEM proof-of-possession) is marked as FIXED in AGENTS.md but the fix is incomplete. The `confirm_key()` method does not verify the shared secret matches between client and server, only that decapsulation succeeds without error.