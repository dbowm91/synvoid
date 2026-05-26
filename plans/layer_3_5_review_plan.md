# Layer 3.5 Deep Dive Review Plan

**Document Reviewed:** `architecture/layer_3_5_deep_dive.md`  
**Review Date:** 2026-05-26  
**Reviewer:** Code Analysis Agent

---

## Stale Items Identified

### 1. TunnelBackend Path Reference
- **Document says:** `src/tunnel/upstream.rs` (line 63)
- **Issue:** The document describes this as the file containing TunnelBackend, which is correct. However, `TunnelBackend.to_backend()` at line 120-122 creates `BackendProtocol::Tcp` correctly, but the document's description of "half-TCP" mode may be outdated as the tunnel system has evolved.

### 2. rustls_post_quantum Dependency
- **Document implies:** PQC TLS via `prefer-post-quantum` configuration flag
- **Actual State:** 
  - Feature flag `post-quantum = ["dep:rustls-post-quantum"]` exists in `Cargo.toml:30`
  - `rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }` is configured at line 154
  - The `prefer-post-quantum` feature is built into rustls itself (not requiring rustls-post-quantum)
  - `rustls-post-quantum = { version = "0.2", optional = true }` exists but is NOT enabled by default
  - `rustls_post_quantum::provider()` is only called in `src/startup/master.rs:214` behind `#[cfg(feature = "post-quantum")]`

### 3. HybridSignature Structure Description
- **Document says (line 13):** "concatenates an Ed25519 signature (64 bytes) with an ML-DSA-44 signature (2420 bytes)"
- **Actual State:** `HybridSignature` is a struct with separate fields (`ed25519_signature`, `ml_dsa_signature`), not a simple concatenation. See `src/mesh/hybrid_signature.rs:17-22`

### 4. KEM Algorithm Names
- **Document says (line 10):** "X25519Kyber768Draft00 or X25519MLKEM768"
- **Actual State:** Only X25519MLKEM768 is used in `src/startup/master.rs:221`. The Kyber768Draft00 variant appears to be deprecated/not implemented.

---

## Claims Verified / Issues Found

### ✓ VERIFIED - PQC Layer 3 (TLS)
| Claim | Status | Location |
|-------|--------|----------|
| Uses rustls with aws-lc-rs backend | ✓ Verified | `Cargo.toml:154`, `src/tls/server.rs:25` |
| prefer-post-quantum configuration | ✓ Verified | `src/tls/config.rs:9`, `src/tls/server.rs:285` |
| X25519MLKEM768 hybrid key exchange | ✓ Verified | `src/startup/master.rs:211,221` |

### ✓ VERIFIED - PQC Layer 5 (Mesh)
| Claim | Status | Location |
|-------|--------|----------|
| ML-KEM-768 for QUIC tunnels | ✓ Verified | `src/mesh/ml_kem_key_exchange.rs:35` |
| MlKemKeyExchangeService exists | ✓ Verified | `src/mesh/ml_kem_key_exchange.rs:100` |
| Hybrid signature scheme (MeshHybridSigner) | ✓ Verified | `src/mesh/ml_dsa.rs:122` |
| Ed25519 + ML-DSA-44 concatenation | ⚠️ Partially | Struct fields, not byte concatenation |

### ✓ VERIFIED - Trust Model
| Claim | Status | Location |
|-------|--------|----------|
| validate_peer_role function | ✓ Verified | `src/mesh/peer_auth.rs:248` |
| Role boundaries enforced | ✓ Verified | `src/mesh/config.rs:26-33` (MeshNodeRole bitflags) |
| GlobalNodeRevocationList | ✓ Verified | `src/mesh/peer_auth.rs:21` |
| DhtAccessControl | ✓ Verified | `src/mesh/dht/mod.rs:689` |
| PoW validation for edge nodes | ✓ Verified | `src/mesh/peer_auth.rs:540` |

### ⚠️ ISSUE FOUND - verify_hybrid()Ed25519-Only Rejection
| Location | Issue |
|----------|-------|
| `src/mesh/ml_dsa.rs:206-218` | When `signature.has_ml_dsa()` returns `false`, verification returns `false` |

**Problem:** The document claims the hybrid scheme is a "fail-safe" where "if the new PQC algorithm is broken mathematically, the classical Ed25519 signature still holds." However, `verify_hybrid()` returns `false` when ML-DSA is absent, meaning Ed25519-only signatures are rejected.

**Code analysis:**
```rust
pub fn verify_hybrid(&self, content: &[u8], signature: &HybridSignature) -> bool {
    // ... Ed25519 verification ...
    
    if signature.has_ml_dsa() {  // Returns false if ML-DSA not present
        // ... ML-DSA verification ...
    } else {
        false  // <-- Ed25519-only signatures are rejected here!
    }
}
```

**Note:** According to `AGENTS.md:186`, this is listed as "BUG-L1" but marked as "FIXED". However, the code at line 217 clearly shows `false` being returned when ML-DSA is absent. Need to verify if this is actually fixed.

### ⚠️ ISSUE - verified_upstream Allowed for Edge
| Location | Issue |
|----------|-------|
| `src/mesh/dht/mod.rs:707` | `verified_upstream:` is in `allowed_keys_for_edge` |

**Contradiction:** The document (line 53) states origin nodes "cannot overwrite `verified_upstream:` routes." However, `DhtAccessControl::new()` puts `verified_upstream:` in `allowed_keys_for_edge` (line 707), meaning edge nodes CAN write to it.

**Note:** The `can_store()` method at line 788 has additional checks via `global_signature_required_keys` which includes `verified_upstream:`, but this appears to be for writes requiring global signature, not access control.

---

## Improvement Plan

### High Priority

1. **Clarify verify_hybrid() Fail-Safe Behavior**
   - Issue: Ed25519-only signatures should be valid as fail-safe
   - Location: `src/mesh/ml_dsa.rs:189-219`
   - Fix: Modify `verify_hybrid()` to accept Ed25519-only signatures when ML-DSA is absent

2. **Edge Node verified_upstream Access**
   - Issue: Contradiction between document and code
   - Location: `src/mesh/dht/mod.rs:707`
   - Fix: Either update document or fix code if edge nodes should NOT have `verified_upstream:` in allowed keys

### Medium Priority

3. **Update rustls_post_quantum Documentation**
   - Issue: Document implies active usage of rustls-post-quantum
   - Location: `Cargo.toml:156`, `src/startup/master.rs:214`
   - Fix: Clarify that post-quantum TLS requires `--features post-quantum` flag

4. **KEM Algorithm Consistency**
   - Issue: Document mentions X25519Kyber768Draft00 which is not used
   - Fix: Update document to only mention X25519MLKEM768

5. **HybridSignature Byte Layout**
   - Issue: Document describes "concatenation" but it's struct fields
   - Location: `src/mesh/hybrid_signature.rs:17-17`
   - Fix: Update description to reflect actual struct implementation

### Low Priority

6. **Add Half-TCP + Mesh Integration Details**
   - Issue: Section 6 hints at DHT integration but doesn't explain how
   - Fix: Add details on how tunnel routes are published to DHT and discovered

---

## Bug Report

### Critical Bugs

**BUG-L1: verify_hybrid() Rejects Ed25519-Only Signatures**
- **Severity:** Critical
- **Location:** `src/mesh/ml_dsa.rs:206-218`
- **Description:** The `verify_hybrid()` function returns `false` when `has_ml_dsa()` is `false`, even if a valid Ed25519 signature is present. This contradicts the documented "fail-safe" design where Ed25519 should remain valid if ML-DSA fails.
- **Impact:** Nodes without ML-DSA capability cannot communicate with nodes that have ML-DSA, OR messages signed without ML-DSA will be rejected system-wide.
- **Status:** Listed in AGENTS.md as "FIXED" but code shows `false` at line 217

### Minor Bugs

**MINOR-1: Stale Feature Reference**
- **Severity:** Minor
- **Location:** `architecture/layer_3_5_deep_dive.md:10` - mentions X25519Kyber768Draft00
- **Description:** Algorithm not used in codebase
- **Impact:** Documentation inaccuracy

**MINOR-2: Edge Write Access Contradiction**
- **Severity:** Minor  
- **Location:** `src/mesh/dht/mod.rs:707` vs document line 53
- **Description:** `verified_upstream:` in `allowed_keys_for_edge` contradicts document stating origin/edge nodes cannot overwrite it
- **Impact:** Unclear security boundary

---

## Summary

| Category | Count |
|----------|-------|
| Stale Items | 4 |
| Verified Claims | 6 |
| Issues Found | 2 (1 critical, 1 minor) |
| Improvement Items | 6 (2 high, 2 medium, 2 low) |

**Key Finding:** The most critical issue is the `verify_hybrid()` function potentially rejecting valid Ed25519-only signatures, contradicting the fail-safe design principle stated in the document. The disconnect between AGENTS.md claiming this is "FIXED" and the code showing `false` at line 217 needs immediate verification.
