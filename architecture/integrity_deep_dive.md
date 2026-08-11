# Integrity Deep Dive

SynVoid's integrity module provides end-to-end integrity verification for HTTP traffic through edge WAF nodes, enabling WAF inspection and caching while detecting tampering by clients, edges, or origins.

## Architecture

### Hybrid Cryptography

```
Integrity
├── Ed25519 (classical signing)
├── ML-DSA-44 (post-quantum signing)
├── X25519 (classical key exchange)
├── ML-KEM-768 (post-quantum key exchange)
└── Session Key Derivation
```

### Session Key Exchange

```
Client                        Edge Node                     Origin
  │                               │                            │
  ├── KeyOffer ──────────────────►│                            │
  │   (X25519 pub + ML-KEM ct)   │                            │
  │                               ├── KeyConfirm ─────────────►│
  │                               │   (origin signature)       │
  │                               │                            │
  ├── KeyComplete ◄──────────────┤◄───────────────────────────┤
  │   (session key derived)       │   (session key derived)    │
```

### Message Signing

```rust
pub struct HttpMessageSigner {
    ed25519_key: Ed25519Signer,
    ml_dsa_key: Option<MlDsaSigner>,  // Post-quantum (feature-gated)
}

// Signature format: [type_byte][ed25519_sig(64)][ml_dsa_sig(2420)]
```

### Verification

```rust
pub struct HttpMessageVerifier {
    ed25519_verifier: Ed25519Verifier,
    ml_dsa_verifier: Option<MlDsaVerifier>,
}

impl HttpMessageVerifier {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        // Returns true if EITHER Ed25519 OR ML-DSA is valid
        // (backward compatibility during migration)
        self.verify_ed25519(message, signature) 
            || self.verify_ml_dsa(message, signature)
    }
}
```

### Origin Key Exchange

Feature-gated `origin_key_exchange` module:

1. Origin signs session key with its mesh Ed25519 key
2. Client verifies via origin's mesh public key
3. Bypasses untrusted edge nodes
4. Provides origin-to-client integrity without edge trust

### Attestation

```rust
pub struct AttestationRegistry {
    trusted_keys: DashMap<String, Ed25519PublicKey>,
}

pub struct OriginAttestation {
    pub origin_node_id: String,
    pub attestation_key: Ed25519PublicKey,
    pub signed_by: Ed25519PublicKey,  // Global node
    pub expires_at: u64,
    pub signature: [u8; 64],
}
```

### Verification Modes

```rust
pub enum IntegrityMode {
    AuditOnly,    // Log failures, allow traffic
    Enforced,     // Reject invalid signatures
}
```

## Integration Points

- Configured per-site
- Session keys established via mesh key exchange
- `X-Integrity-*` headers carry signatures
- Audit reports sent to global nodes
- ML-KEM support via `pqc` crate

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `SessionKeyManager` | `crates/synvoid-integrity/src/session.rs` | Session lifecycle |
| `HttpMessageSigner` | `crates/synvoid-integrity/src/signing.rs` | Message signing |
| `HttpMessageVerifier` | `crates/synvoid-integrity/src/verification.rs` | Message verification |
| `IntegrityVerifier` | `crates/synvoid-integrity/src/lib.rs` | High-level verification |
| `OriginKeyExchangeManager` | `crates/synvoid-integrity/src/origin_key_exchange.rs` | Origin-signed flow |
| `AttestationRegistry` | `crates/synvoid-integrity/src/attestation.rs` | Origin attestation |
