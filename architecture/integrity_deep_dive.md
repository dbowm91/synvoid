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
    session_key: Arc<RwLock<Option<SessionKey>>>,
    ed25519_signing_key: Option<Ed25519SigningKey>,
    ed25519_verifying_key: Option<Ed25519VerifyingKey>,
    mldsa_signing_key: Option<MldsaSigningKey>,
    mldsa_verifying_key: Option<MldsaVerifyingKey>,
}

// Signature format: [type_byte][ed25519_sig(64)][ml_dsa_sig(2420)]
// type_byte: 0x00 = Ed25519 only, 0x01 = hybrid Ed25519+ML-DSA
```

### Verification

```rust
pub struct HttpMessageVerifier {
    session_keys: Arc<RwLock<HashMap<String, SessionKey>>>,
    client_ed25519_verifying_keys: Arc<RwLock<HashMap<String, Ed25519VerifyingKey>>>,
    client_mldsa_verifying_keys: Arc<RwLock<HashMap<String, MldsaVerifyingKey>>>,
}

impl HttpMessageVerifier {
    pub fn verify_request(&self, method, path, query, headers, body, integrity_header, signature)
        -> Result<bool, String> { ... }
    pub fn verify_response(&self, status, headers, body, integrity_header, signature)
        -> Result<bool, String> { ... }
    // Returns true if EITHER Ed25519 OR ML-DSA signature is valid
    // (backward compatibility during migration)
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
    attestations: Arc<RwLock<HashMap<String, OriginAttestation>>>,
    trusted_keys: Arc<RwLock<HashMap<String, String>>>,
    max_attestations: usize,
}

pub struct OriginAttestation {
    pub mesh_id: String,
    pub node_id: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: Option<String>,
    pub signed_at: i64,
    pub expires_at: i64,
    pub signature: String,
    pub attested_by: String,
}
```

### Verification Modes

```rust
pub enum IntegrityMode {
    Disabled,   // No integrity checking (default)
    Audit,      // Log failures, allow traffic
    Enforced,   // Reject invalid signatures
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
| `SessionKeyManager` | `crates/synvoid-integrity/src/protocol.rs` | Session lifecycle |
| `HttpMessageSigner` | `crates/synvoid-integrity/src/signing.rs` | Message signing |
| `HttpMessageVerifier` | `crates/synvoid-integrity/src/signing.rs` | Message verification |
| `IntegrityVerifier` | `crates/synvoid-integrity/src/verification.rs` | High-level verification |
| `OriginKeyExchangeManager` | `crates/synvoid-integrity/src/protocol.rs` | Origin-signed flow (feature-gated) |
| `AttestationRegistry` | `crates/synvoid-integrity/src/attestation.rs` | Origin attestation |
