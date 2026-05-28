# Integrity Architecture

## 1. Purpose and Responsibility

The Integrity module (`src/integrity/`) provides **end-to-end integrity verification for HTTP traffic** through edge WAF nodes using Ed25519 signing, X25519 key exchange, and optional origin-signed key exchange protocol.

**Core Responsibilities:**
- HTTP request/response signing (Ed25519)
- Session key management via X25519 key exchange
- Audit trail generation
- Attestation framework for origin nodes
- Origin-signed key exchange (feature-gated)

---

## 2. Key Data Structures

```rust
pub struct IntegrityConfig {
    pub enabled: bool,
    pub mode: IntegrityMode,
    pub key_exchange_url: Option<String>,
    pub global_node_domains: Vec<String>,
    pub session_ttl_secs: u64,
    pub max_concurrent_sessions: usize,
    pub sign_request_headers: Vec<String>,
    pub sign_response_headers: Vec<String>,
    pub include_body_hash: bool,
    pub include_method: bool,
    pub include_path: bool,
    pub include_query: bool,
    pub cache_freshness_signed: bool,
    pub audit_report_url: Option<String>,
    pub verify_on_edge: bool,
    pub allow_unsigned_on_edge_failure: bool,
    pub audit_pow_enabled: bool,
    pub audit_pow_difficulty: u8,
    pub audit_pow_timeout: u64,
    pub audit_nodes: Vec<String>,
    pub allowed_upstream_ips: Vec<String>,
}

pub enum IntegrityMode {
    Disabled,
    Audit,
    Enforced,
}

pub struct IntegrityHeader {
    pub session_id: String,
    pub key_id: String,
    pub timestamp: i64,
    pub nonce: String,
}

pub struct SignedHttpMessage {
    pub integrity_header: IntegrityHeader,
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub body_hash: Option<String>,
    pub signature: String,
    pub signed_at: i64,
}

pub struct SessionKey {
    pub session_id: String,
    pub key_id: String,
    pub mesh_id: String,
    pub verifying_key: String,
    pub client_x25519_pubkey: Option<String>,
    pub derived_key: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `IntegrityConfig::is_enabled()` | Check if integrity is active |
| `IntegrityConfig::is_audit_only()` | Audit-only mode check |
| `IntegrityConfig::is_enforced()` | Enforcement mode check |
| `to_header_value(edge_node_id, mesh_id, pow_challenge)` | Generate X-Integrity-Config header |
| `derive_session_key()` | Derive session key |
| `generate_random_key()` | Generate random key material |

---

## 4. Submodules

### `signing/` — HTTP Message Signing
- Ed25519 key operations
- HTTP header canonicalization
- Signature generation

### `verification/` — Message Verification
- Signature verification
- Timestamp validation
- Replay protection

### `audit/` — Audit Trail
- Verification result logging
- Audit report generation
- Anomaly detection

### `attestation/` — Attestation Framework
- Origin node attestation
- Attestation signing/verification
- Trust chain validation

---

## 5. Integration Points

- **HTTP Server**: Request/response signing in pipeline
- **Mesh**: Identity system for key management
- **Admin API**: Integrity configuration endpoints
- **Feature Gate**: `origin_key_exchange` for origin-signed protocol

---

## 6. Security Considerations

- **Ed25519**: High-performance elliptic curve signatures
- **X25519**: Ephemeral key exchange for forward secrecy
- **Audit Mode**: Logs violations without blocking (testing)
- **Enforced Mode**: Blocks unsigned/invalid requests
- **Timestamp Validation**: Prevents replay attacks
