# Security Patterns Skill (Wave 1 & Wave 2)

## Overview

This skill documents the security patterns implemented in Wave 1 and Wave 2 (2026-04-13) for the MaluWAF codebase.

## Wave 1: Critical Security (Completed 2026-04-11)

## Constant-Time Comparison for Sensitive Data

### CSRF Token Validation

**Location**: `src/auth/mod.rs:validate_csrf_token()`, `src/admin/state.rs:validate_csrf()`

**Issue**: Timing attacks on CSRF token comparison using `==` operator.

**Pattern**: Use `subtle::ConstantTimeEq::ct_eq()` for comparing sensitive strings:

```rust
use subtle::ConstantTimeEq;

// BEFORE (vulnerable to timing attack)
return session.csrf_token.as_deref() == Some(csrf_token);

// AFTER (constant-time comparison)
if let Some(stored) = session.csrf_token.as_deref() {
    return bool::from(stored.as_bytes().ct_eq(csrf_token.as_bytes()));
}
```

**When to use**: Any time you compare secrets, tokens, keys, or other sensitive data that could leak timing information.

---

## Crypto RNG Error Handling

### DNS Crypto RNG Pattern

**Location**: `src/dns/crypto_rng.rs`

**Issue**: Cryptographic functions returning zero-filled values when entropy fails instead of propagating errors.

**Pattern**: Functions return `Result<T, CryptoRngError>`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoRngError {
    #[error("Failed to get random bytes: {0}")]
    EntropyError(#[from] getrandom::Error),
}

pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoRngError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)?;
    Ok(bytes)
}

pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoRngError> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)?;
    Ok(bytes)
}
```

**Handling at call sites**:
- **Critical startup paths** (secret keys, HSM): Use `.expect()`
- **Response building** (transaction IDs): Use `.expect()` - cannot fail safely
- **Non-critical paths** (rate limiting): Use fallback with warning logged

```rust
// Critical: fail fast at startup
let secret_key = super::crypto_rng::random_array::<32>()
    .expect("Crypto RNG failure at startup");

// Rate limiting: degrade gracefully
fn rand_f32() -> f32 {
    match crate::dns::crypto_rng::random_u32() {
        Ok(bytes) => (bytes as f32) / (u32::MAX as f32),
        Err(e) => {
            tracing::warn!("Crypto RNG failed in rate limiter: {}", e);
            0.0  // Reject all on RNG failure (safe default)
        }
    }
}
```

---

## Mesh Peer Authentication

### Node Role Validation

**Location**: `src/mesh/peer_auth.rs`

**Issue**: Non-global nodes bypassed authentication entirely - malicious edge nodes could claim any role.

**Fix**: All node types now require Ed25519 signature verification:

| Node Type | Requirement | Challenge Format |
|----------|-------------|------------------|
| Global | Ed25519 signature + authorized key | `"{node_id}:{timestamp}"` |
| Edge | Ed25519 self-signature | `"edge:{node_id}:{timestamp}"` |
| Origin | Ed25519 self-signature + Global attestation | `"origin:{node_id}:{timestamp}"` |

**Key functions**:
- `validate_peer_role()` - main entry point, dispatches by role
- `validate_edge_node()` - verifies self-signature
- `validate_origin_node()` - verifies self-signature + global attestation
- `validate_global_node()` - verifies against authorized keys
- `verify_signature()` - shared Ed25519 verification logic

**Helper for signature generation**:
```rust
pub fn generate_global_node_auth(
    node_id: &str,
    secret_key: &[u8; 32],
) -> Result<(String, u64), String> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let timestamp = crate::utils::current_timestamp();
    let challenge = format!("{}:{}", node_id, timestamp);
    let signature = signing_key.sign(challenge.as_bytes());
    Ok((base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()), timestamp))
}
```

---

## IPC Message Signing

### Overseer-Worker Communication

**Location**: `src/process/ipc.rs`, `src/overseer/ipc_client.rs`, `src/process/ipc_signed.rs`

**Issue**: IPC messages between overseer and workers were unsigned.

**Fix**: Added HMAC-signed message support:

```rust
// IpcSigner for creating signed connections
pub struct IpcSigner {
    key: Arc<[u8; 32]>,
}

impl IpcSigner {
    pub fn new(key: &[u8; 32]) -> Self { ... }
    pub fn sign(&self, message: &[u8]) -> Vec<u8> { ... }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool { ... }
}

// Connect with signer
let stream = IpcStream::connect_with_signer(path, signer).await?;

// Send signed message
stream.send_signed(&msg, &signer).await?;
```

**Backwards compatibility**: If no key is available, falls back to unsigned.

---

## File Permissions for Private Keys

### Unix Permission Pattern

**Location**: `src/mesh/config_identity.rs`, `src/tls/acme.rs`

**Issue**: Private key files created with default permissions (readable by others).

**Pattern**:
```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;

// Write to temp file first
let temp_path = path.with_extension("tmp");
fs::write(&temp_path, &key_data)?;

// Set restrictive permissions BEFORE rename
fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;

// Atomic rename
fs::rename(&temp_path, &path)?;
```

---

## Bounded Caches

### Nonce Cache Size Limit

**Location**: `src/process/ipc_signed.rs`

**Issue**: Unbounded LRU cache could grow indefinitely.

**Pattern**:
```rust
const MAX_NONCE_CACHE_SIZE: usize = 10000;

static NONCE_CACHE: LazyLock<RwLock<LruCache<String, Instant>>> = ...

fn evict_oldest() {
    let mut cache = NONCE_CACHE.write();
    while cache.len() > MAX_NONCE_CACHE_SIZE {
        if let Some(_oldest) = cache.pop_oldest() {
            // Evict until under limit
        }
    }
}
```

---

## ThreatIntel DHT Keys

### Composite Key Pattern

**Location**: `src/mesh/threat_intel.rs`

**Issue**: Multiple threat types for same IP overwrote each other (key was just IP).

**Fix**: Use composite keys `"{threat_type}:{ip}"`:

| Key Pattern | Purpose |
|-------------|---------|
| `IpBlock:{ip}` | IP blocking indicator |
| `{threat_type}:{ip}` | Specific threat type |
| `RateLimitViolation:{ip}` | Rate limit exceeders |
| `SuspiciousActivity:{ip}` | Suspicious behavior |

---

## Wave 2: High Security (Completed 2026-04-13)

### bcrypt Cost Validation (W2.1)

**Location**: `src/config/admin.rs:validate()`

**Pattern**: Minimum cost enforcement:
```rust
if self.bcrypt_cost < 12 || self.bcrypt_cost > 15 {
    return Err(ConfigValidationError {
        field: "admin.bcrypt_cost".to_string(),
        message: "bcrypt_cost must be between 12 and 15".to_string(),
    });
}
```

**Recommended values**: Industry standard is 12+. Higher values are more secure but slower.

---

### Multi-Genesis Key Support (W2.2)

**Location**: `src/mesh/config.rs:GenesisKeyConfig`, `src/mesh/config_identity.rs`

**Pattern**: Authorized key list with backward compatibility:
```rust
pub struct GenesisKeyConfig {
    pub authorized_genesis_keys: Vec<String>,  // Empty = any key allowed
    pub previous_genesis_key_base64: Option<String>,
    pub rotation_sequence: u32,
}

impl GenesisKeyConfig {
    pub fn is_genesis_key_authorized(&self, public_key: &str) -> bool {
        if self.authorized_genesis_keys.is_empty() {
            return true;  // Backward compatible - any key allowed
        }
        self.authorized_genesis_keys.iter().any(|k| k == public_key)
    }
}
```

---

### Distributed Revocation (W2.3)

**Location**: `src/mesh/transport_global.rs`

**Pattern**: DHT + gossip for revocation propagation:
```
1. Global node creates signed revocation
2. Stores in DHT: revoked_global_node:{node_id} with 24h TTL
3. Broadcasts to peers: RevokeGlobalNode message
4. Peers verify signature, store locally, rebroadcast
5. validate_global_node() checks revocation list before trusting
```

---

### Edge Node PoW Authentication (W2.6)

**Location**: `src/mesh/peer_auth.rs`, `src/mesh/transport.rs`

**Pattern**: Dual authentication (Ed25519 OR PoW):
```rust
pub fn validate_peer_role(
    // ... existing params ...
    pow_nonce: Option<u64>,
    pow_public_key: Option<&str>,
) -> Result<(), String> {
    if let (Some(nonce), Some(pubkey)) = (pow_nonce, pow_public_key) {
        // PoW path - validate using NodeId::verify_pow()
        validate_edge_node_pow(pubkey, nonce)
    } else {
        // Ed25519 signature path (original)
        validate_edge_node(node_id, peer_public_key, peer_signature, ...)
    }
}
```

---

### Capability Attestation (W2.8)

**Location**: `src/mesh/dht/capability_attestation.rs`, `src/mesh/transport.rs`

**Pattern**: Global node verifies and attestates capabilities:
```rust
pub struct CapabilityAttestation {
    pub node_id: String,
    pub capability: String,  // dns_server, waf, edge_proxy, origin
    pub attested_by_global_node: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

// Attest only after verification
fn attest_capability(node_id: &str, capability: &str) {
    // 1. Verify node actually HAS the capability
    verify_node_capability(peer_state, capability)?;
    // 2. Sign attestation with global node key
    // 3. Store in DHT: capability_attestation:{node_id}:{capability}
}
```

**Capability types**:
- `dns_server` - Node runs DNS server
- `waf` - WAF enabled
- `edge_proxy` - Can proxy requests
- `origin` - Has registered upstreams

---

## Key Files Reference

| File | Security Pattern |
|------|------------------|
| `src/auth/mod.rs` | Constant-time CSRF comparison |
| `src/admin/state.rs` | Constant-time session ID comparison |
| `src/dns/crypto_rng.rs` | Result-based RNG with error propagation |
| `src/mesh/peer_auth.rs` | Role-based Ed25519 + PoW authentication |
| `src/process/ipc.rs` | IPC signing with HMAC |
| `src/process/ipc_signed.rs` | Signed message deserialization |
| `src/overseer/ipc_client.rs` | Signed overseer IPC |
| `src/mesh/config_identity.rs` | 0o600 key permissions, multi-genesis keys |
| `src/mesh/threat_intel.rs` | Composite DHT keys |
| `src/mesh/transport_global.rs` | Distributed revocation |
| `src/mesh/dht/capability_attestation.rs` | Capability attestation |
| `src/challenge/mod.rs` | Reduced PoW timeout (12s) |
| `src/config/admin.rs` | bcrypt cost minimum 12 |

---

## Wave 4: Code Quality (Completed 2026-04-13)

### SAFETY_REASON Comments for Intentional Dead Code

**Location**: Throughout codebase, primarily `src/mesh/`, `src/overseer/`, `src/waf/`

**Pattern**: Use `// SAFETY_REASON: ...` comments to document intentional `#[allow(dead_code)]` suppressions:

```rust
// SAFETY_REASON: Reserved for future DNS mesh protocol handling
#[allow(dead_code)]
const DNS_MESH_CONSTANT: &str = "...";

// SAFETY_REASON: Serde requires this field for deserialization but it's not read
#[allow(dead_code)] // serde: field required for deserialization
pub struct UpgradeConfig { ... }
```

**Categories of intentional suppressions**:
- Reserved protocol handlers (transport_dns.rs, transport_org.rs, etc.)
- HSM support (dns/server/mod.rs:503)
- Serde deserialization fields (overseer/upgrade.rs)
- Debug/introspection fields (stored but not read)
- Future use items

**When to use**:
- Reserved code for future protocol/features
- Required by external interfaces (serde)
- Debug/introspection that isn't read yet
- Platform-specific code only used on some platforms

**When NOT to use** (remove the code instead):
- Truly unused helper functions
- Debug prints left in code
- Temporary workarounds (use TODO instead)

---

## Verification Commands

```bash
# Check constant-time comparisons are used
rg "ct_eq" src/auth/mod.rs src/admin/state.rs

# Check crypto RNG returns Result
rg "fn random_" src/dns/crypto_rng.rs
rg "Result.*CryptoRngError" src/dns/

# Check peer auth validation
rg "validate_peer_role" src/mesh/

# Check file permissions
rg "set_permissions.*0o600" src/mesh/config_identity.rs src/tls/acme.rs

# Check bcrypt cost validation
rg "bcrypt_cost < 12" src/config/

# Check PoW authentication
rg "validate_edge_node_pow" src/mesh/

# Check capability attestation
rg "CapabilityAttestation" src/mesh/

# Audit dead_code suppressions
rg "#\[allow\(dead_code)\]" src/ --glob '*.rs' -c

# Check SAFETY comments on unsafe blocks
rg "unsafe \{" src/ --glob '*.rs' -l | xargs -I{} rg "SAFETY" {}
```
