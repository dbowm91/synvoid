# Security Patterns Skill

## Overview

This skill documents the security patterns implemented for the SynVoid codebase.

## Critical Security Fixes (Wave 4)

### Trusted Signer Default Deny (P0.3)

**Location**: `crates/synvoid-mesh/src/mesh/threat_intel.rs:1628-1656`

**Issue**: When `trusted_signers` is empty, condition `!self.node_role.is_global() && !self.config.trusted_signers.is_empty()` short-circuits and ALL non-global nodes bypass the check. Any non-global node can send forged threats.

**Fix**: Deny-by-default for non-global nodes:
```rust
if !self.node_role.is_global() {
    if self.config.trusted_signers.is_empty() {
        tracing::warn!("No trusted signers configured - rejecting threat from non-global node");
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
    if !self.check_trusted_signer(source_node_id, signer_public_key) {
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
}
```

---

### Time-Based Challenge Verification (P0.5)

**Location**: `crates/synvoid-mesh/src/mesh/security_challenge.rs:159-218`

**Issue**: Previously, `verify_time_based_challenge()` took `_solution: &str` (unused) and only checked challenge existence and expiry. Any string was accepted.

**Fix (implemented)**: Store expected solution at creation, verify against it:
```rust
// In generate_time_based_challenge:
solution: Some(expected_solution),  // Store HMAC of solution

// In verify_time_based_challenge:
let expected_solution = match &challenge.solution {
    Some(s) => s,
    None => { /* reject - no solution expected */ }
};
if solution != expected_solution {
    return false;
}
```

**Verification**: `cargo test --lib -- security_challenge`

---

### Pass-Over Fallback Signing (P0.6)

**Location**: `crates/synvoid-mesh/src/mesh/passover_key_exchange.rs:505-515`

**Issue**: When origin is unreachable, fallback path used `origin_signing_key` to sign. A global node with `origin_signing_key` would produce messages appearing signed by an origin node.

**Fix**: Check node role before using origin signing key:
```rust
let pending_signature = if self.config.role.is_global() {
    // Use global node key instead of origin signing key
    let global_key = self.config.global_node.ed25519_private_key
        .ok_or_else(|| Status::unavailable("Global node Ed25519 key not available"))?;
    // ... sign with global key
} else if let Some(ref signer_config) = self.config.origin_signing_key {
    // Original origin signing path
};
```

---

### RecordStoreManager Clone (P0.7)

**Location**: `crates/synvoid-mesh/src/mesh/dht/record_store.rs:468-519`

**Issue**: Clone impl used `records: ShardedRecordStore::new()` instead of cloning from `self.records`. Cloned managers had zero records.

**Fix**: Iterate and clone records:
```rust
let records = ShardedRecordStore::new();
for (key, value) in rs.records.iter() {
    records.insert(key.clone(), value.clone());
}
```

---

### YARA Trusted Signer Bypass (P0.12)

**Location**: `crates/synvoid-mesh/src/mesh/yara_rules.rs:942-954,1818-1824`

**Issue**: Two problems:
1. DHT sync path: `if !self.config.trusted_signers.is_empty()` with no `is_global()` check
2. Announce path: Signature verification only, no trusted_signers check

**Fix**: Add deny-by-default for non-global nodes in both paths:
```rust
// DHT sync path
if !self.node_role.is_global()
    && !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    // reject
}

// Announce path
if !self.node_role.is_global() && !self.config.trusted_signers.is_empty() {
    if !self.check_trusted_signer(from_node, signer_public_key) {
        return Some(MeshMessage::YaraRuleAcknowledgement { accepted: false, ... });
    }
}
```

---

### WASM Table Growing Unbounded (P0.1)

**Location**: `src/plugin/wasm_runtime.rs:319-326`

**Issue**: `table_growing()` returned `Ok(true)` unconditionally. Tables could grow without bound.

**Fix**: Check against max_table_elements limit:
```rust
fn table_growing(
    &mut self,
    _current: usize,
    desired: usize,
    _maximum: Option<usize>,
) -> std::result::Result<bool, wasmtime::Error> {
    Ok(desired <= self.max_table_elements)
}
```

---

### WASM Pool DHT Prefix Leakage (P0.2)

**Location**: `src/plugin/instance_pool.rs:148-163`

**Issue**: `prepare_for_request()` reset `start`, `timeout`, and `env` but NOT `allowed_dht_prefixes`. Previous tenant's DHT prefixes persisted across pool reuse.

**Fix**: Reset allowed_dht_prefixes:
```rust
pub(crate) fn prepare_for_request(&mut self, env: ..., timeout_seconds: u64) {
    self.store.data_mut().start = Instant::now();
    self.store.data_mut().timeout = Duration::from_secs(timeout_seconds);
    self.store.data_mut().env = env;
    self.store.data_mut().allowed_dht_prefixes = self.default_allowed_dht_prefixes.clone();
    // ...
}
```

---

### Serverless Ignore Limits (P0.4)

**Location**: `src/serverless/manager.rs:479-491,506-518`

**Issue**: `_limits` was constructed but NOT passed to `load_plugin_from_memory()` / `load_plugin()`. Memory/CPU/timeout limits were silently discarded.

**Fix**: Pass limits to the calls:
```rust
let limits = WasmResourceLimits {
    max_memory_mb: func_def.memory_mb.unwrap_or(default_memory),
    // ...
};
return self.runtime
    .load_plugin_from_memory(&func_def.name, &data, limits)
    .map_err(|e| ServerlessError::WasmError(e.to_string()));
```

---

### KyberSlash Vulnerability (P0.A)

**Location**: `src/wasm_pow/Cargo.toml:30`, `src/wasm_pow/src/pqc.rs:6`

**Issue**: `pqc_kyber` 0.7.1 has timing side-channel in ML-KEM-768 division operations (CVSS 7.4).

**Fix**: Replace with fixed fork:
```toml
# Cargo.toml
pqc_kyber_edit = { version = "0.7", features = ["wasm", "kyber768", "zeroize"] }
```
```rust
// pqc.rs
use pqc_kyber_edit::*;
```

---

## Critical Security

### Path Traversal Prevention in Template Loading

**Location**: `src/static_files/directory.rs:30-74`

**Fix**: Ensure template paths can't escape allowed directories:

```rust
pub fn load_directory_template(template_path: &str) -> Result<String, StaticError> {
    let path = Path::new(template_path);

    // 1. Reject absolute paths
    if path.is_absolute() {
        return Err(StaticError::Internal(format!(
            "Absolute template paths are not allowed: {}",
            template_path
        )));
    }

    // 2. Reject path traversal attempts
    let path_str = template_path.replace('\\', "/");
    if path_str.contains("..") {
        return Err(StaticError::Internal(format!(
            "Template path traversal attempt detected: {}",
            template_path
        )));
    }

    // 3. Canonicalize and verify within allowed directories
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(Path::new("/etc/synvoid/").as_path())
        && !canonical.starts_with(Path::new("/var/lib/synvoid/").as_path())
        && !canonical.starts_with(Path::new("/var/www/").as_path())
    {
        return Err(StaticError::Internal(
            "Template path must be within allowed directories".into(),
        ));
    }

    fs::read_to_string(&canonical).map_err(|e| ...)
}
```

### XSS Prevention in Directory Listing

**Location**: `src/static_files/directory.rs`, `src/theme/dir_listing.rs`

**Fix**: Always escape user-controlled data in HTML:

```rust
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// Use in directory entry rendering
let escaped_name = escape_html(&entry.name);
format!(r#"<td><a href="{}">{} {}</a></td>"#, entry.href, icon, escaped_name)
```

### RSA 1024 Auto-Upgrade in DNSSEC

**Location**: `src/dns/dnssec_key_mgmt.rs:232-254`

**Fix**: Auto-upgrade RSA 1024 to 2048:

```rust
let bits = if _rsa_key_size == 0 {
    2048_usize
} else {
    let requested_bits = _rsa_key_size as usize;
    if requested_bits == 1024 {
        tracing::warn!("RSA 1024 is insecure, auto-upgrading to 2048");
        2048
    } else {
        requested_bits
    }
};
if !matches!(bits, 2048 | 4096) {
    return Err(format!("Unsupported RSA key size {}. Use 2048 or 4096.", bits));
}
```

---

### ML-KEM/ML-DSA Key Pair Derivation from Loaded Secrets

**Location**: `crates/synvoid-mesh/src/mesh/config_identity.rs:49-84`, `pqc/src/keys.rs`, `pqc/src/dsa.rs`

**Issue**: When loading ML-KEM-768 or ML-DSA private keys from base64 configuration, the code was discarding the loaded key and generating a new random keypair instead.

**Pattern**: Derive public key FROM the loaded secret key:

```rust
// ML-KEM-768: Extract public key from secret key
let sk = MlKem768::secret_key_from_base64(b64)
    .map_err(|e| format!("Invalid base64 ML-KEM key: {}", e))?;
let pk = sk.public_key().map_err(|e| format!("Failed to derive public key: {}", e))?;
self.ml_kem_public_key_base64 = Some(pk.to_base64());

// ML-DSA-44: Extract verifying key from signing key
let sk = pqc::SigningKey::from_base64(b64)
    .map_err(|e| format!("Invalid base64 ML-DSA key: {}", e))?;
let vk = sk.verifying_key();
self.ml_dsa_public_key_base64 = Some(vk.to_base64());
```

**Implementation**:
- `pqc/src/keys.rs`: Added `public_key()` method to `SecretKey` using aws-lc-rs
- `pqc/src/dsa.rs`: Added `verifying_key()` method to `SigningKey`

---

### Threat Intel DHT Sync Signature Requirement

**Location**: `crates/synvoid-mesh/src/mesh/threat_intel.rs:1233-1242`

**Issue**: `sync_from_dht()` accepted records without signatures, allowing unsigned threats to be accepted.

**Pattern**: Skip records without valid signatures:

```rust
if !signature.is_empty() && !signer_pk.is_empty() {
    // verify signature...
} else {
    tracing::warn!(
        "Threat intel DHT sync: missing signature or signer pk for {}",
        key
    );
    continue;  // Skip unsigned records
}
```

---

### Threat Intel Publish Signature Requirement

**Location**: `crates/synvoid-mesh/src/mesh/threat_intel.rs:650-654`

**Issue**: When a node had no signer configured, `publish_indicator_to_dht()` would publish with empty signature.

**Pattern**: Refuse to publish if no signer:

```rust
if self.signer.is_none() {
    tracing::warn!("Cannot publish threat indicator: no signer configured");
    return;
}
```

---

### Edge Node PoW Revocation Check Order

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs:120-150`

**Issue**: Edge nodes could bypass PoW requirement by not providing credentials.

**Pattern**: PoW is REQUIRED for edge nodes - all-or-nothing validation:
- Edge nodes must provide BOTH `pow_nonce` AND `pow_public_key`
- If either is missing, authentication fails with error "Edge node X did not provide PoW nonce and public key - PoW is required"

```rust
fn validate_edge_node(...) -> Result<(), String> {
    // ALWAYS check revocation first, regardless of auth method
    if let Some(revocation_list) = revoked_nodes {
        if let Some(revocation_info) = revocation_list.is_node_revoked(peer_node_id) {
            return Err(format!(
                "Edge node {} has been revoked: {} (at {})",
                peer_node_id, revocation_info.reason, revoked_info.revoked_at
            ));
        }
    }

    // PoW is REQUIRED - all-or-nothing
    let (nonce, pow_key) = match (pow_nonce, pow_public_key) {
        (Some(nonce), Some(pk)) => (nonce, pk),
        (None, None) => {
            return Err(format!(
                "Edge node {} did not provide PoW nonce and public key - PoW is required",
                peer_node_id
            ))
        }
        // Handle partial submissions with specific errors
        (None, Some(_)) => return Err(format!("... provided PoW public key but not nonce")),
        (Some(_), None) => return Err(format!("... provided PoW nonce but not public key")),
    };
    validate_edge_node_pow(peer_node_id, peer_public_key, Some(nonce), Some(pow_key))?;
    // ...
}
```

---

### DnsRecord Privilege Classification

**Location**: `crates/synvoid-mesh/src/mesh/dht/keys.rs:496`

**Issue**: `DnsZone` was privileged but `DnsRecord` was not, allowing edge nodes to store individual DNS records without proper authorization.

**Pattern**: Add DnsRecord to privileged key types:

```rust
pub fn is_privileged(&self) -> bool {
    matches!(
        self,
        DhtKey::Organization(_)
            | DhtKey::TierKey(_, _)
            | DhtKey::MemberCertificate(_, _)
            | DhtKey::GlobalNodeList
            | DhtKey::OrgNameReservation(_)
            | DhtKey::DnsZone(_)
            | DhtKey::DnsRecord(_, _)  // Added
            | DhtKey::DnsDomainRegistration(_)
            | DhtKey::AnycastNode(_)
    )
}
```

---

## Critical Security

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

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs`

**Issue**: Non-global nodes bypassed authentication entirely - malicious edge nodes could claim any role.

**Fix**: All node types now require Ed25519 signature verification:

| Node Type | Requirement | Challenge Format |
|----------|-------------|------------------|
| Global | Ed25519 signature + authorized key | `"{node_id}:{timestamp}"` |
| Edge | Ed25519 self-signature | `"edge:{node_id}:{timestamp}"` |
| Origin | Ed25519 self-signature + Global attestation | `"origin:{node_id}:{timestamp}"` |

**Key functions**:
- `validate_peer_role()` - main entry point, dispatches by role; for Edge nodes with member certificate and org key, routes through Raft attestation validation when `raft_attestation` is `Some`
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

**Location**: `src/process/ipc.rs`, `src/supervisor/ipc_client.rs`, `src/process/ipc_signed.rs`

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

**Location**: `crates/synvoid-mesh/src/mesh/config_identity.rs`, `src/tls/acme.rs`

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

**Location**: `crates/synvoid-mesh/src/mesh/threat_intel.rs`

**Issue**: Multiple threat types for same IP overwrote each other (key was just IP).

**Fix**: Use composite keys `"{threat_type}:{ip}"`:

| Key Pattern | Purpose |
|-------------|---------|
| `IpBlock:{ip}` | IP blocking indicator |
| `{threat_type}:{ip}` | Specific threat type |
| `RateLimitViolation:{ip}` | Rate limit exceeders |
| `SuspiciousActivity:{ip}` | Suspicious behavior |

---

## High Security

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

**Location**: `crates/synvoid-mesh/src/mesh/config.rs:GenesisKeyConfig`, `crates/synvoid-mesh/src/mesh/config_identity.rs`

**Pattern**: Authorized key list with backward compatibility:
```rust
pub struct GenesisKeyConfig {
    pub authorized_genesis_keys: Vec<String>,  // Empty = deny all (secure default)
    pub previous_genesis_key_base64: Option<String>,
    pub rotation_sequence: u32,
}

impl GenesisKeyConfig {
    pub fn is_genesis_key_authorized(&self, public_key: &str) -> bool {
        if self.authorized_genesis_keys.is_empty() {
            return false;  // Secure default - deny when no keys configured
        }
        self.authorized_genesis_keys.iter().any(|k| k == public_key)
    }
}
```

---

### Distributed Revocation (W2.3)

**Location**: `crates/synvoid-mesh/src/mesh/transport_global.rs`

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

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs`, `crates/synvoid-mesh/src/mesh/transport.rs`

**Pattern**: Dual authentication (Ed25519 OR PoW):
```rust
pub fn validate_peer_role(
    // ... existing params ...
    pow_nonce: Option<u64>,
    pow_public_key: Option<&str>,
    raft_attestation: Option<&SignedRaftAttestation>,
    allow_v1_raft_attestations: bool,
) -> Result<(), String> {
    if let (Some(nonce), Some(pubkey)) = (pow_nonce, pow_public_key) {
        // PoW path - validate using NodeId::verify_pow()
        validate_edge_node_pow(pubkey, nonce)
    } else {
        // Ed25519 signature path (original)
        // For Edge nodes with member cert + org key:
        //   raft_attestation Some -> validate_member_certificate_with_raft_attestation
        //     (accepts quorum sigs OR value-bound Raft attestation)
        //   raft_attestation None -> validate_member_certificate (quorum-only)
        //   raft_attestation Some but invalid -> error immediately
        validate_edge_node(node_id, peer_public_key, peer_signature, ...)
    }
}
```

---

### Capability Attestation (W2.8)

**Location**: `crates/synvoid-mesh/src/mesh/dht/capability_attestation.rs`, `crates/synvoid-mesh/src/mesh/transport.rs`

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

### Additional Security Fixes

### SSRF Allowlist Bypass Prevention (S2.6)

**Location**: `src/waf/attack_detection/ssrf.rs:267-294`

**Pattern**: Word boundary checks instead of substring matching:
```rust
fn has_word_boundary(input: &str, substring: &str) -> bool {
    if let Some(pos) = input.find(substring) {
        let before_ok = pos == 0 || input.as_bytes()[pos - 1] == b'.';
        let after_pos = pos + substring.len();
        let after_ok = after_pos >= input.len()
            || input.as_bytes()[after_pos] == b'.'
            || input.as_bytes()[after_pos] == b':';
        before_ok && after_ok
    } else {
        false
    }
}
```

**Why**: Prevents bypasses like `evillocalhost.com` (contains `.localhost`) or `evil.comalloweddomain.com` (contains `alloweddomain.com`).

---

### Open Redirect Bypass Prevention (S2.7)

**Location**: `src/waf/attack_detection/open_redirect.rs:114-133`

**Pattern**: Newline and homograph attack checks:
```rust
// Reject newlines in redirect targets
if input_lower.contains('\n') || input_lower.contains('\r') {
    return true;
}

// Reject non-ASCII schemes (homograph attacks)
if let Some(scheme_end) = input_lower.find(':') {
    let scheme = &input_lower[..scheme_end];
    if !scheme.bytes().all(|b| b.is_ascii_lowercase()) {
        return true;
    }
}
```

---

### Transfer-Encoding Parsing (S2.8)

**Location**: `src/waf/attack_detection/request_smuggling.rs:12-40`

**Pattern**: Proper comma-separated TE header parsing:
```rust
fn te_contains_chunked(te_str: &str) -> bool {
    te_str
        .split(',')
        .map(|v| v.trim().to_lowercase())
        .any(|v| v == "chunked")
}
```

**Why**: Prevents bypasses like `chunked,invalid` or `xchunked` that substring matching would miss.

---

### JWT Algorithm Validation (S2.9)

**Location**: `src/waf/attack_detection/jwt.rs:125-186`

**Pattern**: Proper JSON parsing with algorithm whitelist:
```rust
const SAFE_JWT_ALGORITHMS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
    "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA",
];

if let Ok(header_json) = serde_json::from_str::<Value>(&header_lower) {
    if let Some(alg) = header_json.get("alg").and_then(|v| v.as_str()) {
        let alg_safe = SAFE_JWT_ALGORITHMS
            .iter()
            .any(|&a| a.eq_ignore_ascii_case(alg));
        if !alg_safe {
            // detected
        }
    }
}
```

**Why**: Prevents algorithm confusion attacks where `none` or custom algorithms bypass verification.

---

### Unicode Normalization (S2.10)

**Location**: `src/proxy.rs:138-236`

**Pattern**: NFKC normalization for path sanitization:
```rust
use unicode_normalization::UnicodeNormalization;

// At function start
let path = path.nfkc().collect::<String>();

// At return points
return Cow::Owned(result.nfkc().collect());
```

**Why**: Prevents homograph attacks where Cyrillic `а` looks like ASCII `a`.

---

### Revocation Check for Edge/Origin (M1.3)

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs:116-132, 223-240`

**Pattern**: Revocation checks in all node validation paths:
```rust
fn validate_edge_node(..., revoked_nodes: Option<&GlobalNodeRevocationList>) -> Result<(), String> {
    if let Some(revocation_list) = revoked_nodes {
        if let Some(revocation_info) = revocation_list.is_node_revoked(peer_node_id) {
            return Err(format!("Edge node {} has been revoked: ...", peer_node_id));
        }
    }
    // ... rest of validation
}
```

---

### DHT Churn Handling (M2.1)

**Location**: `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs:483-557`

**Pattern**: Background ping loop for peer health:
```rust
async fn ping_peers_loop(&self, transport: Arc<dyn PingTransport>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let peers = self.get_peers_to_ping();
        for peer in peers {
            transport.send_ping(&peer.node_id, request_id.clone(), local_id.clone()).await;
        }
    }
}
```

---

### Bucket Refresh (M2.2)

**Location**: `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs:455-492`

**Pattern**: Periodic refresh of sparse buckets:
```rust
fn refresh_sparse_buckets(&self) {
    let sparse = self.routing_table.get_sparse_bucket_indices(k);
    for bucket_idx in sparse {
        let target = NodeId::generate_random_in_bucket(bucket_idx, &self.local_node_id);
        self.iterative_find_node(&target);
    }
}
```

---

### Revocation Bypass Edge/Origin | `crates/synvoid-mesh/src/mesh/peer_auth.rs:116-132,223-240` | Revocation checks added to edge/origin validation |
| `src/auth/mod.rs` | Constant-time CSRF comparison |
| `src/admin/state.rs` | Constant-time session ID comparison |
| `src/dns/crypto_rng.rs` | Result-based RNG with error propagation |
| `crates/synvoid-mesh/src/mesh/peer_auth.rs` | Role-based Ed25519 + PoW authentication |
| `src/process/ipc.rs` | IPC signing with HMAC |
| `src/process/ipc_signed.rs` | Signed message deserialization |
| `src/supervisor/ipc_client.rs` | Signed overseer IPC |
| `crates/synvoid-mesh/src/mesh/config_identity.rs` | 0o600 key permissions, multi-genesis keys |
| `crates/synvoid-mesh/src/mesh/threat_intel.rs` | Composite DHT keys |
| `crates/synvoid-mesh/src/mesh/transport_global.rs` | Distributed revocation |
| `crates/synvoid-mesh/src/mesh/dht/capability_attestation.rs` | Capability attestation |
| `src/challenge/mod.rs` | Reduced PoW timeout (12s) |
| `src/config/admin.rs` | bcrypt cost minimum 12 |

---

## Code Quality

### SAFETY_REASON Comments for Intentional Dead Code

**Location**: Throughout codebase, primarily `crates/synvoid-mesh/src/mesh/`, `src/supervisor/`, `src/waf/`

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
rg "validate_peer_role" crates/synvoid-mesh/src/mesh/

# Check file permissions
rg "set_permissions.*0o600" crates/synvoid-mesh/src/mesh/config_identity.rs src/tls/acme.rs

# Check bcrypt cost validation
rg "bcrypt_cost < 12" src/config/

# Check PoW authentication
rg "validate_edge_node_pow" crates/synvoid-mesh/src/mesh/

# Check capability attestation
rg "CapabilityAttestation" crates/synvoid-mesh/src/mesh/

# Audit dead_code suppressions
rg "#\[allow\(dead_code)\]" src/ --glob '*.rs' -c

# Check SAFETY comments on unsafe blocks
rg "unsafe \{" src/ --glob '*.rs' -l | xargs -I{} rg "SAFETY" {}
```

---

## Critical Security Fixes

### Session Fixation Prevention

**Location**: `src/auth/mod.rs:479-493`

**Issue**: When a user logs in, existing sessions for that user were NOT invalidated. An attacker with a valid session could continue using it after legitimate user login.

**Pattern**: Invalidate all existing sessions before creating new session:

```rust
// Before creating new session, remove all existing sessions for this user
store.sessions.retain(|_, s| s.user_id != user_id);
store.sessions.insert(session.id.clone(), session.clone());
```

---

### IPC Nonce Cache Poisoning Prevention

**Location**: `src/process/ipc_signed.rs:230-262`

**Issue**: Nonce was inserted into cache BEFORE HMAC verification. An attacker could flood nonce cache with fake nonces before HMAC rejection.

**Pattern**: Verify HMAC BEFORE inserting nonce:

```rust
// 1. Extract timestamp and nonce
// 2. Verify HMAC FIRST
if !self.signer.verify(&hmac_data, &hmac) {
    return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HMAC verification failed",
    ));
}
// 3. Only after HMAC passes, check and insert nonce
if !check_and_insert_nonce(&nonce, timestamp) {
    return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "replay detected: duplicate nonce",
    ));
}
```

---

### DNS Dynamic Update TSIG Enforcement

**Location**: `src/dns/update.rs:288-395`

**Issue**: `handle_update` never enforced TSIG authentication despite `require_tsig` field existing.

**Pattern**: Parse TSIG from additional section and verify before processing update:

```rust
// Compute additional section offset
let additional_offset = self.compute_additional_section_offset(query, 12, qdcount, ancount, nscount)?;
let tsig = parse_tsig_from_query(query, additional_offset);

if self.require_tsig {
    if tsig.is_none() {
        return Err("Dynamic updates require TSIG authentication".to_string());
    }
    // Verify TSIG using TsigVerifier
}
```

---

### DNS Cookie Timing Attack Prevention

**Location**: `src/dns/cookie.rs:82-88`

**Issue**: Cookie MAC comparison used XOR loop instead of constant-time comparison.

**Pattern**: Use `subtle::ConstantTimeEq`:

```rust
use subtle::ConstantTimeEq;

// BEFORE (timing attack vulnerable)
let mut diff = 0u8;
for (a, b) in expected_server.iter().zip(server_cookie.iter()) {
    diff |= a ^ b;
}
diff == 0

// AFTER (constant-time)
expected_server.ct_eq(server_cookie).into()
```

---

### Origin Attestation with Empty Authorized List

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs:281-300`

**Issue**: When `authorized_global_pubkeys` is empty, origin attestation was bypassed entirely.

**Pattern**: Reject attestation when no authorized keys configured:

```rust
// If no authorized keys, reject all attestation attempts
if authorized_global_pubkeys.is_empty() {
    return Err("No authorized global node keys configured for origin attestation".to_string());
}

// Then check if key is in authorized list
if !authorized_global_pubkeys.iter().any(|k| k == attestation_key) {
    return Err("Origin node attestation key not in authorized list".to_string());
}
```

---

### DHT Snapshot Request Rate Limiting

**Location**: `crates/synvoid-mesh/src/mesh/transport_dht.rs:6-77`

**Issue**: `DhtSnapshotRequest` had no rate limiting or authentication - DoS vector.

**Pattern**: 
1. Track request times per peer with automatic expiration
2. Verify signature before responding
3. Limit response size

```rust
// Rate limit check
let now = Instant::now();
let window = Duration::from_secs(SNAPSHOT_REQUEST_RATE_LIMIT_WINDOW_SECS);
{
    let mut times = self.snapshot_request_times.write();
    let peer_times = times.entry(from_peer.to_string()).or_insert_with(Vec::new);
    peer_times.retain(|&t| now.duration_since(t) < window);
    if peer_times.len() >= MAX_SNAPSHOT_REQUESTS_PER_WINDOW {
        return; // Rate limited
    }
    peer_times.push(now);
}

// Signature verification
if !signature.is_empty() && !signer_public_key.is_empty() {
    // Verify Ed25519 signature...
}

// Size limit on response
.take(MAX_SNAPSHOT_RECORDS)
```

---

### Slashing Quorum Scalability

**Location**: `crates/synvoid-mesh/src/mesh/dht/stake.rs:425-447`

**Issue**: Slashing required exactly 3 global node votes - impossible with 1-2 global nodes.

**Pattern**: Percentage-based quorum calculation:

```rust
fn get_global_node_count(&self) -> usize {
    let stakes = self.stakes.read();
    stakes.values().filter(|s| s.role.is_global()).count()
}

fn process_global_slash_vote(&self, vote: GlobalSlashVote) {
    // ... add vote ...
    
    let global_count = self.get_global_node_count();
    let quorum = (global_count * 2 / 3).max(1);  // >50% of global nodes
    
    if entry.len() >= quorum {
        self.slash_node(&target_id, reason, "global_committee");
    }
}
```

Quorum table:
| Global Nodes | Quorum |
|-------------|--------|
| 1 | 1 |
| 2 | 1 |
| 3 | 2 |
| 4 | 2 |
| 5 | 3 |

---

## Security Fixes

### TLS Passthrough WAF Enforcement

**Location**: `src/worker/unified_server.rs:214-226`, `src/config/site/proxy.rs`

**Issue**: When `tls_passthrough = true`, L7 WAF inspection was completely bypassed.

**Pattern**: Add opt-in WAF enforcement for passthrough traffic:
```rust
// In site proxy config
pub struct SiteProxyConfig {
    pub tls_passthrough: bool,
    pub tls_passthrough_enforce_waf: bool,  // NEW
}

// In unified server, check enforcement flag
if site.proxy.tls_passthrough && site.proxy.tls_passthrough_enforce_waf {
    // Run WAF checks on passthrough traffic
    waf.check_request_full(...);
}
```

**Metrics**: `TLS_PASSTHROUGH_REQUESTS`, `TLS_PASSTHROUGH_WAF_BYPASSED`

---

### Connection Limiter Slot Hash Collisions

**Location**: `src/waf/flood/connection_limiter.rs:8,119-121`

**Issue**: `CONNECTION_TRACKER_SLOTS = 65536` with simple modulo hash - high collision risk.

**Pattern**: Increased slot count to reduce collision probability:
```rust
// BEFORE
const CONNECTION_TRACKER_SLOTS: usize = 65536;

// AFTER
const CONNECTION_TRACKER_SLOTS: usize = 262144;
```

---

### Revocation List Passed in Discovery

**Location**: `crates/synvoid-mesh/src/mesh/discovery.rs:439`

**Issue**: Global node, Edge, and Origin revocation was bypassed - revocation list always `None`.

**Pattern**: Store and pass revocation list to validation:
```rust
pub struct MeshDiscovery {
    // ... existing fields
    revocation_list: Option<Arc<GlobalNodeRevocationList>>,
}

impl MeshDiscovery {
    pub fn new(/* ... */, revocation_list: Option<Arc<GlobalNodeRevocationList>>) -> Self {
        Self { revocation_list, .. }
    }
}

// Pass to validate_peer_role
validate_peer_role(
    // ...
    self.revocation_list.as_ref().map(|r| r.as_ref()),
    // ...
    raft_attestation,           // Option<&SignedRaftAttestation>
    allow_v1_raft_attestations, // bool
)
```

---

### SSRF Subdomain Spoofing Detection

**Location**: `src/waf/attack_detection/ssrf.rs:267-294`

**Issue**: Only checked exact `.localhost` and `.local` - bypassable via subdomain.

**Pattern**: Check for localhost lookalikes:
```rust
fn matches_localhost_lookalike(input: &str) -> bool {
    let lookalike_patterns = [
        "localhost", "localshost", "locahost", "locaihost",
        "loca1host", "iocalhost", "1ocalhost", "oocalhost",
    ];
    
    for pattern in &lookalike_patterns {
        if let Some(pos) = input.find(pattern) {
            // Check word boundaries
            let before_ok = pos == 0 || !input.as_bytes()[pos - 1].is_ascii_alphanumeric();
            let after_ok = /* ... */;
            if before_ok && after_ok {
                return true;
            }
        }
    }
    // Also check 127.0.0.1 with proper boundaries
    false
}
```

---

### Genesis Key Default Deny

**Location**: `crates/synvoid-mesh/src/mesh/config_identity.rs:238-245`

**Current behavior**: Empty `authorized_genesis_keys` denies all remote immutable records (secure default). Implemented 2026-05-26.

**Pattern**: Deny by default with warning:
```rust
pub fn is_genesis_key_authorized(&self, genesis_public_key: &str) -> bool {
    if self.authorized_genesis_keys.is_empty() {
        tracing::warn!(
            "No authorized genesis keys configured - rejecting genesis key authentication. \
            This is a security risk if the system expects authorized keys."
        );
        return false;  // Changed from true
    }
    self.authorized_genesis_keys.iter().any(|k| k == genesis_public_key)
}
```

---

### Rate Limiting Race Condition Fix

**Location**: `src/admin/auth.rs:35-52`

**Issue**: Check-before-add pattern allowed bursts exceeding limit.

**Pattern**: Atomic check-after-add:
```rust
// BEFORE (race condition)
if counter.get() >= limit { return Err(); }
counter.fetch_add(1, Ordering::Relaxed);

// AFTER (atomic)
let current = counter.fetch_add(1, Ordering::Relaxed);
if current >= limit {
    counter.fetch_sub(1, Ordering::Relaxed);  // rollback
    return Err();
}
```

---

### Revocation List Propagation in Discovery

**Location**: `crates/synvoid-mesh/src/mesh/discovery.rs:439`

**Issue**: `handle_hello` passed `None` for revocation list.

**Fix**: Now stores `revocation_list` in struct and passes it to `validate_peer_role()`.

---

## Security

### VerifiedUpstream Signature Verification

**Location**: `crates/synvoid-mesh/src/mesh/topology.rs:732-805`

**Issue**: `find_verified_upstreams_for_site()` accepted records without verifying `global_node_signature`.

**Pattern**: Verify Ed25519 signature before accepting VerifiedUpstream record:
```rust
// Construct signing data
let sign_data = format!(
    "{}:{}:{}:{}",
    verified.upstream_id,
    verified.origin_node_id,
    verified.upstream_url,
    verified.registered_at
);

// Look up global node's public key
if let Some(pubkey) = lookup_global_node_key(&verified.global_node_id) {
    // Verify signature
    if !verify_ed25519(&sign_data, &verified.global_node_signature, &pubkey) {
        continue; // Skip invalid record
    }
}
```

---

### RFC 5011 Missing→Pending Transition

**Location**: `src/dns/trust_anchor.rs:481-500`

**Issue**: Key in `Missing` state could transition to `Seen` without verifying it was previously Valid.

**Pattern**: Per RFC 5011 Section 3.3, only keys that were previously Valid (trust_point != 0) can auto-restore to Pending via `observe_dnskey_at_root()`. Keys that were never Valid (trust_point == 0) must go through digest verification via `trust_anchor_check()`:

```rust
TrustAnchorState::Missing => {
    if anchor.trust_point == 0 {
        // Never valid - require digest verification
        return Rfc5011Event::KeyIgnored {
            key_tag,
            reason: "missing key was never valid, requires digest verification".to_string(),
        };
    }
    // Was previously valid - can transition to Pending
    anchor.state = TrustAnchorState::Pending;
    anchor.pending_since = Some(now);
    Rfc5011Event::KeyPending { key_tag }
}
```

**Verification flow**:
1. Key becomes Missing when not seen for `trust_anchor_retention_days`
2. `observe_dnskey_at_root()` called when key reappears in DNSKEY RRset
3. If `trust_point == 0` → stay Missing, require `trust_anchor_check()` with DS digest
4. If `trust_point != 0` → transition to Pending, then to Valid after observation period

---

### CSPRNG for Signing Key Generation

**Location**: `crates/synvoid-mesh/src/mesh/config_identity.rs:343-345`

**Issue**: Used `rand::rng().fill_bytes()` (SmallRng) instead of OS CSPRNG.

**Pattern**: Use `OsRng` for cryptographic key generation:
```rust
use rand::TryRngCore;
let mut rng = rand::rngs::OsRng;
rng.try_fill_bytes(&mut key).expect("RNG failure");
```

---

### Dynamic Update RDATA Validation

**Location**: `src/dns/update.rs:455-517`

**Issue**: `check_prerequisite()` only verified existence, not RDATA content when present.

**Pattern**: Validate RDATA when present in prerequisite per RFC 2136:
```rust
if !prereq.rdata.is_empty() {
    let record_values: Vec<String> = records.iter().map(|r| r.value.clone()).collect();
    let has_matching_rdata = record_values.iter().any(|v| {
        let encoded = Self::encode_rdata_normalized(v);
        encoded == prereq.rdata
    });
    Ok(has_matching_rdata)
}
```

---

### RouteResponse Signature Verification

**Location**: `crates/synvoid-mesh/src/mesh/discovery.rs:585-608`

**Issue**: RouteResponse signature was logged but never verified.

**Pattern**: Verify Ed25519 signature using provider's public key:
```rust
let sign_data = format!(
    "{}:{}:{}:{}:{}",
    upstream_id, provider_node_id, hops, ttl_secs, timestamp
);

if let Some(pubkey) = cert_manager.get_global_node_key(&provider_node_id) {
    if !verify_ed25519(&sign_data, &signature, &pubkey) {
        tracing::warn!("Route response signature verification failed");
        return;
    }
}
```

---

### DHT Record Content Hash Chain

**Location**: `crates/synvoid-mesh/src/mesh/protocol.rs:1319-1340`

**Issue**: DHT records used timestamp-based conflict resolution without cryptographic integrity.

**Pattern**: Add `content_hash` field computed from record value:
```rust
pub struct DhtRecord {
    // ... existing fields ...
    pub content_hash: Vec<u8>,
}

impl DhtRecord {
    pub fn compute_content_hash(&self) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(&self.value).to_vec()
    }

    pub fn verify_content_hash(&self) -> bool {
        self.content_hash == self.compute_content_hash()
    }
}
```

---

## Wave 16 Security Fixes (2026-05-01)

### Trusted Proxy XFF Handling

**Location**: `src/waf/request_sanitization.rs`

**Issue**: `get_real_ip()` returned `ips[0]` (first IP) but standard XFF order is `client, proxy1, proxy2`. The client is the first untrusted public IP before the trusted proxy suffix, not the first IP overall.

**Fix**: Replaced `validate_forwarded_chain()` with `find_client_ip_in_xff()` that scans XFF right-to-left:
- First trusted proxy marks the trusted suffix boundary
- Client is the first untrusted public IP immediately before the trusted suffix
- Private/spoofed middle IPs handled correctly

### Cache Purge Token Comparison

**Location**: `src/proxy/mod.rs`

**Issue**: Cache purge token comparison used normal string equality (`==`) instead of constant-time comparison.

**Fix**: Changed to use `subtle::ConstantTimeEq`:
```rust
use subtle::ConstantTimeEq;
// Before: token == required_token.as_str()
// After: required_token.as_bytes().ct_eq(token.as_bytes()).into()
```

### Attack Detection Action Semantics

**Location**: `src/waf/mod.rs`

**Issue**: `AttackDetectionConfig.action` was validated but ignored at runtime. All attacks returned `WafDecision::Stall`.

**Fix**: `check_attack_patterns()` now reads action from config:
- `stall` (default): returns `WafDecision::Stall`
- `block`: returns `WafDecision::Block(403, "Forbidden")`
- `log`: records metrics but returns `None` (request passes)

### Serverless WAF Bypass Removed

**Location**: `src/http/server.rs`, `src/config/serverless.rs`

**Issue**: `serverless_only` flag bypassed `waf.check_request_full()` unconditionally.

**Fix**: Removed unconditional skip. Added `ServerlessWafMode` enum (`enforce|log|off`) with default `enforce`. Only explicit `waf_mode = "off"` skips WAF.

### Body Inspection UTF-8 Hardening

**Location**: `src/waf/attack_detection/sqli.rs`, `xss.rs`, `normalizer.rs`

**Issue**: `unwrap_or("")` on invalid UTF-8 body input allowed payloads to evade inspection.

**Fix**: Changed to `String::from_utf8_lossy(body)` to decode invalid UTF-8 with replacement characters instead of empty string.

### Retry Policy Honesty

**Location**: `src/proxy/mod.rs`, `src/proxy/retry.rs`

**Issue**: `RetryConfig.enabled` was never checked - retries happened even when disabled. `retry_non_idempotent` was ignored. Off-by-one in attempt counting.

**Fix**: Added to `forward_with_pool()`:
```rust
let retry_enabled = retry_config.map(|c| c.enabled).unwrap_or(false);
let should_retry_method = retry_config
    .map(|c| should_retry_request_impl(&method, c))
    .unwrap_or(true);

// Method safety check: GET/HEAD/OPTIONS/TRACE are idempotent
pub fn should_retry_request(method: &Method, config: &RetryConfig) -> bool {
    is_idempotent_method(method) || config.retry_non_idempotent
}
```

### Request Header Forwarding

**Location**: `src/proxy/headers.rs`

**Issue**: Default forwarding only preserved 4 headers (X-Real-IP, XFF, XFP, Host). Application headers like Authorization, Content-Type, Cookie were dropped.

**Fix**: Changed default to forward all end-to-end headers:
- Strip hop-by-hop headers (Connection, Keep-Alive, TE, etc.)
- Sanitize spoofable forwarded headers from client (X-Forwarded-For, X-Real-IP, Forwarded, X-Forwarded-Proto)
- Respect `clear`/`hide` config for explicit removals
- Apply `set` overrides for header values

**Implementation**: In `build_forward_headers()`, the following headers are skipped during the forward loop and replaced with sanitized values:
- `x-forwarded-for` → replaced with validated XFF + real client IP
- `x-real-ip` → replaced with real client IP
- `forwarded` → stripped entirely
- `x-forwarded-proto` → stripped (listener protocol inserted separately)

### Security Regression Tests (Wave P1)

**Location**: `tests/security_regression.rs`

Added tests validating header sanitization security:

1. **`test_forwarded_headers_spoofed_by_client_rejected`**:
   - Spoofed X-Forwarded-For, X-Real-IP, Forwarded headers are stripped
   - Replaced with sanitized real client IP
   - X-Forwarded-Proto set based on listener protocol, not client-supplied value

2. **`test_hop_by_hop_headers_stripped_from_forwarding`**:
   - Connection, Keep-Alive, Transfer-Encoding, Proxy-Authorization stripped
   - End-to-end headers (Content-Type, Host, User-Agent, etc.) preserved

3. **`test_build_forward_headers_preserves_non_spoofed_headers`**:
   - Host, User-Agent, Accept, and custom headers preserved
   - Only spoofable headers are replaced

4. **`test_forwarded_protocol_header_based_on_listener`**:
   - HTTP listener sets x-forwarded-proto to "http"
   - HTTPS listener sets x-forwarded-proto to "https"
   - Ensures protocol cannot be spoofed by client

These tests ensure proxy security defaults are enforced and prevent regression.
```
