# Security Policy

## Supported Versions

We release security patches for the latest released version. We recommend users to always use the latest release.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within SynVoid, please send an email to the maintainers. All security vulnerabilities will be promptly addressed.

Please include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Features

SynVoid includes several security features:

### Attack Detection
- SQL Injection (via libinjection)
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Remote/Local File Inclusion (RFI/LFI)
- Server-Side Request Forgery (SSRF)
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE)
- LDAP/XPath Injection
- Open Redirect
- HTTP Request Smuggling

### Rate Limiting
- Per-IP rate limiting with configurable windows
- Global rate limiting
- Connection limiting

### Bot Protection
- Known search bot allowlisting
- AI crawler blocking (configurable)
- Scraper detection (configurable)
- Proof-of-Work challenges
- CSS honeypot challenges

### Process Security
- HMAC-signed IPC messages
- Socket FD passing for zero-downtime upgrades
- Graceful connection draining

## Configuration Recommendations

For production deployments:

1. **Use strong admin tokens**: Generate tokens using `--generatetoken` or set `admin.token_env_var`
2. **Enable HTTPS**: Configure TLS in your site configuration
3. **Restrict trusted proxies**: Don't trust `0.0.0.0` in production
4. **Configure rate limits**: Adjust based on your traffic patterns
5. **Enable logging**: Monitor for attack patterns
6. **Keep updated**: Use the latest version for security patches
7. **Enable IPC signing**: Set `security.ipc_enforce_signing = true` and configure `security.ipc_session_key_env`
8. **Configure CORS carefully**: Avoid wildcard origins in production

## IPC Security

SynVoid supports HMAC-signed IPC communication between the master process and workers. This prevents unauthorized workers from connecting to the master.

### Configuration

```toml
[security]
# Require signed IPC messages (recommended for production)
ipc_enforce_signing = true

# Environment variable containing 64-character hex session key
# Generate with: xxd -l 32 -p /dev/urandom
ipc_session_key_env = "SYNVOID_IPC_KEY"
```

### Setup

1. Generate a secure key: `xxd -l 32 -p /dev/urandom`
2. Set the environment variable: `export SYNVOID_IPC_KEY="<your-key>"`
3. Enable enforcement: Set `ipc_enforce_signing = true`

Without IPC signing enabled, any process on the same machine can connect to the master IPC socket.

---

## Known Dependency Vulnerabilities

The following vulnerabilities exist in transitive dependencies and are documented for awareness. Fixes are monitored via [RustSec Advisory Database](https://rustsec.org/).

### High Severity

| Vulnerability | Crate | ID | Status | Notes |
|---------------|-------|-----|--------|-------|
| KyberSlash | `pqc_kyber` | RUSTSEC-2023-0079 | No fix | Used by wasm-pow for PoW challenges |
| ~~Denial of Service~~ | ~~`quinn-proto`~~ | ~~RUSTSEC-2026-0037~~ | **Patched** | Fixed via git patch to 0.11.14 |
| Winch compiler backend sandbox escape | `wasmtime` | RUSTSEC-2026-0095 | **Patched** | Updated to 42.0.2 |
| Cranelift aarch64 sandbox escape | `wasmtime` 40.0.4 | RUSTSEC-2026-0096 | **Yanked** | Transitive via yara-x |

### Medium Severity

| Vulnerability | Crate | ID | Status | Notes |
|---------------|-------|-----|--------|-------|
| Marvin Attack | `rsa` | RUSTSEC-2023-0071 | **Low exposure** | Transitive via yara-x, not actively used |

### Unmaintained Dependencies (Warnings)

| Crate | Alternative | Status | Notes |
|-------|-------------|--------|-------|
| ~~`bincode`~~ | ~~`postcard`~~ | **Removed** | Dead dependency — postcard shim handles serialization |
| `paste` | None | Acceptable | Transitive via utoipa |
| `proc-macro-error` | None | Acceptable | Transitive via yew |
| `atomic-polyfill` | None | Acceptable | Transitive via postcard/heapless |
| ~~`rustls-pemfile`~~ | ~~`rustls-pki-types`~~ | **Removed** | Migrated to rustls-pki-types PEM iterator |
| `once_cell` | `std::sync::LazyLock` | **Removed** | Replaced with std library equivalent |
| `unicode-segmentation` 1.13.1 | 1.13.2 | **Yanked** | Transitive dep; 1.13.1 yanked, 1.13.2 available |
| `gimli` 0.33.1 | None | **Yanked** | Transitive via wasmtime; build warning only |

### Cryptographic Dependencies

| Crate | Version | Language | Purpose |
|-------|---------|----------|---------|
| `aws-lc-rs` | 1.16.2 | C (compiled) | TLS 1.3, ML-KEM, ML-DSA |
| `ring` | 0.17.14 | Rust | DNS/QUIC (transitive via hickory/quinn) |
| `libcrux-ml-dsa` | 0.0.8 | Pure Rust | ML-DSA signatures |
| `pqc_kyber` | 0.7.1 | Pure Rust | ML-KEM key exchange |
| `ed25519-dalek` | 2.1.0 | Pure Rust | Ed25519 signatures |
| `x25519-dalek` | 2.0.0 | Pure Rust | X25519 key exchange |
| `sha2`, `sha3` | 0.10 | Pure Rust | Hashing |
| `hmac` | 0.12 | Pure Rust | HMAC |
| `aes-gcm` | 0.10 | Pure Rust | AES-GCM |
| `zeroize` | 1.8 | Pure Rust | Secret destruction |
| `subtle` | 2.12 | Pure Rust | Constant-time ops |

### Post-Quantum Crates

| Crate | Algorithm | Location | Vulnerability |
|-------|-----------|----------|----------------|
| `pqc_kyber` | ML-KEM-768 | src/wasm_pow | RUSTSEC-2023-0079 (no fix) |
| `libcrux-ml-dsa` | ML-DSA-65/87 | pqc/workspace | ✅ Secure |
| `aws-lc-rs` | ML-KEM + ML-DSA | Cargo.toml | ✅ Secure |

### NASM Not Used

- **Status**: Confirmed - NASM assembler is NOT used
- pqc_kyber uses pure Rust implementation (no `nasm` feature)
- No C/asm additions at build time

---

## YARA Rule Provenance & Trust (Phase 4)

Active YARA rules carry provenance metadata tracking their source, verification state, and identity.

### Rule Source Types

| Source | Trust Level | Description |
|--------|------------|-------------|
| `Bundled` | Low | Default malware rules shipped with the binary |
| `Directory` | Operator-controlled | Rules loaded from a local filesystem directory |
| `DirectoryWithFallback` | Operator-controlled | Directory rules with bundled fallback on failure |
| `Inline` | High | Rules provided directly via config or admin API |
| `Mesh` | Network-trusted | Rules received from mesh peers, Ed25519-verified |
| `CompiledBundle` | Operator-controlled | Pre-compiled YARA-X binary rules |

### Directory Loading Hardening

Directory-based rule loading enforces:
- **Sorted file order**: Rules loaded alphabetically for deterministic compilation
- **Symlink rejection**: Symlinks are rejected by default (`yara_allow_rule_symlinks = false`)
- **File count limit**: Maximum rule files per directory (`yara_max_rule_files = 256`)
- **Aggregate size limit**: Maximum total source bytes (`yara_max_rule_source_bytes = 8MB`)
- **Canonical path enforcement**: Directory is canonicalized to prevent traversal

### Signed Bundle Format

YARA rule bundles can be signed with Ed25519 keys via `YaraRuleManifest`:
- Content SHA-256 hashes for source and compiled rules
- Ed25519 signature over `source_hash:compiled_hash`
- Base64-encoded signature in TOML manifest
- Verification via `manifest.verify()` and `manifest.verify_content()`

### Mesh Rule Trust

Mesh-delivered rules are verified against trusted signers (`require_signature = true` by default). Unsigned mesh updates are rejected in production mode. The mesh trust model uses Ed25519 signatures, not RSA.

### Operator Inspection

```rust
// Get active rule provenance
let provenance = scanner.get_rule_provenance();
// provenance.source_type, .version, .content_sha256, .verified, .loaded_at

// Get last reload error (None if last reload succeeded)
let error = scanner.get_last_reload_error();
```

### Dependency Policy

`deny.toml` enforces:
- Yanked crate denial (`yanked = "deny"`)
- Documented rationale and review dates for all ignored advisories
- Known-vulnerable wasmtime versions blocked
- RSA exposure assessed as low (transitive via yara-x, never invoked)

---

## Dependency Patches

### quinn-proto (RUSTSEC-2026-0037)
- **Issue**: DoS via malformed QUIC transport parameters (CVE-2026-31812)
- **Severity**: High (CVSS 8.7)
- **Fix**: Patched in `quinn-proto 0.11.14`
- **Patch**: Applied via `[patch.crates-io]` in Cargo.toml
- **TODO**: Remove patch when quinn 0.11.10+ is released on crates.io
- **Tracking**: https://github.com/quinn-rs/quinn/releases

### wasmtime (RUSTSEC-2026-0095)
- **Issue**: Winch compiler backend sandbox escape (CVE-2026-34987)
- **Severity**: High
- **Fix**: Updated to `wasmtime 42.0.2`
- **Status**: Patched in Cargo.toml

### rustls-pemfile Removal
- **Issue**: Unmaintained (RUSTSEC-2025-0134)
- **Fix**: Replaced with `rustls_pki_types::CertificateDer::pem_slice_iter()`
- **Status**: `rustls-pemfile` removed from Cargo.toml

### bincode → postcard Migration
- **Issue**: bincode unmaintained (RUSTSEC-2025-0141)
- **Fix**: Migrated to `postcard` for serialization
- **Benefits**: 
  - Actively maintained
  - 30% smaller serialized output
  - No dependency conflicts
- **Completed**: 2025-03-11

### rkyv for High-Performance Paths
- **Purpose**: Zero-copy serialization for DNS and DHT operations
- **Implementation**:
  - Added `rkyv` dependency (renamed to avoid lightningcss conflict)
  - Created `src/serialization_rkyv.rs` module re-exporting rkyv
  - Added rkyv derives to DNS message types (`crates/synvoid-dns/src/messages.rs`)
  - Added rkyv derives to DHT types (keys, signed, stake, network_policy, merkle, store, routing)
  - Added rkyv derives to `MeshNodeRole` in `src/mesh/config.rs`
- **Default Serialization**: rkyv is now the default for:
  - `SignedDhtRecord::serialize()` / `deserialize()` - DHT record storage
  - `PersistedRoutingTable::to_bytes()` / `from_bytes()` - routing table persistence
  - `RoutingTable::to_persisted_bytes()` / `from_persisted_bytes()` - routing table
  - `DhtRoutingManager::get_persisted_bytes()` / `init_with_persisted_bytes()` - manager API
- **Fallback Methods**: 
  - `serialize_json()` / `deserialize_json()` - for wire format compatibility
  - `to_bytes_postcard()` / `from_bytes_postcard()` - for postcard compatibility
- **Error Handling**: Methods return `Result` types with proper error propagation
- **Completed**: 2025-03-12

### yara-x/rsa Exposure Assessment (RUSTSEC-2023-0071)
- **Vulnerability**: Marvin Attack - potential key recovery through timing side-channels
- **Exposure**: LOW
- **Analysis**:
  - The `rsa` crate is a transitive dependency via yara-x
  - yara-x uses RSA only for optional YARA rule signature verification
  - SynVoid uses **ed25519-dalek** for YARA rule feed signature verification (not RSA)
  - The RSA functionality is loaded but never invoked in the current code path
- **Recommendation**: No action required unless you enable RSA-based YARA rule signing

### yara-x/wasmtime Transitive Vulnerability (RUSTSEC-2026-0096)
- **Issue**: yara-x pulls wasmtime 40.0.4 which has multiple vulnerabilities
- **Severity**: CRITICAL - wasmtime 40.0.4 is yanked
- **Your direct version**: wasmtime 42.0.2 (secure) - direct dependency is fine
- **Affected path**: yara-x → wasmtime 40.0.4 (transitive)
- **Mitigation**: Wait for yara-x to update to wasmtime 42+; your direct dependency is secure
- **Recommendation**: Monitor yara-x releases for update; current risk is acceptable

### Post-Quantum Architecture
- **Hybrid Key Exchange**: X25519 + pqc_kyber provides defense-in-depth
- **ML-DSA**: Uses libcrux-ml-dsa (pure Rust) in pqc workspace
- **TLS Post-Quantum**: Via aws-lc-rs feature in rustls
- **Reference**: See `skills/crypto_dependencies.md` for full documentation

---

### Monitoring

Run `cargo audit` regularly to check for new vulnerabilities:
```bash
cargo audit
```

To add automated checking, consider integrating [cargo-deny](https://cargo-deny.readthedocs.io/) in CI.
