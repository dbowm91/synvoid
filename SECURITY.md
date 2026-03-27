# Security Policy

## Supported Versions

We release security patches for the latest released version. We recommend users to always use the latest release.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within MaluWAF, please send an email to the maintainers. All security vulnerabilities will be promptly addressed.

Please include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Features

MaluWAF includes several security features:

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

MaluWaf supports HMAC-signed IPC communication between the master process and workers. This prevents unauthorized workers from connecting to the master.

### Configuration

```toml
[security]
# Require signed IPC messages (recommended for production)
ipc_enforce_signing = true

# Environment variable containing 64-character hex session key
# Generate with: xxd -l 32 -p /dev/urandom
ipc_session_key_env = "MALU_IPC_KEY"
```

### Setup

1. Generate a secure key: `xxd -l 32 -p /dev/urandom`
2. Set the environment variable: `export MALU_IPC_KEY="<your-key>"`
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
| ~~Shared linear mem unsoundness~~ | ~~`wasmtime`~~ | ~~RUSTSEC-2025-0118~~ | **Patched** | 36.0.6 >= 36.0.3 fix threshold |

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

---

## Dependency Patches

### quinn-proto (RUSTSEC-2026-0037)
- **Issue**: DoS via malformed QUIC transport parameters (CVE-2026-31812)
- **Severity**: High (CVSS 8.7)
- **Fix**: Patched in `quinn-proto 0.11.14`
- **Patch**: Applied via `[patch.crates-io]` in Cargo.toml
- **TODO**: Remove patch when quinn 0.11.10+ is released on crates.io
- **Tracking**: https://github.com/quinn-rs/quinn/releases

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
  - Added rkyv derives to DNS message types (`src/dns/messages.rs`)
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
  - MaluWAF uses **ed25519-dalek** for YARA rule feed signature verification (not RSA)
  - The RSA functionality is loaded but never invoked in the current code path
- **Recommendation**: No action required unless you enable RSA-based YARA rule signing

---

### Monitoring

Run `cargo audit` regularly to check for new vulnerabilities:
```bash
cargo audit
```

To add automated checking, consider integrating [cargo-deny](https://cargo-deny.readthedocs.io/) in CI.
