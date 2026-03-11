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

### Medium Severity

| Vulnerability | Crate | ID | Status | Notes |
|---------------|-------|-----|--------|-------|
| Marvin Attack | `rsa` | RUSTSEC-2023-0071 | **Low exposure** | Transitive via yara-x, not actively used |

### Unmaintained Dependencies (Warnings)

| Crate | Alternative | Status | Notes |
|-------|-------------|--------|-------|
| `bincode` | Abstraction layer | **Abstraction added** | IPC via serialization wrapper |
| `paste` | None | Acceptable | Transitive via utoipa |
| `proc-macro-error` | None | Acceptable | Transitive via yew |
| ~~`rustls-pemfile`~~ | ~~`rustls-pki-types`~~ | **Completed** | TLS certificate parsing |

---

## Dependency Patches

### quinn-proto (RUSTSEC-2026-0037)
- **Issue**: DoS via malformed QUIC transport parameters (CVE-2026-31812)
- **Severity**: High (CVSS 8.7)
- **Fix**: Patched in `quinn-proto 0.11.14`
- **Patch**: Applied via `[patch.crates-io]` in Cargo.toml
- **TODO**: Remove patch when quinn 0.11.10+ is released on crates.io
- **Tracking**: https://github.com/quinn-rs/quinn/releases

### rustls-pemfile → rustls-pki-types
- **Issue**: Unmaintained (RUSTSEC-2025-0134)
- **Fix**: Migrated to `rustls-pki-types` for PEM parsing
- **Files changed**: 
  - `src/tls/cert_resolver.rs`
  - `src/mesh/cert.rs`
  - `src/tunnel/quic/tls.rs`

### bincode → Serialization Abstraction Layer
- **Issue**: Unmaintained (RUSTSEC-2025-0141)
- **Fix**: Created abstraction layer (`src/serialization.rs`) to wrap serialization
- **Rationale**: Allows future migration to alternative serializers without API changes
- **Files changed**:
  - Added `src/serialization.rs` (wrapper module)
  - Updated `src/process/ipc_framing.rs`
  - Updated `src/process/ipc_signed.rs`
  - Updated `src/tunnel/quic/ipc.rs`
  - Updated `src/tunnel/quic/messages.rs`
  - Updated `src/tunnel/quic/codec.rs`

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
