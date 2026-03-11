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
| Marvin Attack | `rsa` | RUSTSEC-2023-0071 | No fix | Used by yara-x for rule scanning |

### Unmaintained Dependencies (Warnings)

| Crate | Alternative | Status | Notes |
|-------|-------------|--------|-------|
| `bincode` | `oxicode`, `postcard` | Pending migration | IPC serialization |
| `paste` | None | Pending removal | Macro crate - used by utoipa |
| `proc-macro-error` | `proc-macro2` | Pending migration | Used by yew |
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

---

### Monitoring

Run `cargo audit` regularly to check for new vulnerabilities:
```bash
cargo audit
```

To add automated checking, consider integrating [cargo-deny](https://cargo-deny.readthedocs.io/) in CI.
