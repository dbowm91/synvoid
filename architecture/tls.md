# TLS Module Architecture

**Module:** `src/tls/`
**Last Updated:** 2026-05-27

---

## 1. Purpose and Responsibility

The TLS module provides complete TLS/HTTPS server functionality for SynVoid, including:

- **TLS termination** for incoming HTTPS connections
- **Certificate management** with SNI-based dynamic resolution
- **ACME/Let's Encrypt integration** for automatic certificate issuance and renewal
- **Certificate rotation** via file watching and background renewal tasks
- **Post-quantum hybrid key exchange** support (TLS 1.3 hybrid KEM)
- **mTLS (mutual TLS)** client authentication
- **OCSP stapling** for reduced connection latency
- **Client fingerprinting** via JA4 hash computation

The module sits at the edge of the request pipeline, handling the TLS handshake before requests reach the WAF, routing, or upstream proxy layers.

---

## 2. Submodules Overview

```
src/tls/
├── mod.rs           # Public re-exports and module declarations
├── server.rs        # HttpsServer, connection handling, request pipeline
├── cert_resolver.rs # SNI-based certificate resolution, key loading, file watching
├── config.rs        # InternalTlsConfig, InternalAcmeConfig, InternalClientAuthConfig
├── acme.rs          # AcmeManager, Let's Encrypt integration, certificate issuance
├── acme_dns.rs      # AcmeDnsChallenge for DNS-01 ACME challenges
└── sni_peek.rs      # SNI extraction, JA4 fingerprinting from raw ClientHello
```

### 2.1 `server.rs` — HttpsServer

**Responsibility:** Manages the HTTPS server lifecycle, TLS acceptance, HTTP/1.1 and HTTP/2 multiplexing, flood protection, and request handling.

**Key Types:**
- `HttpsServer` — Main server struct wrapping a `TokioTcpListener`, `TlsAcceptor`, router, WAF, and all supporting components.
- `HttpsConnection` — Per-connection wrapper tracking the TLS stream, drop state, and JA4 hash.

**Entry Points:**
- `HttpsServer::new()` — Constructor with all dependencies.
- `HttpsServer::serve()` — Main loop: accepts TCP connections, performs flood checks, spawns async tasks for TLS handshakes, and routes HTTP/1.1 vs HTTP/2 based on ALPN negotiation.
- `HttpsServer::handle_request_with_cache()` — Full request pipeline including early WAF decisions, bandwidth tracking, body collection, site routing, and upstream proxy dispatch.

**Flood Protection:** L3/L4 flood protection (`FloodProtector`) is applied **before** the TLS handshake, fixing an earlier bug where checks were done post-handshake.

**ALPN Routing:**
- `h2` → HTTP/2 via `http2_server::Builder`
- HTTP/1.1 fallback via `http1_server::Builder`

---

### 2.2 `cert_resolver.rs` — CertResolver

**Responsibility:** Loads and caches TLS certificates and private keys, resolves certificates by SNI hostname (including wildcard matching), validates key strength, manages OCSP stapling, and triggers reloads on file changes.

**Key Types:**
- `CertResolver` — Implements `rustls::server::ResolvesServerCert`. Holds:
  - `certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>` — Domain → Certificate map (thread-safe)
  - `default_cert: Arc<RwLock<Option<Arc<CertifiedKey>>>>` — Fallback certificate (thread-safe)
  - `config: InternalTlsConfig` — TLS configuration (cert paths, PQC, OCSP, etc.)
  - `reload_tx: broadcast::Sender<()>` — Notifies listeners of certificate reloads

**Key Methods:**
- `load_certificates()` — Loads the primary cert/key PEM files, validates key strength (2048-bit minimum RSA), parses OCSP response if configured, and registers watch directory for auto-reload.
- `load_certs_from_dir()` — Scans a directory for `domain.pem` + `domain.key` pairs, enabling multi-domain certificates from a directory.
- `build_server_config()` — Constructs a `rustls::ServerConfig` with:
  - TLS 1.3 only, or TLS 1.2+1.3 fallback (with optional BEAST attack warning)
  - Post-quantum hybrid KEM if `prefer_post_quantum` is set
  - mTLS verifier if client auth is enabled
- `watch_for_cert_changes()` — Free function (not a method) that spawns a `notify`-based file watcher that debounces certificate directory changes, sleeps 500ms to coalesce multiple file events, and calls `load_certificates()`.

**SNI Resolution (`resolve()`):**
1. Exact match on hostname
2. Wildcard match (`*.example.com` matches `www.example.com`)

**Security Features:**
- RSA key strength validation (≥2048-bit, warns at <3072-bit)
- Certificate validity period enforcement (not before, not expired)
- OCSP stapling with max 256KB response size

---

### 2.3 `config.rs` — Internal Configuration Types

**Responsibility:** Internal configuration types that bridge the public config layer with the TLS module internals.

**Key Types:**

```rust
pub struct InternalTlsConfig {
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub watch_dir: Option<PathBuf>,
    pub prefer_post_quantum: bool,      // Default: true
    pub tls_1_3_only: bool,            // Default: true
    pub enable_tls_12_fallback: bool,  // Default: false
    pub ocsp_stapling_enabled: bool,   // Default: true
    pub ocsp_response_path: Option<PathBuf>,
    pub port: u16,                     // Default: 443
    pub acme: InternalAcmeConfig,
    pub client_auth: InternalClientAuthConfig,
}

pub struct InternalAcmeConfig {
    pub enabled: bool,
    pub email: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub staging: bool,
    pub domains: Vec<String>,
    pub challenge_type: InternalAcmeChallengeType, // Http01 or Dns01
    pub terms_of_service_agreed: bool,
}

pub enum InternalAcmeChallengeType {
    Http01,  // Default
    Dns01,
}

pub struct InternalClientAuthConfig {
    pub enabled: bool,
    pub ca_cert_path: Option<PathBuf>,
}
```

**Defaults:** `tls_1_3_only = true`, `prefer_post_quantum = true`, `ocsp_stapling_enabled = true`.

---

### 2.4 `acme.rs` — AcmeManager

**Responsibility:** Manages the full ACME/Let's Encrypt lifecycle: account creation, certificate orders, challenge fulfillment (HTTP-01 and DNS-01), certificate issuance, renewal monitoring, and disk persistence.

**Key Types:**
- `AcmeManager` — Wraps `instant_acme::Account`, manages `ManagedCert` entries, spawns a 24-hour renewal background task.
- `ChallengeGuard` — RAII guard that stores HTTP-01 challenge tokens and cleans them up on drop.
- `ManagedCert` — Tracks domain and expiry for renewal scheduling.

**Error Type:**
```rust
pub enum AcmeError {
    Disabled,
    Protocol(String),
    Config(String),
    Io(String),
}
```

**Key Methods:**
- `init()` — Loads existing account credentials from `cache_dir/account_credentials.json` (0o600 permissions) or creates a new account via Let's Encrypt Staging or Production.
- `request_certificate(domain)` — Full ACME flow:
  1. Creates order with domain identifier
  2. Authorizes via HTTP-01 or DNS-01 challenge (challenge token stored in `DashMap`)
  3. Polls order readiness (120s timeout)
  4. Finalizes (generates CSR via `rcgen`)
  5. Polls certificate issuance
  6. Writes `domain.pem` and `domain.key` to cache directory
  7. Calls `cert_resolver.load_certificates()` to reload
  8. Invokes `renew_callback` if set

- `handle_http_challenge(path)` — Looks up `/.well-known/acme-challenge/{token}` in the `DashMap`, returns key authorization string. Used by the HTTP server handler.

- `renew_expiring()` — Checks all managed certificates; renews those expiring within 30 days.

- `spawn_renewal_task()` — Background task that:
  - Runs every 24 hours
  - Calls `renew_expiring()`
  - Reloads all certificates from disk

- `set_renew_callback(F)` — Registers a callback invoked after successful renewal with the list of renewed domains.

---

### 2.5 `acme_dns.rs` — AcmeDnsChallenge

**Responsibility:** Manages DNS-01 ACME challenges by computing the SHA-256 hash of the key authorization (base64url encoded) and providing the value for `_acme-challenge.{domain}` TXT records.

**Key Methods:**
- `prepare_challenge(domain, key_authorization)` — Computes `base64_url(sha256(key_authorization))`, stores in `pending` map, returns the TXT value.
- `get_txt_value(domain)` — Retrieves the pending challenge value.
- `cleanup(domain)` — Removes the pending challenge after completion.
- `pending_challenges()` — Returns all pending (domain, txt_value) pairs for the DNS server to serve.

---

### 2.6 `sni_peek.rs` — SNI Extraction and JA4

**Responsibility:** Parses raw TLS ClientHello bytes to extract the SNI hostname without consuming the stream. Also computes JA4 client fingerprint hashes for analytics.

**Key Functions:**
- `extract_sni(data: &[u8])` — Parses the TLS record layer and ClientHello handshake to extract the SNI extension hostname.
- `compute_ja4(data: &[u8])` — Computes JA4 fingerprint from ClientHello bytes for client fingerprinting.

**Error Types:**
```rust
pub enum SniError {
    TooShort,
    NotHandshake(u8),
    Incomplete,
    NotClientHello(u8),
    InvalidHostname,
    ConnectionClosed,
    Io(String),
}
```

---

## 3. Major Data Structures

| Struct | Module | Purpose |
|--------|--------|---------|
| `HttpsServer` | server.rs | Main HTTPS server actor |
| `HttpsConnection` | server.rs | Per-connection state (stream, drop flag, JA4 hash) |
| `CertResolver` | cert_resolver.rs | Certificate storage + SNI resolution |
| `InternalTlsConfig` | config.rs | TLS server configuration |
| `InternalAcmeConfig` | config.rs | ACME client configuration |
| `InternalClientAuthConfig` | config.rs | mTLS CA configuration |
| `AcmeManager` | acme.rs | ACME account, orders, renewal |
| `ChallengeGuard` | acme.rs | RAII guard for HTTP-01 challenge cleanup |
| `ManagedCert` | acme.rs | Domain + expiry tracking |
| `AcmeDnsChallenge` | acme_dns.rs | DNS-01 challenge value storage |

---

## 4. Key APIs and Entry Points

### Server Lifecycle
```rust
// Construction
let server = HttpsServer::new(addr, config, cert_resolver, router, waf, http_config, main_config, shutdown_rx)
    .with_flood_protector(fp)
    .with_metrics(metrics)
    .with_drain_state(drain_state)
    .with_connection_limit(semaphore);

// Start serving
server.serve().await?;
```

### Certificate Loading
```rust
let resolver = CertResolver::new(internal_tls_config);
resolver.load_certificates()?;

// Monitor reloads
let watcher = watch_for_cert_changes(resolver.clone(), watch_dir);
```

### ACME Initialization
```rust
let acme = AcmeManager::new(acme_config, resolver.clone());
acme.init().await?;
acme.spawn_renewal_task();

let challenges = acme.http_challenges();
```

### Challenge Handling
```rust
// From HTTP server handler:
if let Some(key_auth) = acme.handle_http_challenge(path) {
    return Ok(Response::builder()
        .status(200)
        .body(Full::new(Bytes::from(key_auth)).boxed())?);
}
```

---

## 5. How TLS Termination Works

1. **TCP Accept:** `HttpsServer::serve()` loops on `TcpListener::accept()`, receiving a raw TCP stream.

2. **L3/L4 Flood Protection:** Before TLS handshake, `FloodProtector::check_tcp_connection()` is evaluated. Connections that are blackholed or rate-limited are dropped immediately with metrics recording.

3. **Strict Protocol Validation (optional):** If `http_config.strict_protocol_validation` is enabled, the server peeks 16 bytes from the socket. If the bytes match an HTTP method pattern (`GET `, `POST `, etc.) but the socket is on the TLS port, the connection is rejected with a counter increment. This prevents accidental HTTP traffic on HTTPS ports.

4. **TLS Handshake:** `TlsAcceptor::accept(stream)` is called asynchronously. The acceptor is built from `CertResolver::build_server_config()` which provides:
   - `rustls::ServerConfig` with `Arc<CertResolver>` as the cert resolver (SNI-based resolution)
   - Protocol versions (TLS 1.3 only, or TLS 1.2+1.3 fallback)
   - Post-quantum hybrid KEM if enabled
   - mTLS verifier if configured

5. **ALPN Negotiation:** After handshake, `tls_stream.get_ref().1.alpn_protocol()` is checked:
   - `b"h2"` → HTTP/2 connection
   - Other/none → HTTP/1.1 connection

6. **JA4 Fingerprint:** On connection creation, `extract_client_hello_bytes_from_stream()` extracts raw ClientHello bytes, and `compute_ja4()` produces a JA4 hash stored in `HttpsConnection`.

7. **Request Handling:** The appropriate Hyper server builder (`http2_server::Builder` or `http1_server::Builder`) is used with:
   - Max header list size from `http_config.max_headers`
   - Service function closure capturing all dependencies
   - `handle_request_with_cache()` as the handler

8. **Per-Connection State:** `HttpsConnection` wraps the stream with:
   - `Mutex<Option<TlsStream>>` — allows taking ownership of the stream (e.g., for forwarding in passthrough scenarios)
   - `RunningFlag` — allows the WAF to request connection drop during early screening
   - `Mutex<Option<String>>` — JA4 hash for logging/metrics

---

## 6. ACME/Let's Encrypt Integration

### Account Management
- **Cache location:** `/var/lib/synvoid/acme/account_credentials.json` (created with `0o600` permissions)
- **Staging vs Production:** Configurable via `acme.staging` boolean
- **Account restoration:** On startup, `AcmeManager::init()` attempts to load existing credentials before creating a new account

### Challenge Types

#### HTTP-01 Challenge
1. AcmeManager stores `(token, key_authorization)` in `Arc<DashMap<String, String>>`
2. HTTP server handler intercepts `/.well-known/acme-challenge/{token}` paths and returns the key authorization
3. `ChallengeGuard` cleans up entries on drop (including early returns)

#### DNS-01 Challenge
1. `AcmeDnsChallenge::prepare_challenge()` computes `base64_url(sha256(key_authorization))`
2. The value is stored in `pending: Arc<DashMap<String, String>>`
3. DNS server intercepts `_acme-challenge.{domain}` queries and returns the TXT value
4. `cleanup()` removes the entry after challenge completion

### Certificate Issuance Flow
```
request_certificate(domain)
  └── new_order(domain)
      ├── authorization() for each domain
      │   ├── HTTP-01: store key_auth in DashMap
      │   ├── DNS-01: call prepare_challenge() → store hash
      │   └── challenge_handle.set_ready()
      ├── order.poll_ready() (120s timeout)
      ├── order.finalize() → generates CSR, returns private key PEM
      └── order.poll_certificate() → returns full cert chain PEM
          ├── Write {domain}.pem for cert
          ├── Write {domain}.key for private key
          ├── Parse expiry → store in ManagedCert
          └── cert_resolver.load_certificates() to reload
```

### Renewal
- **Trigger:** `spawn_renewal_task()` runs every 24 hours
- **Threshold:** Certificates expiring within 30 days are renewed
- **Callbacks:** `set_renew_callback()` is invoked after successful renewal with renewed domain names

---

## 7. Certificate Rotation

### Method 1: ACME Automatic Renewal
- `AcmeManager` spawns a background task
- Every 24 hours, expires within 30 days → re-issues via Let's Encrypt
- New certificates written to disk and reloaded into `CertResolver`
- No downtime; certificates are served via SNI resolution without restart

### Method 2: File Watching (Hot Reload)
1. `CertResolver::load_certificates()` is called at startup with primary cert/key
2. If `watch_dir` is configured, `watch_for_cert_changes()` spawns a `notify` file watcher
3. On file change debounce (500ms), `load_certs_from_dir()` re-scans the directory
4. New `domain.pem` + `domain.key` pairs are loaded and inserted into the `certs` HashMap
5. SNI resolution picks up new certificates immediately on next connection

### Method 3: Manual Reload
- `cert_resolver.load_certificates()` can be called directly to reload from configured paths

### Key Strength Validation
- RSA keys < 2048 bits are rejected
- RSA keys < 3072 bits generate a warning
- EC keys (SEC1/PKCS8) are accepted without strength validation (inherently >= 160 bits)

### OCSP Stapling
- Optional via `ocsp_stapling_enabled` and `ocsp_response_path`
- Max OCSP response size: 256KB
- Failures to load OCSP result in a warning; OCSP stapling is disabled gracefully without breaking TLS

---

## 8. Security Considerations

| Feature | Implementation |
|---------|----------------|
| TLS 1.3 only (default) | `tls_1_3_only = true`; can be relaxed via `enable_tls_12_fallback` |
| Key strength validation | RSA < 2048 bits rejected; < 3072 bits warned |
| Certificate validity | Parses `not_before` and `not_after`, rejects expired/not-yet-valid certs |
| Post-quantum KEM | Hybrid key exchange via `prefer_post_quantum` (TLS 1.3 only) |
| mTLS | `WebPkiClientVerifier` built from CA certificates |
| ACME credentials | Saved with `0o600` permissions on Unix |
| File watcher | Debounced (500ms) to avoid repeated reloads |
| Input validation | OCSP response size limited to 256KB |

---

## 9. Dependencies

| Dependency | Purpose |
|------------|---------|
| `tokio-rustls` | Async TLS acceptor using rustls |
| `rustls` | TLS protocol implementation (ServerConfig, CertifiedKey) |
| `aws-lc-rs` | Cryptographic provider (default_provider) |
| `instant_acme` | ACME protocol client (Let's Encrypt) |
| `notify` | File system watching for certificate hot reload |
| `x509_parser` | X.509 certificate parsing (expiry, validity) |
| `rsa` | RSA key strength validation |
| `dashmap` | Concurrent map for HTTP-01 challenge tokens |
| `base64` | Base64 encoding for DNS-01 challenge values |
| `sha2` | SHA-256 for DNS-01 challenge value computation |

---

## 10. Feature Flags

| Feature | Module | Effect |
|---------|--------|--------|
| `dns` | acme_dns.rs | Enables DNS-01 challenge support (`AcmeDnsChallenge`) |
| `mesh` | server.rs | Enables mesh transport and IPC fields in `HttpsServer` |
| `post-quantum` | server.rs | Logs post-quantum crypto status at startup |
