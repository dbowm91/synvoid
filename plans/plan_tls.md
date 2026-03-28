# Plan: TLS Passthrough, ACME Support, and Cert Distribution

## Problem Statement

The TLS subsystem has three gaps:

1. **No built-in ACME client** — `src/tls/acme.rs` is a stub that returns `AcmeError::UseExternalClient`. Config fields exist (`AcmeConfig` with `enabled`, `email`, `domains`, `staging`, `cache_dir`) but no actual ACME protocol implementation.

2. **No TLS passthrough mode** — In mesh mode, the edge always terminates TLS and re-encrypts to the origin. There is no option for the edge to forward raw TLS bytes to the origin, allowing end-to-end encryption between client and origin. The `tls_passthrough` field in `src/tunnel/quic/messages.rs` and `src/config/tunnel.rs` is dead code — logged and ignored.

3. **No cert distribution from origin to edge** — When an origin obtains a certificate via ACME, there is no mechanism to distribute it to edge nodes serving the same upstream. The `SiteConfigSync` message only syncs between origin nodes, not origin→edge.

## Design Decisions

- **ACME challenges:** Support both HTTP-01 (default) and DNS-01 (when `dns` feature enabled). HTTP-01 intercepts `/.well-known/acme-challenge/{token}` before the router. DNS-01 creates `_acme-challenge.{domain}` TXT records via the DNS server.
- **TLS passthrough WAF scope:** Layer 3/4 only — IP-based rate limiting and connection limits. No HTTP-level inspection, caching, or bot detection.
- **Cert transport security:** Private keys are encrypted with AES-256-GCM using a per-site key derived via HKDF from the mesh session key before transmission. Defense-in-depth even if mTLS is compromised.
- **New dependency:** `instant-acme = "0.7"` for RFC 8555 ACME protocol. All other crypto primitives already exist in the codebase (`aes-gcm`, `hkdf`, `sha2`, `ed25519-dalek`).

---

## Part 1: Built-in ACME Client

### Goal
Replace the stub in `src/tls/acme.rs` with a real ACME protocol implementation that obtains and renews certificates from Let's Encrypt or any RFC 8555 CA.

### Existing Files to Rewrite

#### `src/tls/acme.rs` (rewrite existing stub, ~400 lines)

Replace `AcmeClient` with `AcmeManager`:

```rust
pub struct AcmeManager {
    config: InternalAcmeConfig,
    cert_resolver: Arc<CertResolver>,
    account: Arc<RwLock<Option<AcmeAccount>>>,
    http_challenges: Arc<DashMap<String, String>>,  // token -> key_authorization
}
```

Key methods:
- `init()` — Load or create ACME account from `cache_dir`. Uses `instant-acme` to register with the CA (Let's Encrypt production or staging based on `config.staging`).
- `request_certificate(domain, challenge_type)` — Full ACME order flow:
  1. Create order for domain(s)
  2. Get pending challenges
  3. For HTTP-01: store `(token, key_authorization)` in `http_challenges` DashMap, tell ACME server to validate
  4. For DNS-01: create `_acme-challenge.{domain}` TXT record, tell ACME server to validate
  5. Poll for challenge completion
  6. Finalize order, download cert chain
  7. Write cert+key to `cert_path`/`key_path` → file watcher hot-reloads
- `handle_http_challenge(path: &str) -> Option<String>` — Returns key authorization for `/.well-known/acme-challenge/{token}` paths. Called from HTTP server before router.
- `renew_expiring()` — Check all managed certs via `x509-parser` (existing dependency). If any expire within 30 days, re-run ACME order.
- `spawn_renewal_task()` — Spawn tokio task that calls `renew_expiring()` every 24 hours. Replaces current stub that only reloads from disk.

#### `src/tls/acme_dns.rs` (new, ~150 lines, feature-gated `dns`)

DNS-01 challenge integration:
- `create_challenge_record(domain, key_authorization)` — Creates `_acme-challenge.{domain}` TXT record via DNS server API
- `remove_challenge_record(domain)` — Removes the TXT record after validation
- Uses existing DNS server infrastructure

#### `src/tls/sni_peek.rs` (new, ~100 lines)

Lightweight ClientHello SNI parser (used by Part 3):
- `extract_sni(data: &[u8]) -> Option<String>` — Parse TLS ClientHello record to extract SNI extension
- Pure byte parsing, no TLS library dependency
- Handles TLS 1.2 and 1.3 ClientHello format

### Files to Modify

- **`Cargo.toml`** — Add `instant-acme = "0.7"` dependency
- **`src/tls/mod.rs`** — Declare `acme_dns` and `sni_peek` modules
- **`src/config/tls.rs`** — Add `challenge_type: AcmeChallengeType` field to `AcmeConfig` (enum: `Http01`, `Dns01`)
- **`src/http/server.rs`** — Add HTTP-01 challenge interception: before router dispatch, check if path starts with `/.well-known/acme-challenge/` and call `acme_manager.handle_http_challenge()`

### ACME HTTP-01 Challenge Flow

```
Client -> GET /.well-known/acme-challenge/{token}
  -> HTTP server intercepts (before router)
  -> AcmeManager::handle_http_challenge(token)
  -> Returns key_authorization from DashMap
  -> 200 OK with key_authorization body

Simultaneously:
  AcmeManager::request_certificate()
    -> Creates order, gets challenge token
    -> Stores (token -> key_authorization) in DashMap
    -> Tells ACME server to validate
    -> ACME server connects to http://{domain}/.well-known/acme-challenge/{token}
    -> Gets key_authorization back
    -> Challenge validated, cert issued
    -> Writes cert to cert_path, key to key_path
    -> CertResolver hot-reloads via file watcher
```

### ACME DNS-01 Challenge Flow

```
AcmeManager::request_certificate(dns-01)
  -> Creates order, gets challenge token
  -> Computes DNS-01 key_authorization hash
  -> Creates _acme-challenge.{domain} TXT record via DNS server
  -> Tells ACME server to validate
  -> ACME server queries _acme-challenge.{domain} TXT
  -> Gets hash back
  -> Challenge validated, cert issued
  -> Removes TXT record
  -> Writes cert to cert_path, key to key_path
```

### Config Example

```toml
[tls]
enabled = true
port = 443

[tls.acme]
enabled = true
email = "admin@example.com"
domains = ["example.com", "*.example.com"]
staging = false
cache_dir = "/var/lib/maluwaf/acme"
challenge_type = "http-01"   # or "dns-01"
```

---

## Part 2: TLS Cert Distribution (Origin → Edge)

### Goal
Origin nodes that obtain certificates via ACME distribute them to edge nodes over the mesh transport, enabling edges to terminate TLS on behalf of the origin.

### New Files

#### `src/mesh/cert_dist.rs` (new, ~250 lines)

Cert distribution logic:

```rust
pub struct CertDistributor {
    mesh_transport: Arc<MeshTransport>,
    cert_resolver: Arc<CertResolver>,
    topology: Arc<MeshTopology>,
}
```

Key functions:
- `encrypt_cert_key(private_key_pem, site_id, mesh_session_key) -> (ciphertext, nonce)` — AES-256-GCM encryption with HKDF-derived per-site key
- `decrypt_cert_key(ciphertext, nonce, site_id, mesh_session_key) -> String` — Decryption
- `distribute_cert_to_peers(site_id, cert_chain_pem, private_key_pem)` — Origin calls this after ACME obtains/renews a cert. Encrypts key, broadcasts `SiteTlsCertSync` to all mesh peers. Edges that serve this upstream pick it up.
- `handle_cert_sync(message)` — Edge receives, verifies signature, decrypts key, loads into CertResolver
- `request_cert_from_origin(site_id)` — Edge calls on startup to request current cert from origin (pull-based)

**Edge discovery note:** The topology only tracks `find_all_origins_for_site` (`src/mesh/topology.rs:1003`), not edges serving a site. There is no reverse mapping. Cert distribution uses two mechanisms:
1. **Pull-based (edge startup):** Edge sends `SiteTlsCertRequest` to its upstream origins
2. **Push-based (cert renewal):** Origin broadcasts `SiteTlsCertSync` to all mesh peers via `broadcast_to_random_peers` (`src/mesh/transport.rs:1647`). Edges filter for site IDs they serve.

Key derivation:
```
site_salt = SHA-256(site_id + mesh_network_id)
site_cert_key = HKDF-SHA256(mesh_session_key, site_salt, "maluwaf-tls-cert-dist", 32)
```

Uses existing crates: `hkdf = "0.12"`, `aes-gcm = "0.10"`, `sha2 = "0.10"`.

### New Mesh Messages in `src/mesh/protocol.rs`

```rust
// Origin -> Edge: push certificate
SiteTlsCertSync {
    site_id: String,
    cert_version: u64,
    cert_chain_pem: String,
    encrypted_key: Vec<u8>,          // AES-256-GCM encrypted private key
    encryption_nonce: Vec<u8>,
    domains: Vec<String>,
    not_after: u64,                  // cert expiry timestamp
    source_node_id: String,
    signature: Vec<u8>,              // Ed25519 signature
    signer_public_key: Option<String>,
}

// Edge -> Origin: request current cert (on startup)
SiteTlsCertRequest {
    site_id: String,
    edge_node_id: String,
    request_id: String,
}

// Origin -> Edge: respond with cert
SiteTlsCertResponse {
    site_id: String,
    cert_version: u64,
    cert_chain_pem: String,
    encrypted_key: Vec<u8>,
    encryption_nonce: Vec<u8>,
    domains: Vec<String>,
    not_after: u64,
    source_node_id: String,
    signature: Vec<u8>,
    signer_public_key: Option<String>,
}
```

### Files to Modify

- **`src/mesh/protocol.rs`** — Add `SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse` to `MeshMessage` enum (~30 lines)
- **`src/mesh/transport.rs`** — Add `broadcast_cert_to_peers()` method that broadcasts cert sync messages to all mesh peers via `broadcast_to_random_peers` (~80 lines)
- **`src/mesh/transport_peer.rs`** — Add handlers: `handle_site_tls_cert_sync()`, `handle_site_tls_cert_request()`, `handle_site_tls_cert_response()` (~120 lines)
- **`src/tls/cert_resolver.rs`** — Add `load_cert_from_pem(key_pem: &str, cert_chain_pem: &str)` for in-memory cert loading without touching files (~40 lines). Stores in `HashMap<String, Arc<CertifiedKey>>` under a `RwLock`.
- **`src/mesh/mod.rs`** — Declare `cert_dist` module

### Cert Distribution Flow

```
Origin ACME renewal completes
  -> Origin calls CertDistributor::distribute_cert_to_peers()
  -> Derives site_cert_key via HKDF
  -> Encrypts private key with AES-256-GCM
  -> Broadcasts SiteTlsCertSync to all mesh peers (broadcast_to_random_peers)
  -> Includes Ed25519 signature
  -> Edges that serve this upstream pick up the message

Edge receives SiteTlsCertSync
  -> Checks if it serves this site_id
  -> Verifies sender is a valid origin for this site
  -> Verifies Ed25519 signature
  -> Derives site_cert_key via HKDF (same derivation)
  -> Decrypts private key
  -> Calls CertResolver::load_cert_from_pem()
  -> Edge immediately serves new cert (parking_lot::RwLock, no restart)

Edge startup (no cert cached):
  -> Edge sends SiteTlsCertRequest to origin
  -> Origin responds with SiteTlsCertResponse
  -> Edge processes same as above
```

### Security Properties

- **mTLS channel:** Only authenticated mesh nodes can send/receive messages
- **Ed25519 signature:** Origin signs the cert bundle; edge verifies sender is a legitimate origin
- **Encrypted private key:** Even if a mesh node is compromised and can intercept messages, the private key is encrypted with a per-site key derived from the mesh session
- **Key derivation uses HKDF:** Site-specific salt prevents key reuse across sites

---

## Part 3: TLS Passthrough Mode

### Goal
Site-level config option to forward raw TLS bytes from client to origin without decryption. The edge peeks at the ClientHello for SNI-based routing, then proxies raw bytes. WAF applies layer 3/4 protections only (IP rate limiting, connection limits).

### Files to Modify

- **`src/config/site.rs`** — Add `tls_passthrough: Option<bool>` to `SiteProxyConfig` (~5 lines)
- **`src/tls/server.rs`** — Add passthrough mode: when site has `tls_passthrough: true`, extract SNI from ClientHello without completing handshake, then do bidirectional raw TCP proxy to origin (~150 lines)
- **`src/tls/sni_peek.rs`** — Created in Part 1, used here for SNI extraction

### How It Works

**Normal mode (current):**
```
Client --TLS--> [Edge terminates TLS, inspects HTTP, applies WAF] --HTTP/HTTPS--> Origin
```

**Passthrough mode:**
```
Client --TLS--> [Edge peeks SNI, applies rate limit] --raw TCP--> Origin --TLS--> Client
                       |                                   |
                 Layer 3/4 only                    Origin terminates TLS
                 (rate limit, conn limit)          Edge never sees plaintext
```

### SNI Extraction Without TLS Termination

The edge reads the first TLS record from the client:
1. TLS record header (5 bytes): `content_type` (0x16 = Handshake), `version`, `length`
2. Handshake message: `msg_type` (0x01 = ClientHello), length, 32-byte random, session ID, cipher suites, compression, extensions
3. Find SNI extension (type `0x0000`): extract hostname
4. Route to site based on SNI hostname
5. **Buffer the read bytes** — prepend them to the stream when forwarding to origin

The original `ClientHello` bytes must be preserved and forwarded to the origin, since the edge is not completing the handshake.

### Layer 3/4 Protections

Applied at TCP accept time, **before** the TLS handshake (unlike normal mode where flood protection runs after handshake at `src/tls/server.rs:176`).

```rust
// In TLS server accept loop, BEFORE any TLS handshake:
let client_ip = peer_addr.ip();

// Connection limits (flood_protector.check_tcp_connection)
// Returns FloodDecision enum: Allowed, RateLimited, Blackholed
match flood_protector.check_tcp_connection(client_ip) {
    FloodDecision::Blackholed | FloodDecision::RateLimited => {
        drop(stream);
        continue;
    }
    FloodDecision::Allowed => {}
}

// If passthrough site: peek ClientHello for SNI, then proxy raw TCP
if site_config.tls_passthrough {
    let sni = extract_sni(&peeked_bytes);
    proxy_raw_tcp(stream, origin_addr).await;
    return;
}

// Otherwise: proceed with normal TLS handshake
acceptor.accept(stream).await ...
```

Note: `flood_protector.check_tcp_connection()` returns `FloodDecision` (enum: `Allowed`, `RateLimited`, `Blackholed`), defined at `src/waf/flood/mod.rs:19`. It is called with `match`, not as a boolean. The existing TLS server applies this check AFTER the TLS handshake (line 176); passthrough mode must apply it BEFORE.

`RateLimiterManager::check_rate_limit()` is `async` and cannot be called directly in the synchronous TCP accept loop. For passthrough mode, use only the synchronous `flood_protector` API. If async rate limiting is needed, restructure the accept loop to be async-aware.

### Passthrough Interaction with Cert Distribution

When a site uses TLS passthrough:
- The origin terminates TLS directly — it does not need to distribute certs to the edge
- The edge only needs to know the upstream address (IP:port) to forward raw TCP
- ACME at the origin obtains certs for the origin's own TLS termination
- The WAF layer is bypassed (layer 7 inspection not possible without decryption)

When a site uses normal mode with distributed certs:
- The origin obtains certs via ACME
- The origin distributes certs to edges
- The edge terminates TLS and applies full WAF inspection
- The edge connects to origin over the mesh transport (already encrypted via QUIC/mTLS)

---

## Implementation Order

```
Phase 1 (parallel):
├── Part 1: ACME client (src/tls/acme.rs rewrite)
└── Part 3: TLS passthrough (src/tls/server.rs + src/tls/sni_peek.rs)

Phase 2 (after Part 1):
└── Part 2: Cert distribution (src/mesh/cert_dist.rs + protocol messages)
```

Parts 1 and 3 are independent. Part 2 depends on Part 1 (needs real certs to distribute).

---

## New Dependencies

| Crate | Version | Purpose | Used In |
|-------|---------|---------|---------|
| `instant-acme` | `"0.7"` | ACME protocol (RFC 8555) | Part 1 |

All other required crates are already in the codebase:
- `aes-gcm = "0.10"` — AES-256-GCM for key encryption (Part 2)
- `hkdf = "0.12"` — HKDF key derivation (Part 2)
- `sha2 = "0.10"` — SHA-256 for HKDF salt (Part 2)
- `x509-parser = "0.16"` — Certificate expiry checking (Part 1)
- `ed25519-dalek = "2"` — Ed25519 signing for cert bundles (Part 2)
- `dashmap = "5"` — Concurrent map for HTTP-01 challenges (Part 1)
- `rcgen = "0.13"` — Self-signed cert fallback (existing)

---

## New Files Summary

| File | Lines | Part | Purpose |
|------|-------|------|---------|
| `src/tls/acme_dns.rs` | ~150 | 1 | DNS-01 challenge integration (feature-gated `dns`) |
| `src/tls/sni_peek.rs` | ~100 | 1+3 | ClientHello SNI extraction |
| `src/mesh/cert_dist.rs` | ~250 | 2 | Cert encryption and distribution |

## Modified Files Summary

| File | Part | Changes |
|------|------|---------|
| `Cargo.toml` | 1 | Add `instant-acme` |
| `src/tls/mod.rs` | 1 | Declare `acme_dns`, `sni_peek` modules |
| `src/tls/acme.rs` | 1 | Rewrite stub → real ACME client (~400 lines) |
| `src/tls/cert_resolver.rs` | 2 | Add `load_cert_from_pem()` for in-memory loading |
| `src/tls/server.rs` | 3 | Passthrough mode with SNI peek + raw TCP proxy |
| `src/http/server.rs` | 1 | HTTP-01 challenge route interception |
| `src/config/tls.rs` | 1 | `challenge_type` field in `AcmeConfig` |
| `src/config/site.rs` | 3 | `tls_passthrough` field in `SiteProxyConfig` |
| `src/mesh/protocol.rs` | 2 | `SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse` messages |
| `src/mesh/transport.rs` | 2 | `broadcast_cert_to_peers()` via `broadcast_to_random_peers` |
| `src/mesh/transport_peer.rs` | 2 | Cert sync/request/response handlers |
| `src/mesh/mod.rs` | 2 | Declare `cert_dist` module |

---

## Testing Strategy

### Part 1 (ACME)
- Unit test: `AcmeManager` with Let's Encrypt staging CA
- Integration test: HTTP-01 challenge flow with local HTTP server
- Unit test: DNS-01 TXT record creation/cleanup (feature-gated)
- Test: Certificate renewal triggers before expiry
- Test: CertResolver hot-reloads after ACME writes new cert

### Part 2 (Cert Distribution)
- Unit test: `encrypt_cert_key` / `decrypt_cert_key` round-trip
- Unit test: `SiteTlsCertSync` serialization/deserialization
- Integration test: Origin pushes cert to mock edge, edge loads into CertResolver
- Test: Edge startup cert request flow
- Test: Invalid signature rejection

### Part 3 (TLS Passthrough)
- Unit test: `extract_sni()` with valid/invalid ClientHello data
- Integration test: Client connects to edge, edge peeks SNI, forwards raw TCP to origin
- Test: Rate limiting applied before passthrough
- Test: Connection limits enforced on passthrough connections
- Test: Non-passthrough sites still use normal TLS termination

### Verification Commands
```bash
cargo test                          # All tests
cargo test --test integration_test  # Fast integration tests
cargo clippy -- -D warnings         # Lint
cargo fmt --check                   # Format
```

---

## Known Risks and Mitigations

1. **ACME rate limits** — Let's Encrypt has strict rate limits (50 certs/domain/week). Mitigation: Use staging for development, cache certs aggressively, only re-request when genuinely needed.

2. **Private key exposure in memory** — Decrypted private keys exist in memory on edge nodes. Mitigation: Use `zeroize` (already a dependency) on key material after loading into CertResolver.

3. **Passthrough and WAF bypass** — TLS passthrough completely bypasses layer 7 inspection. Mitigation: Clear documentation, site config explicitly opts in, metrics track passthrough vs normal mode.

4. **SNI extraction failures** — Malformed ClientHello or non-TLS traffic on TLS port. Mitigation: Fallback to default site handling or connection drop with appropriate error logging.

5. **Cert distribution race conditions** — Edge receives cert update while handling connections with old cert. Mitigation: CertResolver uses `RwLock` and atomic swap — new connections get new cert, existing connections continue with old cert until they close.
