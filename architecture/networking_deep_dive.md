# Networking & Protocols

SynVoid's networking layer is built for extreme performance and flexibility, supporting modern protocols and high-concurrency workloads.

## Protocol Support

### 1. HTTP/1.1 & HTTP/2
SynVoid uses **Hyper** as its foundational HTTP library.
- **HTTP/1.1:** Robust implementation with connection pooling and keep-alive support.
- **HTTP/2:** Infrastructure exists — `ErasedHttpClient::send_request(&self, request, authority, is_http2, timeout)` (`crates/synvoid-http-client/src/erased_pool.rs:365`) carries an `is_http2` flag, and `synvoid-proxy` threads `is_http2` through `ProxyServer::with_http2()` (`crates/synvoid-proxy/src/server.rs:283`). However, HTTP/2 pooled connections are not fully available in current implementation. **Milestone:** HTTP/2 upstream connection pooling is a planned enhancement. There is no `Http2PooledConnection` type anywhere in `crates/` or `src/`; the pooling work is unimplemented rather than stubbed. This is a known limitation (HTTP2-POOL deferred item).
- **Protocol Detection:** At TLS handshake, protocol negotiation occurs via ALPN (`src/tls/server.rs:420-421`). The server extracts the ALPN protocol and determines if the connection should use HTTP/2 (`h2`) or HTTP/1.1. This detection happens during the TLS handshake callback before request processing begins.

### 2. HTTP/3 (QUIC)
SynVoid features native HTTP/3 support via the **Quinn** library.
- **Connection Migration:** QUIC's use of connection IDs allows clients (like mobile devices) to switch networks without dropping connections. When a client changes network interfaces (e.g., Wi-Fi to cellular), the connection persists using the same connection ID, enabling seamless migration.
- **0-RTT:** Enables clients to send data in the first packet of a handshake, significantly reducing time-to-first-byte. **Security Tradeoff:** 0-RTT data is susceptible to replay attacks (RFC 9000). By default, 0-RTT is **disabled**. When enabled, only idempotent requests should be sent early. Configuration: `quic_enable_0rtt` on the **mesh** TLS config (`MeshTlsConfig` in `crates/synvoid-config/src/mesh.rs:302`, `#[serde(default)]` → `false`; mirrored in `crates/synvoid-mesh/src/mesh/config.rs:1571`), consumed by `crates/synvoid-mesh/src/mesh/cert.rs:417,431` to set `max_early_data_size = 0` on the QUIC server config and emit a replay warning. It is a mesh-node setting, not a site-level `tls.*` option.
- **Independence:** QUIC streams are independent, meaning packet loss on one stream doesn't stall others (eliminating Head-of-Line blocking).
- **QUIC Tunnel Datagrams:** Maximum datagram payload size is **1200 bytes** (per `crates/synvoid-tunnel/src/quic/messages.rs:4` `MAX_DATAGRAM_PAYLOAD`).

### 3. TCP & UDP Listeners
Beyond HTTP, SynVoid can act as a generic proxy for any TCP or UDP service.
- **TCP Listener:** Uses `src/tcp/listener.rs` for connection management with `TcpSocketOptions` for socket configuration (reuse_port, send/recv buffer sizes, keepalive, nodelay).
- **UDP Handling:** Built-in protections against amplification attacks.
- **Listener Configuration:** `crates/synvoid-http/src/listener/common.rs` defines `ConnectionContext` for connection handling. TCP socket options are configured via `TcpSocketOptions` in `src/tcp/listener.rs`.

---

## TLS & Security

### 1. TLS Termination
SynVoid handles TLS termination at the edge using **Rustls**.
- **Dynamic Certificate Selection:** The `CertResolver` selects the appropriate certificate for each connection based on SNI.
- **ACME Integration:** Built-in support for Let's Encrypt and other ACME-based CAs for automated certificate issuance and renewal. Requires explicit configuration via `tls.acme` in site config.

### 2. ACME DNS-01 Challenge Support
SynVoid supports **DNS-01** challenges for ACME certificate issuance, enabling certificate management for wildcard domains and environments where HTTP challenges are not feasible.

**Challenge Flow:**
1. ACME server delivers a `dns-01` challenge with a key authorization
2. SynVoid computes `SHA-256(key_authorization)` and base64url-encodes it
3. The challenge value is stored in `AcmeDnsChallenge` (`crates/synvoid-tls/src/acme_dns.rs`)
4. DNS server serves the value via `_acme-challenge.<domain>` TXT records (`crates/synvoid-dns/src/server/query.rs:920`)
5. ACME server validates by querying the TXT record
6. On success, the challenge is cleaned up automatically

**Implementation Details:**
- `AcmeDnsChallenge` (`crates/synvoid-tls/src/acme_dns.rs`) manages pending challenges using a thread-safe `DashMap`
- DNS integration via `build_acme_txt_response()` in `crates/synvoid-dns/src/server/response.rs:446`
- Feature-gated: requires `dns` feature flag
- TXT records are only served for exact `_acme-challenge.<domain>` queries (type 16)

**Configuration:** DNS-01 challenges require the `dns` feature and ACME configuration in site config (`tls.acme`).

### 3. Post-Quantum Cryptography (PQC)
SynVoid is at the forefront of post-quantum security:

**Key Exchange:**
- **X25519MLKEM768:** A hybrid key exchange that combines classical X25519 with the ML-KEM-768 (Kyber) algorithm.
- **Not an inbound gate:** hybrid key exchange is always available, because `synvoid-tls` and `synvoid-http-client` unconditionally enable rustls `prefer-post-quantum` + `aws-lc-rs`. The root `post-quantum` feature is a marker for http-client/admin **egress** only (see the Feature Flags list below).
- Configuration: `mesh.mlkem` section in `MeshConfig` (variant, rotation interval, session TTL, max sessions).

**Message Signatures:**
- **ML-DSA-44:** Post-quantum digital signature algorithm for mesh message authentication.
- **Always compiled:** there is no `pqc-mesh` feature flag. `synvoid-mesh` depends on the `pqc` crate (`features = ["async"]`) unconditionally and `mesh/ml_dsa.rs` contains no `cfg(feature)` gate, so hybrid signing is available in every mesh build; Ed25519-only operation is a runtime fallback in `verify_hybrid()`, not a build-time choice.
- Configuration: `global_node.ml_dsa_private_key_base64` in `GlobalNodeConfig`.

**Feature Flags:**
- `post-quantum` — Marker feature wiring `synvoid-http-client/post-quantum` + `synvoid-admin/post-quantum` for http-client/admin egress (`crates/synvoid-http-client/src/tls.rs` gates PQ log/status on `cfg!(feature = "post-quantum")`). It does NOT gate inbound TLS: both `crates/synvoid-tls` and `crates/synvoid-http-client` unconditionally enable rustls `prefer-post-quantum` + `aws-lc-rs` (see both Cargo.tomls).
- ~~`pqc-mesh`~~ — **No such feature exists.** It appears in neither the root `Cargo.toml` nor `synvoid-mesh/Cargo.toml`. Do not add a `pqc-mesh` Cargo snippet; ML-DSA-44 mesh signing is unconditional (see the "Always compiled" bullet above).
- `verify-pq` — Declared in the root `Cargo.toml:38` and `synvoid-mesh/Cargo.toml:17`. It has exactly one use site: at mesh QUIC transport construction, `cert_manager.read().verify_post_quantum()` runs a startup self-check (`crates/synvoid-mesh/src/mesh/transports/quic.rs:31-33`). It is off by default and gates no request-path behavior.

---

## Performance Optimizations

### 1. Ownership-Based Buffer Reuse
SynVoid leverages Rust's ownership model and a custom `BufferPool` to minimize data copying and allocation overhead. The buffer pool (see `crates/synvoid-utils/src/buffer/pool.rs`) provides reusable buffers across IO operations, significantly reducing garbage collection pressure. True zero-copy paths exist in specific hot paths, but most handlers currently copy data between network and application layers.

### 2. Connection Limiting
The `ConnectionLimiter` (`crates/synvoid-waf/src/traffic_shaper/limiter.rs`, canonical since Phase 19) provides fine-grained control over concurrent connections at multiple levels:
- **Global Limit:** Total connections the WAF instance will accept.
- **Per-Site Limit:** Per-site connection counting via `try_acquire_with_limits()` which applies limits by site_id parameter.
- **Per-IP Limit:** Prevents connection exhaustion attacks from a single source.

### 3. Buffer Management
A custom `BufferPool` is used to reuse memory buffers for IO operations, significantly reducing garbage collection pressure and allocation overhead.
