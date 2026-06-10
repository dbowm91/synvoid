# Networking & Protocols

SynVoid's networking layer is built for extreme performance and flexibility, supporting modern protocols and high-concurrency workloads.

## Protocol Support

### 1. HTTP/1.1 & HTTP/2
SynVoid uses **Hyper** as its foundational HTTP library.
- **HTTP/1.1:** Robust implementation with connection pooling and keep-alive support.
- **HTTP/2:** Infrastructure exists (see `ErasedHttpClient::send_request(..., is_http2)`) but HTTP/2 pooled connections are not fully available in current implementation. **Milestone:** HTTP/2 upstream connection pooling is a planned enhancement. The `Http2PooledConnection` stub exists but is not wired for production use. This is a known limitation (HTTP2-POOL deferred item).
- **Protocol Detection:** At TLS handshake, protocol negotiation occurs via ALPN (`tls/server.rs:410-411`). The server extracts the ALPN protocol and determines if the connection should use HTTP/2 (`h2`) or HTTP/1.1. This detection happens during the TLS handshake callback before request processing begins.

### 2. HTTP/3 (QUIC)
SynVoid features native HTTP/3 support via the **Quinn** library.
- **Connection Migration:** QUIC's use of connection IDs allows clients (like mobile devices) to switch networks without dropping connections. When a client changes network interfaces (e.g., Wi-Fi to cellular), the connection persists using the same connection ID, enabling seamless migration.
- **0-RTT:** Enables clients to send data in the first packet of a handshake, significantly reducing time-to-first-byte. **Security Tradeoff:** 0-RTT data is susceptible to replay attacks (RFC 9000). By default, 0-RTT is **disabled** (`tls.quic_enable_0rtt = false`). When enabled, only idempotent requests should be sent early. Configuration: `tls.quic_enable_0rtt` (default: false).
- **Independence:** QUIC streams are independent, meaning packet loss on one stream doesn't stall others (eliminating Head-of-Line blocking).
- **QUIC Tunnel Datagrams:** Maximum datagram payload size is **1200 bytes** (per `src/tunnel/quic/messages.rs:4` `MAX_DATAGRAM_PAYLOAD`).

### 3. TCP & UDP Listeners
Beyond HTTP, SynVoid can act as a generic proxy for any TCP or UDP service.
- **TCP Listener:** Uses `src/listener/mod.rs` with `ListenerInstance` for connection management; actual TCP listener implementation in `src/tcp/listener.rs`.
- **UDP Handling:** Built-in protections against amplification attacks.
- **Listener Configuration:** `src/listener/common.rs` defines `ListenerConfigBase`, `ListenerInstance`, `ConnectionContext` for connection handling. The `SocketOptionsBase` struct provides reusable socket options (reuse_port, send_buffer_size, recv_buffer_size).

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
3. The challenge value is stored in `AcmeDnsChallenge` (`src/tls/acme_dns.rs:11-64`)
4. DNS server serves the value via `_acme-challenge.<domain>` TXT records (`src/dns/server/query.rs:698-721`)
5. ACME server validates by querying the TXT record
6. On success, the challenge is cleaned up automatically

**Implementation Details:**
- `AcmeDnsChallenge` (`src/tls/acme_dns.rs:11-64`) manages pending challenges using a thread-safe `DashMap`
- DNS integration via `build_acme_txt_response()` in `src/dns/server/response.rs:782`
- Feature-gated: requires `dns` feature flag
- TXT records are only served for exact `_acme-challenge.<domain>` queries (type 16)

**Configuration:** DNS-01 challenges require the `dns` feature and ACME configuration in site config (`tls.acme`).

### 3. Post-Quantum Cryptography (PQC)
SynVoid is at the forefront of post-quantum security:

**Key Exchange:**
- **X25519MLKEM768:** A hybrid key exchange that combines classical X25519 with the ML-KEM-768 (Kyber) algorithm.
- **Feature-Gated:** PQ key exchange can be enabled via the `post-quantum` feature flag.
- Configuration: `mesh.mlkem` section in `MeshConfig` (variant, rotation interval, session TTL, max sessions).

**Message Signatures:**
- **ML-DSA-44:** Post-quantum digital signature algorithm for mesh message authentication.
- **Feature-Gated:** PQ mesh signatures can be enabled via the `pqc-mesh` feature flag.
- Configuration: `global_node.ml_dsa_private_key_base64` in `GlobalNodeConfig`.

**Feature Flags:**
- `post-quantum` — Enables TLS hybrid key exchange (ML-KEM) for incoming HTTPS connections. Enables `X25519MLKEM768` in rustls for TLS 1.3 handshakes. Can be used independently for post-quantum key exchange without mesh signatures.
- `pqc-mesh` — Enables post-quantum mesh message signatures (ML-DSA-44) for inter-node communication. When enabled, Global nodes sign DHT records and threat intel messages with hybrid Ed25519+ML-DSA signatures. Requires `post-quantum` to be enabled as well for full PQC protection.
- `verify-pq` — Enables verification of post-quantum key exchange proofs during mesh connection establishment. Ensures that hybrid key exchange properly validates both the classical and post-quantum components. Typically used in production mesh deployments.

---

## Performance Optimizations

### 1. Ownership-Based Buffer Reuse
SynVoid leverages Rust's ownership model and a custom `BufferPool` to minimize data copying and allocation overhead. The buffer pool (see `crates/synvoid-utils/src/buffer/pool.rs`) provides reusable buffers across IO operations, significantly reducing garbage collection pressure. True zero-copy paths exist in specific hot paths, but most handlers currently copy data between network and application layers.

### 2. Connection Limiting
The `ConnectionLimiter` (`src/waf/traffic_shaper/limiter.rs`) provides fine-grained control over concurrent connections at multiple levels:
- **Global Limit:** Total connections the WAF instance will accept.
- **Per-Site Limit:** Per-site connection counting via `try_acquire_with_limits()` which applies limits by site_id parameter.
- **Per-IP Limit:** Prevents connection exhaustion attacks from a single source.

### 3. Buffer Management
A custom `BufferPool` is used to reuse memory buffers for IO operations, significantly reducing garbage collection pressure and allocation overhead.
