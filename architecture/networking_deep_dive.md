# Networking & Protocols

SynVoid's networking layer is built for extreme performance and flexibility, supporting modern protocols and high-concurrency workloads.

## Protocol Support

### 1. HTTP/1.1 & HTTP/2
SynVoid uses **Hyper** as its foundational HTTP library.
- **HTTP/1.1:** Robust implementation with connection pooling and keep-alive support.
- **HTTP/2:** Fully multiplexed streams over a single TCP connection, reducing latency for complex web pages.
- **Shared Handler:** Both H1 and H2 share a common request processing pipeline, ensuring consistent security and routing behavior.

### 2. HTTP/3 (QUIC)
SynVoid features native HTTP/3 support via the **Quinn** library.
- **Connection Migration:** QUIC's use of connection IDs allows clients (like mobile devices) to switch networks without dropping connections.
- **0-RTT:** Enables clients to send data in the first packet of a handshake, significantly reducing time-to-first-byte.
- **Independence:** QUIC streams are independent, meaning packet loss on one stream doesn't stall others (eliminating Head-of-Line blocking).

### 3. TCP & UDP Listeners
Beyond HTTP, SynVoid can act as a generic proxy for any TCP or UDP service.
- **TCP Pool:** Manages multiple TCP listeners with auto-tuned worker pools.
- **UDP Pool:** Optimized for high-throughput UDP packet handling, with built-in protections against amplification attacks.

---

## TLS & Security

### 1. TLS Termination
SynVoid handles TLS termination at the edge using **Rustls**.
- **Dynamic Certificate Selection:** The `CertResolver` selects the appropriate certificate for each connection based on SNI.
- **ACME Integration:** Built-in support for Let's Encrypt and other ACME-based CAs for automated certificate issuance and renewal.

### 2. Post-Quantum Cryptography (PQC)
SynVoid is at the forefront of post-quantum security:

**Key Exchange:**
- **X25519MLKEM768:** A hybrid key exchange that combines classical X25519 with the ML-KEM-768 (Kyber) algorithm.
- **Feature-Gated:** PQ key exchange can be enabled via the `post-quantum` feature flag.
- Configuration: `mesh.ml_kem` section in `MeshConfig` (variant, rotation interval, session TTL, max sessions).

**Message Signatures:**
- **ML-DSA-44:** Post-quantum digital signature algorithm for mesh message authentication.
- **Feature-Gated:** PQ mesh signatures can be enabled via the `pqc-mesh` feature flag.
- Configuration: `global_node.ml_dsa_private_key_base64` in `GlobalNodeConfig`.

**Feature Flags:**
- `post-quantum` — Enables TLS hybrid key exchange (ML-KEM)
- `pqc-mesh` — Enables post-quantum mesh message signatures (ML-DSA)
- `verify-pq` — Enables post-quantum key exchange verification for mesh connections

---

## Performance Optimizations

### 1. Ownership-Based Buffer Reuse
SynVoid leverages Rust's ownership model and a custom `BufferPool` to minimize data copying and allocation overhead. The buffer pool (see `crates/synvoid-utils/src/buffer/pool.rs`) provides reusable buffers across IO operations, significantly reducing garbage collection pressure. True zero-copy paths exist in specific hot paths, but most handlers currently copy data between network and application layers.

### 2. Connection Limiting
The `ConnectionLimiter` provides fine-grained control over concurrent connections at multiple levels:
- **Global Limit:** Total connections the WAF instance will accept.
- **Per-Site Limit:** Limits the impact of a surge in traffic to a single domain.
- **Per-IP Limit:** Prevents connection exhaustion attacks from a single source.

### 3. Buffer Management
A custom `BufferPool` is used to reuse memory buffers for IO operations, significantly reducing garbage collection pressure and allocation overhead.
