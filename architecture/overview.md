# SynVoid Architecture Overview

SynVoid is a high-performance Web Application Firewall (WAF) and multi-tenant reverse proxy written in Rust, designed for **1M+ RPS** with **millions of tenants**. It uses a multi-process architecture with a unified async event loop for maximum efficiency.

---

## Table of Contents

- [System Architecture](#system-architecture)
- [Process Model](#process-model)
- [HTTP Stack](#http-stack)
- [Security & WAF](#security--waf)
- [Proxy & Upstream](#proxy--upstream)
- [Application Handlers](#application-handlers)
- [DNS Server](#dns-server)
- [Mesh Networking](#mesh-networking)
- [TLS & Cryptography](#tls--cryptography)
- [Admin & Auth](#admin--auth)
- [Platform & Infrastructure](#platform--infrastructure)
- [Deep Dive Index](#deep-dive-index)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Supervisor (Control Plane)                       │
│  Process management, gRPC API, Raft consensus, DHT routing, config loading │
│  (Consolidated from legacy Overseer + Master hierarchy)                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                      ┌───────────────┼───────────────┐
                      ▼               ▼               ▼
           ┌──────────────────┐ ┌──────────┐ ┌───────────────┐
           │ UnifiedServer   │ │  Static  │ │  Mesh Agent   │
           │ Worker (HTTP/   │ │  Worker  │ │  (optional    │
           │ HTTPS/HTTP3)    │ │  (CSS/JS │ │   control     │
           │                 │ │  minify) │ │   plane)      │
           └─────────────────┘ └──────────┘ └───────────────┘
```

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Single async event loop** | Tokio's cooperative scheduling handles all cores efficiently |
| **Shared-nothing workers** | Linear scalability, no mutex contention |
| **SO_REUSEPORT** | Kernel-level load balancing across workers |
| **Postcard/Rkyv serialization** | Zero-copy alternative to JSON for IPC and mesh |
| **Domain-based routing O(1)** | Millions of tenants without performance degradation |
| **Pure Rust crypto** | aws-lc-rs for TLS, libcrux for post-quantum signatures |

---

## Process Model

SynVoid employs a hierarchical process model for high availability and zero-downtime operations.

| Process | Binary Flag | Purpose | Count |
|---------|-------------|---------|-------|
| **Supervisor** | (default) | Worker spawn/manage, IPC, gRPC control plane, zero-downtime upgrades | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | HTTP/HTTPS/HTTP3 + WAF + proxy | N |
| **StaticWorker** | `--static-worker` | CSS/JS minification, compression | N |
| **MeshAgent** | `--mesh-agent` | Distributed control plane coordination | N |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated) | configurable |

### Documentation

- [Process Lifecycle](process_lifecycle.md) - Worker hierarchy, drain coordination, zero-downtime upgrades
- [Worker Architecture](worker_architecture.md) - Unified server, listener pools, request flow
- [Platform Deep Dive](platform_deep_dive.md) - IPC, sandboxing, platform abstraction

---

## HTTP Stack

The HTTP stack handles all incoming client connections with support for HTTP/1.1, HTTP/2, and HTTP/3.

| Module | Path | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **HTTP Server** | `src/http/` | HTTP/1.1 + HTTP/2 server, request parsing, routing, WebDAV | [networking_deep_dive.md](networking_deep_dive.md) |
| **HTTP/3** | `src/http3/` | HTTP/3 QUIC handling via quinn/h3 | [networking_deep_dive.md](networking_deep_dive.md) |
| **HTTP Client** | `src/http_client/` | Upstream proxy, connection pooling, streaming | [networking_deep_dive.md](networking_deep_dive.md) |
| **Listener** | `src/listener/` | Socket binding, accepting, connection limiting | [networking_deep_dive.md](networking_deep_dive.md) |
| **Protocol** | `src/protocol/` | Protocol detection (WebSocket, gRPC, DNS) | [networking_deep_dive.md](networking_deep_dive.md) |

### Key HTTP Components

**HTTP Server (`src/http/server.rs`)**
- `HttpServer` struct with router, WAF, HTTP client integration
- `HttpConnection` wraps TCP stream with protocol validation
- `StreamingWafBody` for WAF scanning during streaming
- WebSocket upgrades via `hyper::upgrade::on()`
- Flood protection via `FloodProtector`

**HTTP/3 (`src/http3/server.rs`)**
- `Http3Server` using `quinn` for QUIC transport
- Uses `h3` for HTTP/3 protocol handling
- Shares infrastructure with HTTP/1.1 server
- Max 100 concurrent bidirectional streams, 60s idle timeout

**HTTP Client (`src/http_client/mod.rs`)**
- `HttpClient`, `StreamingHttpClient`, `UnixHttpClient` variants
- `ErasedHttpClient` type-erased pooling for 1M+ RPS
- Connection pooling via `moka` cache
- `StreamingWafBody<B>` for per-chunk WAF scanning

**Protocol Detection (`src/protocol/`)**
- `ProtocolHandler` trait for extensible protocol handling
- `WebSocketHandler` with frame parsing and masking
- `GrpcHandler` for gRPC protocol

---

## Security & WAF

Multi-layered protection against threats with coordinated attack detection and bot mitigation.

| Module | Path | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **WAF Core** | `src/waf/` | Request filtering, decision engine (Pass/Block/Drop/Stall/Tarpit/Challenge) | [waf_deep_dive.md](waf_deep_dive.md) |
| **Attack Detection** | `src/waf/attack_detection/` | SQLi, XSS, path traversal, RFI, SSRF, SSTI, cmd injection, XXE, LDAP, XPath, open redirect | [waf_deep_dive.md](waf_deep_dive.md) |
| **Bot Detection** | `src/waf/bot.rs` | JA3/JA4 fingerprinting, UA analysis via `isbot` crate | [waf_deep_dive.md](waf_deep_dive.md) |
| **Rate Limiting** | `src/waf/ratelimit/` | IP/global rate limiting with sliding window | [waf_deep_dive.md](waf_deep_dive.md) |
| **Threat Level** | `src/waf/threat_level/` | Adaptive threat scoring with SQLite persistence | [waf_deep_dive.md](waf_deep_dive.md) |
| **Flood Protection** | `src/waf/flood/` | SYN flood, UDP flood, connection limiting; eBPF on Linux | [waf_deep_dive.md](waf_deep_dive.md) |
| **Filter** | `src/filter/` | TCP/UDP protocol filtering framework | [waf_deep_dive.md](waf_deep_dive.md) |
| **Challenge** | `src/challenge/` | PoW, CSS, Mesh-PoW challenges | [waf_deep_dive.md](waf_deep_dive.md) |
| **GeoIP** | `src/geoip/` | MaxMind GeoIP lookup, country/ASN blocking | [waf_deep_dive.md](waf_deep_dive.md) |
| **Block Store** | `src/block_store.rs` | Persistent 64-shard blocklist with LRU eviction | [waf_deep_dive.md](waf_deep_dive.md) |
| **Tarpit** | `src/tarpit/` | Markov chain bot trap for scrapers | [waf_deep_dive.md](waf_deep_dive.md) |
| **Honeypot Ports** | `src/honeypot_port/` | Port honeypot with AI responders, protocol detection | [waf_deep_dive.md](waf_deep_dive.md) |
| **Auth** | `src/auth/` | User auth, session management, bcrypt, brute-force protection | [admin_deep_dive.md](admin_deep_dive.md) |
| **TCP Proxy** | `src/tcp/` | TCP proxy with protocol detection | [waf_deep_dive.md](waf_deep_dive.md) |
| **UDP Proxy** | `src/udp/` | UDP proxy with flood protection | [waf_deep_dive.md](waf_deep_dive.md) |

### WAF Pipeline Flow

```
Request → Rate Limiting → Bot Detection → Attack Detection → Challenge → Proxy
          (IP/Global)    (JA3/JA4)      (YARA rules)       (PoW/CSS)
```

### Key WAF Structs

- **`WafCore`** (`src/waf/mod.rs`): Central orchestrator
- **`WafDecision`** enum: `Pass`, `Block`, `Drop`, `Stall`, `Tarpit`, `Challenge`
- **`AttackDetector`** (`src/waf/attack_detection/mod.rs`): 12+ attack type detectors
- **`StreamingWafCore`** (`src/waf/attack_detection/streaming.rs`): Sliding window body inspection
- **`ThreatLevelManager`** (`src/waf/threat_level/mod.rs`): Adaptive scoring with baseline learning

---

## Proxy & Upstream

| Module | Path | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **Proxy** | `src/proxy/` | Reverse proxy, upstream dispatch, retry logic | [proxy_deep_dive.md](proxy_deep_dive.md) |
| **Proxy Cache** | `src/proxy_cache/` | LRU response caching with TTL, SWR, SIE | [proxy_deep_dive.md](proxy_deep_dive.md) |
| **Upstream** | `src/upstream/` | Backend pools, load balancing, health checks | [routing_deep_dive.md](routing_deep_dive.md) |
| **Router** | `src/router.rs` | Domain-based routing, Host header matching, wildcards | [routing_deep_dive.md](routing_deep_dive.md) |

### Load Balancing Algorithms

| Algorithm | Description |
|-----------|-------------|
| **RoundRobin** | Default, cycles through backends |
| **Random** | Random selection |
| **LeastConnections** | Backend with lowest composite load |
| **PeakEwma** | Cost-based: `(connections + 1) * (latency + 1)` |
| **WeightedRoundRobin** | Weight-based rotation |
| **IpHash** | Consistent hashing by client IP |

### Key Proxy Structs

- **`ProxyServer`** (`src/proxy/mod.rs`): Core proxy with upstream pool, cache, retry config
- **`UpstreamPool`** (`src/upstream/pool.rs`): Pool management and backend selection
- **`Backend`** (`src/upstream/pool.rs`): Individual backend with connection count and health
- **`CacheKey`** (`proxy_cache/key.rs`): Cache key with Vary header support

---

## Application Handlers

SynVoid supports multiple backend types natively.

| Handler | Path | Purpose | Deep Dive |
|---------|------|---------|-----------|
| **Static Files** | `src/static_files/` | File serving, caching, compression, minification | [app_handlers.md](app_handlers.md) |
| **PHP** | `src/php/` | PHP-FPM via FastCGI | [app_handlers.md](app_handlers.md) |
| **FastCGI** | `src/fastcgi/` | Generic FastCGI backend with connection pooling | [app_handlers.md](app_handlers.md) |
| **CGI** | `src/cgi/` | CGI script execution (Perl, Python, Ruby, etc.) | [app_handlers.md](app_handlers.md) |
| **Serverless** | `src/serverless/` | WASM runtime with instance pooling | [plugin_deep_dive.md](plugin_deep_dive.md) |
| **Spin** | `src/spin/` | Fermyon Spin framework support | [plugin_deep_dive.md](plugin_deep_dive.md) |
| **Plugin** | `src/plugin/` | Dynamic WASM/native plugin loading | [plugin_deep_dive.md](plugin_deep_dive.md) |

### BackendType Enum Variants

`src/router.rs` defines 11 backend variants:
- `Upstream`, `FastCgi`, `Php`, `Cgi`, `AxumDynamic`, `AppServer`, `Static`, `QuicTunnel`, `Serverless`, `Mesh`, `Spin`

---

## DNS Server (Optional - `dns` feature)

| Component | Path | Purpose | Deep Dive |
|-----------|------|---------|-----------|
| **DNS Server** | `src/dns/` | Authoritative DNS with zone management | [dns_deep_dive.md](dns_deep_dive.md) |
| **Recursive Resolver** | `src/dns/recursive.rs` | Full recursive resolver with caching | [dns_deep_dive.md](dns_deep_dive.md) |
| **DNSSEC** | `src/dns/dnssec*.rs` | Signing, validation, key management (NSEC/NSEC3) | [dns_deep_dive.md](dns_deep_dive.md) |
| **TSIG** | `src/dns/tsig.rs` | Transaction signature for dynamic updates | [dns_deep_dive.md](dns_deep_dive.md) |
| **Zone Transfer** | `src/dns/transfer.rs` | AXFR/IXFR zone transfers | [dns_deep_dive.md](dns_deep_dive.md) |
| **Encrypted DNS** | `src/dns/doh.rs`, `dot.rs`, `doq.rs` | DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC | [dns_deep_dive.md](dns_deep_dive.md) |
| **Tunnel** | `src/tunnel/` | QUIC tunnel, WireGuard VPN | [dns_deep_dive.md](dns_deep_dive.md) |
| **VPN Client** | `src/vpn_client/` | VPN client functionality | [dns_deep_dive.md](dns_deep_dive.md) |

### DNS Key Files

- **`DnsServer`** (`src/dns/server/mod.rs`): Core authoritative server
- **`ZoneStore`** (`src/dns/store.rs`): SQLite-backed zone persistence
- **`TrustAnchorManager`** (`src/dns/trust_anchor.rs`): RFC 5011 trust anchor management
- **`ZoneSigningKey`** (`src/dns/dnssec.rs`): DNSSEC key lifecycle

---

## Mesh Networking (Optional - `mesh` feature)

Distributed peer-to-peer networking for DDoS defense, threat intelligence, and coordination.

| Component | Path | Purpose | Deep Dive |
|-----------|------|---------|-----------|
| **DHT** | `src/mesh/dht/` | Distributed hash table, Kademlia routing | [mesh_deep_dive.md](mesh_deep_dive.md) |
| **Raft** | `src/mesh/raft/` | Consensus for global control plane | [mesh_deep_dive.md](mesh_deep_dive.md) |
| **Transport** | `src/mesh/transport.rs` | QUIC-based encrypted transport | [mesh_deep_dive.md](mesh_deep_dive.md) |
| **MeshProxy** | `src/mesh/proxy.rs` | HTTP proxy routing through mesh | [mesh_deep_dive.md](mesh_deep_dive.md) |
| **MeshBackend** | `src/mesh/backend.rs` | DHT-backed backend factory | [mesh_deep_dive.md](mesh_deep_dive.md) |
| **Threat Intel** | `src/mesh/threat_intel.rs` | Distributed threat intelligence | [mesh_deep_dive.md](mesh_deep_dive.md) |
| **Peer Auth** | `src/deputy_auth.rs` | Peer authentication | [mesh_deep_dive.md](mesh_deep_dive.md) |

### Mesh Node Roles

| Role | Description |
|------|-------------|
| **Global Node** | Full mesh participant, Raft consensus, DNSSEC signing |
| **Edge Node** | PoW enforcement, geographic distribution |
| **Origin Node** | Backend origin announcing routes through mesh |

### DHT Submodules

```
mesh/dht/
├── mod.rs              # Core DHT types
├── signed.rs           # Record signing, quorum verification
├── quorum.rs           # Quorum consensus
├── record_store.rs     # Sharded in-memory store (64 shards)
├── keys.rs             # DhtKey enum (50+ key variants)
├── routing/            # K-bucket routing
│   ├── table.rs       # RoutingTable with 256 K-buckets
│   └── manager.rs      # DhtRoutingManager
└── merkle.rs           # Merkle tree digests
```

---

## TLS & Cryptography

| Module | Path | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **TLS** | `src/tls/` | TLS termination, ACME/Let's Encrypt, SNI peeking | [layer_3_5_deep_dive.md](layer_3_5_deep_dive.md) |
| **WASM PoW** | `src/wasm_pow/` | Browser WASM proof-of-work with PQC key exchange | [layer_3_5_deep_dive.md](layer_3_5_deep_dive.md) |

### Cryptographic Standards

| Feature | Implementation |
|---------|----------------|
| **TLS** | `rustls` with `aws-lc-rs` crypto provider |
| **Post-Quantum TLS** | ML-KEM-768 hybrid key exchange via `libcrux-ml-dsa` |
| **Post-Quantum Mesh** | ML-DSA-44 signatures |
| **Hashing** | BLAKE3 for checksums, SHA-3 for HMAC |
| **Signing** | Ed25519 + ML-DSA hybrid |

### Key TLS Structs

- **`CertResolver`** (`src/tls/cert_resolver.rs`): Multi-domain certificate resolution with hot-reload
- **`AcmeManager`** (`src/tls/acme.rs`): Let's Encrypt automated provisioning
- **`HttpsServer`** (`src/tls/server.rs`): TLS acceptor server

---

## Admin & Auth

| Module | Component | Deep Dive |
|--------|-----------|-----------|
| **Admin API** | Axum-based HTTP/HTTPS management interface, WebSocket broadcasting | [admin_deep_dive.md](admin_deep_dive.md) |
| **Auth** | Session management, bcrypt password hashing, brute-force protection | [admin_deep_dive.md](admin_deep_dive.md) |
| **Overseer** | Legacy parent process (health monitoring, upgrade coordination) | [platform_deep_dive.md](platform_deep_dive.md) |
| **Master** | Legacy mid-tier process manager | [platform_deep_dive.md](platform_deep_dive.md) |
| **Metrics** | Prometheus exporter, site/worker metrics | [platform_deep_dive.md](platform_deep_dive.md) |

### Key Admin Components

- **`AdminState`** (`src/admin/state.rs`): Central admin state with config and trackers
- **`AuditLog`** (`src/admin/audit.rs`): Config change audit trail
- **`Broadcaster`** (`src/admin/ws/`): WebSocket event broadcasting
- **`AuthManager`** (`src/auth/mod.rs`): Session and authentication management

---

## Platform & Infrastructure

| Module | Path | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **Platform** | `src/platform/` | Cross-platform abstractions (Linux, macOS, BSD, Windows) | [platform_deep_dive.md](platform_deep_dive.md) |
| **Sandbox** | `src/platform/sandbox.rs` | OS sandboxing (Landlock, Capsicum, Pledge, Windows Job Objects) | [platform_deep_dive.md](platform_deep_dive.md) |
| **Process** | `src/process/` | IPC primitives, worker lifecycle, message framing | [platform_deep_dive.md](platform_deep_dive.md) |
| **Supervisor** | `src/supervisor/` | Process supervision, health monitoring | [platform_deep_dive.md](platform_deep_dive.md) |
| **Metrics** | `src/metrics/` | Prometheus metrics, bandwidth tracking | [platform_deep_dive.md](platform_deep_dive.md) |
| **Logging** | `src/logging/` | Access logging, syslog, dynamic log levels | [platform_deep_dive.md](platform_deep_dive.md) |
| **Config Crate** | `crates/synvoid-config/` | Strongly-typed configuration, TOML loading | [config_deep_dive.md](config_deep_dive.md) |
| **Utils Crate** | `crates/synvoid-utils/` | Buffer pooling, serialization | [config_deep_dive.md](config_deep_dive.md) |

### Platform Sandboxing

| OS | Backend | Level |
|----|---------|-------|
| Linux 5.13+ | Landlock | Basic/Strict |
| FreeBSD | Capsicum | Basic/Strict |
| OpenBSD | Pledge | Basic/Strict |
| macOS | Seatbelt (feature-gated) | Basic/Strict |
| Windows | Job Objects + DEP/ASLR | Basic/Strict |

### Buffer Pool Architecture

`crates/synvoid-utils/src/buffer/pool.rs`:
- 4-tier architecture: Small (4KB), Medium (64KB), Large (256KB), Jumbo (256KB+)
- 8 shards with lock-free TLS cache (16 buffers/tier)
- Global memory limit enforcement
- ABA-safe lock-free implementation

---

## Deep Dive Index

This overview serves as an index for detailed documentation. Each link provides an in-depth exploration of the respective subsystem.

| Category | Document | Coverage |
|----------|----------|----------|
| **Process Model** | [Process Lifecycle](process_lifecycle.md) | Overseer, Supervisor, Worker hierarchy, drain coordination |
| **Worker Architecture** | [Worker Architecture](worker_architecture.md) | Unified server, listener pools, request flow |
| **HTTP Stack** | [Networking Deep Dive](networking_deep_dive.md) | HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, connection handling |
| **Request Routing** | [Routing Deep Dive](routing_deep_dive.md) | Router, upstream pools, load balancing, health monitoring |
| **Proxy & Upstream** | [Proxy & Upstream Deep Dive](proxy_deep_dive.md) | Proxy server, connection pooling, retry logic, cache governor |
| **Security/WAF** | [WAF Deep Dive](waf_deep_dive.md) | WAF pipeline, attack detection, bot mitigation, challenges |
| **Admin & Auth** | [Admin & Auth Deep Dive](admin_deep_dive.md) | Admin API, session management, CSRF, rate limiting |
| **Application Handlers** | [App Handlers](app_handlers.md) | Static files, PHP-FPM, FastCGI, CGI, WASM, Spin |
| **Plugin & Serverless** | [Plugin & Serverless Deep Dive](plugin_deep_dive.md) | WASM plugin runtime, Spin, serverless instance pooling |
| **Mesh Networking** | [Mesh Deep Dive](mesh_deep_dive.md) | DHT, Raft consensus, QUIC transport, threat intelligence |
| **DNS & Tunnel** | [DNS & Tunnel Deep Dive](dns_deep_dive.md) | DNS server, DNSSEC, TSIG, tunnel protocols, VPN client |
| **Platform & Process** | [Platform & Process Deep Dive](platform_deep_dive.md) | IPC, sandboxing, platform abstraction, supervisor |
| **Configuration** | [Config & Utils Deep Dive](config_deep_dive.md) | Configuration hierarchy, buffer pool, serialization |
| **Post-Quantum & Trust** | [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) | PQC key exchange, ML-DSA/ML-KEM, trust models |
| **Review Summary** | [Deep Dive Review](deep_dive_review.md) | Cross-cutting findings, architectural analysis |

---

## Module Index by Source Path

| Path | Primary Purpose |
|------|----------------|
| `src/admin/` | Admin API, WebSocket broadcasting, audit logging |
| `src/auth/` | User auth, sessions, bcrypt, brute-force protection |
| `src/block_store.rs` | Persistent 64-shard IP blocklist with LRU eviction |
| `src/cgi/` | CGI script execution (Perl, Python, Ruby, Shell, Lua) |
| `src/challenge/` | PoW, CSS, Mesh-PoW anti-bot challenges |
| `src/config/` | Configuration loading (delegates to `crates/synvoid-config/`) |
| `src/dns/` | Authoritative DNS server, DNSSEC, recursive resolver |
| `src/drain/` | Graceful drain coordination types |
| `src/fastcgi/` | FastCGI protocol client with connection pooling |
| `src/filter/` | Protocol filtering framework for TCP/UDP |
| `src/geoip/` | MaxMind GeoIP lookup, country/ASN blocking |
| `src/honeypot_port/` | Port honeypot with AI responders |
| `src/http/` | HTTP/1.1 + HTTP/2 server |
| `src/http3/` | HTTP/3 QUIC server via quinn/h3 |
| `src/http_client/` | Upstream proxy client with connection pooling |
| `src/icmp_filter/` | ICMP filtering via nftables/pf/winfw/ebpf |
| `src/integrity/` | Merkle tree, content integrity verification |
| `src/listener/` | Socket configuration, connection context |
| `src/logging/` | Dynamic log levels, access logging |
| `src/master/` | Legacy master process (IPC with workers) |
| `src/mesh/` | Mesh networking: DHT, Raft, QUIC transport |
| `src/metrics/` | Prometheus metrics, bandwidth tracking |
| `src/overseer/` | Legacy overseer (health monitoring, upgrades) |
| `src/php/` | PHP-FPM integration via FastCGI |
| `src/plugin/` | WASM plugin runtime with instance pooling |
| `src/process/` | IPC primitives, worker lifecycle management |
| `src/proxy/` | Reverse proxy, header filtering, retries |
| `src/proxy_cache/` | LRU response caching |
| `src/protocol/` | Protocol detection (WebSocket, gRPC) |
| `src/router.rs` | Domain-based routing to backends |
| `src/sandbox/` | Process sandboxing for WASM/YARA execution |
| `src/serverless/` | WASM serverless with instance pooling |
| `src/spin/` | Fermyon Spin framework support |
| `src/startup/` | Bootstrap, daemonization, signal handling |
| `src/static_files/` | Static file serving with caching/compression |
| `src/supervisor/` | Process supervisor, gRPC control plane |
| `src/tarpit/` | Markov chain bot trap for scrapers |
| `src/tcp/` | TCP proxy with protocol detection |
| `src/tls/` | TLS termination, ACME, SNI peeking |
| `src/tunnel/` | QUIC tunnel, WireGuard VPN |
| `src/udp/` | UDP proxy with flood protection |
| `src/upstream/` | Backend pools, load balancing, health checks |
| `src/utils.rs` | Misc utilities (time, parsing, hashing, regex) |
| `src/vpn_client/` | VPN client for tunnel connections |
| `src/waf/` | Web Application Firewall engine |
| `src/wasm_pow/` | Browser-side WASM proof-of-work |
| `src/worker/` | Worker process implementation |
| `src/worker_pool/` | Worker pool management |
| `crates/synvoid-config/` | Strongly-typed configuration structs |
| `crates/synvoid-utils/` | Buffer pool, serialization utilities |

---

## Feature Gates

| Feature | Purpose |
|---------|---------|
| `dns` | DNS server with DNSSEC, encrypted DNS |
| `mesh` | Mesh networking, DHT, Raft |
| `socket-handoff` | Socket transfer between processes (Unix sendmsg/recvmsg) |
| `wireguard` | WireGuard VPN support |
| `icmp-filter` | ICMP packet filtering |
| `flood-ebpf` | eBPF-based flood protection (Linux) |
| `post-quantum` | Post-quantum TLS (ML-KEM-768) |
| `pqc-mesh` | Post-quantum mesh signatures (ML-DSA-44) |
| `macos-sandbox` | macOS Seatbelt sandbox |
| `erased_pool` | Type-erased HTTP connection pool |
| `rkyv` | Rkyv zero-copy serialization |

---

## Key Architectural Patterns

### Constant-Time Comparison
Always use `subtle::ConstantTimeEq` for secrets: keys, MACs, auth tokens, passwords.
Simple `!=` comparison is acceptable for publicly-known values (puzzle solutions).

### IPC Message Signing
Messages between processes are signed via `AES-GCM` + `HMAC-SHA256` with session keys.
Session key passed via temp file with `create_new=true` to prevent symlink attacks.

### Sharded Storage
High-contention structures use sharding: `BlockStore` (64 shards), `ShardedRecordStore` (64 shards).

### Streaming WAF
`StreamingWafBody<B>` wraps upstream bodies for per-chunk WAF scanning without buffering entire request.

### Post-Quantum Hybrid Signatures
Mesh messages support `HybridSignature` combining Ed25519 + ML-DSA for post-quantum security.

---

*This overview provides a bird's eye view of SynVoid's architecture. For detailed exploration of any subsystem, refer to the linked deep dive documents.*
