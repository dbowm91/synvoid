# SynVoid Architecture Overview

SynVoid is a high-performance Web Application Firewall (WAF) and multi-tenant reverse proxy written in Rust, designed for **1M+ RPS** with **millions of tenants**. It uses a multi-process architecture with a unified async event loop for maximum efficiency.

## Table of Contents

- [System Architecture](#system-architecture)
- [Process Model](#process-model)
- [HTTP Stack](#http-stack)
- [Security & WAF](#security--waf)
- [Proxy & Upstream](#proxy--upstream)
- [Application Handlers](#application-handlers)
- [TLS & Cryptography](#tls--cryptography)
- [DNS Server](#dns-server)
- [Mesh Networking](#mesh-networking)
- [Platform & Infrastructure](#platform--infrastructure)
- [Deep Dive Index](#deep-dive-index)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Supervisor (Control Plane)                       │
│  Process management, gRPC API, Raft consensus, DHT routing, config loading  │
│  (Consolidated from legacy Overseer + Master hierarchy)                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                     ┌───────────────┼───────────────┐
                     ▼               ▼               ▼
          ┌──────────────────┐ ┌──────────┐ ┌───────────────┐
          │ UnifiedServer    │ │  Static  │ │  Mesh Agent   │
          │ Worker (HTTP/    │ │  Worker  │ │  (optional    │
          │ HTTPS/HTTP3)     │ │  (CSS/JS │ │   control     │
          │                  │ │  minify) │ │   plane)      │
          └──────────────────┘ └──────────┘ └───────────────┘
```

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Single async event loop** | Tokio's cooperative scheduling handles all cores efficiently |
| **Shared-nothing workers** | Linear scalability, no mutex contention |
| **SO_REUSEPORT** | Kernel-level load balancing across workers |
| **Postcard serialization** | Zero-copy alternative to JSON for IPC |
| **Domain-based routing O(1)** | Millions of tenants without performance degradation |

---

## Process Model

SynVoid employs a hierarchical process model for high availability and zero-downtime operations.

| Process | Binary Flag | Purpose | Count |
|---------|-------------|---------|-------|
| **Supervisor** | (default) | Worker spawn/manage, IPC, gRPC control plane, zero-downtime upgrades | 1 |
| **Master** | `--master` | Legacy mid-tier process manager (spawned by Overseer) | 1 |
| **Overseer** | `--overseer` | Legacy parent process (health monitoring, upgrade coordination) | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | HTTP/HTTPS/HTTP3 + WAF + proxy | N |
| **StaticWorker** | `--static-worker` | CSS/JS minification, compression | N |
| **MeshAgent** | `--mesh-agent` | Distributed control plane coordination | N |

### Legacy Overseer & Master (Deprecated)

The legacy **Overseer** process (`src/overseer/`) and **Master** process (`src/master/`) have been **deprecated** in favor of the consolidated Supervisor. These modules remain in the codebase for backward compatibility but are not invoked when using the default Supervisor mode.

- **Old model:** Overseer → Master → Worker (three-tier hierarchy)
- **Current model:** Supervisor → Worker (consolidated two-tier for simpler deployments)
- **Note:** The `--master` and `--overseer` flags still exist for environments requiring the legacy hierarchy.

**Note:** The UnifiedServerWorker uses a single Tokio runtime with `worker_threads` equal to CPU cores. Adding more worker processes does NOT increase throughput—it only adds process isolation overhead.

### Process Documentation

| Document | Description |
|----------|-------------|
| [Process Lifecycle](process_lifecycle.md) | Supervisor-Worker hierarchy, zero-downtime upgrades |
| [Worker Architecture](worker_architecture.md) | Unified server, listener pools, request flow |
| [Platform & Process Deep Dive](platform_deep_dive.md) | IPC, sandboxing, platform abstraction |

---

## HTTP Stack

| Module | Path | Purpose |
|--------|------|---------|
| **HTTP Server** | `src/http/` | HTTP/1.1, HTTP/2 server, request parsing, routing, response handling, WebDAV |
| **HTTP/3** | `src/http3/` | HTTP/3 QUIC handling, h3 protocol implementation |
| **HTTP Client** | `src/http_client/` | Upstream proxy connections, connection pooling, streaming |
| **Listener** | `src/listener/` | Socket binding, accepting, connection limiting |
| **Protocol** | `src/protocol/` | Protocol detection and handling |

### HTTP Documentation

| Document | Description |
|----------|-------------|
| [Networking Deep Dive](networking_deep_dive.md) | HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, connection handling |

---

## TLS & Cryptography

| Module | Path | Purpose |
|--------|------|---------|
| **TLS** | `src/tls/` | TLS termination, ACME/Let's Encrypt certificate management, SNI peeking |
| **WASM PoW** | `src/wasm_pow/` | WASM-based proof-of-work with post-quantum key exchange |

### Cryptographic Standards

| Feature | Purpose |
|---------|---------|
| **Post-Quantum TLS** | ML-KEM-768 (Kyber) hybrid key exchange via `post-quantum` feature |
| **Post-Quantum Mesh** | ML-DSA-44 signatures for mesh messages via `pqc-mesh` feature |
| **Hashing** |Blake3 for fast checksums, SHA-3 for HMAC |

### TLS Documentation

| Document | Description |
|----------|-------------|
| [Networking Deep Dive](networking_deep_dive.md) | TLS termination, certificate management |
| [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) | Post-quantum crypto, trust models |

---

## Proxy & Upstream

| Module | Path | Purpose |
|--------|------|---------|
| **Proxy** | `src/proxy/` | Reverse proxy, upstream pool, load balancing, caching, retry logic |
| **Proxy Cache** | `src/proxy_cache/` | Response caching layer |
| **Upstream** | `src/upstream/` | Backend address management, health checks, load balancing |
| **Router** | `src/router.rs` | Domain-based routing to sites, Host header matching, wildcards |

### Proxy Documentation

| Document | Description |
|----------|-------------|
| [Proxy & Upstream Deep Dive](proxy_deep_dive.md) | Proxy server, connection pooling, retry logic, cache governor |
| [Routing Deep Dive](routing_deep_dive.md) | Router, upstream pools, load balancing, health monitoring |

---

## Security & WAF

The WAF provides multi-layered protection against threats.

### WAF Pipeline

```
Request → Rate Limiting → Bot Detection → Attack Detection → Challenge → Proxy
          (IP/Global)    (JA3/JA4)      (YARA rules)       (PoW/CSS)
```

| Module | Path | Purpose |
|--------|------|---------|
| **WAF Core** | `src/waf/` | Request sanitization, decision engine (Pass/Block/Drop/Stall/Tarpit/Challenge) |
| **Filter** | `src/filter/` | Protocol filtering framework (TCP/UDP) |
| **Challenge** | `src/challenge/` | PoW, CSS, Mesh-PoW challenges for bot mitigation |
| **WASM PoW** | `src/wasm_pow/` | Browser-based WebAssembly proof-of-work |
| **GeoIP** | `src/geoip/` | Country/ASN lookup, geographic blocking |
| **Block Store** | `src/block_store.rs` | Persistent IP blocklists with LRU eviction |

### Authentication & Session Management

| Module | Path | Purpose |
|--------|------|---------|
| **Auth** | `src/auth/` | User auth, session management, bcrypt, brute-force protection |
| **Admin API** | `src/admin/` | Management interface (Axum-based), OpenAPI docs |

### Threat Mitigation

| Module | Path | Purpose |
|--------|------|---------|
| **Tarpit** | `src/tarpit/` | Markov chain-based bot trap with fake HTML content |
| **Honeypot Ports** | `src/honeypot_port/` | Port scanning detection, protocol honeypots |
| **ICMP Filter** | `src/icmp_filter/` | ICMP filtering/flood protection (eBPF) |
| **TCP Proxy** | `src/tcp/` | TCP proxy with protocol detection |
| **UDP Proxy** | `src/udp/` | UDP proxy with flood protection |

### Security Documentation

| Document | Description |
|----------|-------------|
| [WAF Security Pipeline](waf_deep_dive.md) | WAF engine, attack detection, bot mitigation |
| [Admin & Auth Deep Dive](admin_deep_dive.md) | Admin API, session management, CSRF protection |
| [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) | Post-quantum crypto, trust models |

---

## Application Handlers

SynVoid supports multiple backend types natively.

| Handler | Path | Purpose |
|---------|------|---------|
| **Static Files** | `src/static_files/` | File serving, caching, compression, minification, directory listing |
| **PHP** | `src/php/` | PHP-FPM via FastCGI |
| **FastCGI** | `src/fastcgi/` | Generic FastCGI backend support |
| **CGI** | `src/cgi/` | CGI script execution |
| **Serverless** | `src/serverless/` | WASM runtime with instance pooling |
| **Spin** | `src/spin/` | Fermyon Spin framework support |

> **Note:** Spin requires manual app registration via the Admin API before use. See [Application Handlers](app_handlers.md) for setup instructions.
| **Plugin** | `src/plugin/` | Dynamic WASM/native plugin loading |
| **Static Worker** | `src/worker/` | CSS/JS minification, compression |

<sup>1. All mesh networking components (DHT, Raft, Transport, Threat Intel, YARA Rules, MeshBackend, MeshProxy) require the `mesh` feature flag to compile.</sup>

### App Handler Documentation

| Document | Description |
|----------|-------------|
| [Application Handlers](app_handlers.md) | Static files, PHP-FPM, FastCGI, Python, WASM, Spin |
| [Plugin & Serverless Deep Dive](plugin_deep_dive.md) | WASM plugin runtime, Spin, serverless execution |
| [Routing Deep Dive](routing_deep_dive.md) | BackendType routing, load balancing, health checking |

---

## DNS Server (Optional - `dns` feature)

| Component | Path | Purpose |
|-----------|------|---------|
| **DNS Server** | `src/dns/` | Authoritative DNS server with DNSSEC signing |
| **Recursive Resolver** | `src/dns/` | Recursive resolution with cache |
| **TSIG** | `src/dns/` | Transaction signature authentication for dynamic updates |
| **Zone Transfer** | `src/dns/transfer.rs` | AXFR/IXFR zone transfers (partial implementation) |
| **DNSSEC** | `src/dns/dnssec*.rs` | Signing, validation, key management |
| **Encrypted DNS** | `src/dns/doh.rs`, `dot.rs`, `doq.rs` | DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC |

### Tunnel & VPN

| Component | Path | Purpose |
|-----------|------|---------|
| **Tunnel** | `src/tunnel/` | QUIC tunnel, WireGuard VPN |
| **VPN Client** | `src/vpn_client/` | VPN client functionality |

### DNS Documentation

| Document | Description |
|----------|-------------|
| [DNS & Tunnel Deep Dive](dns_deep_dive.md) | DNS server, DNSSEC, TSIG, tunnel protocols, VPN client |

---

## Platform & Infrastructure

### Observability

| Module | Path | Purpose |
|--------|------|---------|
| **Metrics** | `src/metrics/` | Prometheus metrics, site/worker metrics |
| **Logging** | `src/logging/` | Access logging, syslog, structured JSON |

### Configuration

| Component | Path | Purpose |
|-----------|------|---------|
| **Config Crate** | `crates/synvoid-config/` | Strongly-typed configuration structs, validation |
| **Utils Crate** | `crates/synvoid-utils/` | Buffer pooling with `synvoid_utils::buffer::pool`, serialization |

### Platform Abstraction

| Module | Path | Purpose |
|--------|------|---------|
| **Platform** | `src/platform/` | Cross-platform abstractions (Linux, macOS, BSD, Windows) |
| **Process** | `src/process/` | IPC, Unix domain sockets, named pipes, message framing |
| **Supervisor** | `src/supervisor/` | Process supervision, health monitoring, zero-downtime upgrades |

### Utilities

| Module | Path | Purpose |
|--------|------|---------|
| **Utils** | `src/utils/` | Misc utilities, IP hashing, duration parsing |
| **Serialization** | `src/serialization_rkyv.rs` | rkyv zero-copy serialization |
| **Integrity** | `src/integrity/` | Merkle tree, content integrity |

### Infrastructure Documentation

| Document | Description |
|----------|-------------|
| [Platform & Process Deep Dive](platform_deep_dive.md) | IPC, sandboxing, platform abstraction |
| [Config & Utils Deep Dive](config_deep_dive.md) | Configuration hierarchy, buffer pool |

---

## Deep Dive Index

This overview serves as an index for detailed documentation. Each link below provides an in-depth exploration of the respective subsystem.

| Category | Document | Coverage |
|----------|----------|----------|
| **Process Model** | [Process Lifecycle](process_lifecycle.md) | Overseer, Supervisor, Worker hierarchy, zero-downtime upgrades |
| **Worker Architecture** | [Worker Architecture](worker_architecture.md) | Unified server, listener pools, request flow |
| **HTTP Stack** | [Networking Deep Dive](networking_deep_dive.md) | HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, connection handling |
| **Request Routing** | [Routing Deep Dive](routing_deep_dive.md) | Router, upstream pools, load balancing, health monitoring |
| **Proxy & Upstream** | [Proxy & Upstream Deep Dive](proxy_deep_dive.md) | Proxy server, connection pooling, retry logic, cache governor |
| **Security/WAF** | [WAF Deep Dive](waf_deep_dive.md) | WAF pipeline, attack detection, bot mitigation, challenges |
| **Admin & Auth** | [Admin & Auth Deep Dive](admin_deep_dive.md) | Admin API, session management, CSRF, rate limiting |
| **Application Handlers** | [App Handlers](app_handlers.md) | Static files, PHP-FPM, FastCGI, Python, WASM, Spin |
| **Plugin & Serverless** | [Plugin & Serverless Deep Dive](plugin_deep_dive.md) | WASM plugin runtime, Spin, serverless instance pooling |
| **Mesh Networking** | [Mesh Deep Dive](mesh_deep_dive.md) | DHT, Raft consensus, QUIC transport, threat intelligence |
| **DNS & Tunnel** | [DNS & Tunnel Deep Dive](dns_deep_dive.md) | DNS server, DNSSEC, TSIG, tunnel protocols, VPN client |
| **Platform & Process** | [Platform & Process Deep Dive](platform_deep_dive.md) | IPC, sandboxing, platform abstraction, supervisor |
| **Configuration** | [Config & Utils Deep Dive](config_deep_dive.md) | Configuration hierarchy, buffer pool, serialization |
| **Post-Quantum & Trust** | [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) | PQC key exchange, ML-DSA/ML-KEM, trust models |
| **Review Summary** | [Deep Dive Review](deep_dive_review.md) | Cross-cutting findings, architectural analysis |

---

## Mesh Networking (Optional - `mesh` feature)

SynVoid supports peer-to-peer mesh networking for distributed DDoS defense and threat intelligence sharing.

| Component | Path | Purpose |
|-----------|------|---------|
| **DHT** | `src/mesh/dht/` | Distributed hash table for peer discovery, Kademlia routing |
| **Raft** | `src/mesh/raft/` | Consensus for global node state, leader election |
| **Transport** | `src/mesh/transport/` | QUIC-based transport with TLS 1.3 |
| **Threat Intel** | `src/mesh/` | Distributed threat intelligence sharing |
| **YARA Rules** | `src/mesh/` | Rule distribution and synchronization |
| **MeshBackend** | `src/mesh/backend.rs` | Backend routing via mesh network |
| **MeshProxy** | `src/mesh/proxy.rs` | Backend routing via mesh (1996 lines, key routing component) |
| **Peer Auth** | `src/mesh/peer_auth.rs` | Peer authentication with edge/global node verification |
| **Protocol** | `src/mesh/protocol.rs` | Mesh protocol messages and encoding |

### Key Mesh Submodules (`src/mesh/`)

```
mesh/
├── dht/                    # Distributed Hash Table
│   ├── mod.rs
│   ├── bucket.rs           # K-bucket maintenance
│   ├── capability_access.rs # Capability-based access control
│   ├── hierarchical_routing.rs # Bloom filter routing
│   └── signed.rs          # Signed DHT entries, quorum verification
├── raft/                   # Raft consensus (incomplete)
│   ├── log.rs
│   ├── state_machine.rs
│   └── types.rs
├── transport/              # Transport layer
│   ├── mod.rs
│   ├── peer.rs             # Peer-to-peer transport
│   ├── org.rs              # Organization-level transport
│   ├── global.rs           # Global node transport
│   └── dns.rs              # DNS transport
├── proxy.rs                # Mesh proxy routing (key routing component)
├── backend.rs              # Mesh backend
├── protocol.rs             # Protocol message definitions
├── threat_intel.rs         # Threat intelligence handling
├── peer_auth.rs            # Peer authentication
├── audit.rs                # Distributed audit logging
├── certificate.rs          # Certificate management
└── signed.rs               # Signing utilities
```

### Mesh Node Roles

| Role | Description |
|------|-------------|
| **Global Node** | Full mesh participant, Raft consensus, DNSSEC signing, threat intel authority |
| **Edge Node** | PoW enforcement, geographic distribution, WAF enforcement |
| **Origin Node** | Backend origin, announces routes through mesh |
| **Composite Roles** | Global+Edge, Global+Origin, Edge+Origin combinations |

### Mesh Documentation

| Document | Description |
|----------|-------------|
| [Mesh Deep Dive](mesh_deep_dive.md) | DHT, Raft consensus, QUIC transport, threat intelligence |

---

## Module Index by Source Path

| Path | Primary Purpose |
|------|----------------|
| `src/admin/` | Admin API & UI |
| `src/app_server/` | Application server integration |
| `src/auth/` | Authentication & sessions |
| `src/bin/` | Binary crate |
| `src/block_store.rs` | IP blocklist storage |
| `src/captcha/` | CAPTCHA generation |
| `src/cgi/` | CGI script support |
| `src/challenge/` | PoW/CSS challenges |
| `src/common/` | Common/shared utilities |
| `src/config/` | Configuration loading |
| `src/dns/` | DNS server (DNSSEC) |
| `src/drain/` | Graceful drain handling |
| `src/fastcgi/` | FastCGI client |
| `src/filter/` | Protocol filtering |
| `src/geoip/` | GeoIP lookup |
| `src/honeypot_port/` | Port honeypot with AI responders, protocol detection, threat intelligence, and mesh integration |
| `src/honeypot_unified/` | Unified honeypot handler |
| `src/http/` | HTTP server |
| `src/icmp_filter/` | ICMP packet filtering via platform-specific backends (nftables, pf, winfw, wfp, ebpf) |
| `src/integrity/` | Integrity verification |
| `src/listener/` | Socket listening |
| `src/logging/` | Access logging |
| `src/master/` | Master process |
| `src/mesh/` | Mesh networking |
| `src/metrics/` | Metrics collection |
| `src/mime/` | MIME type detection |
| `src/overseer/` | Overseer process |
| `src/php/` | PHP-FPM support |
| `src/plugin/` | WASM plugin runtime with instance pooling, hot-reloading, and Axum integration |
| `src/process/` | IPC primitives |
| `src/protocol/` | Protocol handling |
| `src/proxy/` | Reverse proxy |
| `src/proxy_cache/` | Response caching |
| `src/router.rs` | Request routing |
| `src/sandbox/` | Process sandboxing for WASM/YARA execution with restricted child processes (jail model) |
| `src/serverless/` | Serverless function management with async compilation, instance pooling, and registry |
| `src/spin/` | Spin framework runtime with WASM support, KV store, and manifest parsing |
| `src/startup/` | Bootstrap & startup |
| `src/static_files/` | Static file serving |
| `src/streaming/` | Streaming primitives |
| `src/supervisor/` | Process supervisor |
| `src/tarpit/` | Bot tar pit with Markov chain HTML generation to waste scraper/bot resources |
| `src/tcp/` | TCP proxy |
| `src/theme/` | Theme rendering |
| `src/tls/` | TLS termination |
| `src/tunnel/` | Tunnel management |
| `src/udp/` | UDP proxy |
| `src/upstream/` | Backend management |
| `src/upload/` | Upload handling |
| `src/utils/` | Utilities |
| `src/vpn_client/` | VPN client |
| `src/waf/` | WAF engine |
| `src/wasm_pow/` | WASM-based proof-of-work challenge solver with PQC key exchange |
| `src/worker/` | Worker process |
| `src/worker_pool/` | Worker pool management |
| `crates/synvoid-config/` | Configuration crate |
| `crates/synvoid-utils/` | Utilities crate |

---

## Errata & Known Corrections

The following corrections were made to address discrepancies between documentation and implementation:

| Item | Correction |
|------|------------|
| **Process Hierarchy** | SynVoid uses a three-tier hierarchy (Overseer → Master → Worker) for legacy deployments, with Supervisor consolidating Overseer + Master responsibilities for simpler deployments. See [Process Lifecycle](process_lifecycle.md) for details. |
| **gRPC Control Plane** | The gRPC API binds to localhost only — TLS is not required for local IPC between processes. See [Platform Deep Dive](platform_deep_dive.md). |
| **Spin Framework** | Spin support (`src/spin/`) requires manual app registration via Admin API. Routing integration and component mapping are not fully automated. |
| **File Path Corrections** | Several file path references in deep dive docs were corrected in AGENTS.md. Key corrections: `collect_body_with_chunk_waf` is in `src/http/server.rs:4661` (not `shared_handler.rs`), quorum verification is in `src/mesh/dht/signed.rs:860-934` (not `state_machine.rs:166-172`). |

---

## Feature Gates

| Feature | Purpose |
|---------|---------|
| `dns` | DNS server with DNSSEC |
| `mesh` | Mesh networking, DHT, Raft |
| `socket-handoff` | Socket transfer between processes |
| `wireguard` | WireGuard VPN |
| `icmp-filter` | ICMP filtering |
| `flood-ebpf` | eBPF flood protection |
| `post-quantum` | Post-quantum TLS |
| `pqc-mesh` | Post-quantum mesh signatures (ML-DSA-44) |
| `macos-sandbox` | macOS sandbox enforcement |
| `erased_pool` | Type-erased connection pool |
| `rkyv` | Rkyv serialization |

---

*This overview provides a bird's eye view of SynVoid's architecture. For detailed exploration of any subsystem, refer to the linked documents above.*