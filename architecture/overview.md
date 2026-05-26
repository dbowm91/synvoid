# SynVoid Architecture Overview

SynVoid is a high-performance, multi-tenant Web Application Firewall (WAF) and reverse proxy written in Rust, designed for **1M+ RPS** with **millions of tenants**. It uses a multi-process architecture with a unified async event loop for maximum efficiency.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Process Model](#process-model)
3. [Core Modules](#core-modules)
   - [HTTP Stack](#http-stack)
   - [Security & WAF](#security--waf)
   - [Proxy & Routing](#proxy--routing)
   - [Application Handlers](#application-handlers)
   - [DNS & Tunnel](#dns--tunnel)
   - [Mesh Networking](#mesh-networking)
   - [TLS & Cryptography](#tls--cryptography)
   - [Admin & Platform](#admin--platform)
   - [Utilities](#utilities)
4. [Request Flow](#request-flow)
5. [Deep Dive Index](#deep-dive-index)
6. [Feature Gates](#feature-gates)
7. [Key Architectural Patterns](#key-architectural-patterns)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Supervisor (Control Plane)                         │
│  Process management, gRPC API, Raft consensus, DHT routing, config loading  │
│  (Consolidated from legacy Overseer + Master hierarchy)                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                     ┌─────────────────┼─────────────────┐
                     ▼                 ▼                 ▼
          ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
          │ UnifiedServer    │ │   Static     │ │    Mesh Agent    │
          │ Worker (HTTP/    │ │   Worker     │ │    (optional     │
          │ HTTPS/HTTP3)     │ │   (CSS/JS    │ │    control       │
          │                  │ │   minify)    │ │    plane)        │
          └──────────────────┘ └──────────────┘ └──────────────────┘
```

**Key Design Decisions:**

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

SynVoid employs a hierarchical process model:

| Process | Flag | Purpose |
|---------|------|---------|
| **Supervisor** | (default) | Worker spawn/manage, IPC, gRPC control plane, zero-downtime upgrades |
| **UnifiedServerWorker** | `--unified-server-worker` | HTTP/HTTPS/HTTP3 + WAF + proxy |
| **StaticWorker** | `--static-worker` | CSS/JS minification, compression |
| **MeshAgent** | `--mesh-agent` | Distributed control plane coordination |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated) |

---

## Core Modules

### HTTP Stack

The HTTP stack handles all incoming client connections across multiple protocol versions.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **HTTP Server** | [`src/http/mod.rs`](networking_deep_dive.md) | HTTP/1.1 + HTTP/2 server, request parsing, routing | [Networking Deep Dive](networking_deep_dive.md) |
| **HTTP/3 Server** | [`src/http3/mod.rs`](networking_deep_dive.md) | HTTP/3 QUIC handling via quinn/h3 | [Networking Deep Dive](networking_deep_dive.md) |
| **HTTP Client** | [`src/http_client/mod.rs`](networking_deep_dive.md) | Upstream proxy, connection pooling, streaming | [Networking Deep Dive](networking_deep_dive.md) |
| **Listener** | [`src/listener/`](networking_deep_dive.md) | Socket binding, accepting, connection limiting | [Networking Deep Dive](networking_deep_dive.md) |
| **Protocol Detection** | [`src/protocol/`](networking_deep_dive.md) | Protocol detection (WebSocket, gRPC, DNS) | [Networking Deep Dive](networking_deep_dive.md) |
| **Server** | [`src/server/mod.rs`](worker_architecture.md) | Unified server orchestrating HTTP/HTTPS/HTTP3/TCP/UDP/DNS listeners | [Worker Architecture](worker_architecture.md) |

**HTTP Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `http/directory_viewer` | Directory listing for static file serving |
| `http/early_parse` | Pre-parse HTTP requests for early rejection |
| `http/file_manager` | Static file management and caching |
| `http/headers` | HTTP header manipulation and injection |
| `http/internal_handlers` | Built-in endpoints (health, metrics, etc.) |
| `http/response_builder` | HTTP response construction |
| `http/response_transform` | Compression and minification |
| `http/validation_helpers` | Request validation utilities |
| `http/webdav` | WebDAV support (MKCOL, PROPFIND, etc.) |

---

### Security & WAF

The WAF subsystem provides comprehensive attack detection, rate limiting, bot mitigation, and threat intelligence.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **WAF Core** | [`src/waf/mod.rs`](waf_deep_dive.md) | Core WAF engine, request filtering, decision engine | [WAF Deep Dive](waf_deep_dive.md) |
| **Attack Detection** | [`src/waf/attack_detection/`](waf_deep_dive.md) | SQLi, XSS, path traversal, RFI, SSRF, SSTI, cmd injection, XXE | [WAF Deep Dive](waf_deep_dive.md) |
| **Bot Detection** | [`src/waf/bot.rs`](waf_deep_dive.md) | JA3/JA4 fingerprinting, UA analysis, bot detection | [WAF Deep Dive](waf_deep_dive.md) |
| **Rate Limiting** | [`src/waf/ratelimit/`](waf_deep_dive.md) | IP/global rate limiting with sliding window | [WAF Deep Dive](waf_deep_dive.md) |
| **Threat Level** | [`src/waf/threat_level/`](waf_deep_dive.md) | Adaptive threat scoring with SQLite persistence | [WAF Deep Dive](waf_deep_dive.md) |
| **Challenge** | [`src/challenge/`](waf_deep_dive.md) | PoW, CSS, Mesh-PoW challenges | [WAF Deep Dive](waf_deep_dive.md) |
| **GeoIP** | [`src/geoip/`](waf_deep_dive.md) | MaxMind GeoIP lookup, country/ASN blocking | [WAF Deep Dive](waf_deep_dive.md) |
| **Tarpit** | [`src/tarpit/`](waf_deep_dive.md) | Markov chain bot trap for scrapers | [WAF Deep Dive](waf_deep_dive.md) |
| **Honeypot Port** | [`src/honeypot_port/`](waf_deep_dive.md) | Port honeypot with AI responders | [WAF Deep Dive](waf_deep_dive.md) |
| **Block Store** | [`src/block_store.rs`](waf_deep_dive.md) | Persistent 64-shard blocklist with LRU eviction | [WAF Deep Dive](waf_deep_dive.md) |

**WAF Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `waf/asn_tracker` | ASN-based scraping detection |
| `waf/endpoints` | Endpoint blocking and sensitive path tracking |
| `waf/flood` | TCP/UDP flood protection |
| `waf/ip_feed` | External IP feed integration |
| `waf/mitigation` | Threat mitigation actions |
| `waf/probe_tracker` | Honeypot probe tracking |
| `waf/request_sanitization` | Input sanitization |
| `waf/rule_feed` | External rule feed integration |
| `waf/threat_intel` | Threat intelligence integration |
| `waf/traffic_shaper` | Bandwidth limiting and quotas |
| `waf/violation_tracker` | Violation tracking and escalation |

---

### Proxy & Routing

The proxy subsystem handles request forwarding, load balancing, and caching.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **Router** | [`src/router.rs`](routing_deep_dive.md) | Domain-based routing, Host header matching, wildcards | [Routing Deep Dive](routing_deep_dive.md) |
| **Proxy Server** | [`src/proxy/mod.rs`](proxy_deep_dive.md) | Reverse proxy, upstream dispatch, retry logic | [Proxy Deep Dive](proxy_deep_dive.md) |
| **Proxy Cache** | [`src/proxy_cache/`](proxy_deep_dive.md) | LRU response caching with TTL, SWR, SIE | [Proxy Deep Dive](proxy_deep_dive.md) |
| **Upstream Pool** | [`src/upstream/`](routing_deep_dive.md) | Backend pools, load balancing, health checks | [Routing Deep Dive](routing_deep_dive.md) |

**Proxy Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `proxy/cache` | Cache key building and response caching |
| `proxy/client_registry` | Upstream client tracking |
| `proxy/dispatch` | Request dispatch to upstream |
| `proxy/executor` | Upstream request execution |
| `proxy/governor` | Rate limiting for upstream |
| `proxy/headers` | Header filtering and transformation |
| `proxy/retry` | Retry logic with backoff |
| `proxy/streaming` | Streaming response handling |

---

### Application Handlers

Application handlers process requests for various backend types.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **Static Files** | [`src/static_files/`](app_handlers.md) | File serving, caching, compression, minification | [App Handlers](app_handlers.md) |
| **PHP-FPM** | [`src/php/`](app_handlers.md) | PHP-FPM via FastCGI | [App Handlers](app_handlers.md) |
| **FastCGI** | [`src/fastcgi/`](app_handlers.md) | Generic FastCGI backend with connection pooling | [App Handlers](app_handlers.md) |
| **CGI** | [`src/cgi/`](app_handlers.md) | CGI script execution (Perl, Python, Ruby, etc.) | [App Handlers](app_handlers.md) |
| **Serverless** | [`src/serverless/`](plugin_deep_dive.md) | WASM runtime with instance pooling | [Plugin Deep Dive](plugin_deep_dive.md) |
| **Spin** | [`src/spin/`](plugin_deep_dive.md) | Fermyon Spin framework support | [Plugin Deep Dive](plugin_deep_dive.md) |
| **Plugin** | [`src/plugin/`](plugin_deep_dive.md) | Dynamic WASM/native plugin loading | [Plugin Deep Dive](plugin_deep_dive.md) |

---

### DNS & Tunnel

DNS and tunnel modules provide optional connectivity features.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **DNS Server** | [`src/dns/mod.rs`](dns_deep_dive.md) | Authoritative DNS with zone management | [DNS Deep Dive](dns_deep_dive.md) |
| **DNSSEC** | [`src/dns/dnssec*.rs`](dns_deep_dive.md) | Signing, validation, key management (NSEC/NSEC3) | [DNS Deep Dive](dns_deep_dive.md) |
| **Recursive DNS** | [`src/dns/recursive.rs`](dns_deep_dive.md) | Full recursive resolver with caching | [DNS Deep Dive](dns_deep_dive.md) |
| **DNS-over-TLS** | [`src/dns/dot.rs`](dns_deep_dive.md) | DoT server | [DNS Deep Dive](dns_deep_dive.md) |
| **DNS-over-HTTPS** | [`src/dns/doh.rs`](dns_deep_dive.md) | DoH server | [DNS Deep Dive](dns_deep_dive.md) |
| **DNS-over-QUIC** | [`src/dns/doq.rs`](dns_deep_dive.md) | DoQ server | [DNS Deep Dive](dns_deep_dive.md) |
| **Tunnel** | [`src/tunnel/`](dns_deep_dive.md) | QUIC tunnel, WireGuard VPN | [DNS Deep Dive](dns_deep_dive.md) |
| **VPN Client** | [`src/vpn_client/`](dns_deep_dive.md) | VPN client functionality | [DNS Deep Dive](dns_deep_dive.md) |

**DNS Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `dns/anycast` | Anycast support for DNS |
| `dns/cache` | Response caching |
| `dns/compression` | DNS message compression |
| `dns/cookie` | DNS Cookie (RFC 7873) |
| `dns/dns64` | DNS64 translation |
| `dns/firewall` | DNS firewall |
| `dns/hsm` | HSM support for key storage |
| `dns/mesh_sync` | Mesh DNS synchronization |
| `dns/messages` | DNS message parsing |
| `dns/rpz` | Response Policy Zones |
| `dns/transfer` | Zone transfers (AXFR/IXFR) |
| `dns/tsig` | Transaction signatures |
| `dns/update` | Dynamic updates |
| `dns/zone_file` | Zone file parsing |

---

### Mesh Networking

The mesh subsystem provides peer-to-peer connectivity, DHT-based service discovery, and distributed security.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **Mesh Core** | [`src/mesh/mod.rs`](mesh_deep_dive.md) | Mesh networking: DHT, Raft, QUIC transport | [Mesh Deep Dive](mesh_deep_dive.md) |
| **DHT** | [`src/mesh/dht/`](mesh_deep_dive.md) | Distributed hash table, Kademlia routing | [Mesh Deep Dive](mesh_deep_dive.md) |
| **Raft** | [`src/mesh/raft/`](mesh_deep_dive.md) | Consensus for global control plane | [Mesh Deep Dive](mesh_deep_dive.md) |
| **Transport** | [`src/mesh/transport.rs`](mesh_deep_dive.md) | QUIC-based encrypted transport | [Mesh Deep Dive](mesh_deep_dive.md) |
| **Mesh Proxy** | [`src/mesh/proxy.rs`](mesh_deep_dive.md) | HTTP proxy routing through mesh | [Mesh Deep Dive](mesh_deep_dive.md) |

**Mesh Submodules (53 total):**

| Submodule | Purpose |
|-----------|---------|
| `mesh/audit` | Security audit logging |
| `mesh/audit_session` | Session-based auditing |
| `mesh/behavioral` | Behavioral fingerprinting |
| `mesh/behavioral_intel` | Behavioral intelligence |
| `mesh/cert` | Certificate management |
| `mesh/cert_dist` | Certificate distribution |
| `mesh/client_audit` | Client audit reporting |
| `mesh/config` | Mesh configuration |
| `mesh/crypto_verification` | Cryptographic verification |
| `mesh/hierarchical_routing` | Bloom filter routing |
| `mesh/hybrid_signature` | Post-quantum signatures |
| `mesh/kem` | Key encapsulation (ML-KEM) |
| `mesh/ml_dsa` | ML-DSA signatures |
| `mesh/ml_kem_key_exchange` | ML-KEM key exchange |
| `mesh/network_security` | Network access control |
| `mesh/org_key_manager` | Organization key management |
| `mesh/organization` | Multi-tenant org management |
| `mesh/passover_key_exchange` | Key handover protocol |
| `mesh/peer_auth` | Peer authentication |
| `mesh/protocol` | Mesh message protocol |
| `mesh/reputation` | Peer reputation system |
| `mesh/security` | Security configuration |
| `mesh/security_challenge` | Security challenges |
| `mesh/session` | Session management |
| `mesh/threat_intel` | Threat intelligence |
| `mesh/tier_key_encryption` | Tier-based encryption |
| `mesh/topology` | Network topology |
| `mesh/transport_connection` | Connection management |
| `mesh/transport_core` | Transport core |
| `mesh/transport_dht` | DHT transport |
| `mesh/transport_dns` | DNS transport |
| `mesh/transport_global` | Global transport |
| `mesh/transport_org` | Organization transport |
| `mesh/transport_peer` | Peer-to-peer transport |
| `mesh/transport_rate_limit` | Rate limit transport |
| `mesh/transport_routing` | Routing transport |
| `mesh/transport_serverless` | Serverless transport |
| `mesh/transport_types` | Transport type definitions |
| `mesh/transports` | Transport implementations |
| `mesh/verification` | Identity verification |
| `mesh/wasm_dist` | WASM distribution |
| `mesh/yara_rules` | YARA rule management |

---

### TLS & Cryptography

TLS and cryptographic modules handle encryption and certificate management.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **TLS** | [`src/tls/`](layer_3_5_deep_dive.md) | TLS termination, ACME/Let's Encrypt, SNI peeking | [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) |
| **WASM PoW** | [`src/wasm_pow/`](layer_3_5_deep_dive.md) | Browser WASM proof-of-work with PQC key exchange | [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) |

**TLS Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `tls/acme` | ACME protocol implementation |
| `tls/acme_dns` | DNS-01 ACME challenge |
| `tls/cert_resolver` | Certificate resolution |
| `tls/config` | TLS configuration |
| `tls/server` | TLS server implementation |
| `tls/sni_peek` | SNI-based routing |

---

### Admin & Platform

Admin and platform modules provide management, monitoring, and system integration.

| Module | File | Purpose | Deep Dive |
|--------|------|---------|-----------|
| **Admin API** | [`src/admin/`](admin_deep_dive.md) | Axum-based HTTP/HTTPS management interface | [Admin Deep Dive](admin_deep_dive.md) |
| **Auth** | [`src/auth/`](admin_deep_dive.md) | Session management, bcrypt password hashing | [Admin Deep Dive](admin_deep_dive.md) |
| **Platform** | [`src/platform/`](platform_deep_dive.md) | Cross-platform abstractions (Linux, macOS, BSD, Windows) | [Platform Deep Dive](platform_deep_dive.md) |
| **Process** | [`src/process/`](platform_deep_dive.md) | IPC primitives, worker lifecycle, message framing | [Platform Deep Dive](platform_deep_dive.md) |
| **Supervisor** | [`src/supervisor/`](platform_deep_dive.md) | Process supervision, health monitoring | [Platform Deep Dive](platform_deep_dive.md) |
| **Config** | [`crates/synvoid-config/`](config_deep_dive.md) | Strongly-typed configuration, TOML loading | [Config Deep Dive](config_deep_dive.md) |
| **Utils** | [`crates/synvoid-utils/`](config_deep_dive.md) | Buffer pooling, serialization | [Config Deep Dive](config_deep_dive.md) |

**Admin Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `admin/alerting` | Alert management |
| `admin/audit` | Audit logging |
| `admin/auth` | Authentication |
| `admin/handlers` | API handlers |
| `admin/metrics` | Metrics collection |
| `admin/metrics_events` | Metrics events |
| `admin/middleware` | Admin middleware |
| `admin/openapi` | OpenAPI spec |
| `admin/prometheus_exporter` | Prometheus exporter |
| `admin/rate_limit` | Admin rate limiting |
| `admin/schema` | JSON schema |
| `admin/state` | Admin state |
| `admin/ws` | WebSocket broadcasting |

**Platform Submodules:**

| Submodule | Purpose |
|-----------|---------|
| `platform/service` | Service management |
| `platform/sandbox` | OS sandboxing |

---

### Utilities

Utility modules provide cross-cutting functionality.

| Module | File | Purpose |
|--------|------|---------|
| **Buffer** | [`src/buffer.rs`](config_deep_dive.md) | Buffer pool integration |
| **Serialization** | [`src/serialization_rkyv.rs`](config_deep_dive.md) | Rkyv zero-copy serialization |
| **Utils** | [`src/utils.rs`](config_deep_dive.md) | Misc utilities (time, parsing, hashing, regex) |
| **Integrity** | [`src/integrity/`](config_deep_dive.md) | Merkle tree, content integrity |
| **Metrics** | [`src/metrics/`](admin_deep_dive.md) | Prometheus metrics, bandwidth tracking |
| **Logging** | [`src/logging/`](admin_deep_dive.md) | Dynamic log levels, access logging |
| **Worker Pool** | [`src/worker_pool/`](worker_architecture.md) | Worker pool management |
| **Upload** | [`src/upload/`](app_handlers.md) | File upload handling |
| **Captcha** | [`src/captcha/`](waf_deep_dive.md) | CAPTCHA integration |
| **Theme** | [`src/theme/`](waf_deep_dive.md) | Challenge page theming |
| **Mime** | [`src/mime/`](app_handlers.md) | MIME type detection |

---

## Request Flow

```
Client Request
       │
       ▼
┌─────────────────┐
│  HTTP Server    │ ← HTTP/1.1, HTTP/2, HTTP/3 (QUIC)
│  (src/http/)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Protocol       │ ← WebSocket, gRPC detection
│  Detection      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────┐
│  WAF Core       │────▶│ Rate Limit  │ ← Token bucket, sliding window
│  (src/waf/)     │     └─────────────┘
└────────┬────────┘     ┌─────────────┐
         │              │ Bot Detect   │ ← JA3/JA4, UA analysis
         │              └─────────────┘
         │              ┌─────────────┐
         │              │ Attack      │ ← SQLi, XSS, SSRF, etc.
         │              │ Detection   │ ← YARA rules, libinjection
         │              └─────────────┘
         │              ┌─────────────┐
         │              │ Challenge   │ ← PoW, CSS, Mesh-PoW
         │              └─────────────┘
         │
         ▼
┌─────────────────┐
│  Router         │ ← Domain/Host matching
│  (src/router.rs)│   (exact, wildcard, suffix)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Backend Type   │
│  Selection      │
└────────┬────────┘
         │
    ┌────┴────┬────────┬────────┬────────┬────────┐
    ▼         ▼        ▼        ▼        ▼        ▼
 Upstream  FastCGI   Static   Serverless  Spin    Plugin
    │         │        │         │         │        │
    ▼         ▼        ▼        ▼         ▼        ▼
 HTTP      FastCGI  File    WASM      Spin     WASM
 Client   Client   System  Runtime   Runtime  Plugin
                               │
            ┌──────────────────┼──────────────┐
            ▼              ▼              ▼
       Upstream       Upstream        Upstream
       Pool           Pool            Pool
```

---

## Deep Dive Index

Each module has a dedicated deep dive document for detailed exploration:

| Category | Document | Coverage |
|----------|----------|----------|
| **Process Model** | [Process Lifecycle](process_lifecycle.md) | Overseer, Supervisor, Worker hierarchy, drain coordination |
| **Worker Architecture** | [Worker Architecture](worker_architecture.md) | Unified server, listener pools, request flow |
| **HTTP Stack** | [Networking Deep Dive](networking_deep_dive.md) | HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, connection handling |
| **Request Routing** | [Routing Deep Dive](routing_deep_dive.md) | Router, upstream pools, load balancing, health monitoring |
| **Proxy & Upstream** | [Proxy Deep Dive](proxy_deep_dive.md) | Proxy server, connection pooling, retry logic, cache governor |
| **Security/WAF** | [WAF Deep Dive](waf_deep_dive.md) | WAF pipeline, attack detection, bot mitigation, challenges |
| **Admin & Auth** | [Admin Deep Dive](admin_deep_dive.md) | Admin API, session management, CSRF, rate limiting |
| **Application Handlers** | [App Handlers](app_handlers.md) | Static files, PHP-FPM, FastCGI, CGI, WASM, Spin |
| **Plugin & Serverless** | [Plugin Deep Dive](plugin_deep_dive.md) | WASM plugin runtime, Spin, serverless instance pooling |
| **Mesh Networking** | [Mesh Deep Dive](mesh_deep_dive.md) | DHT, Raft consensus, QUIC transport, threat intelligence |
| **DNS & Tunnel** | [DNS Deep Dive](dns_deep_dive.md) | DNS server, DNSSEC, TSIG, tunnel protocols, VPN client |
| **Platform & Process** | [Platform Deep Dive](platform_deep_dive.md) | IPC, sandboxing, platform abstraction, supervisor |
| **Configuration** | [Config Deep Dive](config_deep_dive.md) | Configuration hierarchy, buffer pool, serialization |
| **Post-Quantum & Trust** | [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) | PQC key exchange, ML-DSA/ML-KEM, trust models |

---

## Module Index by Source Path

### Core HTTP & Proxy

| Path | Purpose |
|------|---------|
| `src/http/` | HTTP/1.1 + HTTP/2 server |
| `src/http3/` | HTTP/3 QUIC server via quinn/h3 |
| `src/http_client/` | Upstream proxy client with connection pooling |
| `src/listener/` | Socket configuration, connection context |
| `src/protocol/` | Protocol detection (WebSocket, gRPC) |
| `src/router.rs` | Domain-based routing to backends |
| `src/proxy/` | Reverse proxy, header filtering, retries |
| `src/proxy_cache/` | LRU response caching |
| `src/upstream/` | Backend pools, load balancing, health checks |

### Security & WAF

| Path | Purpose |
|------|---------|
| `src/waf/` | Web Application Firewall engine |
| `src/block_store.rs` | Persistent 64-shard IP blocklist with LRU eviction |
| `src/challenge/` | PoW, CSS, Mesh-PoW anti-bot challenges |
| `src/geoip/` | MaxMind GeoIP lookup, country/ASN blocking |
| `src/tarpit/` | Markov chain bot trap for scrapers |
| `src/honeypot_port/` | Port honeypot with AI responders |
| `src/filter/` | Protocol filtering framework for TCP/UDP |
| `src/tcp/` | TCP proxy with protocol detection |
| `src/udp/` | UDP proxy with flood protection |
| `src/icmp_filter/` | ICMP filtering via nftables/pf/winfw/ebpf |

### Application Handlers

| Path | Purpose |
|------|---------|
| `src/static_files/` | Static file serving with caching/compression |
| `src/php/` | PHP-FPM integration via FastCGI |
| `src/fastcgi/` | FastCGI protocol client with connection pooling |
| `src/cgi/` | CGI script execution (Perl, Python, Ruby, Shell, Lua) |
| `src/serverless/` | WASM serverless with instance pooling |
| `src/spin/` | Fermyon Spin framework support |
| `src/plugin/` | WASM plugin runtime with instance pooling |

### DNS & Tunnel

| Path | Purpose |
|------|---------|
| `src/dns/` | Authoritative DNS server, DNSSEC, recursive resolver |
| `src/tunnel/` | QUIC tunnel, WireGuard VPN |
| `src/vpn_client/` | VPN client for tunnel connections |

### Mesh Networking

| Path | Purpose |
|------|---------|
| `src/mesh/` | Mesh networking: DHT, Raft, QUIC transport |
| `src/mesh/dht/` | Distributed hash table, Kademlia routing |
| `src/mesh/raft/` | Raft consensus for global control plane |
| `src/mesh/transport.rs` | QUIC-based encrypted transport |
| `src/mesh/proxy.rs` | HTTP proxy routing through mesh |

### TLS & Cryptography

| Path | Purpose |
|------|---------|
| `src/tls/` | TLS termination, ACME, SNI peeking |
| `src/wasm_pow/` | Browser-side WASM proof-of-work |

### Admin & Platform

| Path | Purpose |
|------|---------|
| `src/admin/` | Admin API, WebSocket broadcasting, audit logging |
| `src/auth/` | User auth, sessions, bcrypt, brute-force protection |
| `src/platform/` | Cross-platform abstractions, sandboxing |
| `src/process/` | IPC primitives, worker lifecycle management |
| `src/supervisor/` | Process supervisor, gRPC control plane |
| `src/overseer/` | Legacy overseer (health monitoring, upgrades) |
| `src/master/` | Legacy master process (IPC with workers) |
| `src/metrics/` | Prometheus metrics, bandwidth tracking |
| `src/logging/` | Dynamic log levels, access logging |

### Utilities

| Path | Purpose |
|------|---------|
| `crates/synvoid-config/` | Strongly-typed configuration structs |
| `crates/synvoid-utils/` | Buffer pool, serialization utilities |
| `src/utils.rs` | Misc utilities (time, parsing, hashing, regex) |
| `src/serialization_rkyv.rs` | Rkyv zero-copy serialization |
| `src/buffer.rs` | Buffer pool integration |
| `src/integrity/` | Merkle tree, content integrity verification |

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
| `audit` | Audit logging |

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

## BackendType Enum

The router supports 11 backend types (defined in `src/router.rs:66-77`):

```rust
pub enum BackendType {
    Upstream,      // HTTP/HTTPS upstream
    FastCgi,       // FastCGI backend
    Php,           // PHP-FPM
    Cgi,           // CGI script
    AxumDynamic,   // Dynamic Axum handler
    AppServer,     // Application server
    Static,        // Static file serving
    QuicTunnel,    // QUIC tunnel endpoint
    Serverless,    // WASM serverless function
    Mesh,          // Mesh-based backend
    Spin,          // Fermyon Spin app
}
```

---

## Load Balancing Algorithms

Upstream pool supports multiple algorithms (in `src/upstream/pool.rs`):

| Algorithm | Description |
|-----------|-------------|
| **RoundRobin** | Default, cycles through backends |
| **Random** | Random selection |
| **LeastConnections** | Backend with lowest composite load |
| **PeakEwma** | Cost-based: `(connections + 1) * (latency + 1)` |
| **WeightedRoundRobin** | Weight-based rotation |
| **IpHash** | Consistent hashing by client IP |

---

## Platform Sandboxing

| OS | Backend | Level |
|----|---------|-------|
| Linux 5.13+ | Landlock | Basic/Strict |
| FreeBSD | Capsicum | Basic/Strict |
| OpenBSD | Pledge | Basic/Strict |
| macOS | Seatbelt (feature-gated) | Basic/Strict |
| Windows | Job Objects + DEP/ASLR | Basic/Strict |

---

*This overview provides a bird's eye view of SynVoid's architecture. For detailed exploration of any subsystem, refer to the linked deep dive documents.*