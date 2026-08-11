# SynVoid Architecture Overview

SynVoid is a high-performance, multi-process Web Application Firewall (WAF) and reverse proxy written in Rust. It provides Layer 7 request filtering, attack detection, load balancing, TLS termination, and optional mesh networking — designed for 1M+ RPS with millions of tenants.

**Key Capabilities:**
- Layer 7 WAF with 14 attack detectors, bot protection, rate limiting, anomaly scoring
- Reverse proxy with 6 load balancing algorithms and circuit breaker
- TLS termination with ACME (Let's Encrypt) and post-quantum hybrid key exchange
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC) support
- WASM plugin/serverless runtime (wasmtime-based) with trust tiers and capabilities
- Mesh networking with DHT, Raft consensus, and post-quantum cryptography
- DNS server with DNSSEC signing, recursive resolution, DoT/DoH/DoQ
- Multi-platform OS abstraction (Linux, macOS, FreeBSD, Windows)

---

## Project Structure

```
synvoid/
├── src/                    # Root crate (binary + library, ~60 modules)
├── crates/                 # 37 dedicated synvoid-* library crates
├── pqc/                    # Post-quantum cryptography (ML-KEM, ML-DSA)
├── admin-ui/               # Yew-based WASM admin frontend
├── tools/                  # xtask runner + repo-guards
├── fuzz/                   # 17 fuzz targets
├── examples/               # 2 example apps (dynamic-plugin, embedded-app)
├── architecture/           # Architecture documentation (100+ docs)
├── .opencode/skills/       # 30 subsystem skill docs
├── docs/                   # User guides, ADRs
├── plans/                  # Implementation tracking
├── proto/                  # Protobuf definitions
├── config/                 # Default configuration files
├── rules/                  # WAF rules
├── scripts/                # CI/build scripts
└── Cargo.toml              # Workspace manifest (45 members)
```

**Workspace**: 45 members total — 37 `synvoid-*` library crates, root crate, `pqc`, `admin-ui`, 2 examples, `fuzz`, `synvoid-repo-guards`, and `xtask`.

---

## Process Architecture

SynVoid uses a two-tier architecture: a Supervisor-owned control plane and a data plane built around one UnifiedServerWorker plus bounded CPU offload workers.

```
┌─────────────────────────────────────────────────────┐
│                   Supervisor Process                 │
│  • Zero-downtime upgrades (drain protocol)          │
│  • Worker lifecycle management                      │
│  • gRPC control plane API                           │
│  • Mesh agent mode                                  │
│  • IPC orchestrator                                 │
└──────────┬──────────────────────────────────────────┘
           │ IPC (Unix domain socket, signed messages)
           ▼
┌──────────────────────────────┐
│    UnifiedServerWorker       │
│  • HTTP/HTTPS/HTTP3          │
│  • WAF pipeline              │
│  • Routing and proxy path    │
│  • Cheap request-path work   │
└──────────┬───────────────────┘
           │ bounded IPC task offload
           ▼
┌──────────────────────────────┐
│    CPU Offload Workers       │
│  • minify/compress           │
│  • image transforms          │
│  • YARA scanning             │
│  • WASM execution            │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│         Upstream Apps        │
│  • Static Files              │
│  • PHP-FPM / FastCGI         │
│  • Granian (ASGI)            │
│  • WASM Serverless           │
│  • Mesh Backend              │
└──────────────────────────────┘
```

| Process | Flag | Purpose | Default |
|---------|------|---------|---------|
| **Supervisor** | (default) | Control plane, lifecycle, gRPC API | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | Latency-sensitive HTTP/HTTPS/HTTP3 + WAF + proxy | 1 |
| **CPU Offload Worker** | `--cpu-worker` | Bounded heavy transforms | 1 |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated) | — |

---

## Request Flow

```
Client ──► TLS Termination ──► HTTP Server ──► WAF Pipeline ──► Proxy Dispatch ──► Upstream Pool ──► Backend
                                    │               │              │
                                    │          ┌────▼────┐    ┌────▼─────┐
                                    │          │ Attack  │    │ WASM     │
                                    │          │ Detection│    │ Filters  │
                                    │          │ Bot Det. │    │(serverless│
                                    │          │ Rate Lim│    │ /plugin) │
                                    │          └─────────┘    └──────────┘
                                    │
                              ┌─────▼──────┐
                              │ Static File │
                              │ FastCGI/PHP │
                              │ CGI         │
                              │ Spin/WASM   │
                              └─────────────┘
```

### HTTP Pipeline (7 Stages)

The HTTP request pipeline in `synvoid-http` processes every request through 7 stages:

1. **Metadata Normalization** (`request_frontdoor.rs`) — Client IP sanitization, internal endpoint dispatch, mesh special paths
2. **Route Resolution** (`request_preparation.rs`) — Domain/path matching, early WAF decision, trust cookie bypass
3. **Body Policy** (`body_policy.rs`) — Body collection, chunked WAF scanning for large bodies (256KB-1MB threshold)
4. **WAF Evaluation** (`waf_decision.rs`) — Full attack detection, anomaly scoring, bot detection, challenge/tarpit decisions
5. **Terminal Response** (`internal_endpoint_dispatch.rs`) — Health/ready/drain endpoints, mesh key exchange
6. **Backend Dispatch** (`backend_dispatch.rs`) — 12 backend types: WebSocket, Static, FastCGI/PHP, CGI, AppServer, Serverless, Spin, WASM filter, Upload, Mesh, Upstream proxy
7. **Accounting** (`http_request_postlude.rs`) — Metrics, IPC request logging, bandwidth tracking

---

## Feature Gates

| Feature | Purpose | Default |
|---------|---------|---------|
| `dns` | DNS server with DNSSEC, DoT/DoH/DoQ | Yes |
| `mesh` | Mesh networking, DHT, Raft consensus | Yes |
| `socket-handoff` | Socket transfer between processes | Yes |
| `erased_pool` | Type-erased HTTP client pool | Yes |
| `swagger-ui` | OpenAPI documentation UI | Yes |
| `post-quantum` | Post-quantum TLS key exchange (ML-KEM) | No |
| `wireguard` | WireGuard VPN tunnel support | No |
| `icmp-filter` | ICMP flood filtering | No |
| `flood-ebpf` | eBPF-based flood protection (Linux) | No |
| `macos-sandbox` | macOS sandbox enforcement | No |
| `pqc-mesh` | Post-quantum mesh signatures (ML-DSA-44) | No |
| `fastcgi_streaming` | Streaming FastCGI response handling | No |

**Compilation Profiles:**
- **Core** (`--no-default-features`): Minimal
- **Mesh** (`--no-default-features --features mesh`): Mesh networking
- **DNS** (`--no-default-features --features dns`): DNS server
- **Full** (`--no-default-features --features mesh,dns`): All features

---

## Module Index

Each component below links to its deep-dive document for detailed review of implementation internals, state machines, and integration points.

### Layer 1: Core Infrastructure

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **Configuration** | `synvoid-config` | Strongly-typed config structs, TOML parsing, validation, encryption, runtime reload | [`config_deep_dive.md`](./config_deep_dive.md) |
| **Platform** | `synvoid-platform` | OS detection, filesystem utils, socket bind, process sandboxing, service management | [`platform_deep_dive.md`](./platform_deep_dive.md) |
| **IPC & Process** | `synvoid-ipc` | Unix socket transport, FD passing, signed messages, process spawning | [`ipc_deep_dive.md`](./ipc_deep_dive.md) |
| **Supervisor** | `src/supervisor/` | Process supervision, drain protocol, gRPC API, worker lifecycle | [`supervisor_deep_dive.md`](./supervisor_deep_dive.md) |
| **Worker** | `src/worker/` | UnifiedServerWorker + CPU offload, Tokio runtime, task registry | [`worker_deep_dive.md`](./worker_deep_dive.md) |
| **CLI** | `synvoid-cli` | Clap-based argument parsing, feature flag dispatch | — |
| **Core Types** | `synvoid-core` | Dependency-light shared types: admin mutation, verdicts, request context | — |
| **Utils** | `synvoid-utils` | Buffer pool, ArcStr, drain/running flags, IP utils, serialization | — |
| **Drain** | `src/drain/` | Connection drain state for graceful shutdown | — |

### Layer 2: Security & WAF

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **WAF Engine** | `synvoid-waf` | 14 attack detectors (SQLi, XSS, path traversal), normalization, bot detection, anomaly scoring | [`waf_deep_dive.md`](./waf_deep_dive.md) |
| **Auth** | `src/auth/` | User authentication, sessions, bcrypt, brute-force protection, CSRF | [`auth_deep_dive.md`](./auth_deep_dive.md) |
| **Challenge** | `synvoid-challenge` | Browser verification: PoW, CSS challenges, honeypot, adaptive difficulty | [`challenge_deep_dive.md`](./challenge_deep_dive.md) |
| **Block Store** | `synvoid-block-store` | Persistent IP/mesh-ID blocklist, LRU eviction, mesh propagation | [`block_store_deep_dive.md`](./block_store_deep_dive.md) |
| **Tarpit** | `synvoid-tarpit` | Anti-scraping tarpit: Markov chain HTML, session budgets, admission control | [`tarpit_deep_dive.md`](./tarpit_deep_dive.md) |
| **Honeypot** | `synvoid-honeypot` | Port/URL honeypots, AI responders, protocol fingerprinting, threat intel | [`honeypot_deep_dive.md`](./honeypot_deep_dive.md) |
| **Upload** | `synvoid-upload` | File upload validation, YARA scanning, sandbox quarantine | [`upload_deep_dive.md`](./upload_deep_dive.md) |
| **GeoIP** | `synvoid-geoip` | MaxMind GeoIP lookup, country/ASN blocking, auto-update | [`geoip_deep_dive.md`](./geoip_deep_dive.md) |
| **ICMP Filter** | `synvoid-icmp-filter` | ICMP flood filtering (nftables, eBPF, pf, WFP) | — |
| **Integrity** | `synvoid-integrity` | Signed HTTP integrity verification (Ed25519, X25519 key exchange) | [`integrity_deep_dive.md`](./integrity_deep_dive.md) |

### Layer 3: Networking & Proxy

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **HTTP Server** | `synvoid-http` | HTTP/1.1 + HTTP/2, 7-stage request pipeline, WebSocket, compression | [`http_deep_dive.md`](./http_deep_dive.md) |
| **HTTP/3** | `synvoid-http3` | HTTP/3 QUIC server, WAF boundary | [`http3_deep_dive.md`](./http3_deep_dive.md) |
| **HTTP Client** | `synvoid-http-client` | Upstream HTTP client, connection pooling, erased body, PQ TLS | [`http_client_deep_dive.md`](./http_client_deep_dive.md) |
| **Proxy** | `synvoid-proxy` | Reverse proxy, load balancing, retry/backoff, header manipulation | [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| **Upstream** | `synvoid-upstream` | Backend pools, health checking, QUIC tunnel support, load balancing | [`upstream_deep_dive.md`](./upstream_deep_dive.md) |
| **TLS** | `synvoid-tls` | TLS termination, ACME, SNI peeking, JA4 fingerprinting, cert resolution | [`tls_deep_dive.md`](./tls_deep_dive.md) |
| **Router** | `src/router.rs` | Request routing, domain/path matching, radix tree | [`routing_deep_dive.md`](./routing_deep_dive.md) |
| **Location Matcher** | `src/location_matcher.rs` | Nginx-style location matching (`=`, `^~`, `~`, `~*`, prefix) | [`location_matcher.md`](./location_matcher.md) |
| **Listener** | `src/listener/` | Network listener configuration primitives | — |
| **Tunnel** | `synvoid-tunnel` | VPN tunnels (QUIC, WireGuard), TUN interfaces, tunnel routing | [`tunnel_deep_dive.md`](./tunnel_deep_dive.md) |
| **VPN Client** | `synvoid-vpn-client` | VPN client connectivity, port mapping, reconnection | [`vpn_client_deep_dive.md`](./vpn_client_deep_dive.md) |
| **Streaming** | `src/streaming/` | Bidirectional proxy streaming with WAF scanning | [`streaming.md`](./streaming.md) |
| **Proxy Cache** | `synvoid-proxy-cache` | HTTP response caching, LRU eviction, TTL, Cache-Control parsing | [`proxy_cache.md`](./proxy_cache.md) |
| **Filter** | `synvoid-filter` | Generic protocol filter framework (allowlist/denylist) | — |

### Layer 4: Application Handlers

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **App Handlers** | `synvoid-app-handlers` | CGI, FastCGI, PHP dispatch, MIME detection | — |
| **Static Files** | `synvoid-static-files` | Static serving, gzip/brotli compression, CSS/JS/HTML minification | [`static_files.md`](./static_files.md) |
| **FastCGI** | (via `synvoid-app-handlers`) | FastCGI client, connection pool, streaming | [`fastcgi.md`](./fastcgi.md) |
| **CGI** | (via `synvoid-app-handlers`) | Classic CGI script execution | [`cgi.md`](./cgi.md) |
| **MIME** | `src/mime/` | MIME type registry, content detection | — |
| **Theme** | `synvoid-theme` | CSS theming for challenge/error pages, dark/light mode | [`theme.md`](./theme.md) |
| **App Server** | `synvoid-app-server` | Granian application server management, supervisor lifecycle | — |

### Layer 5: WASM & Plugin Runtime

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **Plugin/WASM** | `synvoid-plugin-runtime` | WASM plugin sandbox: trust tiers, capabilities, ABI, hot-reload | [`plugin_deep_dive.md`](./plugin_deep_dive.md) |
| **Serverless** | `synvoid-serverless` | WASM serverless functions: registry, routing, instance pooling | [`serverless_deep_dive.md`](./serverless_deep_dive.md) |
| **Spin** | `src/spin/` | Spin Framework WASM runtime integration | [`spin.md`](./spin.md) |
| **WASM PoW** | `synvoid-wasm-pow` | WASM proof-of-work solver for browser challenges | — |
| **Native Extensions** | (via `synvoid-plugin-runtime`) | Unsafe native library loading with path allowlist | [`unsafe_native_extensions.md`](./unsafe_native_extensions.md) |

### Layer 6: Distributed Systems

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **Mesh** | `synvoid-mesh` | P2P networking, DHT, Raft consensus, transport, peer auth | [`mesh_deep_dive.md`](./mesh_deep_dive.md) |
| **DNS** | `synvoid-dns` | Authoritative/recursive DNS, DNSSEC, DoT/DoH/DoQ, TSIG | [`dns_deep_dive.md`](./dns_deep_dive.md) |
| **DNS Operations** | (via `synvoid-dns`) | Zone lifecycle, health checks, production diagnostics | [`dns_zone_lifecycle.md`](./dns_zone_lifecycle.md) |
| **PQC** | `pqc` | Post-quantum crypto: ML-KEM-768/1024, ML-DSA-44 | — |
| **Threat Intel** | (mesh + block-store) | Federated threat intel, mesh propagation, enforcement rules | [`threat_intel_consumer_actionability.md`](./threat_intel_consumer_actionability.md) |

### Layer 7: Observability & Admin

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **Admin API** | `synvoid-admin` | REST API, token auth, metrics, alerting, Swagger UI | [`admin_deep_dive.md`](./admin_deep_dive.md) |
| **Admin UI** | `admin-ui` | Yew-based WASM admin dashboard frontend | — |
| **Metrics** | `synvoid-metrics` | Atomic counters, per-site metrics, bandwidth tracking | [`metrics.md`](./metrics.md) |
| **Logging** | `src/common/` | Syslog integration, dynamic log levels | [`log_controller.md`](./log_controller.md) |
| **Protocol Detection** | `src/protocol/` | Protocol detection framework (HTTP, WebSocket, gRPC) | — |

### Cross-Cutting Concerns

| Component | Crate(s) | Purpose | Deep Dive |
|-----------|----------|---------|-----------|
| **Buffer Pool** | `synvoid-utils` | Sharded mutex buffer pool (4 tiers), ABA-safe | — |
| **Serialization** | `synvoid-utils` | Postcard/rkyv strategy, typed structs | [`serder.md`](./serder.md) |
| **Root Module Ledger** | — | Module ownership classification (84 modules) | [`root_module_ledger.md`](./root_module_ledger.md) |
| **Composition Boundary** | — | Request-path vs composition root rules | [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) |
| **Request Path Boundary** | — | Trait-based capability boundary enforcement | [`request_path_capability_boundary.md`](./request_path_capability_boundary.md) |
| **Testkit** | `synvoid-testkit` | Shared test utilities (TCP/UDP fixtures, temp certs) | — |
| **Repo Guards** | `tools/synvoid-repo-guards` | Static architecture guard tests, CI policy | — |
| **xtask** | `tools/xtask` | Test orchestration runner (`cargo xtask test`) | — |

---

## Key Integration Patterns

### IPC Message Categories (60+ types)

| Category | Examples | Direction |
|----------|----------|-----------|
| Worker Lifecycle | Spawn, Ready, Shutdown, Drain | Supervisor → Worker |
| Configuration | ConfigReload, SiteUpdate | Supervisor → Worker |
| Health | HealthCheck, Heartbeat | Bidirectional |
| Metrics | MetricsReport, BandwidthReport | Worker → Supervisor |
| Socket | SocketHandoff, SocketRelease | Supervisor → Worker |
| Security | ThreatUpdate, BlockNotify | Supervisor → Worker |
| WASM | PluginLoad, PluginUnload | Supervisor → Worker |
| Blocklist | BlocklistRequest, BlocklistUpdate, BlocklistEventUpdate | Bidirectional |

### WAF Decision Variants

| Decision | Behavior | Response |
|----------|----------|----------|
| `Pass` | Allow request | Forward to backend |
| `Drop` | Blackhole (silent drop) | 404 Not Found |
| `Stall` | Concurrency-capped delay | 408 Timeout |
| `Block` | Active block | Themed error page |
| `Challenge` | Browser verification | HTML challenge page |
| `ChallengeWithCookie` | Challenge + session cookie | HTML + Set-Cookie |
| `Tarpit` | Slow-response trap | Streamed infinite HTML |

### Security Patterns

| Pattern | Implementation | Location |
|---------|---------------|----------|
| Constant-time comparison | `subtle::ConstantTimeEq` | All secrets, MACs, tokens |
| CSRF protection | `ct_eq()` validation | `src/admin/state.rs` |
| Brute-force protection | Account locking after N failures | `src/auth/mod.rs` |
| Path traversal prevention | Canonicalize + prefix check | `synvoid-static-files`, `synvoid-upload` |
| ReDoS prevention | Regex complexity checking | `src/location_matcher.rs` |
| Sandboxing | Per-platform backends (Landlock, Seatbelt, Capsicum) | `synvoid-platform` |
| WAF normalization | Overlong UTF-8 detection, homoglyph mapping, NFKC | `synvoid-waf::normalizer` |
| IPC signing | Ed25519 signed messages | `synvoid-ipc` |

### Serialization Strategy

| Path | Format | Reason |
|------|--------|--------|
| DHT/Mesh/Persistence | Postcard | Compact, deterministic, cross-language |
| IPC Messages | Postcard | Performance, type safety |
| High-perf paths | Rkyv | Zero-copy deserialization |
| Admin API | JSON | Human-readable, OpenAPI compatible |
| DNS wire format | hickory-proto | RFC-compliant DNS encoding |

---

## Key Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/worker/unified_server/mod.rs` | ~1305 | Primary composition root |
| `crates/synvoid-http/src/` | ~58 modules | HTTP pipeline (largest crate) |
| `crates/synvoid-mesh/src/mesh/` | ~72400 | Mesh networking (DHT, transport, Raft) |
| `crates/synvoid-dns/src/` | ~1174+ | DNS server with DNSSEC |
| `crates/synvoid-plugin-runtime/src/` | ~935 | WASM plugin sandbox |
| `src/commands/plan.rs` | ~942 | Command planning/dispatch |
| `src/supervisor/` | ~875 | Process supervision |
| `crates/synvoid-config/src/lib.rs` | ~447 | Configuration types |
| `crates/synvoid-waf/src/` | ~702 | WAF engine |
| `crates/synvoid-proxy/src/` | ~600 | Reverse proxy |

---

## Documentation Index

### Architecture Docs (`architecture/`)

| File | Description |
|------|-------------|
| [`overview.md`](./overview.md) | This file — bird's eye view and component index |
| [`root_module_ledger.md`](./root_module_ledger.md) | Root module ownership classification (84 modules) |
| [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) | Composition boundary rules |
| [`http_request_pipeline.md`](./http_request_pipeline.md) | 7-stage HTTP pipeline |
| [`mesh_trust_domains.md`](./mesh_trust_domains.md) | 7 trust domains, CanonicalTrustReader |
| [`release_profile_matrix.md`](./release_profile_matrix.md) | Compilation profiles, feature gates |
| [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md) | 17 fuzz targets, failure-injection seams |
| [`dns_config_runtime_matrix.md`](./dns_config_runtime_matrix.md) | DNS config field inventory |
| [`plugin_runtime_sandbox.md`](./plugin_runtime_sandbox.md) | Plugin trust tiers, sandbox model |
| [`block_store.md`](./block_store.md) | BlockStore architecture, persistence |
| [`deep_dive_review.md`](./deep_dive_review.md) | Layered architectural review |

### External Documentation

| Path | Description |
|------|-------------|
| [`AGENTS.md`](../AGENTS.md) | Developer guide for AI agents |
| [`.opencode/skills/`](../.opencode/skills/) | Detailed subsystem patterns (30 skills) |
| [`docs/adr/`](../docs/adr/) | Architecture decision records |
| [`SECURITY.md`](../SECURITY.md) | Security policy |
| [`docs/releasing.md`](../docs/releasing.md) | Manual publication procedure |
