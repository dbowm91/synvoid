# SynVoid Architecture Overview

## 1. Project Summary

SynVoid is a high-performance, multi-process Web Application Firewall (WAF) and reverse proxy written in Rust. The default deployment model is one latency-sensitive UnifiedServerWorker plus bounded CPU offload workers, coordinated by a Supervisor-owned control plane. It provides comprehensive request filtering, attack detection, load balancing, TLS termination, and optional mesh networking — designed for 1M+ RPS with millions of tenants.

**Key Capabilities:**
- Layer 7 WAF with 13 attack detectors, bot protection, rate limiting
- Reverse proxy with 6 load balancing algorithms and circuit breaker
- TLS termination with ACME (Let's Encrypt) and post-quantum hybrid key exchange
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC) support
- WASM plugin/serverless runtime (wasmtime-based)
- Mesh networking with DHT, Raft consensus, and post-quantum cryptography
- DNS server with DNSSEC signing and recursive resolution
- Multi-platform OS abstraction (Linux, macOS, FreeBSD, Windows)

---

## 2. Project Structure

```
synvoid/
├── src/                    # Main application source (~70 modules)
├── crates/
│   ├── synvoid-config/     # Configuration types and defaults
│   └── synvoid-utils/      # Shared utilities (buffer pool, serialization)
├── admin-ui/               # Admin dashboard frontend
├── pqc/                    # Post-quantum cryptography crate
├── cloak/                  # Cloakrs encryption library
├── skills/                 # Detailed subsystem documentation
├── architecture/           # This documentation set
├── docs/                   # Architecture decision records (ADRs)
├── plans/                  # Implementation tracking
├── proto/                  # Protobuf definitions
├── config/                 # Default configuration files
├── rules/                  # WAF rule definitions
├── scripts/                # Build and deployment scripts
├── tests/                  # Integration tests
├── benches/                # Benchmarks
├── fuzz/                   # Fuzzing harnesses
└── Cargo.toml              # Workspace manifest
```

---

## 3. Process Architecture

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
           │ IPC
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
│  • scans / heavy transforms  │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│         Upstream Apps        │
│  • Static Files              │
│  • PHP-FPM                   │
│  • Granian                   │
│  • FastCGI                   │
│  • WASM                      │
└──────────────────────────────┘
```

| Process | Flag | Purpose | Default |
|---------|------|---------|---------|
| **Supervisor** | (default) | Control plane, lifecycle, gRPC API | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | Latency-sensitive HTTP/HTTPS/HTTP3 + WAF + proxy | 1 |
| **CPU Offload Worker** | `--cpu-worker` (`--static-worker` compat) | Bounded heavy transforms | 1 |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated) | — |

The default scaling knobs are `worker_threads` for Tokio runtime parallelism, `tcp.worker_pool_size` for accept throughput, and CPU offload worker capacity for heavy transforms. `unified_server_workers > 1` remains an advanced isolation mode, not the primary scaling path.

---

## 4. Request Flow

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

---

## 5. Feature Gates

| Feature | Purpose | Default |
|---------|---------|---------|
| `dns` | DNS server with DNSSEC, DoT/DoH/DoQ | ✅ |
| `mesh` | Mesh networking, DHT, Raft consensus | ✅ |
| `socket-handoff` | Socket transfer between processes | ✅ |
| `erased_pool` | Type-erased HTTP client pool | ✅ |
| `swagger-ui` | OpenAPI documentation UI | ✅ |
| `post-quantum` | Post-quantum TLS key exchange (ML-KEM) | — |
| `wireguard` | WireGuard VPN tunnel support | — |
| `icmp-filter` | ICMP flood filtering | — |
| `flood-ebpf` | eBPF-based flood protection (Linux) | — |
| `macos-sandbox` | macOS sandbox enforcement | — |
| `pqc-mesh` | Post-quantum mesh signatures (ML-DSA-44) | — |
| `fastcgi_streaming` | Streaming FastCGI response handling | — |

**Compilation Profiles:**
- **Core** (`--no-default-features`): Minimal
- **Mesh** (`--no-default-features --features mesh`): Mesh networking
- **DNS** (`--no-default-features --features dns`): DNS server
- **Full** (`--no-default-features --features mesh,dns`): All features

---

## 6. Module Index

### Layer 1: Core Infrastructure

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [Config](./config.md) | Configuration types, validation, site-based config | [`config.md`](./config.md) | [`config_deep_dive.md`](./config_deep_dive.md) |
| [Platform](./platform.md) | OS abstraction, sandboxing, filesystem, IPC | [`platform.md`](./platform.md) | [`platform_deep_dive.md`](./platform_deep_dive.md) |
| [Process & IPC](./ipc_process.md) | IPC communication, process lifecycle, FD passing | [`ipc_process.md`](./ipc_process.md) | [`process_lifecycle.md`](./process_lifecycle.md) |
| [Supervisor](./supervisor.md) | Process supervision, drain protocol, gRPC API | [`supervisor.md`](./supervisor.md) | — |
| [Worker](./worker_architecture.md) | Worker process architecture, Tokio runtime | [`worker_architecture.md`](./worker_architecture.md) | — |
| [Startup](./platform_deep_dive.md) | Bootstrap, daemonization, PID management | [`platform_deep_dive.md`](./platform_deep_dive.md) | — |
| [Drain](./drain.md) | Connection drain state for graceful shutdown | [`drain.md`](./drain.md) | — |

### Layer 2: Security & WAF

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [WAF](./waf.md) | Core WAF engine, attack detection, rate limiting | [`waf.md`](./waf.md) | [`waf_deep_dive.md`](./waf_deep_dive.md) |
| [Auth](./auth.md) | User authentication, sessions, brute-force protection | [`auth.md`](./auth.md) | — |
| [Challenge](./challenge.md) | Browser verification (PoW, CSS challenges, honeypot) | [`challenge.md`](./challenge.md) | — |
| [CAPTCHA](./captcha.md) | Text-based CAPTCHA generation/verification | [`captcha.md`](./captcha.md) | — |
| [Block Store](./block_store.md) | Persistent IP blocklist with LRU eviction | [`block_store.md`](./block_store.md) | — |
| [Tarpit](./tarpit.md) | Anti-scraping tarpit (Markov chain HTML) | [`tarpit.md`](./tarpit.md) | — |
| [Honeypot](./honeypot.md) | Port-based + URL honeypots, threat intel extraction | [`honeypot.md`](./honeypot.md) | — |
| [Upload](./upload.md) | File upload validation, YARA scanning, sandbox quarantine | [`upload.md`](./upload.md) | — |
| [GeoIP](./geoip.md) | GeoIP lookup, country/ASN blocking, auto-update | [`geoip.md`](./geoip.md) | — |
| [ICMP Filter](./icmp_filter.md) | ICMP flood filtering (nftables, eBPF, pf, WFP) | [`icmp_filter.md`](./icmp_filter.md) | — |
| [Integrity](./integrity.md) | Signed HTTP integrity verification (Ed25519) | [`integrity.md`](./integrity.md) | — |

### Layer 3: Networking & Proxy

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [HTTP Server](./http_server.md) | HTTP request handling, 18-phase pipeline | [`http_server.md`](./http_server.md) | — |
| [HTTP Client](./http_shared.md) | Upstream connection pooling, HTTP client | [`http_shared.md`](./http_shared.md) | [`http_shared.md`](./http_shared.md) |
| [HTTP/3](./http_shared.md) | HTTP/3 QUIC server and client | [`http_shared.md`](./http_shared.md) | [`networking_deep_dive.md`](./networking_deep_dive.md) |
| [Proxy](./proxy.md) | Reverse proxy, load balancing, caching | [`proxy.md`](./proxy.md) | [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| [Upstream](./upstream.md) | Upstream server pools, health checks, circuit breaker | [`upstream.md`](./upstream.md) | [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| [TLS](./tls.md) | TLS termination, ACME, post-quantum, mTLS | [`tls.md`](./tls.md) | [`networking_deep_dive.md`](./networking_deep_dive.md) |
| [Router](./routing_deep_dive.md) | Request routing, domain/path matching | [`routing_deep_dive.md`](./routing_deep_dive.md) | — |
| [Listener](./listener.md) | Network listener configuration primitives | [`listener.md`](./listener.md) | [`networking_deep_dive.md`](./networking_deep_dive.md) |
| Tunnel | VPN tunnels (QUIC, WireGuard) | — | [`networking_deep_dive.md`](./networking_deep_dive.md) |
| [Streaming](./streaming.md) | Bidirectional proxy streaming with WAF scanning | [`streaming.md`](./streaming.md) | — |
| [Proxy Cache](./proxy_cache.md) | HTTP response caching (moka + disk) | [`proxy_cache.md`](./proxy_cache.md) | — |
| [Location Matcher](./location_matcher.md) | Nginx-style location matching | [`location_matcher.md`](./location_matcher.md) | — |

### Layer 4: Application Handlers

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [App Handlers](./app_handlers.md) | Static files, FastCGI, CGI, Python, WASM, Spin | [`app_handlers.md`](./app_handlers.md) | — |
| [Static Files](./static_files.md) | Static file serving, compression, minification | [`static_files.md`](./static_files.md) | — |
| [FastCGI](./fastcgi.md) | FastCGI client, connection pool, streaming | [`fastcgi.md`](./fastcgi.md) | — |
| [CGI](./cgi.md) | Classic CGI script execution | [`cgi.md`](./cgi.md) | — |
| [MIME](./mime.md) | MIME type registry, content detection | [`mime.md`](./mime.md) | — |
| [Theme](./theme.md) | WAF theme rendering (CSS, dark mode, SVG) | [`theme.md`](./theme.md) | — |

### Layer 5: WASM & Plugin Runtime

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [Plugin/WASM](./plugin_wasm.md) | WASM plugin execution sandbox | [`plugin_wasm.md`](./plugin_wasm.md) | [`plugin_deep_dive.md`](./plugin_deep_dive.md) |
| [Serverless](./serverless.md) | WASM serverless function execution | [`serverless.md`](./serverless.md) | [`plugin_deep_dive.md`](./plugin_deep_dive.md) |
| [Spin](./spin.md) | Spin WASM runtime integration | [`spin.md`](./spin.md) | [`plugin_deep_dive.md`](./plugin_deep_dive.md) |

### Layer 6: Distributed Systems

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [Mesh](./mesh.md) | P2P networking, DHT, Raft, post-quantum | [`mesh.md`](./mesh.md) | [`mesh_deep_dive.md`](./mesh_deep_dive.md) |
| [DNS](./dns.md) | DNS server, DNSSEC, DoT/DoH/DoQ, TSIG | [`dns.md`](./dns.md) | [`dns_deep_dive.md`](./dns_deep_dive.md) |
| [VPN Client](./dns_deep_dive.md) | VPN client connectivity | — | [`dns_deep_dive.md`](./dns_deep_dive.md) |

### Layer 7: Observability & Admin

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [Admin API](./admin_deep_dive.md) | Admin REST API, metrics, alerting | — | [`admin_deep_dive.md`](./admin_deep_dive.md) |
| [Metrics](./metrics.md) | Atomic counters, per-site metrics, bandwidth | [`metrics.md`](./metrics.md) | — |
| [Logging](./logging.md) | Syslog integration, dynamic log levels | [`logging.md`](./logging.md) | — |
| [Log Controller](./log_controller.md) | Runtime log level management | [`log_controller.md`](./log_controller.md) | — |
| [Protocol](./protocol.md) | Protocol detection framework (HTTP, WS, gRPC) | [`protocol.md`](./protocol.md) | — |

### Cross-Cutting Utilities

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [Buffer Pool](./config_deep_dive.md) | Sharded mutex buffer pool (4 tiers) | [`config_deep_dive.md`](./config_deep_dive.md) | — |
| [Zero Copy](./zero_copy.md) | Kernel-level file-to-socket transfer | [`zero_copy.md`](./zero_copy.md) | — |
| [Filter](./filter.md) | Generic protocol filter framework | [`filter.md`](./filter.md) | — |
| [Common](./common.md) | Panic handler, shared utilities | [`common.md`](./common.md) | — |
| [Serialization](./serde.md) | Postcard/rkyv serialization strategy | [`serde.md`](./serde.md) | — |

---

## 7. Key Integration Patterns

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

### Security Patterns

| Pattern | Implementation | Location |
|---------|---------------|----------|
| Constant-time comparison | `subtle::ConstantTimeEq` | All secrets, MACs, tokens |
| CSRF protection | `ct_eq()` validation | `src/admin/state.rs` |
| Brute-force protection | Account locking after N failures | `src/auth/mod.rs` |
| Path traversal prevention | Canonicalize + prefix check | `src/static_files/`, `src/upload/` |
| ReDoS prevention | Regex complexity checking | `src/location_matcher.rs` |
| Sandboxing | Per-platform backends | `src/sandbox/` |

### Serialization Strategy

| Path | Format | Reason |
|------|--------|--------|
| DHT/Mesh/Persistence | Postcard | Compact, deterministic, cross-language |
| IPC Messages | Postcard | Performance, type safety |
| High-perf paths | Rkyv | Zero-copy deserialization |
| Admin API | JSON | Human-readable, OpenAPI compatible |

---

## 8. Key Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/http/server.rs` | ~4848 | HTTP request handling pipeline |
| `src/waf/mod.rs` | ~936 | WAF core orchestrator |
| `src/mesh/` | ~72400 | Mesh networking (100 files, 100+ types) |
| `src/proxy/mod.rs` | ~1405 | Reverse proxy dispatch |
| `src/supervisor/mod.rs` | ~17 | Process supervision (re-exports) |
| `src/admin/mod.rs` | ~972 | Admin API handlers |
| `src/tls/server.rs` | ~2252 | TLS termination + ACME |
| `src/http_client/mod.rs` | ~1307 | HTTP client pool |
| `src/upstream/pool.rs` | ~1540 | Upstream connection pool |
| `src/plugin/mod.rs` | ~424 | WASM plugin runtime |
| `crates/synvoid-config/src/lib.rs` | ~447 | Configuration types |
| `src/static_files/mod.rs` | ~1126 | Static file serving, `StaticResponseBody` defined at line 96 |

---

## 9. Documentation Index

### This Directory (`architecture/`)

| File | Description |
|------|-------------|
| [`overview.md`](./overview.md) | This file — bird's eye view |
| [`deep_dive_review.md`](./deep_dive_review.md) | Layered architectural review |
| [`review_plan.md`](./review_plan.md) | Review methodology and status |
| [`process_lifecycle.md`](./process_lifecycle.md) | Process execution model |

> **Note:** There is no separate `tunnel.md` or `admin.md`. Tunnel documentation is in [`networking_deep_dive.md`](./networking_deep_dive.md). Admin API documentation is in [`admin_deep_dive.md`](./admin_deep_dive.md).

### External Documentation

| Path | Description |
|------|-------------|
| [`AGENTS.md`](../AGENTS.md) | Developer guide for AI agents |
| [`skills/`](../skills/) | Detailed subsystem patterns (30+ files) |
| [`docs/adr/`](../docs/adr/) | Architecture decision records |
| [`plans/plan.md`](../plans/plan.md) | Consolidated implementation plan |
| [`SECURITY.md`](../SECURITY.md) | Security policy |
