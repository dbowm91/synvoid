# SynVoid Architecture Overview

## Project Structure

```
synvoid/
├── src/                    # Main application source (73 modules)
├── crates/
│   ├── synvoid-config/     # Configuration types and defaults
│   └── synvoid-utils/      # Shared utilities
├── skills/                 # Detailed subsystem documentation
├── docs/                   # Architecture documentation
├── plans/                  # Implementation plan
└── Cargo.toml              # Workspace manifest
```

## Process Architecture

SynVoid uses a multi-process architecture for high scalability (1M+ RPS) with millions of tenants:

| Process | Flag | Purpose |
|---------|------|---------|
| **Supervisor** | (default) | Main control plane - manages lifecycle, health monitoring, consolidates legacy Overseer+Master |
| **Master** | `--master` | Legacy mode - spawns/manages workers, handles IPC, runs admin API |
| **UnifiedServerWorker** | `--unified-server-worker` | Handles HTTP/HTTPS/HTTP3 + WAF + proxy (single Tokio event loop) |
| **StaticWorker** | `--static-worker` | CSS/JS minification, compression |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated, unused for HTTP) |

### UnifiedServerWorker: Single Process for HTTP/HTTPS/HTTP3

The unified worker uses a **single Tokio async event loop** which is far more efficient than spawning multiple worker processes. Tokio's optimization with `worker_threads` equal to CPU cores handles all cores efficiently via cooperative scheduling. Adding more worker processes adds process isolation overhead but NOT throughput.

---

## Module Index

Each module links to detailed documentation. Deep dive files provide in-depth analysis of specific subsystems.

| Module | Purpose | Architecture Doc | Deep Dive |
|--------|---------|------------------|-----------|
| [WAF](./waf.md) | Web Application Firewall - attack detection, rate limiting, bot protection | [`waf.md`](./waf.md) | [`waf_deep_dive.md`](./waf_deep_dive.md) |
| [Mesh](./mesh.md) | Peer-to-peer networking, DHT, Raft consensus, post-quantum crypto | [`mesh.md`](./mesh.md) | [`mesh_deep_dive.md`](./mesh_deep_dive.md) |
| [DNS](./dns.md) | DNS server with DNSSEC signing/validation, recursive resolution | [`dns.md`](./dns.md) | [`dns_deep_dive.md`](./dns_deep_dive.md) |
| [Proxy](./proxy.md) | Reverse proxy, load balancing, caching | [`proxy.md`](./proxy.md) | [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| [HTTP Server](./http_server.md) | HTTP request handling, static file serving | [`http_server.md`](./http_server.md) | |
| [HTTP Client](./http_shared.md) | Upstream connection pooling, HTTP client abstraction | [`http_shared.md`](./http_shared.md) | |
| [TLS](./tls.md) | TLS termination, ACME certificate management | [`tls.md`](./tls.md) | |
| [Supervisor](./supervisor.md) | Process supervision, worker orchestration, control plane API | [`supervisor.md`](./supervisor.md) | |
| [IPC & Process](./ipc_process.md) | IPC communication, process lifecycle management | [`ipc_process.md`](./ipc_process.md) | [`process_lifecycle.md`](./process_lifecycle.md) |
| [Serverless](./serverless.md) | WASM-based serverless function execution | [`serverless.md`](./serverless.md) | |
| [Plugin/WASM](./plugin_wasm.md) | WASM plugin execution sandbox | [`plugin_wasm.md`](./plugin_wasm.md) | [`plugin_deep_dive.md`](./plugin_deep_dive.md) |
| [Spin](./spin.md) | Spin WASM runtime integration | [`spin.md`](./spin.md) | |
| [Upstream](./upstream.md) | Upstream server pool management, health checks | [`upstream.md`](./upstream.md) | |
| [Tunnel](./tunnel.md) | VPN tunnel support (QUIC, WireGuard) | [`tunnel.md`](./tunnel.md) | [`networking_deep_dive.md`](./networking_deep_dive.md) |
| [Admin API](./admin.md) | Administrative REST API, metrics, alerting | [`admin.md`](./admin.md) | [`admin_deep_dive.md`](./admin_deep_dive.md) |
| [Auth](./auth.md) | Authentication, session management, brute-force protection | [`auth.md`](./auth.md) | |
| [Platform](./platform.md) | OS abstraction layer, sandboxing, IPC | [`platform.md`](./platform.md) | [`platform_deep_dive.md`](./platform_deep_dive.md) |
| [Config](./config.md) | Configuration types, validation, site-based config | [`config.md`](./config.md) | [`config_deep_dive.md`](./config_deep_dive.md) |

---

## Key Integration Patterns

### Request Flow

```
Client → HTTPS/TLS → HTTP Server → WAF Check → Proxy Dispatch → Upstream Pool → HTTP Client → Upstream Server
                                              ↓
                                    WASM Filters (Serverless/Plugin)
```

### Process Communication

```
Supervisor
    ↓ IPC
Master → IPC → UnifiedServerWorker(s)
              ↓ IPC
         StaticWorker(s)
```

### Mesh Networking

```
Mesh Node
    ↓
DHT (Distributed Hash Table) → Service Discovery
    ↓
Raft Consensus → Global Control Plane
    ↓
Transport (QUIC/WireGuard/Global) → Peer-to-Peer
    ↓
Post-Quantum Crypto (ML-KEM/ML-DSA)
```

---

## Feature Gates

| Feature | Purpose |
|---------|---------|
| `dns` | DNS server with DNSSEC support |
| `mesh` | Mesh networking for multi-node |
| `socket-handoff` | Socket transfer between processes |
| `post-quantum` | Post-quantum TLS key exchange |
| `wireguard` | WireGuard VPN tunnel support |
| `icmp-filter` | ICMP filtering |
| `flood-ebpf` | eBPF-based flood protection |
| `macos-sandbox` | macOS sandboxing (Landlock) |

### Compilation Profiles

- **Core** (`--no-default-features`): Minimal build
- **Mesh** (`--no-default-features --features mesh`): Mesh networking enabled
- **DNS** (`--no-default-features --features dns`): DNS server enabled
- **Full** (`--no-default-features --features mesh,dns`): All features enabled

---

## Documentation Directory

| Path | Description |
|------|-------------|
| `architecture/*.md` | Module architecture documentation |
| `docs/` | Architecture decision records |
| `skills/` | Detailed subsystem patterns |
| `plans/` | Implementation tracking |
