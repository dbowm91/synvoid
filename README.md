# SynVoid

**High-Performance WAF & Reverse Proxy in Rust**

SynVoid is a high-speed, multi-process Web Application Firewall (WAF) and reverse proxy built for security-conscious infrastructure. The default data plane is one latency-sensitive `UnifiedServerWorker` plus bounded CPU offload workers, with the Supervisor managing lifecycle, upgrades, and control-plane state.

## Architecture

### Development Status

The architecture-hardening roadmap is **complete** through Phase 16 and locally verified. All 27 guard tests pass, all feature profile checks are green, and the release-hardening report is at `architecture/release_hardening_report.md`. Phase 16 added runtime operations drill documents (`architecture/runtime_operations_drill.md`, `architecture/runtime_operations_drill_report.md`) and refined the plugin capability boundary guard heuristic. CI workflow (`.github/workflows/ci.yml`) was fixed in Phase 11 (summary job had broken dynamic expressions that prevented all jobs from running). CI execution is currently blocked by a GitHub billing issue; local verification is authoritative. See `plans/roadmap.md` for the full roadmap and `architecture/final_surface_audit.md` for the public surface inventory.

### 1. Unified Data Plane
The `UnifiedServerWorker` keeps socket accept, TLS, HTTP parsing, routing, WAF checks, and streaming proxying inline.

### 2. Supervisor-Controlled Control Plane
The Supervisor owns worker lifecycle, zero-downtime rotations, Raft/DHT mesh coordination, and the gRPC control API.

### 3. Bounded CPU Offload
Dedicated CPU workers handle bounded heavy jobs such as minification, compression, image rights marking (steganographic / metadata signaling), and other explicit transforms.

### 4. Linux Optimization
Linux offers the best support for CPU affinity and kernel networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Key Features

- **Advanced Attack Detection**: Native support for SQLi, XSS, SSRF, and command injection detection using `libinjection` and high-speed regex engines.
- **Bot Mitigation**: Challenges automated traffic with CSS honeypots, JavaScript execution tests, and behavioral analysis.
- **Distributed WAF Mesh**: Coordinate threat intelligence across geographic regions and build a private, collaborative DDoS defense network. DHT ingress validation uses a centralized key policy table, signed Raft attestations, and mandatory signature enforcement for remote writes. See `architecture/mesh_trust_domains.md` for trust domain boundaries.
- **Modern Protocol Stack**: First-class support for **HTTP/3 (QUIC)**, HTTP/2, and TLS 1.3. DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ) for encrypted DNS.
- **Capacity Scaling**: Tune `worker_threads`, `tcp.worker_pool_size`, and CPU offload capacity to match the workload mix.
- **Silent Security**: Features like "Silent Stalling" and "Tarpitting" waste attacker resources without revealing server information.

## Quick Start

### 1. Build from Source
```bash
git clone https://github.com/synvoid/synvoid.git
cd synvoid
cargo build --release
```

### 2. Run
```bash
# Supervisor manages the configured worker set
./target/release/synvoid --config /etc/synvoid/main.toml
```

The system initializes:
- **Data Plane**: http://localhost:8080 (UnifiedServerWorker)
- **gRPC Control API**: 127.0.0.1:50051 (Supervisor)
- **Admin UI / Metrics**: http://localhost:8081 | http://localhost:9090

## Documentation

Explore our documentation for deeper technical insights:

### Core

| Guide | Description |
|-------|-------------|
| [GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation and first run |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Current data-plane architecture |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete main.toml reference |
| [DEVELOPER.md](docs/DEVELOPER.md) | Developer guide and codebase orientation |

### Operations

| Guide | Description |
|-------|-------------|
| [PROCESS_MANAGEMENT.md](docs/PROCESS_MANAGEMENT.md) | Supervisor and worker lifecycle |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Deployment patterns and Docker |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Tuning `worker_threads`, `tcp.worker_pool_size`, and CPU offload workers |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Logs, IPC, and common issues |
| [UPGRADE.md](docs/UPGRADE.md) | Upgrade procedures |

### Security

| Guide | Description |
|-------|-------------|
| [SECURITY.md](docs/SECURITY.md) | Security model and hardening |
| [SANDBOXING.md](docs/SANDBOXING.md) | OS sandboxing (Windows/macOS/Linux/BSD) |
| [ATTACK_DETECTION.md](docs/ATTACK_DETECTION.md) | SQLi, XSS, SSRF, command injection |
| [BOT_PROTECTION.md](docs/BOT_PROTECTION.md) | Bot detection and mitigation |
| [RATE_LIMITING.md](docs/RATE_LIMITING.md) | Rate limiting configuration |
| [REQUEST_SANITIZATION.md](docs/REQUEST_SANITIZATION.md) | Input sanitization |
| [FLOOD_PROTECTION.md](docs/FLOOD_PROTECTION.md) | Flood/DDoS protection |

### Features

| Guide | Description |
|-------|-------------|
| [WAF_MESH.md](docs/WAF_MESH.md) | Distributed WAF mesh setup |
| [THREAT_INTEL.md](docs/THREAT_INTEL.md) | Threat intelligence integration |
| [HTTP3.md](docs/HTTP3.md) | HTTP/3 (QUIC) configuration |
| [STATIC_FILES.md](docs/STATIC_FILES.md) | Static file serving |
| [UPLOADS.md](docs/UPLOADS.md) | File upload handling |
| [HONEYPOT.md](docs/HONEYPOT.md) | Honeypot listener and deception |
| [TARPIT.md](docs/TARPIT.md) | Anti-scraping tarpit and trapping |
| [SERVERLESS.md](docs/SERVERLESS.md) | Serverless WASM functions |
| [PLUGINS.md](docs/PLUGINS.md) | Plugin system |
| [TUNNELS.md](docs/TUNNELS.md) | Tunnel backend routing |
| [FASTCGI.md](docs/FASTCGI.md) | FastCGI handler |
| [TRAFFIC_SHAPING.md](docs/TRAFFIC_SHAPING.md) | Traffic shaping and throttling |
| [UPSTREAM_HEALTH.md](docs/UPSTREAM_HEALTH.md) | Upstream health checks |

### Reference

| Guide | Description |
|-------|-------------|
| [API_REFERENCE.md](docs/API_REFERENCE.md) | REST API reference |
| [ADMIN_UI.md](docs/ADMIN_UI.md) | Admin UI guide |
| [FAQ.md](docs/FAQ.md) | Frequently asked questions |
| [RFC5011_TRUST_ANCHOR.md](docs/RFC5011_TRUST_ANCHOR.md) | RFC5011 trust anchor management |

## Why Linux?

SynVoid is cross-platform, but Linux offers the best support for CPU affinity, shared memory, and high-performance networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Project Philosophy

SynVoid focuses on keeping the hot path lean. The data plane should stay focused on I/O and routing, the Supervisor should own coordination, and heavy transforms should remain bounded and explicit.

## License

MIT License - see [LICENSE](LICENSE) file for details.
