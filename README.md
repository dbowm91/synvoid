# SynVoid

**High-Performance WAF & Reverse Proxy in Rust**

SynVoid is a high-speed, multi-process Web Application Firewall (WAF) and reverse proxy built for security-conscious infrastructure. The default data plane is one latency-sensitive `UnifiedServerWorker` plus bounded CPU offload workers, with the Supervisor managing lifecycle, upgrades, and control-plane state.

## Architecture

### 1. Unified Data Plane
The `UnifiedServerWorker` keeps socket accept, TLS, HTTP parsing, routing, WAF checks, and streaming proxying inline.

### 2. Supervisor-Controlled Control Plane
The Supervisor owns worker lifecycle, zero-downtime rotations, Raft/DHT mesh coordination, and the gRPC control API.

### 3. Bounded CPU Offload
Dedicated CPU workers handle bounded heavy jobs such as minification, compression, image poisoning, and other explicit transforms.

### 4. Linux Optimization
Linux offers the best support for CPU affinity and kernel networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Key Features

- **Advanced Attack Detection**: Native support for SQLi, XSS, SSRF, and command injection detection using `libinjection` and high-speed regex engines.
- **Bot Mitigation**: Challenges automated traffic with CSS honeypots, JavaScript execution tests, and behavioral analysis.
- **Distributed WAF Mesh**: Coordinate threat intelligence across geographic regions and build a private, collaborative DDoS defense network.
- **Modern Protocol Stack**: First-class support for **HTTP/3 (QUIC)**, HTTP/2, and TLS 1.3.
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

| Guide | Description |
|-------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Current data-plane architecture |
| [PROCESS_MANAGEMENT.md](docs/PROCESS_MANAGEMENT.md) | Supervisor and worker lifecycle |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete main.toml reference |
| [WAF_MESH.md](docs/WAF_MESH.md) | Setting up distributed DDoS defense |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Tuning `worker_threads`, `tcp.worker_pool_size`, and CPU offload workers |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Logs, IPC, and common issues |

## Why Linux?

SynVoid is cross-platform, but Linux offers the best support for CPU affinity, shared memory, and high-performance networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Project Philosophy

SynVoid focuses on keeping the hot path lean. The data plane should stay focused on I/O and routing, the Supervisor should own coordination, and heavy transforms should remain bounded and explicit.

## License

MIT License - see [LICENSE](LICENSE) file for details.
