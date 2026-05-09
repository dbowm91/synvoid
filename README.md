# SynVoid

**High-Performance Shared-Nothing WAF & Reverse Proxy in Rust**

SynVoid is a high-speed, horizontally scalable Web Application Firewall (WAF) and reverse proxy built for modern, security-conscious infrastructure. Utilizing a **Shared-Nothing Architecture**, SynVoid is designed to process 1M+ requests per second with linear scaling across CPU cores.

---

## 🚀 Key Architectural Shifts

SynVoid has recently undergone a major architectural evolution to meet the demands of high-throughput environments:

### 1. Shared-Nothing Data Plane
Workers are now completely isolated processes (or threads) that own their network stack. Using `SO_REUSEPORT`, the kernel handles load balancing at the socket level, eliminating the bottleneck of a single "acceptor" process.

### 2. Unified Supervisor Model
The legacy Overseer and Master processes have been unified into a single **Supervisor**. The Supervisor centralizes the Control Plane (Raft consensus, DHT routing, and Mesh transport) while relegating the high-performance request handling to the Workers.

### 3. gRPC Control Plane
Instance management is now formalized via a high-performance **gRPC API**. Status reporting, configuration reloads, and manual blocking are handled through a strongly-typed interface, enabling robust remote orchestration.

### 4. Zero-Jitter Performance
On Linux, workers are automatically pinned to specific CPU cores via `sched_setaffinity`. This prevents context switching and cache invalidation, ensuring predictable latency even under heavy DDoS load.

---

## ✨ Key Features

- **Advanced Attack Detection**: Native support for SQLi, XSS, SSRF, and command injection detection using `libinjection` and high-speed regex engines.
- **Bot Mitigation**: Challenges automated traffic with CSS honeypots, JavaScript execution tests, and behavioral analysis.
- **Distributed WAF Mesh**: (Opt-in) Coordinate threat intelligence across geographic regions and build a private, collaborative DDoS defense network.
- **Modern Protocol Stack**: First-class support for **HTTP/3 (QUIC)**, HTTP/2, and TLS 1.3.
- **Linear Scaling**: Designed to scale perfectly with available hardware. Adding more CPU cores results in near-perfect throughput gains.
- **Silent Security**: Features like "Silent Stalling" and "Tarpitting" waste attacker resources without revealing server information.

---

## ⚡ Quick Start

### 1. Build from Source
```bash
git clone https://github.com/synvoid/synvoid.git
cd synvoid
cargo build --release
```

### 2. Run
```bash
# Supervisor automatically manages the worker pool based on CPU cores
./target/release/synvoid --config /etc/synvoid/main.toml
```

The system initializes:
- **Data Plane**: http://localhost:8080 (Managed by Workers)
- **gRPC Control API**: 127.0.0.1:50051 (Managed by Supervisor)
- **Admin UI / Metrics**: http://localhost:8081 | http://localhost:9090

---

## 📖 Documentation

Explore our comprehensive documentation for deeper technical insights:

| Guide | Description |
|-------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Shared-nothing vs Traditional Proxy models |
| [PROCESS_MANAGEMENT.md](docs/PROCESS_MANAGEMENT.md) | Supervisor and Worker lifecycle |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete main.toml reference |
| [WAF_MESH.md](docs/WAF_MESH.md) | Setting up distributed DDoS defense |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Tuning for 1M+ RPS |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Logs, IPC, and common issues |

---

## 🐧 Why Linux?

While SynVoid is cross-platform, it is highly optimized for Linux. Features like `SO_REUSEPORT` for load balancing, `sched_setaffinity` for core pinning, and advanced kernel-level network optimizations are most mature on Linux distributions.

---

## 🛠 Project Philosophy

SynVoid started as an exploration of high-performance Rust networking and has evolved into a production-ready security layer. Our philosophy is **Isolation over Coordination**: the data plane should never wait for the control plane. By relegating heavy protocols (like Raft or DHT) to the Supervisor and keeping Workers "dumb," we ensure that security logic never compromises throughput.

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.
