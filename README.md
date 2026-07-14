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
git clone https://github.com/dbowm91/synvoid.git
cd synvoid

# Default build (includes mesh, DNS, socket-handoff, erased_pool, swagger-ui)
cargo build --release

# Or choose a profile — see Build Profiles below
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

> **First Release**: This is SynVoid's first release candidate (`v1.1.0-rc.1`). See [`CHANGELOG.md`](CHANGELOG.md) for the full list of features, known limitations, and migration notes.

## Build Profiles

SynVoid ships five tested compilation profiles. Choose the one that matches your deployment.

| Profile | Command | Use Case |
|---------|---------|----------|
| **Core** | `cargo build --release --no-default-features` | Minimal reverse proxy, no DNS or mesh |
| **Mesh-only** | `cargo build --release --no-default-features --features mesh` | Mesh networking without DNS |
| **DNS-only** | `cargo build --release --no-default-features --features dns` | DNS server without mesh |
| **Default** | `cargo build --release` | Production WAF + mesh + DNS |
| **Full** | `cargo build --release --all-features` | All features including Beta (see below) |

All profiles must compile cleanly on every CI run. The `profile-matrix` CI job and `scripts/verify_architecture.sh` enforce this. See `architecture/release_profile_matrix.md` for the full matrix.

> **Supported profiles** compile and pass tests in CI. The **Full** profile includes Beta features that have limited real-world validation — see [Beta Features](#beta-features) below.

## Beta Features

The following features are functional and compile cleanly, but have limited real-world validation or hard runtime constraints. They are **not** in the default build profile.

| Feature | Flag | Notes |
|---------|------|-------|
| `icmp-ebpf` | `--features icmp-ebpf` | eBPF SYN-level blocking (Linux only, requires kernel BTF + root). Falls back to nftables when unavailable |
| `post-quantum` | `--features post-quantum` | Hybrid ML-KEM-768 post-quantum TLS key exchange |
| `verify-pq` | `--features verify-pq` | Post-quantum signature verification |

To build with all features including Beta:

```bash
cargo build --release --all-features
```

## Deployment Recommendations

| Scenario | Recommended Profile | Key Features |
|----------|-------------------|--------------|
| Minimal reverse proxy | Core | No DNS, no mesh |
| DNS server | DNS-only | DNS without mesh |
| Mesh networking | Mesh-only | Mesh without DNS |
| General production | Default | WAF + mesh + DNS |
| Full-featured | Full (mesh+DNS) | All supported features |

### Production Defaults

- **AI honeypot responder**: Disabled by default (requires explicit opt-in)
- **Honeypot listeners**: Disabled by default unless configured
- **Mesh threat-intel propagation**: Disabled by default (requires threshold configuration)
- **Raw payload retention**: Minimized by default (HashOnly mode)
- **Tarpit admission**: Enabled with sensible defaults (256 global, 4 per-IP)
- **Archive inspection**: ZIP-only, non-recursive
- **eBPF ICMP filter**: Beta; falls back to nftables when unavailable

## Platform Support

| Platform | Support Level | CI Tested | Notes |
|----------|--------------|-----------|-------|
| Linux x86_64 (glibc) | Full | Yes | Primary target, full socket/affinity/eBPF support |
| Linux x86_64 (musl) | Full | Yes | Full feature support |
| macOS (x86_64/aarch64) | Full | Yes | Full support except eBPF |
| Windows 10+ | Full | Yes | Full support except eBPF, uses Named Pipes for IPC |
| FreeBSD x86_64 | Full | Yes | Full support except eBPF, native `SO_REUSEPORT_LB` |

See `architecture/release_profile_matrix.md` for detailed per-platform feature availability.

## CI Testing

SynVoid uses a four-lane CI system with a dedicated `[profile.ci]` for fast routine correctness testing. PRs get fast feedback; comprehensive validation runs on main; qualification runs nightly.

| Lane | Trigger | Duration Target |
|------|---------|----------------|
| PR Fast | Pull requests | <10 minutes |
| Main Comprehensive | Push to main | Full suite |
| Scheduled Qualification | Nightly | Expensive checks |
| Release Qualification | Version tags | Production validation |

### Developer Testing

Run tests for only the packages affected by your changes:

```bash
# Preview what would be tested
bash scripts/test-affected.sh origin/main --dry-run

# Run affected tests
bash scripts/test-affected.sh origin/main

# Force full validation
bash scripts/test-affected.sh origin/main --full
```

### CI Caching

SynVoid CI uses `Swatinem/rust-cache` for Cargo source and target metadata caching. `sccache` compiler output caching is dormant (deferred pending backend verification). See [`docs/testing/cache-policy.md`](docs/testing/cache-policy.md) for the full cache architecture.

See [`docs/testing/ci-lane-policy.md`](docs/testing/ci-lane-policy.md) for the full CI policy.

## Documentation

### Core

| Guide | Description |
|-------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Release history and migration notes |
| [docs/RELEASE.md](docs/RELEASE.md) | Release process, versioning, hotfix, deprecation |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment guide |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Configuration reference |
| [SECURITY.md](SECURITY.md) | Security model and advisory policy |
| [docs/testing/ci-lane-policy.md](docs/testing/ci-lane-policy.md) | CI testing lanes and policy |

### Subsystem Guides

| Guide | Description |
|-------|-------------|
| [docs/HONEYPOT.md](docs/HONEYPOT.md) | Honeypot listener and deception layer |
| [docs/TARPIT.md](docs/TARPIT.md) | Anti-scraping tarpit and trapping |
| [docs/TUNNELS.md](docs/TUNNELS.md) | Tunnel backend routing |

### Architecture

| Document | Description |
|----------|-------------|
| [architecture/release_profile_matrix.md](architecture/release_profile_matrix.md) | Compilation profiles, feature gates, platform coverage |
| [architecture/release_hardening_report.md](architecture/release_hardening_report.md) | Release hardening checklist and guard results |
| [architecture/final_surface_audit.md](architecture/final_surface_audit.md) | Public surface classification and stability audit |
| [architecture/root_module_ledger.md](architecture/root_module_ledger.md) | Root module ownership |
| [architecture/worker_data_plane_composition_root.md](architecture/worker_data_plane_composition_root.md) | Composition boundary rules |

### Plans

| Document | Description |
|----------|-------------|
| [plans/roadmap.md](plans/roadmap.md) | Full development roadmap |

## Why Linux?

SynVoid is cross-platform, but Linux offers the best support for CPU affinity, shared memory, and high-performance networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Project Philosophy

SynVoid focuses on keeping the hot path lean. The data plane should stay focused on I/O and routing, the Supervisor should own coordination, and heavy transforms should remain bounded and explicit.

## License

MIT License - see [LICENSE](LICENSE) file for details.
