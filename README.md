# SynVoid

**High-Performance WAF & Reverse Proxy in Rust**

SynVoid is a high-speed, multi-process Web Application Firewall (WAF) and reverse proxy built for security-conscious infrastructure. The default data plane is one latency-sensitive `UnifiedServerWorker` plus bounded CPU offload workers, with the Supervisor managing lifecycle, upgrades, and control-plane state.

## Architecture

### Development Status

The architecture-hardening roadmap is **complete** through Phase 16 and locally verified. All 27 guard tests pass, all feature profile checks are green, and the release-hardening report is at `architecture/release_hardening_report.md`. CI uses a single routine workflow (`ci.yml`) running `cargo xtask verify`. Local verification is authoritative. Publication to crates.io is manual — see `docs/releasing.md`. See `plans/roadmap.md` for the full roadmap and `architecture/final_surface_audit.md` for the public surface inventory.

### 1. Unified Data Plane
The `UnifiedServerWorker` keeps socket accept, TLS, HTTP parsing, routing, WAF checks, and streaming proxying inline.

### 2. Supervisor-Controlled Control Plane
The Supervisor owns worker lifecycle, zero-downtime rotations, Raft/DHT mesh coordination, and the gRPC control API.

### 3. Bounded CPU Offload
Dedicated CPU workers handle bounded heavy jobs such as minification, compression, image rights marking (steganographic / metadata signaling), and other explicit transforms.

### 4. Linux Optimization
Linux offers the best support for CPU affinity and kernel networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Key Features

- **Advanced Attack Detection**: Native support for SQLi, XSS, SSRF, command injection, LDAP injection, and XPath injection detection using `libinjection` and high-speed regex engines.
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

All profiles must compile cleanly. The routine CI workflow (`ci.yml`) runs `cargo xtask verify`, which includes a core-profile compilation check. Full profile matrix verification is available locally via `cargo xtask verify-full` or `scripts/verify_architecture.sh`. See `architecture/release_profile_matrix.md` for the full matrix.

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

| Platform | Support Level | Notes |
|----------|--------------|-------|
| Linux x86_64 (glibc) | Primary | Full socket/affinity/eBPF support. Routinely verified in CI. |
| Linux x86_64 (musl) | Primary | Full feature support. Routinely verified in CI. |
| macOS (x86_64/aarch64) | Best effort | Full support except eBPF. Manually verified. |
| Windows 10+ | Best effort | Full support except eBPF, uses Named Pipes for IPC. Manually verified. |
| FreeBSD x86_64 | Best effort | Full support except eBPF, native `SO_REUSEPORT_LB`. Manually verified. |

See `architecture/release_profile_matrix.md` for detailed per-platform feature availability.

## CI Testing

SynVoid uses a single routine CI workflow (`ci.yml`) running on Linux x86_64 with a dedicated `[profile.ci]` for fast correctness testing. The canonical verification command is `cargo xtask verify`, which runs formatting, linting, compilation, guard tests, and security regression tests.

Publication to crates.io is manual — see [`docs/releasing.md`](docs/releasing.md).

See [`docs/testing/verification-contract.md`](docs/testing/verification-contract.md) for the full verification specification.

### Verification Status

- **Routine CI** (`cargo xtask verify`): ✅ All 8 steps pass
- **Full verification** (`cargo xtask verify-full`): ✅ 6773 tests pass, 1 specialist skip (`test_worker_crash_recovery`)
- **Release verification** (`cargo xtask verify-release`): ✅ 9/9 phases pass, 39 publishable crates (9 verified, 30 deferred on internal predecessors)

CI verification/release simplification is COMPLETE. See `plans/ci_verification_release_truthful_closure_results.md` for the authoritative evidence record.

### Developer Testing

Run the routine verification contract locally:

```bash
# Run the canonical verification contract (what CI runs)
cargo xtask verify

# Or run individual steps
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
```

### CI Caching

SynVoid CI uses `Swatinem/rust-cache` for Cargo source and target metadata caching.

## Documentation

### Core

| Guide | Description |
|-------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Release history and migration notes |
| [docs/RELEASE.md](docs/RELEASE.md) | Release process, versioning, hotfix, deprecation |
| [docs/releasing.md](docs/releasing.md) | Manual publication procedure and publication order |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment guide |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Configuration reference |
| [SECURITY.md](SECURITY.md) | Security model and advisory policy |
| [docs/testing/verification-contract.md](docs/testing/verification-contract.md) | CI verification specification |

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
| [plans/ci_verification_release_truthful_closure_roadmap.md](plans/ci_verification_release_truthful_closure_roadmap.md) | CI verification and release closure roadmap |
| [plans/ci_phase01_failure_ledger.md](plans/ci_phase01_failure_ledger.md) | Phase 1 failure ledger with 20 remaining failures |
| [plans/ci_phase01_execution_evidence.md](plans/ci_phase01_execution_evidence.md) | Phase 1 execution evidence and deliverables |

## Why Linux?

SynVoid is cross-platform, but Linux offers the best support for CPU affinity, shared memory, and high-performance networking primitives. Advanced shared-port deployments are supported, but they are not the default model.

## Project Philosophy

SynVoid focuses on keeping the hot path lean. The data plane should stay focused on I/O and routing, the Supervisor should own coordination, and heavy transforms should remain bounded and explicit.

## License

MIT License - see [LICENSE](LICENSE) file for details.
