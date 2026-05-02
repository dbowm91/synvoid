# Architecture Profiles

This document defines product profiles for MaluWAF builds, enabling targeted deployment configurations.

## Profile Overview

| Profile | Features | Description |
|---------|----------|-------------|
| `core` | `socket-handoff` | Minimal WAF/reverse proxy - HTTP/HTTPS, process supervision, admin API. **Requires mesh to be compiled.** |
| `mesh-node` | `socket-handoff`, `mesh` | Core + distributed mesh networking, DHT, Raft, threat intel propagation |
| `dns-node` | `socket-handoff`, `dns` | Core + DNS server (DoH/DoT/DoQ, DNSSEC, anycast) **Requires mesh to be compiled.** |
| `edge-full` | `socket-handoff`, `mesh`, `dns`, `post-quantum` | All features for edge deployments |
| `dev-all` | All features | Full development build |

## Default Build Behavior

**Previous**: Default build included `socket-handoff`, `post-quantum`, `mesh`, and `dns`.

**Current**: Default build is `socket-handoff`, `mesh`, and `dns`. `post-quantum` has been moved to an optional feature since it materially complicates TLS/provider setup and isn't needed for all deployments.

> **Note**: Removing `mesh` and `dns` from default would require significant refactoring due to deep dependencies in mesh initialization and DNS resolver trait usage throughout the codebase. The `pub mod mesh` at lib.rs level is always compiled, and mesh transport functions use `crate::dns::resolver::DnsResolver` directly. This is marked as a future improvement.

## Feature Matrix

| Feature | core | mesh-node | dns-node | edge-full | dev-all |
|---------|------|-----------|----------|-----------|---------|
| `socket-handoff` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `mesh` | ❌ | ✅ | ❌ | ✅ | ✅ |
| `dns` | ❌ | ❌ | ✅ | ✅ | ✅ |
| `post-quantum` | ❌ | ❌ | ❌ | ✅ | ✅ |
| `wireguard` | ❌ | ❌ | ❌ | ❌ | ✅ |
| `icmp-filter` | ❌ | ❌ | ❌ | ❌ | ✅ |
| `flood-ebpf` | ❌ | ❌ | ❌ | ❌ | ✅ |
| `tun-rs` | ❌ | ❌ | ❌ | ❌ | ✅ |
| `pqc-mesh` | ❌ | ❌ | ❌ | ❌ | ✅ |
| `macos-sandbox` | ❌ | ❌ | ❌ | ❌ | ✅ |

## Module Inclusion by Profile

### Core Modules (always included)
- `waf` — Core WAF engine
- `proxy` — Reverse proxy and request forwarding
- `config` — Configuration loading and validation
- `process` — IPC communication and process management
- `tls` — TLS termination, ACME certificate management
- `admin` — Admin API
- `http` / `http3` — HTTP server support

### mesh-node Adds
- `mesh` — Mesh networking, DHT, Raft consensus
- Distributed threat intelligence propagation
- Mesh YARA/rule propagation

### dns-node Adds
- `dns` — DNS server with DNSSEC, recursive resolution
- `dnssec` signing and validation
- DoH, DoT, DoQ support
- Anycast DNS support

## Reload Behavior by Feature

| Feature | Hot Reload | Restart Required |
|---------|------------|------------------|
| Core routing | ✅ | |
| TLS certificates | ✅ (LE) | |
| WAF rules | ✅ | |
| `mesh` config | | ❌ (requires restart) |
| `dns` serving | | ❌ (requires restart) |
| Plugin reload | ✅ | |

## Building Specific Profiles

```bash
# Core (default)
cargo build

# Mesh node
cargo build --features mesh

# DNS node
cargo build --features dns

# Edge full
cargo build --features "mesh dns post-quantum"

# Dev all
cargo build --all-features
```

## Config Validation

When a feature is disabled at compile time but enabled in config, validation returns a clear error:

- **DNS**: "DNS server configured but binary built without `dns` feature. Rebuild with `--features dns`."
- **Mesh**: "Mesh configured but binary built without `mesh` feature. Rebuild with `--features mesh`."

## Dependencies by Feature

### `dns` Feature Dependencies
- `hickory-proto` (DNS protocol)
- `hickory-resolver` (Recursive resolver)
- `tokio-dstip`
- `cryptoki` (HSM support)
- `getrandom`

### `mesh` Feature Dependencies
- `openraft` (Raft consensus)
- Post-quantum crypto for mesh signatures

### `post-quantum` Feature Dependencies
- `rustls-post-quantum`

## Compilation Performance

Approximate relative build times (normalized to `core`):

| Profile | Build Time |
|---------|------------|
| core | 1.0x |
| mesh-node | 1.3x |
| dns-node | 1.4x |
| edge-full | 1.6x |
| dev-all | 2.0x |