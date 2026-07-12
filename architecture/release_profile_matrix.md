# Release Profile Matrix

This document defines the supported compilation profiles, platform coverage, feature gate classifications, and release boundaries for SynVoid.

## Compilation Profiles

Five compilation profiles are tested in CI and locally:

| Profile | Command | Description |
|---------|---------|-------------|
| **Default** | `cargo check` | All default features (mesh, dns, socket-handoff, erased_pool, swagger-ui) |
| **Core** | `cargo check --no-default-features` | Minimal build — no DNS, no mesh |
| **Mesh** | `cargo check --no-default-features --features mesh` | Mesh networking only |
| **DNS** | `cargo check --no-default-features --features dns` | DNS server only |
| **Full** | `cargo check --no-default-features --features mesh,dns` | All features |

All five profiles must compile cleanly on every CI run. The `profile-matrix` CI job and `scripts/verify_architecture.sh` enforce this.

## Feature Gate Classification

| Feature | Default? | Support Level | Notes |
|---------|----------|---------------|-------|
| `socket-handoff` | Yes | **Supported** | Core functionality |
| `mesh` | Yes | **Supported** | DHT, Raft, transport, block-store |
| `dns` | Yes | **Supported** | DNSSEC, DoT/DoH/DoQ, zone management |
| `erased_pool` | Yes | **Supported** | Type-erased HTTP client pool |
| `swagger-ui` | Yes | **Supported** | OpenAPI documentation UI |
| `wireguard` | No | **Supported** | WireGuard VPN tunnel |
| `icmp-filter` | No | **Supported** | ICMP flood filtering (nftables/pf/winfw) |
| `icmp-ebpf` | No | **Beta** | eBPF XDP/TC ICMP filter (Linux only, requires kernel BTF + root). Compiles cleanly, returns explicit error at runtime when unavailable |
| `origin_key_exchange` | No | **Supported** | Signed HTTP integrity |
| `audit` | No | **Supported** | Audit logging |
| `post-quantum` | No | **Beta** | Post-quantum TLS key exchange |
| `verify-pq` | No | **Beta** | Post-quantum verification |
| `tun-rs` | No | **Supported** | TUN device support |
| `buffer` | No | **Supported** | Buffer pool |
| `rkyv` | No | **Supported** | Rkyv serialization |
| `macos-sandbox` | No | **Supported** | macOS sandbox enforcement |
| `test-utils` | No | **Supported** | Test utilities |
| `fastcgi_streaming` | No | **Supported** | Streaming FastCGI |

**Support levels:**
- **Supported**: Verified by CI tests, expected to work in production
- **Beta**: Functional, compiles cleanly, but limited real-world validation or hard runtime constraints
- **Experimental**: Wired but untested at scale, may change without notice

## Platform Coverage

| Platform | CI Job | Build Features | Test Suite |
|----------|--------|----------------|------------|
| Linux x86_64 (glibc) | `build` (matrix) | `wireguard,icmp-filter` | Full |
| Linux x86_64 (musl) | `alpine-test` | `wireguard,icmp-filter` | Full |
| Linux aarch64 | `build` (matrix) | `wireguard` | Cross-compile only |
| macOS x86_64 | `build` (matrix) | `wireguard` | Cross-compile only |
| macOS aarch64 | `build` (matrix) | `wireguard` | Cross-compile only |
| Windows x86_64 | `build` (matrix) | `wireguard` | Cross-compile only |
| FreeBSD x86_64 | `freebsd-test` | `wireguard` | Build + limited tests |
| Platform compat | `platform-compat` | Cross-target checks | Compilation only |

## eBPF Feature Classification

The `icmp-ebpf` feature is classified as **Beta** (not Supported):

- **Compiles cleanly**: `cargo check --all-features` and `cargo clippy --all-features` both pass
- **Runtime constraints**: Requires Linux kernel with BTF support, CAP_NET_ADMIN or root, pre-compiled eBPF ELF bytecode, and `tc` CLI
- **Graceful degradation**: Returns `Err(IcmpFilterError::FeatureNotEnabled)` at runtime when eBPF is unavailable, falls back to nftables
- **Not in default profile**: Must be explicitly enabled with `--features icmp-ebpf`
- **CI coverage**: Build matrix compiles with `icmp-filter` (nftables path), not `icmp-ebpf`

## Release Support Matrix

| Profile | CI Compile | CI Tests | Guard Suite | Fuzz Smoke | Release Gate |
|---------|-----------|----------|-------------|------------|--------------|
| Default | ✅ | ✅ | ✅ | ✅ | Required |
| Core | ✅ | ✅ | ✅ | — | Required |
| Mesh | ✅ | ✅ | ✅ | — | Required |
| DNS | ✅ | ✅ | ✅ | — | Required |
| Full | ✅ | ✅ | ✅ | ✅ | Required |

## Known Tracked Exceptions

| Item | Status | Rationale |
|------|--------|-----------|
| `synvoid-icmp-filter` eBPF (`--all-features`) | **Beta** — compiles, runtime fallback | eBPF requires kernel BTF + root; nftables fallback always available |
| `--all-features` full workspace check | **Fails** on `synvoid-icmp-filter` eBPF dep resolution | Not in default profile; individual crate checks pass |
| wasmtime 40.0.4 (via yara-x) | **Tracked** — 11 advisory ignores in deny.toml | Used for YARA compilation only, not wasm sandbox. Re-audit: 2026-10-01 |

## CI Enforcement

The following CI jobs enforce profile and release boundaries:

| Job | Purpose |
|-----|---------|
| `profile-matrix` | Verifies all 5 compilation profiles compile |
| `core-profile` | Dedicated core profile check |
| `build` | Cross-platform build matrix (8 targets) |
| `clippy` | Workspace-wide lint |
| `fmt` | Format check |
| `guard-suite` | Architecture guard tests |
| `security-audit` | cargo-audit advisory check |
| `dependency-audit` | cargo-deny license/ban/sources check |
| `security-regression` | Security regression tests |
| `fuzz-smoke` | Fuzz target smoke tests |
| `docs-link-guard` | Stale markdown link detection |
