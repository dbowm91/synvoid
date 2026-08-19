# Release Profile Matrix

This document defines the supported compilation profiles, platform coverage, feature gate classifications, and release boundaries for SynVoid.

## Compilation Profiles

Six compilation profiles are tested in CI and locally:

| Profile | Command | Description |
|---------|---------|-------------|
| **CI** | `cargo test --profile ci` | Routine correctness testing — inherits dev, opt-level=1, debug=line-tables-only, incremental=false |
| **Default** | `cargo check` | All default features (mesh, dns, socket-handoff, erased_pool, swagger-ui) |
| **Core** | `cargo check --no-default-features` | Minimal build — no DNS, no mesh |
| **Mesh** | `cargo check --no-default-features --features mesh` | Mesh networking only |
| **DNS** | `cargo check --no-default-features --features dns` | DNS server only |
| **Full** | `cargo check --no-default-features --features mesh,dns` | All features |

The **CI profile** is used for routine correctness testing. It avoids expensive LTO settings used by `--release`, providing fast feedback without sacrificing coverage. The core profile must compile cleanly on every CI run via `cargo xtask verify`. Full profile matrix verification (all five feature profiles) is available locally via `cargo xtask verify-full` or `scripts/verify_architecture.sh`.

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

| Platform | CI Verification | Build Features | Test Suite |
|----------|----------------|----------------|------------|
| Linux x86_64 (glibc) | Routine (`cargo xtask verify`) | `wireguard,icmp-filter` | Full |
| Linux x86_64 (musl) | Routine (`cargo xtask verify`) | `wireguard,icmp-filter` | Full |
| Linux aarch64 | Manual local | `wireguard` | Cross-compile only |
| macOS x86_64 | Manual local | `wireguard` | Cross-compile only |
| macOS aarch64 | Manual local | `wireguard` | Cross-compile only |
| Windows x86_64 | Manual local | `wireguard` | Cross-compile only |
| FreeBSD x86_64 | Manual local | `wireguard` | Build + limited tests |

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
| CI | ✅ | ✅ | ✅ | — | — |
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
| wasmtime 40.0.4 (via yara-x) | **Tracked** — 13 advisory ignores in deny.toml | Used for YARA compilation only, not wasm sandbox. Re-audit: 2026-10-01 |

## CI Enforcement

The single routine CI workflow (`ci.yml`) runs `cargo xtask verify` on every pull request and push to `main`. It enforces:

| Property | Command in `verify` |
|----------|---------------------|
| Formatting | `cargo fmt --all -- --check` |
| Lint (ci profile) | `cargo clippy --profile ci --all-targets -- -D warnings` |
| Core profile compilation | `cargo check --no-default-features --profile ci` |
| Architecture guards | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` |
| Security regression | `cargo test --test security_regression --profile ci --test-threads=1` |
| 13 root guard tests | consolidated nextest invocation |
| synvoid-core admin/mesh | consolidated nextest invocation |
| Failure injection | `cargo test --test failure_injection --profile ci` |

Full profile matrix verification (all five feature profiles) is available locally via `cargo xtask verify-full`. Release verification with package inspection is available via `cargo xtask verify-release`. See `docs/testing/verification-contract.md` for the complete specification.
