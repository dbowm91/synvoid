# Release Profile Matrix

This document defines the supported compilation profiles, platform coverage, feature gate classifications, and release boundaries for SynVoid.

## Compilation Profiles

Seven compilation profiles are tested in CI and locally:

| Profile | Command | Description |
|---------|---------|-------------|
| **CI** | `cargo test --profile ci` | Routine correctness testing — inherits dev, opt-level=1, debug=line-tables-only, incremental=false |
| **Default** | `cargo check` | All default features (mesh, dns, socket-handoff, erased_pool, swagger-ui) |
| **Core** | `cargo check --no-default-features` | Minimal build — no DNS, no mesh |
| **Mesh** | `cargo check --no-default-features --features mesh` | Mesh networking only |
| **DNS** | `cargo check --no-default-features --features dns` | DNS server only |
| **ICMP** | `cargo check --no-default-features --features icmp-filter` | ICMP filtering only (`icmp-filter` build profile in `tools/xtask/src/verify.rs:250`) |
| **Full** | `cargo check --no-default-features --features mesh,dns` | All features |

The **CI profile** is used for routine correctness testing. It avoids expensive LTO settings used by `--release`, providing fast feedback without sacrificing coverage. The core profile must compile cleanly on every CI run via `cargo xtask verify`. Full profile matrix verification (all five `--no-default-features` feature profiles — core, mesh, dns, icmp, mesh+dns — plus the broader test and doctest pass) is available locally via `cargo xtask verify-full` or `scripts/verify_architecture.sh`.

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
| `icmp-ebpf` | No | **Beta** | eBPF XDP/TC ICMP filter (Linux only, requires kernel BTF + root). **Crate-scoped feature of `synvoid-icmp-filter`, not a root feature.** Compiles cleanly, returns explicit error at runtime when unavailable |
| `flood-ebpf` | No | **Supported** | Root feature (Cargo.toml:34) enabling `aya` + `synvoid-admin/flood-ebpf` for eBPF flood protection |
| `origin_key_exchange` | No | **Supported** | Signed HTTP integrity |
| `audit` | No | **Supported** | Audit logging |
| `post-quantum` | No | **Beta** | Post-quantum TLS key exchange |
| `verify-pq` | No | **Beta** | Post-quantum verification |
| `tun-rs` | No | **Supported** | TUN device support |
| `buffer` | No | **Supported** | Buffer pool |
| `rkyv` | No | **Supported** | Rkyv serialization |
| `macos-sandbox` | No | **Experimental** | macOS Seatbelt via deprecated `sandbox_init` (opt-in; not App Sandbox) |
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

- **Compiles cleanly**: `cargo check -p synvoid-icmp-filter --features icmp-ebpf` succeeds, and root `cargo check --all-features` passes (`cargo metadata --all-features` exits 0). Workspace-wide `cargo check --workspace --all-features` fails for an unrelated reason — see Known Tracked Exceptions
- **Crate-scoped, not root**: `icmp-ebpf` is declared in `crates/synvoid-icmp-filter/Cargo.toml`; the root feature that enables the crate is `icmp-filter`
- **Runtime constraints**: Requires Linux kernel with BTF support, CAP_NET_ADMIN or root, pre-compiled eBPF ELF bytecode, and `tc` CLI
- **Graceful degradation**: Returns `Err(IcmpFilterError::FeatureNotEnabled)` at runtime when eBPF is unavailable, falls back to nftables
- **Not in default profile**: Must be explicitly enabled on the crate (`-p synvoid-icmp-filter --features icmp-ebpf`)
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
| `synvoid-icmp-filter` eBPF (`icmp-ebpf`) | **Beta** — compiles, runtime fallback | eBPF requires kernel BTF + root; nftables fallback always available |
| `cargo check --workspace --all-features` | **Fails**, on `synvoid-metrics` | `synvoid-metrics` declares an empty `rkyv` feature (`crates/synvoid-metrics/Cargo.toml:11`) with no optional `rkyv` dependency, while `payloads.rs:53` derives `rkyv::Archive` under `cfg_attr(feature = "rkyv")`. **Not** an eBPF/dep-resolution problem |
| `--all-features` (root package) | **Passes** | `cargo metadata --all-features` exits 0 and root `cargo check --all-features` compiles clean |
| `synvoid-icmp-filter` with `icmp-ebpf` | **Compiles clean** | `cargo check -p synvoid-icmp-filter --features icmp-ebpf` succeeds; the Beta classification is a runtime-support limit (kernel BTF + root), not a build failure. Note `icmp-ebpf` is a feature of `crates/synvoid-icmp-filter`, not a root feature |
| wasmtime 48.0.3 (via yara-x 1.20 compat fork) | **Tracked** — 2 advisory ignores in deny.toml (`rsa` 0071, `rkyv` 0235) | Used for YARA compilation only, not wasm sandbox. Both wasmtime lines version-patched for RUSTSEC-2026-0269/0315/0316 + 2026-04 batch. Re-audit: 2026-11-01 |

## CI Enforcement

The single routine CI workflow (`ci.yml`) declares **4 jobs**: `ci` (runs `cargo xtask verify` on every pull request and push to `main`), `dependency-security` (`cargo deny check` + `cargo audit`, also on a daily schedule), and two `workflow_dispatch`-only native-qualification jobs — `sandbox-native-qualification` and `icmp-native-qualification`.

The `ci` job enforces:

| Property | Command in `verify` |
|----------|---------------------|
| Formatting | `cargo fmt --all -- --check` |
| Lint (ci profile) | `cargo clippy --profile ci --all-targets -- -D warnings` |
| Dependency policy | `cargo deny check` |
| Core profile compilation | `cargo check --no-default-features --profile ci` |
| Architecture guards | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` |
| Security regression | `cargo test --test security_regression --profile ci -- --test-threads=1` |
| 23 root guard tests | consolidated nextest invocation (`--features mesh`) |
| synvoid-core admin/mesh | consolidated nextest invocation (`admin_auth_boundary`, `mesh_admin_edge_cases`) |
| Admin route contract | consolidated nextest invocation (`--features mesh,dns,icmp-filter`) |
| Failure injection | `cargo test --test failure_injection --profile ci` |

Full profile matrix verification (all five feature profiles) is available locally via `cargo xtask verify-full`. Release verification with package inspection is available via `cargo xtask verify-release`. See `docs/testing/verification-contract.md` for the complete specification.
