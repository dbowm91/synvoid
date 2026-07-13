# Feature Status

This document tracks the status of all SynVoid features for the 1.1.0 release. Features are classified as **Supported** (production-ready, tested in CI) or **Beta** (functional, limited real-world validation).

## Supported Features

These features are included in the default build profile and are production-ready.

| Feature | Flag | Description | CI Tested |
|---------|------|-------------|-----------|
| Socket Handoff | `socket-handoff` | Graceful connection migration via FD passing | Yes |
| Mesh Networking | `mesh` | DHT-based service discovery, transport lifecycle, Raft consensus | Yes |
| DNS Server | `dns` | Authoritative DNS with DNSSEC, TSIG, encrypted transports | Yes |
| Erased Pool | `erased_pool` | Type-erased HTTP/2 connection pooling | Yes |
| Swagger UI | `swagger-ui` | API documentation UI (disable in production) | Yes |

### Additional Supported Features

These features are supported but not in the default profile. Enable them via feature flags.

| Feature | Flag | Description | Platform |
|---------|------|-------------|----------|
| WireGuard | `wireguard` | WireGuard VPN tunnel for mesh transport | Linux, macOS, FreeBSD |
| ICMP Filter | `icmp-filter` | ICMP flood filtering (nftables/pf/winfw) | Linux, macOS, FreeBSD, Windows |
| Origin Key Exchange | `origin_key_exchange` | Signed HTTP integrity verification | All |
| Audit Logging | `audit` | Audit logging for admin mutations | All |
| TUN Device | `tun-rs` | TUN device support | Linux, macOS |
| Buffer Pool | `buffer` | Sharded buffer pool with ABA-safe design | All |
| rkyv Serialization | `rkyv` | Zero-copy serialization for DNS/DHT types | All |
| macOS Sandbox | `macos-sandbox` | macOS sandbox enforcement | macOS only |
| FastCGI Streaming | `fastcgi_streaming` | Streaming FastCGI response handling | All |

## Beta Features

These features compile cleanly but have limited real-world validation or hard runtime constraints. They are **not** in the default build profile.

| Feature | Flag | Platform Requirement | Runtime Constraints | Known Gaps |
|---------|------|---------------------|---------------------|------------|
| eBPF ICMP Filter | `icmp-ebpf` | Linux only | Requires kernel BTF, CAP_NET_ADMIN or root, precompiled eBPF object | Falls back to nftables when unavailable; integration tests require BTF-capable kernel |
| Post-Quantum TLS | `post-quantum` | Any | Experimental TLS key exchange | Limited real-world validation |
| Post-Quantum Verify | `verify-pq` | Any | Post-quantum signature verification | Limited real-world validation |

### Beta Feature Build Commands

```bash
# eBPF ICMP filter (Beta)
cargo build --release -p synvoid-icmp-filter --features icmp-ebpf

# Post-quantum TLS (Beta)
cargo build --release --features post-quantum

# Post-quantum verification (Beta)
cargo build --release --features verify-pq

# All features including Beta
cargo build --release --all-features
```

### Beta Feature Runtime Requirements

#### eBPF ICMP Filter (`icmp-ebpf`)

- **Platform**: Linux only
- **Kernel**: 5.8+ with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- **Privileges**: Root or `CAP_NET_ADMIN` + `CAP_BPF`
- **Fallback**: When eBPF is unavailable, falls back to nftables-based ICMP filtering
- **Build**: Requires `synvoid-icmp-filter` crate with `icmp-ebpf` feature

#### Post-Quantum Features (`post-quantum`, `verify-pq`)

- **Platform**: All supported platforms
- **Status**: Functional but limited real-world validation
- **TLS**: Hybrid ML-KEM-768 + Ed25519 key exchange via `aws-lc-rs`
- **Verification**: ML-DSA-65/87 signature verification via `libcrux-ml-dsa`

## Promotion Criteria

A Beta feature may be promoted to Supported when:

1. **Integration tests pass** in a representative environment (e.g., Linux with BTF for eBPF)
2. **Runtime constraints are documented** and validated
3. **Fallback behavior is tested** and verified
4. **Metrics and error reporting** are validated under real conditions
5. **Operational runbook** exists for operators
6. **No known blocking issues** remain in the issue tracker

### eBPF Promotion Checklist

- [ ] Integration test on Linux with BTF + root-capable environment
- [ ] Verified XDP/TC attach/detach lifecycle
- [ ] Verified fallback path to nftables
- [ ] Metrics and error reporting validated under real kernel constraints
- [ ] Operational runbook documented
- [ ] No blocking issues in tracker

### Post-Quantum Promotion Checklist

- [ ] Interoperability testing with major TLS libraries
- [ ] Performance benchmarking under realistic workloads
- [ ] Security review of hybrid key exchange implementation
- [ ] Documentation of deployment requirements and limitations

## Unsupported/Experimental Features

These features are not included in any build profile and are not recommended for production use.

| Feature | Status | Notes |
|---------|--------|-------|
| `test-utils` | Test only | Test utilities, not for production |

## See Also

- [`architecture/release_profile_matrix.md`](../architecture/release_profile_matrix.md) — Full compilation profile and feature gate matrix
- [`CHANGELOG.md`](../CHANGELOG.md) — Release history and feature additions
- [`docs/RELEASE.md`](RELEASE.md) — Release process and versioning policy
