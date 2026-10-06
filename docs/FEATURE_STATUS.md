# Feature Status

This document tracks the status of all SynVoid features for the 1.1.0 release. Features are classified as **Supported** (production-ready, tested in CI) or **Beta** (functional, limited real-world validation).

## Supported Features

These features are included in the default build profile and are production-ready.

| Feature | Flag | Description | CI Tested |
|---------|------|-------------|-----------|
| Socket Handoff | `socket-handoff` | Graceful connection migration via FD passing | Yes |
| Mesh Networking | `mesh` | DHT-based service discovery, transport lifecycle, Raft consensus | Yes |
| DNS Server | `dns` | Authoritative DNS with DNSSEC, TSIG, encrypted transports; deferred config capabilities reject activation | Yes |
| Erased Pool | `erased_pool` | Type-erased HTTP/2 connection pooling | Yes |
| Swagger UI | `swagger-ui` | API documentation UI (disable in production) | Yes |

### Additional Supported Features

These features are supported but not in the default profile. Enable them via feature flags.

| Feature | Flag | Description | Platform |
|---------|------|-------------|----------|
| WireGuard | `wireguard` | WireGuard VPN tunnel for mesh transport | Linux, macOS, FreeBSD |
| ICMP Filter | `icmp-filter` | ICMP flood filtering (nftables baseline; PF/WFP lanes per-crate) | Linux, macOS, FreeBSD, OpenBSD, Windows (NetBSD explicitly unsupported: native filter is NPF, a future backend) |
| Origin Key Exchange | `origin_key_exchange` | Signed HTTP integrity verification | All |
| Audit Logging | `audit` | Audit logging for admin mutations | All |
| TUN Device | `tun-rs` | TUN device support | Linux, macOS |
| Buffer Pool | `buffer` | Sharded buffer pool with ABA-safe design | All |
| rkyv Serialization | `rkyv` | Zero-copy serialization for DNS/DHT types | All |
| FastCGI Streaming | `fastcgi_streaming` | Streaming FastCGI response handling | All |
| Flood eBPF | `flood-ebpf` | XDP SYN-level dropping via `ebpf-flood` (needs Aya tooling + CAP_NET_ADMIN/root) | Linux |
| DNS HSM | `dns-hsm` | Opt-in PKCS#11/HSM backing for DNSSEC via the keystore custody boundary (off by default: no `cryptoki` in graph) | All (with HSM) |
| GeoIP | none (config-gated) | `[geoip]` section in `main.toml`, default-disabled. Composition builds the provider and threads it into the DNS construction path as of Phase 138. **No DNS firewall rule can be declared yet** — `DnsFirewallConfig` has no `rules` field — so the capability is present but not yet consumed by any rule. Enabled with no usable database logs a warning rather than refusing to start | All |
| Unsafe Native Extensions | `unsafe-native-extensions` | Opt-in in-process native extensions (compile gate PLUS runtime gates: disabled by default, risk acknowledgement + path allowlist; NOT sandboxed) | All |

### DNS Firewall: Internal-Client Blocking

`[dns.firewall] block_internal_ips = true` installs **8** `Subnet`/`Block` rules:

| id | target |
|----|--------|
| `block_internal_ips` | `10.0.0.0/8` |
| `block_private_172` | `172.16.0.0/12` |
| `block_private_192` | `192.168.0.0/16` |
| `block_loopback` | `127.0.0.0/8` |
| `block_linklocal` | `169.254.0.0/16` |
| `block_ipv6_loopback` | `::1/128` |
| `block_ipv6_ula` | `fc00::/7` |
| `block_ipv6_linklocal` | `fe80::/10` |

This is correct for the shipped public authoritative profile
(`examples/dns/authoritative_public.toml`), but three things are worth knowing:

- **Loopback is included and is not separately controllable.** There is no knob
  to exempt `127.0.0.0/8` or `::1/128`; they are inseparable from the other seven.
  One flag governs all eight.
- **The failure mode is silence.** The block happens at firewall admission, so a
  refused client sees **no SERVFAIL and no REFUSED** — just no answer at all. A
  timeout or an empty response is the expected symptom.
- **Local verification needs an in-memory override, not a config flag.** Any
  harness that queries over loopback must override `block_internal_ips` to
  `false` in the parsed `DnsConfig` value while leaving the shipped file and its
  zone data unchanged. `tests/dns_zone_startup_activation.rs` does exactly this
  and asserts both directions.

`[dns.firewall] block_zone_transfers = true` is separate and installs a ninth
rule, `block_axfr` (opcode `0x2`). These nine rules are defined in exactly one
place, `DnsServer::new`; there is no separate "default rules" list.

## Beta Features

These features compile cleanly but have limited real-world validation or hard runtime constraints. They are **not** in the default build profile.

| Feature | Flag | Platform Requirement | Runtime Constraints | Known Gaps |
|---------|------|---------------------|---------------------|------------|
| eBPF ICMP Filter | `icmp-ebpf` | Linux only | Requires kernel BTF, CAP_NET_ADMIN or root, precompiled eBPF object | Falls back to nftables when unavailable; integration tests require BTF-capable kernel |
| Post-Quantum TLS | `post-quantum` | Any | Experimental TLS key exchange | Limited real-world validation |
| Post-Quantum Verify | `verify-pq` | Any | Post-quantum signature verification | Limited real-world validation |
| macOS Sandbox | `macos-sandbox` | macOS only | Seatbelt via deprecated `sandbox_init` (opt-in experimental; not App Sandbox; Linux is production strict-isolation target) | Native child-process tests on macOS host only; cross-compile is not enforcement evidence |

### Beta Feature Build Commands

```bash
# eBPF ICMP filter (Beta)
cargo build --release -p synvoid-icmp-filter --features icmp-ebpf

# Post-quantum TLS (Beta)
cargo build --release --features post-quantum

# Post-quantum verification (Beta)
cargo build --release --features verify-pq

# NOTE: never treat --all-features as a build profile —
# `cargo check --all-features` is a tracked exception (see docs/RELEASE.md §9:
# synvoid-icmp-filter eBPF resolution). Enable Beta features individually.
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
