# eBPF ICMP Filter

This crate contains the eBPF program for ICMP filtering. It must be compiled on Linux with the proper toolchain.

## Building

### Prerequisites

1. Install the bpf-linker:
   ```bash
   cargo install bpf-linker
   ```

2.el-unknown-none Install the bpf target:
   ```bash
   rustup target add bpfel-unknown-none --toolchain nightly
   ```

### Compilation

Build the eBPF program:

```bash
cd ebpf-icmp
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

The compiled eBPF bytecode will be at:
`target/bpfel-unknown-none/release/synvoid-icmp`

## Architecture

- `xdp.rs` - XDP program for inbound ICMP filtering
- `tc.rs` - TC classifier for outbound ICMP filtering
- `maps.rs` - BPF map definitions (config, exempt IPs, stats, token bucket, type rules)
- `token_bucket.rs` - eBPF-native token bucket rate limiter
- `icmp.rs` - ICMP packet parsing utilities (shared between XDP and TC)

## Features

- **ICMP Type/Code Filtering**: Filter specific ICMP types (e.g., block echo-request but allow echo-reply)
- **Rate Limiting**: Token bucket rate limiting with configurable packets/second and burst
- **Exempt IPs**: Whitelist specific IP addresses from filtering
- **Dual Stack**: Supports both IPv4 and IPv6
- **Directional Filtering**: Separate controls for inbound (XDP) and outbound (TC) filtering

## Maps

| Map | Type | Purpose |
|-----|------|---------|
| `config_map` | Array | Filter configuration (enabled, rate limits, block_all mode) |
| `exempt_ipv4` | HashMap | Exempt IPv4 addresses |
| `exempt_ipv6` | HashMap | Exempt IPv6 addresses |
| `stats_inbound` | PerCpuArray | Inbound packet statistics |
| `stats_outbound` | PerCpuArray | Outbound packet statistics |
| `token_bucket_inbound` | PerCpuArray | Token bucket state for inbound |
| `token_bucket_outbound` | PerCpuArray | Token bucket state for outbound |
| `icmp_type_rules_v4` | Array | ICMPv4 type/code rules (max 32) |
| `icmp_type_rules_v6` | Array | ICMPv6 type/code rules (max 32) |

## Limitations

- **Rate Limiting**: Per-CPU token buckets mean bursts distributed across CPUs may exceed rate limits slightly
- **Kernel Requirements**: Requires Linux kernel with XDP and TC support
- **Privileges**: Requires root/CAP_NET_ADMIN to load eBPF programs
