---
name: ebpf_blocking
description: eBPF-based SYN-level traffic dropping and block store integration for kernel-level IP blocking.
---

# eBPF SYN-Level Dropping and Block Store Integration

## Overview

The eBPF SYN-level dropping feature allows blocking IPs at the network driver level before they consume any userspace memory. This is implemented via XDP (eXpress Data Path) in the `ebpf-flood` crate.

## Key Files

- `ebpf-flood/src/maps.rs` - eBPF map definitions
- `ebpf-flood/src/xdp.rs` - XDP program for SYN filtering and blocklist checking
- `crates/synvoid-block-store/src/lib.rs` - Canonical block store (`BlockStore`,
  `block_ip_with_provenance`); `src/block_store.rs` is only a compat re-export facade
- `crates/synvoid-icmp-filter/src/ebpf.rs` - eBPF backend for ICMP filtering
  (see `icmp_filter` skill for the per-protocol backend)

## Architecture

### eBPF Maps

```rust
// IPv4 blocklist map (65536 entries)
#[map]
pub static IP_BLOCKLIST_V4: HashMap<Ipv4Key, u8> = HashMap::with_max_entries(65536, 0);

// IPv6 blocklist map (16384 entries)
#[map]
pub static IP_BLOCKLIST_V6: HashMap<Ipv6Key, u8> = HashMap::with_max_entries(16384, 0);
```

### XDP Filter Flow

```
filter_syn()
    ├── Check config.enabled → XDP_PASS if disabled
    ├── Check IP_BLOCKLIST_V4/V6 → XDP_DROP if found
    ├── Check global rate limit → XDP_DROP if exceeded
    └── Check per-IP rate limit → XDP_DROP if exceeded
                              └── XDP_PASS (allow)
```

### Block Store Hook (current status — read before copying old snippets)

The `GlobalBlockHook` type alias (`Arc<dyn Fn(IpAddr) + Send + Sync>`) still
exists at `crates/synvoid-block-store/src/lib.rs:33`, but **no setter, field, or
call site references it anywhere in `crates/`, `src/`, or `tests/`** — the old
`BlockStore::set_ebpf_block_hook()` / `ebpf_block_hook` wiring was removed
during modularization. Do NOT add a `set_ebpf_block_hook` method or a
`src/block_store.rs` inherent impl; `src/block_store.rs` is a pure re-export
facade.

Canonical write path for new code (see `block_store` skill):

```rust
use synvoid_block_store::{BlockProvenance, BlockProvenanceKind};

let provenance = BlockProvenance {
    kind: BlockProvenanceKind::LocalWaf, // or the matching kind — never invent one
    source: None,
};
store.block_ip_with_provenance(ip, reason, ttl_secs, site_scope, provenance);
```

`BlockProvenanceKind::LegacyUnknown` is reserved for compat/tests/mocks only.
Kernel-map synchronization for eBPF backends, if needed, must be built as an
explicit subscriber of blocklist events (see `BlocklistEvent`), not as a hidden
hook inside `BlockStore`.

## Integration Pattern (reference — userspace eBPF map sync)

The eBPF hook requires a separate userspace component that:
1. Loads the eBPF program and maps using `aya`
2. Registers a callback with `BlockStore::set_ebpf_block_hook()`
3. The callback inserts blocked IPs into the kernel maps

Example userspace integration:
```rust
use aya::maps::HashMap;
use aya::programs::Xdp;

fn setup_ebpf_blocking() {
    let mut blocklist_v4: HashMap<_, Ipv4Key, u8> = // ... load from Aya
    let mut blocklist_v6: HashMap<_, Ipv6Key, u8> = // ... load from Aya

    let hook = Arc::new(move |ip: IpAddr| {
        match ip {
            IpAddr::V4(v4) => {
                let key = Ipv4Key { addr: v4.to_u32() };
                let _ = blocklist_v4.insert(&key, &1, 0);
            }
            IpAddr::V6(v6) => {
                let key = Ipv6Key { addr: v6.octets() };
                let _ = blocklist_v6.insert(&key, &1, 0);
            }
        }
    });

    block_store.set_ebpf_block_hook(hook);
}
```

## Verification Commands

```bash
# Build eBPF program (requires Aya tooling)
cargo build --package ebpf-flood

# Check userspace compilation
cargo check --profile ci

# Run block-store tests
cargo nextest run -p synvoid-block-store --cargo-profile ci --profile ci
```

## Performance Impact

Dropping at XDP level vs userspace:
- XDP DROP: ~50-100 ns per packet
- Userspace block: ~1000-5000 ns per packet
- **100x improvement** in packet processing overhead

At 1M RPS with 10% blocked IPs (illustrative capacity arithmetic, not a
measured throughput claim):
- Without eBPF: 50ms/sec overhead from blocking
- With eBPF: 0.5ms/sec overhead from blocking

## Related Skills

- `ipc_hardening` - IPC security patterns