---
name: ebpf_blocking
description: eBPF-based SYN-level traffic dropping and block store integration for kernel-level IP blocking.
---

# eBPF SYN-Level Dropping and Block Store Integration

## Overview

The eBPF SYN-level dropping feature allows blocking IPs at the network driver level before they consume any userspace memory. This is implemented via XDP (eXpress Data Path) in the `ebpf-flood/` crate.

**Read this first — the capability is real but OFF by default and currently unwired.**
It is split across two halves that do *not* share a dependency:

| Half | Location | Status |
|---|---|---|
| Kernel program + maps | `ebpf-flood/` (package `synvoid-ebpf-flood`, `aya-ebpf` 0.1) | built separately; **not a workspace member** |
| Userspace loader | `src/waf/flood/ebpf_flood.rs` (`EbpfFlood`, `aya` 0.13) | `#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]` via `src/waf/flood/mod.rs` |

`flood-ebpf` is **not** in the root `default` feature set
(`["socket-handoff", "mesh", "dns", "erased_pool", "swagger-ui"]`), and
`EbpfFlood` has **no construction site anywhere in `src/` or `crates/`** outside
its own module. The capability is therefore built but never reached at runtime.
Admin capability reporting only reflects the compile-time flag
(`crates/synvoid-admin/src/handlers/system.rs`), never a loaded program.

## Key Files

- `ebpf-flood/src/maps.rs` - eBPF map definitions
- `ebpf-flood/src/xdp.rs` - XDP program for SYN filtering and blocklist checking
  (`filter_syn`, the `#[xdp]` entry point)
- `src/waf/flood/ebpf_flood.rs` - userspace loader/attacher: `EbpfFlood::{new,
  is_available, enable, disable, block_ip, unblock_ip, get_stats, update_config,
  check_syn, register_half_open, register_ack, complete_half_open, is_ebpf_loaded}`
- `src/waf/flood/mod.rs` - the `linux` + `flood-ebpf` gate
- `crates/synvoid-block-store/src/lib.rs` - Canonical block store (`BlockStore`,
  `block_ip_with_provenance`); `src/block_store.rs` is only a compat re-export facade
- `crates/synvoid-icmp-filter/src/ebpf.rs` - eBPF backend for ICMP filtering
  (separate program, `icmp-ebpf` feature — see the `icmp_filter` skill for the
  per-protocol backend)

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

The kernel-map write path is `EbpfFlood::block_ip` / `unblock_ip`, reached only
by constructing an `EbpfFlood` and enabling it. There is **no
`BlockStore::set_ebpf_block_hook()`** and no `GlobalBlockHook` call site — that
API was removed during modularization (see the block store hook section above).
Do not resurrect it. If blocklist sync is ever wired, it must be an explicit
subscriber of blocklist events that calls `block_ip`, not a hidden hook inside
`BlockStore`.

Reference shape of the userspace side (mirrors `src/waf/flood/ebpf_flood.rs`,
which uses `aya::maps::HashMap` via the `AyaHashMap` alias):
```rust
use aya::maps::HashMap;
use aya::programs::Xdp;

fn setup_ebpf_blocking(/* ... */) {
    let mut blocklist_v4: HashMap<_, Ipv4Key, u8> = // ... load from Aya
    let mut blocklist_v6: HashMap<_, Ipv6Key, u8> = // ... load from Aya

    // Blocked IPs are pushed by EbpfFlood::block_ip(ip), which writes
    // IP_BLOCKLIST_V4 / IP_BLOCKLIST_V6 keyed by the client's address.
    let _ = blocklist_v4.insert(&key, &1, 0);
    let _ = blocklist_v6.insert(&key, &1, 0);
}
```

## Verification Commands

```bash
# Build the kernel program — it is OUTSIDE the cargo workspace,
# so build from its own directory. The package is named
# `synvoid-ebpf-flood`; there is no `ebpf-flood` package id.
(cd ebpf-flood && cargo build)

# Check the userspace half compiles under the feature (needs Linux
# for the cfg; on non-Linux this module is compiled out entirely)
cargo check --profile ci --features flood-ebpf

# Run block-store tests
cargo nextest run -p synvoid-block-store --cargo-profile ci --profile ci
```

## Performance Impact

Dropping at XDP level vs userspace — **order-of-magnitude estimates only**.
Nothing here is a measured SynVoid figure, and the capability is currently
unwired, so treat these as design rationale rather than a result:
- XDP DROP: ~50-100 ns per packet
- Userspace block: ~1000-5000 ns per packet
- That is roughly a **10x-100x** difference, not a single 100x factor

Arithmetic sanity check (illustrative, not a throughput claim): at 1M pps with
10% of packets dropped, 100k drops/sec costs roughly 100-500 ms/sec in userspace
versus 5-10 ms/sec in XDP.

## Related Skills

- `icmp_filter` — the separate `icmp-ebpf` backend
- `block_store` — canonical blocklist write path