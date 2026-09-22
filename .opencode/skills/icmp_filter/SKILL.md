---
name: icmp_filter
description: ICMP filtering backends — nftables, eBPF, pf, WFP — behind a narrow trait. Use when touching L3 filtering, flood backends, or the icmp-filter feature gate.
---

# ICMP Filter

## Overview

`crates/synvoid-icmp-filter/` filters ICMP at L3 with per-OS backends behind
the narrow `IcmpFilter` trait. Root `src/icmp_filter/` is composition only.
Feature-gated: admin contract tests run with `--features mesh,dns,icmp-filter`;
reduced-feature binaries reject capability-bearing `[icmp_filter]` sections
even when inert (`enabled = false`) — Phase 41 fail-closed config.

## Key Files

- `crates/synvoid-icmp-filter/src/traits.rs` - `IcmpFilter`, `IcmpFilterFactory`,
  `FilterBackend`, `BackendCapabilities`, `FilterStatus`
- `crates/synvoid-icmp-filter/src/config.rs` - `IcmpFilterConfig`,
  `InterfaceSpec`, `Direction`, `FilterType`, `RateLimitConfig`
- `crates/synvoid-icmp-filter/src/nftables.rs` - Linux nftables backend
  (default on Linux)
- `crates/synvoid-icmp-filter/src/ebpf.rs` - Linux eBPF backend
  (`icmp-ebpf` feature)
- `crates/synvoid-icmp-filter/src/pf.rs` - macOS pf backend (`icmp-pf` feature)
- `crates/synvoid-icmp-filter/src/pf_bsd.rs` - FreeBSD/OpenBSD/NetBSD pf
- `crates/synvoid-icmp-filter/src/winfw.rs` / `wfp.rs` - Windows backends
  (`icmp-winfw` / `icmp-wfp` features)
- `crates/synvoid-icmp-filter/src/platform.rs` - `has_privilege_for`,
  `required_privilege_for_operation`, `PrivilegeLevel`
- `crates/synvoid-icmp-filter/src/error.rs` - `IcmpFilterError`
- `src/icmp_filter/mod.rs` - Root composition wiring

## Invariants

- **Trait-only consumption**: request/control paths use `IcmpFilter`, never a
  concrete backend type — backend selection is a composition-root decision.
- **Privilege gating**: raw-socket backends check `required_privilege_for_operation`
  first and fail closed without privilege; never silently degrade to no-filter.
- **No `--all-features`**: per audit, `--all-features` is not a deployment
  profile (eBPF resolution conflicts); test backends via their explicit feature.
- **XDP vs userspace**: for SYN-level dropping performance notes (XDP ~50-100ns
  vs userspace), see the `ebpf_blocking` skill.

## Verification

```bash
cargo check --no-default-features --features icmp-filter --profile ci
cargo nextest run -p synvoid-icmp-filter --cargo-profile ci --profile ci
```
