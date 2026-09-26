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

- `crates/synvoid-icmp-filter/src/policy.rs` - canonical `IcmpPolicy`
  vocabulary (Phase 85 single semantic owner; DTOs convert to it, never JSON)
- `crates/synvoid-icmp-filter/src/compat.rs` - crate-DTO typed adapter
- `crates/synvoid-icmp-filter/src/validation.rs` - RFC 4890/8201 findings
- `crates/synvoid-icmp-filter/src/traits.rs` - `IcmpFilter`, `FilterBackend`,
  static `BackendCapabilities`, `check_policy_compatibility`
- `crates/synvoid-icmp-filter/src/config.rs` - `IcmpFilterConfig`
  serialization DTO (not the semantic owner)
- `crates/synvoid-icmp-filter/src/nftables.rs` - Linux nftables baseline
- `crates/synvoid-icmp-filter/src/ebpf.rs` - Linux eBPF (`icmp-ebpf`)
- `crates/synvoid-icmp-filter/src/pf.rs` - macOS pf (`icmp-pf`)
- `crates/synvoid-icmp-filter/src/pf_bsd.rs` - FreeBSD/OpenBSD pf
  (NetBSD excluded: native filter is NPF, a future backend)
- `crates/synvoid-icmp-filter/src/wfp.rs` - WFP **primary** Windows lane
  (`icmp-wfp`); `winfw.rs` is the COM compatibility fallback (`icmp-winfw`)
- `crates/synvoid-icmp-filter/src/platform.rs` - operation-specific
  `BackendProbe`s, capability parsing, Windows LUID resolution
- `crates/synvoid-icmp-filter/src/error.rs` - `IcmpFilterError`
  (incl. `BackendUnavailable`)
- `src/icmp_filter/adapt.rs` - app-config typed adapter (composition
  boundary); `src/icmp_filter/mod.rs` re-exports the crate

## Invariants

- **Trait-only consumption**: request/control paths use `IcmpFilter`, never a
  concrete backend type — backend selection is a composition-root decision.
- **Strict selection**: explicit backend requests fail (`BackendUnavailable`,
  never silent fallback); only `Auto` falls back, with a `SelectionReport`
  reason (`select_backend_for_host`).
- **Capability vs runtime**: `BackendCapabilities` is static expressiveness;
  runtime truth is `BackendProbe { compiled, mechanism_present, privilege,
  usable, reason }`; policy fit is `check_policy_compatibility` against
  `IcmpPolicy` requirements. Never report `enabled` as kernel proof.
- **Privilege gating**: backends check operation-specific probes first and
  fail closed without privilege; nftables never consults BPF sysctls; no
  low-port checks in ICMP vocabulary.
- **Windows lanes**: WFP primary (transactions, typed ICMP conditions, LUID
  resolution); winfw fallback (no transactions/rate limit/readback).
- **NetBSD**: explicitly unsupported (NPF future); never route through PF.
- **No `--all-features`**: per audit, `--all-features` is not a deployment
  profile (eBPF resolution conflicts); test backends via their explicit feature.
- **XDP vs userspace**: for SYN-level dropping performance notes (XDP ~50-100ns
  vs userspace), see the `ebpf_blocking` skill.

## Verification

```bash
cargo check --no-default-features --features icmp-filter --profile ci
cargo nextest run -p synvoid-icmp-filter --cargo-profile ci --profile ci
```
