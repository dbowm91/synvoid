# ICMP Linux nftables Native Qualification

Status: **BLOCKED / UNQUALIFIED** (2026-09-26). This record documents the
Phase 93 host preflight only; no privileged qualification run occurred.

Plan: `plans/phase_93_icmp_linux_nftables_native_qualification.md`.
Gate roadmap: `plans/icmp_linux_native_qualification_gate_roadmap.md`.
Phase 92 lifecycle prerequisite: **CORRECTED**.

## Host and preflight

- Host: Darwin/macOS (`x86_64` process on Apple Silicon), kernel
  `25.6.0 Darwin Kernel Version 25.6.0`.
- Required Linux kernel, network namespaces, root/CAP_NET_ADMIN,
  `ip`, and `nft`: unavailable. `ping` is present.
- `cargo xtask icmp-qualify --check`: **REFUSED**, nonzero exit as designed;
  refusal reasons were non-Linux host, missing native opt-in, insufficient
  privilege, missing `ip`, and missing `nft`.
- `cargo xtask icmp-qualify --dry-run`: **PASS**, zero mutation. It listed
  prefix-scoped `synvoid-q-*` namespaces, `svqa-*`/`svqb-*` veth devices,
  and owned `synvoid_q_*` nft table, with planned cleanup. No resource was
  spawned.
- Native runs, packet observations, generation/readback observations,
  cleanup checks, and machine-readable native artifacts: **NOT RUN**.
- Native run IDs / proof-bearing SHA / nft and Rust native-host versions:
  not applicable; no proof-bearing native execution took place.

## Disposition

Phase 93 is **BLOCKED**, not passed. Linux nftables retains its prior
unqualified evidence tier. eBPF, PF, WFP, Windows Firewall and other platform
tiers are unchanged. Phase 88 extraction disposition remains **RETAIN**.

Resume on a suitable disposable Linux host. Run both complete native passes
with distinct run IDs, prove packet behavior and owned-state readback, verify
cleanup after each, and attach both bounded artifacts here before changing
the support tier.
