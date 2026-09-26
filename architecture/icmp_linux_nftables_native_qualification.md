# ICMP Linux nftables Native Qualification

Status: **NATIVE ATTEMPT PENDING / UNQUALIFIED** (2026-09-26). The original
macOS preflight was blocked; an opt-in workflow-dispatch lane now attempts
the complete two-run matrix on a disposable GitHub-hosted Linux VM. No native
proof exists until that exact-SHA run completes successfully.

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

The macOS preflight is **BLOCKED**, not passed. The manual workflow attempt
is pending; Linux nftables retains its prior unqualified evidence tier until
the full matrix and artifact review pass. eBPF, PF, WFP, Windows Firewall and
other platform tiers are unchanged. Phase 88 extraction disposition remains
**RETAIN**.

The manual workflow is `icmp-native-qualification` in `.github/workflows/ci.yml`
and is dispatched with `icmp_native_qualification=true`. It runs two complete
native passes with distinct run IDs, proves packet behavior and owned-state
readback, verifies cleanup after each, and uploads bounded JSON artifacts.
Record the exact run and artifact details here before changing the support
tier.

## Workflow attempt history

Run `36275026606` at SHA
`c9861c2f4e7f1c25f6e8c9313af9be716bb8907f` used an Ubuntu 24.04 x86_64
GitHub-hosted runner. Tool installation and host recording succeeded, but
preflight stopped at the root command with `env: 'cargo': No such file or
directory`: `sudo` reset the runner's Cargo path. No topology preflight,
native run, or evidence artifact was produced. This is a workflow handoff
failure, not a native qualification result. The workflow now calls Cargo by
absolute path and explicitly carries the runner Cargo/Rustup environment; a
new exact-SHA attempt is required.
