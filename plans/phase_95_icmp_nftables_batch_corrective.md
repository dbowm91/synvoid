# Phase 95 Plan: ICMP nftables Replacement Batch Corrective

Status: **PLANNED** (2026-09-26), triggered by Phase 93's native backend
failure.

Registered in: `plans/roadmap.md` and
`plans/icmp_linux_native_qualification_gate_roadmap.md`.

Plan baseline: Phase 93 failed on exact attempt
`36279326809` at SHA `947e4f707cc5aefa9aca78a15b19d6ecfc8c04d4`.

Depends on: Phase 93 **FAILED — BACKEND DEFECT FOUND**.

## Finding

The Phase 93 disposable Ubuntu 24.04.5 x86_64 runner passed Linux/tool/root
preflight (`cap_net_admin=true`) and the zero-mutation dry-run. Its native
nftables matrix failed **0/8** cases with nft parser syntax errors while
applying the replacement ruleset. The current backend emits a
`flush table inet ...` command followed by declarative
`table inet ... { ... }` syntax in `crates/synvoid-icmp-filter/src/nftables.rs`.
Native batch parsing rejected this composition; correct it without reducing
the Phase 93 behavioral matrix or replacement atomicity.

The attempt did not upload machine-readable JSON because the workflow's
relative evidence path resolved from the crate test working directory. The
workflow has been corrected to pass an absolute workspace path and to run
prefix-scoped cleanup after a native pass even when the matrix exits nonzero.

## Scope and acceptance

1. Render an nftables batch that is valid on the supported Linux nftables
   version and preserves atomic replacement semantics. Do not flush or remove
   unrelated tables, chains, rules, or host firewall state.
2. Add deterministic tests for the exact batch grammar used by install,
   replacement, disable, drift repair, and rollback. Tests must reject the
   previously failing `flush table` plus declarative table composition.
3. Run the complete `synvoid-icmp-filter` package suite and repository
   verification.
4. On a disposable privileged Linux host, run the complete Phase 93 native
   matrix twice with distinct run IDs. Require 8/8 cases per pass, exact
   owned-state readback, packet behavior, replacement, drift, disable,
   rollback, and cleanup after each pass.
5. Upload both bounded JSON artifacts at the workspace artifact path even
   when a run fails. Verify the workflow invokes cleanup after a failing
   matrix before propagating its exit status.
6. Reconcile `architecture/icmp_linux_nftables_native_qualification.md`, the
   Phase 93 disposition, this plan, and the root roadmap. Phase 93 may be
   superseded as **QUALIFIED** only after the full exact-SHA two-run proof.

## Constraints

- Phase 88 remains **RETAIN** until its independent re-evaluation trigger is
  satisfied; Linux nftables qualification alone does not authorize extraction.
- No Linux proof upgrades eBPF, PF, WFP, Windows Firewall, or other platform
  evidence tiers.
- Keep the native lane manual and opt-in; routine CI remains non-privileged.
- A preflight refusal or missing artifact is never a pass.
- Do not weaken the matrix, issue standalone shell firewall commands outside
  the harness namespace, or claim support on unsupported platforms.
