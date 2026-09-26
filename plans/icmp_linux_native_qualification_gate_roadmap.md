# ICMP Linux Native Qualification Gate Roadmap (Phases 92–93)

Status: Phase 92 **CORRECTED**; Phase 93 **BLOCKED** on 2026-09-26.

Registered in: `plans/roadmap.md`.

Baseline: `main` at `826e634d7b9475c7b0b44badd2f51f07df6ddd17`.

Predecessors:

- Phases 85–88: closed **RETAIN**;
- Phase 90: operator enforcement truth closed;
- Phase 91: privileged native qualification harness preparation closed,
  with no privileged run available.

This roadmap exists to remove the remaining lifecycle correctness blockers
before using the Phase 91 harness for real Linux nftables qualification.

It does **not** reopen extraction/publication. A successful Phase 93 satisfies
only the Linux nftables native-proof trigger recorded by Phase 88.

## Why a corrective gate is required

Post-Phase-91 review found four lifecycle semantics that should be corrected
before treating the native harness as qualification evidence.

1. `drive_update()` treats `VerificationOutcome::Absent` as failure
   unconditionally. For a replacement whose requested config has
   `enabled = false`, correct backend behavior is to remove owned rules and
   verify `Absent`; the current driver reports that correct result as drift.
2. `verify_live()` always records `Absent` as
   `last_verify_error = "owned objects absent"`. When the committed desired
   state is disabled, absence is healthy and should clear the error.
3. Driver desired fields are mutated before an operation is known to succeed.
   A rejected config update, failed enable, or failed disable can therefore
   leave operator-visible desired state describing a request that the admin
   mutation reported as failed and did not persist.
4. Repeated enable is described as idempotent, but the
   `AlreadyEnabled -> verify -> receipt` path advances generation and creates
   a new apply receipt even though no install occurred.

There is also a documentation registry defect: the dedicated Phase 90–91
roadmap is closed, while the central roadmap section still says
`Phases 90–91 Planned`.

## Execution order

### Phase 92 — Disabled-State and Lifecycle Commit Semantics Corrective

Plan:
`plans/phase_92_icmp_disabled_state_lifecycle_corrective.md`.

Correct the update result matrix, make committed desired state transactional,
make live verification desired-state-aware, define idempotent no-op behavior,
seed initial desired state truthfully, and reconcile the Phase 90–91 registry.

### Phase 93 — Linux nftables Native Qualification

Plan:
`plans/phase_93_icmp_linux_nftables_native_qualification.md`.

After Phase 92 closes, execute the Phase 91 harness on a suitable privileged
Linux host, collect proof-bearing artifacts, independently verify cleanup and
repeatability, and update the Linux nftables evidence tier according to the
observed result.

Phase 93 may remain blocked if no qualifying Linux host is available. Lack of
a host is not a passing qualification result.

## Binding constraints

1. Phase 88 RETAIN remains authoritative.
2. No public crate/repository is created.
3. No fake apply receipt may represent a disabled/absent state or an
   idempotent no-op.
4. Committed driver desired state may not change on a failed mutation unless a
   separately modeled pending/attempted state is introduced and clearly kept
   distinct from committed desired state.
5. `desired_enabled = false` + verified `Absent` is healthy success.
6. `desired_enabled = true` + `Absent` remains an enforcement failure.
7. Qualification must use the Phase 91 disposable netns/veth harness and may
   not touch the host/default firewall namespace.
8. A skipped, refused, or unavailable privileged run is **unqualified**, not
   passed.
9. Linux nftables qualification does not imply eBPF/PF/WFP/Windows-Firewall
   qualification.
10. Qualification evidence and support-tier changes must be tied to an exact
    proof-bearing SHA.

## Terminal outcomes

Phase 92 must close **CORRECTED** before Phase 93 executes.

Phase 93 records exactly one of:

- **QUALIFIED** — all required native cases pass on a suitable Linux host,
  cleanup/repeatability are proven, and Linux nftables may move to the
  repository's native-supported evidence tier;
- **FAILED** — the harness exposed a product/backend defect; register a focused
  corrective rather than weakening the matrix;
- **BLOCKED** — no suitable host/prerequisite is available; retain the current
  evidence tier.

None of these outcomes alone authorizes extraction or publication.

## Execution update (2026-09-26)

Phase 92 is closed CORRECTED; see
`plans/phase_92_icmp_disabled_state_lifecycle_corrective.md`.
Phase 93 preflight ran on Darwin/macOS and refused as designed because the
host is not Linux, `ip` and `nft` are absent, and root/CAP_NET_ADMIN access
for the required network namespace run is unavailable. The zero-mutation
dry-run passed and listed only prefix-scoped `synvoid-q-*` namespace and
veth resources. No native run or evidence artifact was produced. Phase 93 is
therefore **BLOCKED**, and Linux nftables remains unqualified at its existing
evidence tier. See
`architecture/icmp_linux_nftables_native_qualification.md`.
