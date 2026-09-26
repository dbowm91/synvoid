# Phase 87 Closeout: ICMP Transactional Enforcement and State Verification

Status: closed 2026-09-26.

Planning baseline: `81638c251592913579bd9bbce51d013c44d67910`.
Implementation SHA: `8ecd81fe3972448b561a4760d05b2339c1e3d5b3`
(built on Phase 86 closeout `a7d21f20`).

Plan: `plans/phase_87_icmp_transactional_enforcement_and_state_verification.md`.
Roadmap: `plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

## Decision

The backend layer is now a compile-before-mutate boundary: every update
compiles completely before kernel mutation, installs through backend
transaction/staging semantics, verifies live owned state, and records
the new generation only on `Verified`. Local `enabled` no longer stands
in for enforcement truth (`EnforcementReport` does).

## Workstream dispositions

- **A (compile first):** `enforce::compile_policy(backend, policy,
  options)` is pure: capability check + backend-option validation to
  `Exact(EnforcementPlan)` / `Unsupported { requirements, reasons }`.
  No degraded-semantics path. `policy_fingerprint` (FNV-1a over canonical
  policy JSON) binds generations; family-sensitive by construction.
- **B (ownership):** `ownership_tag_for` per lane (nft `inet:<table>` +
  `gen_<fp>` marker chain; PF table-scoped anchors; WFP stable
  provider/sublayer GUIDs derived per table; winfw table-scoped rule
  prefix, single-owner-per-table). macOS anchor nesting
  (`synvoid.icmp/<table>`) and winfw prefix scoping are behavior changes
  with best-effort legacy sweeps on disable (documented migration).
  Restart semantics documented per lane (dynamic WFP filters die with the
  session; COM rules persist; nft/PF re-install idempotently; eBPF
  attachments may linger).
- **C (failure-safe replacement):** nft single `nft -f` flush+create batch
  (create-only fallback; old table survives failure); PF single anchor
  load (no remove-then-add gap); WFP one transaction (retire + ensure +
  add, single commit); winfw bounded staged upsert-verify-retire with
  rollback attempt; eBPF prepare-offline then attach with retained-handle
  discipline. All backends swap config only on success (swap-back
  otherwise), so a failed replacement keeps the previous generation.
- **D (desired/applied/verified):** `EnforcementReport { backend,
  desired_fingerprint, desired_generation, last_receipt, live:
  Applied/Absent/Drifted/Unknown, last_verify_error }` on the manager via
  `report()`; `verify_live()` re-probes without changing generations.
  `FilterStatus` stays a compat desired-state view (documented).
- **E (readback/drift):** nft exact (JSON table + hook chains + marker);
  PF presence-plus-cardinality (documented); WFP provider-GUID
  enumeration; winfw per-rule existence; eBPF attachment liveness (map
  content explicitly unverified). Only owned identity is read; unrelated
  operator state tolerated. Unreadable mechanisms yield `Unknown`, never
  false `Applied`.
- **F (lifecycle):** `ensure_enabled`/`ensure_disabled` idempotent
  additions; legacy `enable`/`disable` errors preserved for compat;
  disable-already-absent converges (nft missing-table, PF missing-anchor,
  WFP empty-ID, winfw tracked+sweep all tolerate absence); partial
  cleanup failure is a visible error.
- **G (observability):** packet-outcome counters deleted (zero callers,
  zero backend evidence); lifecycle metrics added
  (`apply_finished_total{backend,result}`,
  `drift_detected_total`, `verification_observed_total{backend,state}`)
  plus retained enabled/status gauges. Core contract returns receipts,
  never requires `metrics`. Per-packet truth stays in backend APIs
  (`EbpfFilter::get_stats`).
- **H (fake tests):** `tests/transactional_enforcement.rs` (7/7) proves
  over the real `drive_update` flow: zero-mutation compile failure,
  apply-failure retention, mutating-commit-failure exposure via readback,
  Drifted/Unknown-never-Applied, visible cleanup failure, idempotent
  disable, receipt/generation fidelity.

## Acceptance mapping

- Updates compile/validate before destructive mutation (all lanes). ✓
- Unsupported semantics fail explicitly (compile + constructors). ✓
- Owned objects namespaced; unrelated rules untouched (tags + sweeps
  scoped; winfw sweep excludes foreign scoped prefixes). ✓
- Transaction/staging + rollback per lane (atomic where platform
  allows; staged + explicit Unknown where not). ✓
- Desired vs verified state separated (`EnforcementReport`). ✓
- Live verification with Applied/Absent/Drifted/Unknown. ✓
- Failure cannot claim the replacement (receipts advance only on
  Verified; verification failure is an error). ✓
- Restart/stale-state behavior specified per lane. ✓
- Packet metrics evidence-backed or removed (removed + lifecycle). ✓
- Deterministic failure-injection suite proves the machine (7/7). ✓

## Verification evidence (implementation head)

- `cargo fmt --all -- --check`: pass.
- `cargo test -p synvoid-icmp-filter --profile ci` (also
  `--features icmp-pf`): 48 lib + 5 truthfulness + 12 canonicalization
  + 7 transactional pass.
- `cargo clippy --profile ci --all-targets -- -D warnings` (workspace):
  pass.
- `cargo check --no-default-features --features icmp-filter
  --profile ci`: pass.
- `cargo test -p synvoid-config --profile ci`: 98 pass.
- Admin contract (`mesh,dns,icmp-filter`): 22 + 18 + 24 pass.
- `cargo xtask test guards`: 3/3 pass.
- Target compile evidence: `x86_64-pc-windows-msvc` + `-gnu` with
  `icmp-wfp,icmp-winfw` (lib + `--tests`); `x86_64-unknown-linux-gnu`
  with and without `icmp-ebpf`. Cross-checks caught real defects
  (Drop-move, `&&[String]` iteration, transaction borrow).
- Native privileged apply/update/readback/drift/cleanup proof: not in
  this phase by plan (ignored/manual harnesses only); Phase 88 records it.

## Residuals / Phase 88 unblocked

- Readback breadth is per-lane honest minimums (PF cardinality, eBPF
  attachment-only, winfw existence-only); strengthening is Phase 88
  evidence work, not a correctness gap.
- WFP weight ordering, GUID stability, and enumerator behavior are
  compile-proven, not natively proven.
- The admin status endpoint still serves the compat desired-state view;
  operator surfacing of `report()` is future work (recorded in
  `architecture/icmp_filter.md` §9).
- Full `cargo xtask verify` end-to-end belongs to Phase 88 campaign
  closeout.
