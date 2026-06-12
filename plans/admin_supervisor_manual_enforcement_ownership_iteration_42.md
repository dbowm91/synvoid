# Admin/Supervisor Manual Enforcement Ownership — Iteration 42

## Purpose

The threat-intel/WAF/request-path work is now in good shape:

- threat-intel enforcement is policy-gated;
- WAF consumes `BlockStore` rather than raw advisory lookups;
- block entries carry provenance;
- HTTP/3 request/WAF composition is documented and guarded;
- stall concurrency is capped, strict, drop-safe, and documented.

The next architectural plane to clean up is manual and supervisor-driven enforcement.

This pass should audit and tighten ownership for:

- admin ban/unban endpoints;
- supervisor gRPC/manual enforcement actions;
- worker blocklist sync;
- manual vs automated action classification;
- provenance exposure in admin/debug/supervisor responses;
- logging/metrics/auditability of manual enforcement state changes.

The goal is to make manual/supervisor enforcement explicit, auditable, and consistently separated from automated threat-intel/WAF enforcement.

## Current Known State

Known from prior audits:

- `BlockProvenanceKind` includes manual/supervisor-oriented variants such as `AdminManual`, `SupervisorManual`, and `SupervisorSync`.
- Admin IP/mesh-ID ban paths were classified as manual actions, not automated threat-intel enforcement.
- Supervisor gRPC `block_ip` was classified as a manual/supervisor action.
- Worker IPC `BlocklistUpdate` populates `BlockStore` from supervisor sync.
- `block_ip_with_provenance` exists and is preferred for new production writes.
- `LegacyUnknown` should not be used for new production enforcement unless compatibility requires it.

Remaining architectural question:

Manual and supervisor actions are legitimate, but they need a clear ownership model and consistent observability. They should not be confused with policy-gated mesh threat-intel enforcement or local-origin WAF evidence.

## Non-Goals

Do not redesign admin authentication or authorization.

Do not introduce a full event-sourced audit log unless one already exists and can be reused trivially.

Do not change threat-intel policy semantics.

Do not change WAF decision semantics.

Do not add new automated enforcement types.

Do not remove compatibility `block_ip` methods.

Do not add request-path network lookups.

Do not build a broad admin UI.

## Phase 1 — Inventory Manual/Supervisor Enforcement Surfaces

Search and inspect these terms:

- `AdminManual`
- `SupervisorManual`
- `SupervisorSync`
- `block_ip_with_provenance`
- `.block_ip(`
- `ban_ip`
- `ban_mesh`
- `unban`
- `BlocklistUpdate`
- `blocklist`
- `supervisor`
- `mesh_admin`
- `grpc`
- `BlockStoreApi`
- `BlockStoreAdapter`
- `BlockProvenanceKind`
- `LegacyUnknown`

Primary files/directories to inspect:

- `src/admin/handlers/mesh_admin.rs`
- `src/admin/**`
- `src/supervisor/**`
- `src/worker/unified_server/lifecycle.rs`
- `src/worker/unified_server/**`
- `crates/synvoid-block-store/**`
- `crates/synvoid-core/src/block_store.rs`
- `docs/THREAT_INTEL.md`
- `architecture/threat_intel_request_waf_audit.md`
- `AGENTS.md`

Create or update an architecture note:

- `architecture/manual_enforcement_ownership.md`

Include a table with columns:

- surface;
- file/function;
- actor/trigger;
- mutation target;
- provenance kind;
- automated vs manual vs sync;
- response/observability status;
- required action.

## Phase 2 — Define Ownership Rules

Document and enforce the following ownership model:

1. **Admin manual actions** are human/operator initiated and should use `BlockProvenanceKind::AdminManual`.
2. **Supervisor manual actions** are control-plane initiated and should use `BlockProvenanceKind::SupervisorManual`.
3. **Supervisor sync actions** are replicated state application and should use `BlockProvenanceKind::SupervisorSync`.
4. **Mesh threat-intel enforcement** remains `MeshThreatIntelPolicyGated` and must not be conflated with manual/sync actions.
5. **Local WAF/honeypot/ASN evidence** remains local-origin and uses the appropriate local provenance kind.
6. **Manual/supervisor paths may bypass threat-intel policy gates** only because their authority comes from operator/control-plane intent, not remote advisory data.
7. **Every new manual/supervisor production block write should use `block_ip_with_provenance`**, not legacy `block_ip`.
8. **Admin/debug responses should expose provenance where they return block entries.**

If an existing path cannot carry provenance, document why and classify it as compatibility-only.

## Phase 3 — Normalize Provenance on Manual Writers

Audit all admin/supervisor block writes.

For each write:

- confirm it uses `block_ip_with_provenance`;
- confirm `kind` is one of:
  - `AdminManual` for admin API/operator action;
  - `SupervisorManual` for explicit supervisor command;
  - `SupervisorSync` for replicated blocklist state from supervisor/worker sync;
- set `source` meaningfully when available.

Suggested source conventions:

- admin user ID/name if available;
- admin API route/action if user identity is unavailable;
- supervisor node ID / controller identity for supervisor actions;
- sync source, epoch, or channel name for blocklist sync if available.

Do not invent fake actor identity. If identity is not available, use a stable action/source string such as `admin_api:ban_ip` or `supervisor_sync:blocklist_update`.

## Phase 4 — Normalize Responses and DTOs

Audit admin/supervisor/debug response structs that return block entries.

Ensure responses include provenance fields where useful:

- `provenance_kind` as a string or enum-friendly field;
- `provenance_source` if present;
- reason;
- scope;
- expiry/duration;
- inserted/updated timestamp if already available.

Prefer additive fields to avoid breaking clients.

If provenance is already exposed in some responses, ensure naming is consistent across:

- admin ban/list responses;
- supervisor blocklist responses;
- debug/status endpoints;
- docs/OpenAPI schema if present.

If an OpenAPI/schema generator exists, update it or add a follow-up note if schema generation is out of scope.

## Phase 5 — Manual vs Automated Audit Logging

Review logs and metrics around manual/supervisor block mutations.

Minimum desired state:

- admin manual block emits structured log with actor/source, target IP/mesh ID, reason, scope, duration, and provenance kind;
- supervisor manual block emits equivalent structured log;
- supervisor sync block application emits count-level log and avoids noisy per-entry logs unless already standard;
- automated threat-intel/WAF/local-origin logs remain distinct from manual/supervisor logs.

If metrics exist, consider incrementing counters such as:

- manual admin blocks;
- supervisor manual blocks;
- supervisor sync applied entries;
- supervisor sync rejected/malformed entries.

Do not create a large metrics taxonomy. A small counter or structured log may be sufficient.

## Phase 6 — Guardrails

Add a focused source guard if useful.

Suggested test:

- `tests/manual_enforcement_provenance_guard.rs`

Guardrail behavior:

1. Scan admin/supervisor/worker-sync production paths for legacy `.block_ip(` calls.
2. Allow trait definitions, tests, compatibility methods, and provider internals.
3. Fail if admin/supervisor production handlers call legacy `block_ip` instead of `block_ip_with_provenance`.
4. Fail if new manual/supervisor block writes use `LegacyUnknown`.

Candidate denylist paths:

- `src/admin/`
- `src/supervisor/`
- `src/worker/unified_server/`

Candidate allowlist:

- tests;
- docs/plans/architecture;
- trait definitions;
- compatibility wrappers;
- non-mutating reads/listing endpoints;
- provider APIs that are not `BlockStore` writes.

Keep the guard pragmatic. It should catch obvious manual/supervisor provenance regressions without becoming noisy.

## Phase 7 — Tests

Add focused tests where code changes occur.

Recommended tests:

1. admin manual ban writes `AdminManual` provenance;
2. admin mesh-ID ban writes `AdminManual` provenance if it maps to IP blocks;
3. supervisor manual block writes `SupervisorManual` provenance;
4. worker blocklist sync writes `SupervisorSync` provenance;
5. list/detail responses expose provenance kind/source;
6. old persisted block entries still deserialize to `LegacyUnknown`;
7. manual enforcement guard catches a simulated legacy `block_ip` call in admin/supervisor path.

If endpoint tests are expensive, prioritize lower-level handler/service tests plus the guardrail.

## Phase 8 — Documentation

Update:

- `architecture/manual_enforcement_ownership.md` with the inventory and final ownership rules.
- `docs/THREAT_INTEL.md` manual/supervisor provenance table if needed.
- `AGENTS.md` with concise rule:
  - manual/supervisor production block writes require explicit provenance;
  - manual/supervisor authority is separate from mesh threat-intel policy gates;
  - do not use `LegacyUnknown` for new manual/supervisor writes.

If admin API docs or OpenAPI docs exist and responses change, update them.

## Verification Commands

Run focused checks:

```bash
cargo test --test manual_enforcement_provenance_guard
cargo test -p synvoid-block-store
cargo test --lib admin
cargo test --lib supervisor
cargo test --lib blocklist
cargo test --lib --no-run
```

Adjust exact filters to match final test placement.

Also rerun existing boundary checks if practical:

```bash
cargo test --test threat_intel_boundary_guard
cargo test --test http3_waf_boundary_guard
```

If GitHub CI status is unavailable, document local command output in the implementation note.

## Acceptance Criteria

This pass is complete when:

1. Manual/supervisor enforcement surfaces are inventoried and classified.
2. Admin manual block writes use `AdminManual` provenance.
3. Supervisor manual block writes use `SupervisorManual` provenance.
4. Supervisor blocklist sync uses `SupervisorSync` provenance.
5. Admin/supervisor/listing responses expose provenance where block entries are returned.
6. Manual/supervisor logs or metrics distinguish manual/control-plane actions from automated threat-intel/WAF actions.
7. A guardrail prevents obvious legacy `block_ip` use in admin/supervisor production write paths.
8. Tests cover provenance on representative manual/supervisor writes.
9. No threat-intel/WAF policy semantics are changed.
10. No broad admin/auth redesign is introduced.

## Notes for the Implementer

This is an ownership and observability pass, not a feature expansion. The main invariant is:

> Manual and supervisor enforcement are legitimate authority paths, but they must be explicit, provenance-bearing, and distinguishable from automated mesh threat-intel, local WAF, honeypot, ASN, and proxy-originated enforcement.
