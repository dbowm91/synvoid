---
name: admin_contract
description: Admin route contract (Phase 05) — UI/backend endpoint alignment, capability flags, feature matrix, and stale paths that must stay absent. Use when touching admin routes, admin UI API calls, or feature-gated endpoints.
---

# Admin Contract Skill (Phase 05)

## What it is

Every UI-consumed endpoint is mechanically checked against the backend.
Closeout record: `architecture/admin_contract_phase05_closeout.md`.
Authority rules: `architecture/admin_control_plane_authority.md`.
Root ownership matrix: `architecture/admin_root_ownership.md`.

## The three guard suites

| Suite | What it checks |
|-------|----------------|
| `tests/admin_route_contract.rs` | Every UI-consumed endpoint exists in the backend with matching path + method |
| `tests/admin_router_composition.rs` | Capability ↔ route-family mapping, discovery/OpenAPI consistency, auth/middleware classification |
| `tests/admin_smoke_flow.rs` | End-to-end smoke through the admin API |

Routine CI runs all three with `--features mesh,dns,icmp-filter`.
Run `admin_route_contract` explicitly whenever frontend/backend API
alignment changes.

## Bounded feature matrix

Only these profiles are tested — the full powerset is intentionally
untested:

- minimal (`--no-default-features`)
- `mesh`, `dns`, `icmp-filter`, `mesh,dns`

Capability flags track features: `mesh_admin` → `mesh`,
`dns_admin` → `dns`, `icmp_admin` → `icmp-filter`.
Gate new feature-dependent routes behind the matching capability flag.

## Rules for new endpoints

1. Mutating endpoints return typed `AdminMutationResult`
   (`synvoid_core::admin_mutation`) with an `AdminMutationAuthority`
   variant — never generic `{"success": true}`.
2. Canonical commits use `PropagationStatus::CanonicalCommitted`; quorum
   loss uses `PropagationStatus::QuorumUnavailable` (never success);
   best-effort gossip stays `QueuedBestEffort`.
3. Block/unblock emits `AdminAuditEvent` via `state.audit.log_audit_event()`.
   Never store raw session tokens in audit logs.
4. WebSocket auth is per-connection at exactly `/api/ws/metrics` and
   `/api/ws/logs` (constants in `src/admin/ws/mod.rs`) — no broad
   `/api/ws/` prefix bypass.

## Stale paths (must stay absent)

`/system/master`, `/system/overseer`, `/config/overseer`, singular worker
restart, `/api/logs/realtime`. The composition suite fails if any return.

## Ownership note

Root `src/admin/` is `keep_app_root` Axum transport/composition; DTOs and
shared logic live canonically in `crates/synvoid-admin/src/`
(`src/admin/handlers/{logs,probes,stats,system}.rs`, `common.rs` DTOs,
`auth.rs`, `rate_limit.rs` are facades + transport helpers).
