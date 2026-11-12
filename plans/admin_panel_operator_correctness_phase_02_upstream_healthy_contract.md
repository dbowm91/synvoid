# Phase 02 Plan: `upstream_healthy` Bool-vs-Enum Contract Mismatch

Status: **IMPLEMENTED** (`d2cc5cd`; live-verified 2026-10-30:
`/api/stats/sites` serves `"upstream_healthy":"healthy"` string, dashboard
parses with no error).

Registered in: `plans/roadmap.md`.

Campaign: `plans/admin_panel_operator_correctness_roadmap.md`.
Predecessor: none required (independent of Phase 01; run any time before
Phase 05).

## The finding

The Dashboard tab shows `Failed to load dashboard data: HTTP 200: JSON parse
error: invalid type: string "unknown", expected a boolean at line 1 column
470`. Byte 470 of `GET /api/stats/sites` is `"upstream_healthy":"unknown"`
(verified live against the deployment).

## Root cause

Backend `GET /api/stats/sites` serializes `SiteMetricsPayload.upstream_healthy`
as the canonical `HealthStatus` enum (`healthy`/`unhealthy`/`unknown`,
lowercase — `crates/synvoid-metrics/src/payloads.rs:7-13`, default
`Healthy`, with an `as_bool()` helper). The UI declares the field as a bool:

- `admin-ui/src/types/mod.rs:54`: `pub upstream_healthy: bool`

Any site whose health is not yet determined (standalone mode: always —
see Phase 04) kills the whole dashboard fetch. Consumed as a bool in three
pages: `dashboard.rs:626`, `sites.rs:177`, `site_detail.rs:223/225`.

The backend is canonical and shared with mesh/metrics code; the UI type is
the drift. (`WorkerStatus` in the same UI types file is separately missing 6
backend fields — serde ignores extras, so that drift is noted, not fixed,
here.)

## Fix scope

- `admin-ui/src/types/mod.rs`: `upstream_healthy: bool` → `String` (or a
  three-variant UI enum deserializing the backend's lowercase strings;
  either is acceptable, pick one and use it in all three pages).
- Update the three consumption sites to map
  `healthy → Healthy/green`, `unhealthy → Unhealthy/red`,
  `unknown → Unknown/grey` (exact labels follow existing page copy; no new
  Health enum in the API).
- Rebuild `admin-ui/dist/` with pinned `trunk@0.21.14`; keep
  `admin_ui_dist_integrity` and `admin_ui_dist_has_no_inline_scripts` green.
- Extend `admin_route_contract` (or the owning contract test) with a
  deserialization assertion: the live shape of `/api/stats/sites`
  (including `"upstream_healthy":"unknown"`) must parse into the UI-side
  type. The gap survived because no test parses a backend-shaped payload
  with the UI type.

Non-goals: no backend change (`HealthStatus` stays; `as_bool()` stays);
no change to `/api/upstreams` backend `healthy: bool` (a different, working
contract); no new API field.

## Verification

- `cargo xtask verify` (or at minimum fmt + clippy + repo-guards + the admin
  contract trio per the roadmap).
- New contract test parses a captured `/api/stats/sites` payload containing
  all three health strings.
- Live: Dashboard, Sites, and site-detail pages render with an upstream
  health indicator and no parse-error banner; an `unknown` site shows the
  neutral/grey state, not red.
