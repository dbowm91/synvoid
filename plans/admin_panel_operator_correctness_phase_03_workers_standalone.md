# Phase 03 Plan: Workers 404 in Standalone Mode (UI Empty-State)

Status: **IMPLEMENTED** (`d2cc5cd`; live-verified 2026-10-30:
standalone `/system/workers*` stay 404, supervisor 200 Standalone, panel
serves the explanatory empty-state with no error banner).

Registered in: `plans/roadmap.md`.

Campaign: `plans/admin_panel_operator_correctness_roadmap.md`.
Predecessor: none required (independent of Phases 01–02; run any time before
Phase 05).

## The finding

The Workers tab shows `HTTP 404:` at the top with no explanation. Live:
`/api/system/workers` and `/api/system/workers/count` both return 404 while
`/api/system/supervisor` returns 200 with `"mode":"Standalone"`.

## Root cause

`crates/synvoid-admin/src/handlers/system.rs:266` (`get_workers`) and
`:520` (`get_worker_count`) return `404 NOT_FOUND` when
`state.process_manager()` is `None`. Same guard on `restart_worker` and
`scale_workers`. In standalone mode there is no `ProcessManager` — no
supervised `UnifiedServerWorker` children exist to list — so the endpoints
correctly report absence. The backend behavior matches its utoipa contract
(404 `Process manager not found`); only the UI presentation is wrong.

Deliberately UI-side: changing the backend to 200-empty in standalone would
rewrite a documented contract and weaken the supervised-mode signal (a 404
there still means "manager missing when one should exist"). The supervisor
status endpoint already exposes `mode`, and the Workers page already fetches
it (`workers.rs:40-43`) but ignores it for rendering.

## Fix scope

- `admin-ui/src/pages/workers.rs`: when supervisor status `mode` is
  standalone (match the exact backend string; do not invent a new one),
  render an explanatory empty-state — e.g. workers management requires
  supervised (multi-worker) mode; restart/scale controls hidden or disabled
  — and skip the `/system/workers*` calls. Supervised mode keeps the
  current behavior bit-for-bit, including the raw error display for genuine
  failures.
- Rebuild `admin-ui/dist/` with pinned `trunk@0.21.14`; keep
  `admin_ui_dist_integrity` and `admin_ui_dist_has_no_inline_scripts` green.
- Contract test (backend, unchanged behavior): pin that standalone
  `process_manager() == None` yields 404 on `/system/workers*` while
  `/system/supervisor` stays 200 — so a future regression that breaks the
  UI's mode detection (e.g. renaming the mode string) fails loudly instead
  of resurfacing as a bare `HTTP 404:`.

Non-goals: no backend status-code change; no supervised-mode process
management feature work; no fix for the `WorkerStatus` UI-type field drift
(noted in Phase 02; harmless under serde's ignore-unknown).

## Verification

- `cargo xtask verify` (or at minimum fmt + clippy + repo-guards + the admin
  contract trio per the roadmap).
- Live standalone: Workers tab shows the explanatory state, zero calls to
  `/system/workers*` in devtools, no error banner.
- Live supervised (CI or a `--workers N` local run): Workers tab unchanged —
  list renders, restart/scale controls present.
