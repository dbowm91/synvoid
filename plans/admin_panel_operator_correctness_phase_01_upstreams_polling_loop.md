# Phase 01 Plan: Upstreams Infinite Fetch Loop (`use_effect` → `use_effect_with`)

Status: **IMPLEMENTED** (`d2cc5cd`; live-verified 2026-10-30: rapid
upstreams/sites/workers/stats tab tour returns no 429).

Registered in: `plans/roadmap.md`.

Campaign: `plans/admin_panel_operator_correctness_roadmap.md`.
Predecessor: none (first phase; run first — it removes the self-inflicted
429 storm that masks every other tab).

## The finding

The Upstreams tab shows `Failed to load upstreams: HTTP 429: Rate limit
exceeded` and the browser devtools show the same endpoint refetched
continuously. Direct `curl /api/upstreams` with the same token returns 200
with valid data — the endpoint is healthy; the page is DDoSing it.

## Root cause

`admin-ui/src/pages/upstreams.rs:21` uses a bare `use_effect(...)`. In Yew,
bare `use_effect` runs after **every** render, and the effect body ends with
`upstreams.set(data)` (`upstreams.rs:29`), which triggers a re-render, which
re-runs the effect: a hot infinite fetch loop. The error path loops too
(`error.set(...)` at `upstreams.rs:33` → re-render → retry). It is the only
page with a bare `use_effect`; `workers.rs`, `dashboard.rs`,
`request_logs.rs`, `logs.rs`, `sites.rs` all use `use_effect_with`
(verified by grep: one bare occurrence in `admin-ui/src/`, this one).

The loop burns the shared per-IP API budget (60/min) in about a second.
After that every API call 429s — including the loop's own retries, so the
429 is self-sustaining until the tab is closed. Cross-tab collateral: the
loop consumes the whole IP budget, so the dashboard, workers, and logs tabs
429 as well while it runs.

## Fix scope

- `admin-ui/src/pages/upstreams.rs:17-40`: `use_effect` →
  `use_effect_with((), ...)` (fetch once on mount). The manual `refresh`
  callback (`upstreams.rs:42-65`) already exists for operator-driven reload.
- Rebuild `admin-ui/dist/` with pinned `trunk@0.21.14`; keep
  `admin_ui_dist_integrity` and `admin_ui_dist_has_no_inline_scripts` green
  (no new inline scripts; the change is hook-only).
- Optional hardening (same phase, same file): guard the error branch so a
  failed fetch does not schedule retries — with `use_effect_with(())` the
  loop is gone structurally, so this is defense-in-depth only; do not add a
  polling timer.

Non-goals: no backend change; no rate-limit retuning (the budget is correct —
the client was abusive); no polling/auto-refresh feature.

## Verification

- `cargo xtask verify` (or at minimum fmt + clippy + repo-guards + the admin
  contract trio per the roadmap).
- Live: open the Upstreams tab in Chromium (Playwright), assert one
  `/api/upstreams` request on mount, table renders, no 429 banner; click
  Refresh Status, assert exactly one further request; leave the tab open 60s
  and assert no further requests fire.
- Live cross-check: with the tab open, `curl /api/stats/summary` from the
  same egress IP returns 200 (budget no longer exhausted).
