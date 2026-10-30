# Phase 05 Plan: Terminal Verification and Closeout

Status: **READY** (branch `plans/admin-panel-operator-correctness`; not started).

Registered in: `plans/roadmap.md`.

Campaign: `plans/admin_panel_operator_correctness_roadmap.md`.
Predecessor: Phases 01–04 (all four must be implemented; this phase runs last).

## Scope

Terminal gate for the series: re-run every verification lane, re-browse the
four affected tabs against the `~/prodtest` deployment, and record the
closeout by pointer. No production code changes except guard/test updates
required to keep the new invariants green.

## Steps

1. Full gate: `cargo xtask verify` with no lane skips. Any failure is fixed
   in the owning phase (reopen that phase's status), not worked around here.
2. Admin contract trio with `--features mesh,dns,icmp-filter`
   (`admin_route_contract`, `admin_router_composition`, `admin_smoke_flow`)
   plus `security_regression` single-threaded — the lanes that own
   frontend/backend alignment.
3. Repo-guards green, including `admin_ui_dist_integrity`,
   `admin_ui_dist_has_no_inline_scripts`, and any new invariant added by
   Phases 02–04 (contract-deserialization test, standalone-404 pin,
   standalone-telemetry test).
4. Live re-browse (Playwright Chromium, operator-local `~/prodtest`):
   - Upstreams: one request on mount, table renders, Refresh fires exactly
     one request, 60s idle fires none, no 429.
   - Dashboard/Sites/site-detail: no parse-error banner; `unknown` health
     shows the neutral state.
   - Workers (standalone): explanatory empty-state, zero `/system/workers*`
     calls; (supervised local run): list + controls unchanged.
   - Stats/request-logs: traffic (200s + blocked probe) visible in summary,
     history, and request logs within one publisher tick.
5. Write the closeout as a pointer record (new `architecture/` closeout or
   an appendix to the campaign roadmap — not a rewrite of Phases 01–04):
   proof-bearing SHAs, hosted CI run (if any), and the residual list. Known
   residuals to adjudicate explicitly: `WorkerStatus` UI-type field drift
   (Phase 02 note), any remaining `unknown`-health display edge, and whether
   `start_metrics_publisher`'s supervised bridge needs a load test.
6. Flip Phases 01–04 and the roadmap status to **IMPLEMENTED** with the
   proof-bearing SHAs; register the closeout location in `plans/roadmap.md`.

## Verification

This phase *is* verification; its evidence is the closeout record from step 5
plus a green `cargo xtask verify` log. No separate test artifacts.

Non-goals: no new fixes (failures reopen the owning phase); no hosted-CI
claims without a run number; no historical-closeout rewrites.
