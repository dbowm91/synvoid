# Admin Panel Operator-Correctness Roadmap

Status: **IMPLEMENTED** (branch `plans/admin-panel-operator-correctness`;
all five phases landed, verified, and deployed against the `~/prodtest`
blog + SynVoid stack on 2026-10-30).

Proof-bearing commits: `d2cc5cd` (phases 01–04: polling loop, tri-state,
empty-state, metrics/log bridge, dist rebuild), `1146ab7` (publisher
worker totals derived from the per-site map), `ef75889` (latency
percentiles from the per-site map), `49c324b` (`get_logs` served from the
request-log deque + WS broadcast on emit).

Registered in: `plans/roadmap.md`.

Origin: operating the admin panel in a real browser (Chromium via Playwright)
against the `~/prodtest` deployment (blog direct `0.0.0.0:5000`, WAF data
plane `0.0.0.0:8082`, admin `0.0.0.0:8081`, single-process standalone mode).
Four defects, all invisible to the existing gates because no gate browses the
panel or runs the server in standalone mode with traffic:

1. Workers tab shows `HTTP 404:` — `get_workers` / `get_worker_count` return
   `404 NOT_FOUND` when `process_manager()` is `None`, which is always true
   in standalone mode.
2. Upstreams tab shows `HTTP 429: Rate limit exceeded` and refetches
   continuously — `upstreams.rs` uses a bare `use_effect` (every render),
   an infinite fetch loop that burns the shared per-IP rate budget and then
   retries the 429 forever (self-sustaining lockout).
3. Dashboard tab shows `HTTP 200: JSON parse error: invalid type: string
   "unknown", expected a boolean at line 1 column 470` — backend
   `/api/stats/sites` serializes `HealthStatus` (`healthy`/`unhealthy`/
   `unknown`) while the UI declares `upstream_healthy: bool`.
4. No WAF/request logs anywhere and every counter is zero
   (`total_requests: 0`, history `[]`, request logs `{"entries":[],"total":0}`)
   despite live traffic — `start_metrics_publisher` has no production caller
   and `AdminState.request_logs` has no production writer; the data-plane log
   path requires IPC + worker-id (supervised workers only) and lands in a
   different deque (`ProcessManager.request_logs`) that the API never reads.
   Independently, this deployment sets
   `[logging.verbose_request_logging] enabled = false`.

Phases (in order — 01 and 02 are UI-only one-spot fixes, 03 is UI-only
empty-state work, 04 is the backend composition change, 05 closes the series):

| Phase | File | Status |
|---|---|---|
| 01 | `admin_panel_operator_correctness_phase_01_upstreams_polling_loop.md` | **Ready** — `use_effect` → `use_effect_with(())` on the Upstreams page |
| 02 | `admin_panel_operator_correctness_phase_02_upstream_healthy_contract.md` | **Ready** — UI `upstream_healthy` bool → tri-state matching backend `HealthStatus` |
| 03 | `admin_panel_operator_correctness_phase_03_workers_standalone.md` | **Ready** — standalone empty-state for the Workers page, no contract change |
| 04 | `admin_panel_operator_correctness_phase_04_metrics_logs_bridge.md` | **Ready** — wire the metrics publisher and request-log sinks (standalone + supervised) |
| 05 | `admin_panel_operator_correctness_phase_05_verification_closeout.md` | **Ready** — terminal verification, guard updates, closeout pointer |

Run 01 first (it removes the self-inflicted 429 storm that masks every other
tab). 02 and 03 are independent of 01 and of each other. 04 is independent
but largest and touches composition; it may proceed in parallel on a separate
branch. 05 runs last and requires 01–04 green.

Binding constraints for all five phases:

- Admin authority (`architecture/admin_control_plane_authority.md`): no new
  mutating endpoint is authorized by this series (all fixes are read-path or
  UI-only). If Phase 04 needs a debug/trigger endpoint, that is a separate
  explicit decision, not smuggled in.
- Request-path capability boundary (`architecture/request_path_capability_boundary.md`):
  Phase 04's sinks live in composition roots; request-path code consumes a
  narrow sink trait only. No concrete `AdminState`, `ProcessManager`, IPC, or
  `verify_admin_token` in request-path modules.
- Facade dispositions (`architecture/facade_disposition_matrix.md`): `admin`
  is `keep_app_root` transport/composition; reusable DTO/logic goes in
  `synvoid-admin`. Removed root paths stay removed. No new crate.
- Reduced-feature binaries fail closed (Phase 41): no new capability config
  section without its feature gate. Phase 04 reads existing
  `[logging.verbose_request_logging]` / `[metrics]` sections only.
- Root dependency ledger (`architecture/root_dependency_ownership.md`): no
  new root dependency is expected; any new `src/` consumer of an existing
  root dep needs its allowlist extended with guard-green evidence.
- `admin-ui/dist/` is committed: UI phases rebuild with the pinned
  `trunk@0.21.14` (see `.github/workflows/ci.yml`) and keep
  `admin_ui_dist_integrity` + `admin_ui_dist_has_no_inline_scripts` green.
- Every new root `tests/*.rs` file needs a `tests/OWNERSHIP.toml` entry in
  the same commit (`root_test_ownership_guard`); `class = "domain"` rejected.
- Historical closeouts corrected by pointer only, never rewritten.

Verification strategy (all phases):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh,dns,icmp-filter --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo nextest run --cargo-profile ci --profile ci \
  --test admin_route_contract --test admin_router_composition --test admin_smoke_flow \
  --features mesh,dns,icmp-filter
cargo test --test security_regression --profile ci -- --test-threads=1
cargo xtask verify        # full gate before merge
```

Live deployment evidence (operator-local `~/prodtest`, never committed):
authenticated `curl` against `:8081` for each touched endpoint plus a
Playwright Chromium pass over the four affected tabs (login → workers →
upstreams → dashboard → request logs), asserting no `HTTP 4xx`/`5xx` or
parse-error banners and, for Phase 04, non-zero counters after traffic.

Test-deployment evidence kept out of the repo: the `~/prodtest` blog + WAF
configs and tokens that exposed these gaps are operator-local, not committed.
