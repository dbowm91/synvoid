# Phase 03 Plan: Mount the Admin HTTP API

Status: **IMPLEMENTED** (branch `plans/waf-admin-deployment-truthfulness`; `spawn_admin_service` in worker data-plane root, plan `admin_addr` + conflict check, guard inverted to mounted state, authority doc + feature matrix updated).

> Follow-ups found testing the panel in a real browser (same branch):
>
> - **CSP vs inline bootstrap (panel never booted).** The served CSP
>   (`script-src 'self'`, no `unsafe-inline`) refused Trunk's inline WASM
>   bootstrap, so the panel stuck on "Loading…". The bootstrap is now an
>   external `admin-ui/dist/bootstrap.js`; `wasm-unsafe-eval` was added to
>   `script-src` so `instantiateStreaming` compiles (no `eval` permitted).
>   New `admin_ui_dist_has_no_inline_scripts` guard (mutation-tested);
>   stylesheet gate now accepts trunk-hashed CSS.
> - **Rate limit scoped to API+WS.** The 10/sec global budget 429d the
>   panel's own boot storm (bundle, WASM, CSS, fonts), so assets failed
>   alongside API calls. Static fallback + `/health` are unlimited; API+WS
>   keep the budget (rate limit still runs outside auth, shielding bcrypt).
> - **Lockout counted anonymous 401s.** Every logged-out API call recorded
>   an auth failure, so opening the panel (5 boot 401s) locked the
>   operator's IP out for 5 minutes and the login POST 429d. Failures now
>   record only for presented-but-wrong credentials (bad bearer, wrong CSRF
>   value); brute-force protection on the login path is unchanged.
> - Ledger allowlist extended to `server` for `axum` + `synvoid-platform`
>   (worker data-plane listener; same pattern as `tls`/`http`).

Registered in: `plans/roadmap.md`.

Campaign: `plans/waf_admin_deployment_truthfulness_roadmap.md`.
Predecessor: none required (independent of Phases 01–02; may proceed on a
separate branch).

## The finding

`[admin] port 8081` is configured, validated, and port-conflict-checked, but
nothing listens. `ss -tln` shows data plane `0.0.0.0:8082` and metrics
`127.0.0.1:9090` only.

- `pub fn create_admin_router` (`src/admin/mod.rs:105`, token hash at
  `:129-158`, `AdminState::new(...).with_*`, `build_router_from_state`) has
  zero production callers — `grep` finds only definition plus
  `tests/admin_route_contract.rs`, `tests/admin_router_composition.rs`,
  `tests/admin_smoke_flow.rs` (all via `tower::ServiceExt::oneshot`, never
  `bind`/`serve`). Companions `AdminState::new` and `start_metrics_publisher`
  (`src/admin/metrics.rs:10`) are likewise unreached in `src/`.
- Composition roots own everything except admin: `src/server/mod.rs:378-464`
  `run()` wires QUIC tunnel, threat autoscale, plugin runtime, router, HTTP
  runtime, HTTP/HTTPS/HTTP3 listeners, aux pools, DNS, ACME — no admin.
  `listener_tasks.rs` has `spawn_http/https/http3/dns/acme`, no
  `spawn_admin_service`. `startup_plan.rs:13` has no admin field and
  `from_config_snapshot:57-206` never reads `main.admin`. `supervisor/
  process.rs:80-361` spawns workers, IPC accept loop, telemetry exporter
  (`:154-213`, loopback-enforced, registered as `BestEffortMaintenance`),
  gRPC (`:231-269`, mesh-only) — no admin HTTP. `src/worker/` only checks
  the port (`unified_server/state.rs:236-238`).
- `architecture/admin_control_plane_authority.md:5-30` states it plainly:
  `NOT MOUNTED IN THE BINARY`; only the three contract lanes characterize
  the router. The guard
  `tools/synvoid-repo-guards/tests/admin_surface_truthfulness.rs:99`
  (`admin_surface_is_not_mounted`) plus `FEATURE_STATUS.md:27` enforce the
  marker. Mounting without updating both fails the gate by design.
- By the ledger (`architecture/root_module_ledger.md`: `admin|keep_app_root`,
  `server|keep_app_root` real `UnifiedServer` composition root), the listener
  belongs in `src/server/` (consumed by `src/worker/unified_server/`), not
  the supervisor — the supervisor lacks the WAF/mesh/plugin handles that
  `AdminState` requires (`get_probe_tracker`, `get_suspicious_word_tracker`,
  `get_upstream_error_tracker`, `get_threat_level_manager` in
  `server/mod.rs:322-353`, plus `RuleFeedManagerForWaf`, `#[cfg(mesh)]
  mesh_transport`, `#[cfg(icmp-filter)] icmp_filter`).

## Goal

`[admin] enabled=true` results in a listening HTTP API on
`bind_address:port` serving `create_admin_router`, with shutdown draining
like every other listener. `enabled=false` keeps current behavior (no
listener).

## Recommended disposition

New `spawn_admin_service` in `src/server/listener_tasks.rs` (mirror
`spawn_http/https/dns/acme`), called from `src/server/mod.rs:run()` in
startup order; plan field `admin_addr: Option<SocketAddr>` in
`startup_plan.rs:13 UnifiedServerStartupPlan` built in
`from_config_snapshot` from `main.admin.enabled/bind_address/port` (+
conflict check alongside the existing worker-side check); task registered
in `UnifiedServerRuntimeHandles` and the worker `TaskRegistry` via
`worker/unified_server/startup_plan.rs:84 build_worker_startup` Phase 14.

It calls `create_admin_router` with `Arc<RwLock<ConfigManager>>`,
`admin.resolve_token()` (`crates/synvoid-config/src/admin.rs:116`),
`cors/rate_limit/trusted_proxies/secure_cookie` from `main.admin`, live
trackers from `UnifiedServer`/`WafCore`, `#[cfg(mesh)]` / `#[cfg(icmp-filter)]`
handles, then `TcpListener::bind(admin_addr)` + `axum::serve` with the
standard shutdown receiver (telemetry-bridge pattern). Default
`bind_address 127.0.0.1` preserved; `0.0.0.0` allowed with the existing
`secure_cookie=false` warning when not loopback. Metrics stays untouched
(loopback-enforced by `MetricsConfig::validate`).

Same commit must: remove the `NOT MOUNTED` marker
(`admin_control_plane_authority.md:5-30`), update
`tools/synvoid-repo-guards/tests/admin_surface_truthfulness.rs:99,142`
and `docs/FEATURE_STATUS.md:27`, and record the endpoint inventory
(`admin_control_plane_authority.md` Phase 05 enforcement).

Out of scope: admin UI asset pipeline (`admin-ui/dist` committed build,
`admin-ui-build` job unchanged), metrics exporter changes, gRPC control
plane changes, new admin endpoints.

## Workstreams

- **A — listener wiring** (`src/server/` + `src/worker/unified_server/`
  only): plan field, `spawn_admin_service`, `run()` call, task registration,
  shutdown drain. No detector/proxy/request-path changes; no new crate.
- **B — guard + docs sync**: authority doc marker, surface-truthfulness
  guard, `FEATURE_STATUS.md`, `docs/ADMIN_UI.md` + `docs/API_REFERENCE.md`
  startup wording if they imply a listener that now exists.
- **C — tests**: existing contract lanes become live-path characterization
  (no new root test file if avoidable — avoids `OWNERSHIP.toml` churn);
  if a mount test is added, register it in `tests/OWNERSHIP.toml` same
  commit (`class` ≠ `domain`). Manual: `ss -tln` shows `8081`,
  `curl -H 'Authorization: Bearer $TOKEN' :8081/api/` → discovery JSON.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo nextest run --cargo-profile ci --profile ci \
  --test admin_route_contract --test admin_router_composition --test admin_smoke_flow \
  --features mesh,dns,icmp-filter
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo nextest run --cargo-profile ci --profile ci \
  --test facade_disposition_guard --test root_test_ownership_guard \
  --test boundary_composition_guard --features mesh
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify   # full gate before merge
```

Rollback: revert listener call + plan field (router returns to test-only);
guard/doc marker restored in the same revert.
