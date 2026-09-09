# Admin and Plugin Root-Boundary Ownership (Phase 21)

Phase 21 audit closing `admin` and `plugin` as `keep_app_root`.
Plan: `plans/phase_21_admin_plugin_root_boundary_closure.md`.

Position: the admin corrective line already closed router composition,
browser/session authentication, mutation/audit semantics, realtime behavior,
alerting, and frontend/backend contract integrity. This document does not
reopen that behavior. It records, per submodule/handler, what is Axum
transport/composition (root-owned) versus domain semantics (crate-owned),
removes the remaining duplicate implementations, and justifies the final
`keep_app_root` classifications.

Target boundary (from the plan):

- Root `admin` owns Axum transport, route registration, middleware ordering,
  extraction of the authenticated operator identity, response adaptation, and
  application service wiring via explicit typed handles on `AdminState`.
- Domain crates/managers own validation and mutation/query semantics.
- Shared admin mutation/audit DTOs stay in their canonical low-level owner
  (`synvoid-core::admin_mutation`).
- Token cryptography is consumed from `synvoid-admin::auth` (re-exported
  through `src/admin/auth.rs`); `synvoid-auth` owns the reusable
  session/CSRF/lockout manager used by the data plane.

A healthy mutation flow (verified in `threat_level.rs`, `mesh_admin.rs`,
`config.rs`, `plugins.rs`): parse/authenticate/authorize → validate
transport shape → call typed domain/control-plane method → receive typed
`AdminMutationResult` → emit `AdminAuditEvent` via
`state.audit.log_audit_event()` → map to HTTP response. No new
service-locator abstraction was introduced; `AdminState` keeps explicit
typed handles.

## A. Admin submodule inventory (`src/admin/`)

| Submodule | Classification | Owner | Notes |
|-----------|---------------|-------|-------|
| `mod.rs` (router, CORS, SPA fallback, asset resolution) | HTTP transport/router composition | root app | Route registration, middleware ordering, `resolve_admin_ui_assets()`; feature-gated mesh/DNS/ICMP branches |
| `state.rs` (`AdminState`, session/CSRF stores, metrics/request-log stores) | transport composition + session container | root app | Explicit typed handles (`MetricsState`, `WafTrackingState`, `SecurityState`, `MeshState`, `HoneypotState`, `ProcessState`, `PluginsState`); implements `synvoid_admin::handlers::state::AdminStateProvider` so crate handlers consume it through a narrow trait |
| `audit.rs` (`AuditState`, `ConfigVersionManager`, `log_audit_event` bridge) | runtime service adapter + DTO | root app | Mutation/audit DTOs canonical in `synvoid-core::admin_mutation`; this file adapts them to the file+memory audit log |
| `auth.rs` | compatibility facade | `synvoid-admin` | `pub use synvoid_admin::auth::{hash_admin_token, ...}` — token cryptography lives in the crate |
| `rate_limit.rs` | compatibility facade | `synvoid-admin` | Re-exports `AdminRateLimitConfig/Layer/Middleware/Limiter`, `ClientIp` |
| `schema.rs` | DTO/schema adapter | root app | Re-exports `DateTimeUtc`/`PathBufWrapper` from crate; adds `ToSchema` impls for root `AuditLog`/`ConfigVersion` |
| `middleware.rs`, `middleware/yara_rate_limit.rs` | transport middleware | root app | Client-IP extraction, auth/CSRF, security headers, per-op YARA limits |
| `metrics.rs`, `metrics_events.rs`, `prometheus_exporter.rs` | transport observability | root app | Formatting/export; collection stays in `synvoid-metrics` |
| `openapi.rs` | DTO/schema composition | root app | OpenAPI document over the root route tree |
| `ws/` (broadcaster, handlers) | transport | root app | Session-authenticated upgrade; no blanket middleware |
| `alerting/` (`AlertManager`) | runtime service adapter | root app | Owned via `AdminState.process.alert_manager`; SSRF-safe delivery |

## B. Admin handler inventory (`src/admin/handlers/`)

Handlers already extracted to `synvoid-admin` are pure facades here:

| Handler | Classification | Canonical owner |
|---------|---------------|-----------------|
| `logs`, `probes`, `stats`, `system` | facade over crate | `synvoid_admin::handlers::{logs,probes,stats,system}` |
| `common` (pagination, `StatusResponse`, `ErrorPage`) | DTO facade + transport helpers | `synvoid_admin::handlers::common` + root-only `require_role`/`check_rate_limit`/`get_client_ip`/`config_path`/`write_config_file_secure` |

Remaining root handlers are thin adapters (transport + typed service call):

| Handler | Classification | Authoritative operation |
|---------|---------------|-------------------------|
| `auth` | authentication transport | `AdminState` session/CSRF stores; token verify via `synvoid_admin::auth`; timing-normalized dummy verify retained |
| `config` | adapter over config | `synvoid-config` canonicalization/validation; `config_mutation()` typed helper + audit |
| `sites`, `upstreams`, `tcp_udp`, `theme` | adapters over config/process | `ConfigManager` site/upstream/theme sections; typed mutation results |
| `alerting` | adapter over alert service | `AlertManager`; webhook test returns typed delivery outcome |
| `php`, `honeypot`, `icmp` | adapters over runtime controllers | `ProcessManager`, `PortHoneypotController/Runner`, `IcmpFilterManager` |
| `observability` | transport formatting | `synvoid-metrics::collection` counters; no collection logic here |
| `mesh_admin`, `mesh_topology`, `threat_intel_policy`, `behavioral_intel`, `yara_rules`, `tier_keys` | adapters over mesh/service APIs (mesh-gated) | `MeshTransport`, org-key/client-audit managers, YARA rules manager; bans return `AdminMutationResult<BlockMutationTarget>` + audit |
| `plugins`, `serverless`, `spin` | adapters over plugin lifecycle/runtime owner | `WasmPluginManager` (`get_plugin_info`, `reload_plugin_by_name`), `get_all_wasm_metrics()`; reload returns `AdminMutationResult` + reload-log entry |
| `rule_feed`, `threat_level` | adapters over WAF managers | `RuleFeedManagerForWaf`, `ThreatLevelManager`; mutations audited |
| `api_discovery` | feature-capability discovery | Route inventory derived from the root router (transport-owned by nature) |

Read/query endpoints do not reconstruct subsystem state: metrics come from
`synvoid-metrics`, mesh status from mesh/service APIs, plugin status from the
plugin runtime owner, supervisor/process state from the root supervisor
service, config views from `synvoid-config`. The previous duplicate state
derivation was removed by the admin corrective line; spot-checked
`observability.rs` (formats `synvoid_metrics::collection` counters only) and
`plugins.rs` (reads `WasmPluginManager` + metrics registry only).

## C. Decision: `admin` → `keep_app_root`

`admin` is predominantly Axum application/control-plane composition. Every
handler still requires the root composition (`AdminState` wiring WAF, config,
mesh, metrics, supervisor, plugin managers), so extracting a `synvoid-admin`
crate around the handlers would only relocate files while keeping the same
dependency fan-in — the outcome the plan explicitly rejects. The genuinely
reusable, transport-neutral layer (auth primitives, rate limiting, schema
helpers, `AdminStateProvider` narrow trait, and the `logs`/`probes`/`stats`/
`system`/`common` handler logic) already lives in the existing
`synvoid-admin` crate; the root module facades it. Size alone is not
extraction debt. Reclassified `split_required` → `keep_app_root`
(composition), with `synvoid-admin` recorded as the DTO/handler-logic owner.

## D. Plugin ownership audit (`src/plugin/` vs `crates/synvoid-plugin-runtime/`)

| Root component | Classification | Resolution |
|----------------|---------------|------------|
| `PluginManager` struct + inherent methods (~245 lines) | stale duplicate of `synvoid_plugin_runtime::plugin_manager::PluginManager` | Deleted; root re-exports the crate type. Crate version is a superset (adds `load_wasm_plugin_from_bytes`) |
| `PluginManagerLifecycle` struct (~240 lines) | stale duplicate of crate lifecycle | Deleted; root re-exports the crate type |
| `load_wasm_plugin` mesh-store preference (`#[cfg(feature = "mesh")]`) | application lifecycle composition (mesh + plugin) | Preserved as root adapter `load_wasm_plugin_with_mesh_fallback()` + mesh-agnostic `load_plugins_from_dir_with_resolver()` hook in the crate; `PluginRuntimeOwner` passes the mesh resolver. No `synvoid::*` import added to the crate |
| `unsafe_native_loader.rs` | thin shim (already facade) | Retained; delegates to `synvoid_plugin_runtime::unsafe_native_loader::load_plugin` |
| `impl AxumDynamicRouterLookup / WasmFilterBackend for PluginManager` | request-path adapter | Moved to `synvoid-http` (`plugin_backend.rs`; local trait + foreign type is orphan-legal, no new dependency — `synvoid-http` already depends on `synvoid-plugin-runtime`) |
| Manifest/capability validation, trust-tier/signature decisions, WASM execution policy, timeout/resource limits, quarantine/failure accounting | reusable runtime | Canonical in `synvoid-plugin-runtime` (`sandbox/types.rs`, `wasm_runtime.rs`); no root copies exist or remain (guard-enforced) |

Root legitimately retains (Part F): loading plugins from application
configuration (`PluginRuntimeOwner::load_configured_plugins`), attaching the
runtime to worker state (downcast sites in `src/http/`, `src/worker/`),
supervisor task ownership and shutdown (`PluginRuntimeOwner` RAII over the
watcher + epoch incrementer — never `std::mem::forget`), mesh-aware byte
resolution, and handoff wiring. Reclassified `split_required` →
`keep_app_root` (lifecycle/application composition).

## E. Remaining ledger sweep (Part G)

After Phases 18–21 the ledger contains zero `split_required` entries:
`auth`/`challenge` (Phase 18), `waf` (Phase 19), `http`/`tls`/`http_client`
(Phase 20), `admin`/`plugin` (this phase). `http_client` and similar remain
`facade_existing_crate` with documented local adapters (QUIC dispatch,
`ProxyServer` alias, `file_manager`); those are deliberate composition
footnotes, not ownership ambiguity, and each names its blocker. `serder` and
the removed `captcha`/`logging` entries stay `legacy_or_stale` with removal
notes. Ledger, burn-down report, and final surface audit now agree on names
and counts (guard-enforced by `admin_plugin_boundary_guard`).

## F. Guardrails added

`tests/admin_plugin_boundary_guard.rs` (static_policy):

- root `plugin` defines no runtime types (`PluginManager`,
  `PluginManagerLifecycle`, `PluginManifest`, `PluginTrustTier`,
  `PluginCapabilities`, `WasmRuntime`, `runtimes.write`) and re-exports the
  crate manager;
- `synvoid-plugin-runtime` contains no `synvoid::` root path;
- root admin `common` re-exports crate DTOs instead of redefining them;
- ledger, burn-down report, and final surface audit agree on the
  `split_required` set (empty after this phase).
