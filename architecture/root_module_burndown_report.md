# Root Module Burn-Down Report

## Summary

Phase 15 initial burn-down pass. Three modules reclassified from `split_required` to `keep_app_root`:
- `platform`: Removed duplicate fs.rs (280 LOC), re-exported core types from synvoid-platform crate
- `utils`: Removed ~400 LOC of duplicate implementations, re-exported shared types from synvoid-utils crate
- `tarpit`: Deleted dead generator.rs (288 LOC), added facade documentation

Total LOC removed from root: ~688 lines of duplicate/dead code.

## Modules Changed

| Module | Before | After | Change |
|--------|--------|-------|--------|
| `platform` | `split_required` | `keep_app_root` | Thin facade + root-owned sandbox/socket/ipc |
| `utils` | `split_required` | `keep_app_root` | Re-exports from crate + root-only helpers |
| `tarpit` | `split_required` | `keep_app_root` | Clean facade + root-owned handler/manager |

## Dependencies Moved/Removed

- Root `fs.rs` deleted; `PlatformPaths`/`SecureDir` now re-exported from `synvoid-platform`
- Duplicate `ArcStr`, `parse_duration`, timestamp functions, `ip_to_slot`, `check_regex_complexity` etc. removed from root; re-exported from `synvoid-utils`

## Facades Preserved

- `src/platform/mod.rs` — re-exports `Platform`, `PlatformError`, `PlatformPaths`, `SecureDir`, `fs`, convenience functions from crate; root-owned submodules remain
- `src/utils.rs` — re-exports shared types from crate; root-only helpers remain
- `src/tarpit/mod.rs` — re-exports `MarkovChain`, `TarpitConfig` from crate; root-owned `TarpitHandler`, `TarpitManager` remain

## Tests Run

- `root_facade_boundary_guard` — passed
- `root_module_ledger_guard` — passed
- `root_dependency_ownership_guard` — 3/3 passed
- `request_path_capability_boundary_guard` — 11/11 passed
- `synvoid-platform` crate — 4/4 passed
- `synvoid-utils` crate — 31/31 passed
- Root `utils` tests — 51/51 passed
- Root `platform` tests — 2 passed, 2 pre-existing failures (sandbox stub tests fail on clean tree too)

## Phase 18 Closure (auth + challenge)

Phase 18 extracted both high-value root dependencies ahead of the WAF ownership phase:

- `auth` (`src/auth/`, ~1,202 lines) → canonical `crates/synvoid-auth/` (`AuthManager`, session/CSRF/lockout, `BasicAuthManager`); `src/auth/mod.rs` is now `pub use synvoid_auth::*;`. Only `DrainFlag` (already in `synvoid-utils`) and `SiteBasicAuthConfig` (already in `synvoid-config`) blocked extraction; no cycle introduced.
- `challenge` (`ChallengeManager`/`ChallengeConfig`/attempt tracking + `mesh_pow.rs`, ~865 lines) → canonical `crates/synvoid-challenge/src/manager.rs` + `mesh_pow.rs`; `src/challenge/mod.rs` is now a pure re-export facade. Mesh-PoW has no mesh-transport dependency (config-only), so no narrow adapter was needed. Rendering stays directional (`synvoid-challenge` → `synvoid-theme`).
- WAF (`src/waf/mod.rs`, `adapters.rs`), TLS (`src/tls/server.rs`), and server (`src/server/mod.rs`) now import `synvoid_auth` / `synvoid_challenge` directly; no `crate::auth` / `crate::challenge` imports remain in `src/`.

## Phase 20 Closure (HTTP normalization ownership convergence)

Phase 20 made `synvoid-http` the canonical owner of reusable HTTP
parsing/normalization/dispatch logic and reduced `src/http/` to root
application composition:

- Added canonical fail-closed framing policy
  (`crates/synvoid-http/src/framing.rs`, 19 unit tests): duplicate
  `Content-Length`, `Content-Length` + `Transfer-Encoding`, unsupported
  codings, malformed/overflowing lengths, duplicate `Host`,
  absolute-form/origin-form conflicts, per-version missing-host policy.
  Enforced in `prepare_request_preflight` (400 before routing/WAF) and
  re-validated in `finalize_request_preparation` via the same helpers;
  duplicate-`Host` also fails closed on the HTTP/3 prelude.
- Moved listener sniff helpers (`HTTP_VALID_METHODS`,
  `is_tls_client_hello`, `is_valid_http_request_start`) into
  `synvoid_http::framing`; deleted both root copies (`src/http/server/`
  and `src/tls/server.rs`) and the duplicated sniff test modules (behavior
  pinned canonically in `framing.rs`).
- Documented the full 42-module matrix in
  `architecture/http_ownership_convergence.md`: 24 thin facades,
  11 narrow-trait adapters, 5 application handlers, 1 composition root,
  1 deprecated alias. No duplicate implementation remains.
- Added `tests/http_normalization_ownership_guard.rs` (4 tests): no second
  parser, shims delegate to crate, no duplicate WAF-decision tables,
  facades resolve to canonical modules.
- Reclassified `http` (`split_required` → `keep_app_root`, composition),
  `tls` (`split_required` → `keep_app_root`, server integration),
  `http_client` (`split_required` → `facade_existing_crate`, QUIC adapter
  only); ledgers, burn-down, surface audit, and `http_server.md` reconciled.
- Residual (documented, not forced): `HttpsServer::handle_request_with_cache`
  keeps its own flow instead of the canonical postlude composition —
  converging it is a TLS data-path rewrite, explicitly out of scope per the
  phase rejection criteria.

## Remaining `split_required` Modules

No remaining `split_required` modules. All entries closed:

- `admin` — closed by Phase 21 (this report, below): `keep_app_root` (composition)
- `plugin` — closed by Phase 21 (this report, below): `keep_app_root` (lifecycle composition)

## Phase 21 Closure (admin + plugin root-boundary closure)

Phase 21 closed the last two `split_required` modules per
`plans/phase_21_admin_plugin_root_boundary_closure.md`. Full inventory:
`architecture/admin_root_ownership.md`.

- `admin` (`split_required` → `keep_app_root`, composition). The module is
  predominantly Axum application/control-plane composition; extracting a crate
  around the handlers would only relocate files while keeping the same
  dependency fan-in. The reusable transport-neutral layer (auth primitives,
  rate limiting, schema helpers, `AdminStateProvider` narrow trait,
  `logs`/`probes`/`stats`/`system`/`common` handler logic) already lives in
  the existing `synvoid-admin` crate. Mutating handlers follow the typed
  `AdminMutationResult` + `AdminAuditEvent` flow; read handlers consume
  `synvoid-metrics`, mesh/service APIs, the plugin runtime owner, and
  `synvoid-config` without reconstructing subsystem state.
- `plugin` (`split_required` → `keep_app_root`, lifecycle composition).
  Deleted the root duplicate unified manager (~480 lines): `src/plugin/mod.rs`
  now re-exports the canonical `synvoid_plugin_runtime::plugin_manager`
  `PluginManager`/`PluginManagerLifecycle`. The mesh-store load preference is
  preserved via root adapter `load_wasm_plugin_with_mesh_fallback()` plus a
  mesh-agnostic `load_plugins_from_dir_with_resolver()` hook (the crate takes
  bytes, never root mesh types). The `AxumDynamicRouterLookup` /
  `WasmFilterBackend` impls moved to `synvoid-http::plugin_backend` (local
  trait + foreign type; no new dependency).
- `src/admin/handlers/common.rs` (~390→~130 lines): pagination/response DTOs
  re-exported from `synvoid_admin::handlers::common`; root keeps only
  `require_role`, `config_path`, `write_config_file_secure`. Removed
  `check_rate_limit`/`get_client_ip` (superseded by the tower rate-limit
  layer and `extract_client_ip_middleware`) and the duplicate `parse_ip`.
- Added `tests/admin_plugin_boundary_guard.rs` (4 tests): no root runtime
  type definitions, crate takes no `synvoid::` paths, root common
  re-exports DTOs, ledger/burn-down/surface-audit agree on `split_required`.
- Reconciled `root_module_ledger.md`, this report, and `final_surface_audit.md`
  (zero `split_required` entries everywhere).

## Phase 19 Closure (WAF ownership convergence)

Phase 19 made `synvoid-waf` the canonical owner of reusable WAF
policy/detection logic and reduced `src/waf/` to root application composition:

- Deleted never-compiled duplicate orphans (`flood/connection_limiter.rs`,
  `flood/syn_flood.rs`, `flood/udp_flood.rs`, `traffic_shaper/limiter.rs`);
  ported the orphan limiter's increment-then-validate fix and `remove_if`
  release hardening into the canonical crate limiter first.
- Removed the stale crate `ip_feed.rs` copy (never declared in
  `synvoid-waf/src/lib.rs`; feed fetching needs the HTTP-client stack) and
  kept the root feed integration as canonical with a documented blocker.
- Removed hot-path placeholders (`check_block_store`, `check_early`,
  `block_ip_for_honeypot`, `block_ip_with_threat_intel`) with their trait
  methods and production call sites; documented remaining non-hot-path
  placeholders as deprecated no-ops.
- Split `WafCore` into documented composition (`AppWaf`/`AppWafConfig`
  aliases; field classification in `architecture/waf_ownership_convergence.md`).
- Added `tests/waf_ownership_guard.rs` (5 tests) covering crate purity,
  facade thinness, deleted duplicates, removed placeholders, and shim callers.
- Reclassified `waf` from `split_required` to `keep_app_root` (composition
  over `synvoid-waf`); ledgers, burn-down, surface audit, and `waf.md`
  reconciled. Full matrix: `architecture/waf_ownership_convergence.md`.

## Next Recommended Cluster

All `split_required` modules are closed (Phase 21). Remaining follow-ups are
composition footnotes with named owners, not ownership ambiguity:

1. `http_client` QUIC tunnel dispatch (root-owned; depends on root tunnel/QUIC infra)
2. `ProxyServer` root trait-bound alias over `synvoid-proxy`
3. `static_files` local `file_manager` submodule (needs investigation)
4. `HttpsServer::handle_request_with_cache` flow convergence (TLS data-path rewrite, out of scope)
