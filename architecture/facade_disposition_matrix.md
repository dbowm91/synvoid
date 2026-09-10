# Compatibility-Facade Disposition Matrix (Phase 03)

Status: binding for Phase 03 burn-down. Companion to `architecture/root_module_ledger.md`
and `architecture/final_surface_audit.md`. Plan: `plans/architecture_phase_03_compatibility_facade_burndown.md`.

Most current overlap is **alias overlap, not duplicate implementation**. This matrix preserves
that distinction: removing a `pub use` facade deletes a discoverable path, not a second
implementation. Nothing in this phase introduces duplicate implementation.

## 1. Retirement policy (binding)

A root facade is eligible for `remove_now` only if **all** are true:

1. Zero workspace consumers after direct imports are migrated
   (`crate::<mod>` in `src/`, `synvoid::<mod>` in `src/`/`tests/`/`examples/`/`tools/`,
   excluding guard string literals).
2. No user-facing docs/examples intentionally advertise the root path as canonical.
3. No stable public-API commitment documents it (pre-1.0: `final_surface_audit.md`
   §10 promises no compatibility for root facades; root package semver is not a
   facade guarantee).
4. No root-only adapter/feature behavior hides behind it (no local type aliases with
   root trait bounds, no compat submodules, no feature-gated re-export differences,
   no local tests pinning behavior).
5. The canonical crate path is already public and ergonomic.

If external compatibility is uncertain, prefer `retain_stable_compat` over silent removal.
Do not add `#[deprecated]` where it would generate unmanageable internal warnings;
migrate internal callers first, then deprecate or remove.

Dispositions:

- `retain_stable_compat`: deliberate supported compatibility surface. New domain code
  must import the canonical crate; root composition/bins/tests may keep the alias where
  ergonomic. Removal requires a major-version migration note.
- `deprecate_then_remove`: compatibility path has plausible external consumers and needs
  a migration window. Not used in Phase 03 (no candidate needed it; see §4).
- `remove_now`: zero-value internal alias with no compatibility requirement. Deleted in
  Phase 03 with migration recorded below.
- `adapter_keep_app_root`: not a pure facade. Root-specific adapter remains, but the
  canonical domain implementation stays in the crate. New code uses the crate for domain
  types and the root only for the adapter.

`keep_app_root` modules are out of scope and were not re-evaluated for removal.

## 2. Consumer-count method (reproducible)

```text
# per-facade root-internal users
rg -n "crate::<mod>\b" --type rust src
# external-path users (bins use synvoid::; tests/examples/tools do too;
# exclude boundary_composition_guard.rs string literals)
rg -n "synvoid::<mod>\b" --type rust src tests examples tools | grep -v boundary_composition_guard
# docs teaching the root path
rg -n "synvoid::<mod>\b|crate::<mod>\b" --glob "*.md" README.md docs architecture .opencode/skills
```

Counts below are Phase 03 baseline (commit `31a89ae0`), before the burn-down.
Domain crates (`crates/*`) have zero `synvoid::` imports (enforced by
`root_facade_boundary_guard`); they are not listed per facade.

## 3. Disposition matrix

| Root facade | Canonical crate/path | Shape | Workspace consumers (baseline) | Docs/examples teach root? | Feature gate diff? | Disposition | Rationale |
|-------------|----------------------|-------|-------------------------------|---------------------------|-------------------|-------------|-----------|
| `app_server` | `synvoid_app_server` | pure re-export (`pub use synvoid_app_server::*`) | 15 `crate::app_server` in `src/` (tls/server, http/server, server/resources) | No | No | `retain_stable_compat` | Composition roots use the alias; canonical crate public. Removal would churn wiring without deleting impl. |
| `auth` | `synvoid_auth` | pure re-export | 0 | No | No | `remove_now` (Phase 03) | Zero consumers; canonical `synvoid_auth` public. Migration: `crate::auth::X` → `synvoid_auth::X`. |
| `block_store` | `synvoid_block_store` | pure re-export | 11 `crate::` + 3 `synvoid::` (tests) | No (tests use both paths) | No | `retain_stable_compat` | Worker/supervisor composition + integration tests use the alias. |
| `buffer` | `synvoid_utils::buffer` | inline re-export in `lib.rs` | 2 `crate::buffer` (`src/tcp/listener.rs`, docs) | No | No | `retain_stable_compat` | Ergonomic short path for composition; canonical `synvoid_utils::buffer` public. |
| `cgi` | `synvoid_app_handlers::cgi` | pure re-export | 0 | No | No | `remove_now` (Phase 03) | Zero consumers; migration: `crate::cgi::X` → `synvoid_app_handlers::cgi::X`. |
| `challenge` | `synvoid_challenge` | pure re-export (explicit symbol list) | 0 (guard string literals only) | No (only historical "no `crate::challenge` remains" notes) | No | `remove_now` (Phase 03) | Zero consumers since Phase 18; canonical `synvoid_challenge` public. |
| `config` | `synvoid_config` | facade with compat submodules (`main`, `site`, `dns`, `protection`, `traffic` + `DenyListLimitsConfig` alias) | 198 `crate::` + 21 `synvoid::` | Yes (pervasive; composition standard) | No | `adapter_keep_app_root` | Compat submodules are root-owned shims; domain implementation canonical in crate. Do not collapse without migrating 219 call sites. |
| `dns` | `synvoid_dns` | feature-gated re-export | 15 `crate::` + 1 `synvoid::` (test) | No | Yes (`dns`, `mesh` re-exports) | `retain_stable_compat` | Feature-gated (`dns`/`mesh`) parity with crate gates; bins/tests use alias. |
| `fastcgi` | `synvoid_app_handlers::fastcgi` | pure re-export | 2 `crate::fastcgi` | No | No | `retain_stable_compat` | In use by composition; canonical `synvoid_app_handlers::fastcgi` public. |
| `filter` | `synvoid_filter` | pure re-export | 0 | No | No | `remove_now` (Phase 03) | Zero consumers; migration: `crate::filter::X` → `synvoid_filter::X`. |
| `geoip` | `synvoid_geoip` | root re-export (`pub use`) | 4 `crate::geoip` | No | No | `retain_stable_compat` | WAF composition uses alias; canonical `synvoid_geoip` public. |
| `honeypot_port` | `synvoid_honeypot` | pure re-export (directory facade) | 55 `crate::honeypot_port` | No | No | `retain_stable_compat` | Active honeypot composition surface; not a removable stub. |
| `http3` | `synvoid_http3` | pure re-export (`Http3Server`, `Http3WafBackend`) | 1 `crate::http3` | No | No | `retain_stable_compat` | Narrow two-symbol facade used by server composition. |
| `http_client` | `synvoid_http_client` + root `quic_tunnel_dispatch` | facade with local adapter | 15 `crate::` + 8 `synvoid::` | No | No | `adapter_keep_app_root` | Root retains `quic_tunnel_dispatch` (depends on root tunnel/QUIC infra); `streaming_waf_body` is a pure shim. |
| `integrity` | `synvoid_integrity` | root re-export (`pub use`) | 0 | No | No | `remove_now` (Phase 03) | Zero consumers; migration: `crate::integrity::X` → `synvoid_integrity::X`. |
| `listener` | `synvoid_http::listener` | pure re-export (`ConnectionContext` only) | 2 `crate::listener` | No | No | `retain_stable_compat` | Narrow single-symbol alias used by composition. |
| `location_matcher` | `synvoid_proxy::location_matcher` | pure re-export | 1 `crate::location_matcher` | No | No | `retain_stable_compat` | Single consumer; retain to avoid churning proxy wiring for one alias. |
| `mesh` | `synvoid_mesh` | pure re-export, feature-gated | 174 `crate::` + 46 `synvoid::` | Yes (skills/docs use `crate::mesh` in composition context) | Yes (`mesh`) | `retain_stable_compat` | Primary composition surface for mesh; canonical `synvoid_mesh::mesh` public but root alias is ergonomic for 220 call sites. |
| `metrics` | `synvoid_metrics` | facade with local tests | 35 `crate::metrics` | No | No | `retain_stable_compat` | Local test module pins behavior; move tests to crate before any future removal. Not an adapter, so not `adapter_keep_app_root`. |
| `mime` | `synvoid_app_handlers::mime` | pure re-export | 5 `crate::mime` | No | No | `retain_stable_compat` | In use by composition. |
| `php` | `synvoid_app_handlers::php` | pure re-export | 0 | No | No | `remove_now` (Phase 03) | Zero consumers; migration: `crate::php::X` → `synvoid_app_handlers::php::X`. |
| `process` | `synvoid_ipc` | pure re-export (directory facade) | 113 `crate::` + 37 `synvoid::` | Yes (IPC composition standard) | No | `retain_stable_compat` | Core IPC composition surface; 150 call sites. |
| `protocol` | `synvoid_proxy::protocol` | pure re-export | 3 `crate::protocol` | No | No | `retain_stable_compat` | In use by TCP composition. |
| `proxy` | `synvoid_proxy` | facade with local adapter (`ProxyServer` alias bound to `crate::waf::adapter::RootWafProcessor`) | 9 `crate::` + 7 `synvoid::` | Yes (composition standard) | No | `adapter_keep_app_root` | `ProxyServer` alias is root-specific (root WAF trait bound); all other symbols are pure re-exports. |
| `proxy_cache` | `synvoid_proxy_cache` | root re-export (`pub use`) | 0 | No | No | `remove_now` (Phase 03) | Zero consumers; migration: `crate::proxy_cache::X` → `synvoid_proxy_cache::X`. |
| `router` | `synvoid_proxy::router` | pure re-export | 12 `crate::router` | No | No | `retain_stable_compat` | Server/TLS/HTTP composition uses alias. |
| `router_adapter` | `synvoid_proxy::router_adapter` | pure re-export | 2 `crate::router_adapter` | No | No | `retain_stable_compat` | Server composition uses alias. |
| `serialization` | `synvoid_utils::serialization` | root re-export (`pub use`) | 10 `crate::serialization` | No | No | `retain_stable_compat` | Shared serialization path used across composition. |
| `serverless` | `synvoid_serverless` | pure re-export (directory facade) | 30 `crate::serverless` | No | No | `retain_stable_compat` | Active serverless composition surface. |
| `spin` | `synvoid_plugin_runtime::spin` | pure re-export | 2 `crate::spin` | No | No | `retain_stable_compat` | Admin composition uses alias. |
| `static_files` | `synvoid_static_files` | pure re-export (Phase 02) | 3 `crate::static_files` | No | No | `retain_stable_compat` | HTTP composition uses alias; canonical `FileManager` in crate. |
| `streaming` | `synvoid_proxy::bidirectional` | pure re-export | 2 `crate::streaming` | No | No | `retain_stable_compat` | TCP composition uses alias. |
| `theme` | `synvoid_theme` | pure re-export | 13 `crate::theme` | No | No | `retain_stable_compat` | HTTP/admin composition uses alias. |
| `tunnel` | `synvoid_tunnel` | pure re-export | 11 `crate::tunnel` | No | No | `retain_stable_compat` | Supervisor/server composition uses alias. |
| `upload` | `synvoid_upload` | pure re-export | 0 `crate::` + 1 `synvoid::` (test) | No | No | `remove_now` (Phase 03, after test migration) | Single test consumer migrated to `synvoid_upload::yara_scanner`; then zero. |
| `upstream` | `synvoid_upstream` | root re-export (`pub use`) | 6 `crate::upstream`/`synvoid::upstream` (supervisor, tcp) | No | No | `retain_stable_compat` | Supervisor/TCP composition uses alias. |
| `vpn_client` | `synvoid_vpn_client` | pure re-export | 0 `crate::` + 5 `synvoid::` (bins) | No | No | `retain_stable_compat` | Binaries (`src/bin/synvoid-vpn.rs`, `src/bin/server.rs`) use the alias ergonomically; retain for bin composition. |

No facade required `deprecate_then_remove` in Phase 03: the 8 removals had no plausible
external-consumer signal (zero workspace users, no docs advertising the root path, no
stable-API commitment), and every retained facade has active internal users where a
deprecation attribute would create unmanageable warnings.

## 4. Phase 03 burn-down (executed)

Removed 8 root facades (7 with zero baseline consumers + `upload` after migrating its
single test consumer):

| Removed root path | Canonical replacement | Migration evidence |
|-------------------|----------------------|--------------------|
| `crate::auth` / `synvoid::auth` | `synvoid_auth` | Zero `crate::auth`/`synvoid::auth` hits at baseline; `src/auth/mod.rs` was `pub use synvoid_auth::*`. |
| `crate::cgi` / `synvoid::cgi` | `synvoid_app_handlers::cgi` | Zero hits; `src/cgi/mod.rs` was a one-line re-export. |
| `crate::challenge` / `synvoid::challenge` | `synvoid_challenge` | Zero hits (guard string literals excluded); Phase 18 already migrated `src/` to `synvoid_challenge`. |
| `crate::filter` / `synvoid::filter` | `synvoid_filter` | Zero hits; `src/filter/mod.rs` re-exported 5 symbols, all public in crate. |
| `crate::integrity` / `synvoid::integrity` | `synvoid_integrity` | Zero hits; `lib.rs` was `pub use synvoid_integrity as integrity`. |
| `crate::php` / `synvoid::php` | `synvoid_app_handlers::php` | Zero hits; one-line re-export. |
| `crate::proxy_cache` / `synvoid::proxy_cache` | `synvoid_proxy_cache` | Zero hits; `lib.rs` was `pub use synvoid_proxy_cache as proxy_cache`. |
| `crate::upload` / `synvoid::upload` | `synvoid_upload` | 1 test hit (`tests/integration_test.rs` yara_scanner import) migrated to `synvoid_upload::yara_scanner`; then zero. |

Deletions: `src/auth/`, `src/cgi/`, `src/challenge/`, `src/filter/`, `src/php/`,
`src/upload/` directories (each only `mod.rs`, plus `src/auth/AGENTS.override.md`
whose canonical guidance is preserved here and in `crates/synvoid-auth`);
`integrity`/`proxy_cache` lines removed from `src/lib.rs`.
Ledger rows reclassified to `legacy_or_stale` / `removed (Phase 03)` following the
`captcha`/`logging` precedent. `final_surface_audit.md` compatibility table updated.
Guard `tests/facade_disposition_guard.rs` pins the removed set and facade thinness.

## 5. Retained-facade governance

- New domain code must import the canonical crate in §3, never add `crate::<facade>`
  users where a canonical import works.
- Retained facades must stay thin: pure re-exports, documented adapters
  (`config` compat submodules, `proxy::ProxyServer`, `http_client::quic_tunnel_dispatch`),
  or pinned tests (`metrics`). The disposition guard fails substantive additions.
- Reintroducing a §4 removed path without updating this matrix + the ledger fails the guard.
- Next candidates (not in this pass): `upload`-style single-consumer cleanups only after
  migration; `metrics` test relocation to `synvoid-metrics`; `location_matcher`/`listener`
  style narrow aliases only on major-version boundaries. No `keep_app_root` moves.
