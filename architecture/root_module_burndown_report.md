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

## Remaining `split_required` Modules

| Module | LOC | Blocker |
|--------|-----|---------|
| `admin` | 8,358+ | Mixed Axum router + handlers; extract after Phase 12 legacy endpoint closure |
| `http` | 4,720+ | Largest/high-risk; plan after WAF/request boundaries settle |
| `http_client` | 219 | Small; QUIC tunnel dispatch depends on root tunnel infra |
| `plugin` | 608 | Composition root stays root; runtime in synvoid-plugin-runtime |
| `tls` | — | Local `HttpsServer` depends on root HTTP infra; core TLS in dedicated crate |
| `waf` | 1,056+ | `WafCore` and root adapters root-owned; core traits/primitives in synvoid-waf |

## Next Recommended Cluster

1. `http_client` — 219 LOC, smallest remaining, could be reclassified as facade
2. `waf` — Phase 19 ownership convergence (now unblocked: `WafCore` no longer pins root auth/challenge impls)
3. `tls` — server integration still root-owned; core TLS already extracted
