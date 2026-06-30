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

## Remaining `split_required` Modules

| Module | LOC | Blocker |
|--------|-----|---------|
| `admin` | 8,358+ | Mixed Axum router + handlers; extract after Phase 12 legacy endpoint closure |
| `auth` | 1,235 | Good extraction candidate for synvoid-auth; touches admin heavily |
| `challenge` | 865 | ChallengeManager orchestration root-owned; primitives in synvoid-challenge |
| `http` | 4,720+ | Largest/high-risk; plan after WAF/request boundaries settle |
| `http_client` | 219 | Small; QUIC tunnel dispatch depends on root tunnel infra |
| `plugin` | 608 | Composition root stays root; runtime in synvoid-plugin-runtime |

## Next Recommended Cluster

1. `auth` — 1,235 LOC, minimal root dependencies (DrainFlag only), good candidate for `synvoid-auth`
2. `challenge` — 865 LOC, move manager orchestration or classify root-owned
3. `http_client` — 219 LOC, smallest remaining, could be reclassified as facade
