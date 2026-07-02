# Plugin M3 Phase 9: Gap Fixes

**Status: COMPLETE** (all items implemented and verified)

## Goal
Close the gaps between the implemented Phase 9 code and the plan requirements. The core infrastructure (generation tracking, atomic reload pipeline, stable-file detection, lifecycle state machine, hot-reload config, operator APIs, guardrail tests) is implemented and passing. This plan addresses incomplete wiring, missing methods, and absent behavioral tests.

## Priority 1 — Correctness
1. ✅ **Wire `quarantine_plugin` lifecycle state** — Added `reason: &str` parameter, `set_plugin_lifecycle_state(Quarantined)`, `record_lifecycle_transition()`. Added `Quarantined → Active` transition to `is_valid_transition()`.
2. ✅ **Wire `PluginReplacePolicy` into load paths** — Added `check_duplicate_name()` helper that consults `replace_policy`. Wired into all 4 load paths with `PluginSourceIdentity` extraction.
3. ✅ **Add `wait_for_stable_file` call in `prepare_reload_candidate`** — Added `stability_policy: Option<&FileStabilityPolicy>` parameter, calls `wait_for_stable_file(path, policy)` before reading bytes, defaults to `hot_reload_config.stability_policy`.
4. ✅ **Fix `load_plugin_with_limits` missing generation/lifecycle** — Added `LoadedPluginGeneration` creation and `plugin_lifecycle_states` insert. Also fixed `load_plugin_from_memory_with_priority` and `load_plugin_from_memory_with_manifest`.

## Priority 2 — Missing Features
5. ✅ **Add `list_plugin_generations()` method** — Returns `Vec<(String, LoadedPluginGeneration)>` of all loaded plugins.
6. ✅ **Add `get_plugin_detail(name)` method** — Returns `Option<PluginDetail>` with generation, lifecycle state, policy, and source path.

## Priority 3 — Tests
7. ✅ **Behavioral tests for generation lifecycle** — `load_creates_generation_1`, `reload_increments_generation`, `list_plugin_generations_returns_all`, `get_plugin_detail_returns_full_info`.
8. ✅ **Behavioral tests for `validate_hot_reload_config`** — `validate_hot_reload_config_production_default_rejects`.
9. ✅ **Behavioral test for `quarantine_plugin`** — `quarantine_sets_lifecycle_state`, `quarantine_then_reset`.
10. ✅ **Behavioral test for `PluginReplacePolicy`** — `replace_policy_reject_existing_blocks_duplicate`, `replace_policy_replace_same_source_allows_same_name`.

## Files Modified
- `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` — Items 1–6
- `crates/synvoid-plugin-runtime/src/lib.rs` — Exported `PluginDetail`
- `tests/plugin_lifecycle_guard.rs` — Items 7–10 + updated `duplicate_name_check_in_all_load_paths` guardrail
- `Cargo.toml` — Added `wat = "1"` dev-dependency

## Validation Results
```bash
cargo fmt --all -- --check                    ✅ clean
cargo clippy -p synvoid-plugin-runtime ...    ✅ no issues
cargo test -p synvoid-plugin-runtime          ✅ 362 passed
cargo test --test plugin_lifecycle_guard       ✅ 21 passed
cargo test --test plugin_capability_boundary_guard  ✅ 10 passed
cargo test --test plugin_signature_policy_guard     ✅ 12 passed
```
