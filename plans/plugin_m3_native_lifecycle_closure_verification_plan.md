# Plugin M3 Native/Lifecycle Closure and Verification Plan

## Purpose

Milestone 3 added the right major architecture for unsafe native extensions and plugin lifecycle/hot-reload hardening. Two follow-up gap files now exist:

- `plans/plugin_m3_phase_08_gap_fixes.md`
- `plans/plugin_m3_phase_09_gap_fixes.md`

The Phase 9 gap file marks its items complete, while the Phase 8 gap file still lists critical native-loader issues. This plan consolidates the remaining Phase 8 implementation work and adds a verification pass across both Phase 8 and Phase 9 so the milestone can be closed cleanly.

## Current Assessment

### Phase 8: Unsafe Native Extension Containment

Implemented direction is correct:

- native shared libraries have been renamed/reclassified as unsafe native extensions;
- `axum_loader` was replaced with `unsafe_native_loader`;
- `UnsafeNativeExtension` retains an `Arc<Library>` handle;
- unsafe native config exists;
- docs now state native extensions are not sandboxed;
- status/metrics surfaces have been started.

Remaining risk is concentrated in enforcement and tests. The Phase 8 gap file explicitly says the implementation is only partially complete and lists critical issues: production gate enforcement, FFI panic handling, native hot-reload gating, permission policy correction, generation semantics, deprecated config aliases, metrics, last-load error, audit logging, external-client placeholder, and missing tests.

### Phase 9: Lifecycle and Hot Reload

The Phase 9 gap file says complete and lists implemented items:

- `quarantine_plugin` lifecycle state wiring;
- `PluginReplacePolicy` wired into all four load paths;
- `wait_for_stable_file` called from `prepare_reload_candidate`;
- generation/lifecycle metadata in load paths;
- `list_plugin_generations()` and `get_plugin_detail()`;
- behavioral tests for generation lifecycle, hot reload config, quarantine, and replace policy.

Phase 9 should still receive a targeted verification pass because lifecycle code touches multiple load/reload entry points and can regress through wrapper paths.

## Workstream 1: Close Critical Phase 8 Production Gate Enforcement

### Problem

The Phase 8 gap file notes that `load_plugin()` must check production mode, `allow_in_production`, risk acknowledgement, and allowed directories before proceeding, and that some error variants may exist but be dead code.

### Required Invariant

No unsafe native extension may be loaded unless all applicable config gates pass before any library is opened with `libloading::Library::new`.

### Implementation Steps

1. Identify all native load entry points:

- `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`
- root re-export wrapper in `src/plugin/unsafe_native_loader.rs`
- `PluginManager` native load helpers in `src/plugin/mod.rs`
- any hot-reload/native reload function

2. Add a single gate function and route all native load paths through it:

```rust
pub fn enforce_unsafe_native_load_policy(
    path: &Path,
    config: &UnsafeNativePluginConfig,
    env: RuntimeEnvironment,
) -> Result<UnsafeNativeLoadDecision, UnsafeNativePluginError>
```

3. Enforce, before library open:

- `config.enabled == true`;
- if production: `config.allow_in_production == true`;
- if production: risk acknowledgement exactly matches the expected string;
- `allowed_dirs` is non-empty when loading from filesystem;
- candidate path is canonicalized and inside an allowed dir;
- optional exact library hash allowlist matches if configured;
- native hot reload path also checks `hot_reload_enabled` separately.

4. Ensure the function returns structured errors:

- `Disabled`
- `ProductionDenied`
- `MissingRiskAcknowledgement`
- `PathOutsideAllowedDirs`
- `HashMismatch`
- `HotReloadDenied`

5. Record load-denied audit events before returning.

### Tests

Add tests for:

- default config rejects load before `Library::new`;
- production with enabled but `allow_in_production = false` rejects;
- production with missing/wrong risk acknowledgement rejects;
- production with empty allowed dirs rejects;
- path outside allowed dir rejects;
- allowed dir path accepts policy gate;
- hash mismatch rejects;
- hot reload rejects when `hot_reload_enabled = false`.

### Acceptance Criteria

- No native load path can bypass the production gate.
- Error variants are exercised by tests and not dead code.
- Rejections happen before library loading.

## Workstream 2: FFI Panic and Unwind Boundary Hardening

### Problem

The gap file requires wrapping `factory()` and `Box::from_raw()` in `std::panic::catch_unwind` to prevent native panics from crossing FFI/plugin-loader boundaries.

### Required Invariant

A panic or invalid plugin factory result must fail native extension loading safely and must not unwind across FFI or leave partially registered routes.

### Implementation Steps

1. Audit unsafe blocks around:

- ABI version symbol lookup;
- plugin factory symbol lookup;
- calling `create_router`/factory;
- pointer ownership conversion;
- router wrapping/middleware attachment.

2. Wrap unsafe factory execution in `catch_unwind(AssertUnwindSafe(...))`.
3. If factory panics:

- increment `load_failed_total`;
- set `last_load_error`;
- emit structured audit event;
- return `UnsafeNativePluginError::FactoryPanic` or equivalent.

4. Validate factory pointer before `Box::from_raw`:

- null pointer rejects;
- optional alignment/sanity check if possible;
- do not register anything before validation.

5. Document the ABI contract: plugin factories must not panic, must return an owned pointer, and must not return borrowed or stack memory.
6. Consider avoiding `Box::from_raw` on untrusted native pointers if ABI can be changed later; note as future work if not changed now.

### Tests

Because generating actual dynamic libraries in unit tests may be heavy, use one or both approaches:

- split factory-call logic into a helper that can be tested with a function pointer/closure;
- add integration fixture dynamic library build only if the repo already supports it.

Required tests:

- factory panic returns safe error;
- null pointer returns safe error;
- load failure does not register extension;
- load failure records `last_load_error`;
- load failure increments metric/audit event.

### Acceptance Criteria

- No panic crosses native loader boundary.
- No partial registration happens after failed factory call.
- FFI ownership assumptions are documented.

## Workstream 3: Native Hot-Reload Gate and Generation Semantics

### Problem

The gap file says `enable_hot_reload()` must check `hot_reload_enabled`, and native extension reloads need generation semantics.

### Required Invariant

Native hot reload is disabled by default and separately gated from WASM hot reload. Reloaded native extensions produce a new generation and keep old generation references alive until in-flight requests drain.

### Implementation Steps

1. Ensure `enable_hot_reload()` or equivalent checks:

- unsafe native config enabled;
- native hot reload enabled;
- production native hot reload allowed only with separate acknowledgement;
- watched path inside allowed dirs.

2. Add or confirm `generation: u64` on `UnsafeNativeExtension`.
3. Increment generation on reload.
4. Keep old `Arc<UnsafeNativeExtension>` alive during swap.
5. Expose generation in:

- `UnsafeNativeExtensionStatus`;
- global status;
- audit events;
- metrics, if bounded/appropriate.

6. Make native reload prepare new extension completely before replacing old extension in registry.

### Tests

- native hot reload disabled by default;
- enabling WASM hot reload does not enable native hot reload;
- native hot reload requires `unsafe_native.hot_reload_enabled = true`;
- production native hot reload requires the production unsafe native gate plus hot reload gate;
- reload increments generation;
- status reports generation;
- old generation remains alive while an `Arc` reference exists.

### Acceptance Criteria

- Native hot reload cannot be enabled accidentally.
- Generation semantics are visible and tested.
- Reload is load-then-swap for native extensions as well.

## Workstream 4: Correct Permission and Path Policy

### Problem

The Phase 8 gap file says current permission checks are too strict, rejecting `0o644`/`0o744`, while the plan only required rejecting world-writable files and parent directories.

### Required Invariant

Native extension path checks should reject unsafe paths without imposing unnecessary executable-bit or exact-mode constraints that block normal deployment packaging.

### Implementation Steps

1. Replace exact-mode check with:

- reject file if world-writable bit set;
- reject parent dirs if world-writable bit set;
- reject symlink by default;
- require canonical path inside allowed dir;
- require platform extension `.so`, `.dylib`, `.dll`;
- enforce max file size if present.

2. On Unix, use `PermissionsExt` to check `mode & 0o002 != 0`.
3. Decide whether group-writable should be allowed. Recommended: allow group-writable only if parent dir is trusted; otherwise at least document current policy.
4. Keep existing dangerous filename checks as advisory hygiene only if still useful, but do not treat them as a meaningful boundary.

### Tests

- `0o644` accepted when all other checks pass;
- `0o744` accepted when all other checks pass;
- `0o666` rejected;
- world-writable parent dir rejected;
- symlink rejected;
- wrong extension rejected;
- allowed dir canonical prefix enforced;
- path traversal cannot escape allowed dir.

### Acceptance Criteria

- Permission policy matches the plan.
- Tests cover both too-loose and too-strict cases.

## Workstream 5: Deprecated Config Alias and Migration

### Problem

The gap file asks for deprecated config alias support, while implementation appears to have started compatibility around `native_plugins`. The requested alias explicitly names `native_plugins_enabled -> unsafe_native_enabled`; the actual config shape may differ.

### Required Invariant

Legacy config names must either migrate safely with warnings or fail loudly with a clear error. They must never silently enable unsafe native extensions in production.

### Implementation Steps

1. Inventory legacy names used in docs/config/code:

- `native_plugins_enabled`
- `native_plugins`
- `axum_plugins`
- `native_plugins_enabled` under older plugin sections

2. Add deserialization aliases only where safe.
3. Emit deprecation warnings when legacy keys are used.
4. Do not let legacy config bypass the new production gate.
5. If both new and legacy config are present, new config wins.
6. Document migration examples.

### Tests

- legacy key maps to new config in development;
- legacy key does not bypass production acknowledgement;
- new key overrides legacy key;
- unsupported ambiguous legacy config returns clear error or warning;
- docs mention deprecation.

### Acceptance Criteria

- Compatibility is deliberate and safe.
- Deprecated keys cannot accidentally enable production native loading.

## Workstream 6: Metrics, Last Load Error, and Audit Logging

### Problem

The Phase 8 gap file asks for metrics counters, `last_load_error`, and audit logs for load/reject/unload.

### Required Invariant

Operators can determine whether unsafe native loading is disabled, rejected, failed, loaded, reloaded, or unloaded, and can identify the path/hash/generation without unbounded metric labels.

### Implementation Steps

1. Confirm metrics exist and are called in all relevant paths:

- `synvoid_unsafe_native_extension_loaded_total`
- `synvoid_unsafe_native_extension_load_failed_total`
- `synvoid_unsafe_native_extension_reloaded_total`
- optional `synvoid_unsafe_native_extension_request_total`

2. Labels should be bounded:

- extension name;
- result/failure class;
- generation if cardinality is acceptable or use event logs instead;
- avoid full paths as labels.

3. Add `last_load_error` to `PluginManager`/native status if not fully wired.
4. Add audit logs for:

- load accepted;
- load rejected by policy;
- hash mismatch;
- ABI mismatch;
- factory panic;
- reload success/failure;
- unload/remove.

5. Include in audit log:

- canonical path;
- SHA-256;
- ABI version if available;
- generation;
- production/dev mode;
- decision/failure class.

### Tests

- accepted load records loaded metric;
- rejected load records failed metric and last_load_error;
- reload records reload metric;
- unload emits audit log/status transition;
- metrics avoid full path label;
- status contains last_load_error and extension metadata.

### Acceptance Criteria

- Native extension operations are observable.
- Failures are not silent.
- Metrics are cardinality-safe.

## Workstream 7: ExternalPluginClient Placeholder

### Problem

The original Phase 8 plan asked for an out-of-process alternative placeholder. The gap file asks to add `ExternalPluginClient` in `unsafe_native_loader.rs`.

### Required Invariant

Docs and code should make clear that the production-recommended native extensibility path is out-of-process, even if the full RPC implementation is future work.

### Implementation Steps

1. Add a small trait or design stub:

```rust
pub trait ExternalPluginClient {
    type Error;

    fn filter_request(&self, request: ExternalPluginRequest<'_>) -> Result<ExternalPluginDecision, Self::Error>;
}
```

2. Keep it intentionally minimal if no call sites exist.
3. Document as future extension seam, not current production feature.
4. Avoid adding dead complex abstractions beyond the placeholder.

### Tests

- trait exports successfully;
- docs refer to it as future/out-of-process seam;
- no production path depends on unimplemented behavior.

### Acceptance Criteria

- Out-of-process recommendation is reflected in code/docs.
- Placeholder does not create misleading active functionality.

## Workstream 8: Complete Phase 8 Test Matrix

### Problem

The Phase 8 gap file asks for all plan tests across WS1, WS2, WS4, and WS6.

### Required Test Coverage

Add tests for:

1. Defaults disabled.
2. Production gate disabled/enabled variants.
3. Risk acknowledgement exactness.
4. Allowed dirs canonical path enforcement.
5. Symlink rejection.
6. World-writable file rejection.
7. World-writable parent dir rejection.
8. Normal `0o644`/`0o744` accepted on Unix.
9. Wrong extension rejection.
10. Hash mismatch rejection.
11. Hash match policy acceptance.
12. Factory panic safe error.
13. Null factory pointer safe error.
14. Library handle retained in status/extension wrapper.
15. Hot reload disabled by default.
16. Native hot reload requires separate config.
17. Reload generation increments.
18. Last load error set on rejection.
19. Load failure metric path exercised.
20. Load success metric path exercised.
21. Audit event emitted on rejection.
22. Deprecated config alias warning/migration.
23. Native docs do not say sandboxed.
24. Status includes path/hash/ABI/generation without mixing with WASM plugin sandbox status.

### Acceptance Criteria

- Phase 8 has a guardrail test suite comparable to Phase 9.
- Critical loader invariants are executable, not only documented.

## Workstream 9: Phase 9 Verification Pass

### Purpose

The Phase 9 gap file says complete, but lifecycle code must be verified across all entry points and wrappers.

### Verification Targets

1. All load paths route through duplicate-name policy:

- file load;
- memory load;
- memory-with-manifest load;
- mesh/distributed load if present;
- root `src/plugin/mod.rs` wrappers;
- hot reload.

2. All reload paths are prepare-then-commit:

- no active generation mutation before candidate validation;
- failed reload preserves active generation;
- cache invalidation only after commit.

3. Stable-file detection is actually called before hot-reload read.

4. Lifecycle state is created for every loaded plugin.

5. Operator APIs are state-machine enforced:

- disable;
- reset;
- quarantine;
- remove.

6. `PluginInfo`/`PluginDetail` includes generation, hash, lifecycle state, and last error.

7. Native and WASM namespaces do not silently collide.

### Implementation Steps

1. Add a `plugin_lifecycle_entrypoint_guard.rs` test if current guard file is too broad.
2. Use source scanning only for structural invariants that are hard to integration-test.
3. Prefer behavioral tests for duplicate/reload/operator semantics.
4. Update CI guard job to include the lifecycle guard file.

### Tests

- duplicate name rejected across file and memory load;
- memory-with-manifest path creates generation and lifecycle state;
- failed reload leaves old generation active;
- stable-file policy invoked before candidate read;
- mesh/distributed load path either covered or explicitly deferred if not implemented;
- native/WASM namespace collision rejected;
- operator remove clears generation registry and sorted cache.

### Acceptance Criteria

- Phase 9 claims are verified across real entry points.
- Any deferred path is documented with a guard preventing accidental bypass.

## Workstream 10: CI and Status Verification

### Problem

Commit status/workflow runs have not been visible through connector status calls. The CI jobs may be configured but not verified externally.

### Required Invariant

At minimum, the repository must have a local verification script and CI job entries that cover Phase 8/9 guardrails. Ideally, GitHub Actions visibly reports them.

### Implementation Steps

1. Add Phase 8 and Phase 9 tests to CI:

```bash
cargo test -p synvoid-plugin-runtime -- unsafe_native
cargo test --test unsafe_native_sandbox_language_guard
cargo test --test plugin_lifecycle_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
```

2. Add them to `scripts/verify_architecture.sh` or a dedicated `scripts/verify_plugin_runtime.sh`.
3. If GitHub Actions status remains invisible, document manual verification command in `AGENTS.md` and `docs/PLUGINS.md`.
4. Optionally add a lightweight `workflow_dispatch` trigger for manual runs.

### Acceptance Criteria

- Developers have one clear command/job to run before merging plugin runtime changes.
- CI includes unsafe native and lifecycle guardrails.
- Missing external status visibility is either fixed or explicitly documented.

## Recommended Execution Order

1. Phase 8 production gate enforcement.
2. Phase 8 FFI panic/null-pointer handling.
3. Phase 8 hot-reload gate and generation semantics.
4. Phase 8 path/permission correction.
5. Metrics/last-load-error/audit logging.
6. Deprecated config alias and docs.
7. ExternalPluginClient placeholder.
8. Complete Phase 8 test matrix.
9. Phase 9 entry-point verification tests.
10. CI/script verification update.

## Validation Commands

Minimum closure validation:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test unsafe_native_sandbox_language_guard
cargo test --test plugin_lifecycle_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test abi_memory_boundary_guard
```

If native loader tests are by name inside the runtime crate:

```bash
cargo test -p synvoid-plugin-runtime -- unsafe_native
cargo test -p synvoid-plugin-runtime -- test_unsafe_native
```

If root plugin manager tests are added:

```bash
cargo test -p synvoid -- plugin_native
cargo test -p synvoid -- plugin_lifecycle
cargo test -p synvoid -- hot_reload
```

## Completion Definition

Milestone 3 is closed when:

- Phase 8 gap file items are implemented or explicitly marked deferred with safe rationale.
- Native extension production gate cannot be bypassed by any load/reload path.
- Native FFI loader catches panics/null pointers and avoids partial registration.
- Native hot reload is separately gated and generation-aware.
- Native path/permission policy matches the plan and is tested.
- Native metrics, status, last-load-error, and audit logging are wired.
- Phase 8 has broad guardrail tests.
- Phase 9 lifecycle claims are verified across all load/reload/operator entry points.
- CI or local verification script runs the unsafe-native and lifecycle guardrails.
