# Phase 28 Plan: Unsafe Native Extension Capability Isolation

Status: ready for implementation after Phase 25.

Roadmap position: Track 4, Phase 28.

Primary goal: remove native shared-library loading authority from the ordinary sandboxed WASM plugin-runtime dependency surface and make any remaining in-process native execution explicitly opt-in at compile time and runtime.

## Current state

SynVoid correctly labels native extensions as unsafe. `architecture/unsafe_native_extensions.md` documents that they execute with full process authority, may bypass WASM capabilities, and are disabled by default unless explicit production gates are satisfied. The loader includes useful hardening: path canonicalization, allowed-directory checks, world-writable rejection, optional hash allowlisting, library-handle lifetime retention, and reload generation management.

The remaining problem is dependency/capability placement. `crates/synvoid-plugin-runtime` always declares `libloading`, exports `unsafe_native_loader`, and `PluginManager` owns native extension wrappers alongside sandboxed WASM state. This means the normal plugin runtime package carries a capability that is fundamentally outside the WASM trust model even when configuration disables it.

A placeholder `ExternalPluginClient` already exists as an architectural seam for eventual out-of-process native extensions. This phase should make that seam real enough to isolate dependency authority without inventing generic remote execution.

## Target architecture

Preferred package split:

- `synvoid-plugin-runtime`: sandboxed WASM/plugin manifests/capabilities/ABI/lifecycle only; no `libloading` in its default dependency graph.
- `synvoid-native-extension`: explicit unsafe native loader, ABI/version checks, path/hash/permission validation, library lifetime/reload generation, native-specific metrics/status DTOs.
- root composition: chooses whether native support is compiled/enabled and wires a narrow native-extension backend into plugin management.

A compile-time feature such as `unsafe-native-extensions` should be off by default unless compatibility requirements demand a transition period. Runtime config gates remain mandatory even when compiled.

## Part A — Define the native-extension boundary

Inventory all native-specific types and methods in:

- `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`;
- `crates/synvoid-plugin-runtime/src/plugin_manager.rs`;
- root `src/plugin/unsafe_native_loader.rs` shim;
- config/plugin docs and tests;
- native extension examples.

Move native-only types and implementation to `synvoid-native-extension`, including:

- `UnsafeNativeExtension`;
- `UnsafeNativePluginError` and compatibility aliases where needed;
- `Library`/symbol loading and FFI calls;
- path/hash/permission validation;
- generation/hot-reload lifetime state;
- native-specific status/metrics helpers.

Do not move WASM manifest capabilities, guest ABI, Wasmtime, or plugin signing into the native crate unless genuinely shared low-level DTOs require a neutral owner.

## Part B — Remove native assumptions from PluginManager

Refactor `PluginManager` so native support is behind a narrow interface rather than a concrete `UnsafeNativeExtensionWrapper` compiled unconditionally.

Possible interface shape:

- load a named native extension from a validated local artifact;
- unload/reload by generation;
- resolve a request/router callback through an opaque handle;
- query bounded status metadata.

The interface must not expose `libloading::Library`, raw function pointers, or arbitrary symbol lookup to callers.

When the compile-time feature is absent, native-related manager methods should either not exist or return an explicit `Unsupported` capability result through compatibility APIs. They must not silently pretend a native extension loaded.

## Part C — Preserve and strengthen runtime gates

Compilation of native support does not weaken runtime policy.

Retain:

- `enabled = true` requirement;
- production-specific `allow_in_production` requirement;
- exact risk-acknowledgement requirement;
- non-empty allowed directories;
- canonical path enforcement;
- symlink/world-writable policy;
- extension allowlist/hash checks;
- generation-aware handle lifetime;
- separate hot-reload gate.

Add an invariant that every path reaches all applicable gates before the first `Library::new` call. Keep static tests for ordering where practical.

## Part D — Compile-time capability isolation

1. Move `libloading` out of `synvoid-plugin-runtime` default dependencies.
2. Make the root/native crate feature graph explicit.
3. Verify `cargo tree -p synvoid-plugin-runtime` contains no `libloading` when native support is disabled.
4. Keep platform-specific `libloading` uses such as Wintun independent; the success criterion is plugin-runtime capability isolation, not banning `libloading` workspace-wide.
5. Ensure minimal/default deployment profiles document whether unsafe native support is compiled.

## Part E — External process seam

Do not implement a generic remote-exec protocol. Define the smallest typed client/server contract needed to replace in-process native routing later.

If practical in this phase, provide an experimental local external-host backend behind a non-default feature using:

- UDS/named-pipe or existing bounded IPC primitives;
- versioned request/response DTOs;
- request body/header size limits;
- deadlines and concurrency limits;
- child crash/restart handling;
- no inherited secrets beyond explicit capability grants;
- no arbitrary path/symbol operations from the request path.

If full out-of-process hosting is too broad, leave it as a concrete follow-up seam with tests and no placeholder methods that claim execution.

## Part F — ABI/lifecycle compatibility

Preserve native ABI/version checks and library-handle lifetime guarantees.

Required tests:

- incompatible ABI rejected before registration;
- wrong hash/path/permissions rejected before load;
- library stays alive while any derived router/handler handle is alive;
- failed reload does not replace the working generation;
- unload/reload drains old generation safely;
- panic/error containment remains at least as strong as current behavior;
- native feature disabled build contains no plugin-native loader code path.

Do not claim `catch_unwind` makes arbitrary FFI undefined behavior safe. Documentation should state it catches Rust panics only; UB/process corruption remains possible for in-process native code.

## Part G — Guards and documentation

Add guards that:

- `synvoid-plugin-runtime` default manifest does not declare `libloading`;
- native loader code is confined to the approved crate/path;
- root compatibility shim, if retained, remains a pure facade;
- production config cannot enable native extensions if the binary lacks compiled support;
- feature-disabled builds compile and native API behavior is explicit.

Update:

- `architecture/unsafe_native_extensions.md`;
- `architecture/plugin_runtime_sandbox.md`;
- plugin operator/config docs;
- root module/dependency ledgers if direct dependencies change;
- crate granularity audit;
- `AGENTS.md` native extension invariant.

## Acceptance criteria

Phase 28 is complete when:

- sandboxed WASM plugin runtime no longer unconditionally links `libloading`;
- unsafe native loading has a dedicated crate/feature boundary;
- runtime production/path/hash/permission gates are preserved and tested;
- PluginManager consumes a narrow native backend rather than concrete library handles;
- native feature-disabled builds have no load path and report unsupported behavior explicitly;
- current native ABI/lifetime/reload invariants remain covered;
- docs clearly distinguish compile-time capability, runtime enablement, and the still-unsandboxed nature of in-process native code.

## Rejection criteria

Reject an implementation that:

- merely renames `unsafe_native_loader.rs` while `libloading` remains unconditional in plugin-runtime;
- exposes raw library handles/symbols across the new boundary;
- treats `catch_unwind` as an FFI sandbox;
- makes native support default-on to preserve tests;
- weakens runtime production gates because compile-time gating exists;
- adds a generic command-execution IPC API.

## Verification

```bash
cargo test -p synvoid-plugin-runtime --all-targets
cargo test -p synvoid-native-extension --all-targets
cargo check -p synvoid-plugin-runtime --no-default-features
cargo check --no-default-features
cargo test --test plugin_guard --profile ci
cargo xtask verify
cargo tree -p synvoid-plugin-runtime | grep libloading   # expected empty for default/native-disabled graph
cargo tree -i libloading --workspace
```