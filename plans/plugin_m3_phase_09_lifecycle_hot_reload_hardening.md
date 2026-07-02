# Plugin Milestone 3 Phase 9: Plugin Lifecycle and Hot-Reload Hardening

## Goal

Make plugin lifecycle transitions deterministic, auditable, and safe under partial writes, failed reloads, duplicate names, in-flight requests, and production/development mode differences.

Milestones 1 and 2 hardened the WASM trust boundary and runtime containment. Phase 8 separates unsafe native extensions from sandboxed WASM plugins. Phase 9 hardens how plugins are loaded, reloaded, replaced, disabled, quarantined, and unloaded over time.

## Non-Goals

- Do not introduce new plugin host APIs.
- Do not change the WASM ABI unless a lifecycle invariant requires it.
- Do not make native hot reload production-safe by assumption. Native hot reload remains unsafe unless separately gated and acknowledged.
- Do not rely on filesystem watcher behavior as the only correctness boundary.

## Core Invariants

1. A failed reload must not replace a working plugin.
2. A partial file write must not be loaded.
3. Duplicate plugin names must be rejected unless the operation is an explicit replacement of the same logical plugin.
4. In-flight requests must continue against their captured plugin generation.
5. New requests must see either the old generation or the fully prepared new generation, never an intermediate state.
6. Production hot reload must be explicitly enabled and narrower than development hot reload.
7. Every lifecycle transition must be observable.

## Workstream 1: Centralize Plugin Generation Model

### Target

Represent each loaded plugin as a generation with immutable identity and policy metadata.

### Suggested Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PluginGenerationId(u64);

pub struct LoadedPluginGeneration {
    pub name: String,
    pub generation: PluginGenerationId,
    pub source_identity: PluginSourceIdentity,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub trust_tier: PluginTrustTier,
    pub effective_policy: EffectivePluginPolicy,
    pub runtime: Arc<WasmRuntime>,
    pub loaded_at: SystemTime,
    pub previous_generation: Option<PluginGenerationId>,
}
```

Native unsafe extensions should use a parallel generation type rather than sharing the WASM sandbox type unless the authority model is explicitly separated.

### Implementation Steps

1. Replace or wrap bare `Vec<Arc<WasmRuntime>>` state with a generation registry:

```rust
HashMap<String, Arc<LoadedPluginGeneration>>
```

plus a sorted/cache view for execution order.

2. Ensure runtime iteration captures `Arc<LoadedPluginGeneration>` so in-flight requests hold a stable generation.
3. Include generation ID in metrics/logs/status.
4. Add a monotonic generation counter inside the manager.
5. Add `PluginInfo` fields:

- generation
- previous_generation
- binary_hash
- manifest_hash
- loaded_at
- source identity

6. Ensure generation IDs are never reused within process lifetime.

### Tests

- Loading a plugin creates generation 1.
- Reloading creates generation 2 and preserves previous_generation = 1.
- In-flight request captures generation 1 while new request after swap uses generation 2.
- Generation appears in `PluginInfo`.
- Metrics include bounded generation label or event field where appropriate.

### Acceptance Criteria

- Plugin identity is generation-aware.
- In-flight and new-request behavior is deterministic.
- Operators can identify which generation made a decision.

## Workstream 2: Atomic Load-Then-Swap Reload Pipeline

### Target

Reload should prepare and verify the entire candidate plugin before touching the active generation.

### Pipeline

```text
watch/manual reload event
  -> resolve path
  -> wait for stable file
  -> read bytes once
  -> discover/read manifest
  -> validate source identity
  -> verify signature/hash
  -> build effective policy
  -> compile/instantiate candidate runtime
  -> run ABI validation
  -> optional smoke invocation / export check
  -> acquire manager write lock
  -> check duplicate/replacement rules
  -> atomically swap active generation
  -> update sorted cache
  -> emit lifecycle event
```

If any candidate step fails, active generation remains unchanged.

### Implementation Steps

1. Add `prepare_reload_candidate(path) -> Result<PreparedPluginGeneration, WasmPluginError>`.
2. Ensure this candidate owns verified bytes, manifest, effective policy, source identity, and candidate runtime.
3. Add `commit_reload_candidate(candidate)` that performs only the atomic swap and cache invalidation under lock.
4. Make `reload_plugin(path)` call prepare then commit.
5. Ensure failed reload records `last_reload_error` but does not mutate active generation.
6. Expose reload outcome:

```rust
pub enum PluginReloadOutcome {
    Replaced { name, old_generation, new_generation },
    Unchanged { name, reason },
    Failed { name_hint, error },
}
```

### Tests

- Tampered bytes fail reload and old generation remains active.
- Invalid manifest fails reload and old generation remains active.
- ABI-invalid module fails reload and old generation remains active.
- Successful reload swaps generation atomically.
- Cache invalidated only after successful swap.
- Reload outcome contains old/new generation IDs.

### Acceptance Criteria

- Reload is load-then-swap, never swap-then-fix.
- Failed reloads are non-destructive.
- Reload outcomes are structured and testable.

## Workstream 3: Stable File Detection and Debounce

### Problem

Filesystem watchers can fire while a file is still being written. Loading partially written WASM or manifest files can produce noisy failures or, worse, inconsistent candidate state.

### Target

Hot reload should wait until watched files are stable before reading.

### Implementation Steps

1. Add a `FileStabilityPolicy`:

```rust
pub struct FileStabilityPolicy {
    pub debounce: Duration,
    pub stable_checks: usize,
    pub stable_interval: Duration,
    pub max_wait: Duration,
}
```

2. Implement `wait_for_stable_file(path, policy)`:

- check metadata length and modified time;
- optionally hash small files or first/last chunk;
- require N identical observations;
- fail with timeout if not stable.

3. Apply the same stability wait to the `.wasm` file and manifest file.
4. Coalesce multiple watcher events for the same logical plugin into one reload attempt.
5. Handle rename/write patterns:

- temp file write then atomic rename;
- direct overwrite;
- manifest-only change;
- wasm-only change.

6. Add logs for debounced events and stable-file timeouts.

### Tests

- Direct partial write does not trigger immediate reload.
- Atomic rename triggers one reload after stability.
- Multiple rapid writes coalesce into one reload.
- Manifest-only change reloads candidate policy.
- Wasm-only change reloads binary and verifies hash/signature.
- Stable-file timeout records reload failure but keeps old generation.

### Acceptance Criteria

- Hot reload does not consume partial writes.
- Watcher event storms are coalesced.
- Stability policy is configurable and tested.

## Workstream 4: Duplicate Name and Replacement Semantics

### Target

Define exactly when two plugin sources may use the same plugin name.

### Recommended Policy

- New load with an existing name rejects by default.
- Reload of the same source identity may replace the existing generation.
- Explicit replace operation may replace name if source identity rules allow it.
- Mesh/distributed plugin and local file plugin cannot silently shadow each other.
- Unsafe native extension names cannot collide with WASM plugin names unless a global namespace policy explicitly permits it.

### Implementation Steps

1. Add a `PluginNameRegistry` helper.
2. Compare source identity during reload:

- local path canonical path;
- mesh content identity;
- memory plugin identity;
- unsafe native identity if relevant.

3. Add `PluginReplacePolicy`:

```rust
pub enum PluginReplacePolicy {
    RejectExisting,
    ReplaceSameSource,
    ReplaceAnyWithOperatorOverride,
}
```

4. Use policy consistently across:

- file load;
- memory load;
- mesh load;
- reload;
- hot reload;
- unsafe native load.

5. Add status output for conflicts.

### Tests

- Loading duplicate name from different path rejects.
- Reloading same path replaces.
- Mesh plugin cannot shadow local plugin.
- Memory load cannot shadow signed file plugin by default.
- Explicit replace override works and emits audit event.
- Unsafe native and WASM namespace collision rejects by default.

### Acceptance Criteria

- Duplicate handling is deterministic.
- No load path bypasses name registry.
- Shadowing cannot occur silently.

## Workstream 5: Lifecycle State Machine

### Target

Represent plugin lifecycle states explicitly and enforce valid transitions.

### Suggested States

```rust
pub enum PluginLifecycleState {
    Loading,
    Active,
    Reloading,
    Disabled,
    Quarantined,
    Unloading,
    Removed,
    FailedLoad,
}
```

This is separate from invocation guard state if needed, but the two should be reconciled in status output.

### Valid Transitions

```text
Loading -> Active
Loading -> FailedLoad
Active -> Reloading
Reloading -> Active
Reloading -> FailedLoad + old Active retained
Active -> Disabled
Disabled -> Active via operator reset
Active -> Quarantined
Quarantined -> Disabled or Removed
Active -> Unloading -> Removed
```

### Implementation Steps

1. Add lifecycle state to generation or plugin registry entry.
2. Add transition helper that validates allowed transitions.
3. Emit lifecycle event for every transition.
4. Integrate invocation guard disable/quarantine events into lifecycle status.
5. Make operator commands use transition helper.
6. Ensure failed reload records failure without putting active plugin into ambiguous state.

### Tests

- Invalid transition rejected.
- Trap threshold moves Active -> Disabled or Quarantined according to policy.
- Operator reset moves Disabled -> Active.
- Failed reload records FailedLoad event but active generation remains Active.
- Removed plugin no longer appears in runtime iteration.

### Acceptance Criteria

- Lifecycle state transitions are explicit and tested.
- Status output can explain why a plugin is inactive.
- Failed load/reload states do not corrupt active generation.

## Workstream 6: Production vs Development Hot Reload Gates

### Target

Hot reload should be development-friendly but production-safe.

### Recommended Defaults

Development:

- WASM hot reload allowed if `dev_mode = true` and path is allowlisted.
- Unsafe native hot reload disabled by default but can be enabled with explicit risk acknowledgement.

Production:

- WASM hot reload disabled by default.
- If enabled, require signed plugins and stable-file policy.
- Unsafe native hot reload disabled except under a separate high-friction acknowledgement.

### Implementation Steps

1. Add `HotReloadConfig`:

```rust
pub struct HotReloadConfig {
    pub enabled: bool,
    pub production_enabled: bool,
    pub unsafe_native_enabled: bool,
    pub require_signed_wasm: bool,
    pub watch_dirs: Vec<PathBuf>,
    pub stability_policy: FileStabilityPolicy,
}
```

2. Validate config at startup.
3. Reject production WASM hot reload unless `production_enabled = true` and signed policy is strict.
4. Reject native hot reload unless unsafe native config separately permits it.
5. Add logs stating mode and watched dirs.
6. Ensure watcher never watches paths outside allowlisted dirs.

### Tests

- Production default rejects hot reload.
- Production signed WASM hot reload can be enabled explicitly.
- Production unsigned WASM hot reload rejects.
- Native hot reload rejects unless unsafe native hot reload acknowledgement exists.
- Watch dir outside allowed plugin dirs rejects.

### Acceptance Criteria

- Production hot reload cannot be enabled accidentally.
- WASM and native hot reload gates are separate.
- Mode-specific behavior is documented.

## Workstream 7: Operator Controls and Audit Trail

### Target

Operators need deterministic commands/status for plugin lifecycle operations.

### Suggested Operations

- list plugins
- show plugin detail
- reload plugin
- disable plugin
- enable/reset plugin
- quarantine plugin
- remove plugin
- show last load/reload error

### Implementation Steps

1. Add or extend manager APIs:

```rust
list_plugin_generations()
get_plugin_detail(name)
reload_plugin_by_name(name)
disable_plugin(name, reason)
reset_plugin(name)
quarantine_plugin(name, reason)
remove_plugin(name)
```

2. Ensure all operations emit audit events.
3. Include generation ID and binary/manifest hashes in audit events.
4. Avoid raw request data in plugin lifecycle audit logs.
5. Update admin/TUI/API surfaces if applicable, or document that manager APIs are ready for those surfaces.

### Tests

- Disable prevents new invocations.
- Reset re-enables according to policy.
- Quarantine prevents reset unless operator override.
- Remove deletes registry entry and cache.
- Audit event emitted for every operator lifecycle operation.

### Acceptance Criteria

- Lifecycle control is not only implicit through reload/filesystem changes.
- Operators can safely intervene when a plugin misbehaves.

## Workstream 8: CI Guardrails for Lifecycle

### Target

Prevent regressions in hot-reload and lifecycle invariants.

### Guardrail Tests

Add tests for:

- no reload path mutates active generation before candidate validation;
- duplicate name checks exist in every load path;
- hot reload production gates exist;
- unsafe native hot reload is separately gated;
- stable-file wait exists before watcher-triggered reload;
- generation ID appears in plugin info/status.

### CI Updates

Add lifecycle guard tests to the existing `plugin-runtime-guardrails` job or a root plugin guard job if lifecycle code sits outside the runtime crate.

### Acceptance Criteria

- Lifecycle invariants are automatically tested.
- Guardrail job covers both runtime crate and root plugin manager surfaces if needed.

## Validation Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test -p synvoid -- plugin_lifecycle
cargo test -p synvoid -- hot_reload
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_load_path_guard
```

If tests are split into new guard files, add them to CI:

```bash
cargo test --test plugin_lifecycle_guard
cargo test --test plugin_hot_reload_guard
cargo test --test unsafe_native_plugin_guard
```

## Completion Definition

This phase is complete when:

- Reload is prepare-then-commit with generation-aware atomic swaps.
- Failed reloads preserve the old active generation.
- Hot reload waits for stable files and debounces watcher events.
- Duplicate names and source shadowing are rejected unless explicitly replaced.
- Lifecycle states and transitions are explicit and auditable.
- Production/development hot reload gates are distinct and tested.
- Operator lifecycle APIs/status expose generation, hash, state, and last error.
