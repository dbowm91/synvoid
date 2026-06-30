# Plugin Milestone 1 Phase 3: Mandatory Invocation Guard Integration

## Goal

Make `PluginInvocationGuard` the mandatory boundary for every plugin invocation. Capability checks, input limits, concurrency limits, timeout handling, runtime state, failure counters, and disable/quarantine transitions must be enforced in the hot path rather than only represented as available types.

## Problem Statement

The runtime has `PluginInvocationGuard`, `PluginRuntimeState`, failure counters, and concurrency primitives. The main WASM invocation path currently performs direct capability checks and direct Wasmtime calls. That means failures are recorded as metrics, but plugin state is not necessarily changed in a way that prevents repeated invocation of a bad plugin.

For a WAF, repeated plugin traps/timeouts cannot be only observable. They must affect execution policy. Otherwise a malicious or defective plugin can continue consuming resources on every request.

## Desired Architecture

Each `WasmRuntime` should own a guard:

```rust
pub struct WasmRuntime {
    // existing fields
    guard: Arc<PluginInvocationGuard>,
    failure_policy: PluginFailurePolicy,
}
```

Suggested failure policy:

```rust
pub struct PluginFailurePolicy {
    pub failure_threshold: u32,
    pub timeout_threshold: u32,
    pub capability_violation_disables: bool,
    pub fail_closed_on_filter_error: bool,
    pub fail_closed_on_transform_error: bool,
}
```

If this is too much for the first pass, start with a constant threshold and one policy knob. The critical requirement is that every invocation goes through the guard and updates state on failure.

## Hook Classification

Map hooks to required capabilities:

- `filter_request`: require `RequestInspect` or `RequestMutate`.
- `transform_response`: require `ResponseInspect` or `ResponseMutate`.
- `handle_request`: require `RequestInspect` or `RequestMutate`; if it creates a response body, also require an explicit handler capability later if added.
- `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event`: require `Mesh` inside host functions, as already done, but host-function violations should also be able to disable/quarantine the plugin.

The current `PluginCapability` enum does not have a combined capability token. Avoid weakening semantics by mapping filter hooks to a single capability if the implementation needs either inspect or mutate. Use a small helper:

```rust
fn require_any_capability(
    caps: &PluginCapabilities,
    allowed: &[PluginCapability],
) -> Result<(), CapabilityViolation>
```

## Implementation Steps

### 1. Attach Guard to Runtime

When constructing `WasmRuntime`, build a `PluginInvocationGuard` from the effective manifest capabilities and limits:

```rust
let guard = Arc::new(PluginInvocationGuard::new(
    (*limits.capabilities).clone(),
    manifest_limits.clone(),
    manifest_limits.max_concurrency,
));
```

If `WasmRuntime` only receives `WasmResourceLimits`, extend it to also receive the original `PluginLimits` or an effective policy object from Phase 1.

### 2. Convert Sync Runtime Calls to Guarded Calls

`PluginInvocationGuard::invoke_with_limits()` is async. Current runtime methods are mostly sync. Choose one of these approaches:

1. Preferred: add async plugin invocation methods and update call sites to await them where feasible.
2. Transitional: add a synchronous guard method for sync Wasmtime calls:

```rust
pub fn invoke_with_limits_blocking<F, T>(
    &self,
    capability_check: CapabilityCheck,
    input_len: usize,
    f: F,
) -> Result<T, PluginInvokeError>
where
    F: FnOnce() -> Result<T, PluginInvokeError>;
```

Because the WASM call itself is synchronous, a blocking guard path may be the least invasive first step. It must still acquire a concurrency permit or use a synchronous equivalent such as `try_acquire`/`Semaphore` if called outside async context. Do not block an async reactor thread waiting for permits.

### 3. Normalize Error Mapping

Create a conversion from `WasmPluginError` to failure classes:

```rust
pub enum PluginFailureClass {
    CapabilityViolation,
    Timeout,
    FuelExhausted,
    GuestTrap,
    MemoryViolation,
    HostApiViolation,
    LoadError,
    OtherRuntimeError,
}
```

Use it to decide whether to increment failure counters, disable the plugin, quarantine it, or only fail the current invocation.

At minimum:

- Capability violation: disable or reject invocation according to policy.
- Timeout: increment timeout/failure counter.
- Fuel exhausted: increment failure counter.
- Guest trap: increment failure counter.
- Memory violation: increment failure counter.
- Missing optional export: do not count as failure; pass through if hook is absent.

### 4. Enforce Runtime State Before Invocation

Before calling into Wasmtime:

- If state is `Loaded`, proceed.
- If state is `DisabledByConfig`, skip or fail according to hook policy.
- If state is `DisabledByCapabilityViolation`, fail closed for security-sensitive hooks or skip for optional transforms according to policy.
- If state is `DisabledByRuntimeFailure` or `Quarantined`, do not invoke.

Add public manager methods:

```rust
pub fn get_plugin_state(&self, name: &str) -> Option<PluginRuntimeState>;
pub fn reset_plugin_failures(&self, name: &str) -> Result<(), WasmPluginError>;
pub fn quarantine_plugin(&self, name: &str) -> Result<(), WasmPluginError>;
```

### 5. Integrate Host-Function Violations

Host functions such as `mesh_query_dht` currently record capability violations and return error codes. Add a way for those violations to affect plugin state.

Options:

- Store a violation flag/counter in `RequestContext`; after guest invocation returns, check the context and call `guard.disable_for_violation()`.
- Pass a guard handle into `RequestContext` and update directly from the host function.

Prefer the first option to avoid lock-heavy host functions.

Example context field:

```rust
pub(crate) capability_violation: Option<PluginCapability>,
```

After each invocation, if set, record and apply policy.

### 6. Add Fail-Open/Fail-Closed Policy

For now, use conservative defaults:

- Request filter failure: fail closed or configurable per site. If no site policy exists, choose fail closed for security plugins and fail open for optional plugins only if explicitly configured.
- Response transform failure: fail open by default, because breaking responses can degrade availability; security-sensitive transforms can opt into fail closed.
- Missing export: pass through, not failure.

If per-site policy does not exist yet, define the enum and use a runtime default; full site integration can follow later.

## Required Tests

### Guard Unit Tests

- Guard denies invocation when state is disabled.
- Guard enforces input size.
- Guard enforces concurrency.
- Guard timeout returns timeout error.
- `record_failure(threshold)` disables at threshold.
- `disable_for_violation()` transitions to `DisabledByCapabilityViolation`.
- `reset_failures()` returns state to `Loaded`.

### Runtime Integration Tests

Use WASM fixtures where possible:

- Plugin that traps: after N invocations, state becomes `DisabledByRuntimeFailure`.
- Plugin that loops until fuel exhaustion: after N invocations, state becomes disabled/quarantined.
- Plugin that calls mesh without mesh capability: invocation records violation and plugin state changes according to policy.
- Plugin with missing `filter_request`: returns `Pass` and does not increment failure count.
- Plugin with oversized input: rejected before guest invocation and does not execute guest code.

### Manager Tests

- Disabled plugin is skipped or fails according to hook policy.
- `get_plugin_state()` returns current state.
- Resetting failures allows a previously disabled runtime to be manually restored only through explicit API.
- Reloading a plugin resets failure state only if the new load succeeds.

## Edge Cases

- Do not count absent optional exports as runtime failures.
- Do not return poisoned pooled instances after a trap or memory violation unless Wasmtime guarantees the instance remains safe. Prefer dropping failed instances instead of returning them to the pool.
- A plugin disabled during an in-flight request should not invalidate references already executing; state should affect subsequent invocations.
- Host-function violations inside a guest call need to be visible after the call even if the guest returns `Pass`.
- Metrics should record both invocation status and state transitions.

## Acceptance Criteria

This phase is complete when:

- Every request filter, response transform, and handler invocation goes through `PluginInvocationGuard` or an equivalent mandatory guard path.
- Runtime state is checked before guest execution.
- Repeated traps/timeouts/fuel exhaustion disable or quarantine the plugin.
- Capability violations can change plugin state, not only return an ABI error code.
- Failed/poisoned instances are not returned to the pool.
- Plugin state is visible through manager introspection.
- Tests prove that repeated bad behavior stops future invocation.

## Non-Goals

- Changing signature verification. Phase 2 owns signed bytes.
- Rewriting the ABI memory model. Phase 4 owns pointer/allocator hardening.
- Full per-site policy UI/config. This phase can introduce the internal policy enum and defaults; broader config integration can happen later.
