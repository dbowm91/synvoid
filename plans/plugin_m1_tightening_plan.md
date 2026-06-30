# Plugin Milestone 1 Tightening Plan

## Purpose

Milestone 1 substantially improved the Synvoid plugin runtime: manifests now drive runtime authority, signed file loads instantiate from verified bytes, invocation guard state is active in the hot path, and the pointer-length ABI is materially safer. This tightening pass is a focused corrective layer over that work.

The goal is not to expand the plugin feature set. The goal is to remove ambiguity and close the remaining production-readiness gaps before moving into Milestone 2 sandbox-depth work.

## Scope

This pass should address four remaining areas:

1. Allocator contract consistency, especially whether `guest_free` is required or optional.
2. Guest allocator overlap safety, preferably by moving host writes to a single allocation frame.
3. Timeout precision and wall-clock containment semantics.
4. CI/guardrail enforcement so the new trust-boundary invariants cannot regress silently.

## Current State Summary

The repo now has strong Milestone 1 implementation signals:

- `EffectivePluginPolicy`, `PreparedPluginLoad`, `PluginSourceIdentity`, and `limits_from_manifest()` make manifests the source of runtime authority.
- Signed file loads read WASM bytes once, verify those bytes, and instantiate via `Module::from_binary()`.
- `PluginInvocationGuard` is wired into request filter, response transform, handler, and streaming handler paths.
- Host-function capability violations are tracked via `RequestContext.capability_violation`.
- Failed pooled instances are dropped rather than returned to the pool.
- The fixed `1024` fallback in guest memory writes has been removed.
- `checked_guest_range()`, `GuestAllocation`, hardened header serialization, and ABI guard tests exist.

Remaining ambiguity is concentrated in edge contracts, not the broad architecture.

## Workstream 1: Make the Allocator Contract Explicit and Enforced

### Problem

The docs and Phase 4 commit messages describe `guest_alloc` and `guest_free` as required exports for the pointer-length ABI. A later test path allows modules with `guest_alloc` but no `guest_free`: `write_to_guest_memory()` succeeds and `free_guest_memory()` is a no-op.

That is a policy ambiguity. In production, the ABI must say one thing and enforce it.

### Decision Point

Choose one of these policies and make code, tests, docs, and guardrails agree.

Recommended policy: require both `guest_alloc` and `guest_free` for all production pointer-length ABI plugins.

Alternative policy: require `guest_alloc`, allow missing `guest_free` only for development/test compatibility, and mark the instance as non-poolable or one-shot.

The recommended policy is stricter and simpler. It avoids unbounded guest heap growth in pooled instances and avoids hidden state accumulation between requests.

### Implementation Steps

1. Update `GuestAbiInfo::has_required_allocator()` so it means exactly the production ABI requirement.
2. Add or update a method such as:

```rust
impl GuestAbiInfo {
    pub fn validate_for_policy(&self, policy: GuestAbiPolicy) -> Result<(), WasmPluginError> {
        // ProductionPointerLength: memory + guest_alloc + guest_free + at least one hook
        // DevAllowMissingFree: memory + guest_alloc + at least one hook, non-poolable
    }
}
```

3. Introduce an explicit policy enum if needed:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAbiPolicy {
    ProductionPointerLength,
    DevelopmentAllowMissingFree,
}
```

4. Call ABI validation during runtime load/instantiation, not only in unit tests.
5. If missing `guest_free` remains allowed in any mode, mark that runtime or instance as non-poolable and ensure it is dropped after each invocation.
6. Update `architecture/plugin_runtime_sandbox.md`, `docs/PLUGINS.md` if touched, and `src/plugin/AGENTS.override.md` so the stated contract matches implementation.

### Tests

Add or update tests for:

- Production ABI rejects module with `guest_alloc` but no `guest_free`.
- Production ABI rejects module with `guest_free` but no `guest_alloc`.
- Production ABI rejects module with memory and hook but no allocator exports.
- Development compatibility mode, if retained, allows missing `guest_free` but marks runtime non-poolable or drops instances after invocation.
- Guardrail test fails if docs say `guest_free` is required while runtime tests allow it silently.

### Acceptance Criteria

This workstream is complete when:

- The repository has one explicit allocator policy.
- Runtime load or invocation enforces that policy.
- Tests and docs no longer contradict each other.
- Missing `guest_free` cannot produce a pooled production plugin unless that is an explicit, documented decision.

## Workstream 2: Eliminate Guest Allocator Overlap Risk

### Problem

Removing the fixed-offset fallback prevents one major aliasing bug. However, if the host calls `guest_alloc()` separately for method, URI, headers, and body, a malicious or defective allocator can return overlapping ranges. A cooperative fixture can prove non-overlap for that fixture, but it does not prove the runtime is safe against adversarial allocators.

For security-critical request inspection, the host should not trust the guest allocator to return disjoint ranges across multiple allocations.

### Recommended Design

Use one allocation frame per invocation.

Flow:

1. Compute serialized input pieces: method bytes, URI bytes, serialized headers, body bytes.
2. Check each piece and total input frame length against plugin limits.
3. Call `guest_alloc(total_len)` exactly once.
4. Validate the single returned frame range.
5. Copy each input piece into host-computed, non-overlapping offsets inside that frame.
6. Pass the subrange pointers and lengths to the existing hook signature.
7. Call `guest_free(base_ptr, total_len)` exactly once.

This keeps the current ABI signature while removing trust in repeated allocator calls.

Example structure:

```rust
struct GuestInputFrame {
    base: i32,
    len: i32,
    method: GuestAllocation,
    uri: GuestAllocation,
    headers: GuestAllocation,
    body: Option<GuestAllocation>,
}
```

`GuestAllocation` can still represent subranges, but only the frame base/total length should be freed.

### Implementation Steps

1. Add a helper to build input pieces:

```rust
struct RequestInputPieces<'a> {
    method: &'a [u8],
    uri: &'a [u8],
    headers: Vec<u8>,
    body: &'a [u8],
}
```

2. Add a helper to allocate and write one frame:

```rust
fn write_request_input_frame(
    &self,
    store: &mut Store<RequestContext>,
    exports: &GuestExports,
    pieces: RequestInputPieces<'_>,
) -> Result<GuestInputFrame, WasmPluginError>
```

3. Replace the separate `write_to_guest_memory()` calls in `do_filter_request_with_exports()` with this single-frame helper.
4. Apply the same approach to handler and transform paths where multiple host-provided buffers are written.
5. Keep `write_to_guest_memory()` only for simple one-buffer operations or refactor it into `guest_alloc_frame()` and `write_guest_range()` primitives.
6. Add a malicious allocator fixture that always returns `0` or returns overlapping regions. The new single-frame implementation should remain correct because it calls the allocator only once per input frame.
7. Add a fixture whose allocator returns an out-of-bounds frame; the runtime must reject it before any copy.

### Tests

Required tests:

- Malicious allocator always returns the same pointer; request pieces remain non-overlapping because the host subdivides one allocation.
- Single allocation is used for method/URI/headers/body. This can be tested with a fixture allocator that increments a global allocation counter and fails if called more than once for request input.
- Total frame length overflow is rejected.
- Total frame length greater than `max_input_bytes` is rejected.
- Empty body does not require a separate allocation.
- `guest_free` is called once with the frame base and total length.
- If `guest_free` traps, the invocation may return the hook result, but the instance must be treated as poisoned and not returned to the pool.

### Acceptance Criteria

This workstream is complete when:

- The host no longer relies on multiple guest allocator calls for a single request input frame.
- Method, URI, headers, and body subranges are host-computed and pairwise disjoint by construction.
- Malicious overlapping allocator behavior cannot corrupt request-field separation.
- Tests prove single-frame behavior and poisoned-instance handling.

## Workstream 3: Preserve Millisecond Timeout Precision

### Problem

`PluginLimits::timeout_ms` has millisecond precision. `WasmResourceLimits::timeout_seconds` uses seconds. The current conversion appears to round or floor into whole seconds. This loses the ability to enforce tight WAF hook budgets such as 25 ms, 50 ms, or 100 ms.

For a high-throughput WAF, plugin hook budgets should be sub-second by default.

### Recommended Design

Change runtime timeout representation to `Duration`.

Preferred target:

```rust
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,
    pub max_table_elements: Option<usize>,
    pub max_cpu_fuel: u64,
    pub timeout: Duration,
    pub max_instances: usize,
    pub memory_budget_mb: Option<usize>,
    pub wasi_enabled: bool,
    pub allowed_dht_prefixes: Vec<String>,
    pub capabilities: Arc<PluginCapabilities>,
}
```

If changing the field is too invasive, add a parallel field:

```rust
pub timeout: Duration,
```

and deprecate `timeout_seconds` in comments/tests. Do not leave two sources of truth long term.

### Implementation Steps

1. Update `WasmResourceLimits` to carry `Duration`.
2. Update `limits_from_manifest()` to use:

```rust
Duration::from_millis(manifest.limits.timeout_ms.max(1))
```

3. Update `create_store()`, pooled instance preparation, component store creation, and any timeout checks to use `Duration` directly.
4. Update docs to avoid saying sub-second values are rounded to 1 second unless that remains a deliberate compatibility behavior.
5. Add tests proving `timeout_ms = 50` remains 50 ms in the effective runtime policy.
6. If a public API still exposes `timeout_seconds`, mark it as legacy and derive it from `Duration` only for display.

### Wall-Clock Containment Note

This workstream is about precision. It does not need to fully solve interrupting synchronous Wasmtime execution. That belongs mostly to Milestone 2 execution containment. However, this pass should make sure there is no accidental widening of configured timeout budgets.

### Tests

Required tests:

- `timeout_ms = 1` maps to `Duration::from_millis(1)`.
- `timeout_ms = 50` maps to 50 ms.
- `timeout_ms = 1500` maps to 1500 ms, not 1 second if precision is preserved.
- Pooled instance preparation preserves the exact timeout duration.
- `PluginInfo` or policy introspection exposes timeout in milliseconds or duration form without lossy conversion.

### Acceptance Criteria

This workstream is complete when:

- Manifest timeout precision is preserved into runtime store context.
- Runtime docs and policy info expose timeout precisely.
- There is no floor-to-seconds behavior for plugin hook budgets.

## Workstream 4: Clarify Wall-Clock vs Fuel Failure Semantics

### Problem

Fuel exhaustion handles CPU-bound loops well, but wall-clock timeout handling is more subtle because the Wasmtime call path is synchronous. The blocking invocation guard checks state, capability, input size, and concurrency, but it does not by itself interrupt a long-running closure.

This is acceptable only if production policy clearly requires fuel for sandboxed tiers and treats wall-clock timeout as a host-call/request-context budget, not as the only CPU containment mechanism.

### Implementation Steps

1. Add a production invariant: sandboxed tiers must have non-zero fuel unless an explicit unsafe/dev override is enabled.
2. Ensure `limits_from_manifest()` or policy validation rejects `fuel = 0` for `SignedSandboxed` and production `LocalSandboxed` unless a dev override is active.
3. Document that fuel is the primary CPU interruption mechanism for synchronous guest execution.
4. Ensure blocking host functions such as streaming body reads have their own bounded timeout or nonblocking behavior.
5. Add failure-class tests showing fuel exhaustion increments runtime failure counters and disables at threshold.
6. Add policy tests showing production sandboxed plugins cannot silently run with `max_cpu_fuel = 0`.

### Tests

Required tests:

- `SignedSandboxed` with no fuel or zero fuel is rejected in production policy.
- `LocalSandboxed` with zero fuel is rejected when production mode is enabled, unless explicit override is set.
- Development mode may allow zero fuel only if the config clearly opts in.
- Fuel exhaustion continues to classify as `FuelExhausted` and disables after threshold.
- Blocking body-read host function respects a bounded timeout if such a function is in active use.

### Acceptance Criteria

This workstream is complete when:

- Production sandboxed plugins cannot accidentally run with no CPU fuel budget.
- Wall-clock timeout documentation does not imply a guarantee the runtime cannot enforce.
- Host-call blocking behavior is bounded or explicitly deferred to Milestone 2 with a guardrail test documenting the gap.

## Workstream 5: Strengthen CI and Guardrail Enforcement

### Problem

Commit messages report local test and clippy success, but the current repository status view did not expose workflow runs or combined statuses for the head commit. For trust-boundary work, local test claims are not sufficient long-term. The guardrail suite should run automatically.

### Implementation Steps

1. Add or update GitHub Actions workflow for plugin trust-boundary tests.
2. Include at minimum:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test abi_memory_boundary_guard
```

3. If the full workspace is too slow, create a plugin-runtime focused job and a broader nightly/full job.
4. Add branch protection or documented expectation that plugin guardrails must pass before merging plugin runtime changes.
5. Add a CI badge or note in `AGENTS.md`/plugin docs if appropriate.

### Additional Guardrails

Add source-level or integration guardrails for:

- No reintroduction of fixed-offset guest memory fallback.
- No manager load path bypassing `PreparedPluginLoad`.
- No `SignedSandboxed` load path without actual byte verification.
- No production sandboxed plugin with zero fuel.
- No production pointer-length ABI plugin missing required allocator exports.
- No pooled instance returned after allocation/free trap, guest trap, memory violation, or fuel exhaustion.

### Acceptance Criteria

This workstream is complete when:

- Plugin trust-boundary tests run in CI.
- CI fails on clippy warnings in `synvoid-plugin-runtime`.
- All new guardrails are part of automated test execution.
- The repository no longer relies on commit-message assertions for plugin hardening confidence.

## Recommended Execution Order

Implement in this order:

1. Allocator contract consistency.
2. Single-frame allocation / overlap-proof input writes.
3. Timeout precision.
4. Fuel and wall-clock semantics clarification.
5. CI/guardrail enforcement.

The allocator work should come first because it may affect tests and fixtures throughout the runtime. Single-frame allocation should follow immediately because it builds on the ABI contract. Timeout and fuel policy are logically separate and should not require large ABI changes. CI should land last or in parallel, but the final pass should confirm the new tests run under CI.

## Validation Commands

Run at least:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test abi_memory_boundary_guard
```

If feasible, also run:

```bash
cargo test --workspace --all-features
```

If workspace-wide all-features is too broad or currently flaky for unrelated features, document the failure and confirm the plugin-runtime focused suite passes.

## Completion Definition

This tightening pass is complete when:

- The allocator export contract is unambiguous and enforced.
- Request input writes cannot be corrupted by overlapping guest allocator returns.
- Manifest timeout precision is preserved into runtime execution state.
- Production sandboxed plugins cannot run without a CPU fuel budget unless explicitly unsafe/dev configured.
- The plugin guardrail suite is automated in CI.
- Architecture docs and plugin docs match the implementation.

After this pass, the plugin system should be ready to proceed into Milestone 2: sandbox depth, including request/response serialization semantics, execution containment, pool isolation, and narrower host API sub-capabilities.