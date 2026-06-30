# Plugin Milestone 2 Phase 6: Execution Containment and Pool Isolation

## Goal

Strengthen runtime containment around WASM plugin execution so CPU, wall-clock, host-call, memory, and pool-state boundaries remain reliable under malicious or defective plugins.

Milestone 1 established mandatory trust boundaries and hardened the ABI. This phase deepens the runtime containment model: how guest execution is interrupted, how host calls are bounded, how pooled instances are reset or dropped, and whether plugins are stateful or request-isolated by policy.

## Problem Statement

The current runtime now enforces non-zero fuel for sandboxed tiers and uses `Duration` for timeout precision. However, fuel and timeout semantics still need a production-depth pass.

The major questions are:

1. How does the runtime interrupt long-running synchronous Wasmtime execution beyond fuel exhaustion?
2. Which host calls can block, and what are their per-call budgets?
3. What state is allowed to persist across pooled plugin invocations?
4. Which failures poison an instance and force drop rather than pool return?
5. How do warmup and pooled instance preparation preserve the same limits as cold invocation?
6. How does the manager report degraded or disabled plugin state to operators?

## Design Principles

1. Fuel is the primary CPU containment mechanism.
2. Epoch interruption or an equivalent mechanism should backstop wall-clock containment where feasible.
3. Host calls must have independent, bounded budgets; they should not rely only on outer hook timeout.
4. A failed or suspect instance should be dropped, not returned to the pool.
5. Pooling must not accidentally create cross-request state leaks unless statefulness is an explicit plugin policy.
6. Warmed instances must enforce exactly the same policy as cold instances.

## Workstream 1: Add Wasmtime Epoch/Interruption Backstop

### Target

Use Wasmtime epoch interruption, async fuel, or the best supported interruption mechanism available in the current Wasmtime version to enforce wall-clock budgets in addition to fuel.

### Implementation Steps

1. Inspect current Wasmtime configuration and version support for:

- `Config::epoch_interruption(true)`
- `Store::set_epoch_deadline(...)`
- engine epoch increment from a timer/task
- async support if relevant

2. Add a runtime-level `ExecutionInterruptPolicy`:

```rust
pub struct ExecutionInterruptPolicy {
    pub fuel_required: bool,
    pub epoch_deadline_enabled: bool,
    pub epoch_ticks_per_timeout: u64,
    pub host_call_timeout: Duration,
}
```

3. Wire the policy from `WasmResourceLimits` or `EffectivePluginPolicy`.
4. When creating a store, configure:

- fuel budget from `max_cpu_fuel`
- timeout `Duration`
- epoch deadline if supported

5. Start a lightweight epoch incrementer per engine or per runtime owner. Avoid one timer per plugin invocation if possible.
6. Classify epoch interruption as timeout or guest interruption, not generic runtime error.
7. Add a fallback path if epoch interruption is not supported: document fuel-only CPU containment and ensure CI tests prove zero fuel is rejected for sandboxed tiers.

### Tests

- Infinite loop with low fuel exhausts fuel and disables after threshold.
- Infinite loop with high fuel but tiny epoch deadline is interrupted by epoch timeout if supported.
- Epoch timeout is classified as `Timeout` or a stable interruption failure class.
- Epoch incrementer does not panic on shutdown.
- Runtime without epoch support still enforces non-zero fuel.

### Acceptance Criteria

- Production plugin execution has a backstop beyond voluntary host checks.
- Failure classification distinguishes fuel exhaustion from wall-clock interruption.
- Tests prove a pathological loop cannot run indefinitely under production policy.

## Workstream 2: Bound Host Calls Independently

### Target

Every host function callable from a plugin must have a clear per-call budget and a bounded failure mode.

Current host functions include or have included:

- `abort`
- `check_timeout`
- `get_env`
- `synvoid_read_body_chunk`
- `mesh_query_dht`
- `mesh_check_threat`
- `mesh_emit_event`

### Implementation Steps

1. Create a `HostCallBudget` type:

```rust
pub struct HostCallBudget {
    pub env_lookup_timeout: Duration,
    pub body_chunk_timeout: Duration,
    pub mesh_query_timeout: Duration,
    pub mesh_threat_timeout: Duration,
    pub mesh_emit_timeout: Duration,
    pub max_body_chunk_bytes: usize,
    pub max_env_value_bytes: usize,
    pub max_mesh_key_bytes: usize,
    pub max_mesh_value_bytes: usize,
}
```

2. Add this budget to `RequestContext` or the effective runtime policy.
3. For purely in-memory calls such as `get_env`, enforce size bounds and pointer bounds.
4. For async/blocking calls such as body reads or mesh queries, use explicit timeout. If current host function path is synchronous and cannot await, move blocking work to a bounded prefetch/cache layer or return a retry/error code.
5. Define stable ABI error codes for host-call failures:

```text
-1 capability denied
-2 invalid pointer/range
-3 timeout
-4 input too large
-5 unavailable
-6 internal error
```

6. Update metrics for host-call failure class.
7. Ensure host-call failure can mark the invocation as failed and optionally poison the instance where appropriate.

### Tests

- `get_env` rejects output buffer too small without panic.
- `get_env` rejects value over max env value bytes.
- `synvoid_read_body_chunk` respects max chunk size.
- Body chunk timeout returns stable ABI code.
- Mesh query timeout returns stable ABI code and records metric.
- Capability denied returns the capability-denied code and records a violation.
- Invalid pointer returns invalid-pointer code and does not panic.

### Acceptance Criteria

- No host function can block indefinitely.
- All host functions have bounded input/output sizes.
- ABI error codes are stable and documented.
- Host-call failures are visible in metrics without leaking payload data.

## Workstream 3: Define Pool State Semantics

### Target

Decide whether pooled WASM instances are request-isolated or stateful, then enforce that decision.

### Recommended Policy

Default production policy should be request-isolated unless a plugin explicitly opts into stateful execution and the operator allows it.

Request-isolated means:

- no request env persists;
- no body receiver persists;
- no capability violation flag persists;
- no DHT prefix or capability override persists;
- fuel is reset;
- timeout start is reset;
- guest memory/global state is either reset by reinstantiation or treated as untrusted persistent state and not used for security assumptions.

Because WASM linear memory/globals are not trivially reset after arbitrary execution, there are two implementation options.

Option A: reinstantiate per request for strict isolation. More expensive, simpler to reason about.

Option B: pooled instances are explicitly stateful. Reset host-side store context, but document that guest memory/globals persist across requests. Only allow this for trusted plugins or with `stateful = true` manifest field.

Recommended near-term: keep pooling, but make the statefulness policy explicit and observable. For security-sensitive `SignedSandboxed` plugins, prefer reinstantiate-per-request unless benchmarks show unacceptable overhead.

### Implementation Steps

1. Add manifest/runtime field:

```rust
pub enum PluginStateModel {
    RequestIsolated,
    StatefulPooled,
}
```

2. Default:

- `SignedSandboxed`: `RequestIsolated` unless operator override.
- `LocalSandboxed`: `RequestIsolated` or `StatefulPooled` by explicit config.
- `DevelopmentHotReload`: can use `StatefulPooled` for speed.

3. Add pool behavior by state model:

- Request-isolated: instantiate fresh or reset via a validated snapshot strategy.
- Stateful-pooled: reuse instances after successful invocation only.
- Any failure: drop instance.

4. Expose state model in `PluginInfo` / policy introspection.
5. Add logs when loading a stateful pooled plugin.
6. Update docs to avoid implying memory/global reset if the runtime does not enforce it.

### Tests

- Host-side context fields reset between pooled requests.
- Capability violation flag resets before next request.
- Allowed DHT prefixes reset before next request.
- Env values reset before next request.
- Fuel resets before next request.
- Guest global counter persists only under `StatefulPooled` and not under `RequestIsolated`.
- Failed instance is dropped and not reused.

### Acceptance Criteria

- Pool semantics are explicit in code and docs.
- Request-isolated mode does not preserve guest state across requests.
- Stateful pooled mode is opt-in and visible.
- Failed/poisoned instances are never returned to the pool.

## Workstream 4: Warmup and Cold/Warm Parity

### Target

Ensure warmed instances enforce the same policy as normal instances.

### Problem

Warmup paths are easy to let drift. Historically they can create stores with hard-coded defaults, missing fuel, missing capabilities, or missing DHT prefix policy.

### Implementation Steps

1. Remove hard-coded warmup defaults for timeout, memory, table size, fuel, capabilities, and DHT prefixes.
2. Change warmup API to accept `EffectivePluginPolicy` or `WasmResourceLimits` from the prepared load.
3. Verify warmed instances call the same `create_store()`/context construction helper as cold instances.
4. Ensure warmed instances run ABI validation before pooling.
5. Ensure warmed instances set fuel and epoch deadline before first request.
6. Add a guardrail test that scans for hard-coded warmup timeout/memory/fuel constants.

### Tests

- Warmed instance has same fuel as cold instance.
- Warmed instance has same timeout duration as cold instance.
- Warmed instance has same capability set as manifest.
- Warmed instance without required ABI exports is rejected.
- Warmed instance with missing DHT prefix cannot access sensitive DHT key.

### Acceptance Criteria

- Warm and cold instances share the same store/context initialization path.
- No hard-coded resource defaults remain in warmup except documented safe fallbacks.
- Warmed instances cannot bypass manifest policy.

## Workstream 5: State, Backpressure, and Operator Visibility

### Target

Expose runtime containment behavior clearly enough for operators to understand plugin health.

### Implementation Steps

1. Extend plugin metrics:

- active instances
- pool size
- pool hit/miss
- dropped poisoned instances
- fuel exhausted count
- epoch timeout count
- host-call timeout count
- state transitions
- state model

2. Extend `PluginInfo`:

- state model
- failure policy
- current state
- failure count
- timeout count
- last failure class
- fuel budget
- timeout duration
- pool stats

3. Add bounded logs for state transitions:

- loaded
- warmed
- disabled by capability violation
- disabled by runtime failure
- quarantined
- reset by operator

4. Add backpressure behavior for concurrency exhaustion:

- fail open/closed according to hook policy;
- record `ConcurrencyLimitExceeded`;
- never block indefinitely waiting for an instance.

### Tests

- Concurrency exhaustion returns deterministic result.
- Pool stats update on hit/miss/drop.
- State transition metrics are emitted once per transition.
- Last failure class updates on fuel exhaustion, trap, timeout, and capability violation.

### Acceptance Criteria

- Operators can tell whether a plugin is healthy, disabled, quarantined, or saturating.
- Concurrency pressure is deterministic and observable.
- Pool behavior is measurable.

## Required Validation Commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test plugin_failure_does_not_poison_manager
```

Add any new execution-containment integration tests to CI.

## Completion Definition

This phase is complete when:

- Production sandboxed plugins have reliable CPU containment through fuel and, if supported, epoch interruption.
- Host functions have independent timeout and size budgets.
- Pool state semantics are explicit and enforced.
- Warmup cannot bypass manifest-derived policy.
- Poisoned instances are consistently dropped.
- Operators can observe containment failures and pool health.
