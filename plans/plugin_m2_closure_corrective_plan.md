# Plugin Milestone 2 Closure Corrective Plan

## Purpose

Milestone 2 landed the right major pieces: canonical ABI frame serialization, execution containment/pool isolation, and host API sub-capabilities. The repo now has a much stronger plugin sandbox model. This corrective plan is a short closure pass before moving to the next plugin roadmap milestone.

The goal is to tighten the remaining semantic and lifecycle edges, not to add broad new plugin features.

## Current State

Recent implementation commits added:

- `abi_frame.rs` with canonical request/response serialization, frame policies, `PluginHttpView`, mutation policy, and serialization failure metrics.
- Execution containment types: `ExecutionInterruptPolicy`, `HostCallBudget`, stable ABI error codes, `PluginStateModel`, extended metrics, and extended `PluginInfo`.
- Wasmtime epoch interruption setup and a manager-level epoch incrementer task.
- Host-call budget handling for body chunk reads.
- Pool reset fixes for `capability_violation` and poisoned instance handling after `guest_free` traps.
- Mesh sub-capability policy: DHT read/write prefixes, event topics, threat-check gate, size limits, and signing-payload coverage.
- Future policy structs for filesystem, network, persistence, and metrics.

The remaining concerns are narrower:

1. Epoch interruption is implemented, but production lifecycle startup should be verified and guarded.
2. One body chunk timeout test is ignored because the crate lacks the needed Tokio runtime feature.
3. Pool miss and concurrency-limit metrics appear semantically conflated in at least one path.
4. `PluginStateModel::RequestIsolated` may overstate the isolation guarantee if guest memory/globals persist.
5. CI/status visibility still appears absent from the external commit status surface.

## Workstream 1: Wire Epoch Incrementer into Production Lifecycle

### Problem

`WasmPluginManager::start_epoch_incrementer()` exists and fixes the earlier problem where epoch interruption was configured but no task advanced the epoch. However, production correctness depends on the server/plugin runtime lifecycle actually starting this task.

If the incrementer is only available as an API and only exercised in tests, epoch deadlines may still be inert in real deployments.

### Desired Invariant

Any production `WasmPluginManager` that loads sandboxed plugins with `epoch_deadline_enabled = true` must either:

- automatically start an epoch incrementer; or
- be owned by a lifecycle object that starts and stops the incrementer deterministically; or
- fail a startup guard if epoch interruption is enabled but no incrementer is running.

### Implementation Steps

1. Locate all construction/ownership paths for `WasmPluginManager`, including:

- `PluginManager` in `src/plugin/mod.rs`
- server/plugin runtime setup under `src/server/` or equivalent runtime owner
- any serverless manager paths that hold a plugin runtime
- test-only constructors

2. Add a lifecycle-owned start call at the production composition root:

```rust
wasm_manager.start_epoch_incrementer(config.plugin.epoch_interval);
```

3. Avoid hidden background tasks for pure unit tests unless explicitly requested. Recommended shape:

```rust
pub struct PluginRuntimeOwner {
    wasm_manager: Arc<WasmPluginManager>,
    epoch_incrementer: Option<PluginEpochIncrementerGuard>,
}
```

where dropping the owner stops the task.

4. Add an introspection method:

```rust
pub fn epoch_incrementer_running(&self) -> bool;
```

5. Add a startup validation method:

```rust
pub fn validate_execution_containment_runtime(&self) -> Result<(), WasmPluginError>;
```

This should reject production config where any loaded sandboxed runtime has `epoch_deadline_enabled = true` but no incrementer is active.

6. Add structured logs:

- incrementer started
- incrementer stopped
- incrementer already running
- incrementer required but not running

7. Add docs to `architecture/plugin_runtime_sandbox.md` and `AGENTS.md` stating where the incrementer is owned.

### Tests

Add tests for:

- `epoch_incrementer_running()` false before start and true after start.
- Calling start twice does not leak or replace a running task without stopping the old one.
- Dropping the lifecycle owner stops/aborts the task.
- Production validation fails when epoch deadlines are enabled and incrementer is not running.
- Production validation passes when incrementer is running.
- Dev/test mode may allow no incrementer only when epoch deadlines are disabled or explicitly waived.

### Acceptance Criteria

- Epoch interruption is not merely configured; it is lifecycle-owned in the production runtime.
- There is a guardrail against running production sandboxed plugins with inert epoch deadlines.
- Tests cover start, stop, idempotency, and production validation.

## Workstream 2: Resolve Ignored Body Chunk Timeout Test

### Problem

The body chunk timeout test was marked `#[ignore]` because it requires a Tokio runtime feature not available in the crate. This leaves a meaningful host-call containment behavior unverified by default.

The implementation currently attempts to wrap body chunk receive with `tokio::time::timeout`. Host functions are synchronous Wasmtime callbacks, so runtime-context behavior needs explicit testing.

### Desired Invariant

`HostCallBudget.body_chunk_timeout` must be tested in a normal CI path or explicitly deferred with an architectural reason and a guardrail that prevents the host call from pretending to be fully enforced.

### Implementation Options

Option A: Enable the required Tokio runtime feature in `synvoid-plugin-runtime` dev-dependencies.

- Add the needed `rt-multi-thread` feature under dev-dependencies if the production dependency shape should stay minimal.
- Convert the ignored test into a normal `#[tokio::test(flavor = "multi_thread")]` test.
- Ensure CI runs it.

Option B: Refactor host-call timeout logic to avoid nested `Handle::current().block_on(...)` in a synchronous callback.

- Prefetch body chunks outside the guest call with bounded timeout.
- Expose only an in-memory bounded channel/queue to the WASM host function.
- Make `synvoid_read_body_chunk` nonblocking from the host-function perspective: return `ABI_ERR_UNAVAILABLE` or EOF if no pre-fetched chunk is available.

Option C: Explicitly defer streaming body timeout enforcement to a later streaming ABI phase.

- Remove or narrow claims that body chunk timeout is fully enforced in the current synchronous host-call ABI.
- Keep size bounds and invalid pointer handling active.
- Add a guardrail test/documentation marker explaining the deferred runtime test.

Recommended path: Option B if the implementation cost is acceptable; otherwise Option A as a near-term test closure.

### Implementation Steps for Option A

1. Update `crates/synvoid-plugin-runtime/Cargo.toml` dev-dependency features for Tokio.
2. Convert ignored body chunk timeout test to a normal test.
3. Add a specific test name to CI:

```bash
cargo test -p synvoid-plugin-runtime -- test_body_chunk_timeout
```

4. Verify no nested runtime panic occurs.
5. If nested runtime panic occurs, switch to Option B.

### Implementation Steps for Option B

1. Introduce a `BodyChunkProvider` abstraction or prefetch layer.
2. Move async waiting outside Wasmtime host callback.
3. Store bounded, ready chunks in `RequestContext`.
4. Make host function consume ready chunks synchronously.
5. Return stable ABI codes for no chunk, timeout, over-limit chunk, and EOF.
6. Add tests without ignored annotations.

### Tests

Required tests:

- Body chunk no receiver returns EOF or unavailable as documented.
- Body chunk available returns bytes within `max_body_chunk_bytes`.
- Body chunk over max is clamped or rejected according to policy.
- Body chunk timeout is tested without `#[ignore]` or is explicitly documented as deferred.
- Host function does not panic when called under the production runtime flavor.

### Acceptance Criteria

- No ignored body chunk timeout test remains unless accompanied by an explicit defer marker and docs.
- The actual runtime behavior matches the docs.
- CI exercises the chosen behavior.

## Workstream 3: Separate Pool Miss from Concurrency Limit Metrics

### Problem

A pool miss is not the same thing as concurrency exhaustion. A pool miss can mean no warm instance is currently available and fresh instantiation proceeds successfully. A concurrency limit event should mean the runtime could not proceed because configured concurrency/instance limits were reached, or it had to fail-open/fail-closed due to backpressure.

Conflating the two creates misleading operational data.

### Desired Metrics Semantics

Use distinct counters:

- `pool_hit`: a pooled instance was reused.
- `pool_miss`: no pooled instance was available, but execution continued by creating a fresh instance.
- `pool_drop`: a poisoned or failed instance was discarded.
- `concurrency_limit_exceeded`: execution was denied, delayed beyond policy, or failed according to hook policy because concurrency was exhausted.
- `fresh_instance_created`: optional explicit counter if useful.

### Implementation Steps

1. Audit `filter_request`, `transform_response`, handler, and streaming handler paths for calls to `record_concurrency_limit_exceeded`.
2. Remove concurrency-limit metrics from normal pool miss paths.
3. Emit concurrency-limit only from guard/semaphore failure or a concrete pool/instance cap decision.
4. If no actual cap-denial path exists yet, add one or rename the metric to something less specific, such as `record_pool_miss_backfill`.
5. Update `WasmPluginMetrics` fields if they currently conflate these concepts.
6. Update docs and tests.

### Tests

Add tests for:

- First invocation with empty pool increments pool miss but not concurrency limit.
- Reused pooled invocation increments pool hit.
- Failed invocation increments pool drop.
- Artificial semaphore/guard exhaustion increments concurrency limit and returns deterministic fail-open/fail-closed result.
- Metrics remain separate in `PluginInfo`/`WasmPluginMetrics`.

### Acceptance Criteria

- Normal pool miss does not record concurrency-limit exceeded.
- Concurrency-limit metrics mean real backpressure/denial.
- Operator-facing pool metrics are semantically accurate.

## Workstream 4: Clarify `RequestIsolated` Semantics

### Problem

`PluginStateModel::RequestIsolated` currently appears to reset host-side context but may not reset guest linear memory/globals when a Wasmtime instance is reused. The docs note guest memory persists but is untrusted. That is technically valid, but the name `RequestIsolated` may imply stronger isolation than the runtime provides.

### Desired Invariant

The state model names and docs must exactly match runtime guarantees.

### Options

Option A: Rename current `RequestIsolated` to `HostContextIsolated`.

Semantics:

- host-side request context reset;
- env/body/capability/DHT/fuel/timeout reset;
- guest memory/globals may persist if instance is pooled;
- no security invariant relies on guest memory reset.

Add a new stronger mode:

```rust
pub enum PluginStateModel {
    FreshInstancePerRequest,
    HostContextIsolated,
    StatefulPooled,
}
```

Option B: Make `RequestIsolated` truly request-isolated.

- Always instantiate fresh for `RequestIsolated` plugins.
- Never return instances to pool under this mode.
- Keep `StatefulPooled` for explicit reuse.

Option C: Keep the name but add prominent docs and tests saying it is host-context isolation only.

Recommended path: Option A. It avoids a performance cliff while making the guarantee precise. For highest-risk plugins, `FreshInstancePerRequest` can be introduced as a stricter mode.

### Implementation Steps for Option A

1. Add or rename enum variants:

```rust
FreshInstancePerRequest,
HostContextIsolated,
StatefulPooled,
```

2. Migrate existing `RequestIsolated` behavior to `HostContextIsolated`.
3. Add `FreshInstancePerRequest` behavior:

- do not get from pool;
- instantiate fresh;
- drop after invocation;
- record fresh-instance metric.

4. Set defaults:

- `SignedSandboxed`: `FreshInstancePerRequest` or `HostContextIsolated` depending on performance/security choice; document clearly.
- `LocalSandboxed`: `HostContextIsolated` by default.
- `DevelopmentHotReload`/`LocalTrusted`: may use `StatefulPooled`.

5. If preserving backward compatibility in manifests, parse `RequestIsolated` as an alias for `HostContextIsolated` with a deprecation warning.
6. Update `PluginInfo`, docs, tests, and examples.

### Tests

Add tests for:

- `HostContextIsolated` resets env/body/capability violation/DHT/fuel/timeout between requests.
- `HostContextIsolated` may preserve guest global counter if the same instance is reused.
- `FreshInstancePerRequest` does not preserve guest global counter.
- `StatefulPooled` preserves guest global counter and is explicit.
- `SignedSandboxed` default is documented and enforced.
- Deprecated manifest value `RequestIsolated` maps to the chosen compatibility behavior.

### Acceptance Criteria

- State model naming no longer overstates memory/global isolation.
- There is a strict fresh-instance mode or an explicit decision not to provide one yet.
- Tests prove the difference between host-context reset and guest-state reset.

## Workstream 5: CI Status Visibility and Guardrail Confirmation

### Problem

The workflow appears to include guardrail tests, but external commit status/workflow metadata has not been visible through the connector. This may be a connector limitation, disabled Actions, branch-only workflow behavior, or workflow not triggering as expected.

### Desired Invariant

Plugin guardrail suites should run automatically and produce visible pass/fail status for plugin runtime changes.

### Implementation Steps

1. Inspect `.github/workflows/ci.yml` triggers:

- `push` to main
- `pull_request`
- path filters, if any

2. Ensure plugin-runtime paths trigger the workflow:

- `crates/synvoid-plugin-runtime/**`
- `tests/*plugin*`
- `tests/*abi*`
- `tests/*manifest*`
- `architecture/plugin_runtime_sandbox.md`
- `docs/PLUGINS.md`

3. Add a focused workflow job if the existing workflow is too broad:

```yaml
plugin-runtime-guardrails:
  runs-on: ubuntu-latest
  steps:
    - cargo fmt --all -- --check
    - cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
    - cargo test -p synvoid-plugin-runtime
    - cargo test --test abi_memory_boundary_guard
    - cargo test --test plugin_capability_boundary_guard
    - cargo test --test plugin_signature_policy_guard
    - cargo test --test manifest_authority_wiring
    - cargo test --test manifest_authority_load_path_guard
```

4. Add the new Milestone 2 guard tests if separate:

- ABI frame serialization tests
- execution containment tests
- host API sub-capability tests

5. Document the expected workflow/job name in `AGENTS.md`.
6. If the repo intentionally does not use GitHub Actions, add an explicit local verification script and status expectation instead.

### Tests / Verification

- Commit or PR touching plugin runtime should trigger the guardrail job.
- The job should fail if a guardrail test is broken.
- The job should appear in GitHub commit status/checks.
- `scripts/verify_architecture.sh` should include the plugin guardrails or clearly defer to CI.

### Acceptance Criteria

- Plugin runtime hardening has visible automated verification.
- Guardrails are not only local commands in commit messages.
- Developers know which job/script must pass before merging plugin runtime changes.

## Workstream 6: Small Documentation Corrections

### Targets

Update documentation to match closure decisions.

Files likely involved:

- `architecture/plugin_runtime_sandbox.md`
- `docs/PLUGINS.md`
- `src/plugin/AGENTS.override.md`
- `AGENTS.md`
- `.opencode/skills/serverless_wasm/SKILL.md`

### Required Updates

- State exactly who owns the epoch incrementer lifecycle.
- State body chunk timeout status: enforced/tested, refactored, or deferred.
- Clarify state model names and guest memory/global persistence guarantees.
- Clarify pool metrics definitions.
- List CI guardrail job or local verification script.

### Acceptance Criteria

- Docs no longer imply stronger guarantees than code enforces.
- Every closure decision is reflected in operator/developer-facing docs.

## Recommended Execution Order

1. Fix pool/concurrency metric semantics. This is small and prevents misleading observability.
2. Clarify/rename state model semantics, because tests and docs depend on the names.
3. Wire epoch incrementer into production lifecycle and add lifecycle validation.
4. Resolve the ignored body chunk timeout test or explicitly defer with docs and guardrails.
5. Confirm CI/status visibility and update docs.

## Validation Commands

Run at minimum:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test plugin_failure_does_not_poison_manager
```

Also run any newly added closure tests by name:

```bash
cargo test -p synvoid-plugin-runtime -- test_epoch_incrementer
cargo test -p synvoid-plugin-runtime -- test_body_chunk_timeout
cargo test -p synvoid-plugin-runtime -- test_state_model
cargo test -p synvoid-plugin-runtime -- test_pool_metrics
```

## Completion Definition

This closure pass is complete when:

- Production runtime lifecycle starts or validates the epoch incrementer when epoch deadlines are enabled.
- No important host-call timeout behavior is hidden behind an ignored test without explicit documented deferral.
- Pool miss and concurrency-limit metrics are semantically separate.
- Plugin state model names match their actual memory/global isolation guarantees.
- CI or an explicit verification script visibly runs the plugin guardrail suite.
- Documentation matches the implemented guarantees.

After this closure pass, Milestone 2 can be considered complete enough to move into the next roadmap area: native/plugin lifecycle operator safety, hot-reload atomicity, unsafe native extension containment, or the broader plugin author/operator documentation milestone.