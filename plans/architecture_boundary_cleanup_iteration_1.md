# Architecture Boundary Cleanup — Iteration 1

## Goal

This pass should tighten the highest-value architectural seams without broad redesign. The target is to make the current architecture more enforceable: root should become more of a composition layer, HTTP/3 should stop depending on concrete root-owned WAF/drain types, and worker startup should move toward explicit service-context construction instead of ad hoc cross-wiring.

This is intentionally the first iteration. Do not attempt to split the entire mesh crate or redesign DHT/Raft in this pass. Preserve existing behavior and keep changes reviewable.

## Current Architectural Problem

SynVoid now has a clear intended architecture:

- Supervisor owns control-plane state, worker lifecycle, config distribution, Raft/DHT coordination, and management APIs.
- UnifiedServerWorker owns the latency-sensitive request path.
- CPU workers own bounded heavy work.
- DHT is advisory/TTL-bound; Raft is canonical for global trust state.
- Extracted crates are intended to own stable subsystem boundaries.

The weakness is that these boundaries are still partly conventional rather than enforced by type boundaries and dependency ownership. The root crate still owns a broad dependency surface and several concrete subsystem implementations. `UnifiedServerWorker` still manually wires many services in one orchestration path. HTTP/3 extraction is blocked by concrete `WafCore` and `WorkerDrainState` coupling.

## Non-Goals

Do not redesign the WAF detection logic.

Do not change the DHT/Raft trust model.

Do not split `synvoid-mesh` into multiple crates yet.

Do not remove features or change default runtime behavior in this pass.

Do not perform large formatting-only rewrites.

Do not weaken any security check, especially TLS passthrough warnings, WAF enforcement, rate limiting, IPC signing, or mesh write validation.

## Phase 1 — Finish the HTTP/3 WAF/Drain Boundary

### Problem

`crates/synvoid-http3/src/lib.rs` currently documents that the real HTTP/3 server remains in root because the server still stores or dispatches through concrete root-owned types:

- `Arc<WafCore>` or equivalent concrete WAF reference.
- Concrete `WorkerDrainState` rather than a core-owned drain abstraction.
- A cast/dispatch path involving `Http3RequestWaf` that prevents clean crate movement.

### Required Changes

Introduce or complete a single HTTP/3-facing WAF facade that can be passed as a trait object. Prefer a composition like:

```rust
pub trait Http3WafRuntime:
    synvoid_http::Http3RequestWaf + synvoid_waf::WafAccess + Send + Sync + 'static
{
}

impl<T> Http3WafRuntime for T where
    T: synvoid_http::Http3RequestWaf + synvoid_waf::WafAccess + Send + Sync + 'static
{
}
```

If object-safety issues exist because of async trait expansion or associated types, use the smallest adapter object instead:

```rust
pub struct Http3WafAdapter {
    inner: Arc<dyn Http3RequestWaf + Send + Sync>,
    access: Arc<dyn WafAccess>,
}
```

Use whichever approach produces the least churn and compiles cleanly.

Replace HTTP/3 server fields and constructors that store concrete `Arc<WafCore>` with an `Arc<dyn Http3WafRuntime>` or equivalent adapter.

Move any HTTP/3-only WAF access glue into `synvoid-http3` or a narrow shared crate, not root.

Replace concrete `WorkerDrainState` usage in the HTTP/3 server with the existing `DrainState` trait from `synvoid-core`, or create a minimal core-owned trait if the existing one is insufficient.

After this is done, move the root HTTP/3 server implementation into `crates/synvoid-http3` if the only remaining blockers are resolved. If a platform binding helper such as UDP reuse remains root-owned, isolate it behind a tiny function/trait and leave a clearly documented follow-up instead of pulling platform internals into HTTP/3.

### Acceptance Criteria

`crates/synvoid-http3/src/lib.rs` no longer says the server must stay in root due to concrete `WafCore` or `WorkerDrainState` blockers.

HTTP/3 server code does not import `crate::waf::WafCore` directly.

HTTP/3 server code does not import `crate::worker::...::WorkerDrainState` directly.

The root crate constructs the concrete WAF/drain objects and passes only trait objects or adapters into HTTP/3.

Existing HTTP/3 behavior is preserved.

## Phase 2 — Shrink Root Dependency Ownership Around HTTP/3/WAF Movement

### Problem

The root `Cargo.toml` still contains dependencies that appear to be owned by extracted crates or transitional root modules. This weakens compile-time boundaries and keeps the root crate as the architectural gravity well.

### Required Changes

Perform a targeted dependency audit after Phase 1. Do not try to clean the entire root dependency graph.

Focus only on dependencies affected by HTTP/3 movement and WAF access cleanup:

- `quinn`
- `h3`
- `h3-quinn`
- direct HTTP/3-specific TLS/QUIC helpers
- direct dependencies only needed by moved HTTP/3 server code
- any WAF access glue dependencies that should live in `synvoid-waf`, `synvoid-http`, or `synvoid-http3`

For each candidate dependency, determine whether root still imports it. If not, move ownership to the appropriate crate and remove it from root.

Preserve feature wiring. If root features currently activate HTTP/3-related dependencies indirectly, update feature propagation rather than reintroducing root direct dependencies.

### Acceptance Criteria

Root dependency comments remain accurate.

No dependency is removed from root unless `cargo check` confirms it is unused by root.

HTTP/3-owned dependencies live in `crates/synvoid-http3/Cargo.toml` unless another crate clearly owns them.

Feature-gated builds continue to compile.

## Phase 3 — Introduce a DataPlaneServices / WorkerRuntimeContext Builder

### Problem

`run_unified_server_worker` is still doing too much manual cross-subsystem wiring. The code is phase-commented and readable, but many important invariants are still implicit in ordering.

### Required Changes

Introduce a small `DataPlaneServices` or `WorkerRuntimeContext` struct in the worker/unified-server area. Do not over-generalize it yet.

The first version should group already-existing service handles and initialization products, for example:

```rust
pub struct DataPlaneServices {
    pub request_services: Arc<RequestServices>,
    pub serverless_manager: Arc<ServerlessManager>,
    pub port_honeypot_runner: Option<Arc<...>>,
    pub mesh_transport_manager: Option<Arc<...>>,
    pub threat_intel: Option<Arc<...>>,
}
```

Adjust the exact fields to match existing types. The goal is not to invent new abstractions; the goal is to stop scattering cross-wiring across the worker bootstrap.

Move the mesh/threat-intel/serverless/port-honeypot cross-wiring into a small builder function. Suggested shape:

```rust
let services = DataPlaneServices::build(
    &shared_config,
    &args.config_path,
    &unified_server,
    port_honeypot_runner,
).await?;
```

Use this builder to produce the final `RequestServices` injected into the WAF.

Keep TLS passthrough validation inline for now unless extracting it is trivial. It is security-sensitive and should not be mixed into this refactor unless behavior is unchanged and tests cover it.

### Acceptance Criteria

`run_unified_server_worker` is shorter and primarily orchestrates phases rather than manually cross-wiring every service.

`RequestServices::new(...)` construction happens in one dedicated function or builder path.

Mesh/serverless/port-honeypot wiring has a clear home.

No runtime behavior changes.

## Phase 4 — Replace One Global With Explicit Injection Where Low-Risk

### Problem

The mesh module exposes global mutable state for the DHT record store. Global service location makes tests, reload behavior, and multi-tenant reasoning harder.

### Required Changes

Do not attempt to remove every global in this pass.

Pick one low-risk global, preferably the mesh DHT record store global:

```rust
set_global_record_store(...)
get_global_record_store(...)
```

Add an explicit service handle path through `DataPlaneServices` or mesh initialization where feasible.

If too much code still depends on the global, keep the global as a compatibility fallback, but mark the explicit handle as the preferred path and update at least one production call path to use it.

Do not break tests that rely on the global. Add a small reset/helper only under `#[cfg(test)]` if needed.

### Acceptance Criteria

At least one production path that previously retrieved a global service now receives it explicitly.

The global remains only as compatibility/fallback if full removal is too large.

Tests remain isolated and deterministic.

## Phase 5 — Add Boundary Regression Tests

### Required Tests

Add or update tests that cover the actual architectural seam changes:

1. HTTP/3 can be constructed with a mock WAF trait object or adapter, without concrete `WafCore`.
2. HTTP/3 can be constructed with a mock drain trait object, without concrete `WorkerDrainState`.
3. `DataPlaneServices` builder produces request services in mesh-enabled and mesh-disabled builds.
4. The selected explicit service-injection path does not require the global record store.

If full async HTTP/3 server construction is cumbersome, use compile-time style tests with minimal mock objects. The purpose is to prevent concrete root coupling from returning.

## Validation Commands

Run the narrowest useful checks first, then full checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-core
cargo check -p synvoid-waf
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check --workspace --all-targets
cargo test -p synvoid-http3
cargo test -p synvoid-waf
cargo test --workspace --all-targets
```

If feature interactions are expensive, at minimum also run:

```bash
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

## Completion Criteria

This iteration is complete when:

- HTTP/3 no longer depends on concrete root `WafCore` or `WorkerDrainState` types.
- Root has fewer direct dependencies or at least no stale HTTP/3-specific dependency ownership comments.
- Worker bootstrap has a first explicit service-context/builder boundary.
- At least one global service path has an explicit injected alternative.
- Boundary tests prevent the concrete coupling from silently returning.
- Existing behavior and security checks are preserved.

## Follow-Up Iterations

After this pass, the next architectural iteration should likely focus on `synvoid-mesh` decomposition by trust domain:

- mesh transport
- DHT/advisory record distribution
- Raft/canonical trust state
- identity/organization keys
- security-policy services
- optional distributed services such as DNS, YARA, and WASM distribution

Do not start that split until this pass has landed and the root/HTTP3/WAF seams are cleaner.
