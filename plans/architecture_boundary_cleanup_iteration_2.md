# Architecture Boundary Cleanup — Iteration 2

## Goal

This pass continues the previous architecture-boundary cleanup. Iteration 1 successfully moved HTTP/3 ownership into `synvoid-http3`, introduced the `Http3WafBackend` trait-object seam, and added `DataPlaneServices` for data-plane cross-wiring. Iteration 2 should consolidate those gains by reducing root dependency ownership, hardening service injection, and shortening the worker bootstrap without starting the larger mesh decomposition.

The intended end state for this pass is simple: root should remain the composition/binary integration layer, extracted crates should own their protocol/runtime dependencies, globals should be compatibility fallbacks rather than primary production paths, and `run_unified_server_worker` should read as orchestration over validated helper builders rather than a long sequence of mixed subsystem logic.

## Non-Goals

Do not split `synvoid-mesh` into multiple crates yet.

Do not redesign the DHT/Raft boundary.

Do not change WAF detection behavior, challenge behavior, tarpit behavior, rate-limit semantics, mesh trust semantics, or TLS passthrough behavior.

Do not remove the DHT record-store global yet unless the removal is trivial and all call sites are proven migrated.

Do not change default feature profiles in this pass. Feature-profile tightening should be a later dedicated pass.

Do not introduce broad new abstractions. Prefer narrow traits/builders that replace concrete root coupling or hidden globals.

## Phase 1 — Root Dependency Ownership Audit: HTTP/3 and QUIC

### Problem

`synvoid-http3` now owns the HTTP/3 server implementation, and root re-exports the public API. However, root still directly depends on some QUIC/HTTP3-adjacent dependencies, especially `quinn`, under an HTTP/3 + QUIC comment block. That may be legitimate for other root-owned paths, but it needs to be verified and documented. Stale dependency ownership is now the main risk of HTTP/3 extraction drifting back toward root.

### Required Changes

Run targeted searches for every remaining HTTP/3/QUIC dependency in root:

```bash
rg "\bquinn\b|\bh3\b|\bh3_quinn\b|h3-quinn|webpki_roots|webpki-roots" src crates Cargo.toml
cargo tree -p synvoid -i quinn
cargo tree -p synvoid -i webpki-roots
```

Determine why root still needs each dependency. Classify each dependency into one of these categories:

- still genuinely root-owned;
- now owned by `synvoid-http3`;
- owned by `synvoid-mesh`;
- owned by `synvoid-tls` or `synvoid-http-client`;
- stale and removable from root.

If `quinn` is only used through `synvoid-http3` or `synvoid-mesh`, remove the direct root dependency and rely on the owning crate. If root has a real direct usage, update the comment to state which root module owns it.

If `webpki-roots` is not directly used by root, move/remove it from root. If it is used for TLS or mesh, move ownership to the relevant crate.

Do not remove a dependency based only on visual inspection. Validate with `cargo check` after each ownership change.

### Acceptance Criteria

The root `Cargo.toml` no longer has stale `HTTP/3 + QUIC` comments that imply ownership of dependencies actually owned by `synvoid-http3`.

`h3` and `h3-quinn` remain out of root.

`quinn` and `webpki-roots` are either removed from root or annotated with the exact remaining root owner.

`cargo check -p synvoid-http3` and `cargo check --workspace --all-targets` pass.

## Phase 2 — Add a Root Dependency Ownership Note

### Problem

Root dependency ownership has repeatedly required cleanup. A small explicit inventory will prevent future regressions and make handoffs clearer.

### Required Changes

Create or update a short file, preferably:

```text
plans/root_dependency_ownership_iteration_2.md
```

or, if there is already an active root dependency ownership plan, update that file instead.

The note should list only dependencies touched or audited in this pass. It should not become a giant full-repo inventory.

Use this format:

```markdown
| Dependency | Current owner | Root direct? | Reason / next action |
|------------|---------------|--------------|----------------------|
| quinn | synvoid-http3 / synvoid-mesh / root:<module> | yes/no | ... |
```

### Acceptance Criteria

The ownership note exists and matches the final `Cargo.toml` state.

Any root dependency comment changed in `Cargo.toml` points to the ownership note or is self-explanatory.

## Phase 3 — Harden `DataPlaneServicesBuilder` Against Service Locator Drift

### Problem

`DataPlaneServicesBuilder` centralizes cross-wiring, which is good. However, it still creates a fallback serverless manager internally by calling `get_global_plugin_manager()` when no serverless manager is supplied. That keeps a service-locator pattern inside the builder. For iteration 1 this was acceptable; for iteration 2, the builder should become closer to pure dependency assembly.

### Required Changes

Move the default serverless-manager fallback construction out of `DataPlaneServicesBuilder::build()` and into the worker bootstrap or a small explicit helper.

Preferred shape:

```rust
let serverless_manager = unified_server
    .get_serverless_manager()
    .unwrap_or_else(|| build_default_serverless_manager());

let data_plane = DataPlaneServicesBuilder::new()
    .with_serverless_manager(serverless_manager)
    ...
    .build();
```

If `build_default_serverless_manager()` is added, keep it near worker initialization code, not in a generic service bundle.

Make `DataPlaneServicesBuilder::build()` require a serverless manager. Options:

1. Return `Result<DataPlaneServices, DataPlaneServicesBuildError>` if required fields are absent.
2. Keep `build()` infallible but require the serverless manager at constructor time:

```rust
DataPlaneServicesBuilder::new(serverless_manager)
```

Prefer option 2 if it is low-churn.

Avoid adding panics for missing required services unless tests already enforce constructor invariants. This is production bootstrap code; explicit construction should make invalid states difficult to represent.

### Acceptance Criteria

`DataPlaneServicesBuilder::build()` no longer calls `get_global_plugin_manager()`.

The default serverless-manager fallback is built in one explicit worker-bootstrap helper or directly before builder construction.

Tests are updated to provide a serverless manager explicitly.

No runtime behavior changes.

## Phase 4 — Extract TLS Passthrough Validation From Worker Bootstrap

### Problem

`run_unified_server_worker` still contains inline TLS passthrough validation logic. It is security-sensitive and should remain behaviorally identical, but it does not need to live inline in the main worker lifecycle function. Extracting it makes the lifecycle function shorter and gives this policy a clear testable home.

### Required Changes

Move the TLS passthrough validation block into a helper, preferably in `state.rs`, `init_config.rs`, or a new small `validation.rs` under `src/worker/unified_server/`.

Suggested function shape:

```rust
pub async fn validate_tls_passthrough_waf_policy(
    shared_config: &Arc<RwLock<MainConfig>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```

or, if it only logs/records metrics and does not fail:

```rust
pub async fn report_tls_passthrough_waf_policy(shared_config: &Arc<RwLock<MainConfig>>)
```

Preserve exact behavior:

- sites with TLS passthrough and WAF enforcement log informationally;
- sites with TLS passthrough but no WAF enforcement log an error and record the bypass metric;
- passthrough sites without rate limiting log an error;
- do not convert current warnings/errors into hard startup failures unless there is already a config option requiring that behavior.

Add focused tests if the config types make it reasonably easy. If config construction is cumbersome, add a smaller pure helper that classifies passthrough sites from a borrowed site map and test that helper.

### Acceptance Criteria

`run_unified_server_worker` no longer contains the full TLS passthrough scan inline.

The extracted helper preserves current logging/metric semantics.

At least the classification logic is test-covered.

## Phase 5 — Continue Explicit Record Store Injection

### Problem

`DataPlaneServices` now carries an explicit DHT record-store handle, and `MeshTransportManager` already stores and uses a direct record-store field. The global record-store singleton remains in `synvoid-mesh` as compatibility. The next step is to verify call sites and migrate one additional production use away from the global if any remain.

### Required Changes

Search locally with:

```bash
rg "get_global_record_store|set_global_record_store|RECORD_STORE_GLOBAL|get_record_store" src crates tests
```

For every `get_global_record_store()` call, classify it:

- production path that can receive `DataPlaneServices.record_store` or `MeshTransportManager::get_record_store()`;
- compatibility/test path;
- unavoidable global fallback for now.

If a production call site still uses `get_global_record_store()`, migrate one such call site to explicit injection.

If no production call sites use `get_global_record_store()`, add a comment near the global stating that it is legacy compatibility/fallback and should not be used by new production paths.

If `MeshTransportManager` does not yet expose a narrow accessor for its record store, add:

```rust
pub fn get_record_store(&self) -> Option<Arc<RecordStoreManager>>
```

only if it is needed by worker/service injection. Keep the accessor narrow.

### Acceptance Criteria

All current global record-store call sites are classified in a short note or commit message.

At least one additional production path uses explicit injection if such a path exists.

The global is clearly marked as compatibility/fallback.

No DHT trust, TTL, attestation, or write-validation behavior changes.

## Phase 6 — Boundary Regression Tests

### Required Tests

Add or update tests to prevent the specific regressions this pass is addressing.

Suggested tests:

1. `synvoid-http3` still compiles and tests with mock `Http3WafBackend`; no root `WafCore` dependency returns.
2. `DataPlaneServicesBuilder` requires/provides explicit serverless manager and does not call the global plugin manager internally.
3. TLS passthrough classification correctly identifies:
   - passthrough with WAF enforcement;
   - passthrough without WAF enforcement;
   - passthrough without rate limiting.
4. If a record-store accessor/injection path is added, test that `DataPlaneServices` carries the explicit handle when provided.

Do not create broad integration tests that require live QUIC, Raft, DHT, or network sockets unless such tests already exist and are stable.

## Validation Commands

Run targeted checks first:

```bash
cargo fmt --all --check
cargo check -p synvoid-http3
cargo test -p synvoid-http3
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
```

Then run workspace checks:

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
```

Feature checks:

```bash
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If the full test suite is too expensive or flaky, record exactly which narrower checks passed and which broader checks were skipped or failed for pre-existing reasons.

## Completion Criteria

This iteration is complete when:

- root HTTP/3/QUIC dependency ownership is audited and corrected or clearly documented;
- `DataPlaneServicesBuilder` no longer hides a global plugin-manager fallback;
- TLS passthrough policy scanning is extracted from the main worker lifecycle function and covered by focused tests/classification tests;
- record-store global usage is classified and at least one additional explicit-injection path is added if applicable;
- boundary tests prevent regression toward concrete root HTTP/3/WAF coupling;
- behavior remains unchanged.

## Follow-Up Recommendation

After this pass, reassess root dependency ownership again. If root is stable, the next meaningful architectural pass should either:

1. extract another protocol/runtime server implementation out of root, or
2. begin an internal-only `synvoid-mesh` responsibility split by trust domain without creating new crates yet.

Do not start the mesh trust-domain split until this iteration lands cleanly.
