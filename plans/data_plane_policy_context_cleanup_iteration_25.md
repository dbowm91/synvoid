# Data-Plane Policy Context Cleanup — Iteration 25

## Goal

Finish the data-plane composition-root track by adding explicit threat-intel policy-context ownership to the new worker-level `DataPlaneServices` root.

Iteration 24 successfully created a worker bootstrap composition bundle:

- `DataPlaneServices` groups existing worker/data-plane service handles;
- `DataPlaneServicesBuilder` centralizes handle collection;
- worker bootstrap now builds the bundle once and wires request services from it;
- record-store ownership is explicit instead of relying only on globals.

However, the first pass did not yet carry or apply `ThreatIntelPolicyContext`. This cleanup pass should add that missing policy-context ownership without changing proxy, YARA/WASM, routing, WAF, DHT sync, ingestion, or enforcement behavior.

## Core Principle

`DataPlaneServices` should own already-constructed policy/runtime handles. It should not discover concrete mesh state itself.

The safe shape is:

```text
mesh init / canonical reader / advisory source / threat-intel policy context
        ↓
DataPlaneServicesBuilder
        ↓
DataPlaneServices
        ↓
explicit low-risk apply step into ThreatIntelligenceManager
```

The composition root owns and passes context. It does not evaluate request policy.

## Non-Goals

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change `ThreatIntelPolicyDecision`, `CanonicalTrustReader`, `AdvisoryRecordSource`, or threat-intel actionability semantics.

Do not remove raw lookup APIs.

Do not create concrete canonical/advisory implementations inside `DataPlaneServices`.

Do not introduce new globals.

Do not add live DHT/Raft/network tests.

## Phase 1 — Verify Current Baseline

Inspect the current composition bundle.

Run:

```bash
rg "DataPlaneServices|DataPlaneServicesBuilder|cross_wire_mesh_services|ThreatIntelPolicyContext|set_policy_context|threat_intel_policy|with_threat_intel|with_record_store" src/worker/unified_server crates/synvoid-mesh/src architecture AGENTS.md
```

Confirm:

1. `src/worker/unified_server/services.rs` owns `DataPlaneServices` and `DataPlaneServicesBuilder`.
2. `DataPlaneServices` carries existing service handles.
3. `ThreatIntelPolicyContext` is not yet carried by the root.
4. Worker bootstrap builds `DataPlaneServices` in `run_unified_server_worker`.
5. No proxy/YARA/WASM/routing/enforcement behavior was migrated.

### Acceptance Criteria

Record any baseline mismatch before editing.

## Phase 2 — Add Optional ThreatIntelPolicyContext Field

Extend `DataPlaneServices` and `DataPlaneServicesBuilder` under `#[cfg(feature = "mesh")]`.

Suggested field:

```rust
#[cfg(feature = "mesh")]
pub threat_intel_policy: Option<ThreatIntelPolicyContext>,
```

Suggested builder field:

```rust
#[cfg(feature = "mesh")]
threat_intel_policy: Option<ThreatIntelPolicyContext>,
```

Suggested builder method:

```rust
#[cfg(feature = "mesh")]
pub fn with_threat_intel_policy(mut self, ctx: Option<ThreatIntelPolicyContext>) -> Self {
    self.threat_intel_policy = ctx;
    self
}
```

Suggested accessor if direct field access should be avoided:

```rust
#[cfg(feature = "mesh")]
pub fn threat_intel_policy(&self) -> Option<ThreatIntelPolicyContext> {
    self.threat_intel_policy.clone()
}
```

### Rules

- `None` must be the default.
- Empty root must preserve current behavior.
- Do not build canonical/advisory concrete sources here.
- Do not force `ThreatIntelPolicyContext` to exist whenever mesh is enabled.
- Do not make `DataPlaneServices` generic.

### Acceptance Criteria

The composition root can carry an already-constructed `ThreatIntelPolicyContext`.

## Phase 3 — Add A Low-Risk Apply Helper

Add a helper that applies the carried policy context to the existing threat-intel manager.

Suggested shape:

```rust
#[cfg(feature = "mesh")]
pub fn apply_threat_intel_policy_context(&self) {
    if let Some(threat_intel) = &self.threat_intel {
        threat_intel.set_policy_context(self.threat_intel_policy.clone());
    }
}
```

Alternative shape if explicit target is preferred:

```rust
#[cfg(feature = "mesh")]
pub fn apply_threat_intel_policy_context_to(&self, threat_intel: &ThreatIntelligenceManager) {
    threat_intel.set_policy_context(self.threat_intel_policy.clone());
}
```

### Rules

- The helper must only set optional context.
- It must not query DHT, Raft, record store, canonical state, or advisory state.
- It must not change fallback behavior when context is `None`.
- It must not call composed lookup methods.

### Acceptance Criteria

There is exactly one low-risk apply helper for the policy context.

## Phase 4 — Wire The Apply Helper In Worker Bootstrap

In `run_unified_server_worker`, after `let data_plane = builder.build();`, call the helper under `#[cfg(feature = "mesh")]` before or near existing `cross_wire_mesh_services(...)`.

Suggested shape:

```rust
#[cfg(feature = "mesh")]
{
    data_plane.apply_threat_intel_policy_context();
    services::cross_wire_mesh_services(&unified_server, &data_plane);
}
```

This is safe even if `threat_intel_policy` is `None`; it preserves the default no-context behavior already used by threat intel.

### Important

Do not attempt to construct a real `ThreatIntelPolicyContext` in worker bootstrap in this pass unless the canonical/advisory ownership site is already obvious and clean. It is acceptable for the builder to carry `None` until a later pass wires concrete root-owned canonical/advisory sources.

### Acceptance Criteria

Worker bootstrap applies the root-carried context, but behavior remains unchanged when no context is set.

## Phase 5 — Tests

Add tests in `src/worker/unified_server/services.rs` or an adjacent module.

Required tests:

1. builder defaults `threat_intel_policy` to `None` under mesh;
2. builder preserves a provided `ThreatIntelPolicyContext` under mesh;
3. applying a root with no threat-intel manager is a no-op;
4. applying a root with a threat-intel manager and `None` context leaves configured actionability as `None`;
5. applying a root with a threat-intel manager and a populated context enables `evaluate_indicator_actionability_configured(...)`;
6. no DHT/Raft/networking required.

Use existing static canonical/advisory test doubles if available. If constructing a full manager is too heavy in this crate, add a smaller unit test around field/accessor/builder behavior and document manager-apply coverage as a follow-up.

### Acceptance Criteria

Tests cover empty/populated policy context ownership and do not require live mesh networking.

## Phase 6 — Documentation

Update `architecture/mesh_trust_domains.md` or add `architecture/data_plane_composition.md` if that reads better.

Suggested text:

```markdown
### Iteration 25 Data-Plane Policy Context Cleanup

`DataPlaneServices` now carries an optional `ThreatIntelPolicyContext` and exposes a low-risk apply helper for the `ThreatIntelligenceManager`. The default remains `None`, preserving legacy behavior. This pass establishes ownership/wiring for policy context only; it does not migrate proxy, YARA/WASM, routing, WAF enforcement, DHT sync, ingestion, or Raft behavior. Future passes may construct concrete canonical/advisory sources at the root, then pass a populated context through the same field.
```

Also update `AGENTS.md` or worker `AGENTS.override.md` if they summarize `DataPlaneServices`.

### Acceptance Criteria

Docs clearly distinguish:

- `DataPlaneServices` as worker service composition root;
- `ThreatIntelPolicyContext` as optional policy handle;
- no behavior migration in this pass.

## Phase 7 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid data_plane --features mesh
cargo test -p synvoid unified_server --features mesh
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
```

Then adjacent checks:

```bash
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broad checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If a package name differs, use the actual workspace package name from `cargo metadata` or `Cargo.toml`.

## Completion Criteria

This cleanup pass is complete when:

- `DataPlaneServices` carries optional `ThreatIntelPolicyContext` under mesh;
- `DataPlaneServicesBuilder` can set that context;
- default/empty root preserves current behavior;
- a low-risk apply helper wires the context into `ThreatIntelligenceManager`;
- worker bootstrap calls the helper without constructing concrete policy sources in this pass;
- no proxy/YARA/WASM/routing/WAF/enforcement behavior is migrated;
- tests cover empty/populated ownership behavior;
- docs reflect the ownership boundary.

## Follow-Up Recommendation

After this pass, the next architecture step should be deciding where concrete root-owned canonical/advisory sources are constructed. That should be a separate plan: identify canonical snapshot ownership, advisory record-store adapter ownership, and whether populated `ThreatIntelPolicyContext` should become default when mesh is enabled.
