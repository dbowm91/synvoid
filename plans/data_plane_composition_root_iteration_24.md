# Data-Plane Composition Root — Iteration 24

## Goal

Introduce an explicit data-plane composition / ownership root that centralizes construction and wiring of runtime service handles without changing proxy, WAF, YARA/WASM, routing, or threat-intel enforcement behavior.

This follows the completed threat-intel policy track:

- `ThreatIntelPolicyContext` is injectable;
- composed threat-intel local/DHT read APIs exist;
- raw lookup APIs remain compatibility/diagnostic paths;
- the threat-intel policy migration track is paused until a concrete consumer appears.

The next architecture risk is ad hoc dependency wiring. This pass should establish a narrow owner for policy/runtime handles so future proxy/YARA/WASM/routing migration has a single place to draw dependencies from.

## Core Principle

Services should not individually discover or construct mesh policy dependencies.

Instead:

```text
root config / mesh runtime / record store / canonical snapshot
        ↓
data-plane composition root
        ↓
small injected contexts for proxy, WAF, threat intel, plugin runtime, route policy
```

The composition root owns wiring. Consumers use narrow interfaces.

## Non-Goals

Do not migrate proxy request evaluation to threat-intel policy.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, or WAF enforcement.

Do not change `handle_incoming_threat`, `sync_from_dht`, DHT publish/announce, record-store behavior, canonical ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change `ThreatIntelPolicyDecision`, `CanonicalTrustReader`, `AdvisoryRecordSource`, or threat-intel policy semantics.

Do not remove raw lookup APIs or compatibility globals in this pass.

Do not introduce live DHT/Raft/network tests.

## Phase 1 — Inventory Existing Composition Points

Find where root/runtime objects are currently assembled and injected.

Run:

```bash
rg "DataPlane|WorkerRuntimeContext|Http3Waf|Http3RequestWaf|ThreatIntelligenceManager|ThreatIntelPolicyContext|set_policy_context|CanonicalTrustReader|AdvisoryRecordSource|RecordStoreAdvisorySource|SnapshotCanonicalTrustReader|StaticCanonicalTrustReader|RecordStoreManager|MeshTransport|proxy|waf" crates src architecture docs AGENTS.md
```

Inspect likely files:

- root/server startup files;
- proxy construction and runtime context types;
- HTTP/3 runtime wiring;
- mesh transport construction;
- threat-intel manager construction;
- record-store manager construction;
- canonical/advisory source modules;
- architecture notes for previous boundary cleanup.

Classify current composition sites:

1. root-owned runtime composition;
2. subsystem-local construction;
3. compatibility/global access;
4. test-only construction;
5. stale or dead code.

### Acceptance Criteria

Before editing, record where dependencies are currently composed and which area is safest for a new root object.

## Phase 2 — Define A Minimal Composition Root Type

Add a small type in the most appropriate crate/module.

Candidate names:

```rust
DataPlaneServices
DataPlaneRuntimeServices
SecurityPolicyServices
MeshPolicyServices
```

Preferred first version:

```rust
#[derive(Clone)]
pub struct DataPlaneServices {
    threat_intel_policy: Option<ThreatIntelPolicyContext>,
    // future fields intentionally omitted until needed
}
```

or, if threat-intel should remain mesh-scoped:

```rust
#[derive(Clone)]
pub struct MeshPolicyServices {
    threat_intel_policy: Option<ThreatIntelPolicyContext>,
}
```

Start small. Do not add fields for proxy/WAF/plugin runtime unless there is already a clean owner to pass them.

### Rules

- Use typed fields, not maps or dynamic registries.
- Prefer `Arc` handles only at ownership boundaries.
- Do not create concrete canonical/advisory implementations inside consumers.
- Do not create a service locator with arbitrary lookups.
- Do not force all services to depend on this root in the first pass.

### Acceptance Criteria

A composition root exists, is cloneable if necessary, and can carry the existing threat-intel policy context without changing behavior.

## Phase 3 — Add Builder / Constructor Helpers

Add constructor helpers that make ownership explicit.

Suggested shape:

```rust
impl DataPlaneServices {
    pub fn empty() -> Self { ... }

    pub fn with_threat_intel_policy(mut self, ctx: ThreatIntelPolicyContext) -> Self { ... }

    pub fn threat_intel_policy(&self) -> Option<ThreatIntelPolicyContext> { ... }
}
```

If the root owns only references:

```rust
pub fn from_mesh_policy_context(ctx: ThreatIntelPolicyContext) -> Self { ... }
```

### Rules

- Default/empty root must preserve current behavior.
- Do not make context construction side-effectful.
- Do not reach into global record store or mesh transport from the builder.
- The builder may accept already-constructed `ThreatIntelPolicyContext`, but should not construct it from raw pieces unless the ownership site is clearly root-level.

### Acceptance Criteria

Tests can build an empty root and a root carrying threat-intel policy context.

## Phase 4 — Wire Into One Low-Risk Owner Only

Choose one low-risk owner to store or pass the composition root.

Preferred options:

1. root/server runtime context object if one already exists;
2. mesh service container if it already owns `ThreatIntelligenceManager`;
3. threat-intel manager construction site, but only to call `set_policy_context` from the root.

Avoid:

- proxy.rs;
- WAF enforcement code;
- YARA/WASM/plugin runtime;
- route policy hot paths;
- DHT record-store mutation paths.

A safe implementation may only add:

```rust
pub fn apply_to_threat_intel(&self, threat_intel: &ThreatIntelligenceManager) {
    threat_intel.set_policy_context(self.threat_intel_policy());
}
```

or a root-owned setup helper at the construction site.

### Acceptance Criteria

Exactly one low-risk wiring point uses the composition root.

Behavior is unchanged when root is empty.

No broad consumers are migrated.

## Phase 5 — Tests

Add tests around the root object and low-risk wiring.

Required tests:

1. empty root has no threat-intel policy context;
2. root with threat-intel policy context returns/clones the context;
3. applying empty root to `ThreatIntelligenceManager` leaves configured evaluation returning `None`;
4. applying populated root enables `evaluate_indicator_actionability_configured(...)`;
5. no policy-composed lookup behavior changes beyond existing threat-intel tests;
6. no DHT/Raft/networking required.

If root is defined outside `synvoid-mesh`, add crate-appropriate tests and ensure feature flags are correct.

### Acceptance Criteria

Tests prove the root can carry and apply the existing policy context without changing fallback behavior.

## Phase 6 — Documentation

Update architecture documentation.

Add a section to the relevant architecture doc, likely `architecture/mesh_trust_domains.md` or a new `architecture/data_plane_composition.md`.

Suggested text:

```markdown
### Iteration 24 Data-Plane Composition Root

A small data-plane composition root now owns policy/runtime handles that should not be discovered by service consumers directly. The first supported handle is the threat-intel policy context; an empty root preserves legacy behavior. This does not migrate proxy, YARA/WASM, routing, WAF enforcement, DHT sync, or ingestion paths. Future broader consumers should receive narrow policy/runtime interfaces from this root rather than constructing canonical/advisory dependencies locally.
```

Also update `AGENTS.md` or `skills/synvoid_mesh.md` if they track architecture facts.

### Acceptance Criteria

Docs explain that this is an ownership/wiring pass, not a behavior migration.

## Phase 7 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
```

Run any package-specific tests for the new composition root module.

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

If broad checks fail for unrelated reasons, record focused checks and exact unrelated failure.

## Completion Criteria

This iteration is complete when:

- a minimal data-plane/mesh-policy composition root exists;
- it can carry `ThreatIntelPolicyContext`;
- empty root preserves existing behavior;
- one low-risk owner can apply or store the root;
- no proxy/YARA/WASM/routing/enforcement behavior is migrated;
- no new globals or deep concrete dependency construction are introduced;
- tests cover empty/populated root behavior;
- docs explain ownership boundary and future usage.

## Follow-Up Recommendation

After this pass, inspect whether the composition root should become the single place that constructs or receives:

- canonical trust snapshots/readers;
- advisory record-store adapters;
- request security policy interfaces;
- plugin runtime capability contexts;
- route/WAF policy handles.

Do not migrate these consumers until the root object is stable and its ownership boundary is clear.
