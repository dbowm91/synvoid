# Mesh Threat Intel Policy Injection — Iteration 20

## Goal

Complete the injection seam for the selected threat-intel consumer so `ThreatIntelligenceManager` can use the policy-composed path without every caller manually passing both seams.

Iteration 19 added:

- `ThreatIntelligenceManager::evaluate_indicator_actionability(...)`;
- a wrapper over `evaluate_threat_intel_policy(...)`;
- old/raw lookup paths preserved;
- documentation that production injection of `CanonicalTrustReader + AdvisoryRecordSource` remains deferred.

This pass should add the smallest clean injection carrier for those two trait objects and migrate exactly one real read path to use it when configured.

## Core Invariant

Actionability requires:

```text
advisory observation present + canonical trust present
```

Advisory-only records are observations, not actionable policy.

Canonical unknown/unavailable must not silently become actionable.

## Non-Goals

Do not migrate more than one real threat-intel read path.

Do not migrate proxy, YARA/WASM, route policy, bot policy, or broader service consumers.

Do not rewrite `ThreatIntelligenceManager`.

Do not remove legacy/raw lookup functions.

Do not change DHT ingestion, sync, anti-entropy, Push/Announce canonical ingress, quorum, record-store mutation, or Raft apply behavior.

Do not construct concrete `SnapshotCanonicalTrustReader` or `RecordStoreAdvisorySource` deep inside threat-intel logic.

Do not introduce `RECORD_STORE_GLOBAL` usage.

Do not add live Raft/DHT/network tests.

## Phase 1 — Inspect Current Threat-Intel Manager State

Confirm the Iteration 19 state.

Run:

```bash
rg "evaluate_indicator_actionability|evaluate_threat_intel_policy|is_policy_actionable|lookup_threat_indicator_in_dht|lookup_local_indicator|lookup_local_indicator_by_ip|ThreatIntelligenceManager|CanonicalTrustReader|AdvisoryRecordSource|RecordStoreAdvisorySource|StaticAdvisoryRecordSource" crates/synvoid-mesh/src/mesh/threat_intel.rs crates/synvoid-mesh/src/mesh/threat_intel_policy.rs crates/synvoid-mesh/src/mesh/dht/advisory_source.rs architecture docs
```

Confirm:

1. `evaluate_indicator_actionability` exists and takes both trait objects manually.
2. Existing raw lookup paths are still present.
3. No concrete canonical/advisory implementation is constructed inside `threat_intel.rs`.
4. No hot enforcement path is already policy-composed.

### Acceptance Criteria

Do not start changes until the current state is confirmed.

## Phase 2 — Add A Small Injection Carrier

Add a narrow optional policy context to `ThreatIntelligenceManager`.

Suggested type:

```rust
#[derive(Clone)]
pub struct ThreatIntelPolicyContext {
    pub canonical: Arc<dyn CanonicalTrustReader>,
    pub advisory: Arc<dyn AdvisoryRecordSource>,
}
```

Alternative if public fields are not desired:

```rust
#[derive(Clone)]
pub struct ThreatIntelPolicyContext {
    canonical: Arc<dyn CanonicalTrustReader>,
    advisory: Arc<dyn AdvisoryRecordSource>,
}

impl ThreatIntelPolicyContext {
    pub fn new(
        canonical: Arc<dyn CanonicalTrustReader>,
        advisory: Arc<dyn AdvisoryRecordSource>,
    ) -> Self { ... }

    pub fn canonical(&self) -> &dyn CanonicalTrustReader { ... }
    pub fn advisory(&self) -> &dyn AdvisoryRecordSource { ... }
}
```

Add to manager:

```rust
policy_context: RwLock<Option<ThreatIntelPolicyContext>>,
```

Add methods:

```rust
pub fn set_policy_context(&self, ctx: Option<ThreatIntelPolicyContext>) { ... }

fn policy_context(&self) -> Option<ThreatIntelPolicyContext> { ... }
```

### Rules

- Default is `None`.
- No behavior changes when `None`.
- Accept trait objects only.
- Do not construct concrete implementations here.
- Do not create global/static handles.

### Acceptance Criteria

`ThreatIntelligenceManager` can carry both seams optionally.

Default construction remains legacy-compatible.

## Phase 3 — Add A Manager-Level Policy Evaluation Method

Keep the existing manual method for tests/comparison, but add a configured method that uses the injected context.

Suggested shape:

```rust
pub fn evaluate_indicator_actionability_configured(
    &self,
    indicator_value: &str,
    threat_type: ThreatType,
) -> Option<ThreatIntelPolicyDecision> {
    let ctx = self.policy_context()?;
    Some(self.evaluate_indicator_actionability(
        ctx.canonical(),
        ctx.advisory(),
        indicator_value,
        threat_type,
    ))
}
```

or:

```rust
pub fn evaluate_indicator_actionability_or_legacy(
    &self,
    indicator_value: &str,
    threat_type: ThreatType,
) -> ThreatIntelLookupDecision { ... }
```

Prefer the first option if it avoids behavior ambiguity.

### Acceptance Criteria

Configured policy evaluation can be called without every caller manually threading both traits.

Legacy/raw lookup remains separate and explicit.

## Phase 4 — Migrate Exactly One Real Read Path

Pick one narrow read path, likely `lookup_threat_indicator_in_dht` or a new sibling method.

Preferred low-risk approach:

Do **not** rewrite `lookup_threat_indicator_in_dht` directly if that would change existing semantics. Instead add a policy-composed sibling:

```rust
pub fn lookup_threat_indicator_policy_composed(
    &self,
    indicator_value: &str,
    threat_type: ThreatType,
) -> Option<ThreatIndicator> { ... }
```

Behavior:

1. If `policy_context` is `None`, return legacy raw `lookup_threat_indicator_in_dht(...)` or `None` depending on least surprising current behavior. Document the chosen fallback.
2. If policy decision is `Actionable`, return the decoded legacy indicator from raw DHT lookup or local/advisory decode path.
3. If `AdvisoryOnly`, `NotActionable`, or `Deferred`, return `None` and log/debug the reason.
4. Do not make advisory-only actionable.

If decoding from advisory record is too much churn, use policy decision only as a gate around existing `lookup_threat_indicator_in_dht(...)`.

### Acceptance Criteria

Exactly one read path or sibling method is policy-composed.

Legacy method remains intact.

Default behavior remains compatible.

## Phase 5 — Tests

Add focused tests using static/offline sources.

Required tests:

1. `ThreatIntelligenceManager` default has no policy context and legacy/raw lookup remains available.
2. `set_policy_context(Some(...))` enables configured evaluation.
3. Configured actionability returns `Actionable` only when advisory present and canonical trusted.
4. Configured actionability returns not-actionable/deferred for advisory-only, advisory missing, canonical not trusted, canonical unavailable.
5. The selected policy-composed read path returns a result only for `Actionable`.
6. The selected policy-composed read path returns `None` for advisory-only.
7. Legacy/raw path remains available and unchanged for a small fixture.
8. No DHT/Raft/networking required, except existing pure record-store adapter if already used.

### Practical Guidance

If `ThreatIntelligenceManager` construction needs a block-store mock, reuse existing tests/helpers.

If raw DHT lookup needs too much setup, add a policy-composed helper that maps decisions to a small internal result first, and defer raw decode integration.

Do not weaken existing threat-intel validation to make tests pass.

### Acceptance Criteria

Tests prove injection and non-actionability of advisory-only data.

## Phase 6 — Documentation Cleanup

Update `architecture/mesh_trust_domains.md`.

Suggested text:

```markdown
### Iteration 20 Threat Intel Policy Injection

`ThreatIntelligenceManager` now carries an optional `ThreatIntelPolicyContext` containing `Arc<dyn CanonicalTrustReader>` and `Arc<dyn AdvisoryRecordSource>`. Default `None` preserves legacy behavior. A configured policy-composed lookup/evaluation path can now use the injected seams without deep construction or globals. Exactly one threat-intel read path was migrated or added as a policy-composed sibling; old raw lookup paths remain available for comparison/fallback.
```

If the read-path migration is deferred, use:

```markdown
The injection carrier was added, but production read-path migration remains deferred because decoding/action mapping needs a separate pass. The configured evaluation method is tested and old raw paths remain unchanged.
```

Also ensure the follow-up no longer says to complete the injection seam if it is done.

### Acceptance Criteria

Docs match the implementation precisely.

## Phase 7 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh canonical --features mesh
```

Then adjacent seam checks:

```bash
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broader checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks fail for unrelated reasons, record focused checks and exact unrelated failure.

## Completion Criteria

This iteration is complete when:

- `ThreatIntelPolicyContext` or equivalent exists;
- it carries `Arc<dyn CanonicalTrustReader>` and `Arc<dyn AdvisoryRecordSource>`;
- `ThreatIntelligenceManager` can store it optionally;
- default `None` preserves legacy behavior;
- configured evaluation uses the injected seams;
- exactly one read path or sibling method is policy-composed, or deferral is explicitly documented;
- old/raw lookup paths remain available;
- no concrete canonical/advisory implementation is constructed deep in threat intel;
- tests cover injection, actionable, advisory-only not actionable, and legacy availability;
- architecture docs are accurate.

## Follow-Up Recommendation

After this pass, use the injected context to migrate one additional threat-intel read path. Only after two threat-intel paths are stable should proxy, YARA/WASM, routing, or broader service policy move to composed policy outputs.
