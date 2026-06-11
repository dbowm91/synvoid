# Mesh Threat Intel Policy Consumer Migration — Iteration 19

## Goal

Migrate exactly one low-risk threat-intel consumer to use the new policy-composition helper:

```rust
evaluate_threat_intel_policy(
    canonical: &dyn CanonicalTrustReader,
    advisory: &dyn AdvisoryRecordSource,
    intel_id: &str,
    advisory_key: &str,
)
```

The old/raw path should remain available for comparison tests or fallback during this first migration. This is a narrow consumer migration pass, not a broad threat-intel rewrite.

## Current State

The prior tracks established:

- `CanonicalTrustReader` for canonical/Raft-derived trust;
- `AdvisoryRecordSource` for read-only advisory DHT observations;
- `RecordStoreAdvisorySource` and `StaticAdvisoryRecordSource`;
- `threat_intel_policy.rs`, a pure helper returning explicit `Actionable`, `NotActionable`, and `Deferred` decisions;
- no production consumer currently calls the helper.

There is also a small stale documentation issue: `architecture/mesh_trust_domains.md` has an Iteration 18 note saying the next step is a single consumer migration, but the follow-up list still says to build the policy composition helper. Correct that in this pass.

## Non-Goals

Do not migrate more than one production consumer.

Do not migrate `proxy.rs`, YARA/WASM, route/proxy metadata, or bot/security policy consumers.

Do not rewrite the threat-intel manager.

Do not change DHT ingestion, Push/Announce canonical gating, record-store behavior, sync, anti-entropy, quorum, Raft apply, or canonical reader semantics.

Do not remove old/raw consumer behavior yet.

Do not make advisory-only records actionable.

Do not add live DHT/Raft/network integration tests.

## Phase 1 — Identify One Low-Risk Threat-Intel Consumer

Inventory threat-intel call sites and choose exactly one low-risk read/decision path.

Run:

```bash
rg "ThreatIntel|ThreatIndicator|threat_intel|indicator|block|allow|deny|is_threat|malicious|evaluate_threat_intel_policy|AdvisoryRecordSource|RecordStoreAdvisorySource|get_global_record_store|RECORD_STORE_GLOBAL|get_record" crates/synvoid-mesh/src src crates/synvoid-* architecture docs
```

Read at minimum:

- `crates/synvoid-mesh/src/mesh/threat_intel.rs`
- `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`
- `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`
- `crates/synvoid-mesh/src/mesh/canonical.rs`
- any caller that makes a simple yes/no threat-intel decision

Preferred first target:

- a helper or query function that checks whether a threat indicator is actionable/blockable;
- a function with clear input key/indicator ID;
- a function that can be tested with static/mock sources;
- a path that can preserve old behavior behind a fallback/comparison helper.

Avoid first target:

- request hot path enforcement if it requires broad behavior changes;
- YARA/WASM loading;
- proxy routing policy;
- async/network-fed gossip paths;
- mutation/ingest paths.

### Acceptance Criteria

Exactly one consumer/helper is selected and documented in code comments or the architecture note.

No code is changed before selecting the target.

## Phase 2 — Add A Small Consumer-Facing Wrapper

Do not directly scatter `evaluate_threat_intel_policy(...)` into production logic. Add a small wrapper near the selected consumer.

Suggested shape:

```rust
pub fn evaluate_indicator_actionability(
    canonical: &dyn CanonicalTrustReader,
    advisory: &dyn AdvisoryRecordSource,
    intel_id: &str,
    advisory_key: &str,
) -> ThreatIntelPolicyDecision {
    evaluate_threat_intel_policy(canonical, advisory, intel_id, advisory_key)
}
```

If the consumer has an existing manager struct, prefer a method that accepts trait objects or holds optional injected trait handles.

### Rules

- Keep raw/legacy path available.
- Do not introduce globals to fetch the advisory source or canonical reader.
- If an existing manager cannot cleanly receive both traits, stop at adding a wrapper + tests and document injection deferred.
- Do not instantiate `SnapshotCanonicalTrustReader` or `RecordStoreAdvisorySource` deep inside a service function.
- Prefer dependency injection from higher-level composition.

### Acceptance Criteria

The selected consumer can call policy output through a wrapper or injection seam.

No broad constructor churn.

## Phase 3 — Add Fallback / Comparison Behavior

For the first migration, preserve the old/raw behavior path.

One acceptable pattern:

```rust
pub enum ThreatIntelConsumerMode {
    LegacyRaw,
    PolicyComposed,
    CompareOnly,
}
```

But avoid adding config if too much churn. A lower-churn alternative is to keep a test-only comparison helper.

Preferred behavior for this pass:

- production default remains legacy-compatible unless an injected policy context is present;
- if policy context is present, selected consumer can use `ThreatIntelPolicyDecision`;
- tests compare legacy and policy-composed outcomes for a small fixture.

### Acceptance Criteria

Old/raw path remains available.

Policy path can be tested independently.

No behavior surprise for deployments that do not inject both seams.

## Phase 4 — Map Policy Decisions To Consumer Output

For the selected consumer only, map decisions explicitly.

Suggested mapping:

```rust
ThreatIntelPolicyDecision::Actionable(_) => consumer_result_allow_action_or_block,
ThreatIntelPolicyDecision::AdvisoryOnly(_) => non_actionable_observation,
ThreatIntelPolicyDecision::NotActionable(reason) => non_actionable_with_reason,
ThreatIntelPolicyDecision::Deferred(reason) => defer_or_fail_closed_per_existing_behavior,
```

Be conservative:

- advisory-only is never actionable;
- canonical unavailable/unknown should not silently allow actionability;
- if the old consumer had fail-open behavior, preserve it only behind explicit legacy path and document it.

### Acceptance Criteria

Decision mapping is explicit and tested.

No advisory-only data becomes actionable.

## Phase 5 — Tests

Use static/offline sources where possible.

Required tests:

1. Selected consumer returns actionable/blockable only when policy decision is `Actionable`.
2. Advisory present but canonical unknown is not actionable.
3. Advisory missing is not actionable.
4. Canonical not trusted is not actionable.
5. Canonical unavailable/unknown maps to conservative output or documented defer behavior.
6. Legacy/raw path remains available and behaves as before for a small fixture.
7. Comparison test verifies policy-composed path does not make advisory-only records actionable.
8. No DHT/Raft/networking required.

If production integration is not clean yet:

- add wrapper tests only;
- document that production consumer migration remains deferred pending injection seam.

### Acceptance Criteria

The selected consumer or wrapper has focused tests over the policy output.

Tests cover both legacy and policy-composed behavior.

## Phase 6 — Fix Architecture Docs

Update `architecture/mesh_trust_domains.md`.

Required fixes:

1. Remove/update the stale follow-up that says the next step is to build the composition helper.
2. Add Iteration 19 note.

If production consumer is migrated:

```markdown
### Iteration 19 Threat Intel Consumer Migration

One low-risk threat-intel consumer now uses the threat-intel policy composition helper. The old/raw path remains available for comparison/fallback. Policy-composed behavior requires both advisory observation and canonical trust before treating an indicator as actionable; advisory-only records are not actionable. No proxy, YARA/WASM, routing, or broader service consumers were migrated.
```

If migration is deferred because injection is not clean:

```markdown
### Iteration 19 Threat Intel Consumer Migration Preparation

A consumer-facing wrapper was added around the threat-intel policy helper, but production migration remains deferred because the selected consumer does not yet receive both `CanonicalTrustReader` and `AdvisoryRecordSource` cleanly. The old/raw path remains unchanged. No service consumers were migrated.
```

Follow-up should point to the next actual step: either complete the injection seam for the selected consumer or migrate a second consumer only after the first is stable.

### Acceptance Criteria

Docs match actual implementation.

No stale follow-up remains.

## Phase 7 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh canonical --features mesh
```

Run selected consumer tests by module name, for example:

```bash
cargo test -p synvoid-mesh threat_intel --features mesh
```

Then adjacent seams:

```bash
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broader checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broader checks fail for unrelated reasons, document focused checks and exact unrelated failure.

## Completion Criteria

This iteration is complete when:

- exactly one low-risk threat-intel consumer or wrapper uses the policy helper;
- old/raw behavior remains available;
- actionability requires advisory presence plus canonical trust;
- advisory-only records are not actionable;
- tests cover policy-composed and legacy behavior;
- no broad service migration occurs;
- no raw DHT/Raft global access is newly introduced;
- architecture docs accurately describe the migration or deferred state.

## Follow-Up Recommendation

After this pass, review the selected consumer under real code paths. If the injection seam is clean and tests are stable, migrate one additional threat-intel read path. Do not move proxy, YARA/WASM, or routing policy until at least one threat-intel consumer has run through the composed policy path cleanly.
