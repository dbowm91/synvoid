# Threat-Intel Policy-Composed Consumer Selection — Iteration 33

## Goal

Select and implement the first low-risk consumers of policy-composed threat-intel decisions.

The canonical/advisory/policy pipeline is now available:

- advisory DHT source exists through `AdvisoryRecordSource`;
- canonical trust exists through `CanonicalTrustReader`;
- Supervisor exports bounded canonical snapshots to workers;
- workers apply freshness policy before installing canonical snapshot readers;
- `ThreatIntelPolicyContext` can be populated in the worker data-plane composition root;
- policy-composed lookup methods exist alongside raw compatibility APIs.

This pass should **not** start with enforcement. It should introduce shadow/observability consumers first, so the system can prove policy decisions are sane before proxy/WAF/YARA/WASM/routing consumers act on them.

## Core Principle

Policy-composed threat intel must be observable before it becomes authoritative enforcement.

The first consumers should answer:

```text
What would policy composition decide?
Why?
Was the decision actionable, advisory-only, deferred, or not-actionable?
Was canonical state missing, stale, expired, or unavailable?
Would existing raw lookup behavior have disagreed?
```

They should not block traffic or mutate enforcement state.

## Non-Goals

Do not change request blocking behavior.

Do not migrate proxy request evaluation.

Do not migrate WAF enforcement.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not remove raw lookup APIs.

Do not change threat-intel actionability semantics.

Do not introduce global canonical readers.

Do not use `StaticCanonicalTrustReader` in production.

Do not require canonical snapshots for worker startup.

## Desired Outcome

At the end of this pass, Synvoid should have a small, explicit **shadow consumer** for policy-composed threat intel.

A good first outcome:

1. policy-composed decision counters are emitted;
2. an internal diagnostic/admin view can ask for policy-composed status of an indicator;
3. raw and composed lookup disagreement can be logged or counted;
4. no traffic is blocked based on the new consumer;
5. docs state that policy-composed consumers are in shadow/observability mode only.

## Existing Surfaces To Inventory

Before implementation, inspect current APIs:

```bash
rg "evaluate_indicator_actionability_configured|lookup_.*policy_composed|ThreatIntelPolicyDecision|ThreatIntelPolicyContext|lookup_threat_indicator_in_dht|lookup_local_indicator|lookup_local_indicator_by_ip|ThreatIntelligenceManager|RequestServices|admin|diagnostic|metrics|observability" crates src architecture AGENTS.md
```

Key areas:

- `crates/synvoid-mesh/src/mesh/threat_intel.rs`;
- `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`;
- `src/worker/context.rs` / `RequestServices`;
- admin/status/metrics handlers;
- existing threat-intel health/status surfaces;
- WAF request path only for observing, not enforcing.

## Phase 1 — Define Consumer Classes

Create a short internal classification of possible consumers.

### Class A — Safe / Preferred For This Pass

These are allowed:

- metrics counters;
- structured logs;
- admin/debug endpoint;
- CLI/status diagnostic;
- health surface;
- shadow comparison with raw lookup;
- tests-only or diagnostic-only helpers.

### Class B — Design Only, No Implementation Yet

These may be documented but not migrated:

- request blocking decision;
- YARA/WASM callback decision;
- routing choice;
- bot/challenge decision;
- tarpit decision;
- DHT propagation decision;
- feed ingestion acceptance decision.

### Class C — Explicitly Out Of Scope

These must remain untouched:

- Raft consensus;
- canonical snapshot export;
- DHT ingress policy;
- peer auth;
- key policy;
- image/stego/image-protection paths.

### Acceptance Criteria

The implementation clearly selects Class A consumers only.

## Phase 2 — Add A Shadow Decision Record Type

Add a small DTO for reporting policy-composed decision status without exposing internal enum details everywhere.

Candidate location:

- `crates/synvoid-mesh/src/mesh/threat_intel.rs` if mesh-local;
- or main crate diagnostics module if admin/status owns it.

Candidate type:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelPolicyShadowDecision {
    pub indicator_value: String,
    pub threat_type: String,
    pub decision_class: ThreatIntelPolicyDecisionClass,
    pub reason: String,
    pub advisory_status: Option<String>,
    pub advisory_freshness: Option<String>,
    pub canonical_freshness: Option<String>,
    pub raw_lookup_present: Option<bool>,
    pub composed_actionable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIntelPolicyDecisionClass {
    Actionable,
    AdvisoryOnly,
    NotActionable,
    Deferred,
    NotConfigured,
    Error,
}
```

Rules:

- This type is for diagnostics/metrics, not enforcement.
- Do not leak signatures, full payloads, private keys, or raw record bodies.
- Use bounded strings.
- Avoid high-cardinality labels in metrics; high-cardinality values may appear only in logs/admin responses where already appropriate.

### Acceptance Criteria

There is one stable shadow-reporting shape for policy-composed decisions.

## Phase 3 — Add A Pure Mapping Helper

Add a helper that maps `ThreatIntelPolicyDecision` into the shadow DTO or into a compact decision class.

Candidate:

```rust
pub fn classify_threat_intel_policy_decision(
    decision: Option<&ThreatIntelPolicyDecision>,
) -> ThreatIntelPolicyDecisionClass
```

or:

```rust
pub fn threat_intel_policy_shadow_decision(
    indicator_value: &str,
    threat_type: ThreatType,
    decision: Option<ThreatIntelPolicyDecision>,
    raw_lookup_present: Option<bool>,
) -> ThreatIntelPolicyShadowDecision
```

Rules:

- `None` from `evaluate_indicator_actionability_configured` means `NotConfigured`.
- `Actionable(_)` maps to `Actionable`.
- `AdvisoryOnly(_)` maps to `AdvisoryOnly`.
- `NotActionable(reason)` maps to `NotActionable`.
- `Deferred(reason)` maps to `Deferred`.
- Preserve enough reason text to debug behavior.
- Helper must be pure and easily testable.

### Acceptance Criteria

Mapping from internal policy decision to shadow/diagnostic class is deterministic and covered by tests.

## Phase 4 — Add Metrics Counters

Add low-cardinality counters for policy-composed decisions.

Suggested counters:

```text
threat_intel_policy_shadow_decisions_total{decision_class}
threat_intel_policy_shadow_not_configured_total
threat_intel_policy_shadow_raw_disagreement_total{direction}
threat_intel_policy_shadow_canonical_unavailable_total
threat_intel_policy_shadow_advisory_missing_total
```

Do not put indicator value, IP, domain, signer, or node ID in metric labels.

If the metrics system does not support labels cleanly, use separate counters:

```text
threat_intel_policy_shadow_actionable_total
threat_intel_policy_shadow_advisory_only_total
threat_intel_policy_shadow_not_actionable_total
threat_intel_policy_shadow_deferred_total
threat_intel_policy_shadow_not_configured_total
```

### Acceptance Criteria

Policy-composed decisions can be counted by class without high-cardinality labels.

## Phase 5 — Add Shadow Evaluation Helper On ThreatIntelligenceManager

Add a helper that evaluates policy composition without changing enforcement behavior.

Candidate:

```rust
pub fn evaluate_indicator_policy_shadow(
    &self,
    indicator_value: &str,
    threat_type: ThreatType,
) -> ThreatIntelPolicyShadowDecision
```

Behavior:

1. call `evaluate_indicator_actionability_configured(...)`;
2. optionally run the existing raw lookup path relevant to the indicator source;
3. map to shadow DTO;
4. increment metrics;
5. return decision.

Important: do not make this helper decide blocking.

If raw lookup is expensive or async/incompatible, omit raw comparison in this pass and document as follow-up.

### Acceptance Criteria

There is a named shadow helper that can be called by observability/admin code without affecting enforcement.

## Phase 6 — Choose First Concrete Consumer

Choose exactly one or two safe consumers.

Preferred first consumer set:

### Consumer 1: Admin/diagnostic endpoint or status command

Add an internal diagnostic surface that can query one indicator:

```text
GET /admin/threat-intel/policy-shadow?indicator=...&type=ip_block
```

or CLI/status equivalent if admin HTTP is not in place.

Response should include:

- indicator value;
- threat type;
- decision class;
- reason;
- advisory freshness/status if available;
- canonical freshness if available;
- raw/composed comparison if implemented.

### Consumer 2: Passive metrics on existing feed/lookup path

If an existing periodic threat-intel feed/update path already iterates indicators, add shadow evaluation there only as metrics/logging. Do not block or change the feed result.

### Avoid For This Pass

Do not call shadow evaluation on every request unless it is purely sampled and explicitly non-enforcing. Per-request shadowing may create cost and cardinality problems.

### Acceptance Criteria

At least one safe consumer exists, and no enforcement behavior changes.

## Phase 7 — Raw vs Composed Comparison Strategy

If feasible, add a comparison mode.

Classify disagreement as:

```rust
pub enum ThreatIntelPolicyShadowDisagreement {
    RawPresentComposedNotActionable,
    RawMissingComposedActionable,
    RawPresentComposedDeferred,
    RawMissingComposedDeferred,
}
```

Rules:

- This is diagnostic only.
- Do not log every indicator at high volume by default.
- Count disagreements; sample detailed logs.
- Include reason/freshness in debug logs, not high-cardinality metrics labels.

### Acceptance Criteria

Operators can see whether composed policy would materially differ from raw lookup behavior.

## Phase 8 — Sampling And Cost Controls

Policy shadow evaluation can involve advisory/canonical reads. Keep it bounded.

Add one of:

- admin-only on-demand evaluation;
- periodic batch with cap;
- sampling ratio for passive path;
- feature/config flag disabled by default for hot paths.

Suggested config:

```toml
[mesh.threat_intel.policy_shadow]
enabled = true
sample_rate = 0.01
max_evaluations_per_interval = 1000
log_disagreements = true
```

If config expansion is too broad, make the first consumer admin-only and skip runtime config in this pass.

### Acceptance Criteria

Shadow evaluation cannot accidentally become an unbounded hot-path tax.

## Phase 9 — Tests

Required unit tests:

1. `Actionable` maps to `ThreatIntelPolicyDecisionClass::Actionable`;
2. `AdvisoryOnly` maps to `AdvisoryOnly`;
3. `NotActionable` maps to `NotActionable` with reason;
4. `Deferred` maps to `Deferred` with reason;
5. `None` maps to `NotConfigured`;
6. shadow DTO does not include raw payloads/signatures;
7. disagreement classifier maps raw/composed combinations correctly;
8. metrics helper does not use indicator value as label;
9. shadow helper does not mutate enforcement state.

Required integration-ish tests:

10. with populated `ThreatIntelPolicyContext`, shadow helper reports actionable for trusted canonical + advisory record;
11. without context, shadow helper reports not configured;
12. with stale/expired canonical snapshot behavior, shadow helper reports deferred/not-actionable according to freshness policy;
13. admin/diagnostic endpoint returns bounded response;
14. existing raw lookup APIs still work.

### Acceptance Criteria

Tests prove the consumer is observational, not enforcing.

## Phase 10 — Documentation

Update:

- `architecture/mesh_trust_domains.md`;
- `architecture/mesh.md` or `architecture/mesh_deep_dive.md` if they describe threat intel;
- `AGENTS.md` or `skills/synvoid_mesh.md` if they summarize current state;
- admin/API docs if a diagnostic endpoint is added.

Docs must state:

- policy-composed consumers are shadow/observability only;
- raw lookup APIs remain compatibility/diagnostic paths;
- no proxy/WAF/YARA/WASM/routing enforcement migration happened;
- decision classes and meanings;
- what `NotConfigured`, `Deferred`, and `NotActionable` mean operationally;
- how canonical freshness can affect shadow decisions;
- cost/sampling behavior.

### Acceptance Criteria

Docs make it impossible to mistake this pass for enforcement migration.

## Phase 11 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo check -p synvoid --features mesh
cargo test -p synvoid threat_intel --features mesh
cargo test -p synvoid admin --features mesh
cargo test -p synvoid metrics --features mesh
```

Then broad checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If package names differ, use actual names from `cargo metadata`.

## Completion Criteria

This pass is complete when:

- a safe Class A policy-composed consumer is selected and implemented;
- policy decisions are surfaced as metrics/admin diagnostics/shadow logs;
- no enforcement behavior changes;
- decision mapping is deterministic and tested;
- raw/composed disagreement is counted or explicitly deferred;
- cost controls are present or the consumer is admin-only;
- docs clearly state shadow-only status;
- focused tests pass or unrelated failures are documented.

## Follow-Up Recommendation

After shadow observability has real runtime data, create a separate design pass for the first enforcement-adjacent consumer.

Candidate progression:

1. Admin/status diagnostics.
2. Passive sampled request-path shadowing.
3. Advisory-only warning/logging.
4. Non-blocking score annotation.
5. Enforcement proposal only after metrics show low disagreement and stable canonical freshness.
