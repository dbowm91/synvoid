# Mesh Threat Intel Policy Composition — Iteration 18

## Goal

Introduce the first small policy-composition helper that consumes both mesh trust-domain seams:

```rust
&dyn CanonicalTrustReader
&dyn AdvisoryRecordSource
```

Use threat intel as the first narrow domain because it already has an explicit canonical dimension (`CanonicalTrustReader::is_threat_intel_canonical`) and an advisory DHT dimension (`AdvisoryRecordSource` records under threat-intel keys).

This pass should create policy output types and deterministic helper-level tests only. Do not migrate `threat_intel.rs` or any service consumer yet.

## Core Invariant

Advisory source answers: "what has been advertised?"

Canonical source answers: "what is trusted?"

Policy composition answers: "what may be acted on?"

This pass should be the first code layer that composes advisory + canonical inputs into explicit policy results.

## Non-Goals

Do not migrate `threat_intel.rs` production consumers.

Do not migrate `proxy.rs`, YARA/WASM, route/proxy metadata, or any service consumer.

Do not change DHT ingestion, Push/Announce canonical gating, record-store behavior, sync, anti-entropy, quorum, or Raft apply behavior.

Do not alter `CanonicalTrustReader` semantics.

Do not alter `AdvisoryRecordSource` semantics.

Do not add networking, live DHT, or live Raft tests.

Do not parse every threat-intel payload schema unless a minimal identifier extraction helper already exists.

## Phase 1 — Inventory Threat Intel Keys And Existing Semantics

Inspect existing threat-intel code and key shapes before adding policy helper types.

Run:

```bash
rg "ThreatIndicator|threat_intel|ThreatIntel|is_threat_intel_canonical|AdvisoryRecordSource|DhtKey::Threat|DhtKey::from_str|threat:" crates/synvoid-mesh/src src crates/synvoid-* architecture docs
```

Read at minimum:

- `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`
- `crates/synvoid-mesh/src/mesh/canonical.rs`
- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`
- existing `threat_intel.rs` files or modules
- relevant DHT key parsing in `crates/synvoid-mesh/src/mesh/dht/keys.rs`

Identify:

1. the canonical threat-intel ID format used by `CanonicalTrustReader`;
2. the advisory DHT key format for threat-intel records;
3. whether payload decoding is necessary for this helper or whether key-level policy is enough;
4. whether missing advisory record and missing canonical state should be separate outcomes.

### Acceptance Criteria

The helper's chosen key/ID convention is documented in code comments.

No service consumer is changed during inventory.

## Phase 2 — Add Policy Composition Module

Add a small module close to policy boundaries.

Preferred location:

```text
crates/synvoid-mesh/src/mesh/policy/threat_intel.rs
```

If there is no `mesh/policy` module yet and adding one would create churn, use:

```text
crates/synvoid-mesh/src/mesh/threat_intel_policy.rs
```

or:

```text
crates/synvoid-mesh/src/mesh/dht/threat_intel_policy.rs
```

Choose the lowest-cycle location, but name it as policy composition, not advisory or canonical.

### Acceptance Criteria

The module is explicitly policy/composition, not advisory source or canonical reader internals.

It imports both traits but does not own either implementation.

## Phase 3 — Define Threat Intel Policy Output Types

Define explicit policy results.

Suggested shape:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatIntelPolicyDecision {
    Actionable(ThreatIntelPolicyEvidence),
    AdvisoryOnly(ThreatIntelPolicyEvidence),
    NotActionable(ThreatIntelPolicyRejectReason),
    Deferred(ThreatIntelPolicyDeferReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatIntelPolicyEvidence {
    pub intel_id: String,
    pub advisory_key: String,
    pub advisory_status: AdvisoryRecordStatus,
    pub advisory_freshness: AdvisoryFreshness,
    pub canonical_freshness: CanonicalFreshness,
    pub record_signature_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatIntelPolicyRejectReason {
    AdvisoryMissing,
    AdvisoryExpired,
    CanonicalNotTrusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatIntelPolicyDeferReason {
    AdvisoryUnavailable,
    CanonicalUnavailable,
    CanonicalUnknown,
}
```

Adapt exact names and fields based on existing type names.

### Rules

- `Actionable` requires both advisory presence and canonical trust.
- `AdvisoryOnly` may exist if you want to preserve a safe observation state, but it must not be used as actionable security policy.
- `NotActionable` must distinguish missing advisory from canonical rejection where possible.
- `Deferred` must distinguish unavailable/unknown canonical state from advisory unavailability.
- Include freshness in evidence so callers can later apply stricter freshness policy.

### Acceptance Criteria

Policy output makes actionability explicit.

No output type implies that advisory presence alone is trust.

## Phase 4 — Implement A Pure Helper Function

Add a pure helper that composes both seams.

Suggested shape:

```rust
pub fn evaluate_threat_intel_policy(
    canonical: &dyn CanonicalTrustReader,
    advisory: &dyn AdvisoryRecordSource,
    intel_id: &str,
    advisory_key: &str,
) -> ThreatIntelPolicyDecision {
    // 1. read advisory record
    // 2. read canonical trust for intel_id
    // 3. compose into explicit decision
}
```

Potential behavior:

1. Advisory `Unavailable` => `Deferred(AdvisoryUnavailable)`.
2. Advisory `Missing` => `NotActionable(AdvisoryMissing)`.
3. Advisory `Expired` => `NotActionable(AdvisoryExpired)`.
4. Advisory `Present` + canonical `Trusted` => `Actionable(evidence)`.
5. Advisory `Present` + canonical `NotTrusted` => `NotActionable(CanonicalNotTrusted)`.
6. Advisory `Present` + canonical `Unknown` => `Deferred(CanonicalUnknown)`.
7. Advisory `Present` + canonical unavailable reason/freshness => `Deferred(CanonicalUnavailable)`.

### Rules

- Do not fetch from DHT directly.
- Do not fetch from Raft directly.
- Do not inspect `RecordStoreManager` directly.
- Do not use `RECORD_STORE_GLOBAL`.
- Do not mutate anything.
- Do not decode service-specific payloads unless absolutely necessary.
- Do not silently treat canonical unavailable/unknown as actionable.

### Acceptance Criteria

Helper is deterministic and testable with `StaticCanonicalTrustReader` + `StaticAdvisoryRecordSource`.

## Phase 5 — Add Focused Unit Tests

Use static/offline sources only.

Required tests:

1. Advisory present + canonical trusted => `Actionable`.
2. Advisory missing + canonical trusted => `NotActionable(AdvisoryMissing)`.
3. Advisory expired + canonical trusted => `NotActionable(AdvisoryExpired)`.
4. Advisory unavailable => `Deferred(AdvisoryUnavailable)`.
5. Advisory present + canonical not trusted => `NotActionable(CanonicalNotTrusted)`.
6. Advisory present + canonical unknown => `Deferred(CanonicalUnknown)`.
7. Advisory present + canonical unavailable => `Deferred(CanonicalUnavailable)`.
8. Evidence includes advisory freshness and canonical freshness.
9. Record signature validity is carried as evidence but does not by itself produce canonical trust.
10. No DHT/Raft/networking required.

### Acceptance Criteria

All policy outcomes are tested.

Tests show advisory-only data is not actionable without canonical trust.

## Phase 6 — Export Surface

Export the helper/types minimally.

If a `mesh/policy` module is added:

```rust
pub mod policy;
```

and inside it:

```rust
pub mod threat_intel;
pub use threat_intel::{...};
```

If added directly under mesh, re-export only if future callers need it.

### Acceptance Criteria

Future service migration can import the helper without deep internal paths.

No broad public API churn.

## Phase 7 — Architecture Note Update

Update `architecture/mesh_trust_domains.md`.

Suggested text:

```markdown
### Iteration 18 Threat Intel Policy Composition

A small threat-intel policy helper now composes `CanonicalTrustReader` with `AdvisoryRecordSource`. Advisory records provide observations; canonical state provides trust; the helper returns explicit actionability, rejection, or defer decisions. Tests cover present/missing/expired/unavailable advisory records and trusted/not-trusted/unknown/unavailable canonical state. No service consumers were migrated in this pass.
```

Follow-up should say:

```markdown
Next: migrate a single low-risk threat-intel consumer to consume the policy output, keeping the old path available for comparison/tests.
```

### Acceptance Criteria

Docs clearly distinguish composition helper from service migration.

## Phase 8 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
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

If broader checks fail for unrelated reasons, document focused checks and exact unrelated failure.

## Completion Criteria

This iteration is complete when:

- a threat-intel policy composition helper exists;
- helper consumes `&dyn CanonicalTrustReader` and `&dyn AdvisoryRecordSource`;
- all decisions are explicit: actionable, not actionable, deferred;
- tests cover advisory and canonical combinations;
- no service consumers are migrated;
- no raw DHT/Raft access is introduced;
- no mutation behavior changes;
- architecture docs record the composition layer and next migration step.

## Follow-Up Recommendation

After this helper is stable, migrate exactly one low-risk threat-intel consumer to use the policy output. Keep the old/raw path in tests or behind a comparison helper until behavior is validated. Do not migrate proxy, YARA/WASM, or route policy in the same pass.
