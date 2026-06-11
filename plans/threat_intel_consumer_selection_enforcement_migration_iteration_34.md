# Threat-Intel Consumer Selection and Enforcement Migration — Iteration 34

## Purpose

This handoff plan covers the next architectural pass after the policy-composed threat-intel core, worker/data-plane composition root, canonical freshness policy, and shadow diagnostics are in place.

The repository is now in the correct intermediate state: advisory DHT observations and canonical Raft-derived trust are separated; `ThreatIntelPolicyContext` can be injected into `ThreatIntelligenceManager`; worker bootstrap and IPC snapshot refresh can build and apply that context; policy-composed local/DHT lookup wrappers exist; and shadow diagnostics can compare raw and composed decisions. The remaining architectural problem is consumer selection: several action-bearing consumers can still apply mesh threat-intel directly through legacy/raw paths, especially `handle_incoming_threat`, `apply_sync`, and hot-threat gossip.

The goal of this pass is to make actionability an explicit consumer policy. Observability-only consumers may remain shadow-only. Compatibility/debug consumers may still use raw lookup APIs. Enforcement consumers must go through one policy-composed gate before mutating WAF/block/rate-limit state.

## Current State

The relevant current pieces are:

- `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`
  - Pure advisory + canonical policy evaluator.
  - Decision model: `Actionable`, `AdvisoryOnly`, `NotActionable`, `Deferred`.
  - Shadow DTO and disagreement classifier.

- `crates/synvoid-mesh/src/mesh/threat_intel.rs`
  - `ThreatIntelPolicyContext` with `CanonicalTrustReader` + `AdvisoryRecordSource`.
  - `ThreatIntelligenceManager::set_policy_context`.
  - `evaluate_indicator_actionability` and `evaluate_indicator_actionability_configured`.
  - `lookup_threat_indicator_policy_composed`.
  - `lookup_local_indicator_policy_composed`.
  - `lookup_local_indicator_by_ip_policy_composed`.
  - `evaluate_indicator_policy_shadow`.
  - Legacy/raw lookup APIs still available.
  - `handle_incoming_threat` still applies enforcement directly after signature/reputation/TTL checks.

- `src/worker/unified_server/services.rs`
  - `DataPlaneServices` owns the worker-side policy context and explicit record-store handle.
  - `DataPlaneServicesBuilder::build_threat_intel_policy_context` only returns a context when both canonical and advisory handles exist.
  - `apply_threat_intel_policy_context` and `update_threat_intel_policy_context` apply or clear the manager context.

- `src/worker/unified_server/mod.rs`
  - Worker bootstrap derives advisory source from the explicit record store.
  - Worker bootstrap derives canonical reader from supervisor-exported canonical snapshot when present.
  - Worker bootstrap applies the initial policy context to the threat-intel manager.

- `src/worker/unified_server/lifecycle.rs`
  - IPC snapshot updates classify canonical freshness using configured policy.
  - Fresh snapshots apply a freshness-bound canonical reader.
  - Stale snapshots follow configured `allow_stale_with_warning`, `fail_open_defer`, or `fail_closed_not_actionable` behavior.
  - Expired/invalid/missing snapshots clear the policy context.

## Target Architecture

After this pass, threat-intel consumers should be classified into one of four modes:

1. **Raw compatibility/debug consumers**
   - May call raw lookup APIs.
   - Must not mutate enforcement state.
   - Must be clearly documented as compatibility or diagnostics.

2. **Shadow-only consumers**
   - Evaluate policy and emit metrics/logs/admin DTOs.
   - Must not block, rate-limit, or otherwise mutate enforcement state.
   - Used to compare raw and composed behavior before enforcement migration.

3. **Fail-open advisory consumers**
   - May continue non-security-critical behavior when canonical context is absent.
   - Must not apply hard security enforcement based only on advisory DHT records.
   - Acceptable for diagnostics, sync bookkeeping, cache warming, or non-actioning local state.

4. **Enforcement consumers**
   - Must use policy-composed actionability before mutating block stores, rate limit state, WAF deny lists, or equivalent controls.
   - `Actionable` permits the action.
   - `AdvisoryOnly` must not act.
   - `NotActionable` must not act.
   - `Deferred` must follow an explicit mode, not accidental legacy fallback.

The important invariant is: **an advisory DHT record alone must never cause enforcement mutation.** Canonical trust is required for action-bearing threat-intel consumption.

## Non-Goals

Do not redesign the DHT, Raft, record-store format, or supervisor snapshot format in this pass.

Do not remove legacy/raw APIs yet. They are useful for compatibility, diagnostics, migration tests, and admin tooling. Instead, rename/comment them more explicitly if needed and ensure enforcement paths do not depend on them directly.

Do not add new network protocols or persistence layers.

Do not make request-path behavior depend on async network fetches. The policy gate must use existing local/snapshot/advisory seams and remain synchronous or locally available in the hot path.

## Phase 1 — Add an Explicit Consumer Decision/Gate Type

Create a small policy consumer gate in `crates/synvoid-mesh/src/mesh/threat_intel.rs` or a new adjacent module such as `threat_intel_consumer.rs` if the file is becoming too large.

Suggested types:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelConsumerKind {
    ShadowOnly,
    RawCompatibility,
    AdvisoryCache,
    Enforcement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelDeferredMode {
    FailOpenNoAction,
    FailClosedNoAction,
    ShadowOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelConsumerAction {
    PermitAction,
    SuppressAction,
    ShadowOnly,
    RawCompatibilityOnly,
}
```

The exact naming can differ, but the gate should make consumer intent explicit. Avoid a vague boolean like `is_actionable`. The code should encode why the consumer is allowed or suppressed.

Add a method along these lines:

```rust
pub fn classify_consumer_action(
    decision: Option<&ThreatIntelPolicyDecision>,
    consumer: ThreatIntelConsumerKind,
    deferred_mode: ThreatIntelDeferredMode,
) -> ThreatIntelConsumerAction
```

Recommended semantics:

- `ShadowOnly` always returns `ShadowOnly`.
- `RawCompatibility` returns `RawCompatibilityOnly` and must not be used by enforcement code.
- `Enforcement + Some(Actionable)` returns `PermitAction`.
- `Enforcement + Some(AdvisoryOnly | NotActionable)` returns `SuppressAction`.
- `Enforcement + Some(Deferred(_))` returns `SuppressAction` unless a deliberately named mode says otherwise. Prefer no-action for now.
- `Enforcement + None` returns `SuppressAction` by default for action-bearing mesh-sourced indicators. This is the critical shift away from legacy raw fallback for enforcement.
- `AdvisoryCache` may permit local non-enforcement storage/bookkeeping, but not WAF/block-store mutation.

Add tests that cover every matrix row that is security relevant.

## Phase 2 — Split Enforcement from Storage/Bookkeeping in `handle_incoming_threat`

`handle_incoming_threat` currently performs several responsibilities in one method:

- signature verification;
- peer reputation acceptance;
- TTL/expiration checks;
- duplicate checks;
- global-node self-protection checks;
- enforcement mutation, such as block-store updates and rate-limit/suspicious actions;
- local indicator insertion;
- reputation accepted/rejected accounting.

Refactor this without changing external behavior more than necessary.

Suggested internal structure:

```rust
fn validate_incoming_threat_envelope(...) -> Result<(), IncomingThreatRejectReason>
fn should_store_incoming_indicator(...) -> bool
fn evaluate_incoming_threat_policy(...) -> ThreatIntelConsumerAction
fn apply_incoming_threat_enforcement_if_permitted(...) -> bool
fn store_incoming_indicator(...) 
```

A lighter approach is also acceptable if it keeps the diff contained: add one policy gate call immediately before each enforcement mutation branch, then extract later. The key is that block-store/rate-limit/suspicious mutations no longer happen unless policy permits action.

Important rule: local storage/sync bookkeeping can remain more permissive than enforcement, but it must be clearly separated. It is acceptable to remember an advisory indicator locally for diagnostics or future comparison. It is not acceptable to block/rate-limit based on it without canonical actionability.

## Phase 3 — Migrate Action-Bearing Mesh Consumers

Update the following consumers first:

1. `ThreatIntelligenceManager::handle_incoming_threat`
   - Before applying `IpBlock`, `RateLimitViolation`, `SuspiciousActivity`, `IpThrottle`, and future action-bearing variants, evaluate configured policy.
   - If no policy context exists, suppress enforcement for mesh-sourced threat-intel by default.
   - Continue to return a meaningful boolean. Prefer returning `true` only when the message was accepted for storage/bookkeeping, not necessarily when enforcement happened; if ambiguous, add tracing fields that distinguish `stored=true` from `enforced=false`.

2. `ThreatIntelligenceManager::apply_sync`
   - Since it delegates to `handle_incoming_threat`, ensure sync cannot bypass the policy gate.
   - Add regression tests showing synced advisory-only indicators do not block.

3. `ThreatIntelligenceManager::handle_hot_threat_gossip`
   - Hot gossip currently routes immediate indicators into `handle_incoming_threat`; after `handle_incoming_threat` is gated, this should inherit the protection.
   - Add a focused test or at least assert by code structure that hot gossip cannot apply enforcement directly.

4. Any request-path or WAF-path lookup consumers
   - Search for raw `lookup_local_indicator`, `lookup_local_indicator_by_ip`, and `lookup_threat_indicator_in_dht` use outside diagnostics/tests.
   - For request/actionability-sensitive paths, replace with `lookup_local_indicator_policy_composed`, `lookup_local_indicator_by_ip_policy_composed`, or `lookup_threat_indicator_policy_composed`.
   - Leave admin/debug views raw if they are explicitly labeled raw.

5. Honeypot/local-origin flows
   - Be careful not to over-constrain local-origin enforcement. Local honeypot detections may still apply local controls based on local evidence.
   - The policy-composed requirement is specifically for mesh/advisory consumption, not for first-party local detections.
   - Add comments or type distinctions so future maintainers do not accidentally route local-origin actions through remote advisory policy.

## Phase 4 — Make Missing Policy Context Explicit

Current policy-composed lookup wrappers fall back to raw lookups when no policy context is configured. That is acceptable for compatibility lookup APIs, but not for enforcement.

Add separate APIs or arguments so call sites cannot accidentally choose raw fallback:

Option A: add strict wrappers:

```rust
pub fn lookup_threat_indicator_policy_strict(... ) -> Option<ThreatIndicator>
pub fn lookup_local_indicator_policy_strict(... ) -> Option<ThreatIndicator>
```

Strict behavior:

- `Some(Actionable)` returns raw indicator.
- `Some(non-actionable)` returns `None`.
- `None` policy context returns `None`.

Option B: add an enum argument:

```rust
pub enum MissingPolicyContextMode {
    LegacyRawFallback,
    SuppressAction,
}
```

Prefer Option A if the call sites are clearer with separate names. Avoid hidden boolean parameters.

Then update enforcement consumers to use strict behavior only.

## Phase 5 — Preserve and Expand Shadow Metrics

Keep `evaluate_indicator_policy_shadow` as an observability-only method. Add metrics/tracing where enforcement is suppressed by policy so operators can see the rollout impact.

At minimum, record or trace:

- `policy_action_permitted`;
- `policy_action_suppressed_advisory_only`;
- `policy_action_suppressed_not_actionable`;
- `policy_action_suppressed_deferred`;
- `policy_action_suppressed_not_configured`;
- raw/composed disagreement when raw indicator is present but composed action is suppressed.

If adding real metrics is too broad because metrics are currently stubbed, add stub methods in `crates/synvoid-mesh/src/stubs.rs` or the existing metrics stub location, then call them from the gate. Keep label cardinality low: decision class, consumer kind, and reason enum are acceptable; raw indicator values are not acceptable as metric labels.

## Phase 6 — Tests

Add unit tests in `crates/synvoid-mesh/src/mesh/threat_intel.rs` and/or the new consumer module.

Required tests:

1. Advisory present + canonical trusted permits enforcement.
2. Advisory present + canonical unknown suppresses enforcement.
3. Advisory present + canonical unavailable suppresses enforcement.
4. Advisory missing suppresses enforcement.
5. Advisory expired suppresses enforcement.
6. Canonical explicitly not trusted suppresses enforcement.
7. Missing policy context suppresses strict enforcement.
8. Missing policy context still allows explicitly raw compatibility lookup, if raw lookup API is called directly.
9. `apply_sync` cannot bypass the same gate.
10. Hot-threat gossip cannot bypass the same gate.
11. Local-origin honeypot/local block behavior remains allowed where appropriate.
12. Stale snapshot with `AllowStaleWithWarning` can permit action if the canonical snapshot says trusted.
13. Stale snapshot with `FailOpenDefer` suppresses enforcement.
14. Stale snapshot with `FailClosedNotActionable` suppresses enforcement unless the intended implementation maps it to explicit not-actionable rejection.
15. Expired/invalid snapshot suppresses enforcement.

Add one regression test that constructs a manager with a raw local/DHT indicator but no canonical trust, then verifies the block store is not mutated by the migrated enforcement path.

If the concrete `BlockStoreApi` makes mutation assertions awkward, add a minimal test double implementing the trait and recording calls.

## Phase 7 — Documentation and Naming Cleanup

Update the following docs after implementation:

- `docs/THREAT_INTEL.md`
- `docs/WAF_MESH.md`
- `architecture/mesh_trust_domains.md`
- `architecture/mesh_deep_dive.md` if it describes DHT/Raft threat-intel consumption
- `AGENTS.md` or relevant skill docs if they instruct agents to use raw threat-intel APIs

Document the final rule plainly:

> DHT threat-intel records are advisory. Canonical Raft-derived trust decides whether advisory records may become enforcement. Raw lookup APIs are compatibility/debug surfaces and must not be used for action-bearing request or mesh consumers.

Also annotate raw methods in Rustdoc:

- `lookup_threat_indicator_in_dht`
- `lookup_local_indicator`
- `lookup_local_indicator_by_ip`

Their docs should say: **not for enforcement** unless wrapped by an explicit policy-composed gate.

## Phase 8 — Search/Review Checklist

Before considering this pass complete, run repository searches for these symbols and inspect every non-test use:

- `lookup_threat_indicator_in_dht`
- `lookup_local_indicator(`
- `lookup_local_indicator_by_ip`
- `handle_incoming_threat(`
- `apply_sync(`
- `block_ip(` inside `threat_intel.rs`
- `apply_rate_limit_mesh_action`
- `apply_suspicious_mesh_action`
- `HotThreatGossip`
- `evaluate_indicator_actionability_configured`
- `evaluate_indicator_policy_shadow`

For each use, classify it as:

- raw compatibility/debug;
- shadow-only;
- advisory cache/bookkeeping;
- enforcement.

If it is enforcement, it must go through strict policy actionability.

## Acceptance Criteria

This pass is complete when:

1. There is a single explicit consumer-selection/gating abstraction for threat-intel actionability.
2. Mesh-sourced enforcement mutations cannot occur from advisory-only DHT records.
3. Missing policy context does not silently fall back to raw lookup for enforcement.
4. Local-origin detections are not accidentally broken by remote/advisory policy requirements.
5. `handle_incoming_threat`, `apply_sync`, and hot-threat gossip all share the same enforcement gate.
6. Raw lookup APIs remain available but are documented as compatibility/debug surfaces.
7. Shadow diagnostics continue to work and record raw/composed disagreement.
8. Tests cover canonical trusted, unknown, unavailable, missing, stale, expired, and no-policy-context cases.
9. Docs describe the advisory/canonical/enforcement distinction consistently.

## Suggested Implementation Order

1. Add the consumer gate type and tests without touching call sites.
2. Add strict policy-composed lookup wrappers or a named missing-context mode.
3. Migrate `handle_incoming_threat` enforcement branches to the gate.
4. Verify `apply_sync` and hot gossip inherit the gate.
5. Search and migrate request/WAF lookup consumers.
6. Add suppression metrics/tracing.
7. Update docs and Rustdoc.
8. Run focused tests for `synvoid-mesh` and worker service composition.
9. Run broader mesh-feature test coverage if available.

## Notes for the Implementer

Keep the diff conservative. The architecture is now close to the desired shape; avoid another broad abstraction pass. The main thing is to prevent accidental action through raw/advisory paths.

Prefer explicit names over clever generality. `StrictPolicyComposed`, `SuppressAction`, and `RawCompatibilityOnly` are clearer than booleans or overloaded `Option` behavior.

Do not delete raw APIs yet. The next cleanup pass can remove or further isolate them once all enforcement consumers have been migrated and shadow metrics look acceptable.
