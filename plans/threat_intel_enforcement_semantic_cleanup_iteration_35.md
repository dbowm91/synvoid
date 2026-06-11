# Threat-Intel Enforcement Semantic Cleanup — Iteration 35

## Purpose

Iteration 34 successfully moved the main mesh threat-intel enforcement path from raw/advisory consumption to explicit consumer selection. `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`, strict policy-composed lookup wrappers, and the `handle_incoming_threat` enforcement gate are now present.

This follow-up pass should be intentionally narrow. Do not redesign the policy system. Do not add a new authority model. The goal is to clean up the semantic edge cases left by the enforcement migration so the codebase is harder to regress and the observability tells the truth.

The specific issues to address are:

1. `AsnBlock` still uses action-like language and attack metrics without checking the enforcement gate.
2. Suppression metrics currently over-report `not_configured` instead of classifying advisory-only, not-actionable, deferred, and missing-context cases separately.
3. `ThreatIntelDeferredMode` exists but is currently ignored by `classify_consumer_action`.
4. Private mutation helpers remain safe only because current call sites are gated; this needs local guardrails or tests.
5. Raw lookup/action-bearing consumer audit should be completed and documented.

## Current State

Relevant files:

- `crates/synvoid-mesh/src/mesh/threat_intel.rs`
  - Consumer selection enums and `classify_consumer_action` exist.
  - `handle_incoming_threat` evaluates `enforcement_action` before the threat-type match.
  - `IpBlock`, `RateLimitViolation`, `SuspiciousActivity`, and `IpThrottle` are gated before block/rate-limit mutation.
  - `AsnBlock` still logs `Applied mesh ASN block` and records `record_attack_type("AsnScraping")` without checking `enforcement_action`.
  - Strict lookup wrappers exist and do not fall back to raw lookup when policy context is missing.
  - Raw lookup wrappers are documented as not-for-enforcement.

- `crates/synvoid-mesh/src/stubs.rs`
  - Stub metrics exist for:
    - `record_threat_intel_enforcement_permitted`
    - `record_threat_intel_enforcement_suppressed_advisory_only`
    - `record_threat_intel_enforcement_suppressed_not_actionable`
    - `record_threat_intel_enforcement_suppressed_deferred`
    - `record_threat_intel_enforcement_suppressed_not_configured`
  - Current suppression call sites do not yet select the specific metric by policy decision class/reason.

## Non-Goals

Do not remove raw lookup APIs in this pass.

Do not change the DHT key format, canonical snapshot format, supervisor IPC message format, or Raft/DHT ownership model.

Do not move large sections of `threat_intel.rs` unless required for compilation. A future modularization pass can split the file once semantics are stable.

Do not introduce async/network lookups into the request or enforcement hot path.

Do not alter local-origin honeypot/local-block behavior unless a test reveals it accidentally bypasses the intended local/remote distinction.

## Phase 1 — Fix `AsnBlock` Semantics

Inspect the `ThreatType::AsnBlock` branch in `ThreatIntelligenceManager::handle_incoming_threat`.

Decide which of these is true in the current codebase:

1. ASN block is only observational/stub behavior today.
2. ASN block is intended to be enforcement or future enforcement.

If it is observational/stub behavior:

- Change the log line from action-bearing language such as `Applied mesh ASN block` to explicit observational language, for example:
  - `Received mesh ASN block advisory; ASN enforcement is not wired in this path`
- Do not record an attack/enforcement metric that implies local enforcement occurred.
- If a metric is still useful, add/use a shadow/advisory metric rather than an enforcement-style metric.
- Add a comment explaining that no enforcement mutation occurs in this branch.

If it is intended to be enforcement:

- Gate it using the same `enforcement_action == ThreatIntelConsumerAction::PermitAction` check used by IP block/rate-limit/suspicious/IP throttle.
- Suppress action and record suppression metrics when not permitted.
- Add a regression test showing advisory-only or no-policy-context ASN indicators do not produce enforcement-side effects.

Preferred path for this pass: treat it as observational unless there is already a real ASN block store or WAF integration. The current branch appears to log and record only, so the safest cleanup is to stop saying it was applied.

## Phase 2 — Add a Suppression Metric Classifier

The current gated branches call `record_threat_intel_enforcement_suppressed_not_configured()` for all suppressed actions. That hides the actual reason for suppression.

Add a helper near `evaluate_incoming_threat_policy`, for example:

```rust
fn record_enforcement_suppression_metric(
    decision: Option<&crate::threat_intel_policy::ThreatIntelPolicyDecision>,
) {
    match decision {
        None => crate::stubs::metrics::record_threat_intel_enforcement_suppressed_not_configured(),
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::AdvisoryOnly(_)) => {
            crate::stubs::metrics::record_threat_intel_enforcement_suppressed_advisory_only();
        }
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::NotActionable(_)) => {
            crate::stubs::metrics::record_threat_intel_enforcement_suppressed_not_actionable();
        }
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::Deferred(_)) => {
            crate::stubs::metrics::record_threat_intel_enforcement_suppressed_deferred();
        }
        Some(crate::threat_intel_policy::ThreatIntelPolicyDecision::Actionable(_)) => {
            // Do not record suppression for permitted decisions.
        }
    }
}
```

Then adjust `evaluate_incoming_threat_policy` so callers can use both the action and the underlying decision. A clean option is to add a small result struct:

```rust
#[derive(Debug, Clone)]
struct IncomingThreatPolicyGate {
    action: ThreatIntelConsumerAction,
    decision: Option<crate::threat_intel_policy::ThreatIntelPolicyDecision>,
}
```

Alternatively, return a tuple:

```rust
(ThreatIntelConsumerAction, Option<ThreatIntelPolicyDecision>)
```

Prefer the struct if it keeps call sites readable.

Every suppressed enforcement branch should record the correct suppression metric based on the actual decision. Keep metric labels out of this; these are low-cardinality counters.

## Phase 3 — Make `ThreatIntelDeferredMode` Either Meaningful or Explicitly Inert

`classify_consumer_action` currently accepts `_deferred_mode` and ignores it. That is acceptable from a safety perspective because all deferred cases suppress action, but it is semantically unfinished.

Choose one of two options.

Option A, preferred: make the enum meaningful for observability but not permissive.

- `FailOpenNoAction`: suppress action; record/log as fail-open no-action/deferred.
- `FailClosedNoAction`: suppress action; record/log as fail-closed no-action/deferred.
- `ShadowOnly`: return `ShadowOnly` for deferred/missing context decisions.

Do not make any deferred mode permit enforcement in this pass.

Option B: remove the parameter from `classify_consumer_action` and document that all deferred/missing-context cases suppress action for now.

Option A is preferable because the stale snapshot policy already has meaningful names, and preserving the mode in the gate helps future config plumbing. The key is to avoid a misleading unused argument.

Add tests for all deferred modes, even if the action result remains suppression. The tests should encode the intended semantics so a later change cannot silently turn deferred into permit.

## Phase 4 — Guard Private Mutation Helpers

The private helpers `apply_rate_limit_mesh_action` and `apply_suspicious_mesh_action` still mutate the block store directly. They are currently safe because `handle_incoming_threat` calls them only after `PermitAction`, but that protection is implicit.

Add one of these guardrails:

Option A: rename helpers to make precondition explicit.

Examples:

- `apply_rate_limit_mesh_action_after_policy_permit`
- `apply_suspicious_mesh_action_after_policy_permit`

Add Rustdoc or comments:

```rust
// PRECONDITION: caller has verified ThreatIntelConsumerAction::PermitAction.
```

Option B: pass `ThreatIntelConsumerAction` into the helpers and have them return early unless it is `PermitAction`.

Option B is safer but noisier. Option A is acceptable if tests prove the only call sites are gated.

Add tests or source-level assertions where practical:

- advisory-only rate-limit does not mutate block store;
- advisory-only suspicious activity does not mutate block store;
- no-policy-context rate-limit does not mutate block store;
- no-policy-context suspicious activity does not mutate block store.

## Phase 5 — Complete Raw Consumer Audit

Run repository searches and inspect each non-test result:

- `lookup_threat_indicator_in_dht`
- `lookup_local_indicator(`
- `lookup_local_indicator_by_ip`
- `lookup_threat_indicator_policy_composed`
- `lookup_local_indicator_policy_composed`
- `lookup_threat_indicator_policy_strict`
- `lookup_local_indicator_policy_strict`
- `handle_incoming_threat(`
- `apply_sync(`
- `block_ip(` inside threat-intel paths
- `record_attack_type(` inside threat-intel paths
- `HotThreatGossip`

For every raw lookup use, classify it as one of:

- test only;
- raw compatibility/debug;
- shadow/observability;
- advisory cache/bookkeeping;
- enforcement/actionability-sensitive.

If it is enforcement/actionability-sensitive, migrate it to a strict policy-composed lookup or the consumer gate.

Add a short audit note either in this plan file after completion, in `docs/THREAT_INTEL.md`, or as a new lightweight doc under `architecture/`. Do not over-document; a concise table is enough.

## Phase 6 — Documentation Cleanup

Update docs only where semantics changed.

Required updates:

- `docs/THREAT_INTEL.md`
  - Clarify that `AsnBlock` is observational unless real ASN enforcement is wired.
  - Clarify strict vs compatibility lookup APIs.
  - State that enforcement suppression metrics distinguish advisory-only, not-actionable, deferred, and not-configured cases.

- `architecture/mesh_trust_domains.md`
  - Add or update the consumer-selection rule:
    - advisory DHT record = observation;
    - canonical trust = authority;
    - consumer gate = actionability selector;
    - enforcement mutation requires `PermitAction`.

- Rustdoc in `threat_intel.rs`
  - Update `classify_consumer_action` documentation after deferred-mode behavior is fixed.
  - Add precondition docs for private mutation helpers if using the rename/comment approach.

## Phase 7 — Tests

Add or adjust tests for the cleanup items.

Required tests:

1. `AsnBlock` without canonical actionability does not record/apply enforcement semantics. If no observable side effect exists, at minimum verify it does not call block-store mutation and document the branch as observational.
2. Suppressed `IpBlock` due to no policy context records the not-configured suppression path.
3. Suppressed `IpBlock` due to advisory-only records advisory-only suppression path.
4. Suppressed `IpBlock` due to canonical not-actionable records not-actionable suppression path.
5. Suppressed `IpBlock` due to canonical unavailable/deferred records deferred suppression path.
6. Deferred-mode tests cover every `ThreatIntelDeferredMode` variant.
7. Private helper precondition tests for rate-limit and suspicious activity suppression.
8. Strict lookups still return `None` when no policy context exists.
9. Compatibility/raw lookups still return raw records where expected.
10. Hot-threat gossip and `apply_sync` still inherit the gated behavior through `handle_incoming_threat`.

If metrics are hard to assert because they are stubs, use one of these approaches:

- add test-only counters behind `#[cfg(test)]`;
- expose a small classifier helper that maps a decision to a suppression enum and test that helper;
- assert behavior through block-store mutation/non-mutation and keep metric call-site review manual.

Prefer testing the classifier helper; it avoids making stubs stateful.

## Acceptance Criteria

This pass is complete when:

1. `AsnBlock` no longer implies enforcement unless it is actually gated and enforced.
2. Suppression metrics are classified by actual policy outcome rather than all mapping to not-configured.
3. `ThreatIntelDeferredMode` is no longer an ignored parameter, or it is deliberately removed with docs updated.
4. Private mutation helpers cannot be easily reused as policy bypasses.
5. Raw lookup uses have been audited and any actionability-sensitive use has been migrated.
6. Docs and Rustdoc match the final behavior.
7. Tests cover suppression reason classification, deferred modes, strict lookup behavior, and gated mutation behavior.
8. No broad architectural churn is introduced.

## Suggested Implementation Order

1. Fix or relabel `AsnBlock` behavior.
2. Add a suppression-reason classifier and tests.
3. Thread the classifier through suppressed enforcement branches.
4. Resolve the unused `ThreatIntelDeferredMode` parameter.
5. Rename or guard private mutation helpers.
6. Run the raw-consumer audit and migrate any remaining actionability-sensitive call sites.
7. Update docs/Rustdoc.
8. Run focused `synvoid-mesh` tests, then broader mesh-feature tests.

## Notes for the Implementer

Keep the safety invariant simple: remote/advisory mesh threat-intel can be observed, stored, and compared, but it cannot mutate enforcement state unless canonical trust and the consumer gate both permit action.

Avoid adding configuration in this pass unless a test requires it. The current hard default — deferred and missing-context suppress action — is conservative and acceptable. The cleanup should improve clarity and observability, not reopen the enforcement bypass that Iteration 34 closed.
