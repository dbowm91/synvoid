# Threat-Intel Consumer Actionability Audit — Iteration 54

## Purpose

The blocklist plane is now stable enough to leave alone: target model, propagation, offline catchup, provenance, request-path boundaries, and restart-safe stale replay protection are coherent. The next high-leverage target is upstream: threat-intel consumer/actionability correctness.

This pass should audit every threat-intel consumer and ensure enforcement-sensitive paths cannot bypass policy-composed actionability. Raw threat-intel lookups may remain for diagnostics/compatibility, but must not be reachable from action-bearing consumers that block, ban, escalate, emit blocklist events, or mutate trust state.

The goal is a clear consumer taxonomy, explicit actionability gates, and mechanical guardrails.

## Current Known State

Prior threat-intel work established:

- `ThreatIntelPolicyContext` construction/export paths.
- Policy-composed helper APIs such as `evaluate_indicator_actionability` / equivalent.
- `is_policy_actionable` helper patterns.
- Shadow decision types and observability metrics.
- `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, and deferred/shadow modes.
- `classify_consumer_action` style dispatch for fail-open/fail-closed/shadow behavior.
- Raw lookup paths still exist for compatibility/diagnostics.
- Boundary guard tests exist for threat-intel/WAF separation.

The remaining risk is that enforcement-sensitive consumers may still call raw lookups or interpret threat-intel presence as directly actionable.

## Non-Goals

Do not redesign the threat-intel data model.

Do not change blocklist event semantics.

Do not change blocklist persistence or replay behavior.

Do not remove all raw lookup APIs; keep them for explicit diagnostic/compatibility use.

Do not add new WAF detections.

Do not change mesh-ID request-path scope.

Do not introduce Raft/consensus for threat-intel actionability.

Do not make fail-open/fail-closed policy changes unless a consumer is clearly misclassified.

## Phase 1 — Consumer Inventory

Inventory every threat-intel read path and classify it.

Search terms:

- `ThreatIntelligenceManager`
- `evaluate_indicator_actionability`
- `evaluate_indicator_policy_shadow`
- `is_policy_actionable`
- `classify_consumer_action`
- `ThreatIntelConsumerKind`
- `ThreatIntelConsumerAction`
- `ThreatIntelDeferredMode`
- `lookup_indicator`
- `lookup_raw`
- `raw_lookup`
- `threat_intel`
- `handle_incoming_threat`
- `block_ip_with_provenance`
- `BlocklistEvent`
- `announce_local_block`
- `ban_ip`
- `MeshThreatIntelPolicyGated`
- `ShadowOnly`
- `Deferred`
- `FailOpen`
- `FailClosed`

Likely files:

- `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`
- `crates/synvoid-mesh/src/**/threat*.rs`
- `crates/synvoid-core/src/**`
- `src/worker/**`
- `src/supervisor/**`
- `src/admin/**`
- `src/waf/**`
- `architecture/threat_intel*.md`
- `docs/THREAT_INTEL.md`
- `tests/threat_intel_boundary_guard.rs`

For each consumer, record:

- file/function;
- indicator type;
- current lookup API used;
- whether it can mutate enforcement state;
- whether it can emit a blocklist event;
- whether it is request-path, mesh-control, admin, diagnostics, or background sync;
- intended consumer classification.

## Phase 2 — Define Consumer Classes

Use four explicit classes.

### Enforcement

Can cause blocking, banning, trust mutation, peer isolation, blocklist events, or other security state changes.

Rules:

- Must use policy-composed actionability.
- Must pass a `ThreatIntelPolicyContext`.
- Must be classified via `ThreatIntelConsumerKind` or equivalent.
- Must not call raw lookup APIs directly.

### Deferred

Can queue, suppress, or defer action according to fail-open/fail-closed policy.

Rules:

- Must use policy-composed actionability.
- Must respect `ThreatIntelDeferredMode`.
- Must not mutate enforcement state when classified as deferred/no-action.

### ShadowOnly

Can observe and compare policy decisions but cannot mutate enforcement state.

Rules:

- May call shadow-evaluation APIs.
- Must not emit blocklist events.
- Must not call block/unblock APIs.
- Must not change peer trust state.

### Diagnostic

Can use raw lookup APIs for admin/debug/metrics/compatibility.

Rules:

- Must not mutate enforcement state.
- Must be clearly named/documented as diagnostic.
- Must not be reused by enforcement paths.

## Phase 3 — Add a Consumer Inventory Document

Create or update architecture documentation.

Suggested file:

```text
architecture/threat_intel_consumer_actionability.md
```

Include a table:

| Consumer | File/function | Class | Allowed API | Enforcement allowed? | Notes |
|----------|---------------|-------|-------------|----------------------|-------|

Document any raw lookup paths as diagnostic-only or compatibility-only.

This doc should become the canonical map for future threat-intel work.

## Phase 4 — Harden Enforcement Consumers

For every enforcement-capable consumer:

- replace raw lookup calls with policy-composed actionability APIs;
- require explicit `ThreatIntelPolicyContext` construction;
- classify consumer kind;
- enforce fail-open/fail-closed/deferred/shadow result handling;
- ensure blocklist mutation happens only after an actionable decision;
- ensure provenance uses a threat-intel policy-gated provenance kind/source.

Blocklist mutation rule:

```text
Threat-intel sourced blocklist writes require policy-composed actionable decision.
```

If a consumer cannot construct a valid policy context, it must not mutate enforcement state. It may log, shadow, or defer.

## Phase 5 — Constrain Raw Lookup APIs

Keep raw lookup APIs, but make their scope obvious.

Options:

- rename helpers with `diagnostic_` / `raw_` prefix if not already done;
- add doc comments saying “not for enforcement”; 
- make raw lookup APIs private where possible;
- provide a small allowlist for diagnostic callers;
- add guardrail tests to enforce the allowlist.

Do not remove raw APIs if they are needed for admin diagnostics or compatibility, but prevent accidental action-bearing reuse.

## Phase 6 — Shadow and Deferred Safety

Validate shadow/deferred behavior.

Requirements:

- `ShadowOnly` never emits blocklist events.
- `ShadowOnly` never calls block/unblock APIs.
- deferred fail-open/no-action does not mutate enforcement state.
- deferred fail-closed behavior is explicit and tested.
- shadow disagreements are metrics/logs only.
- admin diagnostics can expose shadow disagreement but cannot convert it into action without policy gate.

## Phase 7 — Provenance and Event Emission

Threat-intel-driven blocklist events must carry policy-gated provenance.

Check:

- `BlockProvenanceKind` variant used for threat-intel action.
- provenance source names identify policy-gated path.
- raw lookup/diagnostic paths cannot write `MeshThreatIntelPolicyGated` provenance.
- blocklist events emitted by threat-intel consumers include consumer kind / decision class if available in logs or provenance source.

Do not allow threat-intel action to appear as `AdminManual`, `SupervisorSync`, or `LegacyUnknown`.

## Phase 8 — Guardrail Tests

Add or extend guardrails.

Suggested test file:

```text
tests/threat_intel_consumer_actionability_guard.rs
```

Guardrails:

1. Enforcement files/functions cannot call raw lookup helpers directly.
2. Raw lookup helpers are allowlisted only for diagnostic/admin/shadow docs paths.
3. Blocklist mutation from threat-intel files must be near a policy-composed actionability call or use a policy-gated wrapper.
4. `ShadowOnly` paths cannot call block/unblock APIs.
5. `LegacyUnknown` is not used for new threat-intel blocklist writes.
6. `AdminManual`/`SupervisorSync` are not used for threat-intel-originated blocklist writes.

Use source-scan guardrails sparingly but mechanically enough to prevent regression.

## Phase 9 — Unit and Integration Tests

Add focused behavior tests.

### Consumer classification tests

- each consumer kind maps to expected action class;
- fail-open no-action suppresses enforcement;
- fail-closed no-action suppresses or escalates according to existing policy semantics;
- shadow-only returns shadow result but no mutation.

### Enforcement tests

- actionable threat-intel decision can emit blocklist event;
- non-actionable decision cannot emit blocklist event;
- deferred decision cannot emit blocklist event unless policy explicitly allows;
- raw diagnostic lookup cannot mutate blocklist.

### Provenance tests

- threat-intel blocklist write carries policy-gated provenance;
- diagnostic raw lookup does not create provenance-bearing blocklist entry;
- blocklist event from threat-intel has expected source/provenance.

### Regression tests

- existing threat-intel boundary guard still passes;
- blocklist provenance/persistence tests still pass;
- mesh-ID boundary guard still passes.

## Phase 10 — Documentation Updates

Update:

- `architecture/threat_intel_consumer_actionability.md` (new canonical doc)
- `architecture/threat_intel_request_waf_audit.md`
- `docs/THREAT_INTEL.md`
- `AGENTS.md`
- any existing threat-intel policy composition docs

Docs must state:

- which APIs are enforcement-safe;
- which APIs are diagnostic-only;
- how consumer classes map to action permissions;
- how deferred/shadow decisions behave;
- how threat-intel blocklist provenance is assigned;
- that raw lookup presence is not equivalent to actionability.

## Phase 11 — Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-mesh threat_intel
cargo test -p synvoid-mesh actionability
cargo test -p synvoid-core threat_intel
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test mesh_id_boundary_guard
cargo test -p synvoid-block-store provenance
cargo test -p synvoid-block-store target_state
cargo test --lib --no-run
```

If APIs are renamed or visibility changes:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. Every threat-intel consumer is inventoried and classified.
2. Enforcement consumers use policy-composed actionability, not raw lookups.
3. Raw lookup APIs are documented/guarded as diagnostic or compatibility only.
4. Blocklist mutation from threat-intel requires an actionable policy decision.
5. Shadow-only paths cannot mutate enforcement state.
6. Deferred/fail-open/fail-closed behavior is explicit and tested.
7. Threat-intel-originated blocklist writes use policy-gated provenance.
8. Guardrail tests prevent new raw lookup usage in enforcement-sensitive paths.
9. Existing blocklist provenance/replay/mesh-ID boundary tests still pass.
10. Docs clearly state that raw threat-intel presence is not actionability.

## Notes for the Implementer

This is an upstream correctness pass. The hardened blocklist plane should only receive threat-intel actions that passed policy composition.

The invariant is:

> Threat-intel data is evidence. Policy-composed actionability is authority.
