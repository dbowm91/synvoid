# Mesh Threat Intel Second Consumer Migration — Iteration 21

## Goal

Use the injected `ThreatIntelPolicyContext` to migrate one additional threat-intel read path to policy-composed behavior.

Iteration 20 completed the injection seam:

- `ThreatIntelPolicyContext` carries `Arc<dyn CanonicalTrustReader>` and `Arc<dyn AdvisoryRecordSource>`;
- `ThreatIntelligenceManager` stores it as optional state;
- `evaluate_indicator_actionability_configured(...)` uses the injected context;
- `lookup_threat_indicator_policy_composed(...)` gates the legacy DHT result on policy output;
- old raw lookup paths remain available.

This pass should move one more threat-intel read path to the composed-policy seam without touching proxy, YARA/WASM, routing, or enforcement hot paths broadly.

## Core Invariant

A threat-intel result is actionable only when:

```text
advisory observation present + canonical trust present
```

Advisory-only records are not actionable.

Canonical unknown/unavailable defers or returns no actionable result.

Legacy/raw lookup remains available for compatibility and comparison.

## Non-Goals

Do not migrate proxy, YARA/WASM, route policy, bot policy, or WAF enforcement consumers.

Do not alter `handle_incoming_threat` enforcement behavior.

Do not rewrite `sync_from_dht`, DHT ingestion, record-store behavior, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not remove `lookup_threat_indicator_in_dht`, `lookup_local_indicator`, or `lookup_local_indicator_by_ip`.

Do not change `CanonicalTrustReader`, `AdvisoryRecordSource`, or `ThreatIntelPolicyDecision` semantics.

Do not construct concrete canonical/advisory implementations inside threat-intel methods.

Do not introduce globals or `RECORD_STORE_GLOBAL` usage.

Do not add live DHT/Raft/network tests.

## Phase 1 — Select The Second Consumer

Inventory all threat-intel read paths and choose exactly one.

Run:

```bash
rg "lookup_local_indicator|lookup_local_indicator_by_ip|lookup_threat_indicator_in_dht|lookup_threat_indicator_policy_composed|evaluate_indicator_actionability_configured|check_threat|threat_indicator|ThreatIndicator" crates/synvoid-mesh/src/mesh/threat_intel.rs crates/synvoid-mesh/src src crates/synvoid-* architecture docs
```

Preferred target:

- a read-only helper that currently returns `Option<ThreatIndicator>`;
- a local lookup wrapper with simple inputs;
- a method used by tests or caller code where fallback behavior is easy to preserve.

Suggested candidate:

```rust
lookup_local_indicator_by_ip_policy_composed(ip: &str) -> Option<ThreatIndicator>
```

or a generic sibling:

```rust
lookup_local_indicator_policy_composed(indicator_value: &str, threat_type: ThreatType) -> Option<ThreatIndicator>
```

Avoid:

- `handle_incoming_threat`;
- `sync_from_dht`;
- WASM/plugin callback paths;
- proxy/blocking hot paths;
- DHT publish/announce paths.

### Acceptance Criteria

Exactly one second consumer/sibling is selected.

Selection is documented in code comments or the architecture note.

## Phase 2 — Add A Policy-Composed Sibling For Local Lookup

Do not replace raw local lookup directly. Add a sibling method.

Preferred shape:

```rust
pub fn lookup_local_indicator_policy_composed(
    &self,
    indicator_value: &str,
    threat_type: ThreatType,
) -> Option<ThreatIndicator> {
    let decision = match self.evaluate_indicator_actionability_configured(indicator_value, threat_type) {
        Some(decision) => decision,
        None => return self.lookup_local_indicator(indicator_value, threat_type),
    };

    match decision {
        ThreatIntelPolicyDecision::Actionable(_) => self.lookup_local_indicator(indicator_value, threat_type),
        _ => None,
    }
}
```

Optional convenience wrapper:

```rust
pub fn lookup_local_indicator_by_ip_policy_composed(&self, ip: &str) -> Option<ThreatIndicator> {
    self.lookup_local_indicator_policy_composed(ip, ThreatType::IpBlock)
}
```

### Behavior Rules

- If no policy context is configured, preserve legacy local lookup behavior.
- If policy context is configured, return a local indicator only for `Actionable`.
- `AdvisoryOnly`, `NotActionable`, and `Deferred` return `None`.
- Do not decode advisory payloads in this method.
- Do not touch DHT/record-store directly here.
- Do not make advisory-only local records actionable.

### Acceptance Criteria

One second read path now has a policy-composed sibling.

Raw methods remain unchanged.

## Phase 3 — Add Focused Tests

Use static canonical/advisory sources and existing threat-intel test helpers.

Required tests:

1. With no policy context, policy-composed local lookup falls back to legacy local lookup.
2. With context and `Actionable`, policy-composed local lookup returns the local indicator.
3. With advisory present but canonical unknown, policy-composed local lookup returns `None`.
4. With advisory missing, policy-composed local lookup returns `None`.
5. With canonical not trusted, policy-composed local lookup returns `None`.
6. With canonical unavailable, policy-composed local lookup returns `None`.
7. Raw `lookup_local_indicator` remains available and still returns the indicator for the same fixture.
8. If an IP convenience wrapper is added, it delegates to the generic method.
9. No DHT/Raft/networking required.

### Practical Guidance

If existing tests do not expose an easy way to seed a local indicator, use the lowest-churn public path such as `add_feed_indicator`, `announce_local_block`, or a small local test helper inside the test module.

Do not weaken validation or production behavior for tests.

### Acceptance Criteria

Tests prove policy context gates local lookup while raw lookup remains intact.

## Phase 4 — Keep Documentation Current

Update `architecture/mesh_trust_domains.md`.

Suggested text:

```markdown
### Iteration 21 Second Threat Intel Consumer Migration

A second read-only threat-intel path now has a policy-composed sibling using the injected `ThreatIntelPolicyContext`. Raw local/DHT lookup methods remain available. When policy context is configured, the composed local lookup returns an indicator only for `Actionable`; advisory-only, not-actionable, and deferred decisions return no actionable result. No enforcement hot paths, proxy, YARA/WASM, routing, DHT sync, or ingestion paths were migrated.
```

Update the follow-up so it no longer says to migrate a second threat-intel path if that is now complete.

### Acceptance Criteria

Docs reflect exactly what was migrated and what remains untouched.

## Phase 5 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
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

If broad checks fail for unrelated reasons, record focused checks and exact unrelated failure.

## Completion Criteria

This iteration is complete when:

- one additional read-only threat-intel path has a policy-composed sibling;
- no policy context preserves legacy behavior;
- configured context gates the result on `Actionable`;
- advisory-only/unknown/unavailable/not-trusted cases return no actionable result;
- raw lookup methods remain unchanged;
- tests cover context/no-context behavior;
- no broader service consumers are migrated;
- docs accurately describe the second migration.

## Follow-Up Recommendation

After two threat-intel read paths are stable, stop and reassess before moving into proxy, YARA/WASM, routing, or enforcement hot paths. The next step should likely be a final threat-intel policy cleanup pass: consolidate duplicated mapping logic, verify all docs, and decide whether the policy-composed methods should become the preferred public API while raw paths remain compatibility APIs.
