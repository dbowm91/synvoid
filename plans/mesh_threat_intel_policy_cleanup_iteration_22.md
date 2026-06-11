# Mesh Threat Intel Policy Cleanup — Iteration 22

## Goal

Consolidate and harden the threat-intel policy-composed lookup path after two staged read-path migrations.

The current staged state is intentionally conservative:

- raw local/DHT lookup methods remain available;
- `lookup_threat_indicator_policy_composed(...)` gates raw DHT lookup on `ThreatIntelPolicyDecision::Actionable`;
- `lookup_local_indicator_policy_composed(...)` gates raw local lookup on `Actionable`;
- `lookup_local_indicator_by_ip_policy_composed(...)` delegates to local policy-composed lookup;
- no proxy, YARA/WASM, routing, DHT sync, ingestion, or enforcement hot paths have migrated.

This pass should reduce duplication, verify tests/docs, and define the preferred API posture without expanding the migration surface.

## Non-Goals

Do not migrate proxy, YARA/WASM, routing, bot policy, WAF policy, or enforcement hot paths.

Do not alter `handle_incoming_threat`, `sync_from_dht`, DHT publish/announce, record-store behavior, Push/Announce canonical ingress, quorum, anti-entropy, or Raft apply behavior.

Do not remove raw lookup methods.

Do not change `ThreatIntelPolicyDecision`, `CanonicalTrustReader`, or `AdvisoryRecordSource` semantics.

Do not introduce globals, `RECORD_STORE_GLOBAL`, or concrete canonical/advisory construction inside threat-intel methods.

Do not add live DHT/Raft/network tests.

## Phase 1 — Inventory Current Threat-Intel Policy Surface

Run:

```bash
rg "ThreatIntelPolicyContext|set_policy_context|policy_context\(|evaluate_indicator_actionability|evaluate_indicator_actionability_configured|lookup_threat_indicator_policy_composed|lookup_local_indicator_policy_composed|lookup_local_indicator_by_ip_policy_composed|lookup_threat_indicator_in_dht|lookup_local_indicator|lookup_local_indicator_by_ip" crates/synvoid-mesh/src/mesh/threat_intel.rs crates/synvoid-mesh/src/mesh/threat_intel_policy.rs architecture docs AGENTS.md skills
```

Confirm:

1. `ThreatIntelPolicyContext` exists and carries the two trait objects.
2. Both policy-composed read methods gate on `Actionable`.
3. Raw lookup methods remain available.
4. No broad consumers have migrated.
5. Architecture docs and skills agree with code.

### Acceptance Criteria

Document any mismatch before editing.

## Phase 2 — Consolidate Duplicate Decision Gating

The DHT and local policy-composed methods likely duplicate the same mapping:

```rust
match decision {
    ThreatIntelPolicyDecision::Actionable(_) => legacy_lookup(...),
    other => { debug; None }
}
```

Extract a small private helper to avoid drift.

Suggested shape:

```rust
fn is_policy_actionable(decision: &ThreatIntelPolicyDecision) -> bool {
    matches!(decision, ThreatIntelPolicyDecision::Actionable(_))
}
```

or, if logging should be centralized:

```rust
fn policy_allows_lookup_result(
    decision: &ThreatIntelPolicyDecision,
    indicator_value: &str,
    threat_type: ThreatType,
    lookup_kind: &'static str,
) -> bool { ... }
```

Then update both:

- `lookup_threat_indicator_policy_composed(...)`
- `lookup_local_indicator_policy_composed(...)`

### Rules

- Do not change behavior.
- Keep fallback behavior unchanged when context is `None`.
- Keep `Actionable` as the only result that allows returning an indicator.
- Keep `AdvisoryOnly`, `NotActionable`, and `Deferred` non-actionable.

### Acceptance Criteria

DHT/local composed lookup methods share one decision-to-actionability helper.

Tests continue to pass without behavior changes.

## Phase 3 — Clarify API Posture In Rustdoc

Update rustdocs around raw and composed methods.

Desired posture:

- Raw methods are compatibility and low-level lookup APIs.
- Policy-composed methods are preferred for new actionability-sensitive reads.
- Raw methods remain acceptable for diagnostics, migration comparison, or explicitly advisory/non-actionable reads.
- Composed methods require configured policy context to enforce policy; otherwise they preserve legacy behavior.

Add concise rustdoc to:

- `lookup_threat_indicator_in_dht`
- `lookup_local_indicator`
- `lookup_local_indicator_by_ip`
- `lookup_threat_indicator_policy_composed`
- `lookup_local_indicator_policy_composed`
- `lookup_local_indicator_by_ip_policy_composed`
- `set_policy_context`

### Acceptance Criteria

Future callers can tell which API to use without reading architecture docs.

No rustdoc claims policy enforcement where fallback still preserves legacy behavior.

## Phase 4 — Verify And Tighten Tests

Run or add tests to cover the shared helper and both lookup families.

Required coverage:

1. No context: DHT policy-composed lookup falls back to legacy DHT lookup.
2. No context: local policy-composed lookup falls back to legacy local lookup.
3. With context: DHT policy-composed lookup returns result only for `Actionable`.
4. With context: local policy-composed lookup returns result only for `Actionable`.
5. With context: both return `None` for advisory-only/canonical unknown.
6. With context: both return `None` for advisory missing.
7. With context: both return `None` for canonical not trusted.
8. With context: both return `None` for canonical unavailable.
9. Raw lookup methods still return fixture values for compatibility.
10. IP convenience wrapper delegates to local generic composed method.

If some DHT tests require too much setup, keep them at the helper/mapping layer and document DHT raw-lookup integration as covered by existing tests.

### Acceptance Criteria

Test names make the safety contract obvious.

No DHT/Raft/networking required for policy-specific tests.

## Phase 5 — Update Architecture And Skills Docs

Update `architecture/mesh_trust_domains.md`.

Suggested text:

```markdown
### Iteration 22 Threat Intel Policy Cleanup

The two policy-composed threat-intel lookup paths now share a single decision-to-actionability helper, keeping `Actionable` as the only policy result that returns an indicator. Raw local/DHT lookup APIs remain compatibility/diagnostic paths; policy-composed methods are the preferred API for new actionability-sensitive reads. No proxy, YARA/WASM, routing, DHT sync, ingestion, or enforcement hot paths were migrated.
```

Also update `AGENTS.md` or `skills/synvoid_mesh.md` if they describe stale follow-up tasks.

Follow-up should recommend reassessment before broader migration.

### Acceptance Criteria

Docs match actual code.

No stale claim says the injection seam or second read path is still pending.

## Phase 6 — Validation Commands

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

This cleanup pass is complete when:

- duplicate DHT/local policy gating logic is consolidated;
- `Actionable` remains the only decision that returns an indicator;
- raw lookup APIs remain available and documented as compatibility/diagnostic paths;
- policy-composed APIs are documented as preferred for new actionability-sensitive reads;
- tests cover shared mapping and both lookup families, or clearly document unavoidable fixture limits;
- no broader consumers are migrated;
- architecture and skills docs are current.

## Follow-Up Recommendation

After this cleanup, pause the threat-intel policy track and review actual call graph pressure before migrating proxy, YARA/WASM, routing, or enforcement hot paths. The next migration should be based on a concrete consumer need, not automatic expansion.
