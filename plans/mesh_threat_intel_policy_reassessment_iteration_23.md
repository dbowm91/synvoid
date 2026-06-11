# Mesh Threat Intel Policy Reassessment — Iteration 23

## Goal

Pause after the threat-intel policy-composed lookup cleanup and reassess the next migration based on actual call-graph pressure.

The current state should be:

- `ThreatIntelPolicyContext` is injectable into `ThreatIntelligenceManager`;
- `evaluate_indicator_actionability_configured(...)` uses the injected context;
- `lookup_threat_indicator_policy_composed(...)` gates DHT lookup on policy actionability;
- `lookup_local_indicator_policy_composed(...)` gates local lookup on policy actionability;
- both composed lookups share `is_policy_actionable(...)`;
- raw lookup APIs remain compatibility/diagnostic paths;
- `cargo check -p synvoid-mesh --features mesh` passes.

This pass should identify the next concrete consumer, or explicitly choose to stop the threat-intel migration track until a real consumer need emerges.

## Non-Goals

Do not migrate proxy, YARA/WASM, routing, bot policy, WAF policy, or enforcement hot paths automatically.

Do not alter `handle_incoming_threat`, `sync_from_dht`, DHT publish/announce, record-store behavior, Push/Announce canonical ingress, quorum, anti-entropy, or Raft apply behavior.

Do not remove raw lookup methods.

Do not change `ThreatIntelPolicyDecision`, `CanonicalTrustReader`, `AdvisoryRecordSource`, or policy actionability semantics.

Do not introduce globals, `RECORD_STORE_GLOBAL`, or concrete canonical/advisory construction inside threat-intel methods.

Do not add live DHT/Raft/network tests.

## Phase 1 — Verify Cleanup Baseline

Before selecting another consumer, verify that the current cleanup is actually closed.

Run:

```bash
rg "fn is_policy_actionable|is_policy_actionable\(|lookup_threat_indicator_policy_composed|lookup_local_indicator_policy_composed|lookup_local_indicator_by_ip_policy_composed|lookup_threat_indicator_in_dht|lookup_local_indicator\(" crates/synvoid-mesh/src/mesh/threat_intel.rs
```

Confirm:

1. `is_policy_actionable(...)` exists.
2. Both composed lookup methods call it.
3. Raw lookup methods still exist.
4. Raw lookup methods are documented as compatibility/low-level APIs.
5. Composed lookup methods are documented as preferred for actionability-sensitive reads.

Run focused validation:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
```

### Acceptance Criteria

Do not proceed unless focused checks pass or any failure is clearly unrelated and documented.

## Phase 2 — Build A Threat-Intel Consumer Inventory

Inventory actual callers and potential consumers before migrating anything.

Run:

```bash
rg "lookup_threat_indicator_in_dht|lookup_local_indicator|lookup_local_indicator_by_ip|lookup_threat_indicator_policy_composed|lookup_local_indicator_policy_composed|evaluate_indicator_actionability|ThreatIntelligenceManager|check_threat|threat intel|ThreatIndicator" crates src architecture docs
```

Classify each candidate as one of:

- read-only diagnostic;
- read-only actionability-sensitive;
- enforcement hot path;
- ingestion/sync/replication path;
- proxy/routing/WAF integration;
- test-only.

Document the inventory in `architecture/mesh_trust_domains.md` or an adjacent architecture note if it is substantial.

### Acceptance Criteria

No migration happens before the candidate list is classified.

## Phase 3 — Choose One Of Three Outcomes

After inventory, choose exactly one outcome.

### Outcome A — Stop The Track

Choose this if existing composed local/DHT methods are enough for now and no current caller needs policy-composed behavior.

Requirements:

- Update docs to say threat-intel policy path is staged and ready.
- Keep raw methods as compatibility APIs.
- No code migration.
- Follow-up moves to a different architecture track.

### Outcome B — Migrate One Low-Risk Read-Only Caller

Choose this only if there is a real read-only caller currently using a raw lookup where policy-composed behavior is clearly preferable.

Requirements:

- Migrate exactly one caller.
- Preserve legacy/raw fallback if caller behavior is externally observable.
- Use the existing composed method rather than reimplementing policy mapping.
- Add caller-level tests.
- Do not touch proxy/YARA/WASM/routing/enforcement hot paths.

### Outcome C — Prepare A Broader Consumer But Do Not Migrate It

Choose this if the next apparent consumer is proxy, YARA/WASM, routing, or another high-risk enforcement path.

Requirements:

- Add a design note only.
- Identify required injection ownership.
- Identify fail-open/fail-closed semantics.
- Identify test harness requirements.
- No production behavior change.

### Acceptance Criteria

The implementation must select only one outcome and document why.

## Phase 4 — If Migrating A Low-Risk Caller, Use Existing Composed APIs

If Outcome B is selected, use these APIs:

```rust
lookup_threat_indicator_policy_composed(...)
lookup_local_indicator_policy_composed(...)
lookup_local_indicator_by_ip_policy_composed(...)
evaluate_indicator_actionability_configured(...)
```

Rules:

- Do not call `evaluate_threat_intel_policy(...)` directly from a new service consumer unless there is no viable manager method.
- Do not pass raw advisory/canonical trait objects through unrelated layers.
- Do not create new actionability helpers.
- Do not duplicate `is_policy_actionable(...)`.
- Do not change raw lookup behavior.

### Acceptance Criteria

Any migration reuses the existing manager-level composed API.

## Phase 5 — Documentation Update

Update `architecture/mesh_trust_domains.md` with the selected outcome.

Suggested text for Outcome A:

```markdown
### Iteration 23 Threat Intel Policy Reassessment

The threat-intel policy-composed lookup track is now staged and stable. Two read-only composed lookup APIs exist for DHT and local indicators, both gated by shared `is_policy_actionable` semantics. A call-graph review found no low-risk caller that should migrate before broader proxy/YARA/WASM/routing design work. The track is paused; raw lookup APIs remain compatibility/diagnostic paths.
```

Suggested text for Outcome B:

```markdown
### Iteration 23 Threat Intel Policy Consumer Selection

A call-graph review selected one additional low-risk read-only caller for policy-composed lookup. The caller now uses the existing manager-level composed API rather than raw lookup or direct policy helper calls. Raw APIs remain compatibility/diagnostic paths. No proxy, YARA/WASM, routing, DHT sync, ingestion, or enforcement hot paths were migrated.
```

Suggested text for Outcome C:

```markdown
### Iteration 23 Threat Intel Broader Consumer Design

A call-graph review found that the next meaningful consumer is a higher-risk enforcement path. No production migration was performed. The follow-up design must define injection ownership, fail-open/fail-closed behavior, and test harnesses before proxy/YARA/WASM/routing consumers are allowed to use policy-composed threat intel.
```

### Acceptance Criteria

Docs state what was selected and what was intentionally not changed.

## Phase 6 — Validation Commands

Run focused checks after any change:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh canonical --features mesh
```

If a caller was migrated, run its package/test target explicitly.

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

- the cleanup baseline is verified;
- threat-intel policy consumers are inventoried;
- exactly one outcome is selected;
- any migration, if performed, reuses existing composed manager APIs;
- raw lookup APIs remain compatibility/diagnostic paths;
- no broader enforcement path is migrated without a separate design pass;
- architecture docs accurately record the decision;
- focused checks pass.

## Follow-Up Recommendation

If Outcome A is selected, move to a different architecture track.

If Outcome B is selected, stop after one caller and reassess again.

If Outcome C is selected, create a dedicated design plan for the broader consumer before touching production behavior.
