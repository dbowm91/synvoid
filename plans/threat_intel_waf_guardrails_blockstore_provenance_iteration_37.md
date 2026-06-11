# Threat-Intel/WAF Guardrails and BlockStore Provenance — Iteration 37

## Purpose

The threat-intel/WAF architecture is now in a good state:

- remote mesh threat-intel is advisory until canonical trust and the consumer gate permit enforcement;
- `handle_incoming_threat` gates mesh-sourced block/rate-limit/suspicious/throttle mutations;
- WAF request code reads local `BlockStore` state rather than querying `ThreatIntelligenceManager` directly;
- raw threat-intel lookups are documented as compatibility/debug APIs only;
- docs and agent guidance now describe the advisory/canonical/enforcement split.

The remaining risk is regression. This pass should lock in the boundary with mechanical guardrails and add provenance to `BlockStore` entries so request-time enforcement state is auditable.

This is a combined but bounded pass:

1. Add regression checks that prevent WAF/request code from consuming raw threat-intel lookups.
2. Add or prepare `BlockStore` provenance so entries indicate whether they came from local WAF, honeypot, admin, supervisor sync, mesh policy-gated threat-intel, proxy probing, or another controlled source.

## Non-Goals

Do not redesign threat-intel policy composition.

Do not remove raw threat-intel lookup APIs.

Do not add request-path DHT/network lookups.

Do not change the meaning of local-origin detections. Local WAF/honeypot detections remain first-party evidence and do not require canonical mesh gating.

Do not attempt full audit/event-log persistence in this pass. Provenance should be lightweight metadata attached to block entries and exposed where useful.

Do not overbuild RBAC or admin workflow changes. Admin/manual actions only need clear provenance classification for now.

## Current Boundary to Preserve

The current audited boundary is:

- Mesh threat-intel consumers receive advisory records.
- Canonical trust plus `ThreatIntelConsumerKind::Enforcement` produces `ThreatIntelConsumerAction::PermitAction` when enforcement is allowed.
- Gated mesh enforcement mutates `BlockStore`.
- WAF request code reads `BlockStore` as local enforcement state.
- WAF request code does not call raw `ThreatIntelligenceManager` lookup APIs.

This invariant must remain true:

> Remote mesh threat-intel must not become request/WAF enforcement unless it passed canonical trust and the consumer gate. Request/WAF hot paths may consume local enforcement state, not raw advisory records.

## Phase 1 — Add a Raw Threat-Intel Lookup Boundary Check

Add a lightweight guardrail that fails if raw threat-intel lookup APIs are introduced into request/WAF hot paths or other enforcement-sensitive surfaces.

Suggested implementation options:

### Option A — Rust test that scans source files

Add a test under an appropriate crate/test module, for example:

- `tests/threat_intel_boundary_guard.rs`, or
- a crate-local test in `crates/synvoid-mesh`, if it can access repo files reliably, or
- an existing architecture/guardrail test module if one exists.

The test should recursively inspect source files and search for raw API tokens:

- `lookup_local_indicator(`
- `lookup_local_indicator_by_ip(`
- `lookup_threat_indicator_in_dht(`

It should reject those tokens outside an allowlist.

Allowlist categories:

- `crates/synvoid-mesh/src/mesh/threat_intel.rs` implementation and internal tests;
- explicit tests that validate raw lookup behavior;
- admin/debug/shadow endpoints that are documented as non-enforcement;
- feed dedup/bookkeeping paths, such as threat-intel feed dedup before announcement;
- docs and plans.

Denylist/hot surfaces:

- `src/waf/**`
- `src/http/**`
- `src/worker/unified_server/**` request handling code, except lifecycle/admin sync code if intentionally allowed;
- `src/reverse_proxy/**` or `src/proxy/**` request-path code;
- `crates/synvoid-http3/**` request WAF adapter code;
- any `RequestServices`, `Http3RequestWaf`, `WafContext`, or request handler path.

The failure message should explain the rule:

> Raw threat-intel lookup API used in an enforcement-sensitive path. Use `lookup_*_policy_strict` for actionability-sensitive reads, or document and allowlist the call if it is debug/shadow/bookkeeping only.

### Option B — Script plus CI/documented command

Add a small script, for example:

- `scripts/check_threat_intel_boundary.sh`, or
- `scripts/check-threat-intel-boundary.py`

Then add a test/CI hook or documented command that runs it.

Option A is preferred if it is easy to keep cross-platform. Option B is acceptable if the repo already uses scripts for architecture guardrails.

## Phase 2 — Add Positive Boundary Tests

Add tests that assert behavior, not only source scanning.

Required tests where practical:

1. Mesh advisory record with no policy context cannot mutate `BlockStore` through `handle_incoming_threat`.
2. Mesh advisory record with canonical unknown/unavailable cannot mutate `BlockStore`.
3. Mesh advisory record with canonical actionable can mutate `BlockStore`.
4. `apply_sync` delegates to the same gated path and cannot bypass it.
5. Hot-threat gossip delegates to the same gated path and cannot bypass it.
6. WAF request/check path reads `BlockStore` and does not need `ThreatIntelligenceManager` for enforcement.
7. Local-origin WAF/honeypot detection still mutates local block state as intended.

If tests 4–6 already exist, do not duplicate them. Add only the missing coverage and point the audit doc to the test names.

## Phase 3 — Rename or Harden Private Mesh Mutation Helpers

The private helpers are currently safe because their call sites are gated and Rustdoc states the precondition. Make this harder to misuse.

Preferred change:

- Rename `apply_rate_limit_mesh_action` to `apply_rate_limit_mesh_action_after_policy_permit`.
- Rename `apply_suspicious_mesh_action` to `apply_suspicious_mesh_action_after_policy_permit`.

Keep the Rustdoc precondition:

```rust
/// # Preconditions
/// Caller MUST have verified `ThreatIntelConsumerAction::PermitAction`
/// via the enforcement policy gate before calling this helper.
```

Alternative if the rename is too noisy:

- Pass `ThreatIntelConsumerAction` into the helpers and return early unless it is `PermitAction`.

The rename is simpler and makes misuse obvious in code review.

## Phase 4 — Design Lightweight BlockStore Provenance

Inspect the current `BlockStore`, `BlockEntry`, persistence format, admin views, and WAF use sites.

Identify where block entries are created, including at least:

- WAF local detection / escalation;
- WAF honeypot blocks;
- WAF ASN scraping / local detection;
- mesh threat-intel gated enforcement;
- supervisor IPC blocklist sync;
- admin manual IP ban;
- admin mesh-ID ban;
- supervisor gRPC/manual actions;
- proxy upstream probing auto-ban;
- tests and fixtures.

Add a provenance enum, using names that are stable and easy to serialize. Suggested shape:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockProvenanceKind {
    LocalWaf,
    LocalHoneypot,
    LocalAsnTracker,
    MeshThreatIntelPolicyGated,
    SupervisorSync,
    AdminManual,
    SupervisorManual,
    ProxyHealthProbe,
    Test,
    LegacyUnknown,
}
```

If more context is needed, use a struct rather than only an enum:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProvenance {
    pub kind: BlockProvenanceKind,
    pub source: Option<String>,
}
```

Keep this minimal. Do not create a full audit event model in this pass.

## Phase 5 — Add Provenance to Block Entries Safely

Find the canonical `BlockEntry` type and persistence format. Then add provenance with backward-compatible defaults.

Suggested field:

```rust
#[serde(default)]
pub provenance: BlockProvenance,
```

or if using only enum:

```rust
#[serde(default = "default_block_provenance")]
pub provenance: BlockProvenanceKind,
```

Backward compatibility requirement:

- old persisted block entries without provenance must deserialize as `LegacyUnknown`;
- tests should cover deserializing an old entry without provenance.

If `BlockEntry::new(...)` is currently the main constructor, avoid forcing every call site to pass provenance immediately unless the diff remains small.

Possible migration path:

1. Keep `BlockEntry::new(...)` and default provenance to `LegacyUnknown`.
2. Add `BlockEntry::new_with_provenance(...)`.
3. Gradually migrate important call sites in this pass.

Preferred if call-site count is manageable:

- update `block_ip` or add `block_ip_with_provenance` to accept provenance;
- keep `block_ip` as compatibility wrapper that uses `LegacyUnknown` or a better local default;
- migrate all known production call sites to `block_ip_with_provenance`.

## Phase 6 — Assign Provenance at Important Call Sites

Assign provenance at minimum for these sources:

### Mesh threat-intel gated enforcement

In `handle_incoming_threat`, when `PermitAction` leads to block/rate-limit/suspicious/throttle mutation, use:

- `BlockProvenanceKind::MeshThreatIntelPolicyGated`

Include a compact source string if supported:

- `mesh:<from_node>`
- optionally include threat type in reason/source if already done.

### Local WAF / honeypot detections

Use:

- `LocalWaf` for WAF escalation/block decisions;
- `LocalHoneypot` for honeypot-triggered blocks;
- `LocalAsnTracker` for local ASN scraping detector blocks.

### Admin / supervisor / sync

Use:

- `AdminManual` for admin API bans;
- `SupervisorManual` for supervisor gRPC/manual actions;
- `SupervisorSync` for worker IPC blocklist sync;
- `ProxyHealthProbe` for proxy upstream probing auto-ban;
- `Test` in tests where appropriate.

If a call site cannot be classified confidently, use `LegacyUnknown` and add a TODO only if needed.

## Phase 7 — Expose Provenance Where It Helps

Update only low-risk surfaces:

- admin blocklist/listing DTOs if present;
- debug/log output when a block is created;
- tests that inspect block entries.

Do not change public API compatibility more than needed. If admin DTO changes are risky, leave them for a follow-up but document that provenance is stored internally.

## Phase 8 — Documentation Updates

Update documentation after code changes:

- `docs/THREAT_INTEL.md`
  - Add a short note that mesh threat-intel blocks are stored with mesh-policy-gated provenance.

- `architecture/threat_intel_request_waf_audit.md`
  - Update the audit table/status if call sites changed.
  - Add a paragraph: WAF reads `BlockStore`; provenance identifies whether the block came from mesh-gated threat intel, local detection, admin action, supervisor sync, etc.

- `AGENTS.md`
  - Add one line under Threat-Intel Enforcement Rules:
    - New block-store writes must set meaningful provenance; do not use `LegacyUnknown` for new production enforcement paths unless compatibility requires it.

## Phase 9 — Tests and Verification

Required tests:

1. Raw lookup boundary check fails on disallowed request/WAF raw lookup usage.
2. Raw lookup boundary check allows documented debug/shadow/bookkeeping uses.
3. Old persisted `BlockEntry` without provenance deserializes as `LegacyUnknown`.
4. Mesh threat-intel gated block writes `MeshThreatIntelPolicyGated` provenance.
5. Local WAF/honeypot block writes local provenance.
6. Admin/manual block writes admin/manual provenance where call sites are migrated.
7. WAF request block check behavior is unchanged after adding provenance.
8. `block_ip` compatibility wrapper still works if retained.

Recommended commands:

- `cargo test -p synvoid-mesh threat_intel`
- targeted WAF/block-store tests
- guardrail test or script command
- broader `cargo test --lib --no-run` if touched APIs cross crate boundaries

If GitHub CI still has no statuses, mention that in the final implementation note.

## Acceptance Criteria

This pass is complete when:

1. A mechanical guardrail exists against raw threat-intel lookup use in request/WAF enforcement-sensitive paths.
2. Existing allowed raw lookup uses are explicitly allowlisted or classified.
3. Mesh threat-intel enforcement delegation remains gated through `PermitAction`.
4. Private mesh mutation helper names or signatures make the policy precondition hard to miss.
5. `BlockEntry` or equivalent block-store state carries backward-compatible provenance.
6. Important production block writers set meaningful provenance.
7. WAF behavior remains unchanged: it reads local `BlockStore` enforcement state.
8. Docs and agent guidance describe both the boundary guardrail and provenance expectations.
9. Tests cover source guardrails, backward compatibility, and representative provenance assignment.

## Suggested Implementation Order

1. Add the raw lookup boundary check first. This locks the existing architecture before changing block-store APIs.
2. Add positive behavior tests for mesh gating if missing.
3. Rename or harden private mesh mutation helpers.
4. Inspect BlockStore types, constructors, persistence, and write call sites.
5. Add provenance types with backward-compatible defaults.
6. Add `block_ip_with_provenance` or equivalent and migrate important production call sites.
7. Update admin/debug DTOs only if low risk.
8. Update docs and AGENTS guidance.
9. Run focused tests and record any unsupported CI status.

## Notes for the Implementer

Keep provenance descriptive, not policy-driving. The authorization decision is still made before a block entry is written. Provenance should explain where the enforcement state came from after the fact; it should not become a second enforcement policy engine.

Do not let this pass expand into a full audit-log or event-sourcing rewrite. That may be useful later, but the current goal is simple: prevent boundary regressions and make local enforcement state explainable.
