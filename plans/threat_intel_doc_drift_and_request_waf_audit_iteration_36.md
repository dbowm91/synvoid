# Threat-Intel Doc Drift and Request/WAF Integration Audit — Iteration 36

## Purpose

Iteration 35 resolved the remaining semantic cleanup around the threat-intel enforcement gate. The next pass should combine two related but bounded tasks:

1. Clean up remaining threat-intel documentation drift now that ASN handling, strict lookup semantics, suppression metrics, and consumer selection are stable.
2. Audit the request/WAF integration surface to ensure actionability-sensitive runtime consumers use strict or policy-composed threat-intel APIs rather than raw advisory/local lookups.

This is not a broad architecture pass. The goal is to make the now-correct threat-intel model consistently represented in docs and to verify that the request/WAF side has not retained an implicit bypass through raw lookup APIs.

## Current State

The threat-intel enforcement model now has the desired shape:

- DHT threat-intel records are advisory.
- Canonical trust determines whether advisory records may become enforcement.
- `ThreatIntelConsumerKind` classifies consumer intent.
- `ThreatIntelConsumerAction` gates enforcement mutation.
- `IncomingThreatPolicyGate` carries both action and decision for accurate suppression metrics.
- `IpBlock`, `RateLimitViolation`, `SuspiciousActivity`, and `IpThrottle` are gated in `handle_incoming_threat`.
- `AsnBlock` is observational only in that path.
- Strict lookup wrappers do not fall back to raw lookup when no policy context exists.
- Raw lookup APIs are documented as compatibility/debug surfaces, not enforcement inputs.

Known drift or audit targets from the previous review:

- `docs/THREAT_INTEL.md` still has a minor table inconsistency: `AsnBlock` says observational/no enforcement but its local action column says `Log attack type`. The code no longer records an attack metric for `AsnBlock`; this should become `Log advisory` or `Store advisory`.
- The same doc still has an architecture diagram with edge/origin nodes saying `apply threats`, which is now too blunt. It should say something like `policy-gated threat sync` or `sync + gate threats`.
- The request/WAF integration surface needs a fresh grep audit for raw threat-intel lookups and action-bearing block/rate-limit consumers.

## Non-Goals

Do not redesign the threat-intel policy model.

Do not remove raw lookup APIs in this pass. They remain useful for tests, diagnostics, admin views, and shadow comparison.

Do not alter DHT/Raft ownership, canonical snapshot IPC, record-store formats, or consensus behavior.

Do not add new enforcement behavior for ASN, domain, URL, or cert indicators. If those integrations are missing, document them as future integration points.

Do not introduce request-path network fetches. Request/WAF decisions must rely on local state, snapshots, or already-injected services.

## Phase 1 — Threat-Intel Documentation Drift Cleanup

Update `docs/THREAT_INTEL.md` first.

Required changes:

1. Fix the `AsnBlock` table row.

Current intent:

- Type: `AsnBlock`
- Description: ASN-based block advisory / observational only in the current mesh threat-intel path
- Local Action: `Log advisory` or `Store advisory`; not `Log attack type`

Do not say an ASN block is applied unless there is a real gated ASN enforcement path.

2. Update the architecture diagram labels.

Replace blunt `apply threats` language on edge/origin nodes with wording that reflects the policy gate. Examples:

- `sync threat advisories`
- `policy-gate threats`
- `apply only canonical-actionable threats`

The diagram should communicate that remote mesh data is not automatically applied.

3. Re-check all examples that say `apply`, `block`, or `sync from DHT`.

If an example describes remote/DHT threat-intel consumption, ensure it states or implies policy gating. Local-origin detection examples can still say `announce_local_block`, `announce_local_rate_limit`, and similar because those are first-party detections, not remote advisory consumption.

4. Clarify strict vs legacy composed API guidance.

The existing section is mostly correct. Tighten wording so:

- `lookup_*_policy_strict` is mandatory for enforcement/actionability-sensitive readers.
- `lookup_*_policy_composed` is acceptable for diagnostics or low-risk graceful degradation.
- raw `lookup_*` APIs are compatibility/debug only.

5. Add a short `Current Integration Status` section for non-IP indicators.

Document current behavior:

- `IpBlock`: gated enforcement wired.
- `RateLimitViolation`: gated enforcement wired.
- `SuspiciousActivity`: gated enforcement wired.
- `IpThrottle`: gated enforcement wired.
- `AsnBlock`: observational/advisory only; no enforcement mutation in mesh threat-intel path.
- `DomainBlock`: reserved/future DNS-layer integration.
- `UrlBlock`: reserved/future URL-filter integration.
- `CertBlock`: reserved/future TLS-layer integration.

Keep this short. It should prevent future docs from overstating enforcement coverage.

## Phase 2 — Mesh Trust Domain Documentation Alignment

Update `architecture/mesh_trust_domains.md`.

Required content:

- Explicitly define three planes:
  - advisory plane: DHT records, gossip, sync, local bookkeeping;
  - canonical plane: Raft-derived trust and canonical snapshots;
  - enforcement plane: request/WAF/block/rate-limit mutations gated by consumer action.
- State that raw advisory data may be stored and observed, but not used directly for enforcement.
- State that strict lookup wrappers are the correct API family for enforcement readers.
- State that request/WAF hot-path code must not perform network lookups to resolve actionability.

If this file already says most of this, prefer small edits over a rewrite.

## Phase 3 — AGENTS / Maintainer Guidance Cleanup

Update `AGENTS.md` or any equivalent contributor/agent guidance that references threat intel.

Required guidance:

- Agents must not introduce enforcement decisions from raw DHT/local threat-intel lookups.
- When editing request/WAF paths, prefer strict policy-composed APIs for threat-intel-derived enforcement.
- Raw lookup APIs are allowed only for tests, admin/debug views, diagnostics, or shadow comparison.
- If adding a new threat type that mutates enforcement state, it must use `ThreatIntelConsumerKind::Enforcement` and require `ThreatIntelConsumerAction::PermitAction`.

Keep the section brief and directive.

## Phase 4 — Request/WAF Integration Audit

Perform a repository-wide audit of request and WAF paths for threat-intel usage.

Search terms:

- `lookup_local_indicator(`
- `lookup_local_indicator_by_ip(`
- `lookup_threat_indicator_in_dht(`
- `lookup_local_indicator_policy_composed(`
- `lookup_threat_indicator_policy_composed(`
- `lookup_local_indicator_policy_strict(`
- `lookup_threat_indicator_policy_strict(`
- `evaluate_indicator_actionability_configured(`
- `evaluate_indicator_policy_shadow(`
- `block_ip(`
- `is_blocked(`
- `RateLimitViolation`
- `SuspiciousActivity`
- `IpThrottle`
- `ThreatIntelligenceManager`
- `RequestServices`
- `Http3RequestWaf`
- `Http3RequestContext`
- `WafContext`
- `unified_server`

Likely files/directories to inspect:

- `src/waf/**`
- `src/http/**`
- `src/worker/unified_server/**`
- `src/server/**`
- `src/reverse_proxy/**` if present
- `src/security/**` if it contains request-path controls
- `crates/synvoid-mesh/src/mesh/threat_intel.rs`
- `crates/synvoid-mesh/src/mesh/**`

For every finding, classify it as one of:

1. test-only;
2. local-origin detection;
3. raw compatibility/debug/admin;
4. shadow/observability;
5. advisory cache/bookkeeping;
6. request/WAF enforcement/actionability-sensitive.

Only category 6 must use strict/policy-gated actionability. Category 2 must not be accidentally broken; local-origin detection is first-party evidence and may still directly update local controls according to existing local policy.

## Phase 5 — Migrate Any Remaining Actionability-Sensitive Consumers

If the audit finds request/WAF code making enforcement decisions from raw threat-intel APIs, migrate it.

Preferred migration rules:

- For request/WAF enforcement: use `lookup_local_indicator_policy_strict` or `lookup_local_indicator_by_ip_policy_strict`.
- For DHT reads in actionability-sensitive code: use `lookup_threat_indicator_policy_strict`.
- For diagnostics/admin views: leave raw lookup, but add comments if ambiguity remains.
- For shadow metrics: use `evaluate_indicator_policy_shadow` and do not mutate enforcement state.
- For local-origin WAF decisions: keep the local code path intact, but do not conflate it with remote mesh advisory consumption.

If the WAF request path currently does not consume `ThreatIntelligenceManager` directly, do not force a new integration. The audit can conclude that the request/WAF path relies on block-store state rather than querying threat-intel. In that case, document the boundary:

- threat-intel may mutate block-store only through the gated mesh enforcement path;
- WAF request code consumes block-store as local enforcement state;
- raw DHT/local advisory lookup is not in the request path.

## Phase 6 — Add an Audit Note

Add a concise audit note to one of these locations:

Preferred: `architecture/threat_intel_request_waf_audit.md`

Alternative: a short section in `docs/THREAT_INTEL.md` if a new file feels excessive.

The audit note should include a small table:

| Surface | Finding | Classification | Required Action | Status |
|---------|---------|----------------|-----------------|--------|
| `handle_incoming_threat` | Mesh-sourced enforcement | enforcement | `PermitAction` gate | gated |
| `apply_sync` | Delegates to incoming threat handler | enforcement via delegation | same gate | gated |
| `hot threat gossip` | Delegates to incoming threat handler | enforcement via delegation | same gate | gated |
| request/WAF path | consumes block-store or strict lookup | enforcement | strict/gated only | audited |
| admin/debug/shadow | raw lookup allowed | diagnostics | no mutation | audited |

Use real file/function names from the audit rather than placeholder names where possible.

## Phase 7 — Tests / Verification

This pass may not require many new unit tests if no code path changes are needed. Still, add tests if the audit causes migrations.

Required if code changes occur:

- request/WAF actionability-sensitive lookup returns no enforcement result when policy context is absent;
- raw lookup still works in debug/admin context if covered by existing tests;
- local-origin detection still updates local block/rate-limit state as before;
- request/WAF path does not perform DHT lookup on the hot path.

Recommended verification commands:

- `cargo test -p synvoid-mesh threat_intel`
- any targeted WAF/request-path tests that cover block-store consumption;
- broader workspace test subset if compilation boundaries changed.

If CI is available, check the commit status. If no status checks are configured, mention that explicitly in the final implementation note.

## Acceptance Criteria

This pass is complete when:

1. `docs/THREAT_INTEL.md` no longer claims ASN attack/enforcement behavior that the code does not perform.
2. Diagrams and prose no longer imply that edge/origin nodes blindly apply remote DHT threat-intel.
3. `architecture/mesh_trust_domains.md` reflects advisory/canonical/enforcement planes and strict lookup guidance.
4. `AGENTS.md` or equivalent maintainer guidance warns against raw lookup enforcement.
5. Request/WAF surfaces have been audited for raw threat-intel use.
6. Any actionability-sensitive raw lookup use has been migrated to strict/policy-gated APIs.
7. The audit result is documented in a concise table with real surfaces and statuses.
8. Local-origin detection semantics are preserved.
9. No broad architecture churn is introduced.

## Suggested Implementation Order

1. Fix `docs/THREAT_INTEL.md` table and diagram drift.
2. Align `architecture/mesh_trust_domains.md` with the final three-plane model.
3. Add short agent/maintainer guidance.
4. Run the request/WAF grep audit.
5. Migrate any actionability-sensitive raw lookup call sites.
6. Add the audit note/table.
7. Add tests only if code migrations occur.
8. Run focused tests and record the result.

## Notes for the Implementer

Be conservative. The threat-intel enforcement path is now in good shape. This pass should prevent future misunderstanding and catch any request/WAF integration drift, not create another abstraction layer.

The key invariant to preserve is simple:

> Remote mesh threat-intel is advisory until canonical trust and the consumer gate permit enforcement. Request/WAF code must consume either local enforcement state or strict policy-gated threat-intel, never raw advisory lookups.
