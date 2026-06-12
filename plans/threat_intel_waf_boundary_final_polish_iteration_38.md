# Threat-Intel/WAF Boundary Final Polish — Iteration 38

## Purpose

The threat-intel/WAF boundary and BlockStore provenance work is effectively complete. Iteration 37 added mechanical raw lookup guardrails, explicit `BlockStore` provenance, `block_ip_with_provenance`, migrated production writers, helper renames, and documentation.

This final pass should be deliberately small. Its job is to close the few remaining polish gaps so this section can be treated as finished and we can move on to a different architectural target.

Primary polish targets:

1. Ensure type-erased WAF block-store paths can forward provenance instead of silently dropping it.
2. Audit remaining production `block_ip` calls and either migrate them or explicitly classify them as compatibility/legacy/test-only.
3. Tighten final docs/tests around provenance defaults, `LegacyUnknown`, and the source-scanning boundary guard.
4. Avoid adding new threat-intel architecture in this pass.

## Current State

Known good state:

- `BlockProvenanceKind` and `BlockProvenance` live in `synvoid-core`.
- `BlockEntry` has backward-compatible `#[serde(default)] provenance`.
- `BlockEntry::new` defaults to `LegacyUnknown`.
- `BlockEntry::new_with_provenance` records explicit provenance.
- `BlockStore::block_ip_with_provenance` writes explicit provenance.
- Mesh threat-intel enforcement writes `MeshThreatIntelPolicyGated` provenance.
- WAF/local/admin/supervisor/proxy production call sites were broadly migrated.
- Boundary guard tests reject raw threat-intel lookups in enforcement-sensitive paths.
- Docs and `AGENTS.md` now describe the boundary and provenance rules.

Known remaining polish:

- `ErasedBlockStore` currently exposes `block_ip` but not `block_ip_with_provenance`, even though `BlockListStore` supports provenance. If type-erased WAF code needs provenance-bearing writes, it should not be forced through the legacy method.
- The legacy `block_ip` method remains necessary for compatibility, but production uses should be scarce and classified.
- `LegacyUnknown` should be clearly limited to old persisted entries, compatibility wrappers, tests, or intentionally unclassified legacy paths.

## Non-Goals

Do not remove `block_ip`.

Do not remove raw threat-intel lookup APIs.

Do not add new threat-intel policy modes.

Do not add ASN/domain/URL/cert enforcement integration.

Do not create an audit-log/event-sourcing system.

Do not refactor WAF architecture beyond provenance forwarding and call-site cleanup.

## Phase 1 — Add Type-Erased Provenance Forwarding

Update `crates/synvoid-waf/src/traits.rs`.

Add a forwarding method to `ErasedBlockStore`:

```rust
pub fn block_ip_with_provenance(
    &self,
    ip: IpAddr,
    reason: &str,
    duration_secs: u64,
    scope: &str,
    provenance: BlockProvenance,
) {
    self.inner
        .block_ip_with_provenance(ip, reason, duration_secs, scope, provenance)
}
```

Rationale:

- `BlockListStore` already has a provenance-aware method.
- `BlockStoreAdapter` already forwards provenance to concrete `BlockStore`.
- The type-erased wrapper should not force callers back to the legacy provenance-dropping method.

Add a small unit test if the crate has an existing mockable test pattern. If no ergonomic test exists, at minimum ensure the method compiles and document the rationale in the code.

## Phase 2 — Audit Remaining `block_ip` Production Calls

Run a repository-wide search for direct legacy block writes:

- `.block_ip(`
- ` block_ip(`
- `fn block_ip(`
- `block_ip_with_provenance(`

Classify each `block_ip` result:

1. trait definition / compatibility wrapper;
2. tests / fixtures;
3. mitigation provider or external provider call, not `BlockStore` entry creation;
4. legacy compatibility path intentionally retained;
5. production enforcement writer that should migrate to `block_ip_with_provenance`.

Expected retained `block_ip` sites:

- `BlockStore::block_ip` itself;
- `BlockListStore::block_ip` trait compatibility method;
- default `BlockListStore::block_ip_with_provenance` fallback if intentionally retained;
- mitigation-provider calls inside `BlockStore` implementation;
- tests that explicitly validate legacy/default behavior.

Any production enforcement writer still calling legacy `block_ip` should either:

- migrate to `block_ip_with_provenance`, or
- receive a short comment explaining why provenance is intentionally unavailable.

Do not over-migrate third-party-style provider interfaces where provenance does not belong.

## Phase 3 — Tighten `LegacyUnknown` Semantics

Review all production appearances of `BlockProvenanceKind::LegacyUnknown` and `BlockProvenance::default()`.

Acceptable uses:

- serde/default backward compatibility for old persisted entries;
- legacy `BlockEntry::new` and `BlockStore::block_ip` compatibility paths;
- tests that validate old data still loads;
- mock/default trait implementations.

Suspicious uses:

- new production enforcement writers;
- WAF/local/admin/supervisor/proxy call sites where provenance is knowable;
- mesh threat-intel enforcement.

Migrate suspicious uses to a specific provenance kind.

Add or update tests to assert:

- missing `provenance` in old persisted JSON deserializes to `LegacyUnknown`;
- new provenance-aware writes do not default to `LegacyUnknown`;
- legacy wrapper behavior remains available and documented.

## Phase 4 — Final Boundary Guard Review

Review `tests/threat_intel_boundary_guard.rs`.

Polish targets:

- Confirm allowlist entries are narrowly scoped and still exist.
- Confirm denylist directories include the active request/WAF/proxy/HTTP3 surfaces.
- Consider adding `crates/synvoid-waf` to the denylist if it is not already covered and contains enforcement-sensitive WAF core paths.
- Consider adding `crates/synvoid-proxy` to the denylist if proxy request paths live there rather than only under `src/proxy`.

Do not make the guard noisy. The aim is to catch raw threat-intel lookup regressions in hot/enforcement surfaces, not to ban raw lookups in tests, diagnostics, docs, or explicitly allowlisted feed bookkeeping.

If new denylist directories are added, make sure the positive denylist coverage test still passes.

## Phase 5 — Documentation Polish

Update documentation only where it clarifies final state.

Suggested updates:

- `docs/THREAT_INTEL.md`
  - Clarify that `block_ip_with_provenance` is preferred for all new production block-store writes.
  - Clarify that `LegacyUnknown` is for backward compatibility and legacy wrappers, not new enforcement call sites.

- `architecture/threat_intel_request_waf_audit.md`
  - Add final note that type-erased WAF paths forward provenance.
  - Add final note that remaining legacy `block_ip` uses are compatibility/test/provider paths after audit.

- `AGENTS.md`
  - Make rule 6 concrete:
    - new production `BlockStore` writes should use `block_ip_with_provenance` with a meaningful `BlockProvenanceKind`;
    - `LegacyUnknown` is not acceptable for new production enforcement unless explicitly justified.

Keep all documentation changes short.

## Phase 6 — Final Test/Verification Pass

Run focused tests:

- boundary guard test;
- block-store provenance tests;
- threat-intel gating tests;
- WAF/block-store adapter tests if present.

Recommended commands:

```bash
cargo test --test threat_intel_boundary_guard
cargo test -p synvoid-block-store
cargo test -p synvoid-mesh threat_intel
cargo test --lib --no-run
```

If workspace-wide tests are too heavy, run the focused set and document what was run.

If GitHub status checks remain absent, mention that no GitHub CI status was available and rely on local command output in the implementation notes.

## Acceptance Criteria

This pass is complete when:

1. `ErasedBlockStore` forwards `block_ip_with_provenance`.
2. Remaining legacy `block_ip` call sites are audited and either migrated or classified.
3. `LegacyUnknown` is limited to backward compatibility, tests, legacy wrappers, or explicitly justified cases.
4. Boundary guard denylist/allowlist covers the active request/WAF/proxy/HTTP3 surfaces without excessive false positives.
5. Docs state that new production block writes require meaningful provenance.
6. Focused boundary/provenance/threat-intel tests pass, or any unavailable checks are explicitly documented.
7. No broad architecture churn is introduced.

## Suggested Implementation Order

1. Add `ErasedBlockStore::block_ip_with_provenance` forwarding.
2. Search and classify remaining `block_ip` call sites.
3. Migrate or document any remaining production legacy writers.
4. Search and classify `LegacyUnknown`/`BlockProvenance::default()` production use.
5. Review and tighten boundary guard denylist if needed.
6. Update docs/AGENTS with final concise guidance.
7. Run focused tests.

## Notes for the Implementer

This should be a closing pass. Prefer small, easily reviewable changes. The boundary model is already correct; the goal is to remove final ambiguity and reduce the chance that future edits accidentally drop provenance or reintroduce raw advisory lookups into enforcement-sensitive code.
