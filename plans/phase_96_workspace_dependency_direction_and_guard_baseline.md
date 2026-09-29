# Phase 96 Plan: Workspace Dependency Direction and Guard Baseline

Status: implemented and closed 2026-09-28; evidence: `architecture/workspace_dependency_direction_phase96_closeout.md`.

Registered in: plans/roadmap.md and plans/architecture_maintenance_auditability_roadmap.md.

Baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2.

Depends on: none. This is the first phase of the post-95 architecture-maintenance campaign.

## Goal

Remove the clearest avoidable upward domain dependencies, establish machine-enforced workspace dependency-direction rules, and freeze behavioral labels/contracts before the larger boundary moves.

This phase must not add or remove runtime features.

## Current-head findings

1. synvoid-metrics imports synvoid_waf::attack_detection::config::AttackType. The metrics payload sent through IPC/admin already serializes blocked_by_type as HashMap<String, u64>; the WAF enum is needed only as the in-memory DashMap key.
2. synvoid-block-store imports synvoid_waf::mitigation::{MitigationProvider, SizedMitigationProvider}. The trait is generic IP mitigation: block_ip, unblock_ip, and provider name. Block-store already depends on synvoid-core.
3. synvoid-mesh calls synvoid_proxy::headers::is_private_ip even though that proxy helper delegates directly to synvoid_core::net::is_restricted_ip.
4. synvoid-mesh also uses proxy hop-by-hop header classification. Do not solve that by pushing HTTP types into synvoid-core; retain the edge temporarily if a clean application adapter is not ready. Phase 100 owns the mesh/proxy integration decomposition.
5. Current architecture guards are strong around root ownership but do not provide a single workspace-wide forbidden-edge policy for low-capability crates.

## Workstream A — remove metrics dependency on WAF domain types

Make synvoid-metrics store a transport/observability key rather than AttackType.

Preferred shape:

- blocked counters keyed by a bounded string/label type owned by metrics, or a string key with explicit cardinality limits;
- WAF owns the exhaustive AttackType -> stable metric label mapping;
- request/WAF composition passes the label to metrics;
- payload names remain byte-for-byte/string-for-string equivalent to current operator-visible values unless an existing naming bug is separately documented.

Do not move AttackType into synvoid-core merely to satisfy dependency direction. AttackType is WAF-domain vocabulary.

Add tests pinning every current AttackType label and payload representation so dashboards/admin statistics do not silently change.

After migration, synvoid-metrics must have no synvoid-waf dependency.

## Workstream B — move the neutral mitigation contract below WAF

Move the application-neutral IP mitigation trait contract to synvoid-core, for example under synvoid_core::mitigation.

The low-level contract should contain only what both WAF and block-store require:

- block_ip(ip, reason, duration)
- unblock_ip(ip)
- provider name/identity if still useful

Keep concrete NoOp/Logging/kernel providers and any global WAF compatibility registry in their current domain owners unless evidence supports a different owner.

synvoid-waf should re-export the neutral trait for workspace compatibility where cheap. synvoid-block-store should depend directly on the neutral contract and must no longer import synvoid-waf.

Preserve all current block/unblock invocation ordering, durations, reasons, and failure behavior.

## Workstream C — remove the trivial mesh private-IP dependency path

Replace mesh use of synvoid_proxy::headers::is_private_ip with the canonical synvoid_core::net::is_restricted_ip helper, preserving exact current semantics.

Do not duplicate address-range tables.

The remaining mesh-to-proxy edge for actual HTTP proxy integration/header sanitization is explicitly deferred to Phase 100 unless it can be removed with a narrow adapter without broadening Phase 96.

## Workstream D — manifest entitlement and unused-edge audit

Recompute direct internal dependencies for every workspace crate.

For touched crates, verify source entitlement rather than only manifest presence. Remove dependencies that have zero production/test/build use after accounting for feature-gated paths.

In particular re-check:

- synvoid-ipc -> synvoid-config, because current source search did not identify an obvious direct use;
- stale crypto dependencies in synvoid-config, without removing anything required by feature-gated mesh paths before Phase 99;
- duplicate direct dependencies where one canonical lower-level crate already supplies the functionality.

Do not remove a dependency based solely on text search; confirm cargo metadata/features/tests first.

## Workstream E — workspace dependency-direction guard

Add a checked-in, machine-readable dependency policy consumed by the existing repo-guard/test infrastructure.

At minimum encode:

- synvoid-core and synvoid-utils cannot depend on domain engines;
- synvoid-metrics cannot depend on WAF/proxy/mesh/admin;
- synvoid-block-store cannot depend on synvoid-waf after this phase;
- synvoid-mesh-protocol remains a low-capability leaf with its existing budget;
- synvoid-dnssec-keystore, synvoid-yara, synvoid-rate-limit, synvoid-native-extension retain their existing dependency-budget invariants;
- later phases may extend the policy for synvoid-jail-protocol and synvoid-config-model.

The policy should report the exact forbidden edge and owning rule. Avoid a brittle hard-coded complete graph that makes every legitimate new dependency require unrelated edits.

## Required tests and verification

At minimum:

    cargo test -p synvoid-metrics --profile ci
    cargo test -p synvoid-block-store --profile ci
    cargo test -p synvoid-waf --profile ci
    cargo test -p synvoid-mesh --profile ci --features mesh
    cargo xtask test guards
    cargo check --no-default-features --profile ci
    cargo check --no-default-features --features mesh --profile ci
    cargo xtask verify

Also run cargo metadata/cargo tree checks proving the intended edges are gone.

## Acceptance criteria

- synvoid-metrics has no synvoid-waf edge.
- Existing blocked-by-type metric labels and payloads remain equivalent.
- synvoid-block-store has no synvoid-waf edge.
- The mitigation provider contract has one neutral owner and concrete behavior is unchanged.
- Mesh private-IP checks use the canonical core helper.
- No unsupported mesh/proxy duplication is introduced.
- A workspace dependency-direction guard is active.
- No feature/default/config/runtime behavior changes.
- Architecture dependency documentation is updated to the landed graph.

## Rejection criteria

Reject the phase if it:

- moves WAF-domain enums wholesale into synvoid-core;
- stores unbounded attacker-controlled strings as metric keys;
- changes block durations/reasons/failure policy;
- duplicates private-IP or hop-by-hop classification lists;
- forces mesh HTTP integration cleanup before a narrow adapter is proven;
- removes a dependency based only on grep;
- expands routine CI into a broad matrix.
