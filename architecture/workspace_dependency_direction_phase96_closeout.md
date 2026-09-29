# Phase 96 — Workspace Dependency Direction Closeout

Status: implemented and closed 2026-09-28.

## Landed changes

- `synvoid-metrics` stores bounded static metric labels and no longer depends on
  `synvoid-waf`. `AttackType::metrics_label()` remains WAF-owned and its mapping
  pins the existing `Debug` names used in payloads.
- The neutral `MitigationProvider` contract is owned by
  `synvoid_core::mitigation`; WAF re-exports it for compatibility and
  block-store owns its local trait-object wrapper. `synvoid-block-store` no
  longer depends on `synvoid-waf`.
- Mesh SSRF checks use `synvoid_core::net::is_restricted_ip`; proxy's helper
  already delegates to the same canonical implementation.
- `architecture/workspace_dependency_policy.toml` is enforced by the
  `workspace_dependency_policy` repo-guard. It records focused forbidden
  edges for low-capability crates and existing protocol/security leaves.
- The crate-granularity audit now records metrics' neutral dependency set.

## Dependency audit

`cargo metadata --no-deps` was recomputed. The direct `synvoid-ipc` →
`synvoid-config` dependency remains required: production process-manager IPC
APIs carry `ProcessManagerConfig` and `SupervisorConfig` values. Metrics and
block-store have no resolved path to WAF after removal of their direct edges.
The proxy dependency of mesh remains for actual HTTP proxy integration and
header policy; Phase 100 owns that decomposition. No unverified crypto or
feature-gated configuration edge was removed.

## Verification

- `cargo test -p synvoid-metrics --profile ci` — passed (34 tests).
- `cargo test -p synvoid-block-store --profile ci` — passed (182 tests).
- `cargo test -p synvoid-waf --profile ci` — passed (336 tests).
- `cargo test -p synvoid-mesh --profile ci --features mesh` — passed (1090 tests).
- `cargo test -p synvoid-repo-guards --profile ci` — passed (109 tests, including
  the new dependency policy guard).
- `cargo check --no-default-features --profile ci` — passed.
- `cargo check --no-default-features --features mesh --profile ci` — passed.
- `cargo fmt --all` and `git diff --check` — passed.

The first metrics build after removing WAF exposed an undeclared serde feature
dependency on chrono; metrics now declares it directly. The initial
`cargo tree -i synvoid-waf` probe returned Cargo's expected “package not found
in graph” result for both affected crates, confirming the removed reverse
edges.

## Next phase

Phase 97 is unblocked. Its sole prerequisite, Phase 96's dependency-direction
baseline and active guard, is complete. Phases 98–100 remain ordered behind
their stated prerequisites; Phase 101 remains the campaign qualification.
