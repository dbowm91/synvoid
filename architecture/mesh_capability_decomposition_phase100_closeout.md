# Phase 100 — Mesh Capability Decomposition Closeout

Status: implemented and closed 2026-09-29.

Capability inventory: `architecture/mesh_capability_map_phase100.md`.

## Landed changes

- `MeshTransport` now owns named `MeshApplicationCapabilities`,
  `MeshTransportLifecycle`, and `MeshPendingRequests` groups. Peer extensions
  use those typed groups for application services, lifecycle/task ownership,
  and query/response rendezvous. Constructor, regular clone, and maintenance
  clone preserve the previous sharing/reset behavior. The maintenance clone
  still omits its backend pool, and lifecycle clones still have distinct
  transition locks.
- `synvoid-upload` owns `YaraRuleSnapshotProvider`. Its production manifest no
  longer depends on `synvoid-mesh`; its `mesh` feature keeps the real manager
  only as a dev dependency for source-only reload tests. A root-owned adapter
  exposes the manager's approved current version and source.
- `synvoid-honeypot` owns `HoneypotThreatPublisher` and no longer has a
  production mesh dependency. A root-owned adapter maps local indicator type
  and severity vocabulary to the mesh protocol vocabulary.
- Honeypot scoring, deduplication, durable announced-key recording, disabled
  by-default behavior, actionable-score gate, site scope, TTL, and periodic
  runner task ownership are unchanged. Upload still compiles source text
  locally, keeps the old generation when acceptable source is unavailable,
  and retains the old generation on invalid source.
- The dependency-direction policy now forbids production mesh edges from
  upload and honeypot. Its source guard evaluates normal and build dependencies
  while intentionally excluding development-only provider fixtures.
- The new `mesh_application_capability_boundary` guard protects the named
  application, lifecycle, and pending-request group layouts from regression.

## Dependency and protocol audit

- `cargo tree -p synvoid-upload -e normal -i synvoid-mesh` and the equivalent
  honeypot probe both returned Cargo's expected “package ID did not match any
  packages” result, confirming no normal dependency path to full mesh.
- No wire types, protocol serialization, canonical/advisory trust decisions,
  freshness handling, replay ordering, consensus writes, or peer partition
  policy changed.
- Mesh proxy still owns its local proxy/cache execution bridge and consumes
  the canonical hop-by-hop header helper from `synvoid-proxy`; removing that
  dependency by copying header policy would violate the single-owner rule.
  Mesh proxy does not implement a separate restricted-IP classification path
  to migrate to `synvoid_core::net::is_restricted_ip`. The remaining
  proxy/cache coupling is explicit in the capability map for a future focused
  adapter design.
- `CanonicalTrustReader` and consensus transport seams remain in place. The
  aggregate changes do not introduce a new consensus crate or claim that
  consensus is already extracted. Phase 101 can now assess the boundary and
  choose retain/defer/extract using the new capability map.

## Performance and lifecycle

No lock, heap allocation, dynamic dispatch, or serialization was added to mesh
message dispatch or request lookup. The new grouping adds only typed field
selection, with no extra pointer indirection. This workspace has no mesh
microbenchmark target for the plan's listed peer dispatch/DHT/route/canonical/
proxy paths, so no before/after throughput delta is claimed. Existing full
mesh behavioral suites and the repository verification pipeline are used as
the regression evidence; Phase 101 must not treat this as a numerical
performance qualification.

Startup/rollback and task lifecycle remain owned by the same task group,
signals, generations, and reports. The full mesh tests and the root failure
injection tests in `cargo xtask verify` cover those invariants.

## Verification

- `cargo test -p synvoid-upload --profile ci --features mesh` — passed (130).
- `cargo test -p synvoid-honeypot --profile ci --features mesh` — passed (204).
- `cargo test -p synvoid-mesh --profile ci --features mesh` — passed (1,093).
- `cargo test --test boundary_composition_guard --profile ci` — passed (55).
- `cargo test --test mesh_id_boundary_guard --profile ci` — passed (5).
- `cargo test -p synvoid-repo-guards --test workspace_dependency_policy --test mesh_application_capability_boundary --profile ci` — passed (2).
- `cargo xtask test guards` — passed (112 repo guards, 647 root guards, 16 core/admin guards).
- `cargo check -p synvoid-mesh --profile ci --features mesh` — passed.
- `cargo check --no-default-features --features mesh --profile ci` — passed.
- `cargo check --no-default-features --features mesh,dns --profile ci` — passed.
- `cargo fmt --all -- --check` and `git diff --check` — passed.
- `cargo xtask verify` — passed on the completed Phase 100 implementation:
  all 10 steps passed (fmt, clippy, dependency policy, core compile, repo
  guards, security regression, root guards, core admin tests, admin contract,
  and failure injection); 66 admin-contract tests passed.

## Next phase

Phase 101 is unblocked: Phase 100's application dependency inversions and
field-level capability map are complete. Phase 101 must retain the explicit
proxy residual and quantify the mesh performance evidence gap instead of
assuming a broader consensus extraction is ready.
