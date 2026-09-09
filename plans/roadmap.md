# SynVoid Architecture Hardening Roadmap

Status: extended roadmap. Tracks 1, 2, and 3 are complete. The only active handoff item is the Track 3 post-closure corrective pass (`plans/track3_post_closure_corrective.md`).

Scope: this roadmap covers architecture hardening, trust-boundary closure, verification, release readiness, post-hardening cleanup, and the architecture-convergence work required before another broad feature-expansion pass.

Primary principle: request path remains local, narrow, and capability-driven; control plane remains explicit, audited, and provenance-carrying; distributed mesh data remains policy-gated before it mutates enforcement state; runtime tasks remain owned and drainable; the root crate remains composition, not domain logic; public stability claims remain conservative until verified by tests and release policy.

## Current Architectural Position

SynVoid has completed the initial 10-phase architecture-hardening track and the six-phase post-hardening closure track. The repo now has typed startup/resource/runtime ownership for `UnifiedServer`, supervisor task ownership, request-path capability boundaries, blocklist convergence hardening, admin mutation authority types, plugin sandbox capability types, CI/fuzz/failure-injection scaffolding, security observability artifacts, final surface/release-hardening reports, a first root-module burn-down pass, and an operator deployment drill.

The remaining risk is concentrated rather than broad: enforcement semantics still overlap across adjacent detector/transport result types; the highest-coupling root modules remain mixed; process-jail modes are fail-closed stubs rather than operational isolation; distributed-state consistency guarantees are documented in several places rather than one binding namespace contract; and the final convergence work needs adversarial/performance evidence before compatibility surfaces can be retired confidently.

> **Post-Track-3 current state (supersedes the paragraph above):** the
> canonical enforcement contract exists (Phase 17); auth/challenge are
> canonical crate owners with root facades (Phase 18); WAF/HTTP mixed
> ownership is resolved into explicit composition-vs-domain boundaries
> (Phases 19–20); admin/plugin ownership is explicit (Phase 21); sandbox
> jail IPC is operational with versioned bounded supervised execution
> (Phase 22); the binding distributed-state contract exists
> (`architecture/distributed_state_contract.md`, Phase 23); zero
> `split_required` modules remain across all ledgers (Phases 21/24);
> routine CI (`cargo xtask verify`, single Ubuntu job in
> `.github/workflows/ci.yml`) passes on the final Track 3 commit
> `23949197311f1066abd4bc622c43cada615b1425`; only the corrective
> verification/documentation residuals in
> `plans/track3_post_closure_corrective.md` remain.

## Track 1: Architecture Hardening Baseline — Complete

Track 1 is the completed 10-phase line of work. Its plan files remain the canonical handoff detail for historical implementation and verification.

### Phase 1: Root Ownership Closure and Dependency Entitlement — Complete

Detailed plan: `plans/phase_01_root_ownership_dependency_entitlement.md`.

Result: root dependency ownership is documented and guarded; low-risk extraction started; root facades are classified; domain crates are guarded from importing root compatibility paths.

### Phase 2: UnifiedServer Startup Plan and Runtime Handle Ownership — Complete

Detailed plan: `plans/phase_02_unified_server_startup_runtime_ownership.md`.

Closure plan: `plans/unified_server_lifecycle_closure.md`.

Result: `UnifiedServer` startup validation, resource construction, runtime handles, plugin lifecycle ownership, registered task shutdown, and lifecycle guards are in place.

### Phase 3: Supervisor Lifecycle and Control-Plane Task Hardening — Complete

Detailed plan: `plans/phase_03_supervisor_lifecycle_hardening.md`.

Result: supervisor critical tasks are registered; shutdown causes and drain behavior are typed; supervisor spawn ownership is guarded.

### Phase 4: Request-Path Capability Boundary and Concrete Handle Reduction — Complete

Detailed plan: `plans/phase_04_request_path_capability_boundary.md`.

Result: request services consume narrow traits for threat/behavioral intelligence; request-path boundary guards prevent control-plane and raw threat-intel enforcement leakage.

### Phase 5: Blocklist Convergence, Replay, and Ordering Hardening — Complete

Detailed plan: `plans/phase_05_blocklist_convergence_hardening.md`.

Result: peer cursors, source-scoped ordering metadata, stale replay prevention, snapshot fallback, and convergence docs/tests are in place.

### Phase 6: Admin and Control-Plane Authority Hardening — Complete

Detailed plan: `plans/phase_06_admin_control_plane_authority_hardening.md`.

Result: typed mutation authority, mutation outcomes, propagation status, audit event types, and blocklist/admin mutation tests are in place. Track 2 closed the remaining legacy endpoint residuals.

### Phase 7: Plugin Runtime, Sandbox, and Capability Manifest Hardening — Complete

Detailed plan: `plans/phase_07_plugin_runtime_sandbox_hardening.md`.

Result: plugin trust tiers, manifest schema, default-deny capabilities, filesystem/network validation, invocation limits, failure isolation, and call-site capability gating are present. Track 2 completed signing/loader follow-up.

### Phase 8: Feature Profile CI, Fuzzing, and Failure Injection — Complete

Detailed plan: `plans/phase_08_ci_fuzz_failure_injection_hardening.md`.

Result: CI workflow, verification script, docs path guard, fuzz target inventory, fuzz targets, and failure-injection tests exist. Track 2 added bounded fuzz/CI closure.

### Phase 9: Observability as a Security Boundary — Complete

Detailed plan: `plans/phase_09_observability_security_boundary.md`.

Result: security observability docs, metrics, admin observability handler, runtime/admin/blocklist/plugin/threat-policy signals, and observability guard are in place.

### Phase 10: Final Public Surface Audit and Release Hardening — Complete

Detailed plan: `plans/phase_10_final_surface_audit_release_hardening.md`.

Result: public surface audit, release-hardening report, semver/stability policy, and final verification cleanup report exist.

## Track 2: Post-Hardening Closure — Complete

Track 2 converted the hardened architecture into a more operationally verified and maintainable baseline.

### Phase 11: CI Execution and Release Verification Closure — Complete

Result: CI triggers/summary behavior and architecture verification were reconciled; release artifacts no longer overstate unobserved CI evidence.

### Phase 12: Admin Legacy Endpoint Mutation/Audit Closure — Complete

Result: remaining admin mutation paths were reconciled with typed mutation/audit semantics or explicitly classified as read-only diagnostics.

### Phase 13: Plugin Signature Verification and Loader Trust Audit — Complete

Result: signed plugin trust and loader development-mode boundaries were hardened and tested according to the Track 2 plan.

### Phase 14: Fuzz Smoke Execution and Parser Boundary Expansion — Complete

Result: fuzzing moved from inventory-only scaffolding toward bounded execution/coverage, with remaining parser-specific work delegated to later focused phases where necessary.

### Phase 15: Transitional Root Module Burn-Down Track — Complete for Initial Pass

Detailed plan: `plans/phase_15_transitional_root_module_burndown.md`.

Result: `platform`, `utils`, and `tarpit` were reduced/reclassified, duplicate/dead root code was removed, and the remaining high-risk mixed modules were deliberately deferred rather than extracted unsafely.

### Phase 16: Runtime Operations Readiness and Deployment Drill — Complete

Detailed plan: `plans/phase_16_runtime_operations_deployment_drill.md`.

Result: operator start/stop/reload/status, enforcement, plugin-failure, mesh, and degraded-feature workflows have an explicit drill/verification contract.

## Track 3: Architecture Convergence and Underdeveloped Boundary Closure — Complete

Track 3 is complete through Phase 24. It was completed before broad feature expansion. The objective was not to add another set of subsystems; it was to make the existing subsystem set compose through fewer canonical contracts and to close the largest remaining implementation-vs-architecture gaps.

### Phase 17: Canonical Request Enforcement Decision Contract

Detailed plan: `plans/phase_17_enforcement_decision_contract.md`.

Goal: define one canonical enforcement classification, source/provenance vocabulary, reason coding, and deterministic precedence contract across WAF, rate limiting, bots, flood protection, block state, challenges, HTTP, streaming, and protocol adapters.

Key result required: detector-specific evidence can remain domain-specific, but terminal action semantics cannot evolve independently in multiple enums or through undocumented early-return order.

### Phase 18: Authentication and Challenge Boundary Extraction

Detailed plan: `plans/phase_18_auth_challenge_boundary_extraction.md`.

Goal: move authentication/session/CSRF/lockout behavior to a canonical domain owner and finish challenge-manager ownership so WAF/admin no longer depend on root implementations merely because those types were never extracted.

Key result required: root `auth` and `challenge` become thin facades or precisely justified composition adapters with no duplicated domain implementation.

### Phase 19: WAF Ownership Convergence and Root Composition Reduction

Detailed plan: `plans/phase_19_waf_ownership_convergence.md`.

Goal: make `synvoid-waf` the canonical owner of reusable WAF policy/detection logic, remove root/crate duplicates and dead hot-path compatibility checks, and reduce root `WafCore` to clearly defined composition if it cannot move cleanly.

Key result required: `waf` is no longer `split_required` because of ambiguous ownership.

### Phase 20: HTTP Normalization, Dispatch, and Ownership Convergence

Detailed plan: `plans/phase_20_http_normalization_ownership_convergence.md`.

Goal: establish one canonical HTTP parsing/normalization/framing/body-policy path, remove root/crate duplication, and close adjacent `tls`/`http_client` mixed ownership after HTTP boundaries settle.

Key result required: routing and WAF evaluate the same security-relevant normalized request representation, with ambiguity failing closed.

### Phase 21: Admin and Plugin Root-Boundary Closure

Detailed plan: `plans/phase_21_admin_plugin_root_boundary_closure.md`.

Goal: leave admin as deliberate transport/control-plane composition over typed domain operations and plugin as application lifecycle composition over `synvoid-plugin-runtime`, then reconcile all remaining root-module classifications.

Key result required: module size alone is not treated as debt; only genuine mixed ownership remains `split_required`, and all architecture ledgers agree.

### Phase 22: Sandbox Jail IPC and Runtime Closure

Detailed plan: `plans/phase_22_sandbox_jail_ipc_runtime_closure.md`.

Goal: replace the current WASM/YARA jail fail-closed stubs with versioned, bounded, supervised out-of-process execution using a minimal local IPC protocol and explicit required-isolation failure semantics.

Key result required: real workload round trips execute inside the jail, while launch/protocol/runtime failure cannot silently fall back to unisolated execution when isolation is required.

### Phase 23: Distributed State Consistency and Partition-Semantics Contract

Detailed plan: `plans/phase_23_distributed_state_consistency_contract.md`.

Goal: define authority, consistency, versioning, TTL, conflict, partition-read/write, and enforcement semantics for every security-relevant replicated namespace, and reconcile current Raft behavior with stale/remaining MESH-15 documentation.

Key result required: canonical and advisory state cannot be confused during partition or rejoin, and operator mutation results describe local/best-effort/canonical completion truthfully.

### Phase 24: Adversarial Verification, Performance Baselines, and Surface Closure — Complete

Detailed plan: `plans/phase_24_adversarial_performance_surface_closure.md`.

Goal: add only the focused hostile-input, concurrency, state-machine, and performance evidence needed for the Track 3 refactors, remove stale benchmark/compatibility artifacts, audit crate granularity, and reconcile final root/public surface documentation.

Result: Track 3 invariant suites (`track3_invariant_closure`, `http_differential_closure`, `track3_concurrency_closure`), 3 bounded fuzz targets at the uncovered boundaries, 5 new hot-path benchmark groups with closure baselines (`architecture/track3_performance_report.md`), stale artifacts removed (empty `synvoid-testkit` dir, dead bench TODO, toy microbenchmark), crate granularity audit with no merges (`architecture/crate_granularity_audit.md`), and zero-`split_required` agreement across all ledgers. Routine CI gains 7 fast suites in the existing consolidated invocation (no new jobs).

## Track 3 Dependency Order

Default execution order:

1. Phase 17 — enforcement semantics first; later request-path moves depend on this contract.
2. Phase 18 — remove auth/challenge root ownership blockers.
3. Phase 19 — converge WAF ownership on the settled contracts.
4. Phase 20 — converge HTTP/TLS/client ownership after WAF semantics are stable.
5. Phase 21 — close admin/plugin root boundaries against the canonical domain APIs.
6. Phase 22 — operationalize process isolation once plugin/runtime ownership is clear.
7. Phase 23 — consolidate distributed-state semantics and partition evidence.
8. Phase 24 — final adversarial/performance/surface closure.

Safe parallelism:

- Phase 23 can begin its namespace/document inventory while Phases 18–21 are underway, but code changes to enforcement/control-plane result types should wait for Phase 17.
- Phase 22 protocol design can begin before Phase 21 completes, but plugin call-site migration should use the final plugin ownership boundary.
- Phase 24 inventory/baseline capture can begin early; final regression conclusions and surface cleanup must wait until Phases 17–23 land.

Do not run Phases 19 and 20 as one giant mechanical file move. Each phase should leave tests and architecture ledgers coherent.

## Track 3 Global Acceptance Criteria

Track 3 is complete only when:

- one canonical enforcement classification/source/reason/precedence contract governs terminal request outcomes;
- duplicate terminal-action vocabularies are removed or reduced to exhaustive adapters;
- authentication and challenge domain behavior have canonical owners outside ambiguous root implementations;
- WAF reusable policy/detection logic has one canonical owner and active request paths contain no known no-op placeholder checks;
- HTTP security normalization/framing/body policy has one canonical implementation shared consistently by routing/WAF paths;
- root `http`, `waf`, `auth`, `challenge`, `tls`, `http_client`, `admin`, and `plugin` are no longer ambiguously mixed, or any residual has a precise blocker and named follow-up;
- WASM/YARA jail modes execute real bounded workloads through supervised IPC and fail closed when required isolation is unavailable;
- every security-relevant replicated namespace has explicit authority, consistency, ordering, expiry, conflict, and partition behavior;
- canonical distributed trust never falls back silently to advisory/DHT authority during partition;
- targeted adversarial/concurrency tests cover the new canonical boundaries;
- hot-path benchmarks show no material unexplained regression from convergence work;
- crate-granularity audit distinguishes useful isolation boundaries from thin organizational crates without forcing a merge sweep;
- root-module ledger, burn-down report, dependency ownership, final surface audit, and release-hardening docs agree;
- routine CI remains proportionate to the project rather than growing into a new broad verification matrix.

## Track 3 Rejection Criteria

Reject a Track 3 closeout that:

- treats file movement as ownership closure while duplicate logic remains live;
- weakens request-path capability or canonical mesh trust boundaries;
- changes enforcement precedence accidentally through refactoring;
- creates new crates solely to reduce root LOC;
- makes HTTP routing and WAF normalize security-relevant input differently without explicit tests;
- marks jail mode operational without real WASM/YARA round trips and failure-isolation tests;
- reports distributed best-effort propagation as canonical commit success;
- merges crates solely to lower crate count;
- declares completion while architecture ledgers disagree or `split_required` entries have no precise blocker.

## Roadmap Status

Track 1: Complete.

Track 2: Complete through Phase 16.

Track 3: Complete through Phase 24 (adversarial/performance/surface closure recorded in `architecture/track3_performance_report.md` and `architecture/crate_granularity_audit.md`; ledgers agree on zero `split_required`).
