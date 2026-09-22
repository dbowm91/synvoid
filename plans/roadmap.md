# SynVoid Architecture Hardening Roadmap

Status: Tracks 1-3 and their corrective closures remain complete. Phases 41-48 of the runtime-truthfulness/security/publication campaign are complete (see `architecture/runtime_truthfulness_security_publication_closeout.md`). The post-Phase-48 performance optimization campaign (Phases 49-55) remains complete; Phases 56–57 corrective closure is implemented and closed (Phase 56 `57ad3158754b2f4851e1ce408043d33104106974`, Phase 57 proof-bearing `5212c6862426ee17795994ef1bba590113c52fad`). Eggfetch 0.2 transport consolidation is implemented through Phase 60 (`7a6c617c...`) but final closeout is reopened: the Phase 61 record at `f62bb285...` is superseded for current status by active Phase 62 policy-keying/TLS-failure/evidence corrective work.

Scope: this roadmap covers architecture hardening, trust-boundary closure, verification, release readiness, post-hardening cleanup, and the architecture-convergence work required before another broad feature-expansion pass.

Primary principle: request path remains local, narrow, and capability-driven; control plane remains explicit, audited, and provenance-carrying; distributed mesh data remains policy-gated before it mutates enforcement state; runtime tasks remain owned and drainable; the root crate remains composition, not domain logic; public stability claims remain conservative until verified by tests and release policy.

## Current Architectural Position

SynVoid has completed the initial 10-phase architecture-hardening track and the six-phase post-hardening closure track. The repo now has typed startup/resource/runtime ownership for `UnifiedServer`, supervisor task ownership, request-path capability boundaries, blocklist convergence hardening, admin mutation authority types, plugin sandbox capability types, CI/fuzz/failure-injection scaffolding, security observability artifacts, final surface/release-hardening reports, a first root-module burn-down pass, and an operator deployment drill.

Post-Track-3 plus post-closure corrective state: canonical terminal enforcement semantics are established; auth/challenge domain ownership is canonical outside the root facade; WAF and HTTP ownership boundaries are explicit and guarded; admin/plugin are deliberate application-composition owners; jail IPC is operational with bounded supervised execution and fail-closed required-isolation semantics; distributed-state authority/partition contracts are explicit; zero active `split_required` modules remain; config parse/validation is covered by the final high-value fuzz target; the stale `serder` root surface is removed; routine CI remains one Ubuntu `cargo xtask verify` job; full/release verification and final bounded fuzz evidence are recorded in `architecture/track3_post_closure_corrective_report.md`.

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

Post-Track-3 corrective closure: complete; see `plans/track3_post_closure_corrective.md` and `architecture/track3_post_closure_corrective_report.md`.


## Post-Phase-40 Campaign: Runtime Truthfulness, Security Hardening, and Publication Readiness — Complete

Status: Phases 41-47 implemented; Phase 48 corrective closeout complete.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md` (completed historical record).

Closeout: `architecture/runtime_truthfulness_security_publication_closeout.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

This campaign begins after the Phase 32-40 boundary/security work. It does not reopen the completed ownership decisions. It closes newly identified runtime truthfulness and security residuals, then evaluates a small set of reusable crates for an explicit external support contract.

Execution order:

1. Phase 41 — fail-closed configuration and process bounds.
2. Phase 42 — shared-memory unsafe-boundary hardening.
3. Phase 43 — authentication CPU isolation and durable persistence.
4. Phase 44 — PQC dependency truth and KyberSlash closure.
5. Phase 45 — DNS runtime-contract and protocol-completeness closure.
6. Phase 46 — platform sandbox truthfulness and macOS closure.
7. Phase 47 — public-crate release readiness.
8. Phase 48 — corrective campaign closeout and planning/status/evidence reconciliation.

Detailed plans:

- `plans/phase_41_fail_closed_config_and_process_bounds.md`
- `plans/phase_42_shared_memory_unsafe_boundary_hardening.md`
- `plans/phase_43_auth_cpu_and_persistence_hardening.md`
- `plans/phase_44_pqc_dependency_truth_and_kyberslash_closure.md`
- `plans/phase_45_dns_runtime_contract_and_protocol_completeness.md`
- `plans/phase_46_platform_sandbox_truthfulness_and_macos_closure.md`
- `plans/phase_47_public_crate_release_readiness.md`
- `plans/phase_48_runtime_truthfulness_campaign_corrective_closeout.md`

The current architecture remains the baseline: no broad crate split/merge campaign, no public `synvoid-utils`, no in-place mesh restart implementation in this line, and no independently supported public `synvoid-http-client` until the current eggfetch line is re-evaluated. Phase 48 owns closeout/status reconciliation only; it must not turn that pending eggfetch comparison into an implicit migration.

## Post-Phase-48 Campaign: Performance Optimization and Request-Path Efficiency — Complete

Status: implemented and closed; retained as historical handoff detail.

Roadmap: `plans/performance_optimization_roadmap.md` (historical).

Closeout: `architecture/performance_optimization_closeout.md` (before/after evidence, hypothesis dispositions, residuals).

Baseline reviewed: `70d2bb29de30d2e5f66fd9cb24d682f5e2054670` (2026-09-19).

This campaign is measurement-first and does not reopen the completed ownership/security campaigns. Its purpose is to improve measured throughput, tail latency, allocator pressure, event-loop fairness, and memory efficiency while preserving the existing public API/config/protocol/security/observability capability.

Execution order:

1. Phase 49 — performance measurement and benchmark truth.
2. Phase 50 — WAF execution-model optimization.
3. Phase 51 — request-path allocation and upstream-selection optimization.
4. Phase 52 — metrics and plugin telemetry hot-path optimization.
5. Phase 53 — blocking persistence and honeypot I/O isolation.
6. Phase 54 — buffer-pool and streaming-memory efficiency.
7. Phase 55 — performance qualification and closeout.

Detailed plans:

- `plans/phase_49_performance_measurement_and_benchmark_truth.md`
- `plans/phase_50_waf_execution_model_optimization.md`
- `plans/phase_51_request_path_allocation_and_upstream_selection.md`
- `plans/phase_52_metrics_and_plugin_telemetry_hot_path.md`
- `plans/phase_53_blocking_persistence_and_honeypot_io_isolation.md`
- `plans/phase_54_buffer_pool_and_streaming_memory_efficiency.md`
- `plans/phase_55_performance_qualification_and_closeout.md`

Campaign constraints: no detector/capability removal for benchmark wins; no public signature/type churn solely for optimization; no load-balancing policy changes; no metric-name/payload regressions; no unbounded blocking/offload queues; no buffer-pool public semantic break. Phase 49 evidence gates production refactors, and Phase 55 owns final same-host before/after evidence and planning closeout.

## Phase 56 Corrective Follow-up: Performance Runtime and Evidence Closure — Historical

Status: implemented at `57ad3158754b2f4851e1ce408043d33104106974`; retained as historical handoff detail. Final closure was completed by Phase 57. Existing Phase 56 writer, maintenance, `TeeBody`, and evidence fixes remain valid and unchanged in contract.

Evidence:
`architecture/performance_optimization_corrective_closeout.md`.

Detailed plan:
`plans/phase_56_performance_campaign_corrective_runtime_and_evidence_closure.md`.

Baseline: `92f606b95ee9bb55c5d61115de04e70cebdfe288`.

This is a narrow corrective pass after the completed Phase 49-55 performance
campaign. It does not reopen the performance architecture. It owns:

- race-free/stateful `HoneypotWriter::shutdown()` completion across clones;
- runner-owned honeypot maintenance with no initial overlap or detached
  periodic task after shutdown;
- strict `TeeBody` enforcement of the bytes reserved from
  `GlobalCacheGovernor`, with exact-once release on cache abandonment;
- immutable benchmark/provenance requalification and host/target correction;
- final corrective closeout evidence.

The known isolated 10 KiB WAF latency tradeoff remains an explicit measured
residual unless new event-loop evidence justifies a separate WAF scheduling
plan. Phase 56 did not broaden into detector, buffer-pool, upstream-routing,
or public-API redesign.

## Phase 57 Final Corrective Closeout: Runner Lifecycle and Evidence Truth — Implemented/Closed

Status: implemented/closed. Proof-bearing implementation/qualification SHA: `5212c6862426ee17795994ef1bba590113c52fad`.

Detailed plan:
`plans/phase_57_performance_final_corrective_closeout.md`.

Baseline:
`57ad3158754b2f4851e1ce408043d33104106974`.

This was the final narrow closeout pass for the Phase 49-56 performance line.
It owned only:

- durable real-runner shutdown so an early `stop()` cannot be lost;
- lifecycle-state separation so teardown cannot expose the instance for a
  second overlapping `run()`;
- direct tests of the public `PortHoneypotRunner::run()/stop()/is_running()`
  state machine, rather than helper-only lifecycle tests;
- immutable WAF-concurrency 1/8/32/128 baseline requalification;
- Phase 56/57 status and proof-bearing-SHA reconciliation.

It did not reopen WAF design, `TeeBody`, buffer-pool, upstream-selection, or
public API architecture. Phase 56's landed writer-shutdown and cache-governor
fixes remain in force. No active performance-corrective handoff remains.


## Post-Phase-57 Campaign: Eggfetch 0.2 Transport Consolidation — Active

Status: implementation adopted through Phase 60; Phase 61 closeout reopened; Phase 62 corrective active. Production remains on eggfetch while the corrective closes registry policy isolation, invalid-policy failure semantics, and missing evidence.

Roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Research handoff: `plans/eggfetch_current_line_parity_review.md`.

Baseline reviewed: `e3026667c23e6e0e92ee30d13c53baf2e68c5c77` (2026-09-22).

Target upstream: `eggfetch-core 0.2.0` / `v0.2.0`.

The Phase 34 retain-`synvoid-http-client` decision remains valid historical evidence for eggfetch 0.1.4, but it is no longer a current capability comparison. Eggfetch 0.2.0 now exposes generic native `http_body::Body` execution, explicit Rustls provider injection, chain-preserving hostname-skip control, direct UDS/advanced routing, and resolved-target reuse. The remaining adoption risk is therefore exact SynVoid compatibility/security/performance behavior rather than obvious missing transport primitives.

Execution order:

1. Phase 58 — pin/qualify eggfetch 0.2.0, re-run the capability matrix, prove aws-lc/PQ/TLS/body/UDS/pool semantics, and classify every existing public `synvoid-http-client` export.
2. Phase 59 — introduce an eggfetch-backed native transport lane behind the existing neutral SynVoid policy model and run differential parity against the legacy lane.
3. Phase 60 — migrate production consumers in bounded batches, then retire only redundant legacy transport machinery that is not required by the compatibility contract.
4. Phase 61 — initial security/profile/API closeout attempt; later reopened by the post-closeout audit.
5. Phase 62 — policy-aware registry correction, invalid-TLS-policy fail-closed correction, immutable transport benchmark, full/release verification, and final status reconciliation.

Detailed plans:

- `plans/phase_58_eggfetch_0_2_qualification_and_compatibility.md`
- `plans/phase_59_eggfetch_native_transport_adapter.md`
- `plans/phase_60_eggfetch_consumer_migration_and_legacy_transport_retirement.md`
- `plans/phase_61_eggfetch_transport_qualification_and_closeout.md`
- `plans/phase_62_eggfetch_policy_keying_and_evidence_corrective_closeout.md`

Campaign constraints:

- no weakening aws-lc/PQ, CA, hostname, SNI, or fail-closed TLS behavior;
- no buffering of true streaming WAF/H3 request bodies;
- no migration of retry/upstream/WAF/cache policy into eggfetch;
- no outbound H3 requirement introduced by this work;
- no public concrete type/signature change disguised as an implementation swap;
- no permanent dual active generic transport ownership;
- `synvoid-http-client` remains internal unless a future separate publication decision says otherwise.

The campaign may terminate after Phase 58 on a retained branch if executable evidence shows a security, dependency, or API-compatibility blocker. That is a valid closeout; do not force adoption merely because the upstream feature list is broader.
