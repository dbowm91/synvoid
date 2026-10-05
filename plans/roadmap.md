# SynVoid Architecture Hardening Roadmap

Status: DNS startup-truthfulness and provider-inversion Phases 131–136 are **ACTIVE / REGISTERED** (2026-10-05; umbrella `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`; Phase 131 conformance determinism, Phase 132 authoritative zone startup activation, Phases 131/132/133 **CLOSED QUALIFIED** (Phase 133 returned **GO for TLS and GeoIP**, closeout `architecture/dns_provider_inversion_phase133_closeout.md`, and recorded two high-severity findings — F-1 a config-reachable `GeoIpManager::new` panic, F-2 a GeoLocation block rule that silently allows traffic without a provider — as mandatory Phase 135 workstreams), Phases 134/135 TLS and GeoIP inversion now unblocked, Phase 136 terminal qualification; `synvoid-dns` remains class 1 at 4 direct SynVoid normal edges, mesh inversion out of scope). DNS runtime-DTO conversion Phases 125–130 are **COMPLETE** (2026-10-05; umbrella `plans/dns_runtime_dto_conversion_roadmap.md`; all six phases **CLOSED QUALIFIED**; closeouts `architecture/dns_runtime_dto_phase12{5,6,7,8,9}_closeout.md` and `..._phase130_closeout.md`. Outcome: 7 -> 4 direct SynVoid normal edges (838 -> 827 expanded lines); provider-inversion readiness **DEFER**; `synvoid-dns` remains class 1). Phase 124 post-standalone documentation/evidence reconciliation is **CLOSED QUALIFIED** (2026-10-04; docs/evidence only; plan `plans/phase_124_post_standalone_documentation_evidence_reconciliation.md`; closeout `architecture/standalone_crate_phase124_closeout.md`). The standalone-capable crate campaign (Phases 115–123) remains closed with unchanged dispositions, and the merged-main exact-head proof is now recorded: hosted CI run `37218651222` passed `ci` and `dependency-security` on merge head `cacd44bffe097d7c62e3ddb0c5816967498a7bde`, separate from the campaign-branch proof at `f81182149889e21c4908b7ee38c74bc6b4518f6b` (run `37064917481`). Phase 124 unblocks no successor extraction or promotion plan. The subsystem-boundary/extraction campaign (Phases 105–112) is CLOSED QUALIFIED as of 2026-10-02; umbrella: `plans/subsystem_boundary_extraction_roadmap.md`; proof-bearing SHA `e7c0ec5a1317599b6f98e37a534b53544842a29c`, hosted CI/dependency-security run `36955732943`. Phases 105–111 remain formally closed: 105 QUALIFIED, 106 QUALIFIED, 107 DEFER, 108 QUALIFIED, 109 DEFER, 110 RETAIN INTERNAL, and 111 DEFER. Phase 112 completed campaign-wide evidence refresh and terminal closeout. Post-closeout Phases 113-114 are CLOSED QUALIFIED (113 docs-only reconciliation; 114 tunnel/Eggtunnel parity refresh RETAIN + DEFER relay reuse, 2026-10-02; evidence architecture/tunnel_eggtunnel_parity_phase114.md). ICMP remains RETAIN, process sandbox remains DEFER, and YARA remains DEFER. No downstream extraction or adoption is authorized by registration of Phases 113–114. Phase 104 (Phase 103 qualification-evidence corrective closeout) is CLOSED QUALIFIED (2026-10-01; closeout `architecture/dependency_security_phase104_corrective_closeout.md`; proof-bearing implementation SHA `e0032cd176cd1061a3aa5877555f49ebc4f46a3b`; hosted CI + `dependency-security` green on `36901352762`). Phase 103 (dependency-security re-audit and Wasmtime remediation) remains CLOSED QUALIFIED for its security remediation (2026-10-01; closeout `architecture/dependency_security_reaudit_phase103_closeout.md`; proof-bearing implementation SHA `aeeebc7bac38b1dcc441b06f53c838a74582cd24`; hosted CI + `dependency-security` green on `36891196284`), with Phase 104 owning the residual performance-evidence and support-date corrections. Phase 102 (eggfetch 0.2.1 patch adoption) is CLOSED QUALIFIED (2026-10-01; closeout `architecture/eggfetch_0_2_1_patch_adoption_closeout.md`). Tracks 1–3 and their corrective closures remain complete. Phases 41-48 of the runtime-truthfulness/security/publication campaign are complete (see `architecture/runtime_truthfulness_security_publication_closeout.md`). The post-Phase-48 performance optimization campaign (Phases 49-55) remains complete; Phases 56–57 corrective closure is implemented and closed (Phase 56 `57ad3158754b2f4851e1ce408043d33104106974`, Phase 57 proof-bearing `5212c6862426ee17795994ef1bba590113c52fad`). Eggfetch 0.2 runtime adoption is closed through Phase 62 (`c3568ef4...`) and performance/reproducibility adjudication is closed through Phase 63; Phase 64 docs/evidence-truth correction is closed. Production remains on eggfetch. The EggServe 0.2.2-line inbound H1 campaign remains historical/retained at Phase 65; Phases 66–69 were never started. EggServe 0.3 H1 adoption and corrective requalification are closed as `ADOPTED` through Phase 80 on exact pins `eggserve-server = "=0.4.0"` / `eggserve-primitives = "=0.2.2"`; the Phase 78 terminal claim is superseded by Phase 80 proof-bearing SHA `174fdbcd6f133b35099ed4492f5ed8d3fcaa7d4c` (hosted run `36201213413`). Phase 79 implementation SHA: `171dd1e47f965b04b34465fc72c87adf4d9a9cab`. See `architecture/eggserve_0_3_h1_adoption_closeout.md`. Phases 70–72 remain historical/closed with evidence aligned to their then-current Hyper H1 runtime. The process-sandbox correctness and extraction-readiness campaign (Phases 81-84) remains closed DEFER; Phase 94 corrected and qualified Phase 89's Linux mechanism-selection and native-evidence gaps on exact SHA `e86fb35372b1b66bb59c8a6336bf32e55ff5c93e` (hosted/native run `36271417398`). The independent ICMP policy/enforcement extraction-preparation campaign (Phases 85-88) remains closed RETAIN (see the Post-Phase-80 section below); Phases 90–91 are closed, Phase 92 is CLOSED CORRECTED, Phase 93 is QUALIFIED (superseded by Phase 95 exact-SHA two-run proof `36335520434` on `39bfced25d51267ee5837eaecedae7da9af163d0`), and Phase 95 is CLOSED QUALIFIED with Linux nftables native-supported. Phase 88 stays RETAIN with no extraction authorized. The closed independent cross-repo Eggbench security-qualification asset handoff remains separately registered. The Eggbench Security Qualification M003 telemetry interoperability corrective remains closed qualified at `739e7ba6f02c5e3f83fe9ff5321b09213182b193` for the v2 schema/generation contract, but the live-value path is reopened by the READY heartbeat-dispatch corrective `plans/eggbench_security_qualification_m003_telemetry_heartbeat_dispatch_corrective.md`: current supervisor IPC drops `UnifiedServerWorkerHeartbeat` instead of updating ProcessManager, and downstream Eggbench `m003c-13b` correctly stops. The former v1 terminal qualification remains superseded/withdrawn. The post-Phase-95 architecture-maintenance and auditability campaign (Phases 96–101) is closed qualified on proof-bearing SHA `2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`; see `architecture/architecture_maintenance_auditability_closeout.md`.

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


## Post-Phase-57 Campaign: Eggfetch 0.2 Transport Consolidation — Runtime/Performance/Docs Closed

Status: runtime implementation closed through Phase 62; Phase 61 closeout superseded; Phase 63 performance-evidence requalification closed 2026-09-22 with one accepted, labeled tail residual (`stream-concurrent` under synchronized concurrency ≥ 4). Phase 64 documentation/evidence correction (immutable-session count and concrete upstream-plan reference) is complete/closed; it did not reopen runtime or performance adjudication. Production remains on eggfetch. Final measured authority remains `architecture/eggfetch_0_2_transport_performance_requalification.md`.

Roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Research handoff: `plans/eggfetch_current_line_parity_review.md`.

Baseline reviewed: `e3026667c23e6e0e92ee30d13c53baf2e68c5c77` (2026-09-22).

Target upstream: `eggfetch-core 0.2.0` / `v0.2.0`.

The Phase 34 retain-`synvoid-http-client` decision remains valid historical evidence for eggfetch 0.1.4, but it is no longer a current capability comparison. Eggfetch 0.2.0 now exposes generic native `http_body::Body` execution, explicit Rustls provider injection, chain-preserving hostname-skip control, direct UDS/advanced routing, and resolved-target reuse. The remaining adoption risk is therefore exact SynVoid compatibility/security/performance behavior rather than obvious missing transport primitives.

Execution order:

1. Phase 58 — pin/qualify eggfetch 0.2.0, re-run the capability matrix, prove aws-lc/PQ/TLS/body/UDS/pool semantics, and classify every existing public `synvoid-http-client` export.
2. Phase 59 — introduce an eggfetch-backed native transport lane behind the existing neutral SynVoid policy model and run differential parity against the legacy lane.
3. Phase 60 — migrate production consumers in bounded batches, then retire only redundant legacy transport machinery that is not required by the compatibility contract.
4. Phase 61 — superseded initial security/profile/API closeout attempt (preserved as history).
5. Phase 62 — closed policy-aware registry and fail-closed TLS correction; its initial benchmark conclusion is preserved but superseded for performance evidence.
6. Phase 63 — closed reproducible benchmark/true-streaming requalification, small-request regression adjudication, fixture hygiene, and final evidence closeout (one accepted tail residual under synchronized concurrent streaming).
7. Phase 64 — complete/closed docs/evidence-truth correction: authoritative immutable-session count fixed, vague upstream-tracking language replaced with the concrete eggfetch investigation plan, Phase 62/63 authority split preserved.

Detailed plans:

- `plans/phase_58_eggfetch_0_2_qualification_and_compatibility.md`
- `plans/phase_59_eggfetch_native_transport_adapter.md`
- `plans/phase_60_eggfetch_consumer_migration_and_legacy_transport_retirement.md`
- `plans/phase_61_eggfetch_transport_qualification_and_closeout.md`
- `plans/phase_62_eggfetch_policy_keying_and_evidence_corrective_closeout.md`
- `plans/phase_63_eggfetch_transport_benchmark_requalification_and_final_evidence_closeout.md`
- `plans/phase_64_eggfetch_closeout_evidence_truth_correction.md`

Campaign constraints:

- no weakening aws-lc/PQ, CA, hostname, SNI, or fail-closed TLS behavior;
- no buffering of true streaming WAF/H3 request bodies;
- no migration of retry/upstream/WAF/cache policy into eggfetch;
- no outbound H3 requirement introduced by this work;
- no public concrete type/signature change disguised as an implementation swap;
- no permanent dual active generic transport ownership;
- `synvoid-http-client` remains internal unless a future separate publication decision says otherwise.

The campaign may terminate after Phase 58 on a retained branch if executable evidence shows a security, dependency, or API-compatibility blocker. That is a valid closeout; do not force adoption merely because the upstream feature list is broader.


## Post-Phase-64 Campaign: EggServe 0.2.2-Line Inbound H1 Runtime Consolidation — Retained at Phase 65

Status: Phase 65 executed and closed RETAINED on 2026-09-24. Production remains on Hyper H1; Phases 66–69 are not started. EggServe's mandatory finite handler/body/write deadlines and upper-bound controls cannot be projected without narrowing current SynVoid behavior. Evidence: `architecture/eggserve_0_2_2_h1_compatibility_matrix.md`.

Roadmap: `plans/eggserve_0_2_2_h1_runtime_consolidation_roadmap.md`.

Baseline reviewed: `11a1fb2844cd648418eefd72801f1aee2090d140` (2026-09-24 integration review).

Upstream publication truth:

- `eggserve-core 0.2.2` is published and registry-qualified;
- the direct reusable H1 runtime is currently `eggserve-server 0.2.1`;
- the preferred production target is the narrow caller-owned H1 runtime, not EggServe listener/TLS/H2/H3/static ownership;
- `eggserve-core 0.2.2` may be used for qualification/interop only if Phase 65 proves it is materially required.

Primary objective: consolidate generic plaintext and TLS-HTTP/1 connection/runtime mechanics behind EggServe without moving SynVoid's socket, flood, TLS/ALPN/PQ/JA4, H2/H3, WAF, routing, backend, or application-policy authority.

Execution order:

1. Phase 65 — qualify the exact published runtime/feature graph, configuration semantics, body/response adaptation, and WebSocket/tunnel boundary; production routing unchanged.
2. Phase 66 — remove `hyper::body::Incoming` and `hyper::upgrade::OnUpgrade` from the canonical `synvoid-http` policy boundary while retaining the existing Hyper transports.
3. Phase 67 — adopt the direct EggServe runtime for plaintext H1 only, retaining SynVoid listener/flood/protocol-sniff ownership and a test-only differential lane.
4. Phase 68 — route ALPN-selected TLS-H1 through the same caller-owned EggServe runtime while leaving SynVoid TLS termination and H2/H3 untouched.
5. Phase 69 — run adversarial/wire/performance/full-release qualification, reconcile shutdown ownership, delete superseded production H1 Hyper machinery, and close as ADOPTED or RETAINED.

Detailed plans:

- `plans/phase_65_eggserve_runtime_qualification_and_boundary_contract.md`
- `plans/phase_66_http_transport_neutral_request_and_tunnel_boundary.md`
- `plans/phase_67_eggserve_plaintext_h1_runtime_adoption.md`
- `plans/phase_68_eggserve_tls_h1_runtime_convergence.md`
- `plans/phase_69_eggserve_h1_adversarial_performance_and_closeout.md`

Campaign constraints:

- no default EggServe `RuntimeConfig` in production; every bound must map to existing SynVoid semantics or be explicitly adjudicated;
- no invented `eggserve-server 0.2.2` dependency;
- no loss of WebSocket capability;
- no forced request/response buffering;
- no listener/TLS/H2/H3/static-policy migration;
- no silent double admission/timeout/shutdown authorities;
- no permanent dual production H1 runtime;
- no claim of lower footprint/faster runtime without measured evidence.

The campaign may stop at Phase 65 or later and retain Hyper if executable evidence identifies a correctness, security, configuration, dependency, or performance blocker. Phase 66's transport-neutral boundary may remain only if independently justified.


## Post-Phase-65 Corrective: HTTP Runtime and Configuration Truthfulness — Closed

Status: implemented/closed. This corrective did not reopen EggServe adoption.

Baseline reviewed: `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c` (Phase 65 retained closeout).

The retained EggServe qualification exposed independent current-runtime truthfulness residuals in the existing Hyper server. These are now owned by Phases 70–71 rather than by the gated Phases 66–69.

Execution order:

 1. **Phase 70 — HTTP/1 runtime truthfulness corrective**
    - Closed: plaintext startup log is H1-only; TLS-H1 consumes the same
      header timeout, header-count, and parser-buffer controls as plaintext
      H1 through `src/http/h1_policy.rs` (explicit Tokio timer — Hyper
      panics without one); WebSocket upgrades and TLS H2 preserved.
      Evidence: `architecture/http_h1_runtime_truthfulness_phase70.md`,
      `tests/http_h1_parser_parity.rs`.
    - Plan: `plans/phase_70_http_h1_runtime_truthfulness_corrective.md`.

 2. **Phase 71 — HTTP configuration runtime-semantics truthfulness closure**
    - Closed: every `HttpConfig` field carries a disposition in
      `architecture/http_config_runtime_semantics_matrix.md`
      (`ACTIVE_EXACT`, `ACTIVE_NARROWER_THAN_DOCS`, `DEPRECATED_COMPAT`);
      `max_header_size_ingress` enforced as an aggregate post-parse 431
      bound on H1/H2; validation extended for parser/u32/ingress ranges;
      docs/admin-UI reconciled; guard `tests/http_config_runtime_semantics.rs`
      pins future fields to the matrix.
    - Plan: `plans/phase_71_http_config_runtime_semantics_truthfulness.md`.
     - Residual follow-ups (catalogued in the matrix as future plan
       candidates — no numbered plans registered, not blocking): H3
       ingress threading, true idle keep-alive instrumentation, TCP-connection
       cap vs request admission, egress commit design, request-line wire
       limit/rename.

Known starting evidence for Phase 71 includes active consumers for WAF stall controls, strict protocol validation, streaming-body limits, and the HTTP request semaphore; repository search did not demonstrate canonical runtime consumers for several documented fields including `keep_alive_timeout_secs`, `pipeline_limit`, `max_request_line_size`, and `max_header_size_egress`, while `max_connections` appears to be request-admission rather than literal TCP-connection scope. Phase 71 must verify these facts against its implementation head before changing behavior or docs.

Constraints:

- no EggServe dependency or Phase 66–69 implementation unless a future upstream requalification independently changes the retained decision;
- no h2c implementation solely to preserve a stale log;
- no raw/custom H1 parser hidden inside this corrective;
- no arbitrary new timeouts/limits;
- public config compatibility is preserved unless a separate explicit compatibility decision authorizes removal;
- docs/admin UI must not describe a field as active when runtime evidence says otherwise.

If exact enforcement of a field requires a new parser, TCP-admission subsystem, invasive idle-connection instrumentation, or incompatible config rename/removal, Phase 71 must classify the residual truthfully and register a separate focused follow-up rather than broadening itself.

### Phase 72 — HTTP truthfulness corrective closeout and evidence reconciliation — Implemented/Closed

Plan: `plans/phase_72_http_truthfulness_corrective_closeout.md`.

Baseline: `92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` (Phases 70–71 implementation/closeout head).

Closeout: `architecture/http_truthfulness_phase72_closeout.md`.

Proof-bearing SHA: `1c215fa8d6df94cba3c7bed2d462221b8cf0ad18`. Remote CI
observed green for that SHA: GitHub Actions run `36035559122` (`ci` +
`dependency-security` jobs, both success).

Result:

- Phase 70/71 evidence files reconciled to closed status with the
  proof-bearing closeout SHA recorded and local-vs-remote verification
  distinguished (no remote CI outcome claimed without an observed run);
- real Rustls/Tokio-Rustls TLS handshake + ALPN `http/1.1` fixture added
  (`tests/http_h1_tls_transport.rs`, 5/5) exercising the production H1
  policy helper over the server `TlsStream` (timeout, header-count,
  parser-buffer, WebSocket upgrade);
- misleading `tls_h1_*` plain-TCP test names corrected to
  `shared_policy_repeat`;
- the five Phase 71 residuals recorded as catalogued future plan
  candidates (no numbered plans registered, none active);
- focused tests, feature-profile checks, and `cargo xtask verify` green.

Terminal state: Phases 70–72 closed with evidence aligned to runtime; any later HTTP feature work starts under a new focused plan and baseline.

Closed scope (historical): this phase was evidence/closeout work, not a
feature campaign. It implemented no H3 ingress residual, idle keep-alive
instrumentation, TCP connection caps, egress-header policy,
request-line parsing/rename, EggServe adoption, or Phases 66–69.



## Post-Phase-72 Campaign: EggServe 0.3 Direct H1 Requalification and Adoption — Closed at Phase 80

Final status:

- Phase 73 first closed `RETAIN_PENDING_UPSTREAM` against exact EggServe 0.3.0.
- EggServe 0.3.1 then resolved the parser-range and per-site response-metadata blockers; the Phase 73 re-run reached `GO_DIRECT_0_3`.
- Phases 74–78 were implemented together at `2242e1911d2083448371f707392fdb07f83f1bce`.
- Production plaintext H1 and TLS-ALPN H1 use exact-pinned EggServe (0.3.1/0.2.1 at adoption; moved to `eggserve-server = "=0.4.0"` / `eggserve-primitives = "=0.2.2"` by Phase 79 Finding B — 0.3.1 cannot render an H1 terminal trailer block); H2 remains Hyper and H3 remains unchanged.
- Post-adoption review found two concrete runtime defects plus missing acceptance/evidence: worker shutdown can cancel the EggServe driver future before graceful drain; the exact-size buffered response adapter can discard terminal trailers; the required real AppServer tunnel loopback was not run; and local endpoint fallback can fabricate the remote peer as the local address.
- Phase 78's terminal `ADOPTED` closure claim was superseded. Phases 79–80 corrected and requalified the production baseline; current disposition is `ADOPTED` with hosted proof on `174fdbcd6f133b35099ed4492f5ed8d3fcaa7d4c` (run `36201213413`).

Roadmap:
`plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

Planning baseline for the corrective:
`2242e1911d2083448371f707392fdb07f83f1bce`.

Execution order:

1. **Phase 73 — exact-artifact requalification**
   - historical 0.3.0 result: `RETAIN_PENDING_UPSTREAM`;
   - 0.3.1 re-run: `GO_DIRECT_0_3`.
2. **Phase 74 — transport-neutral inbound/request/upgrade boundary**
   - closed; canonical `synvoid-http` request/body/upgrade policy boundary is transport-neutral.
3. **Phase 75 — EggServe service/config/response/tunnel adapter**
   - closed; exact pins, one projector, External ownership, differential qualification.
4. **Phase 76 — plaintext H1 production adoption**
   - implementation landed; plaintext H1 uses the direct EggServe driver.
5. **Phase 77 — TLS-H1 convergence**
   - implementation landed; post-Rustls ALPN H1 uses the same EggServe driver; H2 unchanged.
6. **Phase 78 — adversarial/performance closeout**
   - implementation/evidence landed, but its terminal closure claim is superseded by post-adoption review.
7. **Phase 79 — EggServe 0.3.1 H1 runtime correctness corrective**
   - implemented; fix shutdown-driver lifetime;
   - preserve exact-body trailers (required the separately justified
     upstream bump to EggServe 0.4.0 / primitives 0.2.2);
   - prove the real AppServer WebSocket/tunnel path without external Granian/Python;
   - remove peer-as-local endpoint fabrication;
   - retain the existing adoption architecture (no rollback-class defect found);
   - evidence: `tests/eggserve_h1_runtime_corrective.rs` (10/10) plus the
     adoption/differential/TLS suites; implementation SHA
     `171dd1e47f965b04b34465fc72c87adf4d9a9cab` handed to Phase 80.
8. **Phase 80 — corrective requalification and evidence closure — closed `ADOPTED` 2026-09-26**
   - focused regressions, performance/resource recheck, feature/security profiles, and `cargo xtask verify` passed;
   - hosted CI and dependency-security passed on SHA `174fdbcd6f133b35099ed4492f5ed8d3fcaa7d4c`, run `36201213413`;
   - Phase 73–78 evidence/status reconciled; final corrective record is `architecture/eggserve_0_3_h1_adoption_closeout.md`.

Detailed plans:

- `plans/phase_73_eggserve_0_3_runtime_requalification_and_contract_gate.md`
- `plans/phase_74_http_transport_neutral_inbound_and_upgrade_boundary.md`
- `plans/phase_75_eggserve_0_3_adapter_and_differential_qualification.md`
- `plans/phase_76_eggserve_plaintext_h1_production_adoption.md`
- `plans/phase_77_eggserve_tls_h1_runtime_convergence.md`
- `plans/phase_78_eggserve_h1_adversarial_performance_closeout.md`
- `plans/phase_79_eggserve_0_3_1_h1_runtime_correctness_corrective.md`
- `plans/phase_80_eggserve_0_3_1_corrective_requalification_and_evidence_closure.md`

Campaign constraints:

- no valid SynVoid config narrowing/clamping hidden in the implementation swap;
- no loss of per-site Date/server-token behavior;
- no default EggServe timeout/body/admission authority layered over SynVoid;
- no loss of request/response trailer semantics;
- no loss of WebSocket/AppServer tunnel capability;
- worker shutdown must signal and then allow the EggServe driver to execute its bounded shutdown path rather than cancelling it from an outer `select!`;
- no fabricated local transport provenance;
- no listener/TLS/H2/H3/static-policy migration;
- no permanent dual production H1 runtime;
- no EggServe types in the canonical `synvoid-http` domain API;
- no footprint/performance claim without measured evidence.

The pre-existing H2 header-list byte-unit issue, duplicate-`Set-Cookie` behavior, and body-limit status relabeling remain separate follow-up candidates. They must not be folded into Phases 79–80 unless the corrective changes those paths.

Terminal state: **closed `ADOPTED`**. The residual H2 header-list byte-unit review, duplicate `Set-Cookie` behavior, body-limit status relabeling, and test-only Hyper differential-lane decision remain separate follow-up candidates. No registered future plan is blocked on this campaign. The process-sandbox correctness and extraction-readiness campaign (Phases 81–84) is closed DEFER (see below); the ICMP policy/enforcement campaign (Phases 85–88) is closed RETAIN (see below).

## Post-Phase-80 Campaign: Process Sandbox Correctness and Extraction Readiness — Closed DEFER at Phase 84

Status: implemented/closed 2026-09-26 with disposition **DEFER** (retain
internal under `synvoid-platform`; no extraction authorized; concrete
re-evaluation triggers recorded). Proof: `cargo xtask verify` 10/10,
platform/jail suites green (incl. new guarantee conformance 14/14 +
no-downgrade 12/12), Linux/Windows cross-checks for `sandbox.rs` clean,
`cargo deny check` clean, `cargo audit` with no new findings, feature-profile
matrix green. Native Linux/Windows/BSD enforcement lanes run on their
qualification hosts (explicit unsupported elsewhere, never skip-as-success).

Baseline: `81638c251592913579bd9bbce51d013c44d67910`.

Roadmap: `plans/process_sandbox_corrective_extraction_readiness_roadmap.md`
(historical).

Closeout: `architecture/process_sandbox_corrective_closeout.md` (defect
table, guarantee matrix, native evidence, dep/footprint delta, residuals,
DEFER verdict + triggers).

Trigger: extraction research found two concrete correctness defects in the current native backend implementation (Landlock UAPI construction/no-new-privs handling and Windows Job Object/mitigation ABI usage) plus a portability-contract defect: `SandboxLevel::Strict` currently reduces to read-path-allowlist capability and cannot express materially different OS guarantees.

Execution order (all closed):

1. **Phase 81 — native backend correctness corrective — closed CORRECTED**
   - repaired/requalified Linux Landlock with ABI-aware, fail-closed enforcement (`landlock` crate, `HardRequirement`, verified `FullyEnforced` + `no_new_privs`);
   - repaired Windows Job Object and mitigation ABI usage with generated bindings (class 9, correct flags, query-back, owned handle);
   - removed host-global DACL mutation from process-sandbox semantics;
   - native behavioral/query evidence (child-process suites per OS) and lifetime-safe backend state.
2. **Phase 82 — guarantee contract and compatibility migration — closed ADOPTED**
   - required/optional guarantees + enforcement report replace the `can_enforce_strict()` decision;
   - child-creation denial vs descendant confinement and resource limits vs access control separated;
   - prepare/enter staging, thread-scope truth, inherited/preopened resources, owned entered-sandbox witness;
   - legacy Off/Basic/Strict adapters pinned; jail deliberately migrated.
3. **Phase 83 — native capability hardening — closed HARDENED**
   - minimal Linux seccomp deny-list for no-network/no-child/no-exec jail guarantees (qualified by construction + child tests + jail round trips);
   - descriptor-capability-aware Capsicum; hardened OpenBSD unveil/pledge;
   - existing macOS Seatbelt evidence mapped into the guarantee model;
   - Windows AppContainer/ProcessContainer gate explicitly retained (no weakening).
4. **Phase 84 — requalification and extraction-readiness closeout — closed DEFER**
   - adversarial no-downgrade tests, native backend matrix, jail end-to-end qualification, unsafe/dependency/footprint audit, documentation reconciliation;
   - recorded DEFER with triggers; no later extraction work registered.

Detailed plans:

- `plans/phase_81_process_sandbox_backend_correctness_corrective.md`
- `plans/phase_82_process_sandbox_guarantee_contract_and_compatibility.md`
- `plans/phase_83_process_sandbox_native_capability_hardening.md`
- `plans/phase_84_process_sandbox_extraction_readiness_closeout.md`

Campaign constraints:

- no silent downgrade of a required guarantee;
- no publication/new standalone repo during Phases 81-84;
- no broad sandbox-level config semantic change hidden in backend repair;
- no generic command-runner API added to `synvoid-platform`;
- jail parent-created stdio IPC and bounded restart/fail-closed semantics remain unchanged;
- cross-compilation is not enforcement evidence;
- Windows Job Objects remain resource/lifecycle containment unless a distinct access-control launch boundary is natively proven;
- Capsicum descendant confinement is not described as child-creation denial;
- macOS Seatbelt remains experimental/deprecated and is never described as Apple App Sandbox.

Phases 81-84 are closed (DEFER); no plan in this campaign remains executable.



## Post-Phase-80 Campaign: ICMP Policy/Enforcement Extraction Preparation — Closed RETAIN (Phases 85–88)

Status: Phases 85–88 are closed RETAIN 2026-09-26 (canonical
policy/adaptation `20dfc148`; backend/privilege truthfulness `f1be64d6`;
transactional enforcement `8ecd81fe`; readiness/qualification `f85b7871`;
closeouts `architecture/icmp_phase85_*`, `architecture/icmp_phase86_*`,
`architecture/icmp_phase87_*`, `architecture/icmp_phase88_*`; decision
record `architecture/icmp_policy_enforcement_extraction_readiness.md`).
No plan in this campaign remains executable and no registered future
plan is blocked on it; the RETAIN verdict registers re-evaluation
triggers, not ordered work.
This campaign prepared the
existing `synvoid-icmp-filter` boundary for a later extraction decision; it
does **not** publish, rename, or move the crate to an external repository.

Roadmap:
`plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

Baseline at planning start:
`81638c251592913579bd9bbce51d013c44d67910`.

Research/current-head review found four prerequisite classes of work:

1. The application config and enforcement crate independently define divergent
   ICMP config/policy types, and the admin persistence path bridges them through
   JSON value conversion. Phase 85 establishes one semantic policy owner,
   explicit typed config adaptation, family-aware ICMP policy, RFC-aware
   ICMPv6 safety validation, and explicit rate-limit semantics.
2. Backend/platform truth is inconsistent: Linux privilege probing mixes BPF
   state into nftables availability; Windows backend source references
   undeclared dependencies and contains interface-resolution defects; NetBSD is
   incorrectly grouped into the PF lane. Phase 86 closes feature/dependency,
   backend-selection, privilege, Windows, and BSD truthfulness gaps.
3. Current config replacement and status are desired-state-biased. Phase 87
   adds compile-before-mutate enforcement, backend-scoped ownership,
   transaction/staging/rollback semantics, apply receipts, live readback, and
   drift/unknown state.
4. Phase 88 requalifies the cleaned boundary against current Rust firewall
   libraries and native platforms, adjudicates subprocess-vs-native backend
   mechanisms, evaluates the binding Phase 47 public-crate bar, and records a
   GO/RETAIN extraction-readiness decision without publishing.

Detailed plans:

- `plans/phase_85_icmp_policy_model_and_config_canonicalization.md`
- `plans/phase_86_icmp_backend_platform_and_privilege_truthfulness.md`
- `plans/phase_87_icmp_transactional_enforcement_and_state_verification.md`
- `plans/phase_88_icmp_extraction_readiness_and_platform_qualification.md`

Execution order is 85 → 86 → 87 → 88. Linux nftables remains the required
baseline; eBPF remains optional. Explicit backend requests become strict while
only `Auto` may fall back. NetBSD PF support is removed from the claim; NPF is
a future separately scoped backend decision. Routine CI remains the current
proportionate Linux verification lane; native privileged platform proof is
recorded separately rather than recreating a broad permanent OS matrix.

Campaign acceptance is governed by the detailed roadmap. A successful Phase
84 GO means only that a separate extraction/publication campaign is justified;
it does not itself create a class-3 support promise.

## Post-Phase-88 Corrective: Process Sandbox Entry and Policy Semantics — Phase 89 Closed

Status: **closed** 2026-09-26 (DEFER extraction disposition unchanged; addendum `architecture/process_sandbox_corrective_closeout.md` §11).

Plan:
`plans/phase_89_process_sandbox_entry_and_policy_semantics_corrective.md`.

Baseline: `7462bb9f36983aaffa8c8d9ec14595240557c3c7`.

Trigger: post-closeout review of the Phases 81–84 implementation found four
bounded semantic defects that do not invalidate the overall corrective
architecture or its DEFER extraction verdict:

1. the jail performs the legacy Strict entry to compute `legacy_ok`, then
   enters the guarantee-driven sandbox a second time;
2. Linux `LandlockSandbox::apply()` unconditionally installs the
   jail-specific seccomp filter, so generic/legacy Basic semantics are
   stronger than documented and mechanism selection is not actually
   guarantee-driven;
3. `SandboxRequest::intersect()` drops disjoint required guarantees and
   copies path/resource authority from only one operand, so it is not safe
   tightening policy algebra;
4. the jail request still omits the no-network/no-child/no-exec guarantees
   that Phase 83 now has a Linux mechanism to enforce.

Phase 89 corrective scope:

- enforce exactly one irreversible jail-entry transition;
- make legacy compatibility checks pure/test-only;
- separate generic Landlock filesystem confinement from explicit
  guarantee-selected seccomp categories;
- build post-entry enforcement reports from mechanisms actually installed;
- remove the unused unsafe `SandboxRequest::intersect()` API unless a real
  production caller justifies a formally monotonic `tighten_with`
  replacement;
- make the jail's required guarantee set match its real security boundary;
- reconcile legacy capability/docs truth and add focused/native regression
  evidence.

Constraints:

- Phases 81–84 remain historically closed; Phase 89 is a post-closeout
  corrective, not a rewrite;
- extraction disposition remains **DEFER**;
- no standalone sandbox crate/repository is created;
- no global reinterpretation of legacy `sandbox_level` config;
- no generic process-runner API;
- no system `libseccomp` dependency;
- no platform support label is preserved by silently weakening a required
  jail guarantee;
- parent-created stdio IPC, fail-closed `IsolationPolicy::Required`,
  bounded restart behavior, and retained `EnteredSandbox` ownership remain
  intact.

Phase 89 implementation is landed, but its terminal qualification claim was
**superseded and corrected by Phase 94**. Exact-SHA run `36271417398` passed
hosted routine verification, dependency security, and Linux native
qualification. Extraction remains DEFER. See
`plans/phase_94_process_sandbox_qualification_corrective.md`.



## Post-Phase-88 ICMP Follow-up: Operator Truth and Native Qualification Preparation — Phases 90–91 Closed

Status: **closed** 2026-09-26. Phase 90 operator truth and Phase 91 harness preparation landed at closeout head `826e634d7b9475c7b0b44badd2f51f07df6ddd17`; privileged Linux qualification was not run. Post-closeout lifecycle corrections are registered separately as Phases 92–93.

Roadmap:
`plans/icmp_post_retain_operator_truth_and_native_qualification_roadmap.md`.

Baseline:
`0c8d3cac2fb214932c22dc360057acdad3c44c98`.

Predecessor disposition: Phases 85–88 remain closed **RETAIN**. This follow-up
does not reopen extraction/publication.

Current-head review found two actionable residuals plus one stale consumer:

1. **Operator enforcement truth is not wired through.** The Phase 87 manager
   exposes `report()` / `verify_live()`, but `GET /icmp/status` still uses
   `is_enabled()`, compatibility `FilterStatus`, and requested
   `filter_type`. Manager `enable()` / `disable()` also bypass
   `DriverState`, so lifecycle state can change without the report advancing.
2. **Backend/status observability is misleading.** The status route fabricates
   an all-zero packet-stat object when counters are unavailable; the backend
   inventory hardcodes returned entries as available and reports the requested
   backend rather than necessarily the selected backend.
3. **The admin UI is on a different domain contract.** Its ICMP page models
   ping/probe concepts (`active`, `backends_count`, `last_ping`,
   node/address/latency/health), while the server implements firewall
   enforcement and returns `IcmpBackendsResponse { backends,
   current_backend }`.

Execution order:

1. **Phase 90 — ICMP Operator Enforcement Truth and Admin Contract
    Reconciliation — closed 2026-09-26**
    - enable/disable/config replacement share one verified lifecycle;
    - admin status exposes Applied/Absent/Drifted/Unknown and the actual
      selected backend;
    - fabricated packet-stat measurements removed (stats null);
    - backend probe/availability reasons exposed;
    - OpenAPI/audit semantics reconciled;
    - ICMP admin UI rewritten against filtering/enforcement semantics and the
      actual server response shape.

    Plan:
    `plans/phase_90_icmp_operator_enforcement_truth_and_admin_contract.md`.

2. **Phase 91 — ICMP Privileged Native Qualification Harness Preparation
    — closed 2026-09-26 (harness/preparation; no privileged host available)**
    - explicit opt-in Linux nftables qualification harness exists;
    - firewall/network changes isolated inside disposable network namespaces
      with a veth IPv4/IPv6 topology (`setns`-isolated enforcement);
    - packet-level cases prepared for type/code, exemptions, global rate
      limit, update/readback/drift/disable/rollback;
    - deterministic cleanup and bounded machine-readable evidence artifact;
    - routine CI non-privileged via preflight/dry-run/unit tests.

    Plan:
    `plans/phase_91_icmp_privileged_native_qualification_harness.md`.

Phase 91 closed as a harness/preparation phase. Its closeout does not claim
native kernel qualification: no privileged host was available, so Linux
nftables remains unqualified (not passed). No Phase 92
qualification/extraction re-evaluation is registered until a suitable
privileged host is actually available and the Phase 88 re-evaluation trigger
can be exercised with real evidence.

Constraints:

- Phase 88 RETAIN remains authoritative;
- no public crate/repository is created;
- GET/status may perform bounded readback but never firewall mutation;
- unsupported packet counters are absent/unknown, not zero;
- backend requested/selected/usable facts remain distinct;
- native qualification must not modify the host/default network namespace;
- privileged execution requires explicit opt-in and deterministic cleanup;
- routine CI remains non-privileged and proportionate.

Phases 90–91 are closed. Phase 89 implementation is landed and its terminal
sandbox qualification is closed by Phase 94. ICMP Phases 92–93 are tracked
separately below. Extraction stays DEFER (sandbox) and RETAIN
(ICMP) under their recorded re-evaluation triggers. The independent cross-repo
Eggbench handoff remains planned and is not blocked on Phase 94.


## Independent Cross-Repo Handoff: Eggbench Security Qualification Assets — Closed

Status: **CLOSED** 2026-09-28. Implementation
`ae045481752b8f750d6e6079b185c526a09c91d5`; closeout
`architecture/eggbench_security_qualification_asset_contract_closeout.md`.
Policy `synvoid.eggbench-qualification.v1` (15-case allowlist, 12-case
exclusion manifest, deterministic xtask materializer, loopback-only
minimal config config-tested on the release minimal binary, provenance
manifest, 15-test self-qualification) plus the mandatory live
reverse-proxy semantic proof (15/15 corpus agreement + 2/2 perf paths
against the pinned minimal binary). Routine verification 10/10 green;
no production WAF semantic weakened. No registered SynVoid future plan
was blocked on this handoff; its downstream is the external Eggbench
Security Qualification M002 full closure.

Historical planning record (superseded status only; content retained):

Plan:
`plans/eggbench_security_qualification_asset_contract.md`.

Planning baseline:
`49b4624b696b4c3aa0172b0326a04ae9e275ca3f`.

Implementation re-audit baseline:
`fb2acbc1c918f8706fc7c65676efe5b275995bfe`.

Consumer:
`eggstack/eggbench` Security Qualification M002.

This is not part of the ICMP Phase 90-91/possible future Phase 92 sequence and
does not reopen any closed SynVoid architecture campaign.

The handoff exists because Eggbench now has a generic fixed-corpus correctness
and qualification-suite substrate, while SynVoid remains the owner of its WAF
fixture semantics. The plan adds a SynVoid-owned export/materialization
contract for a bounded live-proxy-compatible subset of the authoritative WAF
corpus plus a loopback-only minimal qualification config and provenance
manifest.

Key constraints:

- SynVoid translates its own source `detect/pass` semantics into externally
  observable status expectations under a fixed qualification policy;
- unsupported smuggling/hop-by-hop/binary/internal-only fixtures are explicitly
  excluded rather than weakened;
- generated runtime config binds loopback only and targets a controlled
  loopback origin;
- `--no-default-features` remains the qualification runtime profile;
- no Eggbench Rust dependency enters SynVoid;
- no production WAF behavior is changed merely to satisfy the harness;
- no new SynVoid load generator is added.

This plan is dependency-ready and is the next cross-repo prerequisite for Eggbench Security Qualification M002 full closure. It may execute independently of the ICMP/sandbox corrective lines. Closure requires the owner-side live reverse-proxy semantic proof, not only export-generation tests.


## Independent Cross-Repo Handoff: Eggbench Security Qualification M003 Telemetry — Closed Qualified (v2 Corrective)

Status: **CLOSED QUALIFIED** (2026-09-29).

Parent plan:
`plans/eggbench_security_qualification_m003_telemetry_contract.md`
(**CLOSED QUALIFIED** v2 corrective).

Closed corrective:
`plans/eggbench_security_qualification_m003_telemetry_interop_corrective.md`
(**CLOSED QUALIFIED**).

Corrective implementation:
`739e7ba6f02c5e3f83fe9ff5321b09213182b193`.

Terminal closeout:
`architecture/eggbench_security_qualification_m003_telemetry_corrective_closeout.md`
(sole current terminal authority; qualified owner contract
`synvoid.eggbench-telemetry.v2`).

Historical implementation (withdrawn v1, evidence only):
`619602a6cd2440d685020eb52e19c0887622dee1`.

Historical closeout (superseded, not terminal):
`architecture/eggbench_security_qualification_m003_telemetry_closeout.md`.

Corrective baseline:
`c0f121be771456ace2c7eaa1b26fb9f2fe3eb95f`.

Pinned downstream consumer reviewed for the corrective:

- `eggstack/eggbench@18b1c1c8398d559d38bd74d717ff3dc79e3b20ad`
- generic Prometheus collector:
  `2742e0eafaaef38899db5978f1721611ce58a7bc`
- parser:
  `crates/eggbench-drivers/src/prometheus_http.rs`

The supervisor-side implementation remains useful and is retained: loopback-only
Prometheus export, explicit global-recorder installation, supervisor-owned
exporter/bridge lifecycle, ProcessManager heartbeat truth, no admin coupling,
no Eggbench Rust dependency, preserved M002 telemetry-off output, and unchanged
WAF/security semantics.

The terminal qualification was reopened because direct producer/consumer audit
found four blocking classes of defects:

1. **Mapping schema incompatibility.** SynVoid emits a string mapping schema
   identifier, an extra top-level `contract_id`, and string aggregation on
   every field. Pinned Eggbench uses strict `#[serde(deny_unknown_fields)]`,
   requires numeric `schema_version = 1`, has no `contract_id`, accepts only
   `mean|max|min` for gauge trial aggregation, and requires counters to have
   no trial aggregation. The current materialized mapping therefore fails
   before a live trial starts.
2. **Owner/trial aggregation conflation and unit defect.** Producer-side worker
   aggregation such as `sum` and
   `supervisor_lifetime_monotonic_bridge` was incorrectly placed in
   Eggbench's trial-aggregation field. In addition,
   `body_buffering_bytes_total` is labeled with unit `events` instead of
   `bytes`.
3. **Generation/reset correctness.** The bridge counts a first nonzero worker
   observation as a reset, can count one first/reset boundary once per counter,
   and lacks explicit worker-generation identity. Because Unified Server
   workers respawn with the same WorkerId, a new process whose counters already
   exceed the previous process values can be undercounted.
4. **Evidence/retirement mismatch.** Production bridge state does not execute
   the claimed worker-retirement policy, and the rebased plan's required real
   Eggbench consumer proof was moved to an external residual rather than run
   before terminal closure.

Binding corrective decisions:

- do not silently rewrite the already-materialized v1 semantic contract;
- withdraw v1 as unqualified historical evidence and advance the corrected
  owner identity to `synvoid.eggbench-telemetry.v2`;
- preserve stable Prometheus sample names unless a separate concrete defect
  requires a rename;
- separate owner/source aggregation in the owner manifest from Eggbench trial
  aggregation in `telemetry-mapping.json`;
- make the mapping bytes directly parseable by Eggbench
  `PrometheusMappingV1` without translation;
- add explicit monotonic worker-generation identity in ProcessManager telemetry
  snapshots;
- distinguish first observation from generation/reset boundaries and count a
  boundary once, not once per metric;
- prune bridge state on the production refresh path;
- correct the stale generated `[tokio]` comment without changing Tokio
  runtime semantics;
- require an actual pinned Eggbench parser/collector interoperability proof
  before restoring `CLOSED QUALIFIED`.

No broad architecture phase and no Eggbench feature redesign were authorized by
this corrective. Existing M003c remains the downstream Eggbench consumer
authority. The corrective closed when the exact generated mapping was
accepted by that consumer (real pinned parser + collector proof, 16/16)
and a real minimal SynVoid trial succeeded end to end; see the terminal
closeout for proof-bearing SHAs and digests.


## Independent Cross-Repo Corrective: Eggbench M003 Telemetry Heartbeat Dispatch — Closed

Status: **CLOSED QUALIFIED** (2026-10-02).

Terminal closeout:
`architecture/eggbench_security_qualification_m003_telemetry_heartbeat_dispatch_corrective_closeout.md`.

Plan:
`plans/eggbench_security_qualification_m003_telemetry_heartbeat_dispatch_corrective.md`.

Corrective baseline:
`2002b6f82b5b94d9684390d132de535379c0644f`.

Downstream evidence baseline:

- `eggstack/eggbench@7689716c1b3cfaaab366756afc284a8eda0e0b64`;
- normal CI `36995287800`: Linux stable, Linux Rust 1.89, macOS stable and Windows stable all green;
- live qualification `36995287756`: every live job green except `live-m003-linux`, which exits 10 with `m003c-13b` as the single stopped gate.

Trigger/root cause:

- Unified Server workers already emit `Message::UnifiedServerWorkerHeartbeat`;
- `ProcessManager::handle_unified_server_worker_heartbeat` already stores the authoritative worker payload;
- the v2 telemetry bridge already consumes generation-aware ProcessManager snapshots;
- `src/supervisor/ipc.rs` does not dispatch `UnifiedServerWorkerHeartbeat`, so the message falls through `_ => {}` and ProcessManager retains default/stale metrics;
- the same message is absent from the worker-ID classifier, so it also falls back to the global IPC limiter and skips the established per-worker peer-PID identity path.

Corrective boundary:

1. centralize/reuse production worker-message identity classification rather than duplicating it in tests;
2. classify Unified Server heartbeat/ready and audit other worker-origin lifecycle messages for parity;
3. route `UnifiedServerWorkerHeartbeat` to the existing ProcessManager handler without changing payload semantics;
4. add a dispatch-boundary regression proving a distinctive non-default payload reaches the generation-aware snapshot;
5. prove dispatch -> ProcessManager -> v2 bridge -> Prometheus propagation for a gauge and counter;
6. rerun the real minimal SynVoid M002/M003 owner proofs;
7. pin the corrected owner revision in Eggbench and require unchanged `m003c-13b` plus exact-head four-lane and `live-m003-linux` green before terminal closure.

No v3 telemetry contract, heartbeat cadence change, WAF/security semantic change, Eggbench semantic relaxation, IPC wire change, or new load generator is authorized by this corrective. The closed v2 interoperability corrective remains the schema/generation authority; this new corrective owns the missing live heartbeat-routing proof.

Closure outcome:

- Proof-bearing SHAs `ccf926947acf5d7aaf07e5aa152bd7ecfc9798a2` and `1338ce7b60f3793701091b4c329f80eb542f802d`; four live-value defects repaired (missing supervisor dispatch arm, missing worker-ID classification, a second shadowing `WorkerMetrics` instance, and a lag accumulator seeded one cadence ahead).
- Minimal binary `251ac1d2e0c45be399570b3e2abcbb2925589bc01102eb2869585bcd7f8030f7`; contract `synvoid.eggbench-telemetry.v2` and mapping `622f6a13c4353cc7465cce39a57ed86fa0db2fe4114258e6f06226c1748d2d99` unchanged, so no contract renegotiation was needed.
- Eggbench terminal proof on closing revision `30a38251bccb5157beb68202ffe630f6253771e0`: four-lane CI `37143714313` and live external-tool qualification `37143714261` both green, with `m003c-13b` passing against the real pinned owner and all five live jobs green.
- Eggbench M003c, M003d, and the M003 milestone are now closed and hosted-qualified; the milestone's upstream conditional-closure gate is removed.
- Reaching that evidence required repairing three defects in Eggbench's own measurement and reporting (performance arms a suite apart, a live-value check that demanded a non-zero health gauge, and stop reasons pointing at deleted logs) plus one portability bound. Those are Eggbench-side, carry their own tests, and are recorded in the closeout; none relaxed a gate or an assertion.


## Post-Phase-91 ICMP Gate: Disabled-State Corrective and Linux nftables Native Qualification — Phases 92–93

Status: **Phase 92 CORRECTED; Phase 93 QUALIFIED (superseded by Phase 95);
Phase 95 CLOSED QUALIFIED** (2026-09-27). The Phase 95 corrective re-ran the
full two-pass native matrix on the exact proof-bearing SHA with 8/8 cases
per pass; Linux nftables is native-supported. Phase 88 remains RETAIN.

Roadmap:
`plans/icmp_linux_native_qualification_gate_roadmap.md`.

Baseline:
`826e634d7b9475c7b0b44badd2f51f07df6ddd17`.

Trigger: acceptance review after the Phase 90–91 closeout found lifecycle
semantics that should be corrected before the Phase 91 harness is used as
proof-bearing native qualification:

1. `drive_update()` treats `Absent` as failure even when the requested
   replacement is `enabled = false`, although verified absence is the correct
   terminal state;
2. `verify_live()` records every `Absent` outcome as an error, including
   healthy desired-disabled state;
3. committed `DriverState` desired fields are mutated before lifecycle
   operations are known to succeed, so a failed/rejected request can become
   operator-visible desired state;
4. repeated enable verifies the already-live generation but still advances
   generation and creates a new apply receipt despite no install;
5. the Phase 87/90 fake backend does not model disabled replacement as owned
   state absence, hiding the first defect;
6. the central Phase 90–91 roadmap registration still carried a stale
   "planned" label after closeout.

Execution order:

1. **Phase 92 — ICMP Disabled-State and Lifecycle Commit Semantics Corrective — CLOSED CORRECTED (2026-09-26)**
   - make update success depend on desired enabled/disabled state;
   - return no apply receipt for verified disabled absence;
   - stage/commit desired driver state transactionally;
   - make live verification desired-state-aware;
   - seed constructor desired truth without claiming live enforcement;
   - make repeated enable genuinely idempotent for generation/receipt;
   - correct fake-backend semantics and add admin regression for
     `PUT /icmp/config` with `enabled=false`;
   - reconcile the stale Phase 90–91 registry/docs.

   Plan:
   `plans/phase_92_icmp_disabled_state_lifecycle_corrective.md`.

 2. **Phase 93 — ICMP Linux nftables Native Qualification — QUALIFIED
    (superseded by Phase 95, 2026-09-27)**
    - execute the dual-gated Phase 91 netns/veth harness on a suitable
      privileged Linux host;
    - require install/readback, v4/v6 type/code, exemption, global rate-limit,
      replacement, drift, disable, and rollback cases;
    - require two consecutive clean runs with distinct run IDs;
    - preserve bounded machine-readable evidence and a binding architecture
      qualification record;
    - update only the Linux nftables evidence tier if native proof passes.

    Plan:
    `plans/phase_93_icmp_linux_nftables_native_qualification.md`.

Phase 93 run `36279326809` at SHA
`947e4f707cc5aefa9aca78a15b19d6ecfc8c04d4` passed Linux/tool/root
preflight and zero-mutation dry-run, then failed the native matrix 0/8 on
nftables batch syntax. The Phase 95 corrective (proof-bearing SHA
`39bfced25d51267ee5837eaecedae7da9af163d0`, hosted run `36335520434`,
passes `36335520434-a`/`36335520434-b` at 8/8 per pass) supersedes this
to **QUALIFIED**; Linux nftables is native-supported and Phase 88 RETAIN
remains authoritative with no extraction authorized. Details in
`plans/phase_95_icmp_nftables_batch_corrective.md`.

Terminal outcomes for Phase 93 are **QUALIFIED**, **FAILED**, or **BLOCKED**.
Skipped/refused/unavailable privileged execution is BLOCKED, never pass.

Constraints:

- Phase 88 RETAIN remains authoritative;
- no extraction/publication is authorized;
- no fake apply receipt for disabled/no-op state;
- failed lifecycle mutations cannot silently replace committed desired state;
- Linux proof cannot upgrade eBPF/PF/WFP/Windows evidence tiers;
- qualification must remain isolated from the host/default firewall namespace.

Phase 92 is CLOSED CORRECTED. Phase 93 is QUALIFIED (superseded by the
Phase 95 exact-SHA two-run proof). Its binding record is
`architecture/icmp_linux_nftables_native_qualification.md`; Phase 95 is
closed QUALIFIED and the gate is terminally shut.

## Post-Phase-93 Corrective: Process Sandbox Qualification Closure — Phase 94 Closed

Status: **CLOSED — QUALIFIED** 2026-09-26.

Plan:
`plans/phase_94_process_sandbox_qualification_corrective.md`.

Baseline:
`bb69e0a43e58cddd0cd047b6a146726b6d12cff6`.

Trigger: Phase 89 landed the intended single-entry and guarantee-selected
seccomp architecture, but its terminal qualification was premature:

1. hosted GitHub Actions run `36257121876` failed
   `cargo xtask verify` at the `-D warnings` Clippy gate;
2. Linux `MechanismPlan::filesystem_requested` is computed but
   `PreparedSandbox::enter()` still applies Landlock unconditionally;
3. Linux native seccomp probes still enter through legacy
   `ProcessSandbox::with_paths(Strict, ...)`, which Phase 89 deliberately
   decoupled from seccomp.

Phase 94 scope:

- restore exact-head hosted CI proof;
- make Linux mechanism selection operative at entry;
- make final filesystem as well as seccomp truth installation-backed;
- split legacy Landlock filesystem qualification from guarantee-driven seccomp
  qualification;
- directly prove NetworkDenied / ChildCreationDenied / ExecDenied and category
  isolation on the production entry path;
- keep real jail WASM/YARA workload proof under the combined policy;
- reconcile Phase 89/closeout evidence without reopening extraction.

Constraints:

- Phases 81–84 remain closed **DEFER**;
- Phase 89 remains historical implementation evidence, not terminal hosted
  proof;
- ICMP Phases 92–93 are independent and unchanged;
- no standalone sandbox crate/repository;
- no system `libseccomp` dependency;
- no global legacy sandbox-level semantic change;
- unsupported-host early return is not native enforcement proof;
- no closure without green `ci` + `dependency-security` on the exact
  proof-bearing SHA.

Phase 94 closed at proof-bearing SHA
`e86fb35372b1b66bb59c8a6336bf32e55ff5c93e`. Run `36271417398` passed
`ci`, `dependency-security`, and the opt-in Linux native qualification lane.
Phases 81–84 remain historically closed DEFER; no extraction phase is
registered by this closeout.

## Post-Phase-94 Corrective: ICMP nftables Batch Semantics — Phase 95 Closed Qualified

Status: **CLOSED — QUALIFIED** (2026-09-27).

Plan:
`plans/phase_95_icmp_nftables_batch_corrective.md`.

Phase 93 run `36279326809` failed 0/8 on the `flush table` + declarative
table batch. Phase 95 corrected the backend to a single atomic imperative
batch (destroy+add, double-protocol matches, limit-before-allow, owned
delete argv, echo-reply pairing) with deterministic grammar tests, fixed
one harness-only burst-reliability defect (flood instead of interval),
and re-ran the full two-pass matrix on proof-bearing SHA
`39bfced25d51267ee5837eaecedae7da9af163d0` (hosted run `36335520434`,
passes `36335520434-a`/`36335520434-b`, 8/8 per pass, verified cleanup,
both JSON artifacts). Linux nftables is native-supported; Phase 93 is
superseded QUALIFIED. Phase 88 remains RETAIN, and no
extraction/publication is authorized by this closeout. No registered
future plan was blocked on Phase 95.


## Post-Phase-95 Campaign: Architecture Maintenance and Auditability — Phases 96–101 Closed

Status: **CLOSED QUALIFIED** (registered 2026-09-28; closed 2026-09-29).
Phases 96–101 are implemented and closed. Proof-bearing implementation SHA:
`2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`; hosted run 36515438452 passed.
See `architecture/architecture_maintenance_auditability_closeout.md`.

Roadmap:
plans/architecture_maintenance_auditability_roadmap.md.

Planning baseline:
30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2.

Trigger: current-head crate-architecture review found several clean
maintenance/auditability seams that can reduce capability reach without
removing features:

1. synvoid-metrics reaches upward into synvoid-waf only for AttackType metric
   keys, while operator/IPC payloads are already string-keyed;
2. synvoid-block-store reaches upward into synvoid-waf only for the generic IP
   MitigationProvider contract;
3. synvoid-jail-runtime consumes the broad synvoid-ipc crate even though its
   child-side trust contract is the small versioned SVJL wire protocol;
4. HTTP/3-specific request/stream state machines live primarily in
   synvoid-http while synvoid-http3 owns the QUIC/H3 server;
5. high-fanout synvoid-config combines model/schema ownership with file
   loading/ConfigManager and mesh key-realization behavior;
6. synvoid-mesh is a justified large subsystem, but MeshTransport and several
   integrations expose broader internal/application capability than individual
   tasks require.

This campaign is explicitly **not** a feature-removal or crate-count effort.
Completed root composition decisions remain closed. Existing configuration,
default/minimal feature behavior, H1/H2/H3, WAF/proxy, mesh/DNS, jail
WASM/YARA execution, upload/honeypot integration, admin behavior, and
distributed-state authority must be preserved.

Execution order:

1. **Phase 96 — Workspace Dependency Direction and Guard Baseline — CLOSED**
   - remove avoidable metrics -> WAF and block-store -> WAF edges;
   - use the canonical core restricted-IP helper directly where mesh currently
     reaches through proxy;
   - audit manifest entitlement;
   - add a workspace dependency-direction guard.
   - Closeout: architecture/workspace_dependency_direction_phase96_closeout.md.
   - Plan: plans/phase_96_workspace_dependency_direction_and_guard_baseline.md.

2. **Phase 97 — Jail Protocol Boundary Extraction — CLOSED**
   - create an internal low-capability synvoid-jail-protocol leaf;
   - move only v1 wire DTOs/bounds/validation/framing/digest/policy vocabulary;
   - keep binary resolution, process supervision, restart/quarantine, and
     parent lifecycle in synvoid-ipc;
   - make synvoid-jail-runtime consume the protocol leaf directly;
   - require byte-identical SVJL v1 golden vectors and unchanged jail package
     behavior.
   - Closeout: architecture/jail_protocol_phase97_closeout.md.
   - Plan: plans/phase_97_jail_protocol_boundary_extraction.md.

3. **Phase 98 — HTTP/3 Ownership Realignment**
   - move H3-specific stream/request state machines from synvoid-http to
     synvoid-http3;
   - retain one shared protocol-neutral security/policy layer;
   - preserve EggServe H1, Hyper H2, and quinn/h3 H3 production ownership;
   - prohibit synvoid-http <-> synvoid-http3 cycles.
   - Status: CLOSED; closeout: architecture/http3_ownership_phase98_closeout.md.
   - Plan: plans/phase_98_http3_ownership_realignment.md.

4. **Phase 99 — Configuration Model / Runtime Capability Separation**
   - characterize the existing config compatibility surface first;
   - separate lower-capability DTO/default/pure-validation ownership from
     ConfigManager/file loading/reload/mutation;
   - consolidate mesh identity/key realization onto one runtime owner without
     changing key formats or derivation;
   - migrate only true model-only consumers to the lower-capability boundary;
   - create synvoid-config-model only if the measured boundary is materially
     lower-capability.
   - Status: CLOSED; closeout: architecture/config_model_phase99_closeout.md.
   - Plan: plans/phase_99_configuration_model_runtime_separation.md.

5. **Phase 100 — Mesh Capability Decomposition**
   - decompose ambient MeshTransport authority into cohesive internal
     capability groups;
   - replace broad friend-style access with explicit state/service handles;
   - narrow application integrations such as upload/YARA, honeypot/intel, and
     mesh HTTP proxy bridges where consumer-owned adapters reduce full-mesh
     dependency reach;
   - preserve canonical-vs-advisory authority and lifecycle/task ownership;
   - do not create a mesh-consensus crate merely because mesh is large.
   - Status: CLOSED; closeout: architecture/mesh_capability_decomposition_phase100_closeout.md.
   - Plan: plans/phase_100_mesh_capability_decomposition.md.

6. **Phase 101 — Architecture Maintenance Qualification and Closeout**
   - recompute cargo metadata/tree rather than trusting plan counts;
   - prove capability/config/wire compatibility;
   - run focused performance/footprint and dependency-security evidence;
   - reconcile current architecture/release docs;
   - adjudicate future mesh-consensus, process-manager/IPC, and synvoid-filter
     simplification candidates without implementing a new extraction inside
     closeout;
   - require exact-SHA hosted CI/dependency-security proof for terminal closure.
   - Status: CLOSED QUALIFIED; exact-SHA local release and hosted CI/dependency-security evidence passed. Future candidates remain RETAIN/DEFER as recorded in the campaign closeout.
   - Plan: plans/phase_101_architecture_maintenance_qualification_closeout.md.

Binding constraints:

- no supported feature/protocol/backend/config surface is removed to simplify
  the graph;
- no WAF enforcement-precedence or distributed-state authority change is
  hidden in architectural movement;
- jail wire semantics remain protocol v1 unless a separate protocol-change
  plan is opened;
- no new class-3/public crate support promise is created;
- no dependency cycle is introduced to preserve an internal compatibility
  path;
- no low-level crate receives domain-specific types merely to make arrows look
  cleaner;
- no count-only crate split/merge;
- routine CI remains proportionate and focused.

No registered downstream plan was blocked on this campaign. Mesh-consensus
and process-manager/IPC extraction remain deferred; synvoid-filter remains
retained. These are candidate decisions, not newly registered executable
plans.

## Post-Phase-101 Maintenance: Eggfetch 0.2.1 Patch Adoption — Phase 102 Closed Qualified

Status: **CLOSED QUALIFIED** (2026-10-01).

Plan:
plans/phase_102_eggfetch_0_2_1_patch_adoption.md.

Closeout:
architecture/eggfetch_0_2_1_patch_adoption_closeout.md.

Planning baseline:
0dc1f7fb21a5df60e72fc7f2cd60b7cb73bc9f35.

Upstream target:
eggstack/eggfetch v0.2.1 (eggfetch-core 0.2.1), published 2026-09-26.

Research disposition: the upstream v0.2.0...v0.2.1 comparison contains no
production changes under crates/eggfetch-core/src. The core manifest changes
only the package version and the optional eggfetch-http-connect version.
Upstream explicitly records no runtime/user-visible, API, feature/default,
MSRV, or dependency-policy change. SynVoid's current feature closure does not
enable eggfetch proxy support and Cargo.lock contains no eggfetch-http-connect.

Phase 102 owned a narrow exact-pin refresh from eggfetch-core =0.2.0
to =0.2.1, targeted lockfile qualification, existing transport/TLS/parity
regression evidence, feature/dependency-security verification, and a small
closeout record. It did **not** reopen the closed transport architecture or
Phase 63 performance campaign — no SynVoid production source change was
required; the lock delta was exactly one package version + checksum.

Binding constraints satisfied:

- exact pre-1.0 dependency pin retained (`eggfetch-core =0.2.1`) and
  existing native-http1/native-http2/tls-rustls/tls-native-roots feature
  set preserved;
- no opportunistic eggfetch proxy/H3/retry/redirect/compression/cookie
  adoption;
- explicit aws-lc-rs/PQ, fail-closed TLS, SNI/custom-CA,
  streaming/trailer, timeout, UDS, resolved-target, and pool semantics
  preserved;
- Phases 58-64 retained as historical 0.2.0 evidence rather than
  rewritten;
- no unrelated lockfile drift accepted;
- no full benchmark rerun (Phase 63 evidence remains the upstream-cited
  historical authority; the patch is exactly the version + checksum of
  one package with no source change).

Qualification ledger:

- `cargo test -p synvoid-http-client --profile ci`: 105/105 passed
  (59 unit + 33 eggfetch_qualification + 13 egress_parity);
- `cargo xtask test package synvoid-http-client`: 105/105 passed;
- `cargo check -p synvoid-http-client --no-default-features --features post-quantum`:
  clean;
- `cargo check --no-default-features --features post-quantum`: clean;
- root guard suite (`--features mesh`): 647/647 passed;
- core admin tests: 16/16 passed;
- admin contract (`--features mesh,dns,icmp-filter`): 66/66 passed;
- `cargo test --test security_regression --profile ci -- --test-threads=1`:
  15/15 passed;
- `cargo test --test failure_injection --profile ci`: 10/10 passed;
- `cargo fmt --all -- --check`, `cargo clippy --profile ci --all-targets -- -D warnings`,
  `cargo check --no-default-features --profile ci`: clean.

Pre-existing baseline failures (`cargo deny check` for RUSTSEC-2026-0315 /
RUSTSEC-2026-0316 on wasmtime 36.0.15 + 47.0.4, and the
`advisory_ignores_carry_owner_and_review_metadata` re-audit-date
deny.toml guard test) are unchanged on the planning head and are not
introduced by this patch. They remain owned by the routine
`dependency-security` CI job / daily schedule and the Phase 25 dependency
security baseline re-audit cycle.

No registered future plan was blocked on Phase 102. The Phase 102 plan
itself is the only `ACTIVE` plan at registration; the post-Phase-101
residual candidates (mesh-consensus DEFER, process-manager/IPC DEFER,
synvoid-filter RETAIN) are not implicitly authorized or unblocked as
implementation work by this closure.

## Post-Phase-102 Maintenance: Dependency Security Re-audit and Wasmtime Remediation — Phase 103 CLOSED QUALIFIED

Status: **CLOSED QUALIFIED** (2026-10-01).

Closeout:
`architecture/dependency_security_reaudit_phase103_closeout.md`.

Plan:
`plans/phase_103_dependency_security_reaudit_and_wasmtime_remediation.md`
(now marked CLOSED QUALIFIED at the top).

Planning baseline:
`daaa154a9bc16f1922da891ad368a7a28da35268`.

Proof-bearing implementation SHA:
`aeeebc7bac38b1dcc441b06f53c838a74582cd24`.

Hosted CI run: `36891196284` (`ci` success; `dependency-security` success;
`icmp-native-qualification` and `sandbox-native-qualification` skipped — out
of scope for Phase 103). URL:
https://github.com/dbowm91/synvoid/actions/runs/36891196284

Terminal disposition:

- direct Wasmtime resolved to **36.0.16** LTS (in-line patch from 36.0.15;
  patched for RUSTSEC-2026-0316);
- transitive YARA Wasmtime resolved to **48.0.3** (manifest-only delta from
  47.0.4 in the same `third-party/yara-x-compat` fork; vendored yara-x 1.20.0
  `src/` and `build.rs` byte-identical to official; patched for
  RUSTSEC-2026-0315 and RUSTSEC-2026-0316);
- no new ignore for either finding — both version-remediated;
- retained advisory exceptions (`RUSTSEC-2023-0071` rsa 0.9.10 and
  `RUSTSEC-2026-0235` rkyv 0.7.46) refreshed with re-triaged current-path
  capability evidence (Reviewed: 2026-10-01; Re-audit: 2026-11-01);
- both temporary compatibility forks (`minify-html-compat`, `yara-x-compat`)
  refreshed with Reviewed: 2026-10-01 / Re-audit: 2026-11-01; the fork
  guards now reuse a shared `evaluate_fork_block` helper that
  semantically validates Owner / Reviewed / Re-audit / Removal condition
  per fork metadata block, with strict calendar format and time-aware
  future-deadline enforcement (overridable for deterministic tests via
  `SYNVOID_SECURITY_REVIEW_AS_OF`; same override used by
  `deny_ignore_metadata_guard`).
- stock yara-x 1.21.0 (released 2026-09-29) still resolves `wasmtime ^45.0.3`
  (verified via crates.io dependency API) and therefore does NOT satisfy
  the removal condition for the `yara-x` fork; the fork stays in place.

Future-plan unblocking: no registered SynVoid plan was blocked on Phase 103.
No previously-blocked plan is unblocked by this closure. The post-Phase-101
architecture-maintenance campaign remains closed with the recorded residual
candidates (mesh-consensus DEFER, process-manager/IPC DEFER, `synvoid-filter`
RETAIN); these are not implicitly authorized or unblocked by Phase 103.

Historical research / execution-shape / binding-constraints notes from the
ACTIVE version of this section are preserved in the planning registration
SHAs (`5f680f81` plan, `d960f473` registration) and are not re-stated here.

## Post-Phase-103 Corrective: Qualification Evidence and Provenance — Phase 104 CLOSED QUALIFIED

Status: **CLOSED QUALIFIED** (2026-10-01).

Plan:
`plans/phase_104_phase103_qualification_evidence_corrective_closeout.md`
(now marked CLOSED QUALIFIED at the top).

Closeout:
`architecture/dependency_security_phase104_corrective_closeout.md`.

Proof-bearing implementation SHA:
`e0032cd176cd1061a3aa5877555f49ebc4f46a3b`.

Hosted CI run: `36901352762` (`ci` success; `dependency-security` success;
`icmp-native-qualification` and `sandbox-native-qualification` skipped — out
of scope for Phase 104). URL:
https://github.com/dbowm91/synvoid/actions/runs/36901352762

Terminal disposition:

- same-host, same-fixture paired YARA comparison across `d960f473`
  (Wasmtime 47.0.4) → `aeeebc7b` (Wasmtime 48.0.3) shows no repeatable
  regression (pass-1 deltas -5.14%/-3.43%/-10.58%/-1.83% with two rerun
  triggers; rerun deltas -3.41%/+4.37%/-0.53%/-0.21% all within ±5%);
- Phase 103 closeout performance section corrected to reference the paired
  evidence (Phase 40 data demoted to explicitly non-comparable historical
  context);
- Wasmtime 48 LTS provenance corrected to “released 2026-08-20 and
  supported for 24 months” per upstream policy/release record;
- dependency graph unchanged (direct 36.0.16 + YARA 48.0.3, no WASI
  filesystem, no git source, no 0315/0316 ignores);
- focused YARA/repo-guard/security verification plus `cargo xtask verify`
  (10/10) green; hosted exact-SHA proof green.

Future-plan unblocking: no registered SynVoid plan was blocked on Phase 104.
No previously-blocked plan is unblocked by this closure. Residual triggers
remain those recorded in the Phase 103/104 closeouts.

Historical execution-shape notes from the ACTIVE version of this section are
preserved in the planning registration SHAs (`c3242aa7` plan, `3af7aa42`
registration, `e0032cd1` implementation) and are not re-stated here.

Scope: corrective closeout only. Phase 103's dependency-security remediation
remains the accepted production state: direct Wasmtime 36.0.16 LTS,
YARA-transitive Wasmtime 48.0.3, no Wasmtime 0315/0316 ignores,
`wasmtime-wasi`/filesystem absent, no git source, and the YARA compatibility
fork still manifest-only against official yara-x 1.20.0 source.

Phase 104 owns two residual qualification defects:

1. Phase 103 Workstream G required a same-host/same-fixture before/after YARA
   measurement across Wasmtime 47.0.4 -> 48.0.3, but the landed closeout
   records only the post-change Phase 103 probe and compares it to Phase 40
   measurements with a different corpus/payload. That evidence is not an
   apples-to-apples regression proof.
2. `third-party/yara-x-compat/README.SYNVOID.md` incorrectly says Wasmtime 48
   LTS is supported for 24 months from 2026-06-04. Wasmtime 48.0.0 was
   released 2026-08-20; upstream policy defines majors divisible by 12 as LTS
   releases supported for 24 months.

Corrective execution:

- reconstruct one deterministic YARA compile/clean-scan/match-scan/reload
  fixture and run it on both `d960f473...` (Wasmtime 47.0.4 baseline) and
  `aeeebc7b...` (Wasmtime 48.0.3 implementation) on the same host/profile;
- record raw medians/min/max and percentage deltas for all four operations;
- rerun any >5% median shift; a repeatable >10% regression blocks docs-only
  closure and requires a separate runtime/performance corrective plan;
- replace the Phase 103 non-comparable performance claim with the paired
  evidence, retaining Phase 40 data only as explicitly non-comparable
  historical context if useful;
- correct the Wasmtime 48 release/support provenance from authoritative
  upstream release/support data;
- prove Cargo.lock/dependency ownership remains unchanged;
- re-run focused YARA/repo-guard/security verification plus
  `cargo xtask verify`;
- require hosted `ci` and `dependency-security` green on the exact Phase
  104 proof-bearing SHA before closeout.

Binding constraints:

- no production dependency/version change is expected or authorized;
- no security-policy or advisory-ignore change;
- no YARA source-fork expansion;
- no benchmark tuning to manufacture a pass;
- no acceptance of a repeatable >10% regression without a separate
  investigation;
- no unrelated roadmap/documentation cleanup.

Terminal closeout:
`architecture/dependency_security_phase104_corrective_closeout.md`.

## Post-Phase-104 Campaign: Subsystem Boundary and Extraction — Phases 105–112 CLOSED QUALIFIED

Status: **CLOSED QUALIFIED** (2026-10-02; proof-bearing SHA `e7c0ec5a1317599b6f98e37a534b53544842a29c`; hosted CI/dependency-security run `36955732943` passed).

Umbrella roadmap:
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline:
`19c0636535f3728e80b7c6777ec6a552c38c61a0`.

Purpose: reduce SynVoid's repository-level maintenance and audit surface by
extracting or externalizing only subsystems with independent lifecycle,
security, compatibility, and release boundaries. This is not a crate-count
campaign. Existing closed RETAIN/DEFER decisions remain binding until their
explicit triggers are satisfied.

Execution lanes:

1. **Phase 105 — DNS Hickory Patch Adoption and Security Requalification**
   - move the resolved Hickory 0.26.1 DNS graph to the qualified 0.26.3 patch
     line with targeted lockfile churn;
   - requalify DNSSEC, recursive resolution, cache/error behavior, encrypted
     DNS transport integration, and DNS/mesh+DNS profiles;
   - establish the dependency/security baseline required by Phase 108.
   - Status: **CLOSED QUALIFIED** (2026-10-01).
   - Plan: `plans/phase_105_dns_hickory_patch_security_requalification.md`.

2. **Phase 106 — Honeypot Application-Neutral Boundary Preparation**
   - reconcile the current dual config vocabularies and make the honeypot own
     its runtime configuration;
   - remove unnecessary `synvoid-config-model`, `synvoid-http-client`, and
     `synvoid-utils` coupling;
   - preserve injected threat publication, AI budgets, retention/privacy, and
     storage behavior;
   - prove standalone package behavior without creating a new repository yet.
   - Status: **CLOSED QUALIFIED** (2026-10-01; proof-bearing SHA
     `a87d0b0c`). Routine and full verification passed; Phase 107 is unblocked.
   - Plan: `plans/phase_106_honeypot_application_neutral_boundary.md`.

3. **Phase 107 — Honeypot Standalone Qualification and Extraction Decision**
   - requires Phase 106;
   - prove an out-of-workspace consumer, threat model, MSRV/package/release
     hygiene, and explicit API/semver classification;
   - terminal disposition is GO EXTRACT, DEFER, or RETAIN from evidence; no
     automatic publication.
   - Status: **CLOSED DEFER** (2026-10-01). Packaged source and outside-workspace
     consumer passed; extraction is deferred on explicit release/security and
     support prerequisites. See
     `architecture/honeypot_standalone_qualification_phase107.md`.
   - Plan:
     `plans/phase_107_honeypot_standalone_qualification_extraction_decision.md`.

4. **Phase 108 — DNS Hickory Delegation and Ownership Simplification**
   - requires Phase 105;
   - classify DNS modules as DELEGATE / WRAP / RETAIN / DEFER against qualified
     Hickory;
   - remove redundant baseline protocol machinery only behind differential and
     security evidence;
   - preserve SynVoid-specific health/Geo, firewall/RPZ, HSM custody,
     mesh/distributed integration, and operational semantics.
    - Status: **CLOSED QUALIFIED** (2026-10-01; no unsafe deletions).
    - Plan:
      `plans/phase_108_dns_hickory_delegation_ownership_simplification.md`.

5. **Phase 109 — DNS Application-Neutral Boundary and Extraction Readiness**
   - requires Phase 108;
   - move runtime config ownership into DNS, invert mesh/Geo/TLS/platform
     integration behind narrow adapters, and keep DNSSEC key custody separate;
   - prove a standalone DNS consumer and decide GO EXTRACT / DEFER / RETAIN.
   - Status: **CLOSED DEFER** (2026-10-02). One unused platform edge was
     removed; six required SynVoid siblings and optional mesh remain active.
     Exact runtime-boundary work is recorded in
     `architecture/dns_application_neutral_readiness_phase109.md`.
   - Plan:
     `plans/phase_109_dns_application_neutral_boundary_extraction_readiness.md`.

6. **Phase 110 — Mesh Consensus and DHT Boundary Decomposition**
   - preserve the Phase 101 decision against aggregate mesh extraction;
   - isolate canonical consensus/state-machine and advisory DHT mechanisms only
     when they can be application-service-free one-way boundaries;
   - preserve canonical-vs-advisory authority, replay, freshness, partition, and
     wire semantics;
   - no external mesh repository/publication.
   - Status: **CLOSED — RETAIN INTERNAL** (2026-10-02); no independent one-way
     consensus/DHT seam qualified. Ownership map:
     `architecture/mesh_boundary_decomposition_phase110.md`.
   - Plan: `plans/phase_110_mesh_consensus_dht_boundary_decomposition.md`.

7. **Phase 111 — SynVoid Tunnel / Eggtunnel / Eggress Convergence**
   - build a capability/symbol matrix across SynVoid tunnel/VPN, Eggtunnel and
     Eggress;
   - adopt or upstream generic session/QUIC/relay mechanisms where parity and
     maintenance reduction are demonstrated;
   - retain SynVoid route/mesh/VPN policy and explicitly adjudicate
     UDP/datagram and WireGuard/TUN ownership;
   - do not create a standalone SynVoid tunnel repository.
   - Status: **CLOSED DEFER** (2026-10-02); Eggtunnel source was unavailable and
     Eggress transport does not prove tunnel protocol parity. Evidence:
     `architecture/tunnel_convergence_phase111.md`.
   - Plan: `plans/phase_111_tunnel_eggtunnel_eggress_convergence.md`.

8. **Phase 112 — Extraction Gate Refresh and Campaign Closeout**
   - recompute final dependency/maintenance-surface evidence;
   - refresh ICMP RETAIN triggers (including the now-satisfied Linux native
     qualification trigger), process-sandbox DEFER triggers plus current
     ecosystem differential, and YARA upstream/second-consumer triggers;
   - reconcile honeypot/DNS terminal decisions and mesh/tunnel ownership;
   - require exact-SHA hosted CI/dependency-security proof for CLOSED QUALIFIED.
   - Status: **CLOSED QUALIFIED** (2026-10-02); proof-bearing SHA
     `e7c0ec5a1317599b6f98e37a534b53544842a29c`; hosted CI/dependency-security
     run `36955732943` passed.
   - Plan: `plans/phase_112_extraction_gate_refresh_campaign_closeout.md`.

Binding constraints:

- no supported runtime capability is removed to make extraction easier;
- no repository move may leave the extracted library depending on SynVoid
  application/runtime crates without a documented unavoidable reason;
- repository location does not imply class-3/public API stability;
- security-sensitive platform support requires native proof;
- DNS simplification must prove parity/security before deleting custom
  mechanisms;
- aggregate `synvoid-mesh` remains in SynVoid unless a future plan separately
  proves a clean external boundary;
- tunnel genericity converges toward Eggtunnel/Eggress rather than spawning a
  competing repository;
- Phase 88 ICMP RETAIN, Phase 84/94 sandbox DEFER, and current YARA fork-removal
  gates are not silently superseded by registration of this campaign.

## Post-Phase-112 Corrective and Follow-up — Phases 113–114

Status: **CLOSED QUALIFIED** (2026-10-02; both follow-ups closed, no downstream plan unblocked).

The Phase 105–112 campaign remains CLOSED QUALIFIED. These phases repair a
documentation inconsistency discovered after closeout and refresh the one
cross-repository evidence gap that Phase 111 could not inspect. They do not
reopen the qualified implementation baseline or authorize an extraction/adoption.

### Phase 113 — Subsystem Boundary Closeout Evidence Reconciliation

Status: **CLOSED QUALIFIED** (2026-10-02; docs-only reconciliation).

Plan:
`plans/phase_113_subsystem_boundary_closeout_evidence_reconciliation.md`.

Purpose:

- replace the stale Pending verification table in
  `architecture/subsystem_boundary_extraction_closeout.md` with the already
  proven final results;
- reconcile the detailed roadmap/umbrella status text with the terminal
  CLOSED QUALIFIED campaign state;
- correct the stale Phase 108 `PLANNED / READY` entry;
- preserve `e7c0ec5a1317599b6f98e37a534b53544842a29c` and hosted run
  `36955732943` as the Phase 112 proof-bearing evidence;
- make no production, dependency, support-tier, or domain-disposition change.

This is documentation/evidence reconciliation only.

### Phase 114 — Tunnel / Eggtunnel Protocol Parity and Convergence Refresh

Status: **CLOSED QUALIFIED** (2026-10-02; RETAIN + DEFER relay reuse; evidence `architecture/tunnel_eggtunnel_parity_phase114.md`; no migration, no cross-repo plan registered, nothing unblocked).

Plan:
`plans/phase_114_tunnel_eggtunnel_protocol_parity_and_convergence_refresh.md`.

Research baseline:

- SynVoid planning baseline:
  `4d957b2e90c29c018430bdac8af830b9db91b19a`;
- Eggtunnel source baseline:
  `eggstack/eggtunnel@ece46fd223265b7b0609e3640b0caa9efadd1535`.

Purpose:

- supersede only Phase 111's unavailable-Eggtunnel-source evidence gap;
- compare SynVoid framing/auth/session/registration/reconnect/drain/QUIC/relay/
  datagram/VPN/mesh semantics directly against Eggtunnel and Eggress;
- distinguish Eggtunnel's published `0.2.0` wire 1.0 behavior from current
  repository source implementing wire 1.1 at the same workspace version;
- produce explicit ADOPT / ADAPT / UPSTREAM / RETAIN / DEFER dispositions;
- register any required generic upstream work in the actual Eggtunnel/Eggress
  owner repository before SynVoid deletes or forks equivalent mechanism code.

Phase 114 is an evidence/architecture phase. No production protocol replacement,
long-lived git dependency, UDP extension, or Eggtunnel adoption is authorized
until a subsequent scoped implementation plan is registered from its findings.

Binding constraints:

- Phase 105–112 remains CLOSED QUALIFIED; Phase 113 does not change its
  proof-bearing implementation SHA.
- Phase 111 remains historically truthful that Eggtunnel source was unavailable
  to that implementation pass; Phase 114 adds new evidence rather than rewriting
  history.
- QUIC transport equivalence is not tunnel-protocol equivalence.
- SynVoid wire compatibility, mesh authority, VPN/TUN/WireGuard behavior, and
  authenticated datagram semantics cannot change incidentally.
- Published/released Eggtunnel capability must be distinguished from unreleased
  current-source capability.
- ICMP RETAIN, sandbox DEFER, YARA DEFER, honeypot DEFER, DNS DEFER, and mesh
  RETAIN INTERNAL remain unchanged by these registrations.



## Post-Phase-114 Campaign: Standalone-Capable Crate Generalization — Phases 115–123 CLOSED

Status: **CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS** (2026-10-02; closeout:
`architecture/standalone_crate_phase123_closeout.md`). No class-3 promotion or
repository-extraction follow-up was justified. Two distinct exact-SHA hosted
proofs exist and must not be conflated: campaign-branch head
`f81182149889e21c4908b7ee38c74bc6b4518f6b` (run `37064917481`, `ci` +
`dependency-security` success) and merged-main head
`cacd44bffe097d7c62e3ddb0c5816967498a7bde` (run `37218651222`, `ci` +
`dependency-security` success). Native macOS and live HSM evidence remain
external gates; the two optional native qualification jobs were skipped by
their false-by-default inputs on both runs.

Terminal dispositions: 115 CLOSED / ROUTINE QUALIFICATION DEFERRED; 116 CLOSED
DEFER; 117 CLOSED DEFER (116 predecessor not delivered); 118 CLOSED DEFER; 119
CLOSED DEFER (118 predecessor not delivered); 120 CLOSED RETAIN; 121 CLOSED
DEFER with Linux package proof; 122 CLOSED CLASS 2 with live-HSM deferred and
RSA promotion blocked; 123 CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS. See
`architecture/standalone_crate_phase124_closeout.md` for the reconciled
branch-head/merge-head evidence statement and the stale-status classification
ledger.

Umbrella roadmap:
`plans/standalone_crate_generalization_roadmap.md`.

Planning baseline: `main` at
`10ac2e330d74d012819c592b395f67ee8cc09a38`.

Purpose: keep SynVoid as a monorepo while making selected subsystem crates
genuinely usable as standalone Rust packages. Standalone-capable class 2 is
explicitly distinct from class-3/public support and from separate-repository
extraction. No phase in this campaign publishes a new crate or creates an
external repository.

Execution lanes:

1. **Phase 115 — Standalone Crate Contract and Dependency Baseline**
   - Status: **CLOSED / ROUTINE QUALIFICATION DEFERRED** (2026-10-02; implementation `c968594`).
   - Plan: `plans/phase_115_standalone_crate_contract_and_baseline.md`.
   - Defines the standalone-capable class-2 contract, reproducible dependency
     inventory and packaged outside-workspace consumer harness.
   - Closeout: `architecture/standalone_crate_phase115_closeout.md`. Focused
     guard/tooling/package-consumer checks passed; `cargo xtask verify` was
     stopped during failure-injection compilation after earlier routine stages
     passed, so the phase is not labeled qualified.
   - The interrupted local run remains a truthful historical fact and is not
     restated as a pass. Terminal routine verification for the campaign is the
     hosted Verify job: campaign branch head `f8118214` (run `37064917481`)
     and merge head `cacd44bf` (run `37218651222`).

2. **Phase 116 — DNS Runtime-Config and Core Neutralization**
   - Status: **CLOSED DEFER** (2026-10-02; DTO/adapters/parity gate incomplete).
   - Plan: `plans/phase_116_dns_runtime_config_core_neutralization.md`.
   - Moves runtime config ownership into DNS, removes application core/helper
     reach while preserving persisted SynVoid config and behavior.
   - Closeout: `architecture/standalone_crate_phase116_closeout.md`.

3. **Phase 117 — DNS Provider Inversion and Standalone Consumer Qualification**
   - Status: **CLOSED DEFER — Phase 116 predecessor not delivered** (2026-10-02).
   - Plan: `plans/phase_117_dns_provider_inversion_standalone_consumer.md`.
   - Inverts TLS/Geo/mesh/lifecycle dependencies and requires an outside-
     workspace authoritative/resolver/DNSSEC/encrypted-transport consumer.
   - Hickory remains the protocol foundation; no duplicate DNS stack is
     authorized.
   - Closeout: `architecture/standalone_crate_phase116_closeout.md`.

4. **Phase 118 — Mesh Application-Dispatch Capability Inversion**
   - Status: **CLOSED DEFER** (2026-10-02; active dispatch/state owners need typed async seam and parity tests).
   - Plan: `plans/phase_118_mesh_application_dispatch_capability_inversion.md`.
   - Removes concrete proxy/cache/tunnel/serverless/application dispatch from
     reusable peer/runtime mechanisms while preserving canonical-vs-advisory
     authority.
   - Closeout: `architecture/standalone_crate_phase118_closeout.md`.

5. **Phase 119 — Mesh Runtime Extraction Decision and Standalone Qualification**
   - Status: **CLOSED DEFER — Phase 118 predecessor not delivered** (2026-10-02).
   - Plan: `plans/phase_119_mesh_runtime_extraction_standalone_qualification.md`.
   - Creates an internal `synvoid-mesh-runtime` only if a real one-way seam is
     proven; RETAIN is an acceptable outcome. rust-libp2p/Iroh/noq overlap must
     be adjudicated before adding another generic networking layer.
   - Closeout: `architecture/standalone_crate_phase118_closeout.md`.

6. **Phase 120 — Sandbox Guarantee-Boundary Internal Crate Split Decision**
   - Status: **CLOSED RETAIN** (2026-10-02; no proven dependency-reachability reduction).
   - Plan: `plans/phase_120_sandbox_guarantee_boundary_crate_split.md`.
   - Evaluates moving the guarantee/evidence/native-backend contract out of
     broad `synvoid-platform` into internal `synvoid-sandbox`; external
     extraction remains DEFER.
   - Closeout: `architecture/standalone_crate_phase120_closeout.md`.

7. **Phase 121 — Honeypot Standalone-Package Hardening**
   - Status: **CLOSED DEFER — native macOS qualification unavailable** (2026-10-02).
   - Plan: `plans/phase_121_honeypot_standalone_package_hardening.md`.
   - Closes Phase 107's resource-ceiling, persistence, hostile-input,
     provider-containment, docs/MSRV and target-proof gaps.
   - Closeout: `architecture/standalone_crate_phase121_closeout.md`.

8. **Phase 122 — DNSSEC-Keystore and Mesh-Protocol Leaf Package Hardening**
   - Status: **CLOSED CLASS 2 — LIVE HSM PROVIDER DEFERRED; RSA PUBLIC PROMOTION BLOCKED** (2026-10-02).
   - Plan: `plans/phase_122_security_protocol_leaf_package_hardening.md`.
   - Hardens DNSSEC custody threat/secret/crash/HSM behavior and formalizes
     mesh wire/API/replay compatibility before standalone class-2 qualification.
   - Closeout: `architecture/standalone_crate_phase122_closeout.md`.

9. **Phase 123 — Standalone-Crate Campaign Qualification and Promotion Gate**
   - Status: **CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS** (2026-10-02; hosted
     exact-SHA CI passed on the campaign branch head
     `f81182149889e21c4908b7ee38c74bc6b4518f6b`, run `37064917481`).
   - Plan: `plans/phase_123_standalone_crate_campaign_qualification_gate.md`.
   - Closeout: `architecture/standalone_crate_phase123_closeout.md`.
   - Regenerated dependency/package evidence and refreshed the ICMP/YARA/
     proxy-cache/tarpit/filter/jail/native-extension gates. No later class-3 or
     repository-extraction plan met its explicit support/lifecycle criteria.
   - The PR #51 merge head `cacd44bffe097d7c62e3ddb0c5816967498a7bde` was
     independently qualified by hosted run `37218651222` (`ci` +
     `dependency-security` success; both native jobs skipped). That run
     supersedes the campaign branch as the current-`main` proof and does not
     change any Phase 115–123 disposition.

Binding constraints:

- monorepo is the default and remains the target topology;
- package generalization must reduce application dependency reachability rather
  than merely move files;
- class-2 standalone capability is not a support promise;
- no long-lived git dependency, crates.io publication, or new external repository
  is authorized by Phases 115–123;
- Hickory ownership is preserved for generic DNS protocol/server machinery unless
  behavior evidence justifies a separate change;
- mesh authority/partition/provenance semantics cannot weaken;
- OpenRaft/QUIC/network-stack upgrades are separate from boundary extraction;
- native security support requires native evidence.


## Post-Phase-123 Documentation/Evidence Reconciliation — Phase 124 CLOSED QUALIFIED

Status: **CLOSED QUALIFIED** (2026-10-04; docs/evidence only).

Plan:
`plans/phase_124_post_standalone_documentation_evidence_reconciliation.md`.

Closeout:
`architecture/standalone_crate_phase124_closeout.md`.

Planning baseline:
`cacd44bffe097d7c62e3ddb0c5816967498a7bde` (PR #51 merge head).

Scope as executed:

- reconciled stale current-authority Phase 115–123 status and exact-SHA CI
  wording;
- distinguished the campaign-head proof
  `f81182149889e21c4908b7ee38c74bc6b4518f6b` (run `37064917481`) from the
  merged-main proof `cacd44bffe097d7c62e3ddb0c5816967498a7bde`
  (run `37218651222`); both exist and neither is relabeled as the other;
- refreshed the architecture overview and only the release/classification
  records that were actually stale (`architecture/overview.md`; the release
  policy, final surface audit, crate granularity audit, `docs/releasing.md` and
  the standalone candidate registry were re-checked and left unchanged);
- added minimal supersession pointers to Phase 107/109/110-era and
  process-sandbox documents without rewriting historical evidence;
- kept honeypot, DNSSEC-keystore and mesh-protocol class 2 with
  `external_support=false`; `synvoid-rate-limit` remains the sole class-3
  crate;
- made the next DNS boundary research discoverable without performing DNS source
  changes.

Terminal evidence: merge head `cacd44bf` carries hosted run `37218651222`
(`ci`/Verify and `dependency-security` both success; `icmp-native-qualification`
and `sandbox-native-qualification` skipped by their false-by-default inputs).
The earlier red runs on pre-merge main head `fd8fc2a8` (push run `37149285202`,
daily schedule run `37200443692`, `RUSTSEC-2026-0325/0326/0327` against the
pre-campaign Wasmtime pin) are superseded by that merge-head result, which
inherits the Phase 123 Wasmtime 48.0.5 remediation.

DNS runtime-DTO research at Phase 124 close:
`architecture/dns_runtime_dto_conversion_research.md`
(RESEARCH COMPLETE / IMPLEMENTATION NOT YET REGISTERED at that historical close; superseded by the Phases 125–130 registration below).

The DNS study resolves the Phase 116 design blocker at research level: persisted
`synvoid-config` DTOs remain application-owned; a composition adapter belongs
under `src/server/`; `synvoid-dns` should own only parsed runtime values;
unsupported/deferred persisted fields remain fail-closed in config and are
absent from the runtime API. The proposed conversion removes
`synvoid-config`, `synvoid-core`, and `synvoid-utils` before the later
TLS/Geo/mesh provider-inversion work. No Phase 125 implementation plan is
registered by Phase 124 or the research record.

Successor status after Phase 124: **no future plan is unblocked.** Every Phase
115–123 gate decision is unchanged (DNS and mesh extraction DEFER, sandbox
RETAIN, class 2 with `external_support=false` for honeypot/DNSSEC-keystore/
mesh-protocol, `synvoid-rate-limit` the sole class-3 crate, ICMP RETAIN, YARA
DEFER, proxy-cache/tarpit/filter/jail-protocol/native-extension internal).
Native macOS, live PKCS#11/HSM and Windows native sandbox qualification remain
external evidence gates, not support claims. At Phase 124 close, the DNS runtime-DTO research was recorded but not yet registered implementation work. That historical statement is superseded by the Phases 125–130 successor registration below.

Binding constraints observed:

- Phase 124 was documentation/evidence only;
- no Rust source, manifest, lockfile, workflow, package metadata, support tier
  or dependency topology changed;
- merge-head exact-SHA CI was recorded only because a real run was observed;
- no historical test count, proof SHA or DEFER/RETAIN reasoning was rewritten;
- DNS Phase 116/117 implementation was not reopened.

Verification: `git diff --check` clean, `cargo fmt --all -- --check` passed,
`synvoid-repo-guards` passed, `cargo xtask verify` 10/10 passed (1002.1s).
`verify-full` and `verify-release` were deliberately not rerun for this
docs-only phase; see `architecture/standalone_crate_phase124_closeout.md` §8.

Acceptance criteria: met. Rejection criteria: none triggered.


## DNS Runtime-DTO Conversion — Phases 125–130 ACTIVE / REGISTERED

Status: **ACTIVE / REGISTERED** (2026-10-04).

Umbrella:
`plans/dns_runtime_dto_conversion_roadmap.md`.

Research authority:
`architecture/dns_runtime_dto_conversion_research.md`.

Planning baseline:
`f86f99d1ba239cd32e423dede232d684cfeb8fa2`
(Phase 124 closeout head).

Purpose: implement the deferred Phase 116 DNS runtime-config/core neutralization
as a bounded successor campaign. Persisted DNS config remains application-owned;
the conversion adapter belongs under `src/server/`; `src/dns/` remains a
pure facade; `synvoid-dns` owns parsed runtime values.

Execution:

1. **Phase 125 — DNS Runtime DTO Contract, Ownership Matrix and Adapter Parity**
   - Status: **CLOSED QUALIFIED** (2026-10-04).
   - Plan: `plans/phase_125_dns_runtime_dto_contract_adapter_parity.md`.
   - Closeout: `architecture/dns_runtime_dto_phase125_closeout.md`.
   - Delivered the exhaustive persisted-field projection ledger, the DNS-owned
     runtime DTO vocabulary, the single root composition adapter, 15
     absent-by-design tests, and 43 parity fixtures — before any production
     constructor cutover, as required. Production behavior is unchanged except
     one recorded fail-closed tightening (`dns.dns64.prefix` now rejects a
     malformed prefix instead of warning and defaulting). Two findings are
     carried forward: F-1 (the `dns.firewall.max_rules` serde default of 1000
     disagrees with its derived Rust `Default` of 0; pinned, not fixed, because
     persisted-default drift is out of scope) and F-2 (the adapter's ACL
     re-parse is defense in depth behind the persisted validation gate).
     The dependency-edge guards for `synvoid-config`/`core`/`utils` are
     deliberately deferred to Phases 128/129, which own the removals.

2. **Phase 126 — DNS Authoritative and Encrypted-Transport Runtime Cutover**
   - Status: **CLOSED QUALIFIED** (2026-10-04).
   - Plan: `plans/phase_126_dns_authoritative_runtime_cutover.md`.
   - Closeout: `architecture/dns_runtime_dto_phase126_closeout.md`.
   - `DnsServer::new` now takes `AuthoritativeRuntimeConfig` plus the documented
     `DeferredDnsConfig` passthrough; DoT/DoH/DoQ and `SecureDnsServerBase`
     consume parsed `SocketAddr` values. Production `src/` names
     `synvoid_config::dns::DnsConfig` in exactly one file
     (`runtime_config_deferred.rs`). 46 test call sites migrated to runtime
     fixtures, 7 campaign guards green, the Phase 125 parity fixtures pass
     unchanged, and the dead `DnsSettings` persistence bridge was removed. Two
     fail-closed behavior changes recorded (DNS64 prefix rejection; DoQ bind
     validation expressed as an absent address). The `synvoid-config` normal
     edge is intentionally still present — Phase 128 owns its removal.

3. **Phase 127 — DNS Recursive Resolver Runtime-Config Cutover**
   - Status: **CLOSED QUALIFIED** (2026-10-04).
   - Plan: `plans/phase_127_dns_recursive_runtime_cutover.md`.
   - Closeout: `architecture/dns_runtime_dto_phase127_closeout.md`.
   - Recursive upstream strategy, cache policy, client ACL, circuit breaker,
     depth limits, timeouts, and ECS forwarding policy are DNS-owned runtime
     values; `recursive.rs` and `recursive_cache.rs` went from 21 and 23
     persistence references to zero. The forwarder-mode DNSSEC warning is now
     driven by `performs_local_dnssec_validation`. 11 campaign gates green; the
     Phase 125 parity and absent-by-design suites pass unchanged. Three findings
     carried forward: F-1 (dead `check_rebinding_protection` should be deleted
     in Phase 128 rather than converted), F-2 (a hostname-only custom upstream
     list silently falls back to the system resolver; preserved for parity,
     needs its own plan), F-3 (`CdnOnly` recursive ECS is a documented no-op).
     The `synvoid-config` normal edge is intentionally still present.

4. **Phase 128 — DNS Zone, DNSSEC, TSIG/HSM Conversion and synvoid-config Removal**
   - Status: **CLOSED QUALIFIED** (2026-10-04).
   - Plan: `plans/phase_128_dns_zone_dnssec_tsig_config_removal.md`.
   - Closeout: `architecture/dns_runtime_dto_phase128_closeout.md`.
   - Introduces DNS-owned zone/TSIG inputs, moves HSM conversion to composition,
     preserves keystore custody, and removes the normal `synvoid-config` edge.
     Measured: 6 direct SynVoid normal edges (was 7), 846 expanded
     `cargo tree -e normal` lines (was 847). Persisted-schema test coverage
     moved to `crates/synvoid-config/tests/` rather than dropped.

5. **Phase 129 — DNS Core and Utils Neutralization**
   - Status: **CLOSED QUALIFIED** (2026-10-04).
   - Plan: `plans/phase_129_dns_core_utils_neutralization.md`.
   - Closeout: `architecture/dns_runtime_dto_phase129_closeout.md`.
   - Differentially preserves DNS time/restricted-IP/prefix-mask/lifecycle
     semantics and removes normal `synvoid-core` / `synvoid-utils` edges.
     Measured: 4 direct SynVoid normal edges (was 6), 827 expanded
     `cargo tree -e normal` lines (was 846).

6. **Phase 130 — DNS Runtime-DTO Qualification and Provider-Inversion Gate**
   - Status: **CLOSED QUALIFIED** (2026-10-05).
   - Closeout: `architecture/dns_runtime_dto_phase130_closeout.md`.
   - Re-proves the dependency graph, re-runs every parity ledger, qualifies
     the crate, and records the provider-inversion decision: **DEFER**. TLS and
     GeoIP seams are narrow but lack their required evidence; mesh is not a
     narrow seam. `synvoid-dns` remains class 1.
   - Plan: `plans/phase_130_dns_runtime_dto_qualification_provider_gate.md`.
   - Rebuilds dependency/package/runtime evidence and decides whether a separate
     TLS/Geo/mesh provider-inversion campaign is ready to register.

Binding constraints:

- no persisted TOML/admin API change;
- no `synvoid-config -> synvoid-dns` dependency reversal;
- unsupported/deferred DNS fields remain fail-closed and absent from the initial
  runtime API;
- Hickory remains the protocol/resolver engine and its non-exhaustive config
  types remain internal lowering details;
- DNSSEC private-key custody remains in `synvoid-dnssec-keystore`;
- TLS/Geo/mesh provider inversion is outside Phases 125–130;
- no class-2/publication/repository promotion is authorized;
- target dependency reduction is from seven direct SynVoid edges to the
  remaining TLS/Geo/keystore + optional mesh set, subject to actual metadata
  proof.

## DNS Startup Truthfulness and Provider Inversion — Phases 131–136 ACTIVE / REGISTERED

Status line: **ACTIVE** (2026-10-05). Umbrella:
`plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.

This campaign continues from the terminal state of Phases 125–130 and carries
forward the three findings that campaign recorded rather than fixed in place,
because each was a behavior or evidence change outside its ownership scope.
Phase 130 explicitly recorded provider inversion as DEFER and did not register a
successor; this campaign is that separately registered successor, scoped to the
two narrow seams only.

1. **Phase 131 — DNS Conformance Determinism (`free_port()` TOCTOU)**
   - Status: **CLOSED QUALIFIED** (2026-10-05).
   - Plan: `plans/phase_131_dns_conformance_determinism_free_port.md`.
   - Closeout: `architecture/dns_provider_inversion_phase131_closeout.md`.
   - Address: Phase 130 F-3. The Phase 130 recommended remedy proved
     structurally impossible — `DnsServer::start` binds UDP and TCP on the same
     port internally, so a held reservation occupies the port the server needs.
     The assumption was removed instead of the window narrowed: the server
     performs the real bind and a new port is taken only when that bind is
     observed to have lost a race, with a conflict-gated retry and no sleeps.
     The duplicate `context::ephemeral_port()` was deleted. Evidence: 10/10
     repeated parallel `nextest` runs, new 5-test `bind_determinism` suite, and
     `scripts/dns/conformance.sh` 10/10 twice (was 9/9).
   - Residual recorded, not fixed: the two `#[ignore]`d Eggbench live-proof
     suites still predict ports and require a built binary, so they cannot be
     executed as evidence here.
   - No production code changed; `synvoid-dns` remains class 1.

2. **Phase 132 — Authoritative Zone Startup Activation**
   - Status: **CLOSED QUALIFIED** (2026-10-05). Behavior change.
   - Plan: `plans/phase_132_dns_authoritative_zone_startup_activation.md`.
   - Closeout: `architecture/dns_provider_inversion_phase132_closeout.md`.
   - Address: Phase 128 F-2 / matrix F-6. `[[dns.zones.items]]` was parsed,
     validated, converted record-by-record, then dropped at the `zones: _`
     destructure; neither `load_zones` nor `load_zones_from_store` had a
     production caller, and four shipped examples declared zones. Composition
     now activates configured zones and fails startup closed on an
     unactivatable one.
   - Wiring the path exposed two defects it had been hiding, both fixed:
     record names could never match, so a configured zone answered
     **authoritative NXDOMAIN for every name it contained** (fail-wrong); and
     all four shipped profiles declared a record-less zone, which cannot be
     activated. The loader now normalizes record names to the origin-relative
     form the query path keys by and rejects out-of-zone names; the examples
     carry a valid SOA/NS/A set and a `validate()` rule rejects a record-less
     zone at config load.
   - Evidence: a new root suite starts a real server from the real adapter
     output and asserts a served wire response (AA set, `rcode=0`, declared
     rdata), driven from the shipped example. Parity ledger unchanged at 43/43;
     `synvoid-dns` 615 lib tests (622 with mesh); `synvoid-config` 94; two new
     repo guards; conformance 10/10.
   - No persisted schema shape change; DNSSEC custody untouched;
     `synvoid-dns` remains class 1.

3. **Phase 133 — Provider-Inversion Evidence Gate (TLS + GeoIP)**
   - Status: **CLOSED QUALIFIED** (2026-10-05). **GO for both providers.**
   - Plan: `plans/phase_133_dns_provider_inversion_evidence_gate.md`.
   - Closeout: `architecture/dns_provider_inversion_phase133_closeout.md`.
   - Produced, as executable tests, the evidence Phase 130 listed as missing:
     47 tests across four new suites plus four new repo guards. Every claim is
     observed through a real rustls handshake or a real MaxMind database rather
     than by reading struct fields — the repository shipped no `.mmdb` fixture,
     so a minimal MMDB writer was added to make "covered" and "uncovered"
     genuinely distinguishable.
   - Corrected the Phase 130 record that DNS calls zero methods on
     `CertResolver`: `SecureDnsServerBase::create_tls_acceptor` calls
     `build_server_config()`, making the seam rustls-shaped. The GeoIP seam is
     **two** methods, not one, and the TLS contract is **duplicated** (F-12:
     DoQ is QUIC and has its own copy), so Phase 134 has three call sites.
   - Decisions: TLS → `SecureTransportConfig::server_config` +
     `AcmeTxtChallenges::txt_value`; GeoIP → `CountryLookup::country_info` +
     `CountryLookup::asn` over a **new** DNS-owned `CountryInfo`. mesh remains
     out — it is a distributed-authority surface, not a narrow seam.
   - Twelve findings. Two are high severity and are carried into Phase 135 as
     mandatory workstreams rather than fixed here, because this phase changed no
     production behavior: **F-1**, `GeoIpManager::new` panics when
     `[geoip] enabled = true` has no download credentials, even with
     `update_enabled = false` — a config-reachable startup crash; and **F-2**, a
     `GeoLocation` block rule with no provider silently allows traffic, with no
     error and no mention of the skipped rule in the decision.
   - The F-1 pin is a `#[should_panic]` test written so the Phase 135 fix fails
     loudly rather than passing silently; it must be inverted, not deleted.
   - Dependency graph unchanged at 4 direct SynVoid normal edges. `synvoid-dns`
     remains class 1.

4. **Phase 134 — TLS Provider Inversion**
   - Status: **PLANNED**, conditional on a Phase 133 GO for TLS. **GO received.**
   - Plan: `plans/phase_134_dns_tls_provider_inversion.md`.
   - DNS-owned `SecureTransportConfig` (returns `Arc<rustls::ServerConfig>`) and
     `AcmeTxtChallenges`, implemented in composition, remove the direct
     `synvoid-tls` edge. No new dependency: `synvoid-dns` already depends on
     `rustls`. Target: 4 → 3 direct SynVoid normal edges.

5. **Phase 135 — GeoIP Provider Inversion**
   - Status: **PLANNED**, conditional on a Phase 133 GO for GeoIP. **GO
     received.**
   - Plan: `plans/phase_135_dns_geoip_provider_inversion.md`.
   - DNS-owned `CountryLookup` trait and DNS-owned `CountryInfo` result type
     replace `GeoIpManager::get_country_info` **and** `get_asn_info` at their
     four call sites, removing the direct `synvoid-geoip` edge. The ASN half
     narrows to `Option<u32>`, because the firewall reads only the number.
     Target: 3 → 2 direct SynVoid normal edges.
   - **Starts with the two Phase 133 high-severity findings**, as mandatory
     workstreams: F-1 makes `GeoIpManager::new` total (it currently panics when
     `[geoip] enabled = true` has no download credentials), and F-2 gives a
     GeoLocation block rule evaluated with no provider a deliberate fail-closed
     meaning instead of silently allowing traffic. Both are recorded behavior
     changes with their security rationale.

6. **Phase 136 — Campaign Qualification and Truthful Closeout**
   - Status: **PLANNED**.
   - Plan: `plans/phase_136_dns_provider_inversion_qualification.md`.
   - Terminal dependency proof from `cargo metadata` / `cargo tree`, parity
     re-run, full qualification matrix, documentation reconciliation, and an
     honest class/support decision. `synvoid-dns` remains class 1: with mesh
     still concrete, the standalone contract in
     `architecture/public_crate_release_policy.md` is not satisfied.

Binding constraints:

- no persisted TOML/OpenAPI/admin schema change; Phase 132 changes whether a
  documented setting takes effect, not what it parses to;
- no `synvoid-config -> synvoid-dns` dependency and no composition type leaking
  into `synvoid-dns`;
- no provider trait implemented inside `synvoid-dns`; providers stay in
  composition roots;
- no trait signature may name a `synvoid-tls` or `synvoid-geoip` type;
- mesh provider inversion is out of scope and needs its own design phase;
- DNSSEC private-key custody remains one-way through `synvoid-dnssec-keystore`;
- no class/support/publication/repository promotion is authorized;
- no TLS behavior change (ALPN, protocol versions, mTLS) to make inversion
  easier;
- every edge-removal claim requires `cargo metadata` / `cargo tree` proof, and
  every skipped lane is recorded as not-run.
