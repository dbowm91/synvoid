# SynVoid Architecture Hardening Roadmap

Status: Tracks 1–3 and their corrective closures remain complete. Phases 41-48 of the runtime-truthfulness/security/publication campaign are complete (see `architecture/runtime_truthfulness_security_publication_closeout.md`). The post-Phase-48 performance optimization campaign (Phases 49-55) remains complete; Phases 56–57 corrective closure is implemented and closed (Phase 56 `57ad3158754b2f4851e1ce408043d33104106974`, Phase 57 proof-bearing `5212c6862426ee17795994ef1bba590113c52fad`). Eggfetch 0.2 runtime adoption is closed through Phase 62 (`c3568ef4...`) and performance/reproducibility adjudication is closed through Phase 63; Phase 64 docs/evidence-truth correction is closed. Production remains on eggfetch. The EggServe 0.2.2-line inbound H1 campaign remains historical/retained at Phase 65; Phases 66–69 were never started. EggServe 0.3 H1 adoption and corrective requalification are closed as `ADOPTED` through Phase 80 on exact pins `eggserve-server = "=0.4.0"` / `eggserve-primitives = "=0.2.2"`; the Phase 78 terminal claim is superseded by Phase 80 proof-bearing SHA `174fdbcd6f133b35099ed4492f5ed8d3fcaa7d4c` (hosted run `36201213413`). Phase 79 implementation SHA: `171dd1e47f965b04b34465fc72c87adf4d9a9cab`. See `architecture/eggserve_0_3_h1_adoption_closeout.md`. Phases 70–72 remain historical/closed with evidence aligned to their then-current Hyper H1 runtime. No registered future plan remains blocked on this corrective sequence. The process-sandbox correctness and extraction-readiness campaign (Phases 81-84) is closed DEFER (see the Post-Phase-80 section below). An independent ICMP policy/enforcement extraction-preparation campaign is registered as Phases 85-88.

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


## Post-Phase-57 Campaign: Eggfetch 0.2 Transport Consolidation — Runtime/Performance Closed; Phase 64 Docs Correction Active

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

Terminal state: **closed `ADOPTED`**. The residual H2 header-list byte-unit review, duplicate `Set-Cookie` behavior, body-limit status relabeling, and test-only Hyper differential-lane decision remain separate follow-up candidates. No registered future plan is blocked on this campaign. The process-sandbox correctness and extraction-readiness campaign (Phases 81–84) is closed DEFER (see below); the ICMP policy/enforcement campaign (Phases 85–88) proceeds independently.

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



## Post-Phase-80 Campaign: ICMP Policy/Enforcement Extraction Preparation — Planned (Phases 85–88)

Status: Phases 85 is closed (canonical policy/adaptation landed
`20dfc148`, closeout
`architecture/icmp_phase85_policy_canonicalization_closeout.md`); Phases
86–88 are planned and registered. This campaign prepares the
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
