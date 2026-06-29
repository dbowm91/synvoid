# SynVoid Architecture Hardening Roadmap

Status: handoff roadmap for the next architecture-hardening line of work.

Scope: this roadmap assumes SynVoid is past the initial modularization phase. The major systems already exist: WAF engine, reverse proxy, mesh, block store, supervisor/worker runtime, DNS/TLS, HTTP/3, plugin runtime, serverless/app handlers, metrics, IPC, feature profiles, and architectural guardrails. The next work should reduce ambiguity, harden trust boundaries, and make failure behavior deterministic.

Primary principle: request path remains local, narrow, and capability-driven; control plane remains explicit, audited, and provenance-carrying; distributed mesh data remains policy-gated before it mutates enforcement state; runtime tasks remain owned and drainable; the root crate remains composition, not domain logic.

## Current Architectural Position

SynVoid has a broad workspace with dedicated crates for config, WAF, HTTP, HTTP/3, mesh, block-store, IPC, proxy, TLS, static files, app-server integration, and related subsystems. The root crate still exports many compatibility paths and owns root application/runtime composition. The repo already documents this split in `architecture/root_module_ledger.md` and enforces parts of it with guardrail tests such as `root_facade_boundary_guard` and request-path boundary guards.

The remaining architectural risk is not a lack of direction. The risk is that partial extraction becomes permanent: mixed root modules keep real domain behavior, concrete control-plane handles keep flowing through request code, long-lived tasks remain spawned without ownership, and feature-gated dependency creep re-expands root privilege.

## Roadmap Summary

### Phase 1: Root Ownership Closure and Dependency Entitlement

Goal: keep the root crate as an application/runtime composition crate and prevent it from remaining the implicit owner of domain logic or low-level dependencies.

Core work:

- Convert the `split_required` rows in `architecture/root_module_ledger.md` into a burn-down backlog.
- Start with low-risk extraction/cleanup candidates: `auth`, `captcha`, `logging`, `platform`, and `filter`.
- Create a root dependency entitlement ledger mapping every direct root dependency in `Cargo.toml` to a root-owned module, compatibility need, or removal target.
- Add guardrails so new root dependencies require ledger entries.
- Preserve compatibility facades while making new domain code import dedicated crates directly.

Defense-in-depth value:

- Reduces privilege concentration in the root crate.
- Reduces supply-chain blast radius by tying dependencies to explicit owners.
- Prevents domain crates from depending on root compatibility paths.
- Makes feature profile ownership easier to audit.

Detailed handoff plan: `plans/phase_01_root_ownership_dependency_entitlement.md`.

### Phase 2: UnifiedServer Startup Plan and Runtime Handle Ownership

Goal: split the large `UnifiedServer` composition root into validation, resource construction, and runtime handle ownership phases.

Core work:

- Add `UnifiedServerStartupPlan` for mostly pure validation and derived config.
- Add `UnifiedServerResources` for constructed resources such as WAF, listener pools, TLS resolver, DNS server, tunnel router, app supervisors, plugin manager, and serverless handles.
- Add `UnifiedServerRuntimeHandles` for owned spawned tasks, watchers, shutdown signals, and join/drain behavior.
- Replace unmanaged lifecycle leaks, especially plugin hot-reload lifecycle leakage through `std::mem::forget`.
- Add startup dry-run diagnostics and tests for invalid feature combinations, port conflicts, missing certs, and profile constraints.

Defense-in-depth value:

- Reduces half-constructed runtime states.
- Makes startup validation testable without opening sockets or spawning tasks.
- Eliminates orphaned task/watch handles.
- Gives shutdown and failure paths explicit ownership.

Detailed handoff plan: `plans/phase_02_unified_server_startup_runtime_ownership.md`.

### Phase 3: Supervisor Lifecycle and Control-Plane Task Hardening

Goal: bring supervisor task ownership, shutdown semantics, and control-plane runtime discipline up to the quality already established in the worker mesh/task registry line of work.

Core work:

- Add a `SupervisorTaskRegistry` or equivalent for supervisor-owned background tasks.
- Register IPC accept loop and gRPC control API server as named critical control-plane tasks.
- Add `SupervisorShutdownCause` with deterministic mapping to logs, metrics, drain behavior, and process exit code.
- Ensure worker shutdown and drain-aware shutdown are reachable only through the supervisor composition boundary.
- Add guardrails against unregistered supervisor `tokio::spawn` calls and direct worker shutdown from non-owner modules.

Defense-in-depth value:

- Prevents hidden control-plane task leaks.
- Makes degraded supervisor state observable.
- Avoids inconsistent shutdown paths.
- Makes worker drain behavior deterministic under failure.

Detailed handoff plan: `plans/phase_03_supervisor_lifecycle_hardening.md`.

### Phase 4: Request-Path Capability Boundary and Concrete Handle Reduction

Goal: narrow request-path dependencies so HTTP/WAF/proxy code consumes small capabilities, not concrete control-plane or mesh infrastructure.

Core work:

- Treat `RequestServices` as the only broad request-path handle.
- Replace concrete pass-through handles with narrow traits where behavior is actually consumed.
- Extend request-path boundary guardrails to reject control-plane imports, admin imports, mesh snapshot/catchup/gossip APIs, Raft/DHT imports, and concrete block-store ownership.
- Prefer AST-backed import/path guard tests for high-risk boundaries.
- Keep HTTP/1 and HTTP/3 semantically aligned while preserving protocol-specific streaming and backpressure behavior.

Defense-in-depth value:

- Prevents remote/control-plane lookups from slipping into the request hot path.
- Keeps enforcement local and deterministic.
- Reduces the chance that admin or mesh APIs become accidental request-path dependencies.
- Makes future protocol work safer.

Detailed handoff plan: `plans/phase_04_request_path_capability_boundary.md`.

### Phase 5: Blocklist Convergence, Replay, and Ordering Hardening

Goal: strengthen blocklist/event convergence across peer disconnects and process restarts without converting operational blocklists into a Raft/consensus subsystem.

Core work:

- Persist per-peer blocklist catchup cursors.
- Optionally persist a compact recent blocklist event-log window.
- Keep paged snapshot fallback as the repair path for history gaps.
- Add source-scoped sequence numbers or hybrid logical clock metadata to reduce clock-skew sensitivity.
- Expand stale replay, snapshot, provenance, and ordering tests.

Defense-in-depth value:

- Reduces stale block resurrection after restart.
- Makes unblock operations harder to undo with delayed older events.
- Preserves the local-only request-path enforcement model.
- Improves forensic traceability through provenance-preserving convergence.

Detailed handoff plan: `plans/phase_05_blocklist_convergence_hardening.md`.

### Phase 6: Admin and Control-Plane Authority Hardening

Goal: make every admin/control-plane mutation explicit about authority, state mutation, audit behavior, and propagation semantics.

Core work:

- Introduce or standardize typed authority/provenance classes for admin and supervisor mutations.
- Ensure admin responses distinguish applied, no-op, duplicate, stale, invalid, and propagation-queued outcomes.
- Require structured audit events for mutations: actor, source, target, prior state, new state, provenance, event ID, and propagation status.
- Add per-action rate limits and replay-resistant session/token handling where missing.
- Preserve constant-time comparison only for actual secrets.

Defense-in-depth value:

- Reduces ambiguous admin success responses.
- Makes operator/control-plane authority boundaries auditable.
- Improves incident reconstruction.
- Avoids accidental privilege escalation through compatibility paths.

### Phase 7: Plugin Runtime, Sandbox, and Capability Manifest Hardening

Goal: turn plugins into a controlled extension boundary instead of an implicit arbitrary-code boundary.

Core work:

- Define plugin trust tiers: disabled, local trusted, local sandboxed, signed sandboxed, and development hot-reload.
- Require plugin manifests declaring capabilities: request inspection, request mutation, response inspection, filesystem, network, DHT/mesh, admin events, metrics, and persistence.
- Enforce default-deny capability grants.
- Add signature verification for production plugins.
- Ensure plugin hot reload has owned lifecycle handles and bounded shutdown.
- Add failure isolation so plugin failure disables or degrades that plugin without poisoning the worker runtime.

Defense-in-depth value:

- Limits blast radius of third-party or experimental plugins.
- Makes plugin permissions inspectable.
- Prevents hot-reload watchers and plugin tasks from leaking.
- Creates a foundation for safe extension.

### Phase 8: Feature Profile CI, Fuzzing, and Failure Injection

Goal: make profile compatibility and hostile input handling continuously verified.

Core work:

- Promote core, mesh, DNS, full, and relevant optional profile checks to CI gates.
- Add targeted fuzzing for HTTP parsing, chunked response framing, DNS messages, mesh messages, blocklist event decoding, snapshot pagination tokens, and config parsing.
- Add failure-injection tests for startup rollback, supervisor task failure, worker drain timeout, mesh disconnect/reconnect, plugin failure, and snapshot interruption.
- Add a docs path validation test for `architecture/`, `.opencode/skills/`, `docs/`, and `AGENTS.md` references.

Defense-in-depth value:

- Detects feature-gated regressions before release.
- Improves parser robustness against malformed external inputs.
- Makes failure behavior intentional rather than incidental.
- Reduces stale documentation risk in an architecture-heavy repo.

### Phase 9: Observability as a Security Boundary

Goal: make security-relevant state transitions observable without confusing diagnostics with enforcement.

Core work:

- Add metrics/logs for startup validation, profile activation, plugin load/unload/failure, blocklist event apply results, stale/duplicate events, snapshot catchup, admin mutation provenance, supervisor task health, worker drain state, request-path enforcement source, and threat-intel policy decisions.
- Preserve strict labeling of diagnostic-only raw threat-intel lookups.
- Expose control-plane health as structured state, not only logs.
- Add dashboards or admin endpoints for convergence health, task registry state, and profile/runtime capabilities.

Defense-in-depth value:

- Supports incident response.
- Makes degraded security states visible.
- Prevents diagnostic data from being mistaken for enforced policy.
- Improves operator trust in distributed state convergence.

### Phase 10: Final Public Surface Audit and Release Hardening ✅

**Status: Completed.**

Deliverables:
- `architecture/final_surface_audit.md` — CLI classification, admin endpoint audit, public root export audit, facade documentation, request-path boundary verification, profile matrix validation.
- `architecture/release_hardening_report.md` — release-hardening checklist, guard results, profile checks, fuzz inventory, residual risks and intentional tradeoffs.

Goal: close the roadmap by auditing public API, CLI, admin endpoints, root exports, feature profiles, and guardrail completeness.

Core work:

- Classify every CLI command as local inspection, supervisor/control-plane mutation, or runtime launch.
- Audit every admin endpoint for auth, authority, mutation semantics, audit behavior, and propagation behavior.
- Audit every public root export against the root module ownership ledger.
- Ensure compatibility facades are documented and not used by domain crates.
- Verify request-path modules have no control-plane imports.
- Verify profile matrix and critical guardrails pass.
- Produce a release-hardening report summarizing residual risks and intentional tradeoffs.

Defense-in-depth value:

- Prevents accidental public surface creep.
- Documents what is stable, transitional, and internal.
- Provides a clean handoff point before feature expansion resumes.

## Suggested Execution Order

The phases are intended to be mostly sequential because each phase gives the next phase stronger boundaries:

1. Root ownership closure and dependency entitlement.
2. UnifiedServer startup/resource/runtime split.
3. Supervisor lifecycle and control-plane task ownership.
4. Request-path capability boundary tightening.
5. Blocklist convergence and replay hardening.
6. Admin/control-plane authority model.
7. Plugin sandbox/capability hardening.
8. Profile CI, fuzzing, and failure injection.
9. Security observability.
10. Final surface audit.

If implementation pressure requires parallelism, safe parallel tracks are:

- Phase 1 low-risk extraction can run in parallel with Phase 5 blocklist convergence work.
- Phase 6 admin response/audit schema work can start after Phase 5 event result types are stable.
- Phase 8 fuzzing can start at any time, but CI gating should wait until profile checks are green.
- Phase 9 observability can be added incrementally across all phases.

## Global Acceptance Criteria

The roadmap is complete when:

- Root crate direct dependencies are all entitled or removed.
- `split_required` modules in `architecture/root_module_ledger.md` are either extracted, downgraded to root-owned composition, or documented with a narrow blocker.
- `UnifiedServer` startup validation is testable without constructing runtime resources.
- All long-lived runtime tasks/watchers are owned by registries or explicit runtime handle structs.
- Supervisor and worker shutdown paths have typed causes and deterministic reporting.
- Request-path modules consume capability traits or `RequestServices`, not concrete control-plane infrastructure.
- Operational blocklist convergence survives routine restarts without relying only on live in-memory event logs.
- Admin mutations are audited, provenance-carrying, and explicit about no-op/stale/duplicate outcomes.
- Plugin runtime has trust tiers, manifests, lifecycle ownership, and failure isolation.
- Profile matrix, boundary guards, fuzz targets, and failure-injection tests are CI-visible.

## Roadmap Status: Complete

All ten phases are now delivered. The architecture hardening roadmap is closed. Any future work — new features, expanded fuzzing, additional subsystem extractions — should be tracked in a new roadmap rather than appended here.
