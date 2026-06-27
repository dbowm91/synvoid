# Corrective Verification Plan: Phase 1–5 Architecture Hardening Closure

Status: detailed handoff plan.

Scope: verify and correct the implementation work that followed `plans/roadmap.md` phases 1 through 5:

1. Root ownership closure and dependency entitlement.
2. `UnifiedServer` startup/resource/runtime split.
3. Supervisor lifecycle and control-plane task hardening.
4. Request-path capability boundary and concrete handle reduction.
5. Blocklist convergence, replay, and ordering hardening.

This plan is intentionally corrective and verification-focused. Do not start new roadmap features while this pass is open. The goal is to prove that the new architecture is structurally sound, guardrails are meaningful, and the implementation did not leave aspirational types or documentation-only ownership behind.

## Current Assessment

The implementation line appears to have made substantial progress:

- `synvoid-filter` was extracted and dead captcha/logging code was removed.
- `architecture/root_dependency_ownership.md` and `root_dependency_ownership_guard` were added.
- `src/server/mod.rs` was split into `startup_plan`, `resources`, `runtime_handles`, and `plugin_runtime` modules.
- `PluginRuntimeOwner` replaced the plugin hot-reload `mem::forget` pattern.
- `SupervisorTaskRegistry`, `SupervisorShutdownCause`, and `SupervisorDrainReport` were added.
- `ThreatIntelLookup` and `BehavioralIntelLookup` traits reduced request-path coupling to mesh concrete managers.
- `request_path_capability_boundary_guard` was added.
- Blocklist peer cursor persistence and source-scoped ordering metadata were added.

The likely remaining risks are:

- Some runtime-handle ownership may still be comment-based rather than structurally enforced.
- Supervisor task exceptions may be too broad, especially per-connection IPC handlers.
- Request-path capability boundaries may still carry concrete request services that should be explicitly classified.
- Blocklist cursor advancement and ordering semantics are subtle and need stronger behavioral tests.
- No CI evidence should be assumed; all relevant profiles and guardrails need to be run.

## Non-Goals

Do not implement phases 6–10 from `plans/roadmap.md` in this pass.

Do not add new runtime features.

Do not change distributed blocklist semantics to Raft or globally linearizable consensus.

Do not redesign HTTP/1 or HTTP/3 request pipelines.

Do not remove compatibility facades unless tests and call-site inventory prove they are dead.

## Deliverables

1. A verification report committed under `architecture/phase_1_5_verification_report.md` or equivalent.
2. Any corrective patches needed for compile/test/profile failures.
3. Tightened guardrails where current guards prove comment-only or allowlist-heavy.
4. Updated architecture docs reflecting actual implementation, not planned implementation.
5. Green targeted test matrix for phases 1–5.
6. A residual-risk list for items intentionally deferred to phases 6–10.

## Phase A: Baseline Build and Test Matrix

First establish the actual state. Run these commands before changing code.

```bash
cargo fmt --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

Then run the architecture guard suite:

```bash
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test unified_server_lifecycle_ownership_guard
cargo test --test supervisor_task_ownership_guard
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test http3_waf_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
```

Then run focused module/crate tests:

```bash
cargo test -p synvoid --lib server::startup_plan
cargo test -p synvoid --lib server::resources
cargo test -p synvoid --lib server::runtime_handles
cargo test -p synvoid --lib server::plugin_runtime
cargo test -p synvoid --lib supervisor::task_registry
cargo test -p synvoid --lib supervisor::shutdown
cargo test -p synvoid-block-store blocklist
cargo test -p synvoid-mesh --features mesh blocklist
cargo test -p synvoid-filter
cargo test -p synvoid-core block_store
cargo test -p synvoid-waf --features mesh
cargo test -p synvoid-http
cargo test -p synvoid-http3
cargo test -p synvoid-proxy
```

Record every failure in the verification report using this format:

```markdown
| Command | Status | Failure summary | Corrective owner | Fixed in commit |
|---------|--------|-----------------|------------------|-----------------|
```

If a command is too broad or currently impossible because of pre-existing failures, document the exact failure and run the narrowest substitute that still verifies the touched boundary.

## Phase B: Verify Phase 1 — Root Ownership and Dependency Entitlement

### B1. Root Dependency Ledger Accuracy

Inspect `architecture/root_dependency_ownership.md` against `Cargo.toml`.

Checks:

- Every direct root `[dependencies]` entry appears in the ledger.
- Every ledger entry has a valid classification.
- No dependency is incorrectly classified as `composition_runtime` if it is only needed by a mixed module or compatibility facade.
- Removed dependencies such as `syslog` are absent from root `Cargo.toml` and `Cargo.lock` unless still required transitively.
- The new `synvoid-filter` crate is listed as a workspace member and direct dependency only where justified.

Potential correction:

If the root dependency guard only checks presence, extend it to validate classification values and reject placeholders.

Suggested classification check:

```rust
const VALID_CLASSIFICATIONS: &[&str] = &[
    "composition_runtime",
    "compat_facade",
    "migration_blocker",
    "test_or_tooling",
    "remove_candidate",
];
```

### B2. Root Module Ledger Consistency

Inspect `architecture/root_module_ledger.md` and `src/lib.rs`.

Checks:

- `captcha` and `logging` are no longer exported from `src/lib.rs` if their source modules were removed.
- `filter` is classified as `facade_existing_crate` and root `src/filter/mod.rs` is a thin facade only.
- Removed modules do not leave broken architecture doc links without historical-status notes.
- `auth`, `challenge`, `http`, `http_client`, `platform`, `plugin`, `tarpit`, `tls`, `utils`, and `waf` still have accurate `split_required` or corrected classifications.

Potential correction:

If stale docs still present removed modules as active, update them to historical reference or remove links from active architecture indices.

### B3. `synvoid-filter` Extraction Quality

Inspect:

```text
crates/synvoid-filter/Cargo.toml
crates/synvoid-filter/src/lib.rs
src/filter/mod.rs
src/tcp/filter.rs
src/tcp/protocol.rs
src/udp/filter.rs
src/udp/protocol.rs
```

Checks:

- The new crate has no dependency on root `synvoid`.
- Root `src/filter/mod.rs` is a pure facade.
- TCP/UDP consumers import `synvoid_filter` directly where possible.
- Tests cover protocol matching, strict mode, allowlist/denylist behavior, and default behavior.
- Public types preserve previous semantics.

Potential correction:

Add focused `synvoid-filter` unit tests if extraction only moved code without behavior coverage.

## Phase C: Verify Phase 2 — `UnifiedServer` Startup and Runtime Ownership

### C1. Startup Plan Correctness

Inspect `src/server/startup_plan.rs`.

Checks:

- Address parsing has typed errors.
- Worker count normalizes to at least one.
- Rate-limit scaling happens in exactly one place.
- HTTP/HTTPS/HTTP3 listener conflicts are detected.
- HTTP/3 disabled config does not parse or reject irrelevant HTTP/3 fields.
- Tunnel config access avoids unsafe `unwrap()` patterns when disabled.
- Tests cover invalid v4/v6 host, TLS enabled address, HTTP/3 enabled invalid v6 address, listener conflicts, and worker scaling.

Potential correction:

If rate-limit scaling is duplicated in `resources.rs` or WAF creation, remove duplication and make `resources.rs` consume `plan.scaled_rate_limits`.

### C2. Resource Construction Boundary

Inspect `src/server/resources.rs`.

Checks:

- Resource construction may touch disk/config but must not spawn long-lived tasks.
- WAF/TCP/UDP/TLS/tunnel/DNS construction moved out of `mod.rs` without behavior regression.
- TLS certificate load failure preserves prior degrade behavior if prior code warned and continued.
- UDP listener site loop behavior matches previous behavior.
- DNS feature-gated construction compiles under `--features dns` and `--features mesh,dns`.

Potential correction:

If resource constructors spawn or leak runtime tasks, move those into runtime handles or documented manager-owned lifecycles.

### C3. Runtime Handle Ownership Is Real, Not Decorative

Inspect:

```text
src/server/runtime_handles.rs
src/server/mod.rs
src/server/plugin_runtime.rs
tests/unified_server_lifecycle_ownership_guard.rs
architecture/unified_server_startup.md
```

Critical check: determine whether `UnifiedServerRuntimeHandles` actually owns the listener/background `JoinHandle`s created in `UnifiedServer::run()`, or whether ownership is only documented with `// reason:` comments.

Acceptable final state:

- Protocol listener tasks are registered in `UnifiedServerRuntimeHandles`, or
- There is a clearly documented reason they are awaited directly and therefore do not need registry ownership, and the docs avoid claiming registry ownership.

Problematic state:

- `UnifiedServerRuntimeHandles` exists but is not used for main server tasks.
- Guard only requires `// reason:` comments and does not prove handles are joined/drained.
- Architecture docs claim shutdown/drain ownership that code does not implement.

Potential correction:

If handles are not structurally owned, either:

1. Wire the existing `UnifiedServerRuntimeHandles` into `run()` so spawned tasks are registered and drained, or
2. Rename/reframe it as a helper for future use and update docs/guards to avoid false claims.

Preferred correction is structural registration.

Example target pattern:

```rust
let mut runtime_handles = UnifiedServerRuntimeHandles::new();

let http_jh = tokio::spawn(async move {
    Self::run_http_server_inner(state, http_addr, shutdown_rx).await
});
runtime_handles.register(NamedRuntimeHandle::new(
    "http_v4",
    RuntimeHandleClass::CriticalServer,
    http_jh,
));
```

If task output types differ, adapt `NamedRuntimeHandle` to carry `JoinHandle<Result<(), BoxError>>` or normalize task outcomes at spawn boundaries.

### C4. Plugin Lifecycle Ownership

Inspect `src/server/plugin_runtime.rs` and plugin lifecycle code.

Checks:

- No `std::mem::forget` or `mem::forget` remains in server/plugin code.
- `PluginRuntimeOwner` stores lifecycle state for server lifetime.
- Dropping owner stops watcher or at least drops all owned watcher handles.
- Tests prove owner holds lifecycle after hot reload is enabled.
- Hot reload errors are reported without losing already loaded plugin manager state.

Potential correction:

If lifecycle drop semantics are unknown, inspect `PluginManagerLifecycle` and document whether drop stops watchers. Add explicit shutdown if missing.

## Phase D: Verify Phase 3 — Supervisor Lifecycle and Control Plane

### D1. Task Registry Semantics

Inspect `src/supervisor/task_registry.rs`.

Checks:

- Registered tasks are uniquely named/IDed.
- `join_finished()` does not block.
- `shutdown_and_join()` has bounded timeout and aborts tasks that exceed it.
- Failed critical tasks can be surfaced to `SupervisorProcess::run()`.
- Tests cover completed, failed, cancelled, aborted, and timeout paths.

Potential correction:

If `shutdown_and_join()` consumes a fixed timeout per task rather than a shared deadline, document it or change to a shared deadline to avoid unbounded total shutdown time.

### D2. Supervisor Process Integration

Inspect `src/supervisor/process.rs`.

Checks:

- IPC accept loop is registered as `CriticalControlPlane`.
- gRPC control server is registered as `CriticalControlPlane`.
- Main loop polls finished registered tasks.
- Critical task failure maps to `SupervisorShutdownCause::TaskFailed` or a more specific variant.
- Shutdown stops accepting new control-plane work before or during worker drain according to documented order.
- Drain report accounts for every worker exactly once.

Potential correction:

If registered tasks are shut down before worker drain, verify no drain protocol messages depend on those tasks remaining alive. If they do, adjust order or keep a specific IPC path alive for drain.

### D3. Spawn Guard Exceptions

Inspect `tests/supervisor_task_ownership_guard.rs`.

Checks:

- Guard fails on new unmanaged long-lived supervisor `tokio::spawn` calls.
- Exceptions are narrow and live.
- Per-connection IPC handler exception is documented and bounded.
- Mesh agent mode exception is specific to process-context ownership.
- `ProcessManager` internal task exception does not mask supervisor-level spawns.

Potential correction:

If per-connection IPC handlers are long-lived, convert the IPC accept loop to own a `JoinSet` and drain/abort connection handlers on shutdown.

### D4. Shutdown Cause and Metrics

Inspect `src/supervisor/shutdown.rs` and related logging/metrics.

Checks:

- Every shutdown cause has stable metric label.
- Fatal/non-fatal classification matches desired operational behavior.
- Drain timeout is non-fatal only if intentional.
- Fatal task failure is logged at error level or otherwise alertable.

Potential correction:

Add metrics if missing, or document that metrics are deferred to Phase 9 observability.

## Phase E: Verify Phase 4 — Request-Path Capability Boundary

### E1. RequestServices Boundary

Inspect `src/worker/context.rs` and `src/worker/unified_server/services.rs`.

Checks:

- `RequestServices` does not import worker startup, supervision, shutdown, IPC manager internals, task registry, mesh transport, or DHT/Raft handles.
- `ThreatIntelLookup` and `BehavioralIntelLookup` are narrow and read-only.
- Concrete managers are wrapped only in composition-root adapters.
- `DataPlaneServices` still owns concrete control-plane handles needed for IPC/control-plane updates.
- Request path receives trait objects rather than concrete `ThreatIntelligenceManager` or `BehavioralIntelligenceManager`.

Potential correction:

If `RequestServices` imports concrete mesh behavioral types solely to define trait argument/return types, evaluate whether the trait should live in a mesh-facing crate or whether those types are acceptable shared data types. Document the decision in `architecture/request_path_capability_boundary.md`.

### E2. AttackDetector and WAF Decoupling

Inspect:

```text
src/waf/attack_detection/mod.rs
src/waf/mod.rs
src/worker/unified_server/init_mesh.rs
src/worker/unified_server/services.rs
```

Checks:

- `AttackDetector` no longer imports concrete `BehavioralIntelligenceManager`.
- `set_threat_intel` accepts a trait object or is removed if no longer meaningful.
- Raw threat-intel lookups occur only in composition adapters or diagnostic/admin code.
- Request-path enforcement still uses local block store or policy-gated state, not remote DHT lookup.

Potential correction:

If adapters call raw lookup APIs, add comments and guard allowlists explaining they are composition-root read adapters, not enforcement policy bypasses. Prefer method names that make diagnostic/local-only semantics explicit.

### E3. Guardrail Strength and Allowlists

Inspect `tests/request_path_capability_boundary_guard.rs`, `tests/threat_intel_boundary_guard.rs`, and `tests/data_plane_composition_boundary_guard.rs`.

Checks:

- Every allowlist entry has a reason and still corresponds to a live occurrence.
- No broad directory allowlist hides future regressions.
- New request-path files fail closed until classified.
- Forbidden token groups include concrete managers, mesh/DHT/Raft, supervisor/admin, worker lifecycle, catchup/snapshot/gossip APIs, and raw threat lookups.
- Guard distinguishes comments/string literals well enough to avoid noisy false positives without broad exclusions.

Potential correction:

Add exception liveness tests if missing. Remove stale exceptions added during Phase 4 implementation.

### E4. Concrete Request Services Classification

`RequestServices` may still contain concrete request-execution services such as upload validator, YARA rules manager, plugin manager, and serverless registry.

For each, classify as:

- acceptable request-execution concrete service,
- shared data/rules type,
- should become narrow trait in later phase,
- composition-only and should not be in `RequestServices`.

Document the classification in `architecture/request_path_capability_boundary.md`.

Potential correction:

If any service is clearly control-plane rather than request-execution, move it back to `DataPlaneServices` and expose only a narrow trait.

## Phase F: Verify Phase 5 — Blocklist Convergence and Ordering

### F1. Cursor Persistence Correctness

Inspect `crates/synvoid-block-store/src/lib.rs` and any new core types in `crates/synvoid-core/src/block_store.rs`.

Checks:

- Peer cursors are keyed by `(peer_id, source_node)` consistently.
- Cursor records include `peer_id`, `source_node`, `last_sequence`, `last_timestamp`, `last_event_id`, `updated_at`, and `expires_at`.
- Expired cursors are filtered on load.
- Corrupt cursor file logs and falls back safely.
- Cursor persistence uses an atomic write pattern if existing persistence uses atomic writes.
- Cursor update does not synchronously write to disk on hot request paths.
- Shutdown persists cursors synchronously.

Potential correction:

If cursor persistence writes directly to final path without temp+rename while target-state persistence uses safer writes, align the cursor persistence with the existing safer pattern.

### F2. Local Sequence Persistence

Inspect local sequence generation and persistence.

Checks:

- Local source sequence increments monotonically for locally emitted blocklist events.
- Sequence is persisted or boot-scoped so restart does not create ambiguous same-source sequence reuse.
- Event ID uniqueness remains safe if sequence resets.
- Hydration handles missing/corrupt sequence files safely.

Potential correction:

If sequence resets on restart for the same `source_node`, add a persisted boot epoch or persist the sequence counter. Do not rely on wall-clock alone for uniqueness.

### F3. Ordering Semantics

Inspect `LastAppliedBlocklistEvent::is_newer_than()` and all call sites.

Required behavior:

- Higher explicit version wins.
- Same-source higher `source_sequence` wins when version does not decide.
- `logical_time` can order across sources when present.
- Timestamp remains backward-compatible fallback.
- Equal timestamp and no differentiator is not strictly newer.
- Older block cannot resurrect newer unblock.
- Older unblock cannot remove newer block.
- Legacy timestamp-only events remain supported.

Add or verify tests:

```bash
cargo test -p synvoid-block-store same_source_sequence_orders_despite_clock_skew
cargo test -p synvoid-block-store higher_version_wins_over_sequence
cargo test -p synvoid-block-store older_block_does_not_resurrect_after_newer_unblock
cargo test -p synvoid-block-store older_unblock_does_not_remove_newer_block
cargo test -p synvoid-block-store legacy_timestamp_only_events_remain_supported
```

Use actual test names if different. Add missing tests.

Potential correction:

If source sequence ordering is applied across different sources, restrict it to same source only. If logical time is treated as HLC but is only a wall timestamp, rename or document it accurately.

### F4. Mesh Catchup Cursor Flow

Inspect:

```text
crates/synvoid-mesh/src/mesh/transport_connection.rs
crates/synvoid-mesh/src/mesh/transport_peer.rs
crates/synvoid-mesh/src/mesh/blocklist_event.rs
crates/synvoid-mesh/src/mesh/protocol_proto_encode.rs
crates/synvoid-mesh/src/mesh/protocol_proto_decode.rs
crates/synvoid-mesh/src/mesh/proto/mesh.proto
```

Checks:

- On peer connect, persisted cursor is looked up and used as `since_sequence = Some(last_sequence)` only when valid.
- Absence of cursor uses `since_sequence = None` and does not skip sequence 0.
- Cursor advances only after event application is known to have succeeded, duplicated, or intentionally ignored as stale.
- Cursor does not advance past failed/invalid events.
- Snapshot-required response does not incorrectly mark cursor complete before snapshot completes.
- Wire encode/decode preserves `source_sequence` and `logical_time` for new messages.
- Old peers missing fields remain compatible.

Potential correction:

If cursor update happens at response level rather than per-event success level, change it to track last successfully processed event.

### F5. Admin Diagnostics

Inspect `src/admin/handlers/mesh_admin.rs`.

Checks:

- `peer_cursor_count` is included in catchup stats.
- Diagnostics do not expose sensitive identifiers unnecessarily.
- Missing block store or disabled mesh produces stable response.

Potential correction:

Add summarized cursor age range, oldest/newest update, or persistence status only if cheap and safe. Defer richer observability to Phase 9.

## Phase G: Documentation Truthfulness Audit

Review these docs against actual code:

```text
architecture/root_dependency_ownership.md
architecture/root_module_ledger.md
architecture/unified_server_startup.md
architecture/supervisor_lifecycle.md
architecture/request_path_capability_boundary.md
architecture/blocklist_reconciliation.md
architecture/blocklist_remove_consistency.md
architecture/block_store.md
architecture/worker_data_plane_composition_root.md
AGENTS.md
```

Checks:

- Docs do not claim stronger ownership than implemented.
- Guard test names and commands are current.
- Removed modules are marked historical or removed from active indexes.
- `UnifiedServerRuntimeHandles` docs reflect actual usage.
- Supervisor task inventory line numbers are not brittle or stale.
- Blocklist docs preserve non-guarantees clearly.

Potential correction:

Prefer precise wording such as “spawn ownership is documented by guard comment” rather than “registered and drained” unless the code actually registers and drains handles.

## Phase H: Guardrail Quality Audit

For every guard added or changed in this line:

```text
tests/root_dependency_ownership_guard.rs
tests/unified_server_lifecycle_ownership_guard.rs
tests/supervisor_task_ownership_guard.rs
tests/request_path_capability_boundary_guard.rs
tests/threat_intel_boundary_guard.rs
tests/data_plane_composition_boundary_guard.rs
```

Check:

- Does it fail closed for new files in mixed directories?
- Does it have exception liveness checks?
- Are exceptions scoped by path and token rather than directory only?
- Does the failure message tell the next agent how to fix the violation?
- Does it ignore comments and string literals sanely?
- Is the allowlist empty where possible?

Potential correction:

Add liveness checks for every exception list:

```rust
#[test]
fn boundary_exceptions_are_live() {
    for exception in BOUNDARY_EXCEPTIONS {
        assert!(
            matching_files_contain(exception.path_suffix, exception.token),
            "stale boundary exception: {:?}",
            exception
        );
    }
}
```

## Phase I: Corrective Patch Priority

If failures are found, fix in this order:

1. Compile/profile failures.
2. Request-path/control-plane boundary violations.
3. Blocklist ordering or stale replay failures.
4. Runtime task leaks or false lifecycle ownership claims.
5. Guardrail false negatives or broad allowlists.
6. Documentation drift.

Do not fix documentation before fixing code when the doc describes a violated invariant. First decide whether the invariant should be enforced or weakened.

## Phase J: Verification Report

Create `architecture/phase_1_5_verification_report.md`.

Suggested structure:

```markdown
# Phase 1–5 Verification Report

Date: YYYY-MM-DD
Base: <commit before corrective pass>
Head: <commit after corrective pass>

## Summary

## Commands Run

| Command | Status | Notes |
|---------|--------|-------|

## Phase 1 Findings

## Phase 2 Findings

## Phase 3 Findings

## Phase 4 Findings

## Phase 5 Findings

## Guardrail Findings

## Corrective Commits

| Commit | Purpose |
|--------|---------|

## Residual Risks / Deferred Items

## Final Acceptance Statement
```

Residual risks should be explicit. Examples:

- `UnifiedServerRuntimeHandles` only partially owns server spawns; full structural registration deferred.
- Durable event log not implemented; cursor persistence plus snapshot fallback accepted.
- Concrete plugin/serverless request services remain in `RequestServices`; trait extraction deferred.

## Final Acceptance Criteria

This corrective pass is complete when:

- All baseline profile checks compile or failures are documented as pre-existing with narrow substitutes passing.
- All phase 1–5 guard tests pass.
- `synvoid-filter` has no root dependency and root filter path is a pure facade.
- Root dependency ledger covers every direct root dependency and validates classifications.
- `UnifiedServer` docs and code agree about whether runtime handles own server tasks.
- No `mem::forget` remains in server/plugin lifecycle code.
- Supervisor critical tasks are registered and critical task failure maps to shutdown cause.
- Supervisor spawn guard exceptions are narrow and live.
- Request path does not import concrete threat/behavioral intelligence managers.
- Raw threat-intel lookup use is limited to diagnostics or composition-root adapters with explicit guard exceptions.
- Blocklist peer cursors persist/hydrate correctly and do not advance past failed events.
- Source-scoped ordering tests cover clock skew, version precedence, legacy compatibility, and stale replay prevention.
- Architecture docs accurately describe guarantees and non-guarantees.

## Suggested Follow-On After Closure

After this corrective verification pass is green, resume the roadmap at Phase 6: admin/control-plane authority hardening.

Do not start Phase 6 until the verification report is committed and residual risks are accepted.
