# Phase 6 Plan: Admin and Control-Plane Authority Hardening

Status: detailed handoff plan.

Roadmap position: Phase 6 of `plans/roadmap.md`.

Primary goal: make every admin/control-plane mutation explicit about authority, provenance, local mutation outcome, propagation semantics, audit behavior, and operator-visible result. This phase converts ambiguous admin/control-plane success paths into typed, auditable state transitions.

## Context

The request path is now better isolated from mesh/control-plane internals. Blocklist convergence has persisted cursors and clearer ordering semantics. The next risk is control-plane ambiguity: admin handlers may return a generic success response even when the local store did not mutate, propagation was only queued best-effort, the event was stale, or the caller had compatibility authority rather than explicit operator authority.

Operational blocklist/admin changes should carry enough metadata for incident response and for distinguishing:

- mutation applied locally,
- no-op because target already matched requested state,
- duplicate event,
- stale event ignored,
- invalid request rejected,
- local mutation applied but mesh propagation best-effort queued,
- local mutation failed but diagnostics succeeded.

## Non-Goals

Do not redesign the admin UI.

Do not make operational blocklist changes Raft-backed.

Do not move request-path enforcement to remote/admin checks.

Do not introduce new auth providers unless needed to classify existing actors.

Do not implement full security observability dashboards; Phase 9 owns broad observability.

## Deliverables

1. Typed authority/provenance model for admin and control-plane mutations.
2. Typed mutation outcome/result model reused by admin handlers and supervisor/control-plane paths.
3. Structured audit event for mutating admin actions.
4. Response schemas that distinguish applied, no-op, duplicate, stale, invalid, and propagation-queued outcomes.
5. Guardrails preventing generic success responses from new mutating admin endpoints.
6. Tests for block/unblock/admin mutation semantics, audit emission, and authority classification.
7. Architecture doc: `architecture/admin_control_plane_authority.md`.

## Phase A: Inventory Mutating Admin and Control-Plane Surfaces

Inventory all admin/control-plane mutation entry points.

Commands:

```bash
rg "post\(|put\(|delete\(|block|unblock|ban|allow|deny|update|create|remove|reload|propagat|gossip|audit" src/admin crates/synvoid-admin src/supervisor src/commands crates/synvoid-mesh crates/synvoid-block-store
rg "success.*true|ok\(|StatusCode::OK|Json\(" src/admin crates/synvoid-admin
```

Create `architecture/admin_control_plane_authority.md` with an inventory table:

```markdown
| Endpoint / command | File | Mutation target | Current auth | Current response | Propagation | Audit status | Target result type |
|--------------------|------|-----------------|--------------|------------------|-------------|--------------|--------------------|
```

Start with blocklist and mesh admin endpoints, then admin config/reload endpoints, then supervisor control commands.

## Phase B: Define Authority and Actor Types

Add a type in the most appropriate shared crate. Prefer `crates/synvoid-core/src/admin.rs` or `crates/synvoid-admin` if already used by handlers. If root-only at first, use `src/admin/authority.rs` and migrate later.

Suggested model:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AdminMutationAuthority {
    AdminManual,
    SupervisorManual,
    SupervisorSync,
    MeshPolicyGated,
    LocalDetector,
    WorkerIpc,
    CompatibilityLegacy,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdminActor {
    pub authority: AdminMutationAuthority,
    pub actor_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id_hash: Option<String>,
}
```

Rules:

- Do not store raw session tokens in audit logs.
- If session ID is included, hash it or use existing safe identifier.
- Use constant-time comparisons only for actual secrets; do not force constant-time compares for public IDs.
- Compatibility paths must explicitly use `CompatibilityLegacy`, not silently default to admin authority.

## Phase C: Define Mutation Outcome Types

Add a reusable mutation result type.

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AdminMutationStatus {
    Applied,
    NoOpAlreadyPresent,
    NoOpAlreadyAbsent,
    DuplicateIgnored,
    StaleIgnored,
    InvalidRejected,
    UnauthorizedRejected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PropagationStatus {
    NotApplicable,
    QueuedBestEffort,
    AppliedLocalOnly,
    SnapshotRepairRequired,
    FailedToQueue,
    Deferred,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminMutationResult<T = serde_json::Value> {
    pub status: AdminMutationStatus,
    pub target: T,
    pub local_store_mutated: bool,
    pub propagation: PropagationStatus,
    pub event_id: Option<String>,
    pub audit_id: Option<String>,
    pub message: String,
}
```

Do not expose internal error strings directly if they may contain sensitive config or path data. Convert to safe operator messages.

## Phase D: Add Audit Event Model

Add structured audit event types. If an audit subsystem already exists, reuse it. Otherwise, start with an in-memory/log-emitted audit sink and explicit TODO for durable audit storage.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminAuditEvent {
    pub audit_id: String,
    pub timestamp: u64,
    pub actor: AdminActor,
    pub action: String,
    pub target_kind: String,
    pub target_id: String,
    pub prior_state: Option<serde_json::Value>,
    pub requested_state: Option<serde_json::Value>,
    pub resulting_state: Option<serde_json::Value>,
    pub mutation_status: AdminMutationStatus,
    pub propagation_status: PropagationStatus,
    pub event_id: Option<String>,
}
```

Emit audit events for at least:

- admin block,
- admin unblock,
- mesh block/unblock propagation path,
- config reload if present,
- plugin reload if present,
- supervisor stop/restart/drain command if exposed through admin/control API.

Initial audit sink can be:

```rust
pub trait AdminAuditSink: Send + Sync {
    fn record(&self, event: AdminAuditEvent);
}
```

A tracing-backed implementation is acceptable for this phase if durable audit storage is deferred.

## Phase E: Convert Blocklist Admin Responses First

Target block/unblock endpoints before broader admin surfaces.

Expected behavior:

- Apply local mutation through existing block-store/control-plane APIs.
- Preserve existing event IDs/provenance.
- Return `AdminMutationResult`.
- Include whether mesh propagation was queued, not guaranteed delivered.
- Audit before response is returned.

Example response:

```json
{
  "status": "Applied",
  "target": { "kind": "ip", "value": "203.0.113.10", "site_scope": null },
  "local_store_mutated": true,
  "propagation": "QueuedBestEffort",
  "event_id": "...",
  "audit_id": "...",
  "message": "Local block applied; mesh propagation queued best-effort"
}
```

Stale/duplicate behavior:

- Duplicate event: `DuplicateIgnored`, `local_store_mutated=false`.
- Stale event: `StaleIgnored`, `local_store_mutated=false`.
- Already absent unblock: `NoOpAlreadyAbsent`.
- Already present block: `NoOpAlreadyPresent`, unless policy intentionally refreshes TTL/version; document which behavior is chosen.

## Phase F: Convert Supervisor/Control Commands

Inventory supervisor gRPC/admin commands. Add typed result mapping for:

- drain request,
- stop/restart worker,
- reload config,
- reload TLS/certs,
- mesh catchup/snapshot repair trigger if exposed.

Use the same `AdminMutationAuthority` model but distinguish `SupervisorManual` from `AdminManual` and `SupervisorSync`.

Do not allow supervisor-internal sync messages to masquerade as manual admin action.

## Phase G: Guardrails

Add `tests/admin_mutation_response_guard.rs`.

Guard behavior:

- Scan mutating admin handlers for generic `success: true` or raw `Json(json!({ "success": true }))` responses.
- Require mutating handlers to return `AdminMutationResult` or a typed wrapper.
- Allow read-only diagnostics endpoints to return simple responses.
- Require every `AdminMutationAuthority` variant to appear in docs.
- Require every audit exception to be live and narrow.

Suggested deny tokens:

```rust
const GENERIC_SUCCESS_TOKENS: &[&str] = &[
    "\"success\": true",
    "success: true",
    "StatusCode::OK, Json(json!",
];
```

Avoid false positives in tests/docs by scanning handler source paths only.

## Phase H: Tests

Add unit tests for authority/result types:

- `admin_mutation_status_serializes_stably`
- `propagation_status_serializes_stably`
- `legacy_authority_is_explicit`
- `audit_event_omits_raw_secret_tokens`

Add blocklist admin behavior tests:

- `admin_block_applied_returns_mutated_true`
- `admin_unblock_absent_returns_noop_absent`
- `duplicate_block_event_returns_duplicate_ignored`
- `stale_unblock_returns_stale_ignored`
- `mesh_propagation_queue_failure_reported_separately`
- `audit_event_emitted_for_block`
- `audit_event_emitted_for_unblock`

If endpoint integration tests are heavy, test handler helper functions directly.

## Phase I: Documentation

Create `architecture/admin_control_plane_authority.md` with:

- mutation authority taxonomy,
- actor model,
- result semantics,
- propagation semantics,
- audit event schema,
- endpoint inventory,
- non-guarantees: best-effort mesh propagation is not delivery acknowledgement.

Update `AGENTS.md` guard command list:

```bash
cargo test --test admin_mutation_response_guard
```

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
cargo test --test admin_mutation_response_guard
cargo test -p synvoid --lib admin
cargo test -p synvoid-admin
cargo test -p synvoid-block-store blocklist
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
cargo test --test request_path_capability_boundary_guard
```

Adjust crate/test names to actual implementation paths.

## Acceptance Criteria

This phase is complete when:

- Mutating admin/control-plane paths return typed mutation outcomes.
- Block/unblock responses distinguish applied/no-op/duplicate/stale/failure.
- Propagation status is explicit and not conflated with local success.
- Audit events are emitted for key admin mutations.
- Actor authority is explicit; compatibility paths do not silently become admin authority.
- Guardrails prevent new generic success responses for mutating endpoints.
- Docs describe guarantees and non-guarantees.

## Handoff Notes

Start with blocklist admin endpoints. They already have provenance/event semantics and are the highest-value proof point.

Do not broaden this into a full UI/API redesign. Keep response changes typed and local.

Do not promise mesh delivery. The correct phrase is best-effort queued unless an explicit acknowledgement layer is later added.
