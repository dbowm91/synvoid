# Phase 12 Plan: Admin Legacy Endpoint Mutation/Audit Closure

Status: detailed handoff plan.

Roadmap position: Track 2, Phase 12 of `plans/roadmap.md`.

Primary goal: close the remaining admin/control-plane authority gap by converting legacy mutating endpoints from ad-hoc responses to typed mutation outcomes and audit events, or documenting them as read-only diagnostics.

## Context

Phase 6 added `AdminMutationAuthority`, `AdminMutationStatus`, `PropagationStatus`, `AdminMutationResult`, `AdminAuditEvent`, and audit sinks. The final verification cleanup report still listed legacy admin endpoints using ad-hoc response types without audit events. This phase burns that residual down.

## Non-Goals

Do not redesign the admin API.

Do not convert read-only diagnostics to mutation responses.

Do not imply mesh propagation delivery when only local mutation and best-effort queueing happened.

Do not log raw admin/session tokens.

## Deliverables

1. Inventory of all legacy admin endpoints and their classification.
2. Conversion of all mutating endpoints to typed mutation results.
3. Audit event emission for every mutating endpoint.
4. Tests covering each converted endpoint category.
5. Tightened `admin_mutation_response_guard` with live allowlists.
6. Updated `architecture/admin_control_plane_authority.md` and final verification report.

## Phase A: Endpoint Inventory

Run:

```bash
rg "Json\(|json!|success|StatusCode::OK|post\(|put\(|delete\(|patch\(" src/admin crates/synvoid-admin
rg "block|unblock|reload|update|create|delete|remove|enable|disable|upload|rule|plugin|spin|yara|icmp|feed" src/admin crates/synvoid-admin
```

Create or update an inventory table in `architecture/admin_control_plane_authority.md`:

```markdown
| Endpoint / handler | File | Method | Classification | Mutates state | Current response | Target response | Audit required | Status |
|--------------------|------|--------|----------------|---------------|------------------|-----------------|----------------|--------|
```

Classification values:

- `read_only_diagnostic`
- `local_mutation`
- `supervisor_control_mutation`
- `mesh_propagation_mutation`
- `plugin_runtime_mutation`
- `rule_or_feed_mutation`
- `dangerous_operation`

## Phase B: Define Conversion Rules

For each mutating endpoint:

- Return `AdminMutationResult<T>` or a narrow typed wrapper containing it.
- Include `local_store_mutated` / equivalent if state is local.
- Include `PropagationStatus` if any broadcast/mesh/supervisor queueing occurs.
- Include `audit_id` if audit event is emitted.
- Use sanitized operator-facing error messages.

Read-only diagnostics may keep simple response types, but they must be listed as diagnostics and guarded from mutation terms if possible.

## Phase C: Audit Event Emission

For every mutation, emit `AdminAuditEvent` or an endpoint-specific adapter to that schema.

Minimum audit fields:

- `audit_id`
- timestamp
- actor authority
- action name
- target kind/id
- requested state
- resulting status
- propagation status
- event ID if generated

Token/session safety:

- never serialize raw admin token,
- never log bearer token,
- session IDs must be hash/safe IDs only,
- source IP and user-agent should be optional and redacted if not already safe.

## Phase D: Convert High-Value Endpoints First

Suggested order:

1. Mesh admin block/unblock and catchup-repair triggers.
2. YARA/rule feed update/reload handlers.
3. Plugin enable/disable/reload handlers.
4. ICMP/honeypot/network toggles.
5. Spin/serverless runtime mutation handlers.
6. Remaining config/reload endpoints.

For each endpoint, add tests before moving to the next cluster.

## Phase E: Guard Tightening

Update `tests/admin_mutation_response_guard.rs`:

- Strip comments and string literals where practical.
- Fail on generic `"success": true` in mutating handlers.
- Allow simple responses only for documented read-only diagnostics.
- Require allowlist entries to be live.
- Require every mutation-classified handler to reference `AdminMutationResult`, `AdminAuditEvent`, or a documented wrapper.

Add liveness check for endpoint inventory if feasible:

- every inventory path exists,
- every mutating handler path appears in guard classification,
- stale allowlist entries fail.

## Phase F: Tests

Add or extend tests:

```bash
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
```

New tests to add where missing:

- `legacy_mutating_handlers_return_admin_mutation_result`
- `rule_feed_reload_emits_audit_event`
- `plugin_reload_emits_audit_event`
- `yara_update_reports_propagation_status`
- `read_only_diagnostics_do_not_require_mutation_result`
- `audit_event_never_contains_raw_admin_token`
- `mesh_propagation_failure_is_not_reported_as_applied_delivery`

If full handler integration is heavy, extract helper functions that produce `AdminMutationResult` and test those directly.

## Phase G: Documentation Updates

Update:

- `architecture/admin_control_plane_authority.md`
- `architecture/final_verification_cleanup_report.md`
- `architecture/release_hardening_report.md` if residual risks change
- `architecture/final_surface_audit.md` admin endpoint inventory if paths/responses change

Remove or update any claim that “14 legacy endpoints remain” after conversion.

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test -p synvoid-core admin_mutation
cargo test -p synvoid-admin
```

Adjust crate/module names if needed.

## Acceptance Criteria

This phase is complete when:

- All mutating admin endpoints return typed mutation outcomes or documented wrappers.
- Every mutation emits an audit event or is explicitly documented with a justified exception.
- Propagation status is explicit and does not imply delivery.
- Read-only diagnostics are clearly classified.
- No raw admin/session tokens appear in audit/log responses.
- `admin_mutation_response_guard` prevents generic success responses for new mutating endpoints.
- The legacy endpoint residual count is zero or restricted to documented read-only diagnostics.

## Handoff Notes

Do not chase perfect API aesthetics. The main objective is semantic truth: mutation status, propagation status, actor authority, and auditability.
