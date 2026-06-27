# Phase 9 Plan: Observability as a Security Boundary

Status: detailed handoff plan.

Roadmap position: Phase 9 of `plans/roadmap.md`.

Primary goal: make security-relevant state transitions observable without confusing diagnostics with enforcement authority. Operators should be able to understand startup/profile state, task health, plugin state, admin mutation provenance, blocklist convergence, request-path enforcement source, and threat-intel policy decisions from structured logs/metrics/admin diagnostics.

## Context

Prior phases tightened boundaries and lifecycle ownership. This phase makes those boundaries inspectable. Observability here is not cosmetic. It is part of defense-in-depth: silent degradation in plugin loading, blocklist convergence, admin propagation, task ownership, or threat-intel policy must be visible.

## Non-Goals

Do not build a full dashboard UI.

Do not expose secrets or raw auth tokens in logs or metrics.

Do not let diagnostics become enforcement inputs.

Do not add high-cardinality labels such as raw IP/event IDs to metrics unless explicitly bounded/sanitized.

## Deliverables

1. Observability inventory across security-relevant subsystems.
2. Metric/log event taxonomy with stable names and labels.
3. Structured diagnostics endpoints or admin summaries for convergence/task/plugin/profile health.
4. Guardrails for diagnostic-only versus enforcement paths.
5. Redaction/sanitization rules for sensitive fields.
6. Architecture doc: `architecture/security_observability.md`.
7. Verification report: `architecture/phase_9_observability_report.md`.

## Phase A: Observability Inventory

Create `architecture/security_observability.md` and inventory current signals.

Subsystems:

- startup/profile validation,
- `UnifiedServerRuntimeHandles`,
- `SupervisorTaskRegistry`,
- worker task registry,
- admin/control-plane mutations,
- blocklist event apply/catchup/snapshot/cursor state,
- plugin load/invoke/failure/hot reload,
- threat-intel policy decisions,
- request-path enforcement source,
- mesh peer/catchup health,
- TLS/ACME lifecycle,
- DNS runtime if enabled.

Table:

```markdown
| Subsystem | Existing logs | Existing metrics | Missing signals | Priority |
|-----------|---------------|------------------|-----------------|----------|
```

## Phase B: Define Metric Naming Rules

Add metric naming conventions to the doc.

Rules:

- Use stable snake_case names.
- Use low-cardinality labels only.
- Do not use raw IPs, event IDs, usernames, tokens, file paths, or arbitrary plugin names as labels unless bounded/hashed.
- Prefer labels like `status`, `class`, `profile`, `source`, `reason`, `tier`.
- Log event IDs in structured logs if needed; do not emit them as metric labels.

Example metrics:

```text
synvoid_startup_validation_total{status,profile}
synvoid_runtime_task_exit_total{owner,class,status}
synvoid_admin_mutation_total{action,status,authority,propagation}
synvoid_blocklist_event_apply_total{operation,status,source}
synvoid_blocklist_snapshot_fallback_total{reason}
synvoid_blocklist_peer_cursor_total{status}
synvoid_plugin_load_total{tier,status}
synvoid_plugin_invoke_total{capability,status}
synvoid_threat_policy_decision_total{decision,actionable}
synvoid_request_enforcement_source_total{source}
```

## Phase C: Structured Log Event Taxonomy

Define structured log fields for high-value events.

Examples:

Startup validation:

```rust
tracing::info!(profile = %profile, result = "ok", "startup validation complete");
```

Admin mutation:

```rust
tracing::info!(
    audit_id = %audit_id,
    action = %action,
    authority = ?authority,
    status = ?status,
    propagation = ?propagation,
    "admin mutation result"
);
```

Blocklist apply:

```rust
tracing::debug!(
    operation = ?operation,
    status = ?status,
    source = %source_label,
    has_source_sequence = source_sequence.is_some(),
    "blocklist event apply"
);
```

Redaction rules:

- Hash session IDs if logged.
- Avoid raw token/key values entirely.
- Log file paths only at debug level and avoid secret paths if possible.
- Avoid logging request body fragments.

## Phase D: Runtime Task Observability

Instrument:

- `UnifiedServerRuntimeHandles::register`
- task exit classification,
- shutdown report,
- abort-on-timeout count,
- critical task failures.

Metric examples:

```text
synvoid_runtime_task_registered_total{owner="unified_server",class}
synvoid_runtime_task_exit_total{owner="unified_server",class,status}
synvoid_runtime_shutdown_total{owner,status}
synvoid_runtime_task_abort_total{owner,class}
```

Do same for supervisor and worker registries where easy.

## Phase E: Admin Mutation Observability

After Phase 6, emit metrics/logs from typed mutation result paths.

Metrics:

```text
synvoid_admin_mutation_total{action,status,authority,propagation}
synvoid_admin_audit_event_total{action,status}
synvoid_admin_unauthorized_total{action,reason}
```

Ensure propagation status distinguishes `QueuedBestEffort` from applied/delivered.

## Phase F: Blocklist Convergence Observability

Instrument:

- event apply result: applied, duplicate, stale, invalid, failed,
- block/unblock operation,
- source: local_admin, supervisor, mesh_gossip, snapshot, ipc,
- snapshot fallback count,
- cursor load/update/persist failures,
- source-sequence ordering path versus timestamp fallback.

Metrics:

```text
synvoid_blocklist_event_apply_total{operation,status,source}
synvoid_blocklist_stale_replay_ignored_total{operation,source}
synvoid_blocklist_cursor_update_total{status}
synvoid_blocklist_cursor_load_total{status}
synvoid_blocklist_snapshot_apply_total{status}
synvoid_blocklist_ordering_path_total{path}
```

Admin diagnostics should include summarized convergence health:

- event log retained count,
- peer cursor count,
- oldest/newest cursor age,
- snapshot fallback count,
- last cursor persistence status.

Avoid raw peer IDs in metrics. Admin JSON may include peer IDs if authenticated and already exposed, but consider redaction/summary.

## Phase G: Plugin Observability

After Phase 7, instrument:

- manifest parse result,
- trust tier,
- capability violation,
- invocation timeout,
- invocation failure/trap,
- plugin disabled/quarantined,
- hot-reload reload success/failure.

Metrics:

```text
synvoid_plugin_load_total{tier,status}
synvoid_plugin_capability_violation_total{capability,tier}
synvoid_plugin_invoke_total{capability,status}
synvoid_plugin_state_transition_total{from,to,reason}
synvoid_plugin_hot_reload_total{status}
```

Labels should use trust tier/capability/status, not arbitrary plugin names unless bounded by config and acceptable.

## Phase H: Threat-Intel and Request Enforcement Observability

Maintain separation between diagnostics and enforcement.

Instrument strict policy paths:

```text
synvoid_threat_policy_decision_total{decision,actionable,source}
synvoid_threat_policy_shadow_total{decision}
synvoid_request_enforcement_source_total{source}
```

Do not add metrics around raw lookup APIs that make them appear authoritative. If raw diagnostics are counted, label them `diagnostic_only="true"` or keep them out of enforcement dashboards.

Guard rule: request-path enforcement metrics should identify local enforcement source, not remote DHT lookup.

## Phase I: Diagnostics Endpoints / Admin Summaries

Add or extend authenticated admin diagnostics endpoints for:

- runtime task registry state,
- blocklist convergence health,
- plugin runtime state,
- active feature/profile state,
- threat-intel policy config and actionability summary.

Response should be summary-oriented and bounded.

Example:

```json
{
  "runtime_tasks": {
    "unified_server": { "registered": 11, "last_shutdown_report": null },
    "supervisor": { "registered": 2 }
  },
  "blocklist_convergence": {
    "peer_cursor_count": 8,
    "snapshot_fallbacks": 2,
    "last_cursor_persist_status": "ok"
  }
}
```

## Phase J: Guardrails

Add `tests/security_observability_guard.rs`.

Guard checks:

- Metric labels do not include high-cardinality/sensitive fields such as raw IP, token, event_id, path, user_agent.
- Raw threat-intel lookup APIs are not used to emit enforcement metrics.
- Admin mutation result types emit or can emit audit/metrics.
- Runtime registries emit task exit/shutdown reports.
- Observability doc lists every metric prefix used in code.

Use narrow exceptions for tests/examples.

## Phase K: Tests

Unit tests:

- metric label sanitization rejects raw IP/event ID labels,
- admin mutation metrics map all statuses,
- blocklist apply metrics map all statuses,
- plugin capability violation metric uses capability/tier only,
- runtime shutdown report maps to metrics.

Integration-ish tests:

- simulated blocklist stale event increments stale counter,
- simulated runtime task timeout increments abort/timeout counter,
- plugin manifest failure increments plugin load failure counter,
- admin mutation emits audit log/sink event.

If metrics backend is hard to inspect, use a test metrics sink trait or a recorder abstraction where appropriate.

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
cargo test --test security_observability_guard
cargo test -p synvoid --lib metrics
cargo test -p synvoid-block-store blocklist
cargo test -p synvoid --lib server::runtime_handles
cargo test -p synvoid --lib supervisor::task_registry
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
```

## Acceptance Criteria

This phase is complete when:

- Security observability inventory exists.
- Runtime task exits/shutdown are logged and/or metered.
- Admin mutation outcomes are observable without conflating propagation and local mutation.
- Blocklist convergence health has logs/metrics and admin summary.
- Plugin load/invoke/failure states are observable after Phase 7.
- Threat-intel diagnostics remain distinct from enforcement metrics.
- Sensitive/high-cardinality metric labels are guarded against.
- `architecture/phase_9_observability_report.md` records commands and residual gaps.

## Handoff Notes

Do not overbuild dashboards. Add stable low-cardinality signals first.

Avoid turning raw diagnostics into policy signals. Observability should describe enforcement, not become enforcement.
