# Security Observability — Phase 9

## 1. Purpose and Scope

Observability makes security-relevant state transitions visible for diagnostics and incident response without conflating diagnostics with enforcement authority. Observability is part of defense-in-depth: it does not block attacks, but it ensures attacks, misconfigurations, and degradation are detectable.

**Core invariants:**

- Observability signals must never carry enforcement authority. A metric label does not authorize or deny a request.
- Raw threat-intel lookup APIs (`lookup_local_indicator`, `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht`) are diagnostic-only. They must never be used to emit enforcement metrics.
- Structured logs must never leak secrets, tokens, raw session IDs, or arbitrary high-cardinality labels.
- Security metrics must use low-cardinality labels only. High-cardinality data belongs in structured logs, not Prometheus counters.

---

## 2. Observability Inventory

| Subsystem | Existing Logs | Existing Metrics | Missing Signals | Priority |
|-----------|---------------|------------------|-----------------|----------|
| Startup/Profile Validation | `tracing::info` | (none) | Validation result metrics | Medium |
| UnifiedServerRuntimeHandles | `tracing::error`/`warn` on failure | (none) | Task exit counters per class/status, abort/timeout counters | High |
| SupervisorTaskRegistry | (none) | (none) | Registration, exit, shutdown counters | High |
| WorkerTaskRegistry | `tracing`, broadcast exits | `TaskRegistryMetrics` atomics | Prometheus metrics for task lifecycle | Medium |
| Admin/Control-Plane Mutations | Audit log file, handler tracing | `synvoid.admin.auth.*` | Mutation total/status/authority/propagation counters | High |
| Blocklist Event Apply/Catchup | `transport_peer.rs` tracing | `blockstore.event_ordering.*`, `stale_replay_ignored`, `peer_cursor_*` | Apply result counters by source, snapshot fallback counter | High |
| Plugin Load/Invoke/Failure | `tracing` info/error | `wasm_metrics` invocations/decisions/errors | Load by tier, capability violation, state transition, hot-reload | Medium |
| Threat-Intel Policy Decisions | (none) | `policy_shadow.*`, `enforcement_permitted`/`suppressed` | Policy decision counters with actionable label | Low |
| Request-Path Enforcement Source | (none) | (none) | Enforcement source counter | Medium |
| Mesh Peer/Catchup Health | `transport_peer.rs` tracing | (none) | Peer catchup success/failure/snapshot counters | Medium |
| TLS/ACME Lifecycle | `synvoid-tls` tracing | `synvoid.tls.*` | ACME renewal counters | Low |
| DNS Runtime | `DnsMetrics` | `synvoid.dns.*`, `dns_anycast_*` | (adequate) | Low |

---

## 3. Metric Naming Rules

1. **Stable names**: Use `snake_case` with a `synvoid_` prefix for all security-relevant metrics.
2. **Low-cardinality labels only.** Permitted label keys: `status`, `class`, `profile`, `source`, `reason`, `tier`, `action`, `authority`, `propagation`, `decision`, `actionable`, `capability`, `from`, `to`, `path`, `operation`.
3. **Forbidden label values**: Raw IPs, event IDs, usernames, tokens, file paths, or arbitrary plugin names. Log these in structured events at `debug`/`info` level instead.
4. **Prefer summary counters** over high-cardinality histograms for security metrics. Histograms are acceptable for latency but must use bounded buckets.
5. **Log event IDs in structured logs** if needed; never emit them as metric labels.

---

## 4. Standard Metric Names

### Existing

| Prefix | Subsystem |
|--------|-----------|
| `synvoid.http.*` | HTTP/1 request pipeline |
| `synvoid.http3.*` | HTTP/3 QUIC pipeline |
| `synvoid.waf.*` | WAF rule evaluation |
| `synvoid.dns.*` | DNS server |
| `synvoid.admin.auth.*` | Admin authentication |
| `synvoid.admin.csrf.*` | Admin CSRF protection |
| `synvoid.admin.audit.*` | Admin audit log |
| `synvoid.admin.ws.*` | Admin WebSocket |
| `synvoid.admin.alert.*` | Admin alerting |
| `synvoid.admin.rate_limited.*` | Admin rate limiter |
| `synvoid.blockstore.*` | Block store (event ordering, stale replay, cursors) |
| `synvoid.icmp.*` | ICMP filter |
| `synvoid.tls.*` | TLS lifecycle |
| `synvoid.traffic.*` | Traffic counters |
| `synvoid.bandwidth.*` | Bandwidth tracking |
| `synvoid.flood.*` | Flood protection |
| `synvoid.connection_limiter.*` | Connection limiter |
| `synvoid.upstream.*` | Upstream health |
| `synvoid.doq.*` | DNS-over-QUIC |
| `synvoid.doh.*` | DNS-over-HTTPS |
| `synvoid.dot.*` | DNS-over-TLS |
| `synvoid.honeypot.*` | Honeypot |
| `synvoid.static.*` | Static file serving |
| `synvoid.serverless.*` | Serverless WASM |
| `synvoid.dht.*` | DHT operations |
| `synvoid.mesh.*` | Mesh networking |
| `synvoid.persistence.*` | State persistence |
| `synvoid.proxy.*` | Proxy routing |
| `synvoid.ratelimit.*` | Rate limiting |
| `synvoid.request.*` | Request lifecycle |
| `synvoid.requests.*` | Request counters |
| `synvoid.syn_flood.*` | SYN flood protection |
| `synvoid.tcp.*` | TCP proxy and connection management |
| `synvoid.tarpit.*` | Tarpit |
| `synvoid.tunnel.*` | Tunnel (IPC, QUIC, UDP, WireGuard) |
| `synvoid.udp.*` | UDP protocol handling |
| `synvoid.udp_flood.*` | UDP flood protection |
| `synvoid.vpn.*` | VPN client |
| `synvoid.websocket.*` | WebSocket handling |
| `synvoid.worker.*` | Worker metrics |

### New (Phase 9)

| Metric | Labels | Description |
|--------|--------|-------------|
| `synvoid_runtime_task_registered_total` | `owner`, `class` | Task registered in runtime registry |
| `synvoid_runtime_task_exit_total` | `owner`, `class`, `status` | Task exited (completed/failed/cancelled) |
| `synvoid_runtime_shutdown_total` | `owner`, `status` | Shutdown cycle completed |
| `synvoid_runtime_task_abort_total` | `owner`, `class` | Task aborted during shutdown |
| `synvoid_runtime_task_critical_failures_total` | `owner` | Critical task failure during shutdown |
| `synvoid_admin_mutation_total` | `action`, `status`, `authority`, `propagation` | Admin mutation result |
| `synvoid_admin_audit_event_total` | `action`, `status` | Audit event emitted |
| `synvoid_admin_unauthorized_total` | `action`, `reason` | Unauthorized admin attempt |
| `synvoid_blocklist_event_apply_total` | `operation`, `status`, `source` | Blocklist event applied |
| `synvoid_blocklist_stale_replay_ignored_total` | `operation`, `source` | Stale replay suppressed |
| `synvoid_blocklist_cursor_update_total` | `status` | Peer cursor update |
| `synvoid_blocklist_cursor_load_total` | `status` | Peer cursor load |
| `synvoid_blocklist_snapshot_apply_total` | `status` | Snapshot fallback applied |
| `synvoid_blocklist_ordering_path_total` | `path` | Event ordering path taken |
| `synvoid_plugin_load_total` | `tier`, `status` | Plugin loaded |
| `synvoid_plugin_invoke_total` | `capability`, `status` | Plugin invoked |
| `synvoid_plugin_capability_violation_total` | `capability`, `tier` | Capability violation |
| `synvoid_plugin_state_transition_total` | `from`, `to`, `reason` | Plugin state changed |
| `synvoid_plugin_hot_reload_total` | `status` | Hot-reload attempt |
| `synvoid_threat_policy_decision_total` | `decision`, `actionable`, `source` | Policy decision |
| `synvoid_threat_policy_shadow_total` | `decision` | Shadow mode decision |
| `synvoid_request_enforcement_source_total` | `source` | Enforcement source on request path |
| `synvoid_blocklist_snapshot_fallback_total` | (none) | Snapshot fallback triggered |
| `synvoid_blocklist_stale_replay_ignored_total` | `operation`, `source` | Stale replay suppressed |
| `synvoid_blocklist_cursor_update_total` | `status` | Peer cursor update |
| `synvoid_blocklist_cursor_load_total` | `status` | Peer cursor load |
| `synvoid_blocklist_snapshot_apply_total` | `status` | Snapshot fallback applied (`ok`/`noop`/`disabled`) |
| `synvoid_blocklist_catchup_event_total` | `status` | Individual event processed during mesh catchup (`applied`/`noop`/`stale`) |
| `synvoid_blocklist_ordering_path_total` | `path` | Event ordering path taken |
| `synvoid.worker.tasks_started_total` | (none) | Worker task started |
| `synvoid.worker.tasks_completed_cleanly_total` | (none) | Worker task completed cleanly |
| `synvoid.worker.tasks_cancelled_total` | (none) | Worker task cancelled |
| `synvoid.worker.tasks_panicked_total` | (none) | Worker task panicked |
| `synvoid.worker.tasks_aborted_total` | (none) | Worker task aborted |
| `synvoid.worker.tasks_errored_total` | (none) | Worker task errored |
| `synvoid.worker.tasks_unexpectedly_completed_total` | (none) | Worker task unexpectedly completed |
| `synvoid.supervisor.tasks_registered_total` | (none) | Supervisor task registered |
| `synvoid.supervisor.tasks_completed_total` | (none) | Supervisor task completed |
| `synvoid.supervisor.tasks_failed_total` | (none) | Supervisor task failed |
| `synvoid.supervisor.tasks_aborted_total` | (none) | Supervisor task aborted |
| `synvoid.supervisor.tasks_timed_out_total` | (none) | Supervisor task timed out |

---

## 5. Structured Log Event Taxonomy

Structured logs carry high-cardinality context that must never appear as metric labels. All examples use `tracing` macros with structured fields.

### Startup Validation

```rust
tracing::info!(
    profile = %profile,
    result = "ok",
    "startup validation complete"
);
```

### Admin Mutation

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

### Blocklist Apply

```rust
tracing::debug!(
    operation = ?operation,
    status = ?status,
    source = %source_label,
    has_source_sequence = source_sequence.is_some(),
    "blocklist event apply"
);
```

### Runtime Task Exit

```rust
tracing::info!(
    task = %name,
    class = ?class,
    status = ?status,
    "runtime task exited"
);
```

### Plugin State Transition

```rust
tracing::info!(
    plugin_tier = %tier,
    from = ?from_state,
    to = ?to_state,
    reason = %reason,
    "plugin state transition"
);
```

### Threat-Intel Policy Decision

```rust
tracing::info!(
    decision = ?decision,
    actionable = %actionable,
    source = %source,
    "threat-intel policy decision"
);
```

---

## 6. Redaction and Sanitization Rules

| Rule | Rationale |
|------|-----------|
| Hash session IDs before logging (never raw tokens) | Prevents session hijacking from log exposure |
| Never log raw token/key values | Credential leakage |
| Log file paths only at `debug` level; avoid secret paths | Reduces attack surface from log aggregation |
| Avoid logging request body fragments | Potential PII / credential leakage |
| Avoid raw peer IDs in metrics; admin JSON may include if authenticated | Metric label cardinality |
| Use bounded/hashed labels for high-cardinality fields | Prevents metric label explosion |
| Event IDs may appear in structured logs, never in metric labels | Diagnostic-only |

---

## 7. Diagnostic-Only vs Enforcement Paths

Raw threat-intel lookup APIs are diagnostic-only. They must never be used to emit enforcement metrics or authorize blocking decisions.

| API | Classification | May Emit Enforcement Metrics? |
|-----|---------------|-------------------------------|
| `lookup_local_indicator()` | Diagnostic | No |
| `lookup_local_indicator_by_ip()` | Diagnostic | No |
| `lookup_threat_indicator_in_dht()` | Diagnostic | No |
| `lookup_*_policy_strict()` | Enforcement | Yes |

Request-path enforcement metrics must identify the local enforcement source (`LocalDetector`, `AdminManual`, etc.), not the remote DHT lookup source. This separation is enforced by `tests/threat_intel_boundary_guard.rs`.

---

## 8. Admin Diagnostics Endpoints

Diagnostics endpoints return summary-oriented, bounded JSON responses. They are read-only and require admin authentication.

| Endpoint | Returns | Bound |
|----------|---------|-------|
| `GET /admin/observability/tasks` | UnifiedServer + Worker + Supervisor task registry state | Summary counters |
| `GET /admin/observability/blocklist-health` | Blocklist convergence: event apply, stale suppressions, snapshot fallbacks, cursor stats | Summary counters |
| `GET /admin/observability/plugins` | Plugin runtime state: loaded count, per-plugin invocation/error/duration | Per-plugin summary |
| `GET /admin/observability/features` | Active feature flags and compile-time profile | Single JSON object |
| `GET /admin/observability/threat-intel` | Policy config, actionability summary, shadow mode state | Summary counters |

---

## 9. Verification

### Guard Test

`tests/security_observability_guard.rs` enforces:

- No raw IPs, tokens, or event IDs in metric label definitions.
- All new `synvoid_` metrics use the approved label key set.
- Structured log fields do not appear as metric labels in the same module.

```bash
cargo test --test security_observability_guard
```

### Metric Completeness

Verify all Phase 9 counters are emitted at least once in the test suite:

```bash
cargo test --lib --release -- --test-threads=1
```

### Naming Convention

Check that all security-relevant metrics use `synvoid_` prefix and `snake_case`:

```bash
rg 'synvoid_[a-z]+_' src/metrics/ crates/synvoid-*/src/ --include '*.rs' | head -20
```
