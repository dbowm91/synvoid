# Threat-Intel Consumer Actionability Inventory — Iteration 54

## Purpose

This document is the canonical map of every threat-intel consumer in the SynVoid codebase. It classifies each consumer by intent, identifies which lookup APIs are used, and documents enforcement invariants.

## Consumer Classes

| Class | Definition | Allowed APIs | Enforcement Allowed? |
|-------|-----------|-------------|---------------------|
| **Enforcement** | Can cause blocking, banning, trust mutation, peer isolation, blocklist events, or other security state changes | Must use `evaluate_incoming_threat_policy` or `classify_consumer_action` with `PermitAction` | YES — only when policy returns `PermitAction` |
| **Deferred** | Can queue, suppress, or defer action according to fail-open/fail-closed policy | Must use `classify_consumer_action` with `ThreatIntelDeferredMode` | Only when policy explicitly permits |
| **ShadowOnly** | Can observe and compare policy decisions but cannot mutate enforcement state | May call `evaluate_indicator_policy_shadow` | NO |
| **Diagnostic** | Can use raw lookup APIs for admin/debug/metrics/compatibility | May call `lookup_local_indicator`, `lookup_threat_indicator_in_dht` | NO |
| **LocalOrigin** | First-party evidence from local detection (honeypot, admin manual, feed ingestion) | Direct block-store writes with appropriate provenance | YES — operator/local authority |
| **WorkerIPC** | Applies Supervisor-broadcast blocklist events to worker BlockStore | Direct block-store writes with preserved provenance | YES — control-plane authority |

## Lookup API Tiers

| Tier | API Family | Fallback Behavior | Enforcement Safe? |
|------|-----------|-------------------|-------------------|
| **Raw** | `lookup_local_indicator`, `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht` | Returns indicator directly, no policy evaluation | NO — must not be used for enforcement |
| **Policy-Composed** | `lookup_*_policy_composed` | Falls back to raw when no policy context | Read-only; callers must not treat presence as actionability |
| **Policy-Strict** | `lookup_*_policy_strict` | Returns `None` when no policy context | Safe for enforcement consumers — no raw fallback |
| **Enforcement-Gate** | `evaluate_incoming_threat_policy` + `classify_consumer_action` | Returns `IncomingThreatPolicyGate` with action + decision | YES — the canonical enforcement entry point |

## Consumer Inventory

### A. Enforcement Consumers (mesh-control/sync)

These consumers can mutate BlockStore, rate-limit state, or other enforcement controls. All are gated by `evaluate_incoming_threat_policy` which returns `PermitAction` before any mutation.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 1 | `threat_intel.rs:handle_incoming_threat` — IpBlock | IP | enforcement-gate | YES: `block_ip_with_provenance` (`MeshThreatIntelPolicyGated`) | NO | mesh-control |
| 2 | `threat_intel.rs:handle_incoming_threat` — RateLimitViolation | IP | enforcement-gate | YES: `apply_rate_limit_mesh_action_after_policy_permit` | NO | mesh-control |
| 3 | `threat_intel.rs:handle_incoming_threat` — SuspiciousActivity | IP | enforcement-gate | YES: `apply_suspicious_mesh_action_after_policy_permit` | NO | mesh-control |
| 4 | `threat_intel.rs:handle_incoming_threat` — IpThrottle | IP | enforcement-gate | YES: `block_ip_with_provenance` (`MeshThreatIntelPolicyGated`) | NO | mesh-control |
| 5 | `threat_intel.rs:handle_incoming_threat` — AsnBlock | ASN (u32) | enforcement-gate | NO — observational only | NO | mesh-control |
| 6 | `threat_intel.rs:apply_sync` | Multi-type | enforcement-gate (delegates to `handle_incoming_threat`) | Inherits gate | NO | mesh-sync |
| 7 | `threat_intel.rs:handle_hot_threat_gossip` | IP | enforcement-gate (delegates) | Inherits gate | NO | mesh-control |
| 8 | `threat_intel.rs:handle_mesh_message` — ThreatAnnounce | Multi-type | enforcement-gate (delegates) | Inherits gate | NO | mesh-control |
| 9 | `threat_intel.rs:handle_mesh_message` — ThreatSyncResponse | Multi-type | enforcement-gate (delegates) | Inherits gate | NO | mesh-control |

**Invariant**: `handle_incoming_threat` is the single enforcement entry point for mesh-sourced indicators. All 4 threat types that can mutate BlockStore are gated by `evaluate_incoming_threat_policy` → `classify_consumer_action(Enforcement)` → `PermitAction` check. `AsnBlock` is observational only (no block-store mutation).

### B. Local Origin Consumers (first-party evidence)

These consumers represent first-party evidence from local detection systems. They bypass the mesh policy gate by design — authority comes from local operator/system action, not remote advisory consumption.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 10 | `threat_intel.rs:announce_local_block` | IP | admin-manual | YES: writes to indicators + DHT + gossip | NO | local-origin |
| 11 | `threat_intel.rs:announce_local_unblock` | IP/mesh ID | admin-manual | YES: unblock + gossip | YES: `BlocklistEvent::Unblock` | local-origin |
| 12 | `threat_intel.rs:announce_local_rate_limit` | IP | admin-manual | YES: writes to indicators + DHT | NO | local-origin |
| 13 | `threat_intel.rs:announce_local_suspicious` | IP | admin-manual | YES: writes to indicators + DHT | NO | local-origin |
| 14 | `threat_intel.rs:announce_honeypot_indicator` | IP | admin-manual | YES: `block_ip_with_provenance` (`LocalHoneypot`) for High/Critical | NO | local-origin |
| 15 | `threat_intel.rs:add_feed_indicator` | Multi-type | admin-manual | YES: writes to indicators + DHT | NO | feed-ingest |

### C. Admin Manual Enforcement Consumers

These consumers bypass the mesh policy gate by operator authority. Provenance is `AdminManual` or `SupervisorManual`.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 16 | `mesh_admin.rs:ban_ip` | IP | admin-manual | YES: `block_ip_with_provenance` (`AdminManual`) | YES | admin |
| 17 | `mesh_admin.rs:ban_mesh_id` | Mesh ID | admin-manual | YES: `block_mesh_id_with_provenance` (`AdminManual`) | YES | admin |
| 18 | `mesh_admin.rs:unban` (IP) | IP | admin-manual | YES: unblock | YES | admin |
| 19 | `mesh_admin.rs:unban` (mesh ID) | Mesh ID | admin-manual | YES: unblock | YES | admin |

### D. Shadow / Observability Consumers

These consumers observe and compare policy decisions but never mutate enforcement state.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 20 | `threat_intel.rs:evaluate_indicator_policy_shadow` | Any | policy-composed + raw (for disagreement) | NO | NO | diagnostics |
| 21 | `threat_intel_policy.rs:get_policy_shadow` | Any | delegates to shadow evaluation | NO | NO | admin/diagnostics |
| 22 | `threat_intel_policy.rs:get_policy_shadow_stats` | N/A | reads metrics counters | NO | NO | admin/diagnostics |

**Invariant**: `ShadowOnly` paths never emit blocklist events, never call block/unblock APIs, and never change peer trust state.

### E. Raw / Compatibility Read Consumers

These consumers use raw lookup APIs for compatibility, diagnostics, or bookkeeping. They must not be reused by enforcement paths.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 23 | `threat_intel.rs:lookup_threat_indicator_in_dht` | Any | raw (DHT record store) | NO | NO | raw-read |
| 24 | `threat_intel.rs:lookup_local_indicator` | Any | raw (in-memory map) | NO | NO | raw-read |
| 25 | `threat_intel.rs:lookup_local_indicator_by_ip` | IP | raw (convenience wrapper) | NO | NO | raw-read |
| 26 | `feed_client.rs:announce_indicator` — dedup check | Multi-type | raw (`lookup_local_indicator` for dedup) | NO | NO | feed-ingest |

**Invariant**: Raw lookup APIs are compatibility/debug APIs. They must not be consumed by enforcement paths. The `threat_intel_boundary_guard.rs` test enforces this boundary mechanically.

### F. Policy-Composed Read Consumers (staged)

These consumers use policy-composed lookups. They fall back to raw when no policy context is configured. They are staged for future use — no external production callers outside tests exist yet.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 27 | `threat_intel.rs:lookup_threat_indicator_policy_composed` | Any | policy-composed (fallback to raw) | NO | NO | read-preferred |
| 28 | `threat_intel.rs:lookup_local_indicator_policy_composed` | Any | policy-composed (fallback to raw) | NO | NO | read-preferred |
| 29 | `threat_intel.rs:lookup_local_indicator_by_ip_policy_composed` | IP | policy-composed (convenience) | NO | NO | read-preferred |

### G. Strict Policy-Composed Read Consumers (staged)

These consumers use strict policy-composed lookups. They return `None` when no policy context is configured — no raw fallback. They are staged for future enforcement migration.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 30 | `threat_intel.rs:lookup_threat_indicator_policy_strict` | Any | strict (returns `None` without context) | NO | NO | enforcement-intended |
| 31 | `threat_intel.rs:lookup_local_indicator_policy_strict` | Any | strict | NO | NO | enforcement-intended |
| 32 | `threat_intel.rs:lookup_local_indicator_by_ip_policy_strict` | IP | strict (convenience) | NO | NO | enforcement-intended |

### H. Worker IPC Consumers

These consumers apply Supervisor-broadcast blocklist events to worker BlockStore. They trust the Supervisor as control-plane authority.

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 33 | `lifecycle.rs:BlocklistUpdate handler` | IP + mesh ID | admin-manual (IPC replay) | YES: wholesale block-store write | NO | worker-ipc |
| 34 | `lifecycle.rs:BlocklistEventUpdate handler` | IP or mesh ID | admin-manual (IPC event apply) | YES: `apply_blocklist_event` | NO | worker-ipc |
| 35 | `lifecycle.rs:request_initial_blocklist` | IP + mesh ID | admin-manual (IPC bootstrap) | YES: wholesale block-store write | NO | worker-ipc |

### I. Honeypot Consumers (local-origin)

| # | File / Function | Indicator | Lookup API | Mutates Enforcement? | Emits BlocklistEvent? | Path Class |
|---|----------------|-----------|------------|---------------------|----------------------|------------|
| 36 | `honeypot/runner.rs:start_mesh_threat_publishing` | IP | admin-manual (via `announce_honeypot_indicator`) | YES: `block_ip_with_provenance` (`LocalHoneypot`) | NO | local-origin |

### J. Evaluation / Classification Helpers (pure functions)

These are pure helper functions that perform classification or composition without I/O or state mutation.

| # | File / Function | Purpose |
|---|----------------|---------|
| 37 | `threat_intel.rs:classify_consumer_action` | Maps consumer kind + policy decision + deferred mode → consumer action |
| 38 | `threat_intel.rs:evaluate_indicator_actionability` | Manual policy composition (Iteration 19) |
| 39 | `threat_intel.rs:evaluate_indicator_actionability_configured` | Injection-based policy composition |
| 40 | `threat_intel.rs:evaluate_incoming_threat_policy` | Enforcement policy gate — returns `IncomingThreatPolicyGate` |
| 41 | `threat_intel.rs:is_policy_actionable` | Shared gating helper — `Actionable` → true, all others → false |
| 42 | `threat_intel.rs:record_enforcement_suppression_metric` | Metrics recording by policy outcome |
| 43 | `threat_intel_policy.rs:evaluate_threat_intel_policy` | Core policy composition (Iteration 18) |
| 44 | `threat_intel_policy.rs:classify_threat_intel_policy_decision` | Maps decision → decision class |
| 45 | `threat_intel_policy.rs:threat_intel_policy_shadow_decision` | Builds shadow DTO |
| 46 | `threat_intel_policy.rs:classify_shadow_disagreement` | Classifies raw-vs-composed disagreement |

## Enforcement Invariants

1. **Threat-intel data is evidence. Policy-composed actionability is authority.** Raw advisory records alone must never cause enforcement mutations.

2. **`handle_incoming_threat` is the single enforcement entry point for mesh-sourced indicators.** All enforcement mutations for remote advisory consumption flow through this function and its `evaluate_incoming_threat_policy` gate.

3. **Admin/manual paths bypass the mesh policy gate by operator authority.** Admin ban/unban, local-origin announcements, and honeypot detections use `AdminManual` or `LocalHoneypot` provenance — not `MeshThreatIntelPolicyGated`.

4. **Worker IPC applies Supervisor events as control-plane authority.** Workers trust the Supervisor-broadcast blocklist events and preserve original provenance via `ipc_data_to_provenance()`.

5. **Raw lookup APIs are compatibility/diagnostic only.** `lookup_local_indicator`, `lookup_local_indicator_by_ip`, and `lookup_threat_indicator_in_dht` must not be consumed by enforcement paths. The `threat_intel_boundary_guard.rs` test enforces this boundary mechanically. Within `threat_intel.rs`, raw lookups are permitted only in explicit non-enforcement function bodies via function-level allowlisting (`threat_intel_consumer_actionability_guard.rs`). `handle_incoming_threat` and `_after_policy_permit` helpers are denylisted from raw lookups.

6. **Shadow-only paths never mutate enforcement state.** `evaluate_indicator_policy_shadow` is metrics/logs only. Admin diagnostics can expose shadow disagreement but cannot convert it into action without a policy gate.

7. **`AsnBlock` is observational only.** The `AsnBlock` branch in `handle_incoming_threat` does not mutate BlockStore.

8. **`LegacyUnknown` provenance is not used for new threat-intel blocklist writes.** New enforcement writes use `MeshThreatIntelPolicyGated`, `AdminManual`, `LocalHoneypot`, or other specific provenance kinds.

9. **Function-level raw-lookup boundary inside `threat_intel.rs`.** The source-scanning guardrail uses function-level allowlisting for `threat_intel.rs` rather than file-level exemption. Raw lookups are allowed only in diagnostic, policy-composed, and shadow evaluation function bodies. Enforcement functions (`handle_incoming_threat`, `_after_policy_permit` helpers) are explicitly denylisted.

## Provenance Assignment

| Origin | BlockProvenanceKind | Source String |
|--------|-------------------|---------------|
| Mesh enforcement (gated) | `MeshThreatIntelPolicyGated` | Context-dependent |
| Admin ban | `AdminManual` | `admin_ban_ip` / `admin_ban_mesh_id` |
| Honeypot detection | `LocalHoneypot` | Context-dependent |
| WAF escalation | `LocalWaf` | Context-dependent |
| ASN scraping | `LocalAsnTracker` | Context-dependent |
| Supervisor IPC (relay) | Preserved from origin | Via `ipc_data_to_provenance()` |
| Test fixtures | `Test` | N/A |
| Backward compat default | `LegacyUnknown` | `None` |

## Related Documents

- `architecture/threat_intel_request_waf_audit.md` — Request/WAF boundary audit
- `architecture/mesh_trust_domains.md` — Trust domain classification and invariants
- `docs/THREAT_INTEL.md` — User-facing threat-intel documentation
- `tests/threat_intel_boundary_guard.rs` — Raw lookup boundary guardrail test
- `tests/threat_intel_consumer_actionability_guard.rs` — Consumer actionability guardrail test
- `tests/mesh_id_boundary_guard.rs` — Mesh-ID request-path boundary guardrail
- `tests/manual_enforcement_provenance_guard.rs` — Provenance guardrail test
