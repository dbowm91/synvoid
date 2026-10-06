---
name: threat_intel_enforcement
description: Threat-intel enforcement authority split — which lookups may mutate block/rate-limit state, the diagnostic-only raw APIs, consumer kinds/actions, and provenance rules. Use when adding a threat-intel consumer, wiring an indicator into enforcement, or touching mesh threat-intel lookups.
---

# Skill: Threat-Intel Enforcement

## Context

The mesh threat-intel subsystem has a **hard boundary between observation and
enforcement**. Most lookup APIs are diagnostic-only; only a small set of
`*_policy_strict` APIs may drive block/rate-limit mutations. Getting this wrong
is the single most common way to introduce a silent enforcement or
silent-failure bug, so the split is guard-enforced rather than convention.

Binding docs (read these for the full contract):

- `architecture/threat_intel_consumer_actionability.md`
- `architecture/enforcement_decision_contract.md`
- `architecture/manual_enforcement_ownership.md`
- `architecture/threat_intel_request_waf_audit.md`

Canonical implementation: `crates/synvoid-mesh/src/mesh/threat_intel.rs`.
Verification-only wire vocabulary (`ThreatType`, `ThreatSeverity`) lives in
`crates/synvoid-mesh-protocol/src/wire.rs`; the runtime service re-exports it.

## When to Use

Use this skill when:

- Adding a new consumer of threat-intel indicators
- Deciding whether a lookup may mutate block / rate-limit / WAF state
- Writing a new block-store entry from a threat signal
- Reviewing code that calls `lookup_*` and then acts on the result

## The core rule

**Raw lookups are diagnostic-only. Enforcement uses `lookup_*_policy_strict`.**

Canonical policy-strict entry points in `crates/synvoid-mesh/src/mesh/threat_intel.rs`:

| API | Purpose |
|-----|---------|
| `lookup_threat_indicator_policy_strict` | DHT-sourced indicator, policy-gated |
| `lookup_local_indicator_policy_strict` | Locally stored indicator, policy-gated |
| `lookup_local_indicator_by_ip_policy_strict` | IP-shaped local lookup, policy-gated |

Diagnostic-only counterparts (**must not** drive enforcement):
`lookup_local_indicator`, `lookup_local_indicator_by_ip`,
`lookup_threat_indicator_in_dht`.

A `*_policy_composed` family also exists (`lookup_local_indicator_policy_composed`,
`lookup_local_indicator_by_ip_policy_composed`). It composes with the
configured policy; it is not a substitute for the strict gate when the consumer
intends to mutate enforcement state.

`ThreatType` (`crates/synvoid-mesh-protocol/src/wire.rs`) has 9 variants:
`Unspecified`, `IpBlock`, `IpThrottle`, `RateLimitViolation`, `SuspiciousActivity`,
`AsnBlock`, `DomainBlock`, `UrlBlock`, `CertBlock`.

## Consumer kinds

`ThreatIntelConsumerKind` (`crates/synvoid-mesh/src/mesh/threat_intel.rs`)
makes the intent explicit at the call site:

| Variant | Contract (from the doc comments) |
|---------|----------------------------------|
| `ShadowOnly` | Observability-only. Emits metrics/logs/admin DTOs. Must not mutate enforcement state. |
| `RawCompatibility` | Compatibility/debug. Uses raw lookup APIs. Must not mutate enforcement state. |
| `AdvisoryCache` | Advisory cache/bookkeeping. May store locally for diagnostics. Must not mutate WAF/block-store/rate-limit state. |
| `Enforcement` | Permitted to act on indicators. |
| `FailOpenNoAction` / `FailClosedNoAction` | Explicit no-action dispositions on the failure path. |

Paired with a `ThreatIntelConsumerAction` (including `PermitAction`), a new
consumer must declare `ThreatIntelConsumerKind::Enforcement` **and** an explicit
permitting action before it is allowed to mutate state.

**Shadow-only paths never emit blocklist events.** If you are writing a consumer
that must block, it is not shadow-only — do not label it `ShadowOnly` and then
mutate the block store.

## Provenance

New block-store writes must go through `block_ip_with_provenance` with a
`BlockProvenanceKind`. `LegacyUnknown` is reserved for compatibility, tests, and
mocks — never for new production call sites.

Worker admission reads the **BlockStore**, not `ThreatIntelligenceManager`. The
WAF pipeline itself queries and mutates no block/threat state.

`is_mesh_id_blocked()` is admin/control-plane only. Never call it from WAF,
request, proxy, or HTTP/3 code.

## Verification

Guard tests live in `tests/security_guard.rs` (root integration guard) and pin
the boundary. Relevant test functions:

- `threat_intel_rs_raw_lookup_only_in_allowlisted_functions`
- `handle_incoming_threat_contains_no_raw_lookup_calls`
- `handle_incoming_threat_is_policy_gated`
- `no_legacy_unknown_in_threat_intel_blocklist_writes`
- `no_admin_manual_or_supervisor_sync_in_threat_intel_writes`
- `mesh_threat_intel_policy_gated_is_not_flagged`

Run them after any change in this area:

```bash
cargo test --test security_guard --profile ci
```

Note: `security_regression` must run single-threaded
(`cargo test --test security_regression --profile ci -- --test-threads=1`).

## Pitfalls

- Using a raw `lookup_*` and then blocking. The guard allowlists the functions
  that may call raw lookups; anything else is a failure, not a warning.
- Assuming a `ShadowOnly` consumer is safe to give write access.
- Introducing `BlockProvenanceKind::LegacyUnknown` in new code to "make it
  compile" — that variant is a compatibility shim, not a default.
- Reaching for `is_mesh_id_blocked()` from the request path.

> Sections titled "Wave/M/P0.x fix log" in related skills are historical
> evidence, not TODOs. Locate claims by symbol; line numbers drift.