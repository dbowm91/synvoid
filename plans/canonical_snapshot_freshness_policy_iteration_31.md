# Canonical Snapshot Freshness Policy — Iteration 31

## Goal

Define and implement explicit freshness semantics and fail-open/fail-closed policy for Supervisor-exported canonical snapshots before any broader data-plane consumer uses policy-composed threat intel.

Current state after Iteration 30:

- `EdgeReplicaManager::canonical_trust_snapshot()` produces a bounded canonical snapshot.
- `CanonicalTrustSnapshot` implements `CanonicalTrustReader` directly.
- Supervisor sends `CanonicalTrustSnapshotUpdate` to unified workers when they report ready.
- Workers deserialize and store the snapshot.
- Workers refresh `ThreatIntelPolicyContext` from snapshot + advisory source through `DataPlaneServices::update_threat_intel_policy_context(...)`.
- No proxy/YARA/WASM/routing/WAF consumers were migrated.

This pass should make the **meaning of absent, fresh, stale, and expired canonical snapshots explicit** and configurable. It should not expand consumers.

## Core Principle

A canonical snapshot is authoritative only within a bounded freshness policy.

The system must distinguish:

```text
no snapshot         -> canonical unavailable
fresh snapshot      -> normal policy-composed decisions allowed
stale-but-grace     -> degraded/observable mode, configurable allow/deny
expired snapshot    -> canonical unavailable or fail-closed depending policy
malformed snapshot  -> reject update, preserve previous snapshot if still valid
```

Do not silently treat an old snapshot as fresh authority.

## Non-Goals

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change `ThreatIntelPolicyDecision` semantics except where freshness maps into existing `Deferred` / `NotActionable` outcomes.

Do not remove raw lookup APIs.

Do not let workers own Raft or mutate canonical state.

Do not introduce global canonical readers.

Do not use `StaticCanonicalTrustReader` in production.

## Phase 1 — Inventory Existing Freshness Configuration

Find all existing freshness/staleness settings and policy names.

Run:

```bash
rg "freshness|stale|grace|hard_limit|fail_open|fail_closed|CanonicalFreshness|AuthorityFreshnessConfig|last_replica_refresh|canonical_snapshot|ThreatIntelPolicyDecision|Deferred|CanonicalUnavailable" crates src architecture AGENTS.md
```

Inspect:

- `crates/synvoid-mesh/src/mesh/canonical.rs`;
- `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs`;
- `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`;
- config structs for mesh/security policy;
- worker lifecycle snapshot handling;
- `DataPlaneServices::update_threat_intel_policy_context(...)`.

Classify existing knobs:

1. canonical/authority freshness knobs already present;
2. threat-intel-specific stale behavior knobs;
3. transport/snapshot refresh cadence knobs;
4. missing knobs.

### Acceptance Criteria

Do not invent new config names before verifying existing freshness settings.

## Phase 2 — Add A Canonical Snapshot Freshness Policy Type

Add a small policy type near the data-plane/canonical boundary. Prefer the mesh crate if policy semantics are canonical-domain-specific; prefer the main crate config layer if it needs runtime config integration.

Candidate type:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalSnapshotStaleMode {
    FailOpenDefer,
    FailClosedNotActionable,
    AllowStaleWithWarning,
}

#[derive(Debug, Clone)]
pub struct CanonicalSnapshotFreshnessPolicy {
    pub fresh_max_age_ms: u64,
    pub stale_grace_max_age_ms: u64,
    pub stale_mode: CanonicalSnapshotStaleMode,
}
```

Default suggestion:

```text
fresh_max_age_ms = 60_000
stale_grace_max_age_ms = 300_000
stale_mode = FailOpenDefer
```

Rationale:

- Fresh within 60s: use normally.
- Stale within 5m: do not silently trust; return degraded/deferred unless explicitly configured otherwise.
- Beyond grace: canonical unavailable.

Use project-appropriate defaults if existing config already defines better values.

### Acceptance Criteria

Freshness policy is explicit, documented, and has conservative defaults.

## Phase 3 — Classify Snapshot Freshness

Add a pure helper to classify snapshots.

Candidate:

```rust
pub enum CanonicalSnapshotFreshnessState {
    Missing,
    Fresh { age_ms: u64 },
    StaleWithinGrace { age_ms: u64 },
    Expired { age_ms: u64 },
    Invalid,
}

pub fn classify_canonical_snapshot(
    snapshot: Option<&CanonicalTrustSnapshot>,
    policy: &CanonicalSnapshotFreshnessPolicy,
    now_unix: u64,
) -> CanonicalSnapshotFreshnessState
```

Rules:

- `generated_at_unix == 0` is invalid/unavailable.
- Future timestamps should be clamped or treated as invalid; choose and document one behavior.
- Use saturating math.
- The helper must be pure and testable.
- Do not call DHT/Raft/IPC.

### Acceptance Criteria

Snapshot age classification is centralized and covered by tests.

## Phase 4 — Integrate Classification Into CanonicalTrustReader Behavior

Currently `CanonicalTrustSnapshot::freshness()` maps timestamp age directly to `CanonicalFreshness::Snapshot { age_ms }` or `Unavailable`.

Decide whether to preserve this low-level behavior and enforce policy at the composition boundary, or embed policy in a wrapper reader.

Preferred: add a wrapper so the plain snapshot remains a raw data reader.

Candidate:

```rust
pub struct PolicyCanonicalTrustReader {
    snapshot: CanonicalTrustSnapshot,
    policy: CanonicalSnapshotFreshnessPolicy,
}
```

or:

```rust
pub struct FreshnessBoundCanonicalReader {
    snapshot: CanonicalTrustSnapshot,
    policy: CanonicalSnapshotFreshnessPolicy,
}
```

Behavior:

- Fresh: delegate normal decisions with `CanonicalFreshness::Snapshot { age_ms }`.
- StaleWithinGrace + `AllowStaleWithWarning`: delegate but return `CanonicalFreshness::Stale { age_ms }`.
- StaleWithinGrace + `FailOpenDefer`: return `Unknown { freshness: Stale { age_ms }, reason: CanonicalUnavailable }`.
- StaleWithinGrace + `FailClosedNotActionable`: return `NotTrusted { freshness: Stale { age_ms }, reason: ExpiredSnapshot }`.
- Expired/Missing/Invalid: return `Unknown` or `NotTrusted` according to policy; document exact mapping.

### Acceptance Criteria

Policy-bound reader behavior is explicit and does not change raw `CanonicalTrustSnapshot` unless intentionally chosen.

## Phase 5 — Integrate With DataPlaneServices Refresh

Update `DataPlaneServices::update_threat_intel_policy_context(...)` or the worker receive path to apply the freshness policy before setting the manager context.

Candidate flow:

```text
CanonicalTrustSnapshotUpdate received
        ↓
store raw snapshot
        ↓
classify freshness
        ↓
wrap snapshot in freshness-bound reader if usable
        ↓
build ThreatIntelPolicyContext(reader, advisory)
        ↓
set_policy_context(Some(ctx))
```

If snapshot is expired/invalid:

- do not build context; or
- build a policy-bound reader that returns `Unknown`/`NotTrusted` by policy.

Choose one and document it. Conservative default: do not build context for expired/invalid snapshots; set context to `None` or a reader that returns `CanonicalUnavailable` consistently.

### Acceptance Criteria

Live IPC snapshot updates respect freshness policy before becoming active in `ThreatIntelligenceManager`.

## Phase 6 — Config Surface

Add configuration only if there is a clean existing mesh/security config location.

Candidate fields:

```toml
[mesh.canonical_snapshot]
fresh_max_age_secs = 60
stale_grace_secs = 300
stale_mode = "fail_open_defer"
```

Accepted `stale_mode` values:

- `fail_open_defer`
- `fail_closed_not_actionable`
- `allow_stale_with_warning`

Rules:

- Defaults must preserve conservative behavior.
- Missing config must not break startup.
- Add serde coverage if config structs already use serde.
- If config integration is too broad, use an internal default policy for this pass and add config as a follow-up.

### Acceptance Criteria

Either config exists with defaults and docs, or the pass explicitly uses a default-only policy and documents config as follow-up.

## Phase 7 — Metrics And Logging

Add low-cardinality observability for snapshot freshness state.

Suggested logs:

- snapshot received: generated_at, age_ms, counts;
- snapshot accepted fresh;
- snapshot accepted stale under grace;
- snapshot rejected expired;
- snapshot malformed/deserialization failed;
- policy context set/cleared due to freshness.

Suggested counters/gauges if metrics infra is simple:

- `canonical_snapshot_received_total`;
- `canonical_snapshot_malformed_total`;
- `canonical_snapshot_fresh_total`;
- `canonical_snapshot_stale_total`;
- `canonical_snapshot_expired_total`;
- `canonical_snapshot_age_ms`.

Rules:

- Do not log sensitive data.
- Do not log full snapshot contents.
- Avoid high-cardinality labels such as node IDs.

### Acceptance Criteria

Operators can tell whether workers are using fresh, stale, expired, or absent canonical snapshots.

## Phase 8 — Tests

Required unit tests:

1. missing snapshot classifies as `Missing`;
2. zero timestamp classifies as `Invalid` or unavailable;
3. fresh timestamp classifies as `Fresh`;
4. stale timestamp within grace classifies as `StaleWithinGrace`;
5. old timestamp classifies as `Expired`;
6. future timestamp behavior is tested;
7. policy-bound reader returns normal trust decisions for fresh snapshot;
8. policy-bound reader behavior for stale snapshot under each stale mode;
9. expired snapshot clears or disables policy context according to selected behavior;
10. malformed IPC snapshot preserves previous valid snapshot if that is selected behavior, or clears context if selected behavior says so.

Required integration-ish tests:

11. receiving fresh `CanonicalTrustSnapshotUpdate` refreshes `ThreatIntelPolicyContext`;
12. receiving expired snapshot does not silently keep using it as fresh authority;
13. raw `CanonicalTrustSnapshot` still implements `CanonicalTrustReader` for tests/low-level use.

### Acceptance Criteria

Freshness semantics are deterministic and covered without live network or real Raft cluster.

## Phase 9 — Documentation

Update:

- `architecture/mesh_trust_domains.md`;
- `architecture/mesh.md` or `architecture/mesh_deep_dive.md` if they describe trust state;
- `AGENTS.md` or `skills/synvoid_mesh.md` if they summarize mesh trust-domain facts.

Document:

- snapshot lifecycle;
- freshness thresholds;
- stale modes;
- default behavior for absent snapshot;
- default behavior for expired snapshot;
- whether malformed updates preserve previous valid snapshot;
- no consumer migration in this pass.

Suggested text:

```markdown
Canonical snapshots are authoritative only within the configured freshness policy. Workers classify snapshots as fresh, stale-within-grace, expired, invalid, or missing. By default, stale/expired canonical state does not silently authorize actionability; it degrades to deferred canonical-unavailable behavior until a fresh snapshot arrives. No proxy/YARA/WASM/routing/WAF consumers were migrated in this pass.
```

### Acceptance Criteria

Docs explain what happens when canonical snapshots are absent, stale, expired, or malformed.

## Phase 10 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid canonical_snapshot --features mesh
cargo test -p synvoid unified_server --features mesh
cargo test -p synvoid data_plane --features mesh
cargo test -p synvoid ipc --features mesh
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
```

Then adjacent checks:

```bash
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broad checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If package names differ, use actual names from `cargo metadata`.

## Completion Criteria

This pass is complete when:

- canonical snapshot freshness has explicit policy semantics;
- missing/fresh/stale/expired/invalid snapshots are classified centrally;
- stale and expired behavior is deterministic and documented;
- live IPC snapshot updates respect freshness policy before refreshing `ThreatIntelPolicyContext`;
- metrics/logging expose freshness state without sensitive data;
- no broad data-plane consumer migration occurs;
- tests cover the freshness matrix;
- docs match code.

## Follow-Up Recommendation

After freshness policy is stable, create a design-only plan for the first low-risk consumer of policy-composed threat intel. Candidate consumers should be read-only/diagnostic first, not proxy enforcement.
