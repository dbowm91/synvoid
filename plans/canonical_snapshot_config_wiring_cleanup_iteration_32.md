# Canonical Snapshot Config Wiring Cleanup — Iteration 32

## Goal

Finish the canonical snapshot freshness-policy track by wiring runtime configuration into worker snapshot handling and reconciling stale-mode behavior/docs/tests.

Current state after Iteration 31:

- `CanonicalSnapshotFreshnessPolicy` exists with conservative defaults.
- `CanonicalSnapshotStaleMode` exists: `FailOpenDefer`, `FailClosedNotActionable`, `AllowStaleWithWarning`.
- `classify_canonical_snapshot(...)` centralizes missing/fresh/stale/expired/invalid classification.
- `FreshnessBoundCanonicalReader` enforces stale-mode semantics.
- Worker IPC snapshot handling classifies received snapshots before applying them.
- Worker IPC snapshot handling still uses `CanonicalSnapshotFreshnessPolicy::default()` with a TODO to source config.
- Docs mention config fields; verify and reconcile them with code.

This pass should be narrow and should not migrate any new data-plane consumers.

## Non-Goals

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change threat-intel actionability semantics beyond already-defined freshness policy.

Do not remove raw lookup APIs.

Do not move Raft consensus into workers.

Do not let workers mutate canonical state.

Do not introduce global canonical readers.

Do not use `StaticCanonicalTrustReader` in production.

## Phase 1 — Verify Current Config Surface

Run:

```bash
rg "canonical_snapshot_fresh_max_age|canonical_snapshot_stale_grace|canonical_snapshot_stale_mode|CanonicalSnapshotFreshnessPolicy|CanonicalSnapshotStaleMode|AuthorityFreshnessConfig|fresh_max_age_ms|stale_grace" crates src config architecture AGENTS.md
```

Determine whether these fields already exist:

```rust
canonical_snapshot_fresh_max_age_ms
canonical_snapshot_stale_grace_max_age_ms
canonical_snapshot_stale_mode
```

If they exist, verify:

- serde names;
- defaults;
- config docs/examples;
- conversion into `CanonicalSnapshotFreshnessPolicy`.

If they do not exist, add them in the correct config owner or revise docs to say this pass introduces them.

### Acceptance Criteria

The docs and actual config structs agree about the available canonical snapshot freshness knobs.

## Phase 2 — Add Or Normalize Config Conversion

Add a single conversion helper from runtime config into `CanonicalSnapshotFreshnessPolicy`.

Candidate if fields live in `AuthorityFreshnessConfig`:

```rust
impl From<&AuthorityFreshnessConfig> for CanonicalSnapshotFreshnessPolicy {
    fn from(cfg: &AuthorityFreshnessConfig) -> Self {
        Self {
            fresh_max_age_ms: cfg.canonical_snapshot_fresh_max_age_ms,
            stale_grace_max_age_ms: cfg.canonical_snapshot_stale_grace_max_age_ms,
            stale_mode: cfg.canonical_snapshot_stale_mode,
        }
    }
}
```

If fields live in main crate config, use a similarly narrow helper at the worker boundary.

Rules:

- Avoid duplicate ad hoc conversion code.
- Defaults must remain conservative.
- Invalid configs should be rejected at config load if possible, or clamped/logged clearly.
- `stale_grace_max_age_ms` must be >= `fresh_max_age_ms`; decide whether to validate or normalize.

### Acceptance Criteria

There is one obvious way to obtain `CanonicalSnapshotFreshnessPolicy` from runtime config.

## Phase 3 — Thread Config Into Worker Snapshot Handling

Replace the current worker lifecycle TODO/default policy with config-sourced policy.

Current problematic pattern:

```rust
let freshness_policy = CanonicalSnapshotFreshnessPolicy::default();
```

Target shape:

```rust
let freshness_policy = canonical_snapshot_policy_from_config(&shared_config).await;
```

or, if the worker state should own this:

```rust
let freshness_policy = state.canonical_snapshot_freshness_policy().await;
```

Rules:

- Read config once per snapshot update or cache it in worker state; choose the simpler safe option.
- Avoid holding config locks while performing IPC/deserialization or policy-context update.
- Missing config must fall back to conservative defaults.
- Log which policy is active at debug/info level without high-cardinality labels.

### Acceptance Criteria

Worker snapshot handling no longer hardcodes the default policy when runtime config exists.

## Phase 4 — Reconcile Stale-Mode Live Behavior

There is a subtle distinction:

- `FreshnessBoundCanonicalReader` can express stale `FailOpenDefer` and stale `FailClosedNotActionable` as reader decisions.
- The worker path currently clears policy context for stale `FailOpenDefer` and stale `FailClosedNotActionable`.

Choose one canonical live behavior and document it.

Recommended behavior for now:

- `Fresh`: install `FreshnessBoundCanonicalReader`.
- `StaleWithinGrace + AllowStaleWithWarning`: install `FreshnessBoundCanonicalReader`.
- `StaleWithinGrace + FailOpenDefer`: clear context (`None`), causing policy composition to defer canonical decisions.
- `StaleWithinGrace + FailClosedNotActionable`: install `FreshnessBoundCanonicalReader` so canonical queries return `NotTrusted/ExpiredSnapshot`, preserving fail-closed semantics.
- `Expired` / `Invalid` / `Missing`: clear context or install fail-closed reader according to configured policy; document exact choice.

If simpler behavior is preferred, keep current clearing semantics but update docs to say live path clears context for both stale defer and stale fail-closed. Do not leave wrapper and live behavior contradictory.

### Acceptance Criteria

Stale-mode behavior is consistent across code comments, docs, and tests.

## Phase 5 — Preserve Previous Valid Snapshot Policy

Decide malformed/invalid update behavior.

Current likely behavior:

- malformed deserialization logs error and preserves previous snapshot/context;
- invalid/expired deserialized snapshot stores raw snapshot, then clears context.

This needs to be explicit.

Recommended behavior:

- malformed postcard payload: reject update; preserve previous valid snapshot/context;
- invalid timestamp: do not replace stored valid snapshot; clear or preserve context according to selected stale policy;
- expired timestamp: store for diagnostics only if useful, but do not use as active authority.

If implementation complexity is too high, at least document current behavior and test it.

### Acceptance Criteria

Malformed/invalid/expired update semantics are deliberate and covered by tests.

## Phase 6 — Tests

Add or update focused tests.

Required tests:

1. config defaults produce conservative `CanonicalSnapshotFreshnessPolicy`;
2. explicit config values convert into `CanonicalSnapshotFreshnessPolicy`;
3. invalid config where stale grace < fresh threshold is rejected or normalized;
4. worker snapshot path uses config-sourced thresholds rather than hardcoded defaults;
5. `AllowStaleWithWarning` installs a reader and preserves stale freshness;
6. `FailOpenDefer` behavior matches selected live semantics;
7. `FailClosedNotActionable` behavior matches selected live semantics;
8. malformed snapshot payload preserves or clears previous context according to documented behavior;
9. expired snapshot does not silently remain active as fresh authority;
10. docs/examples match enum serde names.

If full worker IPC tests are heavy, extract the policy-application logic into a pure helper and test that helper.

### Acceptance Criteria

Tests prove config-sourced policy and stale-mode behavior.

## Phase 7 — Documentation Cleanup

Update:

- `architecture/mesh_trust_domains.md`;
- `architecture/mesh.md` or `architecture/mesh_deep_dive.md` if they describe canonical snapshots;
- `AGENTS.md` or `skills/synvoid_mesh.md` if they summarize this track;
- config examples/docs if present.

Docs must answer:

- where freshness config lives;
- defaults;
- accepted `stale_mode` values and serde names;
- what happens for no snapshot;
- what happens for malformed snapshot;
- what happens for invalid timestamp;
- what happens for stale snapshot under each mode;
- what happens for expired snapshot;
- no proxy/YARA/WASM/routing/WAF consumer migration in this pass.

### Acceptance Criteria

No docs claim config is wired if lifecycle still uses hardcoded defaults.

## Phase 8 — Validation Commands

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

Then broad checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If package names differ, use actual names from `cargo metadata`.

## Completion Criteria

This pass is complete when:

- freshness policy is config-sourced or docs explicitly state it is default-only;
- lifecycle code no longer has stale TODO/default drift;
- stale-mode live behavior is consistent and tested;
- malformed/invalid/expired snapshot behavior is documented and tested;
- no broad consumers are migrated;
- docs match code.

## Follow-Up Recommendation

After this cleanup, the trust-domain/freshness track is a reasonable stopping point. The next architecture track should be independent unless a concrete low-risk consumer for policy-composed threat intel is selected.
