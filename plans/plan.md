# MaluWAF Wave 15 Plan: Distributed Layer Hardening Follow-Up

**Status**: READY FOR IMPLEMENTATION
**Last Updated**: 2026-05-01
**Scope**: Residual mesh/DHT/Raft hardening after Wave 13 and Wave 14.

## Current State

Wave 13 and Wave 14 have been implemented and committed:

- `d6535e85` - Wave 13: Mesh/DHT/Raft correctness hardening
- `956c7f19` - Wave 14: DHT Ingress Verification Centralization

Targeted test results from the current tree:

- `cargo test --lib mesh::dht` passed: 127 tests.
- `cargo test --lib mesh::raft` passed: 87 tests.
- `cargo clippy --lib -- -D warnings` could not complete because `utoipa-swagger-ui` attempted to download Swagger UI from GitHub and DNS/network access failed.

This plan intentionally prunes the completed Wave 13/Wave 14 task list. The next agent should focus only on the residual concerns below.

## Ground Rules

- Read `AGENTS.md` and `src/mesh/AGENTS.override.md` before editing.
- Keep changes scoped to `src/mesh/` and tests unless a build-system change is required for verification.
- Do not weaken default-deny behavior for sensitive DHT namespaces.
- Do not trust node IDs or public keys carried inside untrusted records/proofs unless they are checked against an authenticated registry, certificate manager, topology, or configured trust anchor.
- Add or update regression tests for each fixed issue.
- Keep distributed signable payloads typed and canonical; use postcard or `crate::serialization`, not ad hoc strings.

## Priority 1: Bind Quorum Proofs To Authorized Global Nodes

### Problem

`src/mesh/dht/signed.rs` now verifies quorum proof signature bytes, which is progress. However, verification currently uses the `signer_public_key` embedded in each proof. That proves possession of some key, not that the signer is an authorized global node for the claimed `node_id`.

Known call sites still pass `0` as the global-node count in at least:

- `src/mesh/dht/record_store_crud.rs`
- `src/mesh/dht/record_store_message.rs`

That falls back to the minimum threshold and can undercount real quorum requirements.

### Required Work

1. Introduce an authorization-aware quorum verifier.

   Suggested shape:

   ```rust
   pub struct QuorumVerifierContext<'a> {
       pub total_known_global_nodes: usize,
       pub regional_voter_set: Option<&'a HashSet<String>>,
       pub request_id: &'a str,
       pub action: &'a str,
       pub authorized_global_keys: &'a dyn Fn(&str) -> Option<String>,
   }
   ```

   Exact API can differ, but the verifier must have access to trusted node-id to public-key mapping.

2. Verify all of the following before counting a signature:

   - `proof.node_id` is a known authorized global node.
   - `proof.signer_public_key` matches the trusted public key for `proof.node_id`, or the proof omits embedded keys and resolves them from trusted state.
   - the signature verifies over the canonical quorum-proof payload for this exact record/request/action.
   - duplicate `node_id`s count once.
   - in regional quorum mode, `proof.node_id` is in the selected voter set.

3. Replace `total_known_global_nodes = 0` call sites with actual topology/cert-manager/global-node counts. If the count is unavailable for a security-sensitive path, fail closed.

4. Preserve a clearly named test-only helper if minimum-threshold behavior is needed for unit tests.

### Tests

Add tests proving:

- A proof signed by an unknown key but claiming a known global `node_id` is rejected.
- A proof signed by a valid key for `global-A` but labelled as `global-B` is rejected.
- A valid proof with fewer than full or regional quorum threshold is rejected.
- Regional quorum rejects signatures from global nodes outside the selected regional voter set.
- Existing valid proof tests still pass when the trusted key map is provided.

### Acceptance Criteria

- No production verification path accepts quorum proof signatures solely because the embedded public key verifies.
- No sensitive DHT path calls quorum verification with `0` total nodes unless explicitly documented as a test-only or bootstrap-only path.
- `verified_upstream:*` and `tier_claim:*` records require an authorized quorum proof.

## Priority 2: Add Real SQLite Migration Handling For Disk DHT Storage

### Problem

`src/mesh/dht/record_store_disk.rs` now creates new columns for `signature`, `signer_public_key`, `quorum_proof`, and `request_id`, but `CREATE TABLE IF NOT EXISTS` does not migrate existing databases. Current `SELECT` statements expect those columns, so old databases can fail at runtime.

### Required Work

1. Add a schema migration path in `DiskRecordStore::new()`.

   Minimum viable approach:

   - inspect `PRAGMA table_info(dht_records)`;
   - `ALTER TABLE` missing columns one by one;
   - use nullable/default-safe columns for legacy rows;
   - set a `PRAGMA user_version` for future migrations.

2. Decide and implement legacy-row semantics:

   - legacy rows without signatures/proofs must not be treated as verified sensitive records;
   - public cacheable records may be loaded if policy allows;
   - privileged/sensitive legacy rows should be rejected, quarantined, or ignored with a clear log message.

3. Ensure all read paths tolerate missing/null auth metadata after migration.

4. Add a small helper to detect whether a row came from legacy auth metadata if needed.

### Tests

Add tests that create an old-schema SQLite DB manually, then open it with `DiskRecordStore::new()`:

- old schema migrates without panic;
- new columns exist after open;
- old public record can be read if allowed;
- old sensitive record is not silently promoted as verified/live;
- new records round-trip all security metadata.

### Acceptance Criteria

- Existing on-disk databases do not break after upgrade.
- Full security metadata round-trips for new rows.
- Legacy sensitive rows fail closed.

## Priority 3: Finish Raft Snapshot Framing Cleanup

### Problem

`RaftSnapshotFrame` exists and new snapshot messages decode explicitly, but `src/mesh/transport_peer.rs` still falls back to the old `payload.data.len() < 100` heuristic when frame decode fails.

That may be acceptable temporarily for rolling upgrades, but the current plan and tests should make the intended compatibility window explicit.

### Required Work

Choose one path:

1. **Strict path**: remove the legacy length heuristic entirely.

2. **Compatibility path**: keep fallback but gate it behind a config flag or clearly named constant, for example `ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES`, defaulting to false for new deployments.

If keeping fallback:

- add telemetry/logging that identifies legacy snapshot frame usage;
- add a TODO/removal version;
- ensure malformed short chunks cannot be accepted as headers unless legacy mode is explicitly enabled.

### Tests

Add tests for:

- valid explicit header frame;
- valid explicit short chunk frame;
- malformed/non-frame payload is rejected when legacy mode is disabled;
- legacy fallback only works when explicitly enabled, if compatibility path is chosen.

### Acceptance Criteria

- Production default does not rely on payload length to identify snapshot frame type.
- Short final chunks cannot be misclassified as headers in the default path.

## Priority 4: Audit Network Ingress Identity Binding End-To-End

### Problem

Wave 14 added centralized verification and `is_local_origin` handling, but the network ingress surface is broad. We still need a path-by-path audit proving remote payloads cannot influence local-origin classification or bypass signer checks.

### Required Work

Audit and document each ingress path:

- `DhtRecordAnnounce`
- `DhtRecordPush`
- `DhtRecordCommit`
- `DhtSyncResponse`
- `DhtSnapshotResponse`
- `DhtAntiEntropyResponse`
- quorum store/signature/rejection messages

For each path, confirm:

- authenticated transport peer ID is available;
- record `source_node_id` is compared to peer identity or validated through explicit delegation;
- local-origin bypass is impossible for network-originated records;
- signer public key is bound to source node or trusted registry where required;
- sensitive namespace policy runs after source classification and before storage mutation.

If any path cannot prove these properties, fix it or make it fail closed.

### Tests

Add at least one adversarial test per ingress class where practical:

- remote peer sends record with `source_node_id == local_node_id`;
- remote peer sends record with mismatched signer and source;
- remote peer sends valid signature for a different source node;
- remote sync/anti-entropy path attempts to promote a local-looking sensitive record.

### Acceptance Criteria

- The code has no network path where remote records are treated as local based only on payload fields.
- Tests cover the highest-risk announce, commit, and sync/anti-entropy paths.

## Priority 5: Make Verification Gate Reproducible Without Network

### Problem

`cargo clippy --lib -- -D warnings` failed because `utoipa-swagger-ui` attempted to download Swagger UI during build. This blocks the repository's own verification command in offline/restricted environments.

### Required Work

Investigate the intended project pattern for Swagger UI assets. Options:

- vendor the required Swagger UI archive/assets in the repository or a local build cache;
- configure `utoipa-swagger-ui` to use local assets;
- gate Swagger UI build features so `cargo clippy --lib` does not require network;
- document an environment variable or setup step if a local asset already exists.

Do not add a build path that silently fetches network resources during normal verification.

### Tests

Run in a network-restricted environment:

```bash
cargo clippy --lib -- -D warnings
```

If the command still requires an external artifact, the task is not complete.

### Acceptance Criteria

- `cargo clippy --lib -- -D warnings` can run without downloading from GitHub.
- Any remaining warnings in touched mesh/DHT/Raft areas are fixed.

## Priority 6: Clean Up Warnings Introduced Or Exposed By The Hardening Work

### Problem

Targeted tests pass, but current builds emit warnings from mesh/DHT/Raft-related files, including unused imports and unused variables.

Known examples seen during test builds:

- `src/mesh/dht/record_store.rs`
- `src/mesh/dht/record_store_message.rs`
- `src/mesh/dht/record_store_sync.rs`
- `src/mesh/dht/signed.rs`
- `src/mesh/raft/network.rs`
- `src/mesh/raft/state_machine.rs`
- `src/mesh/raft/edge_replica.rs`

### Required Work

- Remove unused imports and variables where straightforward.
- Prefix intentionally unused variables with `_`.
- Do not hide meaningful dead code with broad `allow` attributes unless there is a concrete reason.

### Acceptance Criteria

- `cargo test --lib mesh::dht` and `cargo test --lib mesh::raft` run without warnings from touched code, or every remaining warning is documented as pre-existing and outside this scope.
- `cargo clippy --lib -- -D warnings` passes after Priority 5.

## Verification Commands

Run during implementation:

```bash
cargo test --lib mesh::dht
cargo test --lib mesh::raft
cargo test --lib verify_quorum_proof
cargo test --lib record_store_disk
cargo test --lib snapshot
```

Final verification:

```bash
cargo test --lib --no-run
cargo test --lib mesh::dht
cargo test --lib mesh::raft
cargo clippy --lib -- -D warnings
cargo fmt --check
```

## Done Criteria

- Quorum proofs are verified against authorized global-node identity, not embedded self-asserted public keys.
- Sensitive DHT records use actual full/regional quorum thresholds.
- Existing disk DHT databases migrate safely.
- Legacy rows without auth metadata fail closed for sensitive namespaces.
- Default Raft snapshot handling no longer relies on payload length heuristics.
- Network DHT ingress identity binding is audited, tested, and fail-closed.
- The repository's verification commands can run without network downloads.
