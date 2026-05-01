# MaluWAF Wave 15 Plan: Distributed Layer Hardening Follow-Up

**Status**: COMPLETED
**Last Updated**: 2026-05-01
**Completed**: All 6 priorities implemented and committed

## Current State

Wave 13 and Wave 14 have been implemented and committed:

- `d6535e85` - Wave 13: Mesh/DHT/Raft correctness hardening
- `956c7f19` - Wave 14: DHT Ingress Verification Centralization

Wave 15 (all priorities) has been implemented:

| Priority | Branch | Commit | Description |
|----------|--------|--------|-------------|
| P1 | wave15-p1-quorum-authorization | `0e993b2f` | Authorization-aware quorum proof verification |
| P2 | wave15-p2-sqlite-migration | `12497518` | SQLite schema migration for DiskRecordStore |
| P3 | wave15-p3-raft-snapshot-framing | `5358ec4c` | Raft snapshot framing cleanup |
| P4 | wave15-p4-ingress-identity-audit | `51eac01d` | Network ingress identity binding audit |
| P5 | wave15-p5-clippy-offline | `d116f46d` | Make clippy reproducible offline |
| P6 | wave15-p6-warning-cleanup | `fbc7cecd` | Clean up warnings from hardening work |

Test results from final verification:

- `cargo test --lib mesh::dht`: 132 tests passed
- `cargo test --lib mesh::raft`: 87 tests passed
- `cargo clippy --lib -- -D warnings`: clean build (no warnings)

## Done Criteria - All Met

- [x] Quorum proofs are verified against authorized global-node identity, not embedded self-asserted public keys.
- [x] Sensitive DHT records use actual full/regional quorum thresholds.
- [x] Existing disk DHT databases migrate safely.
- [x] Legacy rows without auth metadata fail closed for sensitive namespaces.
- [x] Default Raft snapshot handling no longer relies on payload length heuristics.
- [x] Network DHT ingress identity binding is audited, tested, and fail-closed.
- [x] The repository's verification commands can run without network downloads.

## Implementation Notes

### Priority 1: Quorum Authorization (Commit `0e993b2f`)

Added `QuorumVerifierContext` struct with `authorized_global_keys` callback:
- `verify_quorum_proof_with_context()` validates node_id is authorized
- `verify_quorum_proof_authoritative()` gets actual global node count from topology
- Replaced `0`-count call sites in `store_record_global`, `apply_sync`, `handle_record_commit`
- Tests: rejects unknown key claiming known node, rejects key for global-A labeled as global-B

### Priority 2: SQLite Migration (Commit `12497518`)

Added migration-based schema initialization in `DiskRecordStore::new()`:
- `run_migrations()` inspects `PRAGMA table_info` and `ALTER TABLE` missing columns
- Adds signature, signer_public_key, quorum_proof, request_id columns
- Sets `PRAGMA user_version` for future migrations
- `is_legacy_row()` helper detects rows without auth metadata
- `load_from_disk()` quarantines legacy sensitive records (skips them)
- 6 tests: migration succeeds, columns exist, legacy row behavior, security metadata round-trip

### Priority 3: Raft Snapshot Framing (Commit `5358ec4c`)

- Added `ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES` constant defaulting to `false`
- When disabled: reject InstallSnapshot on decode failure (no length heuristic)
- When enabled: use legacy length heuristic with LEGACY logging prefix
- 6 tests: explicit header/chunk roundtrip, Header vs Chunk discriminant differentiation

### Priority 4: Ingress Identity Audit (Commit `51eac01d`)

Enhanced `DhtRecord::verify_for_ingress()`:
- Binds signer public key to source_node_id via `NodeId::from_public_key()` derivation
- Added `InvalidSourceNodeId` error when signer doesn't match source
- 4 adversarial tests: local_node_id rejection, mismatched signer/source, different source rejection

### Priority 5: Clippy Offline (Commit `d116f46d`)

- Added `vendored` feature to `utoipa-swagger-ui` to embed assets locally
- `cargo clippy --lib -- -D warnings` now runs without network access

### Priority 6: Warning Cleanup (Commit `fbc7cecd`)

Clean up unused imports and variables:
- record_store.rs: removed unused DiskRecordStore import
- signed.rs: removed unused Ed25519Signer/Ed25519Verifier imports, fixed ref pattern
- hybrid_signature.rs: removed unused rkyv imports
- raft/network.rs: removed unused bytes::Bytes import
- raft/state_machine.rs: removed unused Path, Async*Ext imports, use Error::other()
- record_store_disk.rs: use .ok(), .flatten() patterns
- record_store_persist.rs: removed unnecessary mut
- protocol.rs: prefix unused pool with underscore, added #[derive(Default)]
- topology.rs: collapsed nested if-else block

## Verification Commands

```bash
cargo test --lib mesh::dht
cargo test --lib mesh::raft
cargo clippy --lib -- -D warnings
cargo fmt --check
```