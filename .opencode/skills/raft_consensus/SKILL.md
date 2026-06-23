---
name: raft_consensus
description: Raft consensus integration for global control plane coordination and state replication.
---

# Raft Consensus for Global Control Plane

## Overview

Wave 6-7 implemented Raft consensus for the SynVoid Global Control Plane, replacing the previous quorum-based signature approach that required 2/3 of Global nodes to manually sign records.

## Architecture

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `MeshRaftNetwork` | `crates/synvoid-mesh/src/mesh/raft/network.rs` | Implements `RaftNetworkV2` trait, wraps `MeshBackendPool` |
| `MeshRaftNetworkFactory` | `crates/synvoid-mesh/src/mesh/raft/network.rs` | Creates `MeshRaftNetwork` instances per target |
| `GlobalRegistryStateMachine` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | RaftStateMachine impl using rusqlite |
| `GlobalRegistryLogStorage` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | RaftLogStorage impl for log persistence |
| `GlobalRegistryTypeConfig` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | RaftTypeConfig impl for GlobalRegistry |
| `RaftInstance` | `crates/synvoid-mesh/src/mesh/raft/instance.rs` | Wraps openraft::Raft with lifecycle management |
| `RaftAwareClient` | `crates/synvoid-mesh/src/mesh/raft/client.rs` | ConsistentRead RPC for Edge/Origin nodes |
| `RaftSnapshotManager` | `crates/synvoid-mesh/src/mesh/raft/instance.rs` | Point-in-time snapshots using rusqlite backup API |

### Namespaces

The Raft state machine organizes data by namespace:

```rust
pub enum Namespace {
    Org,        // Organization public keys
    Intel,      // Threat intelligence indicators
    Revocation, // Global node revocation list
}
```

## RaftTypeConfig Implementation

```rust
pub struct GlobalRegistryTypeConfig;

impl RaftTypeConfig for GlobalRegistryTypeConfig {
    type D = RaftCommand;                            // Application data (Set/Delete commands)
    type R = ();                                    // Response type (empty for now)
    type NodeId = u64;                              // Node ID type
    type Node = BasicNode;                          // Node with address info
    type Term = u64;                                // Term number
    type LeaderId = LeaderId<u64, NodeId>;          // Leader identification
    type Vote = openraft::Vote<LeaderId<u64, NodeId>>;
    type Entry = Entry<CommittedLeaderId<u64>, RaftCommand, NodeId, BasicNode>;
    type SnapshotData = bytes::Bytes;                     // Binary snapshot (streaming format since W11.2)
    type AsyncRuntime = openraft::impls::TokioRuntime;
    type Responder<T> = OneshotResponder<GlobalRegistryTypeConfig, T>;
    type Batch<T> = Vec<T>;
    type ErrorSource = AnyError;
}
```

## Raft Network Implementation

### MeshRaftNetwork

```rust
pub struct MeshRaftNetwork<C: RaftTypeConfig> {
    backend: Arc<MeshBackendPool>,
    proxy: Arc<MeshProxy>,
    target: String,
}

impl<C: RaftTypeConfig> RaftNetworkV2<C> for MeshRaftNetwork<C>
where
    C::NodeId: std::fmt::Display + Send + 'static,
    C::Node: Send + 'static,
{
    async fn append_entries(...);
    async fn vote(...);
    async fn full_snapshot(...);  // Returns Unsupported error
}
```

### Key Design Decisions

1. **Multiplexed over existing transport**: Raft RPCs use `MeshMessage::Raft` variant, not a separate port
2. **Postcard serialization**: Raft messages serialized with `postcard` for binary stability
3. **DHT fallback**: If Raft is unreachable, nodes fall back to DHT with "Eventually Consistent" marker

## Trust Transition

### The Problem (Before)

The old system required 2/3 of Global nodes to manually sign a record. If 1/3+1 nodes were partitioned, no new trust records could be created (quorum deadlock).

### The Solution (After)

In Raft, a record is "Authorized" the moment it is committed to the log. The Leader's commitment IS the cryptographic proof of majority consensus.

### Transition Logic

1. `OrgKeyManager.commit_key_to_raft()` submits new key to Raft cluster
2. Once committed, Leader broadcasts `RaftCommitNotification` via DHT (gossip)
3. Verification logic in `peer_auth.rs` accepts **either**:
   - 2/3 signature set (legacy DHT-based), OR
   - Raft-signed attestation from current Leader

## Message Types

### MeshMessage::Raft

```rust
pub struct RaftPayload {
    pub msg_type: RaftMsgType,
    pub data: Vec<u8>,
    pub request_id: Option<String>,  // Added in W9.1 for RPC correlation
}

pub enum RaftMsgType {
    VoteRequest,
    VoteResponse,
    AppendEntries,
    AppendEntriesResponse,
    InstallSnapshot,
    InstallSnapshotResponse,
    ClientProposal,  // For client_write() calls
}
```

### RaftCommitNotification

```rust
pub struct RaftCommitNotification {
    pub leader_id: String,
    pub commit_index: u64,
    pub namespace: Namespace,
    pub key_id: String,
    pub timestamp: u64,
}
```

## RaftInstance - Cluster Lifecycle

```rust
pub struct RaftInstance {
    pub raft: Arc<Raft<GlobalRegistryTypeConfig, GlobalRegistryStateMachine>>,
    pub registry: GlobalRegistry,
    pub network_factory: MeshRaftNetworkFactory,
    node_id: u64,
    is_observer: bool,
    observer_tags: Vec<String>,
}

impl RaftInstance {
    pub async fn new(...) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
    pub async fn initialize(&self, cluster_nodes: Vec<u64>) -> Result<(), ...>;
    pub async fn add_learner(&self, node_id: u64, tags: Vec<String>) -> Result<(), ...>;
    pub async fn add_node(&self, node_id: u64) -> Result<(), ...>;
    pub async fn remove_node(&self, node_id: u64) -> Result<(), ...>;
    pub async fn client_write(&self, command: RaftCommand) -> Result<u64, ...>;
    pub async fn raft_append_entries(&self, rpc: AppendEntriesRequest<C>) -> Result<AppendEntriesResponse<C>, ...>;  // W9.1
    pub async fn raft_vote(&self, rpc: VoteRequest<C>) -> Result<VoteResponse<C>, ...>;  // W9.1
    pub async fn install_snapshot(&self, meta: &SnapshotMeta, snapshot: Bytes) -> Result<(), ...>;  // W9.6
    pub async fn is_leader(&self) -> bool;
    pub async fn get_leader_id(&self) -> Option<u64>;  // Now uses raft.current_leader()
    pub async fn get_current_leader(&self) -> Option<u64>;  // W9.4
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<u64, ...>;
    pub async fn read(&self, namespace: Namespace, key: &str) -> Option<Vec<u8>>;  // W9.3: Linearizable read
}
```

## Client Write Correction (W7.4)

The RaftAwareClient now uses `client_write()` instead of raw `AppendEntries`:

```rust
impl RaftAwareClient {
    pub async fn raft_write_local(&self, namespace: Namespace, key: String, value: Vec<u8>) -> Result<u64, RaftAwareClientError> {
        let command = RaftCommand::Set {
            namespace,
            key,
            value,
            source_node_id: None,  // Set by handler if needed
            signature: None,      // Set by handler if needed
        };
        let resp = self.raft_instance.as_ref().unwrap().raft.client_write(command).await?;
        Ok(resp.log_id.index)
    }
}
```

## Global Registry State Machine

Uses rusqlite for persistence with full `RaftStateMachine` trait implementation:

```rust
pub struct GlobalRegistryStateMachine {
    db: Arc<Mutex<Connection>>,
}

#[add_async_trait]
impl RaftStateMachine<GlobalRegistryTypeConfig> for GlobalRegistryStateMachine {
    async fn applied_state(&mut self) -> Result<(Option<LogIdOf<GlobalRegistryTypeConfig>>, StoredMembershipOf<GlobalRegistryTypeConfig>), io::Error>;
    async fn apply<Strm>(&mut self, entries: Strm) -> Result<(), io::Error>;
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder;
    async fn begin_receiving_snapshot(&mut self) -> Result<Bytes, io::Error>;
    async fn install_snapshot(&mut self, meta: &SnapshotMetaOf<GlobalRegistryTypeConfig>, snapshot: Bytes) -> Result<(), io::Error>;  // W11.2: streaming binary format
    async fn get_current_snapshot(&mut self) -> Result<Option<SnapshotOf<GlobalRegistryTypeConfig>>, io::Error>;
}
```

## SQLite Snapshots (W7.5)

Point-in-time snapshotting using rusqlite backup API:

```rust
pub struct RaftSnapshotManager {
    db_path: PathBuf,
}

impl RaftSnapshotManager {
    pub fn create_point_in_time_snapshot(&self, target_path: &PathBuf) -> Result<(), ...> {
        let source = rusqlite::Connection::open(&self.db_path)?;
        let mut target = rusqlite::Connection::open(target_path)?;
        let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
        backup.run_to_completion(5, Duration::from_millis(250), None)?;
        Ok(())
    }

    pub fn restore_from_snapshot(snapshot_path: &PathBuf, db_path: &PathBuf) -> Result<(), ...>;
    pub fn compact_database(&self) -> Result<(), ...>;
    pub fn get_snapshot_path(&self, snapshot_id: &str) -> PathBuf;
}
```

## ConsistentRead RPC

Edge/Origin nodes use `RaftAwareClient` for strong reads:

```rust
impl RaftAwareClient {
    // Query any Global node - if not leader, get NotLeader hint
    pub async fn consistent_read(&self, key: &str) -> Result<ConsistentReadResult, RaftAwareClientError>;

    // Fallback to DHT if Raft fails
    async fn fallback_to_dht(&self, key: &str) -> Result<ConsistentReadResult, RaftAwareClientError>;
}
```

## Global Registry State Machine

Uses rusqlite for persistence:

```rust
pub struct GlobalRegistryStateMachine {
    db: Arc<Mutex<Connection>>,
}

impl RaftStateMachine for GlobalRegistryStateMachine {
    // get_value(), set_value(), delete_value() for Org/Intel/Revocation namespaces
}
```

## Wave 8 - Control Plane Hardening

### W8.1: Raft-Backed CRL

Global node revocation now goes through Raft:

```rust
impl OrgKeyManager {
    pub async fn revoke_global_node(
        &self,
        target_node_id: &str,
        reason: &str,
    ) -> Result<(), OrgKeyError> {
        // Commit revocation to Namespace::Revocation via Raft
        let revocation_info = RevocationInfo {
            revoked_at: crate::mesh::safe_unix_timestamp(),
            reason: reason.to_string(),
        };
        let value = crate::serialization::serialize(&revocation_info)?;
        if let Some(raft_client) = self.raft_client.read().clone() {
            raft_client.raft_write(Namespace::Revocation, target_node_id.to_string(), value).await?;
        }
        // Broadcast RaftCommitNotification after commit
    }
}
```

### W8.2: Observer Nodes

Learner nodes that replicate but don't vote:

```rust
pub struct RaftInitConfig {
    pub node_id: u64,
    pub db_path: PathBuf,
    pub cluster_nodes: Vec<u64>,
    pub is_observer: bool,           // NEW
    pub observer_tags: Vec<String>,   // NEW
}

impl RaftInstance {
    pub async fn add_learner(&self, node_id: u64, tags: Vec<String>) -> Result<(), ...> {
        self.raft.add_learner(node_id, (), false).await?;
    }
}
```

### W8.3: Genesis Membership

Auto-add Genesis-authorized nodes to Raft cluster:

```rust
pub struct PendingMembershipChange {
    pub node_id: u64,
    pub action: MembershipChangeAction,
    pub authorized_at: u64,
}

impl MeshTransport {
    pub async fn trigger_membership_change(&self, node_id_str: &str, action: MembershipChangeAction) {
        // If leader: call raft_instance.change_membership()
        // If not leader: queue for later processing
    }
}
```

### W8.4: Edge State Mirroring

Edge nodes mirror Raft state locally for O(1) lookups:

```rust
pub struct EdgeReplicaManager {
    db: Arc<Mutex<Connection>>,
    cache: moka::sync::Cache<String, Vec<u8>>,
}

impl EdgeReplicaManager {
    pub fn get_org_key(&self, org_id: &str) -> Option<OrgPublicKey>;
    pub fn get_threat_intel(&self, indicator_id: &str) -> Option<ThreatIntel>;
    pub fn update_from_notification(&self, notification: &RaftCommitNotification) -> Result<(), ...>;
}
```

### W8.6: YARA-X Binary Distribution

Global nodes serialize compiled YARA rules and distribute binary blobs to Edge nodes, eliminating Edge-side compilation overhead:

```rust
// Global node: compile and serialize
let compiled_rules = yara_x::Rules::serialize(&rules);
broadcast_to_edges(RuleAnnouncement { compiled_rules, ... });

// Edge node: deserialize directly (no compilation)
let rules = yara_x::Rules::deserialize(compiled_rules).unwrap();
```

**Benefits:**
- Edge nodes bypass YARA-X compilation (expensive at scale)
- Binary format is stable across versions (with version field)
- Fallback to source rules if deserialization fails

### Clippy Cleanup

The codebase maintains `-D warnings` clippy policy:

```bash
cargo clippy -- -D warnings
```

All new code must compile without clippy warnings. Common fixes:
- Use `.cloned()` instead of manual cloning
- Avoid unnecessary `.to_string()` conversions
- Use `Arc::clone()` for Arc reference counting

### W8.5: EdgeReplicaManager Test Coverage

The `EdgeReplicaManager` includes comprehensive error handling tests:

| Test | Purpose |
|------|---------|
| Disk full handling | Verifies graceful failure when SQLite returns `SQLITE_FULL` |
| Corrupted database | Tests recovery when DB checksum fails on open |
| Concurrent notification burst | Ensures cache/DB consistency under high-frequency updates |

Key test patterns:
```rust
#[test]
fn test_disk_full_handling() {
    // Simulate SQLITE_FULL by mocking disk operations
    // Verify EdgeReplicaManager returns meaningful error
}

#[test]
fn test_corrupted_db_recovery() {
    // Corrupt DB file, verify graceful degradation
    // Edge can still serve cached reads
}

#[test]
fn test_concurrent_notification_burst() {
    // Spawn multiple tasks updating same keys
    // Verify final state is consistent
}
```

### Fuzzing Targets

The fuzz directory (`fuzz/`) provides coverage-guided fuzzing for critical paths:

| Target | Purpose |
|--------|---------|
| `fuzz_attack_detection` | HTTP attack pattern parsing |
| `fuzz_ipc` | IPC message serialization |
| `fuzz_serialization` | Postcard round-trip fuzzing |
| `fuzz_serialization_new` | Extended serialization coverage |
| `fuzz_early_parse` | Early request parsing |
| `fuzz_protocol_proto_decode` | Mesh protocol decode |
| `fuzz_raft_response` | RaftResponse message decoding |
| `fuzz_raft_commit_notification` | RaftCommitNotification decoding |

Fuzz targets use `libfuzzer-sys` and integrate with `cargo-fuzz`:

```bash
cargo fuzz add fuzz_raft_types  # Add new target
cargo +nightly fuzz run fuzz_raft_types  # Run with corpus
```

## Verification Commands

```bash
# Build and test
cargo build
cargo test --lib

# Run integration tests
cargo test --test integration_test
```

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/raft/mod.rs` | Module exports and types |
| `crates/synvoid-mesh/src/mesh/raft/network.rs` | MeshRaftNetwork and Factory with full_snapshot() (W9.6) |
| `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | GlobalRegistryStateMachine, GlobalRegistryLogStorage, GlobalRegistryTypeConfig, LeaderCache (W9.4, W9.5) |
| `crates/synvoid-mesh/src/mesh/raft/client.rs` | RaftAwareClient with LeaderCache, linearizable reads (W9.3, W9.4) |
| `crates/synvoid-mesh/src/mesh/raft/instance.rs` | RaftInstance with raft_append_entries(), raft_vote(), install_snapshot() (W9.1, W9.6) |
| `crates/synvoid-mesh/src/mesh/raft/regression_tests.rs` | 33 regression tests for distributed control plane (W9.9) |
| `crates/synvoid-mesh/src/mesh/dht/signed.rs` | DhtRecordSignable canonical struct with SHA256 value hashing (W9.8) |
| `crates/synvoid-mesh/src/mesh/transport_dht.rs` | DHT auth default-deny, signature verification (W9.7) |
| `crates/synvoid-mesh/src/mesh/org_key_manager.rs` | Raft commit path in OrgKeyManager |
| `crates/synvoid-mesh/src/mesh/peer_auth.rs` | Dual verification (quorum OR Raft) |

## Wave 9 Changes Summary

| Task | Key Changes |
|------|-------------|
| W9.1 | request_id in RaftPayload, raft_append_entries/raft_vote methods, proper AppendEntries/VoteRequest dispatch |
| W9.2 | Response correlation with request_id, NotLeader handling with leader hints |
| W9.3 | Real linearizable reads via instance.read(), NotLeader error if not leader |
| W9.4 | LeaderCache (5s TTL), get_leader_id() uses raft.current_leader() |
| W9.5 | Full LogId metadata (term+index), membership persistence, explicit last_purged_log_id |
| W9.6 | full_snapshot() with 64KB chunks, SnapshotHeader/SnapshotChunk, install_snapshot() |
| W9.7 | Default-deny for missing signature/public key, URL_SAFE_NO_PAD base64 decode |
| W9.8 | DhtRecordSignable with SHA256 value_hash: key, value_hash, source, timestamp, ttl, sequence, record_type |
| W9.9 | 33 regression tests: signed records, pending leaks, DHT adversarial, Raft commands, edge replica |

## Wave 10 Changes Summary

| Task | Key Changes |
|------|-------------|
| W10.1 | Fixed double-encoding: `send_raw()` no longer wraps payload in another `MeshRaftPayload` and re-serializes |
| W10.2 | Added bounded 30s timeout to `send_message_to_peer_with_response()` in `transport.rs`. On timeout/error, stream NOT returned to pool to prevent poisoning |
| W10.3 | Added `raft_write_to_leader()` helper with one retry against hinted leader on `NotLeader`. Invalidates leader cache on redirect |
| W10.4 | Added `InProgressSnapshot` struct and `pending_snapshot_transfers` HashMap. `handle_raft_message()` handles `InstallSnapshot` header/chunks with offset validation |
| W10.5 | Canonical `DhtSnapshotResponseSignable` and `DhtSyncResponseSignable` with postcard serialization. Producer and verifier use same helpers |
| W10.6 | OpenRaft `get_read_linearizer(ReadPolicy::ReadIndex)` and `try_await_ready()` ensures reads are linearizable |
| W10.7 | Added `snapshot_install_tests` and `dht_snapshot_signable_tests` modules. Tests for InstallSnapshot header/chunk encode/decode, InProgressSnapshot chunk assembly |

## Key Files (Updated for Wave 10)

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/transport.rs` | `InProgressSnapshot` struct, `pending_snapshot_transfers` field, `send_message_to_peer_with_response()` with 30s timeout |
| `crates/synvoid-mesh/src/mesh/transport_peer.rs` | `handle_raft_message()` with `InstallSnapshot` handling, `InProgressSnapshot` chunk assembly and validation |
| `crates/synvoid-mesh/src/mesh/dht/signed.rs` | `DhtSnapshotResponseSignable`, `DhtSyncResponseSignable`, `get_snapshot_signable_content()`, `get_sync_signable_content()` |
| `crates/synvoid-mesh/src/mesh/dht/record_store_sync.rs` | Updated to use postcard-based signable content helpers |
| `crates/synvoid-mesh/src/mesh/transport_dht.rs` | Updated DHT signature verification to use postcard-based signable content |

## Wave 11 Changes Summary

| Task | Key Changes |
|------|-------------|
| W11.2 | Streaming binary snapshot format replacing JSON materialization. `streaming_serialize()` and `streaming_deserialize_and_apply()` on `GlobalRegistryStateMachine`. Peak memory reduced from ~2x to ~1x state size. Backward-compatible JSON fallback. |

### W11.2: Streaming Raft Snapshots

#### Problem

Previously, `build_snapshot()` called `get_all_entries()` which loaded ALL entries from SQLite into a `Vec<(Namespace, String, Vec<u8>)>`, then `serde_json::to_vec()` serialized them to another `Vec<u8>`. For a 1GB state machine, this meant ~2GB+ peak RAM usage during snapshot creation.

Similarly, `install_snapshot()` used `serde_json::from_slice()` which deserialized all entries into a Vec before inserting them to SQLite.

#### Solution

A streaming binary format that processes entries one at a time:

```
[MAGIC u32 0x53524D53 ("SRMS")]
[ENTRY_COUNT u64 LE]
[ENTRY_1_LEN u32 LE][postcard-serialized StreamingSnapshotEntry]
[ENTRY_2_LEN u32 LE][postcard-serialized StreamingSnapshotEntry]
...
```

Where `StreamingSnapshotEntry` is:
```rust
#[derive(Serialize, Deserialize)]
struct StreamingSnapshotEntry {
    ns: String,    // namespace string ("org", "intel", "revocation")
    key: String,
    val: Vec<u8>,
}
```

#### Key Methods

```rust
impl GlobalRegistryStateMachine {
    /// Serialize all state machine entries to Bytes, processing one SQLite row at a time.
    /// Never holds all entries in memory simultaneously.
    pub fn streaming_serialize(&self) -> io::Result<Bytes>;

    /// Deserialize and apply entries to the state machine, inserting one at a time.
    /// Falls back to JSON deserialization if magic number is absent (rolling upgrades).
    pub fn streaming_deserialize_and_apply(&self, data: &[u8]) -> io::Result<()>;
}
```

#### Backward Compatibility

The magic number `0x53524D53` is checked on deserialization. If absent, the data is assumed to be legacy JSON format and deserialized accordingly. This enables rolling upgrades where old nodes send JSON snapshots to new nodes.

#### Memory Profile

- **Before**: `get_all_entries()` (all entries Vec) + `serde_json::to_vec()` (serialized Vec) = ~2x state size
- **After**: Output buffer only, entries iterated one at a time from SQLite = ~1x state size
- Binary format also avoids JSON base64 encoding of binary values (~33% size reduction)

#### Tests

8 tests in `regression_tests::streaming_snapshot_tests`:
- Empty state round-trip
- Multi-namespace entry round-trip
- Magic number verification
- Entry count verification
- JSON fallback deserialization
- Data replacement on install
- 10K-entry large dataset
- Binary value (0x00-0xFF) preservation

## Wave 15: Raft Attestation Hardening (W15)

### SignedRaftAttestation V2 Protocol

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs`

V2 attestations bind to a specific DHT value via `value_hash`:

```rust
pub struct SignedRaftAttestation {
    pub attestation: RaftAttestation,
    pub signer_node_id: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub protocol_version: u32,  // v2: RAFT_ATTESTATION_PROTOCOL_VERSION = 2
}

pub struct RaftAttestation {
    pub leader_id: String,
    pub commit_index: u64,
    pub namespace: Namespace,
    pub key_id: String,
    pub timestamp: u64,
    pub value_hash: Option<Vec<u8>>,  // v2: binds attestation to value digest
}
```

V1 attestations without `value_hash` (protocol_version < 2) are **rejected by default**. Set `allow_v1_raft_attestations=true` in config to permit them during migration from V1 to V2. V2 attestations with `value_hash` continue to work normally.

### Envelope Signer-to-Node Binding

Envelope signer-to-node binding is enforced for all signed DHT message types on global nodes via `verify_envelope_signer_binding()`. This verifies the public key used to sign an envelope belongs to the claimed sender node.

**Applies to**: `DhtSyncRequest`, `DhtSyncResponse`, `DhtAntiEntropyRequest`, `DhtAntiEntropyResponse`, `DhtRecordPush`.

**Mechanism**: `NodePublicKeyResolver` trait provides pluggable key resolution. Called via `MeshTransport::verify_signer_node_binding()` during message processing on global nodes.