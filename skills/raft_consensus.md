# Raft Consensus for Global Control Plane

## Overview

Wave 6-7 implemented Raft consensus for the MaluWAF Global Control Plane, replacing the previous quorum-based signature approach that required 2/3 of Global nodes to manually sign records.

## Architecture

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `MeshRaftNetwork` | `src/mesh/raft/network.rs` | Implements `RaftNetworkV2` trait, wraps `MeshBackendPool` |
| `MeshRaftNetworkFactory` | `src/mesh/raft/network.rs` | Creates `MeshRaftNetwork` instances per target |
| `GlobalRegistryStateMachine` | `src/mesh/raft/state_machine.rs` | RaftStateMachine impl using rusqlite |
| `GlobalRegistryLogStorage` | `src/mesh/raft/state_machine.rs` | RaftLogStorage impl for log persistence |
| `GlobalRegistryTypeConfig` | `src/mesh/raft/state_machine.rs` | RaftTypeConfig impl for GlobalRegistry |
| `RaftInstance` | `src/mesh/raft/instance.rs` | Wraps openraft::Raft with lifecycle management |
| `RaftAwareClient` | `src/mesh/raft/client.rs` | ConsistentRead RPC for Edge/Origin nodes |
| `RaftSnapshotManager` | `src/mesh/raft/instance.rs` | Point-in-time snapshots using rusqlite backup API |

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
    type SnapshotData = Cursor<Vec<u8>>;            // In-memory snapshot
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
}

impl RaftInstance {
    pub async fn new(...) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
    pub async fn initialize(&self, cluster_nodes: Vec<u64>) -> Result<(), ...>;
    pub async fn add_node(&self, node_id: u64) -> Result<(), ...>;
    pub async fn remove_node(&self, node_id: u64) -> Result<(), ...>;
    pub async fn client_write(&self, command: RaftCommand) -> Result<u64, ...>;
    pub async fn is_leader(&self) -> bool;
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<u64, ...>;
}
```

## Client Write Correction (W7.4)

The RaftAwareClient now uses `client_write()` instead of raw `AppendEntries`:

```rust
impl RaftAwareClient {
    pub async fn raft_write_local(&self, namespace: Namespace, key: String, value: Vec<u8>) -> Result<u64, RaftAwareClientError> {
        let command = RaftCommand::Set { namespace, key, value };
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
    async fn begin_receiving_snapshot(&mut self) -> Result<Cursor<Vec<u8>>, io::Error>;
    async fn install_snapshot(&mut self, meta: &SnapshotMetaOf<GlobalRegistryTypeConfig>, snapshot: Cursor<Vec<u8>>) -> Result<(), io::Error>;
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
| `src/mesh/raft/mod.rs` | Module exports and types |
| `src/mesh/raft/network.rs` | MeshRaftNetwork and Factory |
| `src/mesh/raft/state_machine.rs` | GlobalRegistryStateMachine, GlobalRegistryLogStorage, GlobalRegistryTypeConfig |
| `src/mesh/raft/client.rs` | RaftAwareClient for Edge/Origin |
| `src/mesh/raft/instance.rs` | RaftInstance and RaftSnapshotManager |
| `src/mesh/org_key_manager.rs` | Raft commit path in OrgKeyManager |
| `src/mesh/peer_auth.rs` | Dual verification (quorum OR Raft) |