# Raft Consensus for Global Control Plane

## Overview

Wave 6 implemented Raft consensus for the MaluWAF Global Control Plane, replacing the previous quorum-based signature approach that required 2/3 of Global nodes to manually sign records.

## Architecture

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `MeshRaftNetwork` | `src/mesh/raft/network.rs` | Implements `RaftNetworkV2` trait, wraps `MeshBackendPool` |
| `MeshRaftNetworkFactory` | `src/mesh/raft/network.rs` | Creates `MeshRaftNetwork` instances per target |
| `GlobalRegistryStateMachine` | `src/mesh/raft/state_machine.rs` | RaftStateMachine impl using rusqlite |
| `GlobalRegistryLogStorage` | `src/mesh/raft/state_machine.rs` | RaftLogStorage impl for log persistence |
| `RaftAwareClient` | `src/mesh/raft/client.rs` | ConsistentRead RPC for Edge/Origin nodes |
| `RaftCommitNotification` | `src/mesh/raft/mod.rs` | Leader commit broadcast message |

### Namespaces

The Raft state machine organizes data by namespace:

```rust
pub enum Namespace {
    Org,        // Organization public keys
    Intel,      // Threat intelligence indicators
    Revocation, // Global node revocation list
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
    // append_entries, vote, full_snapshot methods
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
| `src/mesh/raft/state_machine.rs` | GlobalRegistryStateMachine and LogStorage |
| `src/mesh/raft/client.rs` | RaftAwareClient for Edge/Origin |
| `src/mesh/org_key_manager.rs` | Raft commit path in OrgKeyManager |
| `src/mesh/peer_auth.rs` | Dual verification (quorum OR Raft) |