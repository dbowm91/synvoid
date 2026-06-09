# Mesh Consensus Boundary Notes

> Created by IFACE-C01 during interface-pass modularization.

## 1. Current coupling between Raft network and mesh transport

The Raft consensus layer is tightly coupled to the mesh transport layer:

- `src/mesh/raft/` contains the Raft consensus implementation
- `src/mesh/transport.rs` and `src/mesh/transports/` contain the mesh networking transport
- Raft directly uses mesh transport for peer communication (AppendEntries, InstallSnapshot, Vote RPCs)
- The mesh transport handles DHT operations, peer discovery, and Raft message routing
- Both share the same `MeshNode` identity, TLS configuration, and peer management

## 2. Which transport operations Raft actually needs

From analyzing `src/mesh/raft/`, Raft uses these transport operations:

- **Send AppendEntries** to a peer (with log entries)
- **Send InstallSnapshot** to a peer (with snapshot data)
- **Send Vote** request/response to a peer
- **Receive messages** from peers (via channels or callbacks)
- **Peer health checking** (is peer reachable?)

These are essentially: send a typed message to a peer ID, and receive messages from peers.

## 3. Candidate future trait: ConsensusTransport

```rust
pub trait ConsensusTransport: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn send_append_entries(
        &self,
        peer: PeerId,
        entries: Vec<LogEntry>,
        commit_index: u64,
    ) -> Result<AppendEntriesResponse, Self::Error>;

    async fn send_install_snapshot(
        &self,
        peer: PeerId,
        snapshot: Snapshot,
    ) -> Result<InstallSnapshotResponse, Self::Error>;

    async fn send_vote(
        &self,
        peer: PeerId,
        request: VoteRequest,
    ) -> Result<VoteResponse, Self::Error>;

    fn is_peer_alive(&self, peer: &PeerId) -> bool;
}
```

## 4. Why synvoid-consensus should not be extracted yet

- The Raft implementation directly uses mesh-specific types (MeshNodeId, mesh transport channels)
- Log entries and snapshots may contain mesh-specific serialization formats
- Peer discovery and health checking are mesh transport concerns that Raft depends on
- The boundary between "consensus logic" and "transport" is not clean — Raft needs to know about peer reachability, which is a transport concern
- Extracting consensus would require defining a transport trait that both mesh and any future consensus implementation agree on — this needs more real-world validation first

## 5. Recommendation

Keep Raft inside `synvoid-mesh` for now. The internal `ConsensusTransport` trait (IFACE-C02) can be defined as a first step toward eventual separation, but actual extraction should wait until:
1. The trait has been proven with at least one alternative transport implementation
2. The log entry and snapshot types are fully decoupled from mesh-specific formats
3. Peer discovery is separated from consensus routing

## 6. Raft vs DHT Ownership Boundary

The hardened boundary between Raft and DHT is as follows:

- **Raft commits canonical global authority records.** `OrgPublicKey`, `ThreatIntel`, `GlobalNodeRevocationList`, and `AuthorizedGlobalNodes` are committed via Raft consensus. Raft is the single source of truth for trust, ownership, revocation, and global policy.

- **DHT distributes signed or Raft-attested records.** DHT provides eventual-consistency record distribution for routing policies, provider info, DNS records, capability attestations, and YARA rules. DHT does not decide trust, ownership, revocation, or global policy.

- **DHT records are soft-state.** All DHT records are advisory and TTL-bound. They never override Raft-committed state.

- **Authority-adjacent DHT records require signed proof.** Records in sensitive namespaces (org keys, verified upstreams) require a signed Raft attestation or quorum proof for acceptance.

- **Edge nodes cache and gossip Raft-derived artifacts but independently verify them.** `EdgeReplicaManager` caches Raft state machine snapshots locally; receiving nodes verify signatures against the Raft state machine before accepting cached records.

- **Remote DHT writes require explicit ingress validation.** `DhtAntiEntropyRequest` and `DhtRecordPush` are fully signed/bound at the transport layer.
