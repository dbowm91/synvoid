# SynVoid Mesh & P2P Networking

The SynVoid Mesh is an experimental peer-to-peer network layer designed to transform individual WAF instances into a collective, distributed defense system. It enables multiple WAF nodes to share threat intelligence, distribute DDoS load, and coordinate security policies in real-time.

## Network Topology

The mesh follows a hierarchical structure inspired by decentralized networks but optimized for low-latency security operations.

- **Global Nodes (Authorities):** A small set of trusted nodes that act as directory authorities. They maintain a full map of the network and handle peer admission using **Raft consensus** for state consistency.
- **Edge Nodes (WAFs):** Standard WAF instances that connect to Global nodes for discovery and to other Edge nodes for data exchange.
- **Origin Nodes:** WAFs that are directly connected to upstream application servers. They announce routes for their protected services through the mesh.

## Core Technologies

### 1. QUIC Transport
All mesh communication happens over QUIC. This provides:
- **Native Multiplexing:** Multiple streams (threat intel, proxying, heartbeats) can coexist on a single connection without Head-of-Line blocking.
- **Low Latency:** 0-RTT handshakes for rapid reconnection (disabled by default due to replay attack concerns — see `src/mesh/config.rs:1391-1392` for configuration).
- **Encryption:** Mandatory TLS 1.3 encryption for all traffic.

### 2. Post-Quantum Cryptography (PQC)
SynVoid Mesh is designed for future-proof security, utilizing hybrid key exchange:
- **ML-KEM (Kyber):** For quantum-resistant key encapsulation.
- **ML-DSA (Dilithium):** For quantum-resistant digital signatures.
- **Hybrid Approach:** Combines PQC with classical algorithms (X25519/Ed25519) to ensure security even if one algorithm is compromised.

### 3. Distributed Discovery (DHT)
Peer and service discovery are handled via a Kademlia-based **Distributed Hash Table (DHT)**.
- **Capability Attestations:** Nodes sign and publish their capabilities (e.g., "I can proxy example.com") to the DHT.
- **Hierarchical Routing:** Uses Bloom filters and regional hubs to enable memory-efficient route announcement checking in large-scale networks, not to minimize DHT discovery latency. Bloom filters check if a route advertisement has been seen before (via `MeshBloomFilter` in `src/mesh/hierarchical_routing.rs:66`), reducing redundant route propagation.

### 4. Raft Consensus
Global nodes use Raft consensus (`src/mesh/raft/*.rs`) for state consistency:
- **Leader Election:** Global nodes elect a leader to coordinate state changes
- **Log Replication:** State changes are replicated across Global nodes via Raft log
- **Quorum Requirements:** Write operations require quorum (2/3) of Global nodes
- **Note:** Quorum deadlock risk during network partition (see MESH-15)

---

## Collective Defense Features

### 1. Threat Intelligence Sharing
When an Edge node detects a sophisticated attack or a high-volume flood, it broadcasts a **Threat Indicator** to the mesh.
- **Reputation System:** Nodes maintain reputation scores for their peers. Indicators from high-reputation nodes are propagated faster and trusted more.
- **Shared Blocklists:** Real-time synchronization of malicious IP addresses across the entire cluster.

### 2. Distributed DDoS Mitigation
By using the mesh as a P2P CDN, a targeted site can distribute its incoming load across many "scrubbing" Edge nodes.
- **Mesh Proxying:** Traffic for a site can be accepted at any Edge node and routed through the mesh to the node closest to the origin.
- **Load Balancing:** The mesh topology aware router selects the best path based on latency and node health.

### 3. Collaborative Bot Detection
The mesh allows nodes to share behavioral fingerprints of suspected bots.
- **Sequence Entropy:** Nodes share statistical models of request sequences to identify automated behavior across different PoPs.
- **YARA Rule Distribution:** New security rules can be distributed globally across the mesh in seconds.

---

## MeshProxy Component

The `MeshProxy` (`src/mesh/proxy.rs:62-78`, 1994 lines total) is the central routing component for mesh proxying:

- **Proxy Cache:** Caches proxy decisions to reduce latency for repeated requests to the same destination
- **Connection Management:** Tracks active connections via `active_connections: DashMap<String, MeshConnection>`
- **Policy Caching:** Uses `Cache<String, CachedPolicy>` for routing policy decisions
- **Failed Provider Tracking:** Tracks failed providers to avoid routing to unhealthy nodes
- **Provider Statistics:** Maintains per-provider stats via `DashMap<String, ProviderStats>`
- **Organization Management:** `OrganizationManager` handles org-level configuration and policies
- **Transform Cache:** `TieredTransformCache` for efficient data transformation

MeshProxy is the critical routing component that coordinates mesh traffic between Edge nodes and Origin nodes.

---

## Security & Integrity

- **Peer Authentication:** All nodes must have a valid certificate signed by an authorized Organization Key (see [`validate_member_certificate`](src/mesh/peer_auth.rs:141) in `src/mesh/peer_auth.rs`).
- **Audit Logs:** The mesh includes a distributed auditing system (`src/mesh/audit.rs`) to track network events and detect malicious or misconfigured peers.
- **Access Control:** Fine-grained policies control which nodes can proxy which services (see [`CapabilityAccessVerifier`](src/mesh/dht/capability_access.rs:7) in `src/mesh/dht/capability_access.rs`).

### Known DHT Verification Limitations

The DHT ingress path implements a multi-layer identity hierarchy (L1: peer_id/TLS cert → L2: envelope signer → L3: record signer → L4: source_node_id → L5: quorum signer), but certain message types have architectural verification gaps that are documented in [`src/mesh/dht/signed.rs:42-48`](src/mesh/dht/signed.rs:42-48):

| Message Type | Verification Status | Gap Description |
|--------------|---------------------|-----------------|
| `DhtRecordAnnounce` | ✅ Full | Timestamp, role, envelope, record, and binding verification |
| `DhtSyncRequest` | ❌ None | No node_id or TLS certificate validation |
| `DhtSyncResponse` | ✅ Full | Timestamp, envelope, record, and binding verification |
| `DhtAntiEntropyRequest` | ⚠️ Partial | `signer_public_key` field is unused in verification |
| `DhtAntiEntropyResponse` | ✅ Full | Timestamp, envelope, record, and binding verification |
| `DhtRecordPush` | ⚠️ Partial | Record verified but timestamp ignored, no envelope signature |
| `DhtRecordCommit` | ⚠️ Partial | Timestamp and record verified, but no envelope signature validation |
| `QuorumStoreRequest` | ❌ None | No verification performed |
| `QuorumSignatureResp` | ❌ None | No verification performed |

**Mitigating Factors:**
- All DHT communication requires TLS 1.3 encryption (transport layer)
- Global nodes use Raft consensus for state consistency, providing implicit authority
- Reputation systems and audit logs help detect anomalous behavior
- Edge nodes require valid certificates signed by authorized Organization Keys

These limitations are known architectural constraints. Future revisions may address gaps based on threat model evolution and performance requirements.
