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
- **Low Latency:** 0-RTT handshakes for rapid reconnection.
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

## Security & Integrity

- **Peer Authentication:** All nodes must have a valid certificate signed by an authorized Organization Key (see [`validate_member_certificate`](src/mesh/peer_auth.rs:141) in `src/mesh/peer_auth.rs`).
- **Audit Logs:** The mesh includes a distributed auditing system (`audit.rs`) to track network events and detect malicious or misconfigured peers.
- **Access Control:** Fine-grained policies control which nodes can proxy which services (see [`CapabilityAccessVerifier`](src/mesh/dht/capability_access.rs:7) in `src/mesh/dht/capability_access.rs`).
