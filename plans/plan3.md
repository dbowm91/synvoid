# Improvement Plan: Mesh and DHT Subsystems (plan3.md)

This plan outlines strategic improvements to the MaluWAF mesh and DHT implementation to enhance architecture, scalability, robustness, and security. The core principle is a multi-tier network where Global nodes act as the primary trust root and CA, while Edge and Origin nodes provide distributed services and proxying.

---

## 1. Objectives

- **Refine Node Roles**: Formalize role-based capabilities, ensuring DNS server functionality is restricted to Global nodes.
- **Strengthen Security Model**: Enhance the Global-as-CA attestation for all node types, particularly third-party Edge nodes.
- **Optimize Scalability**: Improve hierarchical routing and DHT sharding for larger network sizes.
- **Increase Robustness**: Implement more sophisticated reputation-based gating and adaptive quorum mechanisms.

---

## 2. Architecture & Role Improvements

### 2.1 Capability-Based Enforcement
- **Global-Only DNS**: Update `MeshTransport` and `DnsRegistry` to strictly verify the `GLOBAL` role flag before responding to anycast registration or zone sync requests.
- **Multi-Role Flexibility**: Ensure that a node carrying `EDGE | ORIGIN` can proxy through the mesh to multiple origin services while simultaneously serving as an edge caching point.
- **Global-as-CA**: Extend the `MeshCertManager` to handle delegation, allowing Global nodes to issue short-lived "Capability Certificates" to Edge/Origin nodes for specific operations (e.g., temporary DHT write access for health stats).

### 2.2 Organization & Tier Key Management
- **Hierarchical Trust**: Formalize the relationship between `GENESIS_ORG` and other organizations. Only Genesis-signed organizations should be able to manage Global nodes.
- **Tier Key Scoping**: Improve `TierKey` scoping to restrict their use to specific geographic regions or mesh IDs, preventing key reuse across unrelated partitions of the network.

---

## 3. Scalability & Routing Optimizations

### 3.1 Hierarchical Routing (Kademlia-based)
- **Regional Hub Optimization**: Improve the `RegionalHub` selection logic to use latency-based clustering instead of just geographic distance.
- **Bloom Filter Routing**: Implement the `MeshBloomFilter` for `HierarchicalRoutingManager` to allow nodes to quickly determine if a service is reachable within their regional hub without a full DHT lookup.

### 3.2 DHT Performance
- **Adaptive Sharding**: Transition the `ShardedRecordStore` to dynamic sharding that adjusts based on the number of active records.
- **Hot-Key Mitigation**: Implement proactive replication for frequently accessed ("hot") public DHT records across a wider set of Edge caches.

---

## 4. Robustness & Reputation Enhancements

### 4.1 Advanced Reputation System
- **Proof-of-Uptime**: Award reputation based on continuous, verified uptime via periodic heartbeats to Global nodes.
- **Sybil Resistance**: Integrate the `validate_edge_node_pow` (Proof of Work) more deeply into the connection lifecycle, requiring periodic PoW refreshes for Edge nodes that want to maintain high-reputation status.
- **Slash Events**: Implement a system for Global nodes to broadcast `SlashEvent` messages when an Edge node is detected providing malicious data, leading to immediate network-wide revocation.

### 4.2 Adaptive Quorum Mechanisms
- **Weighted Quorums**: Adjust quorum requirements based on node reputation. Higher-reputation Global nodes could carry more "weight" in a write operation.
- **Degraded Quorum Safety**: Formalize the `enable_degraded_quorum` logic to ensure it only activates when a significant portion of the network is unreachable (Network Partitioning), preventing split-brain scenarios.

---

## 5. Security Model Hardening

### 5.1 Attestation & Identity
- **Hardware-Backed Identity**: If available, support for TPM/Secure Enclave based identity for Global nodes.
- **Origin Attestation Refresh**: Implement mandatory periodic refreshing of `global_node_attestation_sig` for Origin nodes to ensure they remain in good standing with the Global tier.

### 5.2 DHT Access Control
- **Strict Key Prefixing**: Audit and enforce strict key prefixes in `DhtAccessControl`. Prevent any Edge node from writing to prefixes reserved for Global node metadata, even if they have high reputation.
- **Value Encryption**: Implement mandatory encryption for sensitive DHT values using `TierKeyEncryption` (e.g., specific upstream URLs that should only be visible to authenticated Edge nodes in the same organization).

---

## 6. Implementation Phases

1.  **Phase 1: Security & Attestation (Audit/Fixes)**:
    - Audit `DhtAccessControl` and `peer_auth.rs`.
    - Ensure DNS restrictions are fully enforced in `MeshTransport`.
2.  **Phase 2: Reputation & Robustness**:
    - Implement `SlashEvent` and PoW periodic refreshes.
    - Refine the adaptive sync intervals in `RecordStoreManager`.
3.  **Phase 3: Scalability & Routing**:
    - Optimize `RegionalHub` selection.
    - Implement `MeshBloomFilter` for service discovery.
4.  **Phase 4: Multi-Role Integration**:
    - Finalize support for simultaneous `EDGE | ORIGIN` roles with proper capability gating.

---

## 7. Verification Strategy

- **Simulated Partition Testing**: Use a test runner to simulate network partitions and verify that DHT consistency is maintained.
- **Reputation Attack Scenarios**: Simulate "Bad Actor" Edge nodes and verify they are correctly slashed and revoked.
- **Scalability Benchmarks**: Measure lookup latency as the number of nodes in the regional hub increases.
- **Role Validation**: Verify that a node without the `GLOBAL` bit set cannot register as a DNS anycast node or store privileged DHT records.
