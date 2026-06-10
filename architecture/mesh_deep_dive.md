# SynVoid Mesh & P2P Networking

The SynVoid Mesh is an experimental peer-to-peer network layer designed to transform individual WAF instances into a collective, distributed defense system. It enables multiple WAF nodes to share threat intelligence, distribute DDoS load, and coordinate security policies in real-time.

## Network Topology

The mesh follows a hierarchical structure inspired by decentralized networks but optimized for low-latency security operations.

- **Global Nodes (Authorities):** A small set of trusted nodes that maintain the canonical Raft cluster. They commit authoritative records (OrgPublicKey, ThreatIntel, GlobalNodeRevocationList) via Raft consensus. Global nodes also participate in DHT for broader record distribution, but DHT is advisory only — Raft is the source of truth for trust and ownership.
- **Edge Nodes (WAFs):** Standard WAF instances that connect to Global nodes for discovery and to other Edge nodes for data exchange. Edge nodes cache and gossip Raft-derived artifacts but independently verify them.
- **Origin Nodes:** WAFs that are directly connected to upstream application servers. They announce routes for their protected services through the mesh.

## Core Technologies

### 1. QUIC Transport
All mesh communication happens over QUIC. This provides:
- **Native Multiplexing:** Multiple streams (threat intel, proxying, heartbeats) can coexist on a single connection without Head-of-Line blocking.
- **Low Latency:** 0-RTT handshakes for rapid reconnection (disabled by default due to replay attack concerns — see `crates/synvoid-mesh/src/mesh/config.rs:1391-1392` for configuration).
- **Encryption:** Mandatory TLS 1.3 encryption for all traffic.

### 2. Post-Quantum Cryptography (PQC)
SynVoid Mesh is designed for future-proof security, utilizing hybrid key exchange:
- **ML-KEM (Kyber):** For quantum-resistant key encapsulation.
- **ML-DSA (Dilithium):** For quantum-resistant digital signatures.
- **Hybrid Approach:** Combines PQC with classical algorithms (X25519/Ed25519) to ensure security even if one algorithm is compromised.

### 3. Distributed Discovery (DHT)
Peer and service discovery are handled via a Kademlia-based **Distributed Hash Table (DHT)**.
- **Signed/Raft-Attested Records**: DHT distributes signed or Raft-attested records. DHT does not decide trust, ownership, revocation, or global policy — it is a transport layer for record distribution.
- **Capability Attestations:** Nodes sign and publish their capabilities (e.g., "I can proxy example.com") to the DHT. These records are soft-state: advisory and TTL-bound.
- **Authority-Adjacent Records**: Records in sensitive namespaces (org keys, verified upstreams) require a signed Raft attestation or quorum proof for acceptance.
- **Hierarchical Routing:** [RESERVED/PLANNED] Future multi-region topology feature using Bloom filters and regional hubs for memory-efficient route announcement checking. Not yet active. See [`hierarchical_routing.rs`](crates/synvoid-mesh/src/mesh/hierarchical_routing.rs) for implementation details.

### 4. Raft Consensus
Global nodes use Raft consensus (`crates/synvoid-mesh/src/mesh/raft/*.rs`) for **canonical global authority**:
- **Leader Election:** Global nodes elect a leader to coordinate state changes.
- **Log Replication:** Authority records are replicated across Global nodes via Raft log.
- **Quorum Requirements:** Write operations require quorum (2/3) of Global nodes.
- **Canonical Authority:** Raft commits are the single source of truth for OrgPublicKey, ThreatIntel, and GlobalNodeRevocationList. DHT records for these namespaces are derived from Raft commits, not created independently.
- **Note:** Quorum deadlock risk during network partition (see MESH-15).

See `architecture/mesh_trust_domains.md` for the advisory vs. canonical distinction and trust-domain invariants. See `CanonicalTrustReader` in `crates/synvoid-mesh/src/mesh/canonical.rs` (Iteration 8) and `architecture/mesh_trust_domains.md`.

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

The `MeshProxy` (`crates/synvoid-mesh/src/mesh/proxy.rs`) is the central routing component for mesh proxying:

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

- **Peer Authentication:** Mesh TLS supports `strict`, `tofu`, and `permissive` modes. Strict mode requires CA-backed validation, TOFU can pin first-seen fingerprints, and permissive mode accepts peers without CA validation. Transport also enforces node-ID binding for DHT sync and anti-entropy traffic.
- **Audit Logs:** The mesh includes a distributed auditing system (`crates/synvoid-mesh/src/mesh/audit.rs`) to track network events and detect malicious or misconfigured peers.
- **Access Control:** Fine-grained policies control which nodes can proxy which services (see [`CapabilityAccessVerifier`](crates/synvoid-mesh/src/mesh/dht/capability_access.rs:7) in `crates/synvoid-mesh/src/mesh/dht/capability_access.rs`).

### Current DHT Verification Split

All DHT message types are now fully verified. The transport layer enforces node-ID binding, envelope signature verification, signer-to-node binding, and signer identity validation for every message path on global nodes. Unsigned messages are rejected by default; optional compatibility windows are config-controlled and off by default.

| Message Type | Envelope Sig | Signer Binding | Per-Record Ingress | Details |
|--------------|-------------|----------------|--------------------|---------|
| `DhtRecordAnnounce` | ✅ | ✅ | ✅ | Peer binding and message signature enforced before record ingestion |
| `DhtSnapshotRequest` | ✅ | ✅ | — | Signature required; rate-limited and stake-checked |
| `DhtSnapshotResponse` | ✅ | ✅ | ✅ | Signature and timestamp checked before snapshot apply |
| `DhtSyncRequest` | ✅ | ✅ | — | Signed requests verified; unsigned compatibility fallback is config-controlled and off by default |
| `DhtSyncResponse` | ✅ | ✅ | ✅ | Signed: signature + signer-to-node binding + record-set digest verified. Unsigned compat: still stores via `store_record_from_ingress()` with `envelope_signature_valid=false` |
| `DhtAntiEntropyRequest` | ✅ | ✅ | — | Envelope signature verified; `signer_public_key` validated against authorized global node keys; signer-to-node binding enforced |
| `DhtAntiEntropyResponse` | ✅ | ✅ | ✅ | Envelope signature verified; record set digest recomputed and tampered sets rejected |
| `DhtRecordPush` | ✅ | ✅ | ✅ | Envelope signature required; signer-to-node binding enforced; records without valid signatures rejected |

**Four-layer verification** (applied to all remote DHT writes on global nodes):

1. **Timestamp window** — messages outside acceptable time range are rejected
2. **Envelope signature** — proves sender possesses the private key
3. **Signer-to-node binding** (`verify_envelope_signer_binding()`) — the signing key belongs to the claimed node ID
4. **Per-record ingress validation** (`store_record_from_ingress()`) — key-family policy, per-record signature, quorum proof, and freshness checks

**Design notes:**
- All DHT communication requires TLS 1.3 encryption (transport layer)
- Global nodes use Raft consensus for canonical authority, providing implicit authority for committed records
- Authority-adjacent DHT records (org keys, verified upstreams) require signed Raft attestation or quorum proof
- Reputation systems and audit logs help detect anomalous behavior
- Deprecated quorum/commit message types (`DhtRecordCommit`, `QuorumStoreRequest`, `QuorumSignatureResp`) were removed from the protocol; older docs that mention them are stale.

---

## State Ownership Table

The following table clarifies which subsystem owns each category of mesh state. This boundary is enforced at the code level — DHT cannot create authority records independently, and Raft does not manage soft-state record distribution.

| State Category | Owner | Storage | Consistency | Notes |
|----------------|-------|---------|-------------|-------|
| **OrgPublicKey** | Raft | `GlobalRegistryStateMachine` | Linearizable | Canonical authority. DHT copies are derived from Raft commits. |
| **ThreatIntel** | Raft | `GlobalRegistryStateMachine` | Linearizable | Canonical authority. Published to DHT for broader distribution. |
| **GlobalNodeRevocationList** | Raft | `GlobalRegistryStateMachine` | Linearizable | Also distributed via DHT for fast local revocation checks. |
| **AuthorizedGlobalNodes** | Raft | `GlobalRegistryStateMachine` | Linearizable | Node admission requires Raft consensus. |
| **Routing policies** | DHT | `RecordStoreManager` | Eventual | Advisory, TTL-bound. Signed by originating node. |
| **Provider info** | DHT | `RecordStoreManager` | Eventual | Advisory, TTL-bound. Announced via `DhtRecordAnnounce`. |
| **Capability attestations** | DHT | `RecordStoreManager` | Eventual | Soft-state. Signed by the attesting node. |
| **DNS zone ownership** | Raft/Quorum | `RecordStoreManager` | Eventual (proof-gated) | Raft or quorum attestation required; not mutable through remote DHT writes. |
| **DNS records** | DHT | `RecordStoreManager` | Eventual | Per-tenant zone ownership. Capability-attested with DNS capability. TTL-bound. |
| **YARA rules** | DHT | `RecordStoreManager` | Eventual | Signed by global nodes. Content-addressed keys. |
| **Tier keys** | Local | In-process memory | N/A | Derived from org keys; never stored in DHT. |
| **Peer reputation** | Local | In-process memory | N/A | Per-node behavioral scoring. Not distributed. |
| **Behavioral fingerprints** | Local | In-process memory | N/A | Per-peer. Shared via mesh only when explicitly propagated. |
| **TLS certificates** | Local | `MeshCertManager` | N/A | Node identity. Pinned fingerprints for verification. |
| **Session state (KEM)** | Local | `SessionManager` | N/A | Ephemeral key exchange sessions. |

### Boundary Rules

1. **Raft is the only canonical authority source.** DHT cannot independently create, modify, or revoke authority records (OrgPublicKey, ThreatIntel, GlobalNodeRevocationList, AuthorizedGlobalNodes).

2. **DHT records are soft-state.** All DHT records are advisory, TTL-bound, and subject to eviction. They never override Raft-committed state.

3. **Authority-adjacent DHT records require proof.** Records in sensitive namespaces (e.g., org keys, verified upstreams) require a signed Raft attestation or quorum proof for acceptance by receiving nodes.

4. **Edge nodes verify independently.** Edge nodes cache Raft-derived artifacts (via `EdgeReplicaManager`) and gossip them to peers, but independently verify signatures against the Raft state machine before accepting them.

5. **Remote DHT writes require ingress validation.** All remote DHT writes (sync, anti-entropy, record push) undergo four-layer verification: timestamp window, envelope signature, signer-to-node binding, and per-record ingress validation via `store_record_from_ingress()`. Unsigned messages are rejected by default; optional compatibility windows are config-controlled, off by default, and still enforce per-record ingress validation.

6. **Low-level store access is restricted.** Raw `store_record()` is `pub(crate)`; remote paths must use `store_record_from_ingress()` which enforces key-policy and proof requirements. Local creation uses `store_local_record()` which always sets `is_local_origin = true`.
