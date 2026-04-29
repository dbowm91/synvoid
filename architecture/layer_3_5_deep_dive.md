# Architectural Deep Dive: Layers 3 & 5 (Proxy & Mesh)

This document provides an in-depth review of MaluWAF's Layer 3 (Proxy & Routing) and Layer 5 (Mesh & Distributed Systems), focusing on Post-Quantum Cryptography (PQC), Dependency Alignment, Trust Models, and the complexities of peer-to-peer (P2P) communication.

## 1. Post-Quantum Cryptography (PQC) Support

**Are we supporting PQC fully?**
Yes, MaluWAF is exceptionally forward-looking in its PQC implementation. It achieves "Quantum-Ready" status across both the data plane (Layer 3) and the control plane (Layer 5):

*   **Layer 3 (TLS & Proxy):** Uses the `rustls` crate with the `aws-lc-rs` backend and the `prefer-post-quantum` configuration flag. This enables hybrid key exchange algorithms (e.g., X25519Kyber768Draft00 or X25519MLKEM768) during TLS 1.3 handshakes for incoming client traffic.
*   **Layer 5 (Mesh Control Plane):** 
    *   **Key Exchange (KEM):** Implements ML-KEM-768 for securing QUIC tunnels between mesh nodes (`MlKemKeyExchangeService`).
    *   **Authentication (DSA):** Uses `libcrux` for ML-DSA-44. Crucially, it employs a **Hybrid Signature Scheme** (`MeshHybridSigner`) that concatenates an Ed25519 signature (64 bytes) with an ML-DSA-44 signature (2420 bytes). This fail-safe approach ensures that if the new PQC algorithm is broken mathematically, the classical Ed25519 signature still holds.

## 2. Dependency Alignment & Safety

**Are dependencies aligned and safe with sane overlap?**
The dependency tree is generally well-aligned around the modern Rust async ecosystem (`tokio`, `hyper`, `axum`, `rustls`). 

*   **Non-Pure Rust Dependencies:** `aws-lc-rs` (AWS's fork of BoringSSL) is the primary heavy C/Assembly dependency, which is necessary for production-grade, audited PQC primitives. However, it is **not** the only non-pure Rust dependency. `rusqlite` brings in SQLite (C), and `yara-x` depends on `wasmtime` (which has complex system-level integrations). 
*   **Security Posture:** The project proactively patches transitive vulnerabilities (e.g., patching `wasmtime` to `v42.0.2` in `Cargo.toml` to mitigate RUSTSEC-2026-0096).
*   **Overlap:** There is minimal ecosystem overlap. `rustls` is strictly used instead of `openssl`, avoiding dependency conflicts. 

## 3. Mesh Complexity & Maintenance

**Is peer communication/DHT overly complex? Is there room for simplification?**
Yes, the mesh layer (`Layer 5`) is **highly complex** and represents the greatest long-term maintenance risk.

*   **Current Architecture:** It uses a custom Kademlia-style DHT (`ShardedRecordStore`) over QUIC for peer discovery, threat intelligence sharing, and dynamic routing, combined with a custom PKI trust chain and PQC handshakes.
*   **The Issue:** Maintaining state consistency and preventing split-brain scenarios in a high-churn, globally distributed Kademlia DHT is notoriously difficult. Custom cryptographic wrappers over QUIC streams increase the surface area for logic bugs compared to standard mTLS.
*   **Room for Simplification:**
    1.  **Separate Control and Data Planes:** Instead of using a flat Kademlia DHT for everything, the Global nodes could run a proven consensus protocol (like `Raft` via the `async-raft` or `openraft` crates) to maintain the single source of truth for routing and threat intel.
    2.  **Standardize mTLS:** Edge and Origin nodes could simply connect to Global nodes using standard TLS 1.3 mTLS (with PQC enabled) rather than custom KEM handshake protocols over raw QUIC streams.

## 4. The Trust Model: Genesis to Edge

**Are there flaws in the trust system?**
The trust model follows a robust, SPIFFE-like hierarchical chain:
`Genesis Key` → `Global Nodes (2/3 Quorum)` → `Org Keys` → `Member Certificates` → `Edge/Origin Nodes`

*   **Strengths:** This is cryptographically sound. An attacker cannot forge an `OrgKey` without compromising 2/3 of the Global nodes.
*   **Potential Flaws:** 
    *   **Quorum Deadlock:** The reliance on a `2/3 Quorum` of Global nodes to sign new `OrgPublicKey` records is dangerous in a purely DHT-based system without a consensus leader. If the network experiences a temporary partition, or if exactly 1/3 of the global nodes go offline, the entire network loses the ability to onboard new organizations or rotate keys.
    *   **Certificate Revocation:** While a `GlobalNodeRevocationList` exists, distributing revocation lists reliably across a Kademlia DHT during an active attack is a known hard problem.

## 5. Origin Node Protections & Isolation

**Can origin nodes join freely but not become edge nodes?**
Yes. The `validate_peer_role` function strictly enforces role boundaries. An Origin node cannot simply announce itself to the DHT as an Edge node. To claim the `EDGE` role, it must provide a `MemberCertificate` explicitly signed by an `OrgPublicKey` that has been authorized by the Global quorum. Origin nodes can join the mesh to *receive* traffic and threat updates, but they are algorithmically prohibited from routing traffic or acting as authoritative DHT storage nodes.

**Can malicious origin nodes attack the system? What protections exist?**
MaluWAF anticipates malicious origins and protects against them:
1.  **DHT Poisoning:** The `DhtAccessControl` layer restricts what Origin nodes can write. They cannot overwrite `verified_upstream:` routes, `tier_claim:` roles, or Global threat intelligence feeds. They are restricted to writing their own localized telemetry.
2.  **Sybil / DoS Attacks:** Edge nodes joining the network must compute a **Proof of Work (PoW)** (`validate_edge_node_pow`). This makes it computationally expensive for an attacker to spin up thousands of fake Origin/Edge nodes to exhaust QUIC connection pools.
3.  **Threat Feed Isolation:** Threat feeds require strict Ed25519 signatures from the Global tier. A compromised Origin node cannot inject fake blocked IPs into the global `ThreatIntelligenceManager`.

## Summary
MaluWAF’s Layer 3 and 5 are highly advanced, leveraging state-of-the-art PQC and robust cryptographic trust chains. However, the decision to build a bespoke Kademlia-based state synchronization engine for the control plane introduces severe operational complexity. Long-term maintenance would benefit significantly from migrating the Global tier to a standard Raft consensus model.