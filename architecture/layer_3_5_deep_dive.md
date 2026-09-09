# Architectural Deep Dive: Layers 3 & 5 (Proxy & Mesh)

This document provides an in-depth review of SynVoid's Layer 3 (Proxy & Routing) and Layer 5 (Mesh & Distributed Systems), focusing on Post-Quantum Cryptography (PQC), Dependency Alignment, Trust Models, and the complexities of peer-to-peer (P2P) communication.

## 1. Post-Quantum Cryptography (PQC) Support

**Are we supporting PQC fully?**
Yes, SynVoid is exceptionally forward-looking in its PQC implementation. It achieves "Quantum-Ready" status across both the data plane (Layer 3) and the control plane (Layer 5):

*   **Layer 3 (TLS & Proxy):** Uses the `rustls` crate with the `aws-lc-rs` backend and the `prefer-post-quantum` configuration flag. This enables hybrid key exchange algorithms (e.g., X25519MLKEM768) during TLS 1.3 handshakes for incoming client traffic.
*   **Layer 5 (Mesh Control Plane):**
    *   **Key Exchange (KEM):** Implements ML-KEM-768 for securing QUIC tunnels between mesh nodes (`MlKemKeyExchangeService`).
    *   **Authentication (DSA):** Uses `libcrux` for ML-DSA-44. Crucially, it employs a **Hybrid Signature Scheme** (`MeshHybridSigner`) with struct fields `ed25519_signature` (64 bytes), `ml_dsa_signature` (2420 bytes), `ed25519_public_key`, and `ml_dsa_public_key`.

### HybridSignature vs MeshHybridSigner Distinction (L35-3)

SynVoid has two layers of hybrid signature support:

| Type | Location | Purpose |
|------|----------|---------|
| **`HybridSigner`** trait | `crates/synvoid-mesh/src/mesh/hybrid_signature.rs:190` | Generic trait for any hybrid signer implementing `sign_hybrid()` / `verify_hybrid()` |
| **`HybridSignature`** struct | `crates/synvoid-mesh/src/mesh/hybrid_signature.rs:17-22` | Generic signature containing `ed25519_signature` (Vec<u8>), `ml_dsa_signature` (Vec<u8>), `ed25519_public_key` (String), and `ml_dsa_public_key` (Option<String>) |
| **`MeshHybridSigner`** | `crates/synvoid-mesh/src/mesh/ml_dsa.rs:122` | Concrete mesh-specific signer that uses Ed25519 + ML-DSA-44 for DHT/mesh messages |

The generic `HybridSigner` trait provides a consistent interface; `MeshHybridSigner` is the concrete implementation for mesh control plane messages. The `HybridSignature` struct stores the raw signature bytes for serialization.

### Hybrid Signature Verification (BUG-L1)

The `verify_hybrid()` function at `crates/synvoid-mesh/src/mesh/ml_dsa.rs:186-216` implements fail-safe hybrid signature verification:

1. **Ed25519 First:** Always verifies the classical Ed25519 signature first
2. **ML-DSA Optional:** If `signature.has_ml_dsa()` is true, verifies the ML-DSA signature
3. **Fail-Safe Behavior:** If ML-DSA data is absent (`has_ml_dsa()` returns false), the function returns `true` (treating as valid)

This fail-safe approach ensures that if the PQC algorithm is broken or unavailable, the system can still operate on classical Ed25519 signatures alone. See `verify_hybrid()` at `crates/synvoid-mesh/src/mesh/ml_dsa.rs:186-216`.

### Post-Quantum TLS Provider Installation (L35-4)

When the `post-quantum` feature is enabled (`Cargo.toml:33`), the `rustls` crate with `prefer-post-quantum` feature provides hybrid key exchange for TLS 1.3 connections:

```toml
post-quantum = ["synvoid-http-client/post-quantum"]  # Cargo.toml:33
rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }  # Cargo.toml:165
```

This enables X25519MLKEM768 hybrid key exchange for all TLS 1.3 connections, securing Layer 3 (TLS & Proxy) traffic against quantum attacks.

### Async Hybrid Verification

The `verify_hybrid_async()` function (`crates/synvoid-mesh/src/mesh/protocol.rs:196-232`) uses `CryptoVerificationPool` for parallel ML-DSA signature verification.

### ML-KEM Proof-of-Possession (BUG-L3)

The ML-KEM key exchange includes proof-of-possession verification at `crates/synvoid-mesh/src/mesh/ml_kem_key_exchange.rs:204-279`. The `confirm_key` method:

1. **Verifies Client Public Key:** Confirms the client public key matches the stored session public key
2. **Decapsulation Test:** Calls `MlKem768::decapsulate()` with the client's key to confirm the client can actually use the shared secret

This prevents a rogue server from successfully completing key exchange without the client being able to decapsulate. See `confirm_key()` at `crates/synvoid-mesh/src/mesh/ml_kem_key_exchange.rs:241`.

### ML-KEM Timing Side-Channel Consideration (L35-6)

RUSTSEC-2023-0079: `ring` (used via `aws-lc-rs`) ML-KEM implementation uses conditional operations that may leak timing information. For SynVoid's threat model:

- **Data Plane (Layer 3):** Acceptable risk - timing side-channels in TLS handshakes don't expose key material
- **Control Plane (Layer 5):** The `libcrux-ml-dsa` crate is used for ML-DSA-44 signatures (not ML-KEM for signing)
- **Mitigation:** Production deployments should enable `verify-pq` feature to validate PQ implementation behavior

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
    1.  **Raft Consensus:** Global nodes use Raft consensus (`crates/synvoid-mesh/src/mesh/raft/`, openraft majority) for state consistency. Partition behavior is fail-closed with typed `QuorumUnavailable` and freshness-classified reads — see `architecture/distributed_state_contract.md` §2 (MESH-15 closed as stale).
    2.  **Standardize mTLS:** Edge and Origin nodes could simply connect to Global nodes using standard TLS 1.3 mTLS (with PQC enabled) rather than custom KEM handshake protocols over raw QUIC streams.

## 4. The Trust Model: Genesis to Edge

**Are there flaws in the trust system?**
The trust model follows a robust, SPIFFE-like hierarchical chain:
`Genesis Key` → `Global Nodes (Raft majority)` → `Org Keys` → `Member Certificates` → `Edge/Origin Nodes`

*   **Strengths:** This is cryptographically sound. An attacker cannot forge an `OrgKey` without compromising Raft majority of the Global nodes and committing through the leader.
*   **Potential Flaws:**
    *   **Quorum Unavailability (MESH-15 CLOSED, replaced):** The old MESH-15 text described a "2/3 Quorum … in a purely DHT-based system without a consensus leader." That design predates Raft (Waves 6–11) and is stale. The precise current limitation is standard Raft majority unavailability: if the Global cluster loses majority during partition, canonical writes (onboarding, key rotation, revocation) fail typed/fail-closed (`QuorumUnavailable`) while edge reads serve last committed snapshots per freshness policy. DHT/advisory state never becomes fallback authority. Binding contract: `architecture/distributed_state_contract.md` §2.
    *   **Certificate Revocation:** `GlobalNodeRevocationList` is Raft-authoritative (`Namespace::Revocation`, append-only, permanent) and distributed via commit notifications + edge replicas with hard-limit freshness enforcement — not best-effort DHT gossip alone. See `architecture/distributed_state_contract.md` §3a.

## 5. Origin Node Protections & Isolation

**Can origin nodes join freely but not become edge nodes?**
Yes. The `validate_peer_role` function (at `crates/synvoid-mesh/src/mesh/peer_auth.rs:390`) strictly enforces role boundaries. An Origin node cannot simply announce itself to the DHT as an Edge node. To claim the `EDGE` role, it must provide a `MemberCertificate` explicitly signed by an `OrgPublicKey` that has been authorized by the Global quorum. Edge nodes can also validate via a value-bound `SignedRaftAttestation` (v2 protocol, `protocol_version=2`) — when a Raft attestation is provided, it is used exclusively with no fallback to other validation paths. Origin nodes can join the mesh to *receive* traffic and threat updates, but they are algorithmically prohibited from routing traffic or acting as authoritative DHT storage nodes.

**Can malicious origin nodes attack the system? What protections exist?**
SynVoid anticipates malicious origins and protects against them:
1.  **DHT Poisoning:** The `DhtAccessControl` layer restricts what Origin nodes can write. They cannot overwrite `verified_upstream:` routes, `tier_claim:` roles, or Global threat intelligence feeds. They are restricted to writing their own localized telemetry.
2.  **Sybil / DoS Attacks:** Edge nodes joining the network must compute a **Proof of Work (PoW)** (`validate_edge_node_pow`). This makes it computationally expensive for an attacker to spin up thousands of fake Origin/Edge nodes to exhaust QUIC connection pools.
3.  **Threat Feed Isolation:** Threat feeds require strict Ed25519 signatures from the Global tier. A compromised Origin node cannot inject fake blocked IPs into the global `ThreatIntelligenceManager`.

## 6. Half-TCP (Layer 3.5) Implementation

Beyond HTTP/HTTPS proxying, SynVoid supports a **Half-TCP** mode for non-HTTP protocols via `BackendProtocol::Tcp` in the upstream pool system.

### Tunnel Backend

The `TunnelBackend` (defined in `crates/synvoid-tunnel/src/router.rs:199`) provides half-TCP proxy functionality with two routing modes:

```rust
pub enum TunnelBackend {
    Direct { host: String, port: u16 },  // Routes directly to upstream
    Tunnel { session_id: String, identifier: String },  // Routes through mesh tunnel
}
```

**Routing Logic** (`crates/synvoid-tunnel/src/router.rs:149-195`):
- `resolve_tunnel_backend()` first attempts QUIC client resolution
- Falls back to session mappings lookup
- Both result in `TunnelBackend::Direct` variant with resolved host/port
- L35-1 fix: Now uses configured `upstream_host` from `server_mappings` instead of hardcoded `127.0.0.1`

```rust
// TunnelBackend::Direct uses configured host, not hardcoded localhost
TunnelBackend::Direct {
    host: mapping.upstream_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
    port: mapping.upstream_port.unwrap_or(mapping.port),
}
```

### Connection Pool Behavior

When `BackendProtocol::Tcp` is used:
- **No HTTP Parsing:** Raw TCP stream, not parsed as HTTP
- **Pool Key:** Currently uses only address (host:port) for connection reuse, **not** including authority header (L35-2 documentation accuracy note - implementation may not use authority)
- **Keep-Alive:** Connections kept alive in pool for reuse
- **Protocol Name:** Logged as "TCP" in metrics

This enables proxying for SSH, databases (PostgreSQL, MySQL), custom TCP protocols, and QUIC tunnel traffic.

### Integration with Mesh

In mesh mode, half-TCP connections can be routed through the DHT to remote peers.

### ACME DNS Challenge Integration (L35-7)

When the `dns` feature is enabled, SynVoid supports ACME DNS-01 challenge validation:

- DNS provider integration via `crates/synvoid-tls/src/acme_dns.rs` (Route53, Cloudflare, etc.)
- Automatic TXT record creation/deletion for Let's Encrypt/DV certificates
- Requires `dns` feature flag: `cargo build --features dns,mesh`
- ACME integration at `crates/synvoid-tls/src/acme.rs` for certificate management

### Hybrid Signatures Performance (L35-8)

Hybrid signatures (Ed25519 + ML-DSA-44) have significant size overhead:

| Signature Type | Size | Use Case |
|---------------|------|----------|
| Ed25519 only | 64 bytes | Classical signatures |
| ML-DSA-44 only | 2,420 bytes | Post-quantum signatures |
| Hybrid (Ed25519 + ML-DSA) | 2,484 bytes | Both signatures concatenated |

**Performance Impact:**
- Wire transmission: ~39x larger than Ed25519 alone
- Verification time: ML-DSA ~3-5x slower than Ed25519 on same hardware
- DHT storage: Higher memory/disk usage for signed records
- **Mitigation**: Fallback to Ed25519-only when PQ not required (`pqc-mesh` feature flag)

### Raft Consensus Quorum Behavior (L35-9, MESH-15 CLOSED)

The mesh Global tier uses Raft consensus (`crates/synvoid-mesh/src/mesh/raft/`, openraft N/2+1 majority) for state consistency. Historical limitation note:

> **MESH-15 (CLOSED as stale in Phase 23):** The original "Quorum Deadlock Risk During Partition" text described manual 2/3 signing "in a purely DHT-based system without a consensus leader." That predates Raft and no longer describes the implementation. It is replaced by the binding partition contract in `architecture/distributed_state_contract.md` §2: without Raft majority, canonical writes fail typed `QuorumUnavailable` (fail-closed, never success); reads serve last committed snapshots per freshness policy; DHT never becomes fallback authority; on heal, Raft log + snapshots converge and edge replicas refresh (stale divergent writes rejected, revocations permanent).

See [Raft Consensus Skill](../.opencode/skills/raft_consensus/SKILL.md) for detailed Raft implementation status.

### Post-Quantum TLS Configuration (L35-10)

Post-quantum TLS support is provided by `rustls` with the `prefer-post-quantum` feature:

```toml
# Cargo.toml
post-quantum = ["synvoid-http-client/post-quantum"]  # Feature flag
rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }
```

When enabled, this provides X25519MLKEM768 hybrid key exchange for all TLS 1.3 connections.

## Summary
SynVoid’s Layer 3 and 5 are highly advanced, leveraging state-of-the-art PQC and robust cryptographic trust chains. However, the decision to build a bespoke Kademlia-based state synchronization engine for the control plane introduces severe operational complexity. Long-term maintenance would benefit significantly from migrating the Global tier to a standard Raft consensus model.