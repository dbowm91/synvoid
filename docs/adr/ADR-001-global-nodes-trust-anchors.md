# ADR-001: Global Nodes as Trust Anchors (Not Elected)

## Status
Accepted

## Date
2026-03-15

## Context
SynVoid uses a mesh network with multiple node roles (Global, Edge, Origin). There was a question about how global nodes are determined - should they be elected by consensus, or explicitly configured?

## Decision
**Global nodes are explicitly configured bootstrap nodes that serve as Certificate Authority and signing authority for the entire network.** They are NOT elected.

This is a fundamental security design decision.

## Rationale

### Security Model
- Global nodes function analogously to Tor's directory authorities (but with opposite purpose: exposing services rather than providing anonymity)
- All node certificates are signed by global nodes - they serve as the root CA
- Global nodes maintain complete network topology and act as directory servers
- Any system that claims to "elect" or "vote" for global nodes violates this security model

### Bootstrap Requirements
- New nodes need a trusted source of truth to connect to the network
- Elected nodes create a chicken-and-egg problem for new nodes joining
- Explicit configuration provides secure bootstrap without circular trust

### Alternative Considered: Raft-like Election
A consensus-based election was considered where nodes vote on global status. Rejected because:
1. Creates complexity in the trust model
2. Requires majority quorum before any node can be trusted
3. Vulnerable to eclipse attacks during election
4. Adds latency to critical security operations (certificate validation)

## Consequences

### Positive
- Simple, predictable bootstrap process
- Clear trust hierarchy for certificate validation
- No race conditions during node startup
- Global nodes can be hardened independently

### Negative
- Requires out-of-band configuration for new global nodes
- Single point of failure if all global nodes go down ( mitigated by running multiple global nodes)
- Global node list must be maintained manually

## References
- `crates/synvoid-mesh/src/mesh/peer_auth.rs` - `validate_peer_role()` validates global node status; now accepts `raft_attestation` and `allow_v1_raft_attestations` parameters for Edge node validation via value-bound Raft attestation
- `crates/synvoid-mesh/src/mesh/dht/keys.rs` - GlobalNode* DHT key types
- `crates/synvoid-mesh/src/mesh/config_identity.rs` - Genesis key configuration

## Update (2026-06): Raft Consensus Hardening

While global nodes remain explicitly configured (not elected), Raft consensus is used for **operational coordination** (log replication, quorum agreement on DHT state). Recent hardening adds:

- **SignedRaftAttestation** (`crates/synvoid-mesh/src/mesh/peer_auth.rs`): Raft membership attestations now carry Ed25519 signatures verified against authorized global node keys. Previously, attestations were structural-only.
- **ConsensusTransport trait** (`crates/synvoid-mesh/src/mesh/raft/consensus.rs`): Decouples Raft consensus from mesh transport, enabling independent testing and cleaner boundaries.

This does NOT change the trust model: global nodes are still explicitly configured. Raft provides consensus on operational state (DHT records, quorum decisions), not on who is a global node.
