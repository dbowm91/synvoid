# Org Key Trust Chain Skill

## Overview

MaluWAF uses a hierarchical trust chain for mesh node authentication:
`Genesis Key` → `Global Nodes (2/3 Quorum)` → `Org Keys` → `Member Certificates` → `Edge Nodes`

This skill provides context for working with organization keys, quorum signatures, and member certificates.

## Key Components

### 1. OrgKeyManager (`src/mesh/org_key_manager.rs`)
The central coordinator for the trust chain.
- Manages local `Organization` and `OrgKey` records.
- Publishes `OrgPublicKey` to the DHT.
- Coordinates quorum signing with other global nodes.
- Handles automated renewal of keys nearing expiration.

### 2. OrgPublicKey (`src/mesh/organization.rs`)
The public representation of an organization's identity.
- Contains the Ed25519 public key.
- Carries `quorum_signatures` from multiple Global Nodes.
- Validated via `verify_quorum()` using authorized global keys.

### 3. MemberCertificate (`src/mesh/organization.rs`)
Short-lived certificates issued by organizations to individual nodes.
- Signed by an `OrgKey`.
- Bound to a specific `mesh_id`.
- Validated via `verify_with_public_key()` against an `OrgPublicKey`.

## Common Workflows

### Creating an Organization
Only Global Nodes can create organizations.
```rust
let org = org_key_manager.create_organization("my-org".to_string(), Some("My Organization".to_string())).await?;
```

### Requesting Quorum Signatures
When an organization is created, it needs signatures from other Global Nodes to be valid across the network.
```rust
let request_id = org_key_manager.request_quorum_signatures("my-org").await?;
```

### Validating a Peer
Handshake includes `member_certificate` and `org_public_key`.
```rust
crate::mesh::peer_auth::validate_member_certificate(
    cert,
    org_pub_key,
    authorized_global_pubkeys,
    peer_node_id,
)?;
```

## DHT Keys
- `org_pubkey:{org_id}`: Stores the `OrgPublicKey` with its quorum signatures.

## Mesh Messages
- `OrgKeySignRequest`: Request a global node to sign an `OrgPublicKey`.
- `OrgKeySignResponse`: Return a signature for an `OrgPublicKey`.
