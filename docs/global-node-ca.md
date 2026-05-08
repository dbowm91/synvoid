# Global Nodes as Certificate Authority

## Role

Global nodes are the root of trust for the entire SynVoid mesh network. They function as a Certificate Authority (CA) and directory authority — analogous to Tor directory authorities but for service exposure rather than anonymity.

**Admission to the Global tier is consensus-gated.** Instead of a shared secret, new nodes must request admission via the `JoinRequest` protocol and be authorized by the existing Raft cluster.

## Responsibilities

| Function | Description |
|----------|-------------|
| **Admission** | Proposes and votes on new global node candidates |
| **CA** | Signs all node certificates (origin and edge) |
| **Directory** | Maintains the authoritative node registry |
| **Config authority** | Distributes network-wide configuration |
| **Domain verifier** | Validates zone ownership (TXT/NS challenges) |

## Graduated Trust

Trust is based on hardware attestation. Nodes are assigned a **Trust Level** (1-3) based on their environment (Software, TPM, or TEE). Sensitive operations like signing Organizational Tier Keys require a minimum trust level of 2 or 3.

## Certificate Distribution

Node certificates are issued during registration and distributed via the mesh:
...
```
Node                          Global Node
  │                                │
  │── CSR (pubkey, node_id) ──────►│
  │◄─ Signed Cert ─────────────────│
  │   (X.509, CA-signed)          │
```

For TLS site certificates, origin nodes distribute to edges via `src/mesh/cert_dist.rs`:

1. Origin encrypts cert + private key with AES-256-GCM.
2. Per-site encryption key derived via HKDF from the mesh session key.
3. Edge receives `SiteTlsCertSync` message, decrypts, and installs.

Private keys never traverse the mesh in plaintext.

## Node Authentication

Nodes authenticate each other using certificates signed by the global node CA:

1. During QUIC handshake both sides present their CA-signed certificate.
2. Each side verifies the chain up to the global node's root CA.
3. The certificate's SAN contains the node ID, binding identity to the cert.

Compromise of a global node's private key allows impersonation of any node in the network. Global node keys should be stored in HSMs or hardware tokens where possible.

## Relevant Source

- `src/mesh/cert_dist.rs` — Site TLS cert distribution (origin → edge)
- `src/mesh/` — Mesh protocol, peer authentication
- `src/tls/acme.rs` — ACME client (separate from mesh CA)
