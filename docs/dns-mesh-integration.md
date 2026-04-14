# DNS Mesh Integration

## Node Roles

The DNS mesh operates across three node types:

| Role | Responsibility |
|------|----------------|
| **Global** | Root CA, directory server, network-wide config authority |
| **Origin** | Primary DNS for a zone, signs records, distributes to edges |
| **Edge** | Serves queries from cache, forwards to origin for misses |

Global nodes are configured explicitly — they are never elected. Origins register with a global node and edges register with an origin.

## Registration Flow

```
Edge/Origin                  Global Node
    │                             │
    │── MeshHello (role, pubkey) ─►│
    │◄─ SessionKey (ECDH) ────────│
    │                             │
    │── RegisterRequest ─────────►│
    │   (capabilities, domains)   │
    │◄─ RegisterAck ──────────────│
    │   (assigned node ID)        │
```

After registration the node appears in the global directory and other nodes can discover it for DHT lookups.

## Domain Verification

Before a node can serve DNS for a zone it must prove ownership:

1. **TXT challenge** — Global node generates a random token; registrant publishes `_maluwaf-verify.<zone> TXT <token>`. Global node queries authoritative NS to confirm.
2. **NS challenge** — For delegated zones the global node checks that the registrant's NS records match the claimed NS set.

Verification is re-checked periodically. Failure removes the zone from the node's published capabilities.

## DHT Sync

Zone and peer state is replicated via a Kademlia-style DHT over the mesh QUIC transport:

- **Zone records** are stored under `(zone_name, record_type)` keys.
- **Peer state** (load, health, capabilities) is stored under `(node_id)` keys.
- Lookups use XOR distance over a 256-bit node ID space.
- Values are signed by the originating node's mesh key (see below).

Replication factor is configurable (default: 3).

## Mesh Signing Key Derivation

Each mesh session derives a per-node signing key from the QUIC session key via HKDF:

```
signing_key = HKDF-SHA256(
    ikm  = quic_session_key,
    salt = node_id || peer_id,
    info = "maluwaf-mesh-signing-v1",
    len  = 32
)
```

This key is used to sign DHT values and mesh protocol messages. It is never exported or persisted — it lives only for the duration of the QUIC session.

## Relevant Source

- `src/mesh/` — Transport, protocol, DHT, cert distribution
- `src/dns/server/` — DNS server mesh integration
- `src/mesh/cert_dist.rs` — Certificate distribution (origin → edge)
