# DNS Mesh Integration

SynVoid integrates DNS server functionality with the mesh networking layer for distributed DNS resolution and DNSSEC validation.

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

1. **TXT challenge** — Global node generates a random token; registrant publishes `_acme-challenge.<zone> TXT <token>`. ACME HTTP-01 challenges are also supported via mesh proxy.
2. **NS challenge** — For delegated zones the global node checks that the registrant's NS records match the claimed NS set.

Verification is re-checked periodically. Failure removes the zone from the node's published capabilities.

## DNS Providers

SynVoid supports multiple DNS resolver modes:

| Provider | DNSSEC | Description |
|----------|--------|-------------|
| **Recursive** | Full validation | Full DNSSEC validation with trust anchor management |
| **Google** | Trust propagation | Forwards to Google DNS |
| **Cloudflare** | Trust propagation | Forwards to Cloudflare DNS |
| **System** | None | Uses system resolver |
| **Custom** | None | Custom upstream IPs |

### Recursive Resolver with DNSSEC

```toml
[dns.recursive]
upstream_provider = "Recursive"
dnssec_validation = true
trust_anchors.enabled = true
trust_anchor_path = "trusted-key.key"
```

DNSSEC validation uses RFC 5011 trust anchor management for automated key rollover.

## DHT Sync

Zone and peer state is replicated via a Kademlia-style DHT over the mesh QUIC transport:

- **Zone records** are stored under `(zone_name, record_type)` keys
- **Peer state** (load, health, capabilities) is stored under `(node_id)` keys
- **Threat intelligence** indicators stored under composite keys `threat_indicator:{ip}:{threat_type}`
- Lookups use XOR distance over a 256-bit node ID space
- Values are signed by the originating node's mesh key

Replication factor is configurable (default: k=3).

## Mesh Signing Key Derivation

Each mesh session derives a per-node signing key from the QUIC session key via HKDF:

```
signing_key = HKDF-SHA256(
    ikm  = quic_session_key,
    salt = node_id || peer_id,
    info = "synvoid-mesh-signing-v1",
    len  = 32
)
```

This key is used to sign DHT values and mesh protocol messages. It is never exported or persisted — it lives only for the duration of the QUIC session.

## TLS Certificate Distribution

Origin → Edge TLS certificate distribution via mesh messages:

| Message | Purpose |
|---------|---------|
| `SiteTlsCertSync` | Periodic certificate sync |
| `SiteTlsCertRequest` | Edge requests certificate for domain |
| `SiteTlsCertResponse` | Origin sends encrypted certificate + key |

Private keys are encrypted with AES-256-GCM using per-site keys derived via HKDF from the mesh session key.

## ACME HTTP-01 Challenge Serving

ACME HTTP-01 challenges work across edge/origin mesh topologies:

1. Origin initiates ACME order → Global node sends `UpstreamOwnershipChallenge{Http01{token, key_authorization}}` to all edges
2. Edges store token → key_authorization in LRU cache (5 min TTL)
3. ACME server probes edge IP: `GET /.well-known/acme-challenge/{token}`
4. Edge serves key_authorization from store

For DNS-01 challenges, the AcmeDnsChallenge is wired to the DNS server to serve `_acme-challenge.*` TXT records.

## DNS Serving Health

Global nodes advertise their DNS serving health status via the `dns_serving_healthy` field in mesh protocol messages. This allows the mesh to:

1. **Monitor DNS availability** — Edges can query the health of global nodes' DNS servers
2. **Route DNS requests** — Only healthy global nodes are used for DNS serving
3. **Failover** — If a global node's DNS becomes unhealthy, traffic routes to another healthy node

The `dns_serving_healthy` field is:
- `true` when the global node's DNS server is operational
- `false` when DNS serving is unavailable (e.g., DNS feature not compiled, server error)

## Relevant Source

- `src/mesh/` — Transport, protocol, DHT, cert distribution
- `src/dns/server/` — DNS server mesh integration
- `src/mesh/cert_dist.rs` — Certificate distribution (origin → edge)
- `src/dns/trust_anchor.rs` — RFC 5011 trust anchor management
- `crates/synvoid-tls/src/acme.rs` — ACME client implementation
