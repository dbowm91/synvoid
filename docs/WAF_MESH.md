# WAF Mesh Networking

MaluWAF supports peer-to-peer mesh networking for distributed DDoS mitigation, threat intelligence sharing, and coordinated protection via QUIC-based communication.

## Opt-In by Default

**Mesh networking is disabled by default.** A standalone MaluWAF instance operates completely independently without any WAF-to-WAF, server-WAF, or VPN-WAF connections.

To enable mesh networking:

```toml
[mesh]
enabled = true
role = "edge"  # or "global" for directory nodes

# Optional: customize connection settings
[mesh.connection]
min_peer_connections = 3
max_peer_connections = 20
```

## Overview

The WAF mesh enables multiple MaluWAF instances to communicate directly using QUIC, forming an intelligent protection network.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WAF Mesh Network                                    │
└─────────────────────────────────────────────────────────────────────────────┘

        ┌──────────────────────────────────────────────────────────────┐
        │                                                              │
        │   ┌────────┐     ┌────────┐     ┌────────┐                 │
        │   │  WAF   │◄───►│  WAF   │◄───►│  WAF   │                 │
        │   │ Node 1 │     │ Node 2 │     │ Node 3 │                 │
        │   └────────┘     └────────┘     └────────┘                   │
        │        │              │              │                       │
        │        │   QUIC Streams (Encrypted) │                       │
        │        │              │              │                       │
        │        ▼              ▼              ▼                       │
        │   ┌─────────────────────────────────────────┐               │
        │   │     Shared Threat Intelligence         │               │
        │   │     • IP Reputation Database           │               │
        │   │     • Attack Pattern Signatures       │               │
        │   │     • Bot Detection Results            │               │
        │   │     • Blocklist Synchronization       │               │
        │   └─────────────────────────────────────────┘               │
        │                                                              │
        └──────────────────────────────────────────────────────────────┘
```

## Key Capabilities

### 1. Distributed DDoS Mitigation

When one node detects an attack, all nodes benefit:

```toml
[mesh]
enabled = true
bind_address = "0.0.0.0"
port = 5001

# Connect to peers
[mesh.seeds]
"waf-2.internal" = "10.0.1.20:5001"
"waf-3.internal" = "10.0.1.30:5001"

# Share threat intelligence
[mesh.sync]
ip_reputation = true
blocklists = true
bot_signatures = true
```

### 2. Threat Intelligence Sharing

Attack information propagates across the mesh in real-time:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Flow                                  │
└─────────────────────────────────────────────────────────────────────────────┘

  Attack Detected at Node A
         │
         ▼
  ┌─────────────┐
  │  Analyze    │ ← Attack type, source IP, signature
  │  Attack     │
  └─────────────┘
         │
         ▼
  ┌─────────────┐
  │  Propagate  │ ──► All connected nodes
  │  to Mesh    │     receive updated blocklist
  └─────────────┘
         │
         ▼
  ┌─────────────┐
  │  Updated    │ ◄── Immediate protection
  │  IP Rep     │     against attack source
  └─────────────┘
```

### 3. Traffic Scrubbing

Deploy scrubbing centers that inspect and clean traffic:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DDoS Mitigation Architecture                              │
└─────────────────────────────────────────────────────────────────────────────┘

                   Attack Traffic
                        │
                        ▼
           ┌────────────────────────────┐
           │    Edge WAF Nodes          │
           │  (Traffic Aggregation)     │
           └────────────┬───────────────┘
                        │
                        ▼
           ┌────────────────────────────┐
           │    Scrubbing Center       │
           │  ┌────────────────────┐  │
           │  │  WAF Mesh Cluster │  │
           │  │                   │  │
           │  │  ┌───┐  ┌───┐    │  │
           │  │  │WAF│  │WAF│    │  │
           │  │  └───┘  └───┘    │  │
           │  │  ┌───┐  ┌───┐    │  │
           │  │  │WAF│  │WAF│    │  │
           │  │  └───┘  └───┘    │  │
           │  └────────────────────┘  │
           └────────────┬───────────────┘
                        │
                        ▼
           ┌────────────────────────────┐
           │   Clean Traffic            │
           │   to Origin Servers        │
           └────────────────────────────┘
```

## Configuration

### Basic Mesh Setup

```toml
[mesh]
enabled = true
bind_address = "0.0.0.0"
port = 5001
role = "edge"

[mesh.seeds]
# Using DNS names (resolved at startup)
"waf-2.internal" = "10.0.1.20:5001"
"waf-3.internal" = "10.0.1.30:5001"

# Connection settings
[mesh.connection]
keepalive = 30
reconnect_interval = 5
max_reconnect_attempts = 10
```

### Synchronization Settings

```toml
[mesh.sync]
# What to share with peers
share_ip_reputation = true
share_blocklists = true
share_bot_signatures = true

# How often to sync
sync_interval = "5s"
full_sync_interval = "5m"
```

### Bandwidth Limits

```toml
[mesh.limits]
# Limit mesh traffic to preserve production bandwidth
max_bandwidth_mbps = 100
max_peers = 20
```

## Security

### Encryption

All mesh traffic is encrypted via QUIC with TLS 1.3:

```toml
[mesh.tls]
# Certificate verification
verify_certificates = true

# Post-quantum key exchange (recommended for long-term security)
enable_post_quantum = true
```

### Authentication

Control which nodes can join using genesis keys:

```toml
[mesh.node_identity]
# Genesis key for identity derivation (32 bytes, base64 encoded)
genesis_key_base64 = "your-genesis-key-here"

# Authorized genesis keys (empty = any genesis key allowed)
authorized_genesis_keys = []
```

## Mesh Node Types

MaluWAF mesh supports three node roles:

### Global Nodes

Global nodes maintain a complete view of the entire mesh network and serve as:
- **Seed sources** for new edge nodes joining the network
- **Directory servers** for discovering other peers
- **Route aggregators** for upstream service discovery
- **Certificate Authority** for signing node identities

```toml
[mesh]
enabled = true
role = "global"
bind_address = "0.0.0.0"
port = 5001

[mesh.node_identity]
genesis_key_base64 = "your-secret-genesis-key"
```

### Edge Nodes

Edge nodes are typical WAF instances that:
- Connect to global nodes for network discovery
- Share routes and upstream servers
- Participate in traffic routing

```toml
[mesh]
enabled = true
role = "edge"

[mesh.seeds]
- address = "global-1.mesh.example.com:5001"
  global_node_key = "your-genesis-key"
```

### Origin Nodes

Origin nodes are WAFs with direct upstream server connections:
- Announce their upstreams to the mesh
- Preferred routing targets for traffic

```toml
[mesh]
enabled = true
role = "origin"
```

## Network Isolation

### Network IDs

Multiple isolated mesh networks can coexist using `network_id`:

```toml
# Production network
[mesh]
network_id = "production"

[mesh.seeds]
- address = "global-1.mycompany.com:5001"
  network_id = "production"
```

```toml
# Staging network (separate from production)
[mesh]
network_id = "staging"

[mesh.seeds]
- address = "staging-global.mycompany.com:5001"
  network_id = "staging"
```

Nodes with different `network_id` values will not connect to each other, even if addresses are reachable.

---

## Admin API Endpoints

The mesh provides the following admin API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mesh/status` | GET | Get mesh status and node information |
| `/api/mesh/nodes` | GET | List all connected mesh nodes |
| `/api/mesh/nodes/{node_id}` | GET | Get specific node details |
| `/api/mesh/bans` | GET | List active IP bans |
| `/api/mesh/ban/ip` | POST | Ban an IP address |
| `/api/mesh/ban/mesh-id` | POST | Ban a mesh node ID |
| `/api/mesh/ban` | DELETE | Unban an IP or mesh ID |
| `/api/mesh/derive-signing-key` | POST | Derive signing key from genesis key |
| `/api/mesh/audit/report` | POST | Submit client audit report |

### Get Mesh Status

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/mesh/status
```

**Response:**
```json
{
  "is_global_node": true,
  "node_id": "node-abc123",
  "connected_peers": 5,
  "global_nodes": 2,
  "edge_nodes": 3,
  "genesis_key_configured": true,
  "genesis_public_key_fingerprint": "sha256:abc123...",
  "signing_key_derived": true,
  "signing_public_key": "abc123def456...",
  "quic_0rtt_enabled": false,
  "quic_0rtt_warning": null
}
```

### List Mesh Nodes

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/mesh/nodes
```

### Ban an IP

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "reason": "detected_attack",
    "duration_seconds": 3600,
    "site_scope": "global"
  }' \
  http://127.0.0.1:8081/api/mesh/ban/ip
```

### Derive Signing Key

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "genesis_key_base64": "YWJjZDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng=="
  }' \
  http://127.0.0.1:8081/api/mesh/derive-signing-key
```

---

## Per-Site Mesh Bandwidth

When using mesh proxying to route traffic through other WAF nodes, bandwidth is tracked per-site. Each site shows:

| Metric | Description |
|--------|-------------|
| `mesh_bytes_sent` | Request bytes sent to mesh peers |
| `mesh_bytes_received` | Response bytes received from mesh peers |

This is distinct from direct proxy bandwidth (`proxied_bytes_sent`/`proxied_bytes_received`) where the WAF connects directly to the origin server.

---

## When to Use Mesh vs Clustering

Choose the right architecture for your deployment:

| Feature | Master-Worker Clustering | WAF Mesh Network |
|---------|-------------------------|------------------|
| **Complexity** | Low (centralized) | Medium (distributed) |
| **Use Case** | Scale single WAF instance | Distribute across regions |
| **Threat Sharing** | No | Yes (blocklists, patterns) |
| **Origin Lookup** | Per-instance | Global across mesh |
| **Setup Effort** | Minutes | Hours |

### Use Master-Worker Clustering When:
- You need to scale a single WAF instance horizontally
- You want simple horizontal scaling within one datacenter
- You don't need threat intelligence sharing between nodes
- You prefer centralized configuration management

### Use WAF Mesh When:
- You have multiple geographic locations
- You want collaborative DDoS defense (shared blocklists)
- You need to hide origin servers behind edge WAFs
- You're building a private CDN or DDoS mitigation network
- You want automatic origin server discovery across nodes
