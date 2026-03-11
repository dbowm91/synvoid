# WAF Mesh Networking

MaluWAF supports peer-to-peer mesh networking for distributed DDoS mitigation, threat intelligence sharing, and coordinated protection.

## Opt-In by Default

**Mesh networking is disabled by default.** A standalone MaluWAF instance operates completely independently without any WAF-to-WAF, server-WAF, or VPN-WAF connections.

To enable mesh networking:

```toml
[tunnel.mesh]
enabled = true
role = "edge"  # or "global" for directory nodes

# Optional: customize connection settings
[tunnel.mesh.connection]
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
        │   └────────┘     └────────┘     └────────┘                 │
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
[tunnel.mesh]
enabled = true
bind_address = "0.0.0.0"
port = 51820

# Connect to peers
[tunnel.mesh.peers]
"waf-node-2.example.com" = "10.0.0.2:51820"
"waf-node-3.example.com" = "10.0.0.3:51820"

# Share threat intelligence
[tunnel.mesh.sync]
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
[tunnel]
enabled = true

[tunnel.mesh]
enabled = true
bind_address = "0.0.0.0"
port = 51820

[tunnel.mesh.peers]
# Using DNS names (resolved at startup)
"waf-2.internal" = "10.0.1.20:51820"
"waf-3.internal" = "10.0.1.30:51820"
"waf-4.internal" = "10.0.1.40:51820"

# Connection settings
[tunnel.mesh.connection]
keepalive = 30
reconnect_interval = 5
max_reconnect_attempts = 10
```

### Synchronization Settings

```toml
[tunnel.mesh.sync]
# What to share with peers
share_ip_reputation = true
share_blocklists = true
share_bot_signatures = true
share_config = false

# How often to sync
sync_interval = "5s"
full_sync_interval = "5m"
```

### Bandwidth Limits

```toml
[tunnel.mesh.limits]
# Limit mesh traffic to preserve production bandwidth
max_bandwidth_mbps = 100
max_peers = 20
```

## Use Cases

### Use Case 1: Multi-Region Deployment

Deploy WAF nodes across regions with synchronized protection:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Multi-Region WAF Mesh                                    │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │   US-East       │     │   EU-West      │     │   Asia-Pacific  │
  │                 │     │                 │     │                 │
  │  ┌───────────┐  │     │  ┌───────────┐  │     │  ┌───────────┐  │
  │  │ WAF Node │  │◄───►│  │ WAF Node │  │◄───►│  │ WAF Node │  │
  │  │           │  │     │  │           │  │     │  │           │  │
  │  └───────────┘  │     │  └───────────┘  │     │  └───────────┘  │
  │        │        │     │        │        │     │        │        │
  └────────┼────────┘     └────────┼────────┘     └────────┼────────┘
           │                       │                       │
           ▼                       ▼                       ▼
     ┌──────────┐            ┌──────────┐           ┌──────────┐
     │  Origin  │            │  Origin  │           │  Origin  │
     │ Servers  │            │ Servers  │           │ Servers  │
     └──────────┘            └──────────┘           └──────────┘
```

**Benefits:**
- Attack in EU is blocked in US before it reaches origin
- Consistent security policies across regions
- Shared IP reputation database

### Use Case 2: Scrubbing Center

Dedicated high-capacity nodes for traffic cleaning:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Dedicated Scrubbing Center                               │
└─────────────────────────────────────────────────────────────────────────────┘

  Internet Traffic
        │
        ▼
  ┌─────────────────────────────────────────┐
  │         Edge DNS / Anycast              │
  └────────────────────┬────────────────────┘
                       │
                       ▼
  ┌─────────────────────────────────────────┐
  │     WAF Mesh (Scrubbing Cluster)       │
  │                                          │
  │   ┌─────────┐  ┌─────────┐  ┌─────────┐│
  │   │  Scrub  │  │  Scrub  │  │  Scrub  ││
  │   │  Node 1 │  │  Node 2 │  │  Node 3 ││
  │   └─────────┘  └─────────┘  └─────────┘│
  │        │              │              │  │
  │        └──────────────┼──────────────┘  │
  │                      │                   │
  └──────────────────────┼───────────────────┘
                         │
                         ▼
              Clean Traffic to Origins
```

### Use Case 3: Hybrid Cloud

On-premises WAF nodes coordinating with cloud:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Hybrid Cloud Setup                                     │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────┐
  │           Cloud Provider             │
  │                                      │
  │   ┌─────────────────────────────┐   │
  │   │   WAF Mesh (Cloud Nodes)    │   │
  │   │   ┌──────┐  ┌──────┐        │   │
  │   │   │ WAF  │  │ WAF  │        │   │
  │   │   └──────┘  └──────┘        │   │
  │   └─────────────────────────────┘   │
  └───────────────────┬─────────────────┘
                      │ QUIC Tunnel
                      │ (Site-to-Site VPN)
                      ▼
  ┌─────────────────────────────────────┐
  │         On-Premises                  │
  │                                      │
  │   ┌─────────────────────────────┐   │
  │   │   WAF Mesh (Local Nodes)    │   │
  │   │   ┌──────┐  ┌──────┐        │   │
  │   │   │ WAF  │  │ WAF  │        │   │
  │   │   └──────┘  └──────┘        │   │
  │   └─────────────────────────────┘   │
  └─────────────────────────────────────┘
```

## Security

### Encryption

All mesh traffic is encrypted:

- **QUIC** provides built-in TLS 1.3
- **Certificate verification** between nodes
- **Pre-shared keys** for additional security (optional)

```toml
[tunnel.mesh.security]
# Enable TLS
tls_enabled = true

# Certificate verification
verify_certificates = true

# Or use pre-shared key
psk_enabled = false
psk_key = ""  # Set if using PSK
```

### Authentication

Control which nodes can join:

```toml
[tunnel.mesh.auth]
# Node authentication tokens
allowed_tokens = [
    "node-token-1",
    "node-token-2",
    "node-token-3",
]
```

## Monitoring

### Mesh Statistics

```bash
# Active peer connections
maluwaf_mesh_peers_connected

# Messages sent/received
maluwaf_mesh_messages_total

# Sync operations
maluwaf_mesh_sync_total

# Blocklist updates
maluwaf_mesh_blocklist_updates_total
```

### Debugging

```bash
# View mesh status
maluwafctl mesh status

# View peer connections
maluwafctl mesh peers

# View sync status
maluwafctl mesh sync
```

## Performance Considerations

| Setting | Default | Adjust For |
|---------|---------|------------|
| `max_peers` | 20 | Larger meshes need more memory |
| `sync_interval` | 5s | Faster sync = more network traffic |
| `max_bandwidth_mbps` | 100 | Reserve bandwidth for production traffic |

## Troubleshooting

### Nodes Not Connecting

1. Check firewall allows UDP port 51820
2. Verify network connectivity
3. Check time synchronization (NTP)
4. Review logs: `RUST_LOG=debug`

### High Mesh Traffic

1. Reduce sync frequency
2. Disable unnecessary sync types
3. Limit number of peers

### Split Brain

Ensure odd number of overseer nodes for consensus.

---

## Mesh Node Types

MaluWAF mesh supports three node roles:

### Global Nodes

Global nodes maintain a complete view of the entire mesh network and serve as:
- **Seed sources** for new edge nodes joining the network
- **Directory servers** for discovering other peers
- **Route aggregators** for upstream service discovery

```toml
[mesh]
enabled = true
role = "global"  # This node is a global node
global_node_key = "your-secret-key"  # Key for authenticating other global nodes
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
```

### Origin Nodes

Origin nodes are WAFs with direct upstream server connections:
- Announce their upstreams to the mesh
- Preferred routing targets for traffic

---

## Seed Nodes & Bootstrap

### Startup Sequence

When an edge node starts:

1. **Connect to seeds** - Attempts connection to configured seed nodes
2. **Request seed list** - Asks global node for complete network view
3. **Receive topology** - Gets list of known global and edge nodes
4. **Establish connections** - Connects to prioritized peers based on scores

### Default Seeds

By default, edge nodes attempt to connect to these global seeds:

```toml
[mesh.seeds]
# These are example addresses - replace with your network's global nodes
- address = "global-1.mesh.example.com:5001"
- address = "global-2.mesh.example.com:5001"  
- address = "global-3.mesh.example.com:5001"
```

### Custom Seed Configuration

```toml
[mesh.seeds]
- address = "global-1.mycompany.com:5001"
  public_key = "optional-pk"  # For authentication
  network_id = "production"   # Network isolation
  global_node_key = "key"     # Required for global node verification
```

---

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

## Global Node Verification

### Key-Based Authentication

Global nodes use a shared secret key for verification:

1. **Configure the key** on your global nodes:

```toml
[mesh]
role = "global"
global_node_key = "secure-random-key-12345"
```

2. **Configure the same key** in edge node seeds:

```toml
[mesh.seeds]
- address = "global-1.mycompany.com:5001"
  global_node_key = "secure-random-key-12345"
```

3. **Connection validation** - During handshake, global nodes exchange keys and reject connections with invalid keys

### Generating Keys

Generate a secure key:

```bash
# Using openssl
openssl rand -hex 16

# Using uuid
uuidgen | tr -d '-'
```

---

## Connection Quality & Scoring

### Peer Score Components

Each peer is scored based on multiple factors:

| Component | Weight | Description |
|-----------|--------|-------------|
| `latency` | 0.30 | Round-trip time (lower is better) |
| `stability` | 0.25 | Connection success rate |
| `load` | 0.20 | Peer CPU/memory usage |
| `traffic` | 0.15 | Request volume on routes |
| `upstream` | 0.10 | Has upstream servers |

### Connection Persistence

```toml
[mesh.connection]
min_peer_connections = 3   # Minimum connections to maintain
max_peer_connections = 20  # Maximum concurrent connections
health_check_interval_secs = 30  # How often to check peer health

# Score weights (must sum to 1.0)
[mesh.connection.connection_score_weights]
latency = 0.30
stability = 0.25
load = 0.20
traffic = 0.15
upstream = 0.10

# Reconnection priorities
[mesh.connection.reconnection_priority]
global_nodes = 3       # Always maintain N global connections
upstream_providers = 5 # Keep connections to N upstream providers
frequent_routes = 3    # Keep connections to N frequently-used routes
```

### Priority Connection Targets

The system prioritizes connections in this order:

1. **Global nodes** - Required for network discovery
2. **Upstream providers** - Nodes with announced upstreams
3. **High-traffic peers** - Frequently-used route endpoints

---

## Protocol Messages

### Core Messages

| Message | Description |
|---------|-------------|
| `Hello` / `HelloAck` | Initial handshake with role, capabilities, network_id |
| `SeedListRequest` / `SeedListResponse` | Request full mesh topology |
| `RouteQuery` / `RouteResponse` | Discover routes to upstreams |
| `PeerHealthCheck` / `PeerHealthResponse` | Latency and status monitoring |
| `PeerLoadReport` | Periodic load metrics (CPU, memory, connections) |
| `RouteUsageReport` | Route traffic statistics |

### Message Flow

```
Edge Node Start
      │
      ▼
┌─────────────┐
│  Connect to │  Hello + network_id + global_node_key
│  Seed Node  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Request    │  SeedListRequest (full_mesh=true)
│  Seed List  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Receive    │  SeedListResponse {global_nodes, edge_nodes}
│  Topology   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Connect to │  Priority: global → upstream → high-traffic
│  Peers      │
└─────────────┘
       │
       ▼
┌─────────────┐
│  Ongoing    │  Periodic health checks & load reports
│  Health     │
└─────────────┘
```

---

## Bootstrap New Global Nodes

### Initial Setup

1. **Start first global node** with a global_node_key:

```toml
[mesh]
enabled = true
role = "global"
global_node_key = "my-secure-key"
bind_address = "0.0.0.0"
port = 5001
```

2. **Configure edge nodes** to use this global node as seed:

```toml
[mesh]
enabled = true
role = "edge"
network_id = "production"

[[mesh.seeds]]
address = "first-global-node.example.com:5001"
global_node_key = "my-secure-key"
network_id = "production"
```

3. **Start additional global nodes** - they can join via existing global nodes

### Verification Checklist

- [ ] Global node has `global_node_key` configured
- [ ] Edge node seeds include matching `global_node_key`
- [ ] Network IDs match between nodes
- [ ] Firewall allows TCP/UDP on mesh port
- [ ] Nodes can resolve each other's DNS names

---

## CLI Commands

MaluWAF provides mesh management commands:

### Generate a Global Node Key

```bash
maluwaf mesh generate-key
```

Generates a secure key for global node authentication.

### Bootstrap a New Global Node

```bash
# Basic bootstrap with auto-generated key
maluwaf mesh bootstrap-global

# With custom network ID
maluwaf mesh bootstrap-global --network-id production

# With custom bind address and port
maluwaf mesh bootstrap-global --bind-address 0.0.0.0 --port 5001

# Output to config file
maluwaf mesh bootstrap-global --output /etc/maluwaf/mesh-global.toml
```

This creates a mesh configuration for a new global node with:
- `enabled = true`
- `role = "global"`
- Auto-generated `global_node_key` (unless `--no-generate-key`)
- Specified `network_id`, `bind_address`, and `port`

### Print Example Configuration

```bash
# Print config with default seeds
maluwaf mesh print-config

# Print config without seeds
maluwaf mesh print-config --no-with-seeds
```

### Examples

**Create a global node configuration:**

```bash
maluwaf mesh bootstrap-global \
  --network-id production \
  --bind-address 0.0.0.0 \
  --port 5001 \
  --output /etc/maluwaf/mesh-global.toml
```

Then add to main config:

```toml
# /etc/maluwaf/main.toml
[tunnel.mesh]
# Include the generated config
__include = "mesh-global.toml"
```

Or copy the printed config into your main.toml:

```bash
maluwaf mesh bootstrap-global --network-id staging > /etc/maluwaf/mesh-staging.toml
```


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

