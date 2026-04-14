# Tunnel Support

MaluWAF supports multiple tunnel types for site-to-site connectivity and WAF clustering:

1. **WireGuard VPN** - Lightweight VPN for site-to-site connections
2. **WAF Peers** - Peer-to-peer communication between WAF instances
3. **QUIC Tunnels** - High-performance tunnels between WAF nodes

## WireGuard VPN

WireGuard provides fast, modern VPN functionality for connecting remote sites.

> **Note:** WireGuard support requires the `wireguard` feature flag at compile time:
> ```bash
> cargo build --release --features wireguard
> ```
> Without this feature, WireGuard functionality is stubbed and non-operational.

### Configuration

```toml
[tunnel]
enabled = true

[tunnel.vpn]
enabled = true
bind_address = "0.0.0.0"
port = 51820
interface = "wg0"
private_key = "your-private-key-here"

# Tunnel IP addresses
addresses = ["10.0.0.1/24", "fd00::1/64"]

# Peer configuration
[tunnel.vpn.peers]
public_key = "peer-public-key"
allowed_ips = ["10.0.0.0/24", "192.168.0.0/16"]
endpoint = "peer.example.com:51820"
persistent_keepalive = 25
enabled = true
```

### Generating Keys

```bash
# Generate WireGuard key pair
wg genkey | tee private.key | wg pubkey > public.key
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable WireGuard VPN |
| `bind_address` | `"0.0.0.0"` | Bind address |
| `port` | `51820` | WireGuard listen port |
| `interface` | `"wg0"` | Interface name |
| `private_key` | - | Base64-encoded private key |
| `addresses` | - | Tunnel IP addresses (CIDR) |
| `persistent_keepalive` | `25` | Keep-alive interval (seconds) |

### Multiple Peers

```toml
[tunnel.vpn.peers.office1]
public_key = "office1-public-key"
allowed_ips = ["10.0.1.0/24"]
endpoint = "office1.example.com:51820"
persistent_keepalive = 25

[tunnel.vpn.peers.office2]
public_key = "office2-public-key"
allowed_ips = ["10.0.2.0/24"]
endpoint = "office2.example.com:51820"
persistent_keepalive = 25
```

## WAF Clustering (Peers)

Connect multiple MaluWAF instances for shared threat intelligence and coordinated protection.

### Basic Configuration

```toml
[tunnel.waf_peers]
enabled = true
bind_address = "0.0.0.0"
port = 5001
allow_unauthenticated = false
require_tls = true
```

### Peer Configuration

```toml
[tunnel.waf_peers.peers.waf2]
address = "10.0.1.20:5001"
auth_token = "shared-secret-between-wafs"
weight = 100
enabled = true
```

### TLS Configuration

```toml
[tunnel.waf_peers]
client_cert_path = "/etc/maluwafwaf/certs/client.crt"
client_key_path = "/etc/maluwafwaf/certs/client.key"
ca_cert_path = "/etc/maluwafwaf/certs/ca.crt"
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable WAF peers |
| `bind_address` | `"0.0.0.0"` | Bind address |
| `port` | `5001` | Peer listen port |
| `allow_unauthenticated` | `false` | Accept unauthenticated peers |
| `require_tls` | `false` | Enforce TLS for connections |
| `client_cert_path` | - | TLS client certificate |
| `client_key_path` | - | TLS client key |
| `ca_cert_path` | - | CA certificate for peer verification |

### Shared Features

When peers are connected:
- **Blocklist Sharing** - Automatically share blocked IPs
- **Attack Intelligence** - Share detected attack patterns
- **Threat Level Sync** - Coordinate threat responses
- **Statistics** - Aggregate metrics across cluster

## QUIC Tunnels

High-performance QUIC-based tunnels for low-latency WAF-to-WAF communication.

### Server Configuration

```toml
[tunnel.quic]
enabled = true
bind_address = "0.0.0.0"
port = 51821
max_idle_timeout_secs = 300
keepalive_interval_secs = 25
dedicated_worker = true
max_concurrent_streams = 100

# TLS certificates
cert_path = "/etc/maluwafwaf/certs/tunnel.crt"
key_path = "/etc/maluwafwaf/certs/tunnel.key"
auto_generate_certs = true
cert_domain = "tunnel.maluwaf.local"

[tunnel.quic.server]
enabled = true
auth_token = "server-auth-token"

[tunnel.quic.server.mappings.web1]
listen_port = 8081
upstream = "10.0.1.10:80"
```

### Client Configuration

```toml
[tunnel.quic]
enabled = true

[tunnel.quic.client]
enabled = true
auth_token = "client-auth-token"

[tunnel.quic.client.connections.web1]
address = "tunnel.example.com:51821"
upstream = "10.0.1.10:80"
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable QUIC tunnels |
| `bind_address` | `"0.0.0.0"` | Bind address |
| `port` | `51821` | QUIC listen port |
| `max_idle_timeout_secs` | `300` | Connection idle timeout |
| `keepalive_interval_secs` | `25` | Keep-alive interval |
| `dedicated_worker` | `true` | Use dedicated worker |
| `max_concurrent_streams` | `100` | Max concurrent streams |
| `cert_path` | - | TLS certificate path |
| `key_path` | - | TLS key path |
| `auto_generate_certs` | `false` | Auto-generate certificates |

## Prometheus Metrics

### WireGuard Metrics
```bash
maluwaf_tunnel_wireguard_peers  # Active peers
maluwaf_tunnel_wireguard_bytes  # Bytes transferred
```

### QUIC Tunnel Metrics
```bash
maluwaf_tunnel_quic_server_enabled    # Server status
maluwaf_tunnel_quic_server_connections # Active connections
maluwaf_tunnel_quic_client_connections  # Client connections
maluwaf_tunnel_quic_health_rtt          # Round-trip time
maluwaf_tunnel_quic_health_monitored_connections
maluwaf_tunnel_quic_health_recovered    # Recovered connections
maluwaf_tunnel_quic_health_failures     # Connection failures
maluwaf_tunnel_quic_sessions            # Active sessions

# TCP tunnel metrics
maluwaf_tcp_quic_tunnel_streams_opened
maluwaf_tcp_quic_tunnel_streams_closed
```

## Use Cases

### Use Case 1: Distributed WAF Deployment

Deploy WAFs at multiple locations with shared intelligence:

```
[Location A]                [Location B]
WAF (10.0.0.1) <---------> WAF (10.0.0.2)
     |                           |
     v                           v
[Web Servers]            [Web Servers]
```

### Use Case 2: WAF Behind NAT

Use QUIC tunnels to connect WAFs behind NAT firewalls:

```
Internet ---> [WAF Front] ----QUIC Tunnel----> [WAF Backend]
                                                 |
                                                 v
                                            [Internal App]
```

### Use Case 3: Site-to-Site VPN

Protect internal services with WireGuard:

```
Office A (10.0.0.0/24) <=== WireGuard ===> Office B (10.0.1.0/24)
```

## Troubleshooting

### Peer Connection Issues

```bash
# Check peer status via admin API
curl -H "Authorization: Bearer <token>" http://localhost:8081/api/probes
```

### QUIC Tunnel Not Connecting

1. Verify UDP port 51821 is open
2. Check TLS certificates are valid
3. Verify auth tokens match

### WireGuard Interface Issues

```bash
# Check WireGuard interface
wg show wg0

# Check routing
ip route show
```

## Security Considerations

1. **TLS Certificates** - Use valid certificates or properly configured self-signed certs
2. **Auth Tokens** - Use strong, unique tokens for each peer
3. **Network Isolation** - Run tunnel networks on isolated segments
4. **Firewall Rules** - Restrict peer connections to known IPs

## See Also

- [WAF_MESH.md](./WAF_MESH.md) - WAF mesh networking
- [HTTP3.md](./HTTP3.md) - HTTP/3 and QUIC support
- [CONFIGURATION.md](./CONFIGURATION.md) - Tunnel configuration options
- [SECURITY.md](./SECURITY.md) - Security hardening
