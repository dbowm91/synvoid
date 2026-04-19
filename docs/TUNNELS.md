# Tunnel Support

> **Note:** WireGuard VPN has been removed from the codebase. QUIC Tunnels are now the primary transport for site-to-site connectivity.

MaluWAF supports multiple tunnel types for site-to-site connectivity and WAF clustering:

1. **WAF Peers** - Peer-to-peer communication between WAF instances
2. **QUIC Tunnels** - High-performance tunnels between WAF nodes

## WAF Clustering

> **Note:** WAF clustering is now handled via QUIC mesh networking. See the [WAF Mesh documentation](./WAF_MESH.md) for details on peer-to-peer communication between WAF instances using the mesh network.

Previously, WAF clustering used a separate `[tunnel.waf_peers]` configuration. This has been replaced by the mesh networking layer which provides:
- **Shared Threat Intelligence** - Automatic propagation of blocked IPs and attack patterns
- **Coordinated Protection** - Real-time threat level synchronization across nodes
- **Aggregated Metrics** - Statistics shared across the cluster

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
