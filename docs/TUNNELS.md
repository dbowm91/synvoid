# Tunnel Support

> **Note:** WireGuard support is feature-gated (`wireguard` feature). The kernel backend is stubbed (`is_kernel_wireguard_available()` hardcodes `false`, and no `wireguard-control` dependency exists); the userspace boringtun backend is implemented but only reachable when a TUN device is present. QUIC Tunnels are the primary production transport for site-to-site connectivity.

SynVoid supports multiple tunnel types for site-to-site connectivity and WAF clustering:

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
cert_path = "/etc/synvoid/certs/tunnel.crt"
key_path = "/etc/synvoid/certs/tunnel.key"
auto_generate_certs = false          # default: false
cert_domain = "tunnel.synvoid.local"

[tunnel.quic.server]
enabled = true
auth_token = "server-auth-token"

# Mappings are `name -> PortMappingConfig`, which uses `port` (not
# `listen_port`), `protocol`, `upstream_host`, and `upstream_port`
# (not a single `upstream` string).
[tunnel.quic.server.mappings.web1]
port = 8081
protocol = "tcp"
upstream_host = "10.0.1.10"
upstream_port = 80
```

### Client Configuration

```toml
[tunnel.quic]
enabled = true

[tunnel.quic.client]
enabled = true
client_id = "edge-a"
auth_token = "client-auth-token"

# Peers are `name -> TunnelQuicPeerConfig`; the key is `peers`, not
# `connections`.
[tunnel.quic.client.peers.web1]
address = "tunnel.example.com:51821"
auth_token = "client-auth-token"
enabled = true
upstream_host = "10.0.1.10"
upstream_port = 80
```

### Configuration Options

`TunnelQuicConfig` (`crates/synvoid-config/src/tunnel.rs:121`):

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable QUIC tunnels |
| `bind_address` | `"0.0.0.0"` | Bind address |
| `port` | `51821` | QUIC listen port |
| `max_idle_timeout_secs` | `300` | Connection idle timeout |
| `keepalive_interval_secs` | `25` | Keep-alive interval |
| `dedicated_worker` | `true` | Use dedicated worker |
| `max_concurrent_streams` | `100` | Max concurrent streams (must be > 0; validated) |
| `cert_path` | none | TLS certificate path |
| `key_path` | none | TLS key path |
| `auto_generate_certs` | `false` | Auto-generate certificates |
| `cert_domain` | none | Domain for auto-generated certificates |
| `client_ca` | none | Client CA for mutual TLS |
| `whitelist` | `[]` | Allowed peer addresses |
| `congestion_control` | `"bbr"` | One of `bbr`, `cubic`, `new_reno` (validated) |
| `initial_congestion_window` | `32` | Initial congestion window |
| `stream_receive_window` / `connection_receive_window` | see `default_stream_receive_window` / `default_connection_receive_window` | Flow-control windows |
| `max_stream_buffer_size` / `max_message_size` | `1048576` each | Stream buffer / message size caps |
| `udp_tunnel_timeout_secs` | `60` | UDP tunnel idle timeout |
| `udp_max_datagram_size` | `1200` | Max UDP datagram size |
| `high_throughput_mode` | `false` | High-throughput tuning |
| `tls_passthrough` | `false` | Passthrough mode |

Server sub-config (`TunnelQuicServerConfig`) also carries `mappings`, `clients`, `vpn_access`, `require_client_cert`, `allow_unauthenticated`, `allow_unauthenticated_confirmation`, `max_connections`, and `auth_rate_limit_max_attempts`.

## Prometheus Metrics

### QUIC Tunnel Metrics

The runtime emits dotted `metrics`-crate names; the Prometheus exporter sanitizes `.` to `_`.

```bash
synvoid_tunnel_quic_enabled
synvoid_tunnel_quic_server_enabled
synvoid_tunnel_quic_server_connections
synvoid_tunnel_quic_server_active_sessions
synvoid_tunnel_quic_server_auth_failures
synvoid_tunnel_quic_server_access_denied
synvoid_tunnel_quic_client_enabled
synvoid_tunnel_quic_client_connected
synvoid_tunnel_quic_client_connections
synvoid_tunnel_quic_client_sessions
synvoid_tunnel_quic_client_peers
synvoid_tunnel_quic_health_rtt
synvoid_tunnel_quic_health_monitored_connections
synvoid_tunnel_quic_health_recovered
synvoid_tunnel_quic_health_failures

# Stream / datagram / UDP
synvoid_tunnel_quic_client_streams_opened
synvoid_tunnel_quic_client_streams_closed
synvoid_tunnel_quic_client_streams_proxied
synvoid_tunnel_quic_client_udp_tunnels_opened
synvoid_tunnel_quic_datagrams_sent
synvoid_tunnel_quic_datagrams_received
synvoid_tunnel_udp_tunnels_active

# TCP tunnel metrics
synvoid_tcp_quic_tunnel_streams_opened
synvoid_tcp_quic_tunnel_streams_closed

# WireGuard (stubbed backend — metrics exist, functionality does not)
synvoid_tunnel_wireguard_running
synvoid_tunnel_wireguard_server_enabled
```

Note the earlier `synvoid_tunnel_quic_sessions` name does not exist; the session gauges are `synvoid_tunnel_quic_server_active_sessions` and `synvoid_tunnel_quic_client_sessions`.

## WireGuard (Feature-Gated, Stubbed)

WireGuard support is behind the `wireguard` Cargo feature (which pulls in `defguard_boringtun`; `wireguard-control` is **not** a dependency in the current manifest). The kernel backend is stubbed; the userspace backend is implemented but gated on TUN availability:

- **Kernel backend** (`wireguard/kernel.rs`): `is_kernel_wireguard_available()` returns a hardcoded `false`, and `get_wireguard_stats` returns an error. No `wireguard-control` / netlink dependency exists.
- **Userspace backend** (`wireguard/userspace.rs`): Uses `defguard_boringtun` for Noise framing with a working `start_boringtun()` path. It is selected only when `is_userspace_available()` is true, which requires both the `wireguard` feature and a TUN device node (`/dev/net/tun` on Linux, `/dev/tun` on macOS/BSD; always false on other platforms).
- **TUN device** (`wireguard/tun.rs`): Linux/BSD/macOS paths attempt a real TUN open; the remaining platforms return `io::ErrorKind::Unsupported` / `Unsupported` errors with "TUN support requires platform-specific dependencies (not yet available)".

So on a Linux host with `/dev/net/tun` and `--features wireguard`, the userspace backend is reachable; on a host without a TUN node, or without the feature, WireGuard remains unavailable.

To compile with the WireGuard feature: `cargo check -p synvoid-tunnel --features wireguard`

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
# Check mesh peer status via admin API
curl -H "Authorization: Bearer <token>" http://localhost:8081/api/mesh/nodes
```

(`/api/probes` lists honeypot probe records, not tunnel peers.)

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
