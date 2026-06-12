# HTTP/3 (QUIC) Support

SynVoid provides full support for HTTP/3 (QUIC protocol), offering improved performance and security over traditional HTTP/2.

## Why HTTP/3?

HTTP/3 uses QUIC (Quick UDP Internet Connections) instead of TCP, providing:

- **0-RTT Connection Resumption** - Faster page loads for returning clients
- **No Head-of-Line Blocking** - Lost packets don't block other streams
- **Connection Migration** - Seamless switching between networks
- **Improved Security** - Built-in TLS 1.3 encryption
- **Lower Latency** - Reduced connection setup time

## Configuration

### Basic HTTP/3 Setup

```toml
[http3]
enabled = true
port = 443
host_v6 = "::"
alt_svc_max_age = 86400  # 24 hours in seconds
```

### Full TLS + HTTP/3 Configuration

```toml
[server]
host = "0.0.0.0"
port = 80
trusted_proxies = ["127.0.0.1", "::1"]

[tls]
enabled = true
cert_path = "/etc/synvoid/certs/server.crt"
key_path = "/etc/synvoid/certs/server.key"
port = 443
prefer_post_quantum = true  # Enable post-quantum key exchange

[http3]
enabled = true
port = 443
host_v6 = "::"
alt_svc_max_age = 86400
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable HTTP/3 support |
| `port` | `443` | HTTP/3 listen port |
| `host_v6` | - | IPv6 bind address |
| `alt_svc_max_age` | `86400` | Alt-Svc header max-age (seconds) |
| `quic_enable_0rtt` | `false` | Enable 0-RTT connection resumption. **Security note**: 0-RTT has replay attack risks and should be disabled in high-security environments |
| `prefer_post_quantum` | `false` | Use post-quantum key exchange (CRYSTALS-Kyber) for TLS. **Recommended**: Enable for long-term security against quantum computing threats. Protected traffic cannot be decrypted by quantum adversaries even if captured today |

## Per-Site HTTP/3

HTTP/3 can be enabled/disabled per-site:

```toml
# config/sites/example.com.toml
[site]
domains = ["example.com", "www.example.com"]

[site.http3]
enabled = true  # Enable HTTP/3 for this site
```

## How It Works

1. Client connects via HTTPS (HTTP/2 or HTTP/1.1)
2. Server responds with `Alt-Svc: h3=":443"; ma=86400` header
3. Client establishes QUIC connection on port 443
4. All subsequent requests use HTTP/3

```
Client                  SynVoid                Upstream
  |                         |                         |
  |--- HTTPS (HTTP/2) ----->|                         |
  |<-- Alt-Svc: h3=":443" -|                         |
  |                         |                         |
  |====== QUIC v3 =========|                         |
  |                         |--- HTTP/1.1 ----------->|
  |                         |<-- Response ------------|
  |<-- HTTP/3 Response ----|                         |
```

## Prometheus Metrics

HTTP/3-specific metrics available at port 9090:

```bash
# Active connections
synvoid_http3_connections

# Total requests
synvoid_http3_requests_total

# Request duration
synvoid_http3_request_duration_seconds

# Flood protection
synvoid_http3_flood_limited
synvoid_http3_connection_limited
synvoid_http3_flood_blackhole

# Errors
synvoid_http3_connection_errors
synvoid_http3_request_errors

# Response types
synvoid_http3_responses
synvoid_http3_requests_stalled
synvoid_http3_requests_stall_capped
synvoid_http3_requests_blocked
synvoid_http3_requests_challenged
synvoid_http3_requests_tarpitted
synvoid_http3_blackhole_drop
synvoid_http3_requests_not_found
synvoid_http3_request_body_too_large
```

## Troubleshooting

### Client Not Using HTTP/3

1. Verify HTTP/3 is enabled in config
2. Check TLS certificate is valid
3. Ensure firewall allows UDP port 443
4. Check client supports HTTP/3 (modern browsers)

### Alt-Svc Header Missing

```bash
# Check server response headers
curl -I -v https://example.com 2>&1 | grep -i alt-svc
```

### QUIC Connection Issues

1. Check UDP port 443 is open
2. Verify network supports QUIC
3. Check for middleboxes blocking QUIC

## Performance Tuning

### Recommended System Settings

```bash
# Increase UDP buffer sizes
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

# Allow faster connection cleanup
sysctl -w net.ipv4.tcp_fin_timeout=15
```

### Concurrent Connections

```toml
[proxy_limits]
max_connections = 50000
```

## Client Compatibility

| Client | HTTP/3 Support |
|--------|---------------|
| Chrome 90+ | Yes |
| Firefox 90+ | Yes |
| Safari 15+ | Yes |
| Edge 90+ | Yes |
| curl 7.75+ | Yes |

## Fallback Behavior

If HTTP/3 is unavailable, clients automatically fall back to HTTP/2 or HTTP/1.1:

1. HTTP/3 (QUIC on UDP 443)
2. HTTP/2 (TLS ALPN)
3. HTTP/1.1 (TLS)
4. HTTP/1.1 (plaintext)

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - HTTP/3 configuration options
- [TUNNELS.md](./TUNNELS.md) - QUIC tunnel support
- [PERFORMANCE.md](./PERFORMANCE.md) - HTTP/3 performance benefits
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - HTTP/3 connection issues
