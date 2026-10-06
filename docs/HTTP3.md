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
prefer_post_quantum = true  # Telemetry only; post-quantum KEX is always compiled in

[http3]
enabled = true
port = 443
host_v6 = "::"
alt_svc_max_age = 86400
```

### Configuration Options

`Http3Config` (`crates/synvoid-config/src/http.rs`) has exactly five fields:

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable HTTP/3 support |
| `port` | `443` | HTTP/3 listen port |
| `host_v6` | none | IPv6 bind address (`::`); IPv4 uses the `[server] host` |
| `alt_svc_max_age` | `86400` | Alt-Svc header max-age (seconds) |
| `max_request_size` | `10485760` (10 MiB) | Request body cap enforced before buffering (`http3_body.rs`) |

There is no `quic_enable_0rtt` on `[http3]`, and `prefer_post_quantum` belongs to `[tls]`, not `[http3]`. The only 0-RTT switch in the codebase is `quic_enable_0rtt` on `[mesh.tls]` (default `false`), which governs the mesh QUIC transport; `synvoid-http3` contains no 0-RTT code path.

`prefer_post_quantum` (under `[tls]`, default `true`) is telemetry only — it selects nothing. HTTP/3 listeners negotiate a hybrid PQ key exchange because `synvoid-tls` always compiles in rustls `prefer-post-quantum`; no setting turns it off. **Do not tune this, and do not add a `validate()` rejection for it** — it defaults to `true`, so a rejection would fail every default config (`architecture/dns_provider_inversion_phase140_closeout.md`).

## Per-Site HTTP/3

There is no `[site.http3]` section — it parses but is silently ignored (`SiteConfig` has no `http3` field). Per-listener HTTP/3 is declared on the listen entry as `http3 = true`:

```toml
# config/sites/example.com.toml
[site]
domains = ["example.com", "www.example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"

[[site.listen]]
port = 443
ssl = true
http3 = true
```

HTTP/3 bind addresses are derived solely from `[http3]` and `[server] host` (`UnifiedServerStartupPlan::build`, `src/server/startup_plan.rs:120`): the listener spawns when `http3_config.enabled` is true, and per-site `http3` flags are not consulted. `SiteListenConfig::is_http3_enabled()` (`crates/synvoid-config/src/site/listen.rs:57`) is the only accessor for the per-listen field and has **zero callers** in the workspace, so treat `[[site.listen]] http3` as currently unreachable rather than as a working per-site control.

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

HTTP/3 metrics are emitted from `crates/synvoid-http3` through the `metrics` crate as dotted names. The Prometheus exporter sanitizes `.` to `_`, so the exposition names are:

```bash
synvoid_http3_connections                    # gauge: active connections
synvoid_http3_connections_total              # counter: accepted connections
synvoid_http3_request_duration               # histogram: seconds
synvoid_http3_responses                      # counter: responses produced

# Flood / connection protection
synvoid_http3_flood_limited
synvoid_http3_flood_blackhole
synvoid_http3_connection_limited

# Errors
synvoid_http3_connection_errors
synvoid_http3_request_errors
synvoid_http3_framing_rejected

# Request outcomes
synvoid_http3_requests_blocked
synvoid_http3_requests_challenged
synvoid_http3_requests_tarpitted
synvoid_http3_requests_not_found
synvoid_http3_request_body_too_large
synvoid_http3_blackhole_drop

# Routing / stall
synvoid_http3_requests_stalled
synvoid_http3_requests_stall_capped
synvoid_http3_enforcement_class_total         # labelled by class
synvoid_http3_request_streaming_path
synvoid_http3_request_unhandled_route_result
```

There is no `synvoid_http3_requests_total` metric; accepted-connection totals are `synvoid_http3_connections_total` and request outcomes are per-outcome counters.

The exporter listens on `[metrics] port` (default `9090`) bound to loopback — `bind_address` is validated to refuse non-loopback values (`crates/synvoid-config/src/admin.rs:264`).

### Stall Metrics

Three in-process stall counters live in `crates/synvoid-metrics/src/collection.rs`. They are in-memory statics with getters (`get_active_stalled_requests`, `get_stall_rejected_count`, `get_stall_timeouts`) — they are **not** Prometheus series; the observable Prometheus view is `synvoid_http3_requests_stalled` / `synvoid_http3_requests_stall_capped`:

| Internal counter | Type | Description |
|--------|------|-------------|
| `ACTIVE_STALLED_REQUESTS` | gauge | Currently active stall permits (released via `StallPermit` drop) |
| `STALL_REJECTED_CONCURRENCY_CAP` | counter | Permit acquisition rejected because cap was reached |
| `STALL_TIMEOUTS` | counter | Stall sleep completed (not incremented on cancellation/drop) |

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

`ProxyLimitsConfig` (`crates/synvoid-config/src/limits.rs`) has only two fields — there is no `max_connections`:

```toml
[proxy_limits]
max_response_size = 10000000   # default: 10_000_000 bytes
connection_pool_size = 100     # default: 100
```

Per-site HTTP/3 connection limits are enforced by the shared flood/connection limiter (surfaced as `synvoid_http3_flood_limited` and `synvoid_http3_connection_limited`), not by a `[proxy_limits]` key.

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
