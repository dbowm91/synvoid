# Traffic Shaping

SynVoid provides token bucket-based traffic shaping to control bandwidth allocation, prevent resource exhaustion, and ensure fair distribution of resources across sites and clients.

## Overview

Traffic shaping uses token bucket algorithms to:
- **Limit bandwidth** per site
- **Control burst traffic**
- **Cap concurrent connections**
- **Prevent DoS** through bandwidth limits

There is no per-traffic-class priority mechanism in the shaper.

## How It Works

### Token Bucket Algorithm

```
┌────────────────────────────────────────────────────────┐
│                   Token Bucket                         │
│                                                        │
│    Tokens added at rate:                               │
│    ┌──────────────┐                                    │
│    │   refill     │  rate = ingress_max_mb_s           │
│    │   rate       │  burst = burst_allowance_mb         │
│    └──────────────┘                                    │
│         │                                               │
│         v                                               │
│    ┌─────────────────────────────────────────────┐     │
│    │              Bucket (tokens)                │     │
│    │   Capacity: burst_allowance_mb              │     │
│    │   Current: tokens available                │     │
│    └─────────────────────────────────────────────┘     │
│         │                                               │
│    Request arrives                                      │
│         │                                               │
│         v                                               │
│    If tokens >= cost:                                   │
│      - Allow request                                   │
│      - Remove tokens                                   │
│    Else:                                               │
│      - Queue or drop                                   │
└────────────────────────────────────────────────────────┘
```

## Configuration

### Global Traffic Shaping

```toml
[traffic_shaping]
enabled = true

# Global limits apply to all traffic
[traffic_shaping.global]
ingress_max_mb_s = 1000        # Maximum ingress rate in MB/s
egress_max_mb_s = 1000         # Maximum egress rate in MB/s
burst_allowance_mb = 100       # Burst allowance in MB
burst_refill_ms = 100          # Burst refill interval
attack_mode_multiplier = 0.5   # Limits scale by this while under attack

# Connection limits
[traffic_shaping.connection_limits]
max_connections = 1000
max_connections_per_ip = 10
connection_queue_size = 100
connection_queue_timeout_ms = 60000
connection_burst = 5
```

There is no `[traffic_shaping.per_ip]` section. Per-IP bandwidth limits are enforced by
the rate limiter and flood protector (see [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) and
[RATE_LIMITING.md](./RATE_LIMITING.md)), not by the traffic shaper.

### Per-Site Traffic Shaping

```toml
# config/sites/example.com.toml
[site.traffic_shaping]
enabled = true
ingress_max_mb_s = 100         # Site-specific ingress limit
egress_max_mb_s = 100          # Site-specific egress limit
burst_allowance_mb = 10
inherit = true
```

### Site-Specific Connection Overrides

```toml
# config/sites/high-traffic.com.toml
[site.traffic_shaping.connection]
max_connections = 5000
max_connections_per_ip = 50
connection_queue_size = 500
connection_burst = 10
```

## Configuration Options

### Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable traffic shaping |
| `global.ingress_max_mb_s` | `128` | Maximum ingress rate in MB/s |
| `global.egress_max_mb_s` | `128` | Maximum egress rate in MB/s |
| `global.burst_allowance_mb` | `10` | Burst allowance in MB |
| `global.burst_refill_ms` | `100` | Burst refill interval |
| `global.attack_mode_multiplier` | `0.5` | Limit scale factor while under attack |

### Connection Limit Options

| Option | Default | Description |
|--------|---------|-------------|
| `connection_limits.max_connections` | `1000` | Global concurrent connection cap |
| `connection_limits.max_connections_per_ip` | `10` | Concurrent connections per IP |
| `connection_limits.connection_queue_size` | `100` | Connection queue depth |
| `connection_limits.connection_queue_timeout_ms` | `60000` | Queue wait timeout |
| `connection_limits.connection_burst` | `5` | Connection burst allowance |

### Per-Site Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | inherit | Enable site shaping |
| `inherit` | `true` | Inherit global shaping values |
| `ingress_max_mb_s` | inherit | Site ingress rate limit |
| `egress_max_mb_s` | inherit | Site egress rate limit |
| `burst_allowance_mb` | inherit | Site burst allowance |
| `connection.max_connections` | inherit | Site connection cap |
| `connection.max_connections_per_ip` | inherit | Site per-IP connection cap |
| `connection.connection_queue_size` | inherit | Site queue depth |
| `connection.connection_burst` | inherit | Site burst allowance |

## Use Cases

### Use Case 1: Prevent Single Site Dominance

Limit a single site from consuming all bandwidth:

```toml
# Default for all sites
[defaults.traffic_shaping]
enabled = true
ingress_max_mb_s = 100
egress_max_mb_s = 100
burst_allowance_mb = 10

# Exception for API site
[site.traffic_shaping]
enabled = true
ingress_max_mb_s = 500
egress_max_mb_s = 500
burst_allowance_mb = 50
```

### Use Case 2: Per-Client Limits

The traffic shaper has no per-IP bandwidth section. Use connection limits instead:

```toml
[traffic_shaping.connection_limits]
max_connections_per_ip = 5
connection_burst = 2
```

For per-IP *request* rates see [RATE_LIMITING.md](./RATE_LIMITING.md).

### Use Case 3: Bandwidth Accounting

Account monthly transfer and act when the cap is reached:

```toml
[traffic_shaping.bandwidth]
monthly_cap_ingress_gb = 500
monthly_cap_egress_gb = 1000
action_on_limit = "block"     # "block" or "throttle"
retention_days = 365
mesh_excluded_from_total = false

[traffic_shaping.bandwidth.monthly_reset]
mode = "rolling30days"        # or "fixed_day"
fixed_day = 1
```

### Use Case 4: Global Rate Limiting

Protect upstream servers:

```toml
[traffic_shaping.global]
ingress_max_mb_s = 1000  # Cap total ingress
egress_max_mb_s = 1000
```

## Traffic Shaping vs Rate Limiting

| Feature | Traffic Shaping | Rate Limiting |
|---------|-----------------|---------------|
| **Purpose** | Smooth traffic flow | Block excess requests |
| **Mechanism** | Token bucket | Sliding window/counter |
| **Behavior** | Queues excess | Drops excess |
| **Granularity** | Bandwidth (Mbps) | Requests per second |
| **Use Case** | Protect bandwidth | Protect resources |

## Metrics

The traffic shaper exports no dedicated Prometheus series. Enforcement outcomes are counted
on the internal metrics registry:

```bash
synvoid.traffic.connection_limited   # Requests rejected by the connection limiter
synvoid.bandwidth.limit_exceeded     # Requests rejected by the bandwidth limiter
```

Bandwidth and cache counters are also aggregated to the admin API (`GET /api/stats`) as
`proxy_cache_hits` / `proxy_cache_misses` and `static_cache_hits` / `static_cache_misses`.

## Monitoring

### Check Current Shaping Status

```bash
synvoid.traffic.connection_limited
synvoid.bandwidth.limit_exceeded
```

### Identify Issues

1. **High Drop Rate** - Reduce limits or increase capacity
2. **High Queue Time** - Reduce traffic or increase bandwidth
3. **Bucket Empty** - Normal when under limit

## Performance Considerations

### Token Bucket Performance

- O(1) lookup for token availability
- Efficient per-connection tracking
- Minimal memory overhead

### Recommended Settings

| Scenario | Ingress/Egress | Burst |
|----------|----------------|-------|
| Development | 10 MB/s | 2 MB |
| Small Site | 50 MB/s | 5 MB |
| Medium Site | 100 MB/s | 10 MB |
| Large Site | 500 MB/s | 50 MB |
| Enterprise | 1000 MB/s | 100 MB |

Note the units: the config keys are **megabytes per second**, not megabits per second.

## Troubleshooting

### High Latency Under Load

If clients experience high latency:

1. Check for shaping bottleneck
2. Increase `ingress_max_mb_s` / `egress_max_mb_s`
3. Consider upgrading upstream

### Requests Being Dropped

If legitimate traffic is dropped:

1. Increase `burst_allowance_mb`
2. Check connection limits
3. Review traffic patterns

### Not Working

1. Ensure `[traffic_shaping] enabled = true` (this defaults to `true`)
2. Verify limits are set (not 0)
3. Check metrics are incrementing

## Integration with Other Features

### Traffic Shaping + Rate Limiting

Use both for comprehensive protection:

```toml
# Traffic shaping (bandwidth)
[traffic_shaping]
enabled = true
[traffic_shaping.global]
ingress_max_mb_s = 100

# Rate limiting (requests)
[defaults.ratelimit]
mode = "shared"
[defaults.ratelimit.ip]
per_second = 10
```

### Traffic Shaping + Proxy Cache

Traffic shaping works with caching:

```toml
[site.proxy.cache]
enable = true

[traffic_shaping]
enabled = true
[traffic_shaping.global]
ingress_max_mb_s = 100
```

Cached responses don't count against shaping limits.

## Advanced Configuration

### Tighten Under Attack

The shaper scales its limits down while the threat level is elevated, using
`attack_mode_multiplier`:

```toml
[traffic_shaping.global]
attack_mode_multiplier = 0.25   # Quarter the limits during an attack
```

### Queue Management

```toml
[traffic_shaping.connection_limits]
connection_queue_size = 1000
connection_queue_timeout_ms = 30000
```

## Best Practices

1. **Start Conservative** - Begin with generous limits
2. **Monitor** - Watch metrics during tuning
3. **Separate Networks** - Use separate shaping for internal/external
4. **Consider Peak** - Set limits above expected peak
5. **Test Thoroughly** - Load test before production

## See Also

- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Flood protection
- [CONFIGURATION.md](./CONFIGURATION.md) - Traffic shaping configuration
