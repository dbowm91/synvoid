# Traffic Shaping

MaluWAF provides token bucket-based traffic shaping to control bandwidth allocation, prevent resource exhaustion, and ensure fair distribution of resources across sites and clients.

## Overview

Traffic shaping uses token bucket algorithms to:
- **Limit bandwidth** per site or IP
- **Control burst traffic** 
- **Prioritize traffic** based on rules
- **Prevent DoS** through bandwidth limits

## How It Works

### Token Bucket Algorithm

```
┌────────────────────────────────────────────────────────┐
│                   Token Bucket                         │
│                                                        │
│    Tokens added at rate:                               │
│    ┌──────────────┐                                    │
│    │   refill     │  rate = max_rate_mbps             │
│    │   rate       │  burst = burst_mbps               │
│    └──────────────┘                                    │
│         │                                               │
│         v                                               │
│    ┌─────────────────────────────────────────────┐     │
│    │              Bucket (tokens)                │     │
│    │   Capacity: burst_mbps                      │     │
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
max_rate_mbps = 1000      # Maximum rate in Mbps
burst_mbps = 1500         # Burst allowance in Mbps

# Per-IP limits
[traffic_shaping.per_ip]
max_rate_mbps = 100       # Per-IP limit
burst_mbps = 150
```

### Per-Site Traffic Shaping

```toml
# config/sites/example.com.toml
[site.traffic_shaping]
enabled = true
max_rate_mbps = 100       # Site-specific limit
burst_mbps = 150
```

### Site-Specific Overrides

```toml
# config/sites/high-traffic.com.toml
[site.traffic_shaping]
enabled = true
max_rate_mbps = 500       # Higher limit for this site
burst_mbps = 750
```

## Configuration Options

### Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable traffic shaping |
| `max_rate_mbps` | `0` (unlimited) | Maximum rate in Mbps |
| `burst_mbps` | `0` (no burst) | Burst allowance in Mbps |

### Per-IP Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable per-IP shaping |
| `max_rate_mbps` | `100` | Per-IP maximum rate |
| `burst_mbps` | `150` | Per-IP burst allowance |

### Per-Site Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable site shaping |
| `max_rate_mbps` | `100` | Site maximum rate |
| `burst_mbps` | `150` | Site burst allowance |

## Use Cases

### Use Case 1: Prevent Single Site Dominance

Limit a single site from consuming all bandwidth:

```toml
# Default for all sites
[defaults.traffic_shaping]
enabled = true
max_rate_mbps = 100
burst_mbps = 150

# Exception for API site
[site.traffic_shaping]
enabled = true
max_rate_mbps = 500
burst_mbps = 750
```

### Use Case 2: Per-Client Limits

Prevent individual clients from overwhelming the system:

```toml
[traffic_shaping.per_ip]
enabled = true
max_rate_mbps = 10
burst_mbps = 20
```

### Use Case 3: Priority Traffic

Give certain traffic priority:

```toml
# Higher priority for API endpoints
[site.traffic_shaping]
enabled = true
priority = "high"
max_rate_mbps = 500
burst_mbps = 750
```

### Use Case 4: Global Rate Limiting

Protect upstream servers:

```toml
[traffic_shaping.global]
enabled = true
max_rate_mbps = 1000  # Cap total throughput
burst_mbps = 1500
```

## Traffic Shaping vs Rate Limiting

| Feature | Traffic Shaping | Rate Limiting |
|---------|-----------------|---------------|
| **Purpose** | Smooth traffic flow | Block excess requests |
| **Mechanism** | Token bucket | Sliding window/counter |
| **Behavior** | Queues excess | Drops excess |
| **Granularity** | Bandwidth (Mbps) | Requests per second |
| **Use Case** | Protect bandwidth | Protect resources |

## Prometheus Metrics

```bash
maluwaf_traffic_shaper_packets_total     # Total packets processed
maluwaf_traffic_shaper_packets_dropped   # Dropped packets
maluwaf_traffic_shaper_packets_queued    # Queued packets
maluwaf_traffic_shaper_tokens_available  # Available tokens
maluwaf_traffic_shaper_bucket_empty_total # Bucket empty events
maluwaf_traffic_shaper_wait_seconds      # Wait time in queue
```

## Monitoring

### Check Current Shaping Status

```bash
# Via Prometheus
maluwaf_traffic_shaper_packets_dropped
maluwaf_traffic_shaper_packets_queued
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

| Scenario | Max Rate | Burst |
|----------|----------|-------|
| Development | 10 Mbps | 15 Mbps |
| Small Site | 50 Mbps | 75 Mbps |
| Medium Site | 100 Mbps | 150 Mbps |
| Large Site | 500 Mbps | 750 Mbps |
| Enterprise | 1000 Mbps | 1500 Mbps |

## Troubleshooting

### High Latency Under Load

If clients experience high latency:

1. Check for shaping bottleneck
2. Increase `max_rate_mbps`
3. Consider upgrading upstream

### Requests Being Dropped

If legitimate traffic is dropped:

1. Increase burst allowance
2. Check per-IP limits
3. Review traffic patterns

### Not Working

1. Ensure shaping is enabled
2. Verify limits are set (not 0)
3. Check metrics are incrementing

## Integration with Other Features

### Traffic Shaping + Rate Limiting

Use both for comprehensive protection:

```toml
# Traffic shaping (bandwidth)
[traffic_shaping]
enabled = true
max_rate_mbps = 100

# Rate limiting (requests)
[defaults.ratelimit]
enabled = true
[defaults.ratelimit.ip]
per_second = 10
```

### Traffic Shaping + Proxy Cache

Traffic shaping works with caching:

```toml
[proxy_cache]
enabled = true

[traffic_shaping]
enabled = true
max_rate_mbps = 100
```

Cached responses don't count against shaping limits.

## Advanced Configuration

### Site Priority

```toml
[site.traffic_shaping]
enabled = true
priority = "high"  # high, medium, low
max_rate_mbps = 500
```

### Queue Management

```toml
[traffic_shaping.queue]
max_size = 1000
timeout_secs = 30
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
