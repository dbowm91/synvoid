# Rate Limiting

SynVoid provides flexible rate limiting to protect your services from abuse, DoS attacks, and excessive usage.

## Overview

Rate limiting operates at multiple levels:

```
Request → Per-IP Limit → Global Limit → Endpoint Limit → Allow/Block
```

## Configuration Levels

### Global Defaults

Apply rate limiting to all sites:

```toml
[defaults.ratelimit]
enabled = true
mode = "shared"  # "shared" (global state) or "isolated" (per-worker)

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
per_hour = 500
burst = 20
```

### Site-Specific

Override for specific sites:

```toml
[site.ratelimit]
enabled = true
mode = "isolated"

[site.ratelimit.ip]
per_second = 5
per_minute = 30
per_hour = 200
burst = 10
```

### Endpoint-Specific

Different limits for specific paths:

```toml
[site.ratelimit.endpoints]
"/api/auth/login" = { per_minute = 5, burst = 1 }
"/api/auth/register" = { per_minute = 3, burst = 1 }
"/api/search" = { per_minute = 30, burst = 5 }
```

### Authenticated Users

Different limits for logged-in users:

```toml
[site.ratelimit.authenticated]
per_second = 100
per_minute = 1000
per_hour = 10000
burst = 50
```

## Rate Limit Modes

### Shared Mode

- Global rate limit state across all workers
- More accurate (exact request counts)
- Slight overhead for state synchronization

```toml
[defaults.ratelimit]
mode = "shared"
```

### Isolated Mode

- Per-worker rate limits
- Lower overhead
- Slightly less accurate (each worker has independent counters)

```toml
[defaults.ratelimit]
mode = "isolated"
```

**Recommendation:** Use `shared` for accuracy in most cases. Use `isolated` for high-throughput scenarios where slight inaccuracy is acceptable.

## Rate Limit Response

Configure how rate-limited requests are handled:

```toml
[site.ratelimit]
response_code = 429
response_message = "Rate limit exceeded. Please try again later."
retry_after_header = true
```

| Option | Default | Description |
|--------|---------|-------------|
| `response_code` | 429 | HTTP status code to return |
| `response_message` | "Rate limit exceeded" | Response body |
| `retry_after_header` | true | Include `Retry-After` header |

## Memory Management

Rate limiting tracks IPs in memory. Configure limits:

```toml
[defaults.rate_limit_memory]
max_ips = 100000
cleanup_interval_secs = 60
```

| Option | Default | Description |
|--------|---------|-------------|
| `max_ips` | 100000 | Maximum IPs to track |
| `cleanup_interval_secs` | 60 | How often to clean up stale entries |

## Use Cases

### Protect Public API

```toml
[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 100
burst = 20
```

### Login Protection

Prevent brute force attacks on login endpoints:

```toml
[site.ratelimit.endpoints]
"/api/auth/login" = { per_minute = 5, burst = 3 }
"/api/auth/password-reset" = { per_minute = 3, burst = 1 }
```

### Heavy Users

Allow higher limits for authenticated users:

```toml
[site.ratelimit]
enabled = true

[site.ratelimit.ip]
per_minute = 60

[site.ratelimit.authenticated]
per_minute = 1000
```

### Global Protection

Add a global rate limit on top of per-IP limits:

```toml
[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10

[defaults.ratelimit.global]
per_second = 1000  # Max 1000 req/s across all clients
```

## Testing Rate Limiting

```bash
# Make requests until rate limited
for i in {1..70}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Host: api.example.com" \
    http://localhost/api/data
done

# Should see: 200, 200, ... 200, 429
```

## Troubleshooting

### Too Many False Positives

1. Increase limits:
```toml
[defaults.ratelimit.ip]
per_minute = 200  # Increase from default
```

2. Add IP to whitelist:
```toml
[defaults.ratelimit.whitelist]
ip_ranges = ["YOUR_IP/32"]
```

### High Memory Usage

Reduce the number of tracked IPs:

```toml
[defaults.rate_limit_memory]
max_ips = 50000
```

### Rate Limiting Not Working

1. Verify it's enabled:
```toml
[defaults.ratelimit]
enabled = true
```

2. Check mode matches your use case
3. Ensure burst allowance isn't too high

## Integration with Threat Level

Rate limiting integrates with the adaptive threat level system:

```toml
[threat_level]
enabled = true

[threat_level.rate_limit_weight]
baseline = 1.0
```

When threat level increases, rate limits are automatically tightened.

## Metrics

Track rate limiting via Prometheus:

```
synvoid_ratelimit_exceeded_total          # Total rate limit hits
synvoid_ratelimit_exceeded{limit="ip"}    # Per-IP limits
synvoid_ratelimit_exceeded{limit="global"} # Global limits
synvoid_ratelimit_active                  # Currently rate-limited IPs
```

## See Also

- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level flood protection
- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [THREAT_LEVEL.md](./THREAT_LEVEL.md) - Adaptive rate limiting
- [CONFIGURATION.md](./CONFIGURATION.md) - Rate limiting configuration
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging rate limit issues
