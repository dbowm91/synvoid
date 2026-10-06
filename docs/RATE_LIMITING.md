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
mode = "isolated"

[site.ratelimit.ip]
per_second = 5
per_minute = 30
per_hour = 200
burst = 10
```

### Endpoint-Specific

Different limits for specific paths. `endpoints` is an **array of tables**, each entry
carrying its own `path_pattern`:

```toml
[[site.ratelimit.endpoints]]
path_pattern = "/api/auth/login"
per_minute = 5
burst = 1

[[site.ratelimit.endpoints]]
path_pattern = "/api/auth/register"
per_minute = 3
burst = 1

[[site.ratelimit.endpoints]]
path_pattern = "/api/search"
per_minute = 30
burst = 5
```

### Global Override Per Site

```toml
[site.ratelimit.global]
per_second = 500
per_minute = 5000
per_5min = 25000
max_connections = 10000
```

### Trusted Clients

Rate-limit exemptions are configured with the site whitelist, not under `[site.ratelimit]`:

```toml
[site.whitelist]
ips = ["10.0.0.1"]
networks = ["10.0.0.0/8"]
```

There is no `[site.ratelimit.authenticated]` section: SynVoid does not vary rate limits by
whether a request is authenticated.

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

The rate-limited response is **fixed in code** — it is not configurable. When a limit is
exceeded the request path returns `WafDecision::Block(429, "Too Many Requests")`
(`src/waf/mod.rs`).

```toml
# No such keys exist:
# [site.ratelimit]
# response_code = 429
# response_message = "Rate limit exceeded. Please try again later."
# retry_after_header = true
```

There is no `response_code`, `response_message` or `retry_after_header` key on
`[site.ratelimit]`, and the data-plane 429 does not carry a `Retry-After` header.
(`Retry-After` is emitted only by the admin API limiter, not by the site request path.)

## Memory Management

Rate limiting tracks IPs in memory. Configure limits:

```toml
[defaults.rate_limit_memory]
max_ip_entries = 100000
cleanup_interval_secs = 60
num_shards = 256
```

| Option | Default | Description |
|--------|---------|-------------|
| `max_ip_entries` | 100000 | Maximum IP entries to track |
| `cleanup_interval_secs` | 60 | How often to clean up stale entries |
| `num_shards` | 256 | Number of internal shards |

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
[[site.ratelimit.endpoints]]
path_pattern = "/api/auth/login"
per_minute = 5
burst = 3

[[site.ratelimit.endpoints]]
path_pattern = "/api/auth/password-reset"
per_minute = 3
burst = 1
```

### Heavy Users

There is no authenticated-user tier. To give a trusted set of clients higher limits, either
whitelist them:

```toml
[site.whitelist]
networks = ["10.0.0.0/8"]

[site.ratelimit.ip]
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
[site.whitelist]
ips = ["YOUR_IP"]
networks = ["YOUR_IP/32"]
```

There is no global `[defaults.whitelist]`; whitelist entries are configured per site.

### High Memory Usage

Reduce the number of tracked IPs:

```toml
[defaults.rate_limit_memory]
max_ip_entries = 50000
```

### Rate Limiting Not Working

1. Verify `[defaults.ratelimit]` (or `[site.ratelimit]`) is present — there is no `enabled`
   key to set
2. Check mode matches your use case
3. Ensure burst allowance isn't too high

## Integration with Threat Level

Rate limits contribute to the threat score (weight `1.5`, fixed in code) and a rate-limit
violation can escalate the threat level into a ban via `[threat_level.escalation]`. There is
no `[threat_level.rate_limit_weight]` section and rate limits are **not** automatically
tightened when the level rises; use `[threat_level.global_limits]` and
`[threat_level.ban_durations]` to set the per-level rate-limit and ban behavior.

## Metrics

Rate limiting exports these counters on the internal metrics registry:

```
synvoid.ratelimit.global_limited   # Global rate limit hits
synvoid.ratelimit.blackholed       # Requests dropped by blackhole mode
```

TCP-level enforcement adds `synvoid.tcp.ip_rate_limited`, `synvoid.tcp.rate_limited` and
`synvoid.tcp.blackhole_drop`. There are no per-IP or `active` counters; read live limiter
statistics from the admin API instead.

## See Also

- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level flood protection
- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [THREAT_LEVEL.md](./THREAT_LEVEL.md) - Adaptive rate limiting
- [CONFIGURATION.md](./CONFIGURATION.md) - Rate limiting configuration
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging rate limit issues
