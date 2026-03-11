# Upstream Health Checking

MaluWAF continuously monitors the health of your upstream servers and automatically removes unhealthy backends from the pool. This document explains how health checking works and how to configure it.

## Overview

Health checking ensures that traffic is only routed to working upstream servers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Upstream Pool                             │
│                                                              │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│   │  Backend A  │   │  Backend B  │   │  Backend C  │      │
│   │  ✓ Healthy  │   │  ✗ Failed   │   │  ✓ Healthy  │      │
│   └─────────────┘   └─────────────┘   └─────────────┘      │
│                                                              │
│   Health checks run every 30s                                │
│   Backend B removed from pool                                │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Basic Health Check

```toml
[site.upstream]
default = "http://127.0.0.1:8000"

# Health check settings
health_check_path = "/health"
health_check_interval_secs = 30
health_check_timeout_secs = 5
```

### Advanced Configuration

```toml
[site.upstream]
default = "http://127.0.0.1:8000"

# Check settings
health_check_path = "/health"
health_check_method = "HEAD"  # HEAD, GET, or TCP
health_check_interval_secs = 30
health_check_timeout_secs = 5
health_check_port = 8000  # Optional: different port for health checks

# Failure thresholds
health_check_failures = 3  # Consecutive failures before marking unhealthy
health_check_successes = 2  # Consecutive successes before marking healthy

# What to check
health_check_expected_status = 200  # Expected HTTP status code
```

## Health Check Methods

### HTTP HEAD (Default)

The most efficient method - sends a HEAD request and checks for successful response:

```toml
health_check_method = "HEAD"
health_check_path = "/health"
health_check_expected_status = 200
```

**Pros:** Lightweight, no response body transferred
**Cons:** Requires health endpoint on upstream

### HTTP GET

Similar to HEAD but gets the full response:

```toml
health_check_method = "GET"
health_check_path = "/healthz"
```

**Pros:** Can validate response body
**Cons:** Slightly more resource intensive

### TCP Connect

Only tests if the port is reachable:

```toml
health_check_method = "TCP"
```

**Pros:** Works for any TCP service
**Cons:** Doesn't validate application health

## How Health Checking Works

### State Machine

```
┌─────────────────────────────────────────────────────────────┐
│                    Health Check Flow                         │
└─────────────────────────────────────────────────────────────┘

                    ┌──────────────────┐
                    │   Initial State  │
                    │    "Healthy"     │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Run Health     │
                    │     Check       │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌──────────┐   ┌──────────┐   ┌──────────┐
       │ Success  │   │  Timeout │   │  Error   │
       └────┬─────┘   └────┬─────┘   └────┬─────┘
            │              │              │
            ▼              ▼              ▼
     ┌───────────┐  ┌───────────┐  ┌───────────┐
     │successes++│  │failures++ │  │failures++ │
     └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
           │              │              │
           ▼              ▼              ▼
     ┌───────────┐  ┌───────────┐  ┌───────────┐
     │   >= 2   │  │    >= 3   │  │    >= 3   │
     │successes?│  │failures? │  │failures? │
     └─────┬─────┘  └────┬──────┘  └────┬──────┘
           │             │               │
           ▼             ▼               ▼
      ┌────────┐   ┌──────────┐   ┌─────────────┐
      │Healthy │   │Unhealthy │   │ Remove from │
      │        │   │          │   │   Pool     │
      └────────┘   └──────────┘   └─────────────┘
```

### Default Behavior

| Scenario | Consecutive Failures | Action |
|----------|---------------------|--------|
| Backend fails health check 3 times | 3 | Mark as unhealthy |
| Backend passes health check 2 times | 0 | Mark as healthy |
| All backends unhealthy | - | Use all (degraded) |

## Per-Backend Configuration

You can configure health checks per upstream:

```toml
[site.upstream.backends.backend1]
url = "http://10.0.0.1:8000"
weight = 100

[site.upstream.backends.backend1.health_check]
enabled = true
path = "/health"
interval = 30

[site.upstream.backends.backend2]
url = "http://10.0.0.2:8000"
weight = 100

[site.upstream.backends.backend2.health_check]
enabled = false  # Disable health check for this backend
```

## Health Check Endpoint Requirements

### Minimal Health Endpoint

Your upstream should implement a simple health endpoint:

```python
# Flask example
@app.route('/health')
def health():
    return {'status': 'ok'}, 200
```

```javascript
// Express example
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});
```

### Deep Health Checks

For more thorough health validation:

```python
@app.route('/health')
def health():
    # Check database
    db_ok = check_database_connection()
    
    # Check cache
    cache_ok = check_redis_connection()
    
    if db_ok and cache_ok:
        return {'status': 'ok', 'db': 'ok', 'cache': 'ok'}, 200
    else:
        return {'status': 'degraded', 'db': db_ok, 'cache': cache_ok}, 503
```

## Integration with Load Balancing

Health checking works with all load balancing methods:

### Round Robin

```toml
[site.upstream]
load_balancing = "round_robin"
health_check_path = "/health"
```

### Least Connections

```toml
[site.upstream]
load_balancing = "least_conn"
health_check_path = "/health"
```

### IP Hash

```toml
[site.upstream]
load_balancing = "ip_hash"
health_check_path = "/health"
```

Unhealthy backends are excluded from all methods.

## Monitoring

### Prometheus Metrics

```bash
# View upstream health metrics
curl http://localhost:9090/metrics | grep upstream

# Key metrics:
maluwaf_upstream_health_status{backend="http://10.0.0.1:8000"}  # 1 = healthy
maluwaf_upstream_rerequests_total  # Requests retried due to unhealthy backend
```

### Admin API

```bash
# Get upstream status
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/upstreams

# Response:
{
  "backends": [
    {
      "url": "http://10.0.0.1:8000",
      "healthy": true,
      "consecutive_failures": 0,
      "consecutive_successes": 5
    },
    {
      "url": "10.0.0.2:8000",
      "healthy": false,
      "consecutive_failures": 3,
      "consecutive_successes": 0
    }
  ]
}
```

## Troubleshooting

### Backend Marked Unhealthy But Works

1. **Check health endpoint** - Ensure it returns expected status
2. **Increase timeout** - Backend might be slow to respond
3. **Check firewall** - Ensure WAF can reach backend port

```toml
health_check_timeout_secs = 10  # Increase from default 5s
```

### Too Many False Positives

1. **Increase failure threshold** - Require more consecutive failures
2. **Decrease check interval** - More frequent checks catch issues faster
3. **Use TCP check** - If HTTP overhead is causing issues

```toml
health_check_failures = 5  # Require 5 failures
health_check_interval_secs = 10  # Check every 10 seconds
```

### Health Check Not Running

1. Verify health check is enabled
2. Check that backend URL is correct
3. Review logs for health check errors

```bash
# Enable debug logging
RUST_LOG=debug ./maluwaf

# Look for health check messages
tail -f /var/log/maluwaf.log | grep -i health
```

### All Backends Unhealthy

When all backends are unhealthy, MaluWAF will:
1. Continue routing to backends (degraded mode)
2. Log warnings
3. Attempt to recover connections periodically

## Best Practices

1. **Implement health endpoints** - Add `/health` to all upstreams
2. **Return 200 for healthy** - Simple and clear
3. **Return 503 for degraded** - MaluWAF can optionally use this
4. **Keep it fast** - Health checks should respond in <1 second
5. **Don't require auth** - Health endpoints should be unauthenticated
6. **Separate from liveness** - Consider `/health` (app) vs `/live` (process)

## Example: Complete Upstream Configuration

```toml
[site.upstream]
default = "http://127.0.0.1:8000"

# Load balancing
load_balancing = "least_conn"

# Health checking
health_check_path = "/health"
health_check_method = "HEAD"
health_check_interval_secs = 30
health_check_timeout_secs = 5
health_check_failures = 3
health_check_successes = 2
health_check_expected_status = 200

# Retry configuration
max_retries = 3
retry_timeout_secs = 10

[site.upstream.backends.backend1]
url = "http://10.0.0.1:8000"
weight = 100

[site.upstream.backends.backend2]
url = "http://10.0.0.2:8000"
weight = 100

[site.upstream.backends.backend3]
url = "http://10.0.0.3:8000"
weight = 50  # Lower weight - older/smaller instance
```

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Upstream configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging upstream issues
- [PERFORMANCE.md](./PERFORMANCE.md) - Connection pooling and load balancing
