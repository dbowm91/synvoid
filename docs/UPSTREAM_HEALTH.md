# Upstream Health Checking

SynVoid continuously monitors the health of your upstream servers and automatically removes unhealthy backends from the pool. This document explains how health checking works and how to configure it.

## Overview

SynVoid does **not** run active health probes against `[site.proxy.upstream]` backends.
`ProxyUpstreamConfig` (`crates/synvoid-config/src/site/proxy.rs`) has no health-check
fields at all — no `health_check_path`, `health_check_method`, `health_check_failures`,
or `health_check_expected_status`. Upstream health is instead **derived from live
request outcomes**, and active polling exists only for the features that genuinely
probe: `[app_server]` health checking, `[grpc] health_check_enabled`, and the supervised
processes in `[processes]` / `[upgrade]`.

```
┌─────────────────────────────────────────────────────────────┐
│                    Upstream Pool                             │
│                                                              │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│   │  Backend A  │   │  Backend B  │   │  Backend C  │      │
│   │  ✓ Healthy  │   │  ✗ Unhealthy│   │  ? Unknown  │      │
│   └─────────────┘   └─────────────┘   └─────────────┘      │
│                                                              │
│   State derived from request outcomes:                      │
│   successes > 0                        → Healthy            │
│   failures > 0 && successes == 0       → Unhealthy          │
│   no traffic yet                       → Unknown            │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Upstream Selection

```toml
[site.proxy.upstream]
servers = ["http://127.0.0.1:8000"]
backup_servers = ["http://127.0.0.1:8001"]   # used when servers are unavailable
```

### Active Health Checking (where it really exists)

```toml
[site.app_server]
health_check_path = "/"                # polled path
health_check_interval_secs = 10
health_check_timeout_secs = 5

[grpc]
health_check_enabled = true
```

```toml
# Supervised processes (main config)
[processes.upgrade]
health_check_interval_secs = 5
```

There are no `health_check_port`, `health_check_failures`, or
`health_check_successes` keys — unknown keys are silently ignored, so a block written
with them looks configured but probes nothing.

## Health Check Methods

Active probing is configured per capability, not per upstream pool.

### `[app_server]` HTTP Polling (the main use case)

```toml
[site.app_server]
health_check_path = "/"
health_check_interval_secs = 10
health_check_timeout_secs = 5
```

**Pros:** Detects a dead app-server independently of inbound traffic
**Cons:** Only applies when the site uses an `app_server` backend

### `[grpc]` gRPC Health Checking

```toml
[grpc]
enabled = true
upstream = "http://127.0.0.1:50051"
health_check_enabled = true
```

**Pros:** Uses the standard gRPC health protocol
**Cons:** gRPC only

### Outcome-Derived State (proxy upstreams)

For `[site.proxy.upstream]` there is no method selector — `servers` traffic itself
supplies the signal. There is no `health_check_method = "HEAD" | "GET" | "TCP"` key.

## How Health Checking Works

### State Machine

```
┌─────────────────────────────────────────────────────────────┐
│              Outcome-Derived Health State                    │
└─────────────────────────────────────────────────────────────┘

        ┌──────────────┐
        │   No traffic │  successes == 0 && failures == 0
        └───────┬──────┘
                │
                ▼
        ┌──────────────┐
        │    Unknown   │  reported by the metrics payload
        └───────┬──────┘
                │ a request succeeds
                ▼
        ┌──────────────┐
        │   Healthy    │  successes > 0
        └───────┬──────┘
                │ failures > 0 && successes == 0
                ▼
        ┌──────────────┐
        │  Unhealthy   │
        └──────────────┘
```

The rule is implemented in `crates/synvoid-metrics/src/types.rs`
(`upstream_healthy` derivation): a site is only marked `Unhealthy` when it has recorded
at least one failure and **zero** successes. One success restores `Healthy`.

### Default Behavior

| Scenario | Recorded state | Reported status |
|----------|----------------|-----------------|
| Backend has served at least one request | `successes > 0` | Healthy |
| Backend has failed and never succeeded | `failures > 0`, `successes == 0` | Unhealthy |
| No traffic recorded yet | both counters 0 | Unknown |
| All backends failing | `failures > 0`, `successes == 0` | Unhealthy (traffic still attempted) |

Note the consequence: **there is no consecutive-failure threshold and no automatic
removal from a pool.** Unhealthy backends are still selected; resilience comes from
`servers` / `backup_servers` ordering and retry, not from an ejection list.

## Per-Backend Configuration

There is no `[site.upstream.backends.<name>]` table and no per-backend `weight` or
`[...health_check]` block. Backends are a flat list of URLs:

```toml
[site.proxy.upstream]
servers = [
    "http://10.0.0.1:8000",
    "http://10.0.0.2:8000",
]
backup_servers = ["http://10.0.0.3:8000"]
```

Per-path behaviour belongs in `[site.proxy.locations]`, each of which may target its own
upstream.

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

`ProxyUpstreamConfig` has **no `load_balancing` key** — there is no `round_robin`,
`least_conn`, or `ip_hash` selector to configure, and no pool that excludes unhealthy
backends. Selection is driven by the `servers` list plus `backup_servers` failover and
the `[site.proxy.upstream] retry` settings:

```toml
[site.proxy.upstream]
servers = ["http://10.0.0.1:8000", "http://10.0.0.2:8000"]
backup_servers = ["http://10.0.0.3:8000"]
```

## Monitoring

### Health Metrics

There is no `synvoid_upstream_health_status` or `synvoid_upstream_rerequests_total`
Prometheus metric. Health is reported as the `upstream_healthy` field of the admin
metrics payload, with the values `healthy` / `unhealthy` / `unknown`:

```bash
# View upstream health via the admin metrics API
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/metrics

# Prometheus scrape (metrics listener, port 9090 in config/main.toml)
curl http://localhost:9090/metrics | grep -i upstream
```

Field definitions live in `crates/synvoid-metrics/src/payloads.rs`.

### Admin API

Upstream inspection and on-demand checks are exposed under `/api/upstreams`
(`src/admin/routes.rs`):

| Route | Method | Purpose |
|-------|--------|---------|
| `/api/upstreams` | GET | List upstreams across sites |
| `/api/upstreams/{site_id}` | GET | Upstreams for one site |
| `/api/upstreams/{site_id}/check` | POST | Trigger a health check for a site |

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8081/api/upstreams
```

Mutating endpoints return typed results, not `{"success": true}` — see
[admin_control_plane_authority.md](../architecture/admin_control_plane_authority.md).

## Troubleshooting

### Backend Reported Unhealthy But Works

1. **Remember the rule** — `Unhealthy` means `failures > 0 && successes == 0`; a single
   successful proxied request flips it back to `Healthy`
2. **Check upstream errors** — some early requests failed (cold start, slow dependency)
3. **Increase timeouts** — the request may be timing out before the backend replies:

```toml
[site.proxy.upstream]
connect_timeout = "10s"
read_timeout = "30s"
send_timeout = "30s"
```

### Too Many False Positives

For `[app_server]` polling, the interval and timeout are configurable. There is no
failure-count threshold to raise, and no TCP-only check mode:

```toml
[site.app_server]
health_check_path = "/health"
health_check_interval_secs = 30
health_check_timeout_secs = 10
```

### Health Check Not Running

1. Confirm the feature you expect to probe is actually configured — proxy upstreams
   never probe, so a missing `[app_server]`/`[grpc]` block is the usual cause
2. Check the backend URL is correct
3. Review logs for health check errors

```bash
# Enable debug logging (binary is ./target/release/synvoid after a release build)
RUST_LOG=debug ./target/release/synvoid

# Look for health check messages
tail -f /var/log/synvoid.log | grep -i health
```

### All Backends Unhealthy

There is no ejection state to escape: traffic is still attempted against `servers` and
then `backup_servers`. Operations resolve the fault by fixing the backends, and status
returns to `Healthy` on the next successful request.

## Best Practices

1. **Implement health endpoints** - Add `/health` to app-server backends
2. **Return 200 for healthy** - Simple and clear
3. **Treat 5xx as unhealthy yourself** - there is no `health_check_expected_status`; only
   an unreachable/non-2xx app-server response counts as a probe failure
4. **Keep it fast** - Health checks should respond in <1 second
5. **Don't require auth** - Health endpoints should be unauthenticated
6. **Separate from liveness** - Consider `/health` (app) vs `/live` (process)

## Example: Complete Upstream Configuration

```toml
[site.proxy.upstream]
servers = [
    "http://10.0.0.1:8000",
    "http://10.0.0.2:8000",
]
backup_servers = ["http://10.0.0.3:8000"]

keepalive = 32
connect_timeout = "5s"
send_timeout = "30s"
read_timeout = "30s"
buffering = true
```

Active probing, where you need it:

```toml
[site.app_server]
health_check_path = "/health"
health_check_interval_secs = 30
health_check_timeout_secs = 5

[grpc]
enabled = true
upstream = "http://127.0.0.1:50051"
health_check_enabled = true
```

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Upstream configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging upstream issues
- [PERFORMANCE.md](./PERFORMANCE.md) - Connection pooling and load balancing
