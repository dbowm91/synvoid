# API Reference

MaluWAF provides a RESTful Admin API for managing the WAF, configuring sites, monitoring traffic, and handling threat intelligence. All endpoints require `Authorization: Bearer <token>` header unless otherwise noted.

## Base URL

```
http://127.0.0.1:8081/api
```

The admin API runs on a separate port from the reverse proxy (default 8081) to allow direct access even when HTTP ports are under attack.

## Authentication

All API endpoints (except `/health`) require bearer token authentication:

```bash
# Include token in Authorization header
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/health
```

### Generating Tokens

```bash
# Generate and print a new token (does not save it)
./maluwaf --generatetoken

# Generate and save to config
./maluwaf --generatenewtoken
```

## Response Format

API responses vary by endpoint. Most return data directly, while status-changing operations return a status object.

### Success Response (Data Endpoints)
```json
{
  "site_id": "example.com",
  "domains": ["example.com"],
  "upstream": "http://127.0.0.1:8080"
}
```

### Success Response (Status Operations)
```json
{
  "status": "success",
  "message": "Configuration updated. Reload required."
}
```

### Error Response
```json
{
  "error": "Error message describing what went wrong"
}
```

### List Responses
```json
[
  { "site_id": "example.com", ... },
  { "site_id": "api.example.com", ... }
]
```

## Health Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Basic health check |
| `/api/health` | GET | Yes | Detailed health status |

### /health (No Auth Required)

Returns basic server status without authentication. Useful for load balancer health checks.

```bash
curl http://127.0.0.1:8081/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

### /api/health (Authenticated)

Returns comprehensive health information including component status.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/health
```

**Response:**
```json
{
  "uptime_secs": 3600,
  "total_requests": 125000,
  "requests_per_second": 34.7,
  "blocked_per_second": 0.95,
  "active_connections": 45,
  "memory_used_mb": 256,
  "memory_total_mb": 1024,
  "cpu_usage_percent": 12.5,
  "sites_loaded": 3,
  "healthy_backends": 5,
  "unhealthy_backends": 0,
  "blocked_total": 3420,
  "challenged_total": 150,
  "proxied_total": 121430,
  "errors_total": 45,
  "avg_latency_ms": 45.2,
  "p50_latency_ms": 32.1,
  "p95_latency_ms": 120.5,
  "p99_latency_ms": 250.0,
  "peak_concurrent": 128
}
```

## Statistics

The stats endpoints provide visibility into traffic patterns, attack detection, and system performance.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats/summary` | GET | System-wide statistics summary |
| `/api/stats/sites` | GET | Per-site request and traffic statistics |

### /api/stats/summary

Get an overview of system performance including requests, attacks, and throughput.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/stats/summary
```

**Response:**
```json
{
  "uptime_secs": 3600,
  "total_requests": 125000,
  "requests_per_second": 34.7,
  "blocked_per_second": 0.95,
  "active_connections": 45,
  "memory_used_mb": 256,
  "cpu_usage_percent": 12.5,
  "sites_loaded": 3,
  "healthy_backends": 5,
  "unhealthy_backends": 0,
  "blocked_total": 3420,
  "challenged_total": 150,
  "proxied_total": 121430,
  "errors_total": 45,
  "avg_latency_ms": 45.2,
  "p50_latency_ms": 32.1,
  "p95_latency_ms": 120.5,
  "p99_latency_ms": 250.0,
  "peak_concurrent": 128
}
```

### /api/stats/sites

Get per-site statistics to understand traffic distribution and per-domain metrics.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/stats/sites
```

**Response:**
```json
[
  {
    "site_id": "example.com",
    "domains": ["example.com", "www.example.com"],
    "requests_per_second": 22.2,
    "active_connections": 28,
    "blocked_requests": 2500,
    "challenged_requests": 150,
    "proxied_requests": 77350,
    "errors": 32,
    "avg_response_time_ms": 42.1,
    "p50_latency_ms": 30.5,
    "p95_latency_ms": 110.2,
    "p99_latency_ms": 220.0,
    "upstream_healthy": true,
    "bytes_received": 1523456789,
    "bytes_sent": 2345678901,
    "proxied_bytes_sent": 1234567890,
    "proxied_bytes_received": 987654321,
    "mesh_bytes_sent": 112233445,
    "mesh_bytes_received": 55667788
  },
  {
    "site_id": "api.example.com",
    "domains": ["api.example.com"],
    "requests_per_second": 12.5,
    "active_connections": 17,
    "blocked_requests": 920,
    "challenged_requests": 0,
    "proxied_requests": 44080,
    "errors": 13,
    "avg_response_time_ms": 38.5,
    "p50_latency_ms": 28.2,
    "p95_latency_ms": 95.0,
    "p99_latency_ms": 180.0,
    "upstream_healthy": true,
    "bytes_received": 456789012,
    "bytes_sent": 789012345,
    "proxied_bytes_sent": 567890123,
    "proxied_bytes_received": 234567890,
    "mesh_bytes_sent": 0,
    "mesh_bytes_received": 0
  }
]
```

### Per-Site Bandwidth Fields

The bandwidth fields provide detailed traffic accounting per site:

| Field | Description |
|-------|-------------|
| `bytes_received` | Total bytes received from clients (HTTP/HTTPS/HTTP3 ingress) |
| `bytes_sent` | Total bytes sent to clients (blocked pages, challenges, error responses) |
| `proxied_bytes_sent` | Bytes forwarded to origin servers (direct proxy) |
| `proxied_bytes_received` | Bytes received from origin servers (direct proxy) |
| `mesh_bytes_sent` | Bytes sent to mesh peers (when using WAF-WAF proxying) |
| `mesh_bytes_received` | Bytes received from mesh peers (when using WAF-WAF proxying) |

These fields help track bandwidth usage across different traffic types, which is especially useful in environments with bandwidth limits or for billing/chargeback purposes.

## Sites

Sites represent virtual hosts managed by MaluWAF. Each site has its own configuration for upstream routing, protection settings, and access control.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sites` | GET | List all configured sites |
| `/api/sites` | POST | Create a new site |
| `/api/sites/{site_id}` | GET | Get site configuration |
| `/api/sites/{site_id}` | PUT | Update site configuration |
| `/api/sites/{site_id}` | DELETE | Remove a site |

### List All Sites

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/sites
```

**Response:**
```json
[
  {
    "site_id": "example.com",
    "domains": ["example.com", "www.example.com"],
    "upstream": "http://127.0.0.1:8080",
    "ssl_enabled": false,
    "routes": {}
  }
]
```

### Create a New Site

Create a site by providing its configuration.

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["mysite.com", "www.mysite.com"],
    "default_upstream": "http://127.0.0.1:9000"
  }' \
  http://127.0.0.1:8081/api/sites
```

**Response:**
```json
{
  "id": "mysite.com",
  "config": {
    "site": {
      "domains": ["mysite.com", "www.mysite.com"],
      "listen": [],
      "upstream": {
        "default": "http://127.0.0.1:9000",
        "routes": {},
        "tunnel_mappings": {}
      }
    },
    "bot": {
      "inherit": true,
      "block_ai_crawlers": false,
      "enable_css_honeypot": false,
      "enable_js_challenge": false
    },
    ...
  }
}
```

### Get Site Configuration

Retrieve full configuration for a specific site.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/sites/mysite.com
```

**Response:**
```json
{
  "id": "mysite.com",
  "config": {
    "site": {
      "domains": ["mysite.com", "www.mysite.com"],
      "listen": [
        {"port": 80, "ssl": false},
        {"port": 443, "ssl": true}
      ],
      "upstream": {
        "default": "http://127.0.0.1:9000",
        "routes": {}
      }
    },
    "attack_detection": {
      "enabled": true,
      "paranoia_level": 2,
      "action": "block",
      "sqli": {"enabled": true},
      "xss": {"enabled": true},
      "path_traversal": {"enabled": true}
    },
    "bot": {
      "inherit": true,
      "block_ai_crawlers": true,
      "enable_css_honeypot": false,
      "enable_js_challenge": false
    }
  }
}
```

### Update Site Configuration

Modify an existing site's configuration.

```bash
curl -X PUT \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "site": {
      "upstream": {
        "default": "http://127.0.0.1:9001"
      }
    }
  }' \
  http://127.0.0.1:8081/api/sites/mysite.com
```

**Response:**
```json
{
  "status": "success",
  "message": "Site updated successfully"
}
```

### Delete a Site

Remove a site from configuration.

```bash
curl -X DELETE \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/sites/mysite.com
```

**Response:**
```json
{
  "status": "success",
  "message": "Site deleted successfully"
}
```

## Upstreams

Upstream servers are the backend applications that MaluWAF proxies requests to. The upstream API provides health checking and routing information.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/upstreams` | GET | List all upstreams across sites |
| `/api/upstreams/{site_id}` | GET | Get upstreams for a specific site |
| `/api/upstreams/{site_id}/check` | POST | Trigger upstream health check |

### List All Upstreams

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/upstreams
```

**Response:**
```json
[
  {
    "site_id": "example.com",
    "address": "127.0.0.1:8080",
    "healthy": true,
    "weight": 100
  },
  {
    "site_id": "example.com",
    "address": "127.0.0.1:8081",
    "healthy": false,
    "weight": 100
  }
]
```

### Trigger Health Check

Manually trigger a health check for a site's upstreams.

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/upstreams/example.com/check
```

**Response:**
```json
{
  "status": "success",
  "message": "Health check triggered for site: example.com"
}
```

## Configuration

The configuration API allows runtime modification of MaluWAF settings without requiring service restarts.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config/main` | GET | Get main configuration |
| `/api/config/main` | PUT | Update main configuration |
| `/api/config/schema` | GET | Get configuration schema |
| `/api/config/reload` | POST | Reload configuration from disk |
| `/api/config/log-level` | GET | Get current log level |
| `/api/config/log-level` | PUT | Set log level dynamically |

### Get Main Configuration

Retrieve the current main configuration.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/config/main
```

**Response:**
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "worker_threads": 4
  },
  "admin": {
    "enabled": true,
    "port": 8081,
    "bind_address": "127.0.0.1"
  },
  "logging": {
    "level": "info",
    "access_log": true
  },
  "defaults": {
    "attack_detection": {
      "enabled": true,
      "paranoia_level": 2
    },
    "ratelimit": {
      "enabled": true,
      "ip": {
        "per_second": 10,
        "per_minute": 60
      }
    }
  }
}
```

### Update Configuration

Update configuration values at runtime.

```bash
curl -X PUT \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "defaults": {
      "ratelimit": {
        "ip": {
          "per_minute": 120
        }
      }
    }
  }' \
  http://127.0.0.1:8081/api/config/main
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration updated. Reload required."
}
```

### Get Configuration Schema

Returns the JSON schema for configuration validation.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/config/schema
```

### Reload Configuration

Reload configuration from disk.

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/config/reload
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration reloaded successfully"
}
```

### Change Log Level

Adjust logging verbosity without restarting.

```bash
curl -X PUT \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"level": "debug"}' \
  http://127.0.0.1:8081/api/config/log-level
```

**Response:**
```json
{
  "status": "success",
  "message": "Log level set to debug"
}
```

Valid levels: `trace`, `debug`, `info`, `warn`, `error`

## Threat Level

The threat level system dynamically adjusts protection intensity based on detected attack volume.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/threat-level` | GET | Get current threat level status |
| `/api/threat-level/set/{level}` | POST | Set threat level manually (1-5) |
| `/api/threat-level/auto` | POST | Enable auto-scaling mode |
| `/api/threat-level/history` | GET | Get threat level history |
| `/api/threat-level/baseline` | GET | Get baseline statistics |
| `/api/threat-level/reset` | POST | Reset and relearn baseline |

### Get Current Threat Level

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level
```

**Response:**
```json
{
  "level": 2,
  "mode": "auto",
  "attacks_per_minute": 15,
  "baseline_attacks_per_minute": 12,
  "scale_factor": 0.75,
  "block_duration_multiplier": 1.0,
  "challenge_enabled": true,
  "recommendation": "maintain"
}
```

### Threat Levels Explained

| Level | Name | Rate Limit | Block Duration | Challenge |
|-------|------|------------|----------------|-----------|
| 1 | Normal | 100% | Base | Optional |
| 2 | Elevated | 75% | 1.5x | Yes |
| 3 | High | 50% | 2x | Yes |
| 4 | Critical | 25% | 4x | Always |
| 5 | Emergency | 10% | Permanent | Always |

### Set Threat Level Manually

Override automatic scaling with a fixed threat level:

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level/set/3
```

**Response:**
```json
{
  "status": "ok",
  "message": "Threat level set to 3"
}
```

### Enable Auto Mode

Return to automatic threat level scaling:

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level/auto
```

### Get Baseline Statistics

The baseline system learns normal traffic patterns to distinguish attacks from traffic spikes.

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level/baseline
```

**Response:**
```json
{
  "status": "learning",
  "sample_count": 4500,
  "required_samples": 10000,
  "expected_attacks_per_minute": 12.5,
  "variance": 3.2,
  "confidence": "medium"
}
```

### Reset Baseline

Clear learned baseline and start fresh.

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level/reset
```

**Response:**
```json
{
  "status": "ok",
  "message": "Baseline reset and learning restarted"
}
```

## Probes

Probe detection identifies clients making requests that suggest reconnaissance or vulnerability scanning.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/probes` | GET | List detected probes |
| `/api/probes/stats` | GET | Get probe statistics |
| `/api/probes/block` | POST | Block all detected probe IPs |
| `/api/probes/{ip}` | GET | Get details for specific IP |
| `/api/probes/{ip}` | DELETE | Remove probe record |

### Get Probe Statistics

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/probes/stats
```

**Response:**
```json
{
  "total_probes": 145,
  "active_probes": 23,
  "blocked_probes": 122,
  "top_signatures": [
    {"name": "sqlmap", "count": 45},
    {"name": "nikto", "count": 32},
    {"name": "nmap", "count": 28},
    {"name": "dirb", "count": 18},
    {"name": "wpscan", "count": 12}
  ],
  "top_targeted_paths": [
    "/admin",
    "/phpinfo.php",
    "/.git/config",
    "/wp-login.php",
    "/config.php"
  ]
}
```

### Block All Detected Probes

Add all probe IPs to the blocklist:

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/probes/block
```

**Response:**
```json
{
  "status": "success",
  "message": "23 probe IPs blocked"
}
```

## WebSocket Feeds

Real-time WebSocket connections for live metrics and log streaming.

| Endpoint | Description |
|----------|-------------|
| `/api/ws/metrics` | Real-time metrics stream |
| `/api/ws/logs` | Real-time access logs |

### Connecting to WebSocket

```javascript
// JavaScript example
const ws = new WebSocket('ws://127.0.0.1:8081/api/ws/metrics');

// With authentication token as query parameter
const ws = new WebSocket('ws://127.0.0.1:8081/api/ws/metrics?token=your-admin-token');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

## Error Pages

Manage custom error pages for blocked requests.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/error-pages` | GET | List custom error pages |
| `/api/error-pages/{code}` | GET | Get specific error page |
| `/api/error-pages/{code}` | PUT | Create/update error page |
| `/api/error-pages/{code}` | DELETE | Remove custom error page |

### Upload Custom Error Page

```bash
curl -X PUT \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: text/html" \
  -d '<html><body><h1>Access Denied</h1><p>Your request was blocked.</p></body></html>' \
  http://127.0.0.1:8081/api/error-pages/403
```

**Response:**
```json
{
  "status": "success",
  "message": "Error page 403 updated"
}
```

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid token |
| 404 | Not Found - Resource doesn't exist |
| 500 | Internal Server Error |

## Error Response Format

```json
{
  "error": "Detailed error message"
}
```

## Common Usage Patterns

### Automated Health Monitoring

```bash
#!/bin/bash
# Monitor WAF health

TOKEN="your-admin-token"
ADMIN_URL="http://127.0.0.1:8081/api"

# Check health
HEALTH=$(curl -s -H "Authorization: Bearer $TOKEN" $ADMIN_URL/health | jq -r '.status')

if [ "$HEALTH" != "ok" ]; then
  echo "WAF unhealthy: $HEALTH"
  exit 1
fi

# Check attack rate
ATTACKS=$(curl -s -H "Authorization: Bearer $TOKEN" $ADMIN_URL/stats/summary | jq -r '.blocked_total')

if [ "$ATTACKS" -gt 1000 ]; then
  echo "High blocked requests: $ATTACKS"
  # Could trigger alerts here
fi
```

### Dynamic Threat Response

```bash
#!/bin/bash
# Respond to elevated threat levels

TOKEN="your-admin-token"
ADMIN_URL="http://127.0.0.1:8081/api"

# Get current threat level
LEVEL=$(curl -s -H "Authorization: Bearer $TOKEN" $ADMIN_URL/threat-level | jq -r '.level')

if [ "$LEVEL" -ge 4 ]; then
  # Critical - block all probes
  curl -X POST -H "Authorization: Bearer $TOKEN" $ADMIN_URL/probes/block
  
  # Increase logging
  curl -X PUT -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"level": "debug"}' \
    $ADMIN_URL/config/log-level
    
  echo "Critical threat level: $LEVEL - Probe blocking enabled"
fi
```

### Site Management Workflow

```bash
#!/bin/bash
# Add a new site with WAF protection

TOKEN="your-admin-token"
ADMIN_URL="http://127.0.0.1:8081/api"

# Create site
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["newapp.com", "www.newapp.com"],
    "default_upstream": "http://127.0.0.1:8080"
  }' \
  $ADMIN_URL/sites

# Trigger health check
curl -X POST -H "Authorization: Bearer $TOKEN" \
  $ADMIN_URL/upstreams/newapp.com/check

echo "Site created and health check initiated"
```
