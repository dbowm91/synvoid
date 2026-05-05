# API Reference

SynVoid provides a RESTful Admin API for managing the WAF, configuring sites, monitoring traffic, and handling threat intelligence. All endpoints require `Authorization: Bearer <token>` header unless otherwise noted.

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
./synvoid --generatetoken

# Generate and save to config
./synvoid --generatenewtoken
```

## Response Format

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

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid token |
| 404 | Not Found - Resource doesn't exist |
| 500 | Internal Server Error |

---

## Health Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Basic health check |
| `/api/health` | GET | Yes | Detailed health status |

### /health (No Auth Required)

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

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/health
```

---

## Statistics Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats/summary` | GET | System-wide statistics summary |
| `/api/stats/sites` | GET | Per-site request and traffic statistics |

### /api/stats/summary

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/stats/summary
```

### /api/stats/sites

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/stats/sites
```

---

## Sites Endpoints

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

### Create a New Site

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

### Get Site Configuration

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/sites/mysite.com
```

### Update Site Configuration

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

### Delete a Site

```bash
curl -X DELETE \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/sites/mysite.com
```

---

## Upstreams Endpoints

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

### Trigger Health Check

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/upstreams/example.com/check
```

---

## Configuration Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config/main` | GET | Get main configuration |
| `/api/config/main` | PUT | Update main configuration |
| `/api/config/schema` | GET | Get configuration schema |
| `/api/config/reload` | POST | Reload configuration from disk |
| `/api/config/log-level` | GET | Get current log level |
| `/api/config/log-level` | PUT | Set log level dynamically |

### Get Main Configuration

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/config/main
```

### Update Configuration

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

### Reload Configuration

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/config/reload
```

### Change Log Level

```bash
curl -X PUT \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"level": "debug"}' \
  http://127.0.0.1:8081/api/config/log-level
```

Valid levels: `trace`, `debug`, `info`, `warn`, `error`

---

## Threat Level Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/threat-level` | GET | Get current threat level status |
| `/api/threat-level/set/{level}` | POST | Set threat level manually (1-5) |
| `/api/threat-level/auto` | POST | Enable auto-scaling mode |
| `/api/threat-level/baseline` | GET | Get baseline statistics |
| `/api/threat-level/reset` | POST | Reset and relearn baseline |

### Get Current Threat Level

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level
```

### Set Threat Level Manually

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level/set/3
```

### Enable Auto Mode

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/threat-level/auto
```

---

## Probes Endpoints

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

### Block All Detected Probes

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/probes/block
```

---

## Mesh Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mesh/status` | GET | Get mesh status and node information |
| `/api/mesh/nodes` | GET | List all connected mesh nodes |
| `/api/mesh/nodes/{node_id}` | GET | Get specific node details |
| `/api/mesh/bans` | GET | List active IP bans |
| `/api/mesh/ban/ip` | POST | Ban an IP address |
| `/api/mesh/ban/mesh-id` | POST | Ban a mesh node ID |
| `/api/mesh/ban` | DELETE | Unban an IP or mesh ID |
| `/api/mesh/derive-signing-key` | POST | Derive signing key from genesis key |
| `/api/mesh/audit/report` | POST | Submit client audit report |
| `/api/mesh/report/signature-failure` | POST | Report signature failure |

### Get Mesh Status

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/mesh/status
```

### List Mesh Nodes

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/mesh/nodes
```

### Ban an IP

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "reason": "detected_attack",
    "duration_seconds": 3600,
    "site_scope": "global"
  }' \
  http://127.0.0.1:8081/api/mesh/ban/ip
```

### Derive Signing Key

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "genesis_key_base64": "YWJjZDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng=="
  }' \
  http://127.0.0.1:8081/api/mesh/derive-signing-key
```

---

## YARA Rules Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/yara/status` | GET | Get YARA rules status |
| `/api/yara/submissions` | GET | List YARA rule submissions |
| `/api/yara/submissions/{submission_id}` | GET | Get submission details |
| `/api/yara/submissions/{submission_id}/approve` | POST | Approve a submission |
| `/api/yara/submissions/{submission_id}/reject` | POST | Reject a submission |
| `/api/yara/submissions/{submission_id}` | DELETE | Delete a submission |
| `/api/yara/submit` | POST | Submit rules for approval |
| `/api/yara/apply` | POST | Apply rules directly (global only) |
| `/api/yara/broadcast` | POST | Broadcast rules to mesh |
| `/api/yara/sync` | POST | Request sync from global nodes |

### Get YARA Status

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/yara/status
```

### Submit Rules

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": "rule test { strings: $a = \"test\" condition: $a }",
    "description": "Test rule"
  }' \
  http://127.0.0.1:8081/api/yara/submit
```

---

## Honeypot Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/honeypot/status` | GET | Get honeypot status |
| `/api/honeypot/control` | POST | Control honeypot (enable/disable/pause/resume) |

### Get Honeypot Status

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/honeypot/status
```

### Control Honeypot

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "pause",
    "reason": "maintenance",
    "duration_secs": 3600
  }' \
  http://127.0.0.1:8081/api/honeypot/control
```

Commands: `enable`, `disable`, `pause`, `resume`

---

## Serverless Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/serverless/health` | GET | Get serverless functions health status |
| `/api/serverless/functions` | GET | List all serverless functions |
| `/api/serverless/functions/{name}/stats` | GET | Get function statistics |

### Get Serverless Health

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/serverless/health
```

### List Functions

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/serverless/functions
```

---

## Plugins Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/plugins/status` | GET | Get plugins status |
| `/api/plugins/metrics` | GET | Get all plugins metrics |
| `/api/plugins/{plugin_name}/metrics` | GET | Get specific plugin metrics |
| `/api/plugins/{plugin_name}/reload` | POST | Reload a plugin |
| `/api/plugins/mesh/modules` | GET | Get mesh WASM modules |

### Get Plugins Status

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/plugins/status
```

### Reload Plugin

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/plugins/my-plugin/reload
```

---

## Alerting Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerting/config` | GET | Get alerting configuration |
| `/api/alerting/config` | PUT | Update alerting configuration |
| `/api/alerting/test-webhook` | POST | Send test webhook |

### Get Alerting Config

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/alerting/config
```

### Update Alerting Config

```bash
curl -X PUT \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "webhook_enabled": true,
      "webhook_urls": ["https://example.com/webhook"]
    }
  }' \
  http://127.0.0.1:8081/api/alerting/config
```

---

## WebSocket Feeds

| Endpoint | Description |
|----------|-------------|
| `/api/ws/metrics` | Real-time metrics stream |
| `/api/ws/logs` | Real-time access logs |

### Connecting to WebSocket

```javascript
const ws = new WebSocket('ws://127.0.0.1:8081/api/ws/metrics');
const ws = new WebSocket('ws://127.0.0.1:8081/api/ws/metrics?token=your-admin-token');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

---

## Common Usage Patterns

### Automated Health Monitoring

```bash
#!/bin/bash
TOKEN="your-admin-token"
ADMIN_URL="http://127.0.0.1:8081/api"

HEALTH=$(curl -s -H "Authorization: Bearer $TOKEN" $ADMIN_URL/health | jq -r '.status')
if [ "$HEALTH" != "ok" ]; then
  echo "WAF unhealthy: $HEALTH"
  exit 1
fi
```

### Dynamic Threat Response

```bash
#!/bin/bash
TOKEN="your-admin-token"
ADMIN_URL="http://127.0.0.1:8081/api"

LEVEL=$(curl -s -H "Authorization: Bearer $TOKEN" $ADMIN_URL/threat-level | jq -r '.level')
if [ "$LEVEL" -ge 4 ]; then
  curl -X POST -H "Authorization: Bearer $TOKEN" $ADMIN_URL/probes/block
  curl -X PUT -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"level": "debug"}' \
    $ADMIN_URL/config/log-level
fi
```

### Site Management Workflow

```bash
#!/bin/bash
TOKEN="your-admin-token"
ADMIN_URL="http://127.0.0.1:8081/api"

curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["newapp.com", "www.newapp.com"],
    "default_upstream": "http://127.0.0.1:8080"
  }' \
  $ADMIN_URL/sites

curl -X POST -H "Authorization: Bearer $TOKEN" \
  $ADMIN_URL/upstreams/newapp.com/check
```
