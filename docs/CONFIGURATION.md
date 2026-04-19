# Configuration Reference

Complete configuration reference for MaluWAF.

## Table of Contents

- [Main Configuration](#main-configuration-configmaintoml)
- [Server Settings](#server-settings)
- [Admin API](#admin-api)
- [Logging](#logging)
- [Metrics](#metrics)
- [MIME Types](#mime-types)
- [HTTP Settings](#http-settings)
- [Fallback Mode](#fallback-mode)
- [Attack Detection](#attack-detection-configuration)
- [Bot Protection](#bot-protection)
- [Rate Limiting](#rate-limiting)
- [Upstream](#upstream-configuration)
- [TLS/SSL](#tlsssl-configuration)
- [HTTP/3](#http3-configuration)
- [Static Files](#static-file-serving)
- [FastCGI](#fastcgi-configuration)
- [App Server](#app-server-configuration)
- [WAF Mesh](#waf-mesh-configuration)
- [Process Management](#process-management)
- [Security](#security-configuration)

## Main Configuration (`config/main.toml`)

### Server Settings

```toml
[server]
host = "0.0.0.0"
port = 8080
host_v6 = "::"           # Optional: IPv6 bind address
trusted_proxies = ["127.0.0.1", "::1"]
```

### Admin API

```toml
[admin]
enabled = true
port = 8081
token = "your-secure-random-token-here"
```

### Logging

```toml
[logging]
level = "info"
access_log = true
access_log_dir = "/var/log/maluwaf"
access_log_format = "json"
retention_days = 5
```

### Metrics

```toml
[metrics]
enabled = true
port = 9090
```

### MIME Types

MaluWAF includes a built-in list of common MIME types for file extension lookup (used by static file serving and upload detection). You can customize this by providing an nginx-style `mime.types` file.

```toml
[mimes]
enabled = true
file = "config/mimes/mime.types"
```

- `enabled`: Set to `false` to use only hardcoded defaults
- `file`: Path to nginx-style MIME types file. If not specified, defaults to `config/mimes/mime.types`

#### File Format

The file should be in nginx `mime.types` format:

```nginx
types {
    text/html                                        html htm shtml;
    text/css                                         css;
    text/javascript                                  js;
    image/png                                        png;
    image/jpeg                                       jpg jpeg;
    application/json                                 json;
    application/pdf                                   pdf;
    # ... etc
}
```

See `config/mimes/mime.types` for a complete example.

#### Reloading MIME Types

MIME types can be reloaded without restarting the server:

- **CLI**: `maluwaf rehash`
- **Admin API**: `POST /api/config/reload`

This is useful when you've added new MIME type mappings and want to apply them without downtime.

### HTTP Settings

```toml
[http]
header_read_timeout_secs = 10
keep_alive_timeout_secs = 60
max_headers = 128
max_request_line_size = 8192
max_header_size_ingress = 4096
max_header_size_egress = 16384
max_request_size = 1048576
pipeline_limit = 32
```

### Fallback Mode

```toml
[fallback]
mode = "return_404"  # or "proxy" with upstream setting
```

## Attack Detection Configuration

```toml
[defaults.attack_detection]
enabled = true
paranoia_level = 2  # 1=low, 2=medium, 3=high
action = "stall"    # "stall", "block", or "log"

# SQL Injection
[defaults.attack_detection.sqli]
enabled = true

# Cross-Site Scripting
[defaults.attack_detection.xss]
enabled = true

# Path Traversal
[defaults.attack_detection.path_traversal]
enabled = true
custom_patterns = []

# Remote File Inclusion
[defaults.attack_detection.rfi]
enabled = true
custom_patterns = []

# Server-Side Request Forgery
[defaults.attack_detection.ssrf]
enabled = true
block_private_ips = true
allowed_domains = []

# Command Injection
[defaults.attack_detection.cmd_injection]
enabled = true
custom_patterns = []

# JWT Validation
[defaults.attack_detection.jwt]
enabled = true
allow_alg_none = false

# LDAP Injection
[defaults.attack_detection.ldap_injection]
enabled = true

# Open Redirect
[defaults.attack_detection.open_redirect]
enabled = true
allowed_domains = []

# Server-Side Template Injection
[defaults.attack_detection.ssti]
enabled = true
custom_patterns = []

# XML External Entity
[defaults.attack_detection.xxe]
enabled = true

# XPath Injection
[defaults.attack_detection.xpath_injection]
enabled = true

# Request Smuggling
[defaults.attack_detection.request_smuggling]
enabled = true

# Header Validation
[defaults.attack_detection.header_validation]
enabled = true
max_header_length = 8192
```

## Flood Protection Configuration

```toml
[defaults.flood]
syn_rate_per_ip = 50           # SYN packets per second per IP
syn_rate_global = 10000        # Global SYN rate limit
connection_rate_per_ip = 100   # Connections per second per IP
connection_rate_global = 20000 # Global connection rate
half_open_max = 1000          # Max half-open connections
half_open_per_ip_max = 10     # Max half-open per IP
udp_rate_per_ip = 1000        # UDP packets per second per IP
udp_rate_global = 100000       # Global UDP rate
blackhole_threshold = 0.9       # Enter blackhole at 90% capacity
blackhole_duration_secs = 60   # Blackhole duration
```

## Rate Limiting Configuration

```toml
[defaults.ratelimit]
mode = "shared"  # "shared" or "isolated" per site

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
per_5min = 200
per_hour = 500
per_day = 1000
burst = 20

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
max_connections = 10000

[defaults.rate_limit_memory]
max_ips = 1000000
cleanup_interval_secs = 60
```

## Bot Protection Configuration

```toml
[defaults.bot]
block_ai_crawlers = true
enable_css_honeypot = true
enable_js_challenge = false
js_difficulty = 3

known_bots_allow = [
    "googlebot",
    "bingbot", 
    "yandex",
    "duckduckbot",
]

ai_crawlers_block = [
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "CCBot",
    "Google-Extended",
    "Amazonbot",
]

[defaults.honeypot]
endpoints_file = "config/honeypot_endpoints.txt"
```

## Site Configuration (`config/sites/example.com.toml`)

```toml
[site]
domains = ["example.com", "www.example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"

[site.upstream.routes]
"/api" = "http://api.internal:8001"
"/static" = "http://cdn.internal:8002"

[ratelimit]
mode = "isolated"

[ratelimit.ip]
per_second = 20
per_minute = 200

[blocked]
paths = ["/.env", "/.git", "/wp-admin/*", "/phpmyadmin"]
use_regex = true
block_methods = ["GET", "POST"]
block_response_code = 403

[bot]
inherit = true
block_ai_crawlers = true

[attack_detection]
enabled = true
paranoia_level = 2
```

## HTTP/3 Configuration

```toml
[http3]
enabled = true
port = 443
host_v6 = "::"
alt_svc_max_age = 86400
```

## Traffic Shaping

```toml
[defaults.traffic_shaping]
enabled = true

[defaults.traffic_shaping.global]
max_rate_mbps = 1000
burst_mbps = 1500
```

Per-site:
```toml
[site.traffic_shaping]
enabled = true
max_rate_mbps = 100
burst_mbps = 150
```

## Proxy Cache

```toml
[defaults.proxy_cache]
enabled = true
max_entries = 10000
max_size_mb = 512
ttl_secs = 300

[defaults.proxy_cache.vary]
enabled = true
headers = ["Accept-Encoding", "Accept-Language"]
```

## Upload Validation

```toml
[defaults.upload]
enabled = true
max_size_mb = 10

[defaults.upload.allowed_types]
mode = "whitelist"
types = ["image/jpeg", "image/png", "image/gif", "application/pdf"]

[defaults.upload.scan_with_yara]
enabled = true
rules_dir = "rules/"
quarantine_dir = "/var/lib/maluwaf/quarantine"
```

## FastCGI Configuration

```toml
[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"
# or TCP: socket = "127.0.0.1:9000"

[site.fastcgi.params]
SCRIPT_FILENAME = "$document_root$fastcgi_script_name"
SCRIPT_NAME = "$fastcgi_script_name"
```

## WAF Clustering

```toml
[tunnel.waf_peers]
enabled = true
bind_address = "0.0.0.0"
port = 5001
allow_unauthenticated = false
require_tls = true

[tunnel.waf_peers.peers.waf2]
address = "10.0.1.20:5001"
auth_token = "shared-secret"
weight = 100
```

## QUIC Tunnels

```toml
[tunnel.quic]
enabled = true
bind_address = "0.0.0.0"
port = 51821
max_idle_timeout_secs = 300
keepalive_interval_secs = 25
dedicated_worker = true

[tunnel.quic.server]
enabled = true
auth_token = "server-secret"

[tunnel.quic.client]
enabled = false

cert_path = "/etc/maluwaf/certs/tunnel.crt"
key_path = "/etc/maluwaf/certs/tunnel.key"
auto_generate_certs = true
cert_domain = "tunnel.maluwaf.local"
```

## IP Feeds

```toml
[ip_feeds]
enabled = true
url = "https://threatfeed.example.com/blocklist"
update_interval_hours = 6
max_permanent_blocks = 100000
```

## TCP Protocol Filtering

```toml
[tcp]
enabled = true
worker_pool_size = 4

[tcp.protocols.smtp]
ports = [25, 587]
upstream_format = "127.0.0.1:{port}"

[tcp.protocols.imap]
ports = [143, 993]
upstream_format = "127.0.0.1:{port}"

[tcp.protocols.mysql]
ports = [3306]
upstream_format = "127.0.0.1:{port}"
```

## Tarpit System

```toml
[tarpit]
enabled = true
max_depth = 10
links_per_page = 50
response_delay_ms = 100
```

## Threat Level System

```toml
[threat_level]
initial = 1
auto_scale = true
scale_up_attacks_per_min = 50
scale_up_window_secs = 60
scale_down_attacks_per_min = 10
scale_down_window_secs = 300
cooldown_secs = 60
persist_interval_normal_secs = 60
persist_interval_attack_secs = 15
auto_deescalate_timeout_mins = 15

[threat_level.global_limits]
level_1 = 1.0
level_2 = 0.75
level_3 = 0.5
level_4 = 0.25
level_5 = 0.1

[threat_level.ban_durations]
level_1_base = "1h"
level_2_base = "4h"
level_3_base = "24h"
level_4_base = "7d"
level_5_base = "permanent"

[threat_level.escalation]
enabled = true
violations_before_block = 3
violation_window_secs = 300
```

## Common Configurations

Here are practical configurations for common use cases.

### Small Personal Website

A low-traffic personal blog or portfolio:

```toml
[server]
host = "0.0.0.0"
port = 80

[admin]
enabled = true
port = 8081
token = "generate-a-secure-token"

[defaults.attack_detection]
enabled = true
paranoia_level = 1
action = "block"

[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 5
per_minute = 30
per_hour = 100
```

### Business Website

Standard business website with contact forms and basic functionality:

```toml
[server]
host = "0.0.0.0"
port = 80

[admin]
enabled = true
port = 8081
token = "generate-a-secure-token"

[defaults.attack_detection]
enabled = true
paranoia_level = 2
action = "block"

[defaults.flood]
syn_rate_per_ip = 20
connection_rate_per_ip = 50

[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 100
per_hour = 500

[defaults.bot]
enabled = true
block_ai_crawlers = true
enable_css_honeypot = true
```

### High-Traffic API

A public API with rate limiting per client:

```toml
[server]
host = "0.0.0.0"
port = 80

[admin]
enabled = true
port = 8081

[defaults.attack_detection]
enabled = true
paranoia_level = 2
action = "stall"

[defaults.ratelimit]
mode = "isolated"

[defaults.ratelimit.ip]
per_second = 50
per_minute = 500
per_hour = 5000

[defaults.ratelimit.global]
per_second = 10000

# API-specific: stricter limits
[site.ratelimit]
mode = "isolated"

[site.ratelimit.ip]
per_second = 10
per_minute = 100
```

### DDoS-Protected Service

A service requiring aggressive DDoS protection:

```toml
[server]
host = "0.0.0.0"
port = 80

[defaults.attack_detection]
enabled = true
paranoia_level = 3
action = "stall"

[defaults.flood]
syn_rate_per_ip = 10
syn_rate_global = 5000
connection_rate_per_ip = 10
connection_rate_global = 5000
half_open_max = 100
half_open_per_ip_max = 2
blackhole_threshold = 0.5
blackhole_duration_secs = 300

[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 5
per_minute = 20
per_hour = 50

[threat_level]
enabled = true
initial = 1
auto_scale = true
```

### Multi-Site Hosting

Hosting multiple websites with per-site isolation:

```toml
[server]
host = "0.0.0.0"
port = 80

[defaults.ratelimit]
mode = "isolated"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 100

# Each site can override
# See config/sites/ for per-site configs
```

## File Structure

```
/etc/maluwaf/
├── main.toml                 # Main configuration
├── sites/
│   ├── example.com.toml     # Site-specific config
│   └── api.example.com.toml
├── honeypot_endpoints.txt   # Honeypot URL list
├── error_pages/
│   ├── 403.html
│   ├── 404.html
│   ├── 429.html
│   └── 503.html
├── rules/                   # YARA rules
├── static/                  # Static files
├── cache/                  # Proxy cache
├── db/                     # SQLite database
└── certs/                  # TLS certificates
```

## Common Configuration Mistakes

| Mistake | Problem | Solution |
|---------|---------|----------|
| TLS Passthrough bypassing WAF | When `tls_passthrough = true`, all L7 WAF inspection (SQLi, XSS, etc.) is bypassed | Use `tls_passthrough_enforce_waf = true` to still apply WAF rules |
| Port conflicts | Default ports 8080, 8081, 9090 may be in use | Check ports are available before starting MaluWAF |
| Trusted proxies misconfiguration | X-Forwarded-For header not working | Ensure client IP is in `trusted_proxies` list |
| Weak admin token | Using default or short tokens exposes admin API | Use a strong, random token in production |
| Mesh network isolation | Different mesh networks can see each other | Use `network_id` to isolate different mesh deployments |
| DNSSEC with non-recursive provider | DNSSEC validation requires recursive resolver | Use `"Recursive"` provider with `dnssec_validation = true` |
| ACME terms_of_service_agreed | Let's Encrypt ACME fails without agreement | Set `terms_of_service_agreed = true` in ACME config |
