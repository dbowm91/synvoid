# RustWAF - Production-Ready Web Application Firewall

A high-performance, stealth-oriented Web Application Firewall written in Rust, designed to protect multiple websites with advanced attack detection, flood protection, and bot mitigation capabilities.

## Features

### Attack Detection
- **SQL Injection (SQLi)** - Detection via libinjection with fingerprinting
- **Cross-Site Scripting (XSS)** - Context-aware XSS detection via libinjection
- **Path Traversal** - Directory traversal and LFI detection (`../`, encoded variants, sensitive files)
- **Remote File Inclusion (RFI)** - URL-based injection detection with IP address heuristics
- **Server-Side Request Forgery (SSRF)** - Internal IP, cloud metadata endpoint, and protocol detection
- **Paranoia Levels** - Configurable detection sensitivity (1-3)

### Flood Protection
- **SYN Flood Protection** - Per-IP and global SYN rate limiting with half-open connection tracking
- **Connection Rate Limiting** - Per-IP connection rates with active connection tracking
- **UDP Flood Protection** - Per-IP, per-port, and global packet rate limiting
- **Blackhole Mode** - Automatic traffic sampling during sustained attacks

### Stealth Features
- **Silent Stalling** - Attackers receive no response; connections are held indefinitely
- **Header Sanitization** - Removes `Server`, `X-Powered-By`, and other identifying headers
- **No Version Disclosure** - No WAF identification in any response
- **TCP Protocol Stalling** - Protocol mismatch (e.g., SSH on HTTP port) triggers connection stalling

### Bot Detection & Challenges
- **AI Crawler Blocking** - Block GPTBot, ClaudeBot, and other AI scrapers
- **Scraper Tarpit** - Endless Markov chain-generated content to waste scraper resources
- **CSS Honeypot** - Invisible trap links that detect automated scripts
- **JS Challenge** - Browser verification with proof-of-work

### Core Protection
- **Multi-Site Support** - Manage multiple websites from a single WAF instance
- **Reverse Proxy** - Forward requests to upstream servers with automatic routing
- **Rate Limiting** - Per-IP and global rate limiting with sliding windows
- **IP Blocking** - Persistent blocklists with automatic expiration
- **Endpoint Blocking** - Regex/glob pattern matching for sensitive paths

### Observability
- **Prometheus Metrics** - Comprehensive metrics on port 9090
- **Structured Logging** - JSON-formatted access logs
- **Admin API** - Health checks and configuration reload

## Quick Start

```bash
# Build the project
cargo build --release

# Run with default configuration
cargo run --release

# The WAF starts on:
# - Main HTTP server: http://localhost:8080
# - Admin API: http://localhost:8081
# - Prometheus metrics: http://localhost:9090
```

## Configuration

### Main Configuration (`config/main.toml`)

```toml
[server]
host = "0.0.0.0"
port = 8080
trusted_proxies = ["127.0.0.1", "::1"]

[admin]
enabled = true
port = 8081
token = "your-secure-random-token-here"

[logging]
level = "info"
access_log = true
access_log_dir = "/var/log/rustwaf"
access_log_format = "json"
retention_days = 5

[metrics]
enabled = true
port = 9090

[fallback]
mode = "return_404"  # or "proxy" with upstream setting
```

### Attack Detection Configuration

```toml
[defaults.attack_detection]
enabled = true
paranoia_level = 2  # 1=low, 2=medium, 3=high
action = "stall"    # "stall", "block", or "log"

[defaults.attack_detection.sqli]
enabled = true

[defaults.attack_detection.xss]
enabled = true

[defaults.attack_detection.path_traversal]
enabled = true
custom_patterns = []  # Additional patterns to detect

[defaults.attack_detection.rfi]
enabled = true
custom_patterns = []

[defaults.attack_detection.ssrf]
enabled = true
block_private_ips = true
allowed_domains = []  # Whitelist for SSRF
custom_patterns = []
```

### Flood Protection Configuration

```toml
[defaults.flood]
syn_rate_per_ip = 50           # SYN packets per second per IP
syn_rate_global = 10000        # Global SYN rate limit
connection_rate_per_ip = 100   # Connections per second per IP
connection_rate_global = 20000 # Global connection rate
half_open_max = 1000           # Max half-open connections
half_open_per_ip_max = 10      # Max half-open per IP
udp_rate_per_ip = 1000         # UDP packets per second per IP
udp_rate_global = 100000       # Global UDP rate
blackhole_threshold = 0.9      # Enter blackhole at 90% capacity
blackhole_duration_secs = 60   # Blackhole duration
```

### Rate Limiting Configuration

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
max_ips = 1000000           # Max tracked IPs
cleanup_interval_secs = 60  # Cleanup frequency
```

### Bot Protection Configuration

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

### Site Configuration (`config/sites/example.com.toml`)

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

[attack_detection.ssrf]
allowed_domains = ["api.stripe.com", "api.github.com"]
```

## Attack Detection Details

### SQL Injection Detection

Uses libinjection for SQL injection detection with fingerprinting:

- Tests query strings, POST bodies, headers, and cookies
- Handles URL-encoded and double-encoded payloads
- Returns fingerprint for logging and analysis

**Example detections:**
```
1' OR '1'='1
1 UNION SELECT * FROM users
'; DROP TABLE users;--
```

### XSS Detection

Context-aware XSS detection testing multiple HTML parsing contexts:

- Data state
- Unquoted attributes
- Single/double quoted attributes
- Backtick quoted values

**Example detections:**
```
<script>alert('xss')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Path Traversal Detection

Pattern-based detection using Aho-Corasick automaton:

- Basic traversal: `../`, `..\\`
- URL-encoded: `%2e%2e%2f`, `%252e%252e`
- Double-encoded variants
- Sensitive file access: `/etc/passwd`, `/windows/system32`
- Protocol handlers: `file://`, `php://`, `expect://`

### RFI Detection

- URL parameter injection detection
- IP address in URL parameters
- PHP-specific RFI vectors
- Protocol handlers in parameters

### SSRF Detection

- Internal IP detection (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Cloud metadata endpoints (169.254.169.254, metadata.google, metadata.azure)
- Alternative localhost representations (0.0.0.0, localhost, [::1])
- Dangerous protocols (gopher://, dict://)

## Flood Protection Details

### SYN Flood Protection

Tracks half-open connections to detect and mitigate SYN floods:

1. **Per-IP Rate Limiting** - Limit SYN rate per source IP
2. **Global Rate Limiting** - Protect against distributed attacks
3. **Half-Open Tracking** - Monitor incomplete handshakes
4. **Automatic Cleanup** - Remove stale half-open entries

### Connection Rate Limiting

Prevents connection exhaustion:

- Per-IP connection rate tracking
- Global connection limits
- Active connection monitoring
- Automatic window rotation

### UDP Flood Protection

Rate limits UDP traffic with per-port granularity:

- Per-IP packet rate limiting
- Per-port rate limiting (prevents DNS amplification)
- Global packet rate limiting
- Slotted counter design for O(1) lookups

## Stealth Architecture

### Response Strategy

| Threat Type | Response |
|-------------|----------|
| Attack Detected | Connection held indefinitely (stall) |
| Blocked Endpoint | Connection stalled |
| Blocked Bot | Connection stalled |
| Protocol Mismatch | Connection stalled |
| Honeypot Access | Connection stalled + IP ban |
| Rate Limited | Connection stalled |

### Header Sanitization

Automatically removes from upstream responses:
- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-Runtime`
- `X-Generator`
- `Via`
- `X-Cache` and related headers

## TCP Protocol Filtering

Support for non-HTTP protocol proxying with strict filtering:

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

**Protocol Mismatch Handling:**
- HTTP on SMTP port → Connection stalled
- SSH probe on port 80 → Connection stalled
- Unknown protocol → Configurable (stall/allow)

## Tarpit System

Traps scrapers with infinite generated content:

```toml
[tarpit]
enabled = true
max_depth = 10
links_per_page = 50
response_delay_ms = 100
```

Generated pages contain:
- Markov chain-generated realistic text
- 50+ internal links per page
- Valid-looking URLs and structure
- SEO-friendly meta tags

## Admin API

All endpoints require `Authorization: Bearer <token>` header. Base URL: `http://127.0.0.1:8081/api`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/stats/summary` | GET | System stats summary |
| `/stats/sites` | GET | Per-site statistics |
| `/sites` | GET | List configured sites |
| `/sites` | POST | Create new site |
| `/sites/{site_id}` | GET | Get site config |
| `/sites/{site_id}` | DELETE | Delete site |
| `/config/main` | GET | Get main config |
| `/config/main` | PUT | Update main config |
| `/config/reload` | POST | Reload configuration |
| `/logs` | GET | Query access logs |
| `/upstreams` | GET | List upstreams |
| `/tcp-udp/listeners` | GET | List TCP/UDP listeners |
| `/probes` | GET | List probe stats |
| `/threat-level` | GET | Get threat level status |
| `/threat-level/history` | GET | Get threat history |
| `/threat-level/history/stats` | GET | Get history sample count |
| `/threat-level/history/backup` | POST | Create history backup |
| `/threat-level/history/backups` | GET | List backups |
| `/threat-level/history/backups` | DELETE | Delete backup |
| `/threat-level/history/prune` | POST | Prune old history |
| `/threat-level/baseline` | GET | Get baseline stats |
| `/threat-level/reset` | POST | Reset and relearn baseline |
| `/threat-level/set/{level}` | POST | Set threat level (1-5) |
| `/threat-level/auto` | POST | Set to auto mode |

```bash
# Health check
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/health

# Get threat level
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/threat-level

# Create history backup
curl -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/threat-level/history/backup

# Prune old history (default 365 days)
curl -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/threat-level/history/prune
```

## Prometheus Metrics

Available at `http://localhost:9090/metrics`:

### Request Metrics
- `rustwaf_requests_proxied` - Successfully proxied requests
- `rustwaf_requests_stalled` - Stalled (attack detected)
- `rustwaf_requests_blocked` - Blocked requests
- `rustwaf_requests_challenged` - JS/CSS challenges served
- `rustwaf_requests_tarpitted` - Scraper trap requests
- `rustwaf_request_duration` - Request latency histogram

### Attack Detection Metrics
- `rustwaf_attack_detected{type}` - Attacks by type (sqli, xss, path_traversal, rfi, ssrf)

### Flood Protection Metrics
- `rustwaf_flood_syn_limited` - SYN flood limited
- `rustwaf_flood_connection_limited` - Connection rate limited
- `rustwaf_flood_udp_limited` - UDP flood limited
- `rustwaf_syn_flood_half_open_count` - Current half-open connections

### TCP Metrics
- `rustwaf_tcp_protocol_stalled` - Protocol mismatches stalled
- `rustwaf_tcp_protocol_allowed` - Valid protocol connections
- `rustwaf_tcp_connections_proxied` - TCP connections proxied

### Rate Limiting Metrics
- `rustwaf_ratelimit_blackhole_drop` - Blackholed requests
- `rustwaf_requests_dropped` - Dropped requests

## Production Deployment

### System Requirements

- **OS**: Linux (recommended), macOS, FreeBSD
- **RAM**: Minimum 512MB, recommended 2GB+
- **CPU**: 2+ cores recommended
- **Network**: Low latency to upstream servers

### Build for Production

```bash
# Optimized release build
cargo build --release

# The binary is at target/release/rustwaf
```

### Systemd Service

```ini
[Unit]
Description=RustWAF Web Application Firewall
After=network.target

[Service]
Type=simple
User=rustwaf
Group=rustwaf
WorkingDirectory=/opt/rustwaf
Environment=RUSTWAF_CONFIG_DIR=/etc/rustwaf
ExecStart=/opt/rustwaf/rustwaf
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Performance Tuning

```bash
# Increase file descriptor limits
ulimit -n 65536

# Set in /etc/security/limits.conf
rustwaf soft nofile 65536
rustwaf hard nofile 65536

# Kernel tuning for high traffic
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
```

### Docker Deployment

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rustwaf /usr/local/bin/
COPY config/ /etc/rustwaf/
EXPOSE 8080 8081 9090
CMD ["rustwaf"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  rustwaf:
    build: .
    ports:
      - "8080:8080"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config:/etc/rustwaf
      - ./logs:/var/log/rustwaf
    environment:
      - RUSTWAF_CONFIG_DIR=/etc/rustwaf
    restart: always
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

## Architecture

```
                              ┌─────────────────────────────────────────────────────────┐
                              │                     Client Request                       │
                              └─────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │                   Flood Protection                       │
                              │  ┌──────────────────┐  ┌───────────────────────────────┐│
                              │  │ SYN Flood Guard  │  │ Connection Rate Limiter       ││
                              │  │ Half-Open Track  │  │ Active Connection Monitoring  ││
                              │  └──────────────────┘  └───────────────────────────────┘│
                              └─────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │                    Rate Limiting                         │
                              │  ┌──────────────────┐  ┌───────────────────────────────┐│
                              │  │  Per-IP Limits   │  │ Global Rate Limiter           ││
                              │  │  Sliding Windows │  │ Blackhole Mode                ││
                              │  └──────────────────┘  └───────────────────────────────┘│
                              └─────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │                   Attack Detection                       │
                              │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐│
                              │  │   SQLi      │ │    XSS      │ │ Path Traversal      ││
                              │  │libinjection │ │libinjection │ │ Aho-Corasick        ││
                              │  └─────────────┘ └─────────────┘ └─────────────────────┘│
                              │  ┌─────────────┐ ┌─────────────┐                        │
                              │  │    RFI      │ │    SSRF     │                        │
                              │  │Aho-Corasick │ │Aho-Corasick │                        │
                              │  └─────────────┘ └─────────────┘                        │
                              └─────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │                   Bot Detection                          │
                              │  ┌──────────────────┐  ┌───────────────────────────────┐│
                              │  │ AI Crawler Block │  │ Scraper Detection → Tarpit    ││
                              │  │ Known Bot Allow  │  │ User-Agent Analysis           ││
                              │  └──────────────────┘  └───────────────────────────────┘│
                              └─────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │                   WAF Decision                           │
                              │                                                          │
                              │  ┌────────────┐ ┌────────────┐ ┌────────────────────┐  │
                              │  │   PASS     │ │   STALL    │ │      TARPIT        │  │
                              │  │Proxy to    │ │Hold conn.  │ │Infinite fake       │  │
                              │  │upstream    │ │indefinitely│ │content generation  │  │
                              │  └────────────┘ └────────────┘ └────────────────────┘  │
                              └─────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │                   Upstream Proxy                         │
                              │  ┌──────────────────┐  ┌───────────────────────────────┐│
                              │  │ Header Sanitize  │  │ Load Balancing                ││
                              │  │ Response Filter  │  │ Health Checking               ││
                              │  └──────────────────┘  └───────────────────────────────┘│
                              └─────────────────────────────────────────────────────────┘
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTWAF_CONFIG_DIR` | `./config` | Configuration directory path |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

### File Structure

```
/etc/rustwaf/
├── main.toml                 # Main configuration
├── sites/
│   ├── example.com.toml      # Site-specific config
│   └── api.example.com.toml
├── honeypot_endpoints.txt    # Honeypot URL list
└── error_pages/
    ├── 403.html
    ├── 404.html
    ├── 429.html
    └── 503.html
```

## License

MIT License
