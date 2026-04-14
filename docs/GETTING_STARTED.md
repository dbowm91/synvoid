# Getting Started with MaluWAF

Welcome to MaluWAF - a production-ready WAF and reverse proxy built for performance and ease of use.

## Table of Contents

- [What is MaluWAF?](#what-is-maluwaf)
- [Quick Start](#quick-start)
- [Practical Workflows](#practical-workflows)
  - [Protect a Simple PHP Application](#workflow-1-protect-a-simple-php-application)
  - [Deploy Python Application with Granian](#workflow-2-deploy-python-application-with-granian)
  - [Set Up HTTPS with HTTP/3](#workflow-3-set-up-https-with-http3)
  - [Configure Rate Limiting for API Protection](#workflow-4-configure-rate-limiting-for-api-protection)
  - [Set Up Bot Protection](#workflow-5-set-up-bot-protection)
  - [High Availability Setup](#workflow-6-high-availability-setup)
- [Common Use Cases](#common-use-cases)
- [Next Steps](#next-steps)
- [Getting Help](#getting-help)
- [Command Line Options](#command-line-options)

## What is MaluWAF?

MaluWAF is an all-in-one web application firewall and reverse proxy that provides:

- **WAF Protection** - Multi-layer defense against common web attacks
- **Reverse Proxy** - HTTP/1.1, HTTP/2, and HTTP/3 support
- **Application Server** - Built-in support for PHP, Python, and static files
- **High Availability** - Master-worker clustering with overseer orchestration
- **DDoS Mitigation** - WAF-WAF mesh networking for distributed protection

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/maluwaf/maluwaf.git
cd maluwaf

# Build
cargo build --release

# Run
./target/release/maluwaf
```

### 2. Basic Configuration

Create a minimal `main.toml`:

```toml
[server]
host = "0.0.0.0"
port = 80

[admin]
enabled = true
port = 8081
token = "your-secure-token-here"

[logging]
level = "info"

[http]
enabled = true
```

### 3. Add a Site

Create `sites/example.com.toml`:

```toml
[site]
domains = ["example.com", "www.example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"
```

### 4. Start MaluWAF

```bash
./maluwaf --config /path/to/main.toml
```

## Practical Workflows

This section provides step-by-step guides for common tasks.

### Workflow 1: Protect a Simple PHP Application

This workflow shows how to set up MaluWAF in front of a PHP application with PHP-FPM.

**Step 1: Ensure PHP-FPM is Running**

```bash
# Check PHP-FPM status (example for Ubuntu/Debian)
systemctl status php-fpm

# Or start it
sudo systemctl start php-fpm
```

**Step 2: Create Site Configuration**

Create `/etc/maluwaf/sites/myapp.toml`:

```toml
[site]
domains = ["myapp.local", "www.myapp.local"]

[site.upstream]
default = "http://127.0.0.1:9000"

[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"

[site.fastcgi.params]
SCRIPT_FILENAME = "$document_root$fastcgi_script_name"
SCRIPT_NAME = "$fastcgi_script_name"
DOCUMENT_ROOT = "$document_root"
```

**Step 3: Enable WAF Protection**

Add protection settings to the site config:

```toml
[site]
domains = ["myapp.local", "www.myapp.local"]

[site.upstream]
default = "http://127.0.0.1:9000"

[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"

# WAF Protection
[site.attack_detection]
enabled = true
paranoia_level = 2
action = "block"

[site.attack_detection.sqli]
enabled = true

[site.attack_detection.xss]
enabled = true

[site.attack_detection.path_traversal]
enabled = true

# Bot Protection
[site.bot]
enabled = true
block_ai_crawlers = true
```

**Step 4: Verify Configuration**

```bash
./maluwaf --configtest
```

**Step 5: Start MaluWAF**

```bash
# Start in foreground to see logs
./maluwaf -f --config /etc/maluwaf/main.toml

# Or start as daemon
./maluwaf --config /etc/maluwaf/main.toml
```

**Step 6: Test Protection**

```bash
# Test SQL injection should be blocked
curl -H "Host: myapp.local" http://localhost/search?term=1'%20OR%20'1'='1

# Should receive 403 response
# curl output: <html><body><h1>403 Forbidden</h1></body></html>
```

### Workflow 2: Deploy Python Application with Granian

This workflow shows how to deploy a Python ASGI application (FastAPI, Django, etc.) using Granian.

**Step 1: Prepare Your Application**

Ensure your application has proper structure:

```
/var/www/myapp/
├── app/
│   ├── __init__.py
│   └── main.py          # FastAPI app: app = FastAPI()
├── requirements.txt
└── venv/                # Virtual environment (optional)
```

**Step 2: Create Site Configuration**

```toml
[site]
domains = ["api.myapp.local"]

[site.app_server]
enabled = true
working_directory = "/var/www/myapp"
app_path = "app:app"
interface = "asgi"
workers = 4
```

**Auto-detect Settings:**

```toml
[site.app_server]
enabled = true
working_directory = "/var/www/myapp"

# Auto-detect works for most cases (these are defaults)
auto_detect_venv = true
auto_detect_app = true
```

**Full Configuration (if you need more control):**

```toml
[site.app_server]
enabled = true
app_path = "app:app"           # module:variable format
interface = "asgi"              # asgi, wsgi, rsgi
workers = 4
python_path = "/var/www/myapp/venv/bin/python"
working_directory = "/var/www/myapp"
socket_path = "/tmp/maluwaf-myapp.sock"
auto_install_granian = true     # Install granian if missing
auto_detect_venv = true         # Auto-find virtual environment
auto_detect_app = true          # Auto-detect app entry point

# Health check settings
health_check_path = "/health"
health_check_interval_secs = 30
health_check_timeout_secs = 5
```

### Workflow 3: Set Up HTTPS with HTTP/3

This workflow enables secure connections with modern protocol support.

**Step 1: Obtain TLS Certificates**

```bash
# Using certbot (Let's Encrypt)
sudo certbot certonly --standalone -d example.com -d www.example.com

# Copy certificates to MaluWAF directory
sudo cp /etc/letsencrypt/live/example.com/fullchain.pem \
  /etc/maluwaf/certs/example.com.crt
sudo cp /etc/letsencrypt/live/example.com/privkey.pem \
  /etc/maluwaf/certs/example.com.key

# Set permissions
sudo chmod 600 /etc/maluwaf/certs/example.com.key
```

**Step 2: Configure TLS**

```toml
[tls]
enabled = true
port = 443
cert_path = "/etc/maluwaf/certs/example.com.crt"
key_path = "/etc/maluwaf/certs/example.com.key"

# TLS settings
min_version = "1.2"
ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
prefer_server_ciphers = true
```

**Step 3: Enable HTTP/3 (QUIC)**

```toml
[http3]
enabled = true
port = 443
host_v6 = "::"

[http3.quic]
max_idle_timeout_secs = 300
max_concurrent_bidirectional_streams = 100
```

**Step 4: Force HTTPS Redirect**

Add to your site configuration:

```toml
[site]
domains = ["example.com", "www.example.com"]

[site.redirect]
force_https = true
www_redirect = true  # Redirect www to non-www

[site.hsts]
enabled = true
max_age = 31536000
include_subdomains = true
```

**Step 5: Test**

```bash
# Test HTTP/1.1 over TLS
curl -k https://localhost/ -H "Host: example.com"

# Test HTTP/2
curl -k --http2 https://localhost/ -H "Host: example.com"

# Test HTTP/3 (requires quic client or browser)
# In browser: https://example.com/
```

### Workflow 4: Configure Rate Limiting for API Protection

This workflow sets up rate limiting to protect APIs from abuse.

**Step 1: Configure Global Rate Limits**

```toml
[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
per_hour = 500
burst = 20
```

**Step 2: Configure API-Specific Limits**

Create site config for API:

```toml
[site]
domains = ["api.example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"

# More restrictive limits for API
[site.ratelimit]
enabled = true
mode = "isolated"

[site.ratelimit.ip]
per_second = 5
per_minute = 30
burst = 10

# Different limits for authenticated users
[site.ratelimit.authenticated]
per_second = 100
per_minute = 1000
```

**Step 3: Add Endpoint-Specific Limits**

```toml
[site.ratelimit.endpoints]
"/api/auth/login" = { per_minute = 5, burst = 1 }
"/api/auth/register" = { per_minute = 3, burst = 1 }
"/api/search" = { per_minute = 30, burst = 5 }
```

**Step 4: Configure Response for Rate Limited Requests**

```toml
[site.ratelimit]
response_code = 429
response_message = "Rate limit exceeded. Please try again later."
retry_after_header = true
```

**Step 5: Test Rate Limiting**

```bash
# Make requests until rate limited
for i in {1..70}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Host: api.example.com" \
    http://localhost/api/data
done

# Should see: 200, 200, ... 200, 429
```

### Workflow 5: Set Up Bot Protection

This workflow configures bot protection to block unwanted automated traffic.

**Step 1: Basic Bot Protection**

```toml
[defaults.bot]
enabled = true
block_ai_crawlers = true
enable_css_honeypot = true
enable_js_challenge = false  # Set true for stricter protection
```

**Step 2: Configure Known Bot Allowlist**

Allow legitimate search engines:

```toml
[defaults.bot]
known_bots_allow = [
  "googlebot",
  "bingbot",
  "yandex",
  "duckduckbot",
  "slurp",
  "applebot",
  "facebookexternalhit"
]
```

**Step 3: Configure AI Crawler Blocking**

```toml
[defaults.bot.ai_crawlers]
enabled = true

[defaults.bot.ai_crawlers.block]
names = [
  "GPTBot",
  "ChatGPT-User",
  "ClaudeBot",
  "Google-Extended",
  "Amazonbot",
  "anthropic-ai",
  "cohere-ai"
]
```

**Step 4: Add CSS Honeypot**

The CSS honeypot adds invisible links that only bots would follow:

```toml
[defaults.bot.css_honeypot]
enabled = true
hidden_link_class = "w3css"
follow_redirect = false

# Links bots might follow
[defaults.bot.css_honeypot.traps]
paths = [
  "/hidden-admin-link",
  "/secret-crawler-only",
  "/google-sitemap.xml"
]
```

**Step 5: Test Bot Protection**

```bash
# Test with a common scraper user agent
curl -H "Host: example.com" \
  -H "User-Agent: sqlmap/1.4" \
  http://localhost/

# Should receive challenge or block response

# Test with Google bot (should be allowed)
curl -H "Host: example.com" \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
  http://localhost/

# Should return normal response
```

### Workflow 6: High Availability Setup

This workflow sets up multiple MaluWAF nodes with master-worker architecture.

**Step 1: Configure First Master Node**

```toml
[master]
enabled = true
node_id = "master-1"
bind_address = "0.0.0.0"
port = 9000

[master.workers]
count = 4
max_requests_per_worker = 10000
```

**Step 2: Configure Worker Node**

On worker machines:

```toml
[worker]
enabled = true
master_address = "10.0.0.1:9000"
master_token = "shared-secret-token"
```

**Step 3: Configure Overseer (Optional)**

For cluster orchestration:

```toml
[overseer]
enabled = true
bind_address = "0.0.0.0"
port = 8500

[overseer.cluster]
nodes = [
  "10.0.0.1:8500",
  "10.0.0.2:8500", 
  "10.0.0.3:8500"
]

[overseer.raft]
election_timeout_ms = 1000
heartbeat_interval_ms = 300
```

**Step 4: Start Overseer**

```bash
# On first node (will become leader)
./maluwaf --overseer --config /etc/maluwaf/main.toml

# On other nodes
./maluwaf --overseer --config /etc/maluwaf/main.toml
```

**Step 5: Start Masters**

```bash
# Each master node
./maluwaf --master --config /etc/maluwaf/main.toml
```

**Step 6: Verify Cluster Status**

```bash
curl -H "Authorization: Bearer your-token" \
  http://127.0.0.1:8081/api/health

# Response should show cluster status
# "cluster": {"nodes": 3, "healthy": 3}
```

## Common Use Cases

### 1. Simple Website

```
Internet → MaluWAF → Static Files
```

### 2. PHP Application

```
Internet → MaluWAF → PHP-FPM
```

### 3. Python API

```
Internet → MaluWAF → Granian (FastAPI/Django)
```

### 4. High Availability

```
                    ┌──────────────┐
               ┌───►│  MaluWAF #1  │───► App Server
Internet ─────┤    └──────────────┘
               │    ┌──────────────┐
               ├──►│  MaluWAF #2  │───► App Server
               │    └──────────────┘
               │    ┌──────────────┐
               └──►│  MaluWAF #3  │───► App Server
                    └──────────────┘
```

## Next Steps

- [Architecture Overview](./ARCHITECTURE.md) - Learn how MaluWAF works
- [Developer Guide](./DEVELOPER.md) - Technical deep-dive
- [Configuration Reference](./CONFIGURATION.md) - All config options
- [Deployment Guide](./DEPLOYMENT.md) - Production setups

## Getting Help

- GitHub Issues: Report bugs and feature requests
- Documentation: Check the docs folder
- Configuration Examples: See examples/ directory

## Command Line Options

### Process Modes

MaluWAF supports multiple process types (typically managed by the overseer):

```bash
./maluwaf                      # Standalone mode (default, single process)
./maluwaf --worker            # Run as worker (handles requests)
./maluwaf --worker-id <ID>    # Worker ID for multi-worker setups
./maluwaf --static-worker     # Run as static file worker
./maluwaf --static-worker-id <ID>  # Static worker ID
./maluwaf --unified-server-worker   # Run as unified HTTP/HTTPS/HTTP3 worker
./maluwaf --unified-worker-id <ID>  # Unified worker ID
./maluwaf --worker-threads <COUNT>   # Number of tokio threads for worker
```

### Operational Commands

```bash
./maluwaf --configtest              # Validate config files and exit
./maluwaf --status                  # Show status of running instance
./maluwaf --stop                    # Stop running instance
./maluwaf --restart                 # Restart instance (stop + start)
./maluwaf --rehash                  # Reload configuration (graceful)
./maluwaf --generatetoken           # Generate and print admin token
./maluwaf --generatenewtoken        # Generate and save token to config
./maluwaf -f                        # Run in foreground (don't daemonize)
```

### Configuration Options

```bash
./maluwaf --config-path /etc/maluwaf   # Custom config directory
./maluwaf -l debug                     # Set log level (trace/debug/info/warn/error)
```

### Test Modes

Disable specific protections for load testing:

```bash
./maluwaf --test challenge-off      # Disable challenges
./maluwaf --test ratelimit-off     # Disable rate limiting
./maluwaf --test attack-off        # Disable attack detection
./maluwaf --test bot-off           # Disable bot protection
./maluwaf --test flood-off         # Disable flood protection
./maluwaf --test all-off           # Disable all protections

# Combine multiple flags
./maluwaf --test challenge-off --test ratelimit-off
```

### Other Options

```bash
./maluwaf --reuse-port              # Enable SO_REUSEPORT for socket binding
./maluwaf --force                   # Required when using --test all-off
./maluwaf -V, --version             # Print version
./maluwaf -h, --help                # Print help
```
