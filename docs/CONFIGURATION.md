# Configuration Reference

Complete configuration reference for SynVoid.

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
- [CPU Offload IPC Pool Environment Overrides](#cpu-offload-ipc-pool-environment-overrides)
- [Security](#security-configuration)
- [Tarpit System](#tarpit-system)
- [Honeypot Port Deception Layer](#honeypot-port-deception-layer)

## Main Configuration (`config/main.toml`)

### Server Settings

```toml
[server]
host = "0.0.0.0"
port = 8080
host_v6 = "::"           # Optional: IPv6 bind address
trusted_proxies = ["127.0.0.1", "::1"]
```

**Why these defaults:**
- `0.0.0.0` binds to all interfaces, allowing external connections (change to `127.0.0.1` for localhost-only)
- Port 8080 avoids requiring root privileges while remaining a common HTTP port
- IPv6 `::` binds to all IPv6 addresses for dual-stack support
- `trusted_proxies` defaults to localhost only—extending this to include public load balancers is required for proper client IP detection via X-Forwarded-For

### Admin API

```toml
[admin]
enabled = true
port = 8081
token = "your-secure-random-token-here"
```

**Why these defaults:**
- Admin API is enabled by default because it's essential for operational management
- Port 8081 is used (instead of 8080) to separate it from traffic serving and reduce attack surface
- No default token—operators must set a secure token to prevent unauthorized admin access
- Always use `token_env_var` or a secure token in production; short or default tokens expose the admin API

### Logging

```toml
[logging]
level = "info"
access_log = true
access_log_dir = "/var/log/synvoid"
access_log_format = "json"
retention_days = 5
```

**Why these defaults:**
- `info` level provides operational visibility without overwhelming debug noise; `debug` impacts performance
- Access logging is enabled by default because it's critical for audit trails and attack analysis
- JSON format is the default for machine parsing; operators can switch to `text` for human readability
- 5-day retention balances storage costs with the ability to investigate incidents that span several days

### Metrics

```toml
[metrics]
enabled = true
port = 9090
```

**Why these defaults:**
- Metrics are enabled by default to support observability and alerting in production environments
- Port 9090 follows Prometheus conventions, making it easy to integrate with standard monitoring stacks
- Disable if you don't have a metrics collector (increases attack surface slightly)

### MIME Types

SynVoid includes a built-in list of common MIME types for file extension lookup (used by static file serving and upload detection). You can customize this by providing an nginx-style `mime.types` file.

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

- **CLI**: `synvoid rehash`
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

**Why these defaults:**
- `header_read_timeout_secs = 10` prevents slow-client attacks while allowing legitimate slow connections
- `keep_alive_timeout_secs = 60` balances connection reuse (reduces handshakes) with socket resource usage
- `max_headers = 128` accommodates most applications; very complex apps may need more but risk memory pressure
- `max_request_line_size = 8192` handles long URLs (especially with many query params) without blocking legitimate requests
- `max_header_size_ingress = 4096` limits header storage in bytes—ingress headers are typically smaller than egress
- `max_header_size_egress = 16384` allows larger response headers (set-cookies, tokens, etc.)
- `max_request_size = 1048576` (1MB) suits most web applications; file uploads should use dedicated upload handlers
- `pipeline_limit = 32` limits concurrent pipelined requests per connection to prevent resource exhaustion

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
```

**Why these defaults:**
- Attack detection is enabled by default because it's the core WAF function—disabling it defeats the purpose of running a WAF
- `paranoia_level = 2` (medium) catches common attacks without excessive false positives; level 3 is aggressive and may affect legitimate traffic
- `action = "stall"` stalls suspicious requests instead of blocking—reduces false positives by forcing attackers to wait while allowing legitimate users with edge-case patterns through

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

**Why these defaults:**
- Per-IP limits (50 SYN/sec, 100 connections/sec) allow legitimate traffic bursts while blocking abuse scripts
- Global limits (10000 SYN/sec, 20000 connections/sec) protect the system from distributed floods
- `half_open_max = 1000` limits incomplete connection state to prevent memory exhaustion; SYN cookies help, but state still matters
- `blackhole_threshold = 0.9` (90%) triggers blackholing before exhaustion—gives headroom for legitimate traffic during attacks
- `blackhole_duration_secs = 60` is long enough to disrupt attackers but short enough to recover quickly if misconfigured

## Rate Limiting Configuration

```toml
[defaults.ratelimit]
mode = "shared"  # "shared" or "isolated" per site
```

**Why these defaults:**
- `mode = "shared"` uses a global rate limit pool, protecting the system as a whole rather than per-site; use `isolated` when you want each site to have its own independent limit bucket
- Default limits (10/sec, 60/min) are conservative for most applications—legitimate users won't notice, but automated scanners will be throttled
- `burst = 20` allows brief traffic spikes without blocking, while sustained abuse triggers limits
- Global limits (500/sec, 5000/min) protect the WAF itself from being overwhelmed

## Bot Protection Configuration

```toml
[defaults.bot]
block_ai_crawlers = true
enable_css_honeypot = true
enable_js_challenge = false
js_difficulty = 3
```

**Why these defaults:**
- `block_ai_crawlers = true` blocks AI training crawlers (GPTBot, ClaudeBot, etc.) by default—these are increasingly used without compensation to scrape content
- `enable_css_honeypot = true` adds invisible honeypot links that catch bots but not humans; no impact on legitimate traffic
- `enable_js_challenge = false` is conservative—JS challenges may affect crawlers and some legitimate users; enable when dealing with sophisticated bots
- `js_difficulty = 3` (medium) provides reasonable protection without excessive CPU usage on the WAF

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

## TLS/SSL Configuration

### Basic TLS Settings

```toml
[tls]
enabled = true
cert_path = "/etc/synvoid/certs/server.crt"
key_path = "/etc/synvoid/certs/server.key"
port = 443
tls_1_3_only = true
prefer_post_quantum = true
```

### Post-Quantum TLS

SynVoid supports hybrid post-quantum TLS key exchange for long-term security against quantum computers:

```toml
[tls]
prefer_post_quantum = true  # Use hybrid PQ KEX (default: true)
```

**Why these defaults:**
- `prefer_post_quantum = true` protects against future quantum computers that could break classical key exchange; there is no performance penalty when clients also support PQ
- PQ is disabled by default in other WAFs due to compatibility concerns, but SynVoid's implementation gracefully falls back if clients don't support it
- Only disable if you encounter interoperability issues with legacy clients that don't support hybrid PQ key exchange

### 0-RTT (Early Data)

QUIC 0-RTT allows clients to send data before the TLS handshake completes, reducing latency for repeat connections:

```toml
[mesh.tls]
quic_enable_0rtt = false  # Default: false (disabled for security)
```

**Security Note:** 0-RTT has replay attack risks. Only enable when the risk of replay attacks is acceptable for your use case.

### TLS Passthrough

For sites where TLS termination should happen at the origin server:

```toml
[[site.proxy]]
host = "example.com"
port = 443
tls_passthrough = true  # Forward TLS traffic without decryption

# Force WAF L7 inspection even with TLS passthrough
tls_passthrough_enforce_waf = true
```

| Setting | Description |
|---------|-------------|
| `tls_passthrough` | Forward encrypted traffic directly to origin (bypasses WAF L7 inspection) |
| `tls_passthrough_enforce_waf` | Apply WAF attack detection rules to passthrough traffic |
| `tls_passthrough_warn_only` | Log WAF violations but don't block (for monitoring) |

**Warning:** When `tls_passthrough = true` without `tls_passthrough_enforce_waf`, L7 attacks (SQLi, XSS, etc.) in encrypted traffic will not be detected. Only layer 3/4 protections (IP rate limiting, connection limits) apply.

### Strict TLS Passthrough Policy

Controls whether misconfigured TLS passthrough sites fail worker validation at startup.

```toml
[security]
strict_tls_passthrough_policy = false  # Default: false (warn-only)
```

| Value | Behavior |
|-------|----------|
| `false` (default) | Logs warnings and emits metrics for unprotected passthrough sites, but does not fail startup. Safe for existing deployments. |
| `true` | Returns an error and **fails worker validation** when any site has TLS passthrough enabled without WAF enforcement (`tls_passthrough_enforce_waf = true`) **and** without meaningful rate limiting. |

**What counts as "meaningful rate limiting":** A site passes the rate-limit check if any of the following are configured: `ratelimit.mode`, IP-level limits (`ip.per_second`, `ip.per_minute`, etc.), global limits (`global.per_second`, `global.max_connections`), or endpoint-level limits.

**Allowed configurations under strict mode:**

- Passthrough with `tls_passthrough_enforce_waf = true` — WAF inspects L7 traffic despite passthrough.
- Passthrough bypass with configured rate limiting — L7 inspection is bypassed, but the site is still protected by layer 3/4 rate limiting. A warning is still logged that L7 WAF inspection is bypassed.

**Site-level remediation (option A — enable WAF enforcement):**

```toml
[[site.proxy]]
host = "example.com"
port = 443
tls_passthrough = true
tls_passthrough_enforce_waf = true
```

**Site-level remediation (option B — configure rate limiting):**

```toml
[[site.proxy]]
host = "example.com"
port = 443
tls_passthrough = true

[site.ratelimit]
mode = "token_bucket"

[site.ratelimit.ip]
per_second = 10
per_minute = 100
```

Enable this option in hardened production environments after auditing all passthrough site configurations.

### ACME (Let's Encrypt)

Automatic certificate management via ACME protocol:

```toml
[tls.acme]
enabled = true
email = "admin@example.com"
domains = ["example.com", "www.example.com"]
cache_dir = "/var/lib/synvoid/acme"
challenge_type = "Http01"  # or "Dns01" (requires dns feature)
terms_of_service_agreed = true  # Required for Let's Encrypt
staging = false  # Use Let's Encrypt staging for testing
```

**Note:** You must set `terms_of_service_agreed = true` after reviewing the ACME provider's terms of service.

### TLS Client Authentication (mTLS)

```toml
[tls.client_auth]
enabled = false
ca_cert_path = "/etc/synvoid/certs/ca.crt"
```

## Traffic Shaping

```toml
[defaults.traffic_shaping]
enabled = true

[defaults.traffic_shaping.global]
max_rate_mbps = 1000
burst_mbps = 1500
```

**Why these defaults:**
- Traffic shaping is enabled by default to prevent any single site or client from consuming all bandwidth
- `max_rate_mbps = 1000` (1 Gbps) suits most deployments; adjust based on your network capacity
- `burst_mbps = 1500` allows brief bursts above the limit to handle transient traffic spikes
- Per-site overrides allow differential treatment (e.g., premium vs. standard tier)

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

**Why these defaults:**
- Proxy cache is enabled by default to reduce upstream load and improve response times for repeated requests
- `max_entries = 10000` and `max_size_mb = 512` balance memory usage with cache hit rates—tune based on your workload
- `ttl_secs = 300` (5 minutes) provides reasonable freshness for most content while reducing upstream requests
- Vary headers enabled for Accept-Encoding and Accept-Language ensure different renditions aren't served to wrong clients

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
quarantine_dir = "/var/lib/synvoid/quarantine"

# Large file scanning
yara_large_file_scan_mode = "windowed"  # "full", "windowed", or "header_only"
yara_window_size_bytes = 1048576        # 1MB per window
yara_max_window_count = 8               # Maximum windows to scan
yara_magic_scan_limit_bytes = 16777216  # 16MB magic scan region
```

**Why these defaults:**
- Upload validation is enabled by default because file uploads are a common attack vector (malware, webshells)
- `max_size_mb = 10` suits most image/document uploads; larger files should use dedicated upload services with their own scanning
- Whitelist mode ensures only expected file types are accepted—more secure than blacklist mode
- YARA scanning is enabled by default to detect malware in uploaded files
- `windowed` scan mode provides good coverage without excessive memory usage for large files

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

> **Note:** WAF clustering is now handled via QUIC mesh networking. See [WAF_MESH.md](WAF_MESH.md) for details. The `[tunnel.waf_peers]` configuration has been removed.

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

cert_path = "/etc/synvoid/certs/tunnel.crt"
key_path = "/etc/synvoid/certs/tunnel.key"
auto_generate_certs = true
cert_domain = "tunnel.synvoid.local"
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

## CPU Offload IPC Pool Environment Overrides

These environment variables control bounded async IPC offload concurrency for CPU-task clients (`AsyncMinifierClient` and `ImageRightsClient`):

- `SYNVOID_CPU_TASK_POOL_MAX_CONNECTIONS`:
  - Default: `4`
  - Minimum accepted value: `1`
  - Meaning: maximum async IPC connections kept in the per-process CPU task pool.
- `SYNVOID_CPU_TASK_MAX_IN_FLIGHT_PER_CONNECTION`:
  - Default: `1`
  - Minimum accepted value: `1`
  - Meaning: maximum concurrent in-flight requests assigned to a single pooled connection.
    The async CPU-task clients now demultiplex responses by `request_id`, so values above `1`
    are supported when metrics justify them.

Invalid values fall back to defaults. Zero or negative-equivalent values are clamped to `1`.

Example:

```bash
export SYNVOID_CPU_TASK_POOL_MAX_CONNECTIONS=8
export SYNVOID_CPU_TASK_MAX_IN_FLIGHT_PER_CONNECTION=2
```

Operational guidance:
- Increase these values gradually while watching latency and memory.
- Raise per-connection in-flight only if the CPU-offload pool shows measurable contention.
- If the static/CPU worker saturates, tune worker capacity and task limits before raising IPC concurrency aggressively.

## Tarpit System

Anti-scraping tarpit that traps automated crawlers by serving infinitely expanding pages with randomized delays, fingerprint-resistant response variation, and configurable resource budgets.

```toml
[tarpit]
enabled = true
max_depth = 10                       # Maximum crawl depth before loop
links_per_page = 50                  # Fake links generated per page
response_delay_ms = 100              # Delay between chunks (ms)
scraper_patterns = [                 # User-agent patterns that trigger tarpitting
  "scrapy", "curl", "wget", "python-requests",
  "python-urllib", "aiohttp", "httpx"
]

[tarpit.admission]
max_concurrent = 256                 # Global concurrent tarpit sessions
max_per_ip = 4                       # Per-IP concurrent session limit

[tarpit.budget]
max_duration_secs = 600              # Max connection duration (10 min)
max_chunks = 500                     # Max HTML segments sent per response
max_bytes = 52428800                 # Max total bytes sent (50 MB)
max_idle_secs = 30                   # Idle timeout (no client activity)
write_timeout_ms = 5000              # Per-chunk write timeout (ms)

[tarpit.fingerprint]
min_chunk_delay_ms = 5               # Min delay between chunks (randomized)
max_chunk_delay_ms = 30              # Max delay between chunks (randomized)
vary_content_type = true             # Vary Content-Type across responses
vary_status_code = true              # Vary HTTP status codes across responses

[tarpit.redirect_policy]
policy = "RelativeOnly"              # RelativeOnly | AllowList | AllowAll
allow_list = []                      # Hostnames for AllowList policy
```

## Honeypot Port Deception Layer

The port honeypot creates fake listening services (SSH, MySQL, Redis, FTP, etc.) on configurable port ranges to detect unauthorized internal port scanning, lateral movement, and reconnaissance. Disabled by default — enable when you want to detect attackers already inside your network. AI responses are disabled by default; raw payloads are truncated by default (only SHA-256 hashes stored).

```toml
[honeypot]
enabled = false                              # Enable port honeypot deception layer
bind_address = "0.0.0.0"                     # Bind address for honeypot ports
min_port = 10000                             # Minimum port number in range
max_port = 60000                             # Maximum port number in range
num_honeypot_ports = 3                       # Number of simultaneous fake ports
rotation_interval_secs = 1800                # Port rotation interval (seconds)
min_rotation_interval_secs = 600             # Minimum rotation interval (randomized)
max_rotation_interval_secs = 3600            # Maximum rotation interval (randomized)
connection_timeout_ms = 5000                 # Initial connection timeout (ms)
read_timeout_ms = 10000                      # Subsequent read timeout (ms)
max_payload_size = 8192                      # Max bytes to read per connection
max_concurrent_connections = 256             # Global concurrent connection limit
max_connections_per_ip = 10                  # Per-IP concurrent connection limit
site_scope = "global"                        # Site scope for multi-tenant isolation

[honeypot.storage]
database_path = "/var/lib/synvoid/honeypot.db"  # SQLite database path
max_records = 1000000                        # Max records before pruning (oldest deleted)
retention_days = 90                          # Days to retain records
flush_interval_secs = 60                     # Storage flush interval

[honeypot.storage.writer]
queue_capacity = 4096                        # Bounded channel capacity between listener and writer
batch_size = 64                              # Records per batch flush
flush_interval_ms = 1000                     # Periodic flush interval (ms)
write_timeout_ms = 500                       # Per-record write timeout (ms)
payload_retention_mode = "Truncated"         # None | HashOnly | Truncated | Full
max_stored_payload_bytes = 256               # Max payload bytes stored (Truncated mode)
max_stored_payload_hex_bytes = 512           # Max payload hex bytes stored (Truncated mode)

[honeypot.response_mode]
mode = "cycling"                             # Response cycling mode
responder_type = "vulnerable"                # Default responder type

[honeypot.ai]
mode = "Disabled"                            # Disabled | TemplateOnly | LocalModelOnly | ExternalProvider
provider = "ollama"                          # AI provider name
model = "llama3"                             # Model identifier
timeout_secs = 30                            # Provider request timeout

[honeypot.ai.budget]
max_prompt_bytes = 4096                      # Max prompt bytes sent to provider
max_response_bytes = 2048                    # Max response bytes from provider
max_generation_duration_secs = 10            # Max generation time
max_turns_per_connection = 5                 # Max AI turns per connection
max_concurrent_requests = 4                  # Max concurrent AI requests
max_provider_failures = 3                    # Circuit breaker failure threshold

[honeypot.threat_intel]
enabled = true                               # Enable threat intel extraction
mesh_enabled = false                         # Enable mesh propagation (requires minimum confidence/events)

[honeypot.threat_intel.scoring]
base_score_protocol_probe = 0.1              # Base score for protocol probes
base_score_attack_pattern = 0.5              # Base score for known attack patterns
base_score_exploit_payload = 0.7             # Base score for exploit payloads
base_score_credential_attempt = 0.6          # Base score for credential attempts
base_score_scanner_fingerprint = 0.3         # Base score for scanner fingerprints
repeat_bonus_factor = 0.1                    # Bonus per repeat event
repeat_max_bonus = 0.3                       # Maximum repeat bonus
threshold_rate_limit = 0.3                   # Score threshold for rate-limit candidate
threshold_local_block = 0.6                  # Score threshold for local block candidate
threshold_mesh_share = 0.75                  # Score threshold for mesh share candidate
threshold_mesh_block = 0.9                   # Score threshold for mesh block candidate
min_events_for_mesh = 3                      # Minimum events before mesh propagation
min_confidence_for_mesh = "Medium"           # Minimum confidence for mesh propagation
mesh_ttl_secs = 86400                        # Mesh indicator TTL (24 hours)
decay_half_life_secs = 3600                  # Score decay half-life (1 hour)
```

**Safety notes:**
- `mode = "Disabled"` (default) means no AI provider calls are made — only deterministic protocol banners and template responses
- `payload_retention_mode = "Truncated"` (default) stores only truncated payload bytes; `"HashOnly"` stores SHA-256 hashes with zero raw content
- `mesh_enabled = false` (default) prevents any honeypot signals from being shared across the mesh network
- `max_concurrent_connections = 256` and `max_connections_per_ip = 10` prevent resource exhaustion from legitimate or malicious connection storms

## Threat Level System

## WAF Mesh Configuration

Mesh and DHT security-sensitive options:

```toml
[mesh]
enabled = true
role = "global"                      # or "edge", "origin", etc.
network_id = "prod-mesh"

[mesh.tls]
enforce_mutual_tls = true
mode = "strict"                     # strict | tofu | permissive
strict_certificate_validation = true

[mesh.dht]
enabled = true
require_signed_sync_requests = true  # default-deny for unsigned DhtSyncRequest
```

### Signed DHT Sync Rollout

- `mesh.dht.require_signed_sync_requests = true` (default):
  - unsigned `DhtSyncRequest` is rejected.
  - signed request validation enforces timestamp window, nonce replay protection, signature verification, and signer-to-node binding.
  - `DhtSyncResponse` envelope signature verified, record-set digest checked, signer-to-node binding enforced. Unsigned compat path (when `unsigned_sync_compat_until_unix` is active) stores via `store_record_from_ingress()` with `envelope_signature_valid=false`; per-record ingress validation is always enforced.
- `mesh.dht.require_signed_sync_requests = false`:
  - temporary compatibility mode for legacy peers that do not sign sync requests.
  - not recommended for production except during controlled migration windows.
  - requires a bounded `unsigned_sync_compat_until_unix` deadline; rejected at startup if unset or expired.

### Recommended Production Baseline

- Keep `mesh.tls.mode = "strict"` for production mesh deployments.
- Keep `mesh.dht.require_signed_sync_requests = true`.
- Treat `require_signed_sync_requests = false` as temporary and remove after peer rollout.

### Mesh TLS Modes

- `mesh.tls.mode = "strict"`:
  - peer certificates must validate against configured mesh CA trust.
  - if no CA certs are configured, peer cert verification fails closed.
- `mesh.tls.mode = "tofu"`:
  - seed certificate fingerprint pinning/TOFU checks are enabled.
  - useful only for controlled bootstrap environments, not as long-term production trust.
- `mesh.tls.mode = "permissive"`:
  - allows peer cert acceptance when CA trust is unavailable.
  - migration-only mode; avoid as steady-state in production.

Legacy compatibility:
- If `mesh.tls.mode` is omitted, SynVoid falls back to `mesh.tls.strict_certificate_validation` for backward compatibility.
- Prefer setting `mesh.tls.mode` explicitly in all new configs.

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
```

**Why these defaults:**
- `initial = 1` starts at minimum threat level, avoiding false positives on startup
- Auto-scaling is enabled so the system responds to attack intensity automatically
- `scale_up_attacks_per_min = 50` triggers escalation when attack rate exceeds 50/min (1 per second)—prevents triggering on normal traffic spikes
- `scale_down_attacks_per_min = 10` only deescalates when attacks drop to near-zero, preventing oscillation
- `auto_deescalate_timeout_mins = 15` returns to normal after 15 minutes of low attack activity

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
/etc/synvoid/
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
| Port conflicts | Default ports 8080, 8081, 9090 may be in use | Check ports are available before starting SynVoid |
| Trusted proxies misconfiguration | X-Forwarded-For header not working | Ensure client IP is in `trusted_proxies` list |
| Weak admin token | Using default or short tokens exposes admin API | Use a strong, random token in production |
| Mesh network isolation | Different mesh networks can see each other | Use `network_id` to isolate different mesh deployments |
| DNSSEC with non-recursive provider | DNSSEC validation requires recursive resolver | Use `"Recursive"` provider with `dnssec_validation = true` |
| ACME terms_of_service_agreed | Let's Encrypt ACME fails without agreement | Set `terms_of_service_agreed = true` in ACME config |
