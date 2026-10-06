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
- [Bot Protection](#bot-protection-configuration)
- [Rate Limiting](#rate-limiting-configuration)
- [Upstream](#site-configuration-configsitesexamplecomtoml)
- [TLS/SSL](#tlsssl-configuration)
- [HTTP/3](#http3-configuration)
- [FastCGI](#fastcgi-configuration)
- [WAF Mesh](#waf-mesh-configuration)
- [Process Management](#process-management)
- [CPU Offload IPC Pool Environment Overrides](#cpu-offload-ipc-pool-environment-overrides)
- [Tarpit System](#tarpit-system)
- [Honeypot Port Deception Layer](#honeypot-port-deception-layer)

## Main Configuration (`config/main.toml`)

### Server Settings

> **Before editing:** the shipped `config/main.toml` does **not** validate on a
> clean machine. `synvoid --configtest` fails with
> `main.toml: logging.access_log_dir: Access log directory not found: /var/log/synvoid`
> (exit 1). Create the directory (or repoint `access_log_dir`) before trusting the
> rest of the file.
>
> These six top-level sections have **no serde default** and are therefore
> required: `server`, `fallback`, `admin`, `logging`, `metrics`, `defaults`.
> A config that omits `fallback` fails with `missing field 'fallback'`.

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
bind_address = "127.0.0.1"  # Default: loopback only
token = "<64 hex characters from `synvoid --generatetoken`>"
```

**Why these defaults:**
- Admin API is enabled by default because it's essential for operational management
- Port 8081 is used (instead of 8080) to separate it from traffic serving and reduce attack surface
- `bind_address` defaults to `127.0.0.1`; widen it only behind a trusted network boundary
- If `token` is omitted entirely, the serde default generates a **random 32-character
  alphanumeric token at each config load** — not a usable stable secret, and it changes
  on restart. Always set it explicitly or use `token_env_var`.
- A configured token must be **at least 32 characters** and must not contain a weak
  pattern (`changeme`, `password`, `admin`, `123456`, …). A short placeholder such as
  `"your-secure-token"` is **rejected at config load**, not warned about.
- Generate a token with `synvoid --generatetoken` (prints 64 hex characters, does not
  save). `synvoid --generatenewtoken` writes a **plaintext** token into `main.toml`
  (`0600` on Unix) — it is not hashed at rest.

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
- `access_log_dir` must exist on disk. The shipped `/var/log/synvoid` normally does
  not, and its absence is a hard `--configtest` failure.

### Metrics

```toml
[metrics]
enabled = true
port = 9090
bind_address = "127.0.0.1"  # Default: loopback only
```

**Why these defaults:**
- Metrics are enabled by default to support observability and alerting in production environments
- Port 9090 follows Prometheus conventions, making it easy to integrate with standard monitoring stacks
- `bind_address` defaults to `127.0.0.1`, and a **non-loopback metrics bind is rejected
  at config-load time** (`MetricsConfig::validate`), not merely warned about. Expose
  metrics through a loopback-side collector or a tunnel.
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
- `header_read_timeout_secs = 10` prevents slow-client attacks while allowing legitimate slow connections (enforced on plaintext H1 and TLS-H1)
- `keep_alive_timeout_secs = 60` is currently not enforced: the H1 servers enable keep-alive but implement no idle-connection timeout from this key. It remains a parseable compatibility key. Do not rely on it to bound idle sockets.
- `max_headers = 128` accommodates most applications; very complex apps may need more but risk memory pressure (enforced on plaintext H1, TLS-H1, and as the TLS-H2 header-list limit)
- `max_request_line_size = 8192` is currently not enforced: no runtime consumer reads this key (the H1 wire request line is not visible to policy code after parsing). It remains a parseable compatibility key.
- `max_header_size_ingress = 4096` limits aggregate parsed request-header bytes (header-name + header-value bytes; framing overhead and the request line are not counted). Requests over the bound are rejected with `431` before routing/WAF/backend work on H1/H2 paths.
- `max_header_size_egress = 16384` is currently not enforced: responses are never truncated to this bound. It remains a parseable compatibility key.
- `max_request_size = 1048576` (1MB) is the H1 parser-buffer ceiling (`max_buf_size`), not a request-body limit: it bounds how much header/request-target bytes the H1 parser will buffer (minimum 8192, enforced by config validation). Body limits live in `max_streaming_body_size` and per-route upload policy.
- `pipeline_limit = 32` is currently not enforced: no H1 pipeline-depth control consumes this key. It remains a parseable compatibility key.
- `max_connections = 10000` bounds concurrent HTTP request admission (per-request semaphore held for request lifetime), not accepted TCP connections.

### Fallback Mode

```toml
[fallback]
mode = "return_404"  # or "proxy" with upstream setting
```

## Attack Detection Configuration

Attack detection is configured **per site** (`config/sites/<domain>.toml`), under
`[attack_detection]`. There is **no `[defaults.attack_detection]` section** —
`DefaultsConfig` has no `attack_detection` field, so a `[defaults.attack_detection]`
block (including the one in `config/main.toml.example`) is silently ignored: the
config crate does not use `deny_unknown_fields`.

```toml
# config/sites/example.com.toml
[attack_detection]
enabled = true
paranoia_level = 2  # 1=low, 2=medium, 3=high
action = "stall"    # "stall", "block", or "log"
```

**Why these defaults:**
- Attack detection is enabled by default because it's the core WAF function—disabling it defeats the purpose of running a WAF
- `paranoia_level = 2` (medium) catches common attacks without excessive false positives; level 3 is aggressive and may affect legitimate traffic
- `action = "stall"` stalls suspicious requests instead of blocking—reduces false positives by forcing attackers to wait while allowing legitimate users with edge-case patterns through

## Flood Protection Configuration

Flood limits live under the top-level **`[tcp]`** section (`TcpDefaults`), not
under `[defaults.flood]`, which does not exist. The keys below are the real
`[tcp]` fields:

```toml
[tcp]
enabled = true
worker_pool_size = 4
syn_rate_per_ip = 50           # SYN packets per second per IP
syn_rate_global = 10000        # Global SYN rate limit
connection_rate_per_ip = 100   # Connections per second per IP
connection_rate_global = 20000 # Global connection rate
half_open_max = 1000          # Max half-open connections
half_open_per_ip_max = 10     # Max half-open per IP

[udp]
enabled = true
rate_per_ip = 1000       # UDP packets per second per IP
rate_global = 100000     # Global UDP rate
```

**There is no `blackhole_threshold` or `blackhole_duration_secs` config key.**
No `[tcp]`, `[udp]`, or `[defaults]` field by those names exists anywhere in
`synvoid-config`; do not add them expecting blackhole behaviour.

**Why these defaults:**
- Per-IP limits (50 SYN/sec, 100 connections/sec) allow legitimate traffic bursts while blocking abuse scripts
- Global limits (10000 SYN/sec, 20000 connections/sec) protect the system from distributed floods
- `half_open_max = 1000` limits incomplete connection state to prevent memory exhaustion; SYN cookies help, but state still matters

## Rate Limiting Configuration

```toml
[defaults.ratelimit]
mode = "shared"  # "shared" or "isolated" per site

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
```

> **Rate-limit defaults are optional, but they are not inert.**
> `DefaultsConfig` carries a struct-level `#[serde(default)]`, so an omitted
> `[defaults]` table is resolved through the Rust `Default` impls rather than
> through the per-field serde defaults. These two paths used to disagree:
> `IpRateLimitConfig` derived `Default` (all zeros) while its serde fields
> defaulted to `per_second = 10`, so omitting `[defaults.ratelimit.ip]` made the
> site check `len() >= per_second` collapse to `len() >= 0` and **100% of
> requests were answered with HTTP 429**.
>
> That is fixed — `IpRateLimitConfig` and `GlobalRateLimitConfig` now have
> hand-written `Default` impls that reuse the same `default_*` functions as the
> serde attributes, and `crates/synvoid-config/tests/serde_defaults_match_rust_defaults.rs`
> pins the parity across the whole `[defaults]` subtree. Writing the values
> explicitly, as above, is still good practice and is what the shipped
> `config/main.toml` does; it is no longer a workaround for a defect.

**Why these defaults:**
- `mode = "shared"` uses a global rate limit pool, protecting the system as a whole rather than per-site; use `isolated` when you want each site to have its own independent limit bucket
- `mode` accepts only `shared` or `isolated`; anything else fails `RateLimitDefaults::validate`. In particular `token_bucket` is **not** a valid value.
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
mode = "isolated"   # "isolated" or "shared" — "token_bucket" is invalid

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

Site-level sections are written **without** the `site.` prefix inside
`config/sites/*.toml`; the prefix shown in `[site.upstream]` above applies to the
nested tables. `SiteRateLimitConfig::validate` accepts only `shared` and
`isolated`.

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

SynVoid supports hybrid post-quantum TLS key exchange for long-term security
against quantum computers, **and it is always available on inbound HTTPS**:

```toml
[tls]
# Telemetry only — this value selects nothing. Present for compatibility and
# intent visibility. See "Post-Quantum TLS" below.
prefer_post_quantum = true
```

**`prefer_post_quantum` does not control post-quantum key exchange.** Setting it
to `false` will not disable it. Which key-exchange groups a listener offers is
decided at compile time: `synvoid-tls` unconditionally enables rustls's
`prefer-post-quantum` cargo feature, so a hybrid group such as `X25519MLKEM768`
is available in every build, and a client that offers only that group will
complete a handshake regardless of this setting.

The field is read in exactly one place — a debug log and the
`synvoid.tls.post_quantum` counter. It is kept so existing configuration keeps
parsing and the intent stays visible, not because it has an effect.

> **On the root `post-quantum` feature.** That feature is a marker covering
> *outbound* http-client and admin TLS egress. It does **not** gate inbound TLS:
> the hybrid key exchange described above is always compiled in. A build without
> the marker feature still negotiates post-quantum inbound. Earlier wording here
> said this setting "requires a `--features post-quantum` build to take effect"
> and told operators to disable it for legacy-client interop; both were wrong,
> and the guide's own examples did not match the shipped binary. Corrected in
> Phase 140 (`architecture/dns_provider_inversion_phase140_closeout.md`).

**Why these defaults:**
- Hybrid PQ key exchange is on by default because there is no configuration cost
  to it; clients that do not offer a hybrid group simply negotiate a classical
  one through normal TLS 1.3 negotiation.
- Only disable `prefer_post_quantum` if a downstream tool parses logs; it has no
  effect on behaviour.

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
| `tls_passthrough` | Forward encrypted traffic directly to origin |
| `tls_passthrough_enforce_waf` | Apply WAF attack detection rules to passthrough traffic (default unless explicitly false) |
| `tls_passthrough_warn_only` | Log WAF violations but don't block (for monitoring) |

**Warning:** Set `tls_passthrough_enforce_waf = false` only when deliberately accepting the loss of L7 inspection. Only layer 3/4 protections (IP rate limiting, connection limits) apply to that bypass.

### Strict TLS Passthrough Policy

Controls whether misconfigured TLS passthrough sites fail worker validation at startup.

```toml
[security]
strict_tls_passthrough_policy = false  # Default: false (warn-only)
```

| Value | Behavior |
|-------|----------|
| `false` (default) | Logs warnings and emits metrics for unprotected passthrough sites, but does not fail startup. Safe for existing deployments. |
| `true` | Returns an error and **fails worker validation** when any site explicitly disables WAF enforcement (`tls_passthrough_enforce_waf = false`) **and** lacks meaningful rate limiting. |

**What counts as "meaningful rate limiting":** A site passes the rate-limit check if any of the following are configured: `ratelimit.mode`, IP-level limits (`ip.per_second`, `ip.per_minute`, etc.), global limits (`global.per_second`, `global.max_connections`), or endpoint-level limits.

**Allowed configurations under strict mode:**

- Passthrough with the default or `tls_passthrough_enforce_waf = true` — WAF inspects L7 traffic despite passthrough.
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

# config/sites/example.com.toml
[ratelimit]
mode = "isolated"   # "shared" | "isolated" — "token_bucket" is invalid

[ratelimit.ip]
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

Global traffic shaping is a **top-level `[traffic_shaping]`** section. The
`[defaults.traffic_shaping]` section that also exists only carries `enabled` and
a `site` sub-table — it has no `global` block, so the `max_rate_mbps` /
`burst_mbps` keys shown below were never real.

```toml
[traffic_shaping]
enabled = true

[traffic_shaping.global]
ingress_max_mb_s = 128
egress_max_mb_s = 128
burst_allowance_mb = 10
burst_refill_ms = 1000
attack_mode_multiplier = 2.0
```

**Why these defaults:**
- Traffic shaping is enabled by default to prevent any single site or client from consuming all bandwidth
- `ingress_max_mb_s` / `egress_max_mb_s` (128 MB/s each by default) suit most deployments; adjust based on your network capacity
- `burst_allowance_mb = 10` allows brief bursts above the limit to handle transient traffic spikes

Per-site overrides use the same key names:
```toml
# config/sites/example.com.toml
[traffic_shaping]
inherit = true
ingress_max_mb_s = 100
egress_max_mb_s = 100
burst_allowance_mb = 15
```

## Proxy Cache

Proxy cache is configured **per upstream**, under `[proxy.cache]` in a site file
(`ProxyCacheConfig` lives in `crates/synvoid-config/src/site/proxy.rs`). There is
no top-level `[defaults.proxy_cache]` section.

```toml
# config/sites/example.com.toml
[proxy.cache]
enabled = true
max_entries = 10000
max_size_mb = 512
ttl_secs = 300

[proxy.cache.vary]
enabled = true
headers = ["Accept-Encoding", "Accept-Language"]
```

## Upload Validation

```toml
[defaults.upload]
enabled = true
max_size = "10MB"        # String size, not `max_size_mb`
scan_with_yara = true     # Flat bool, not a `[scan_with_yara]` table
quarantine_dir = "/var/lib/synvoid/quarantine"
yara_rules_dir = "rules/"

[defaults.upload.allowed_types]
mode = "allowlist"
mime_types = ["image/jpeg", "image/png", "image/gif", "application/pdf"]

# Large file scanning
yara_large_file_scan_mode = "windowed"  # "full", "windowed", or "header_only"
yara_window_size_bytes = 1048576        # 1MB per window
yara_max_window_count = 8               # Maximum windows to scan
yara_magic_scan_limit_bytes = 16777216  # 16MB magic scan region
```

**Why these defaults:**
- Upload validation is enabled by default because file uploads are a common attack vector (malware, webshells)
- `max_size` is a **string** (e.g. `"10MB"`), not a `max_size_mb` number, and `allowed_types` uses `mime_types`, not `types`. `mode` defaults to `"allowlist"`.
- YARA scanning is enabled by default to detect malware in uploaded files
- `windowed` scan mode provides good coverage without excessive memory usage for large files

## FastCGI Configuration

FastCGI is configured **per site** under `[proxy.fastcgi]` (`FastCgiConfig`,
`Option<...>` on the site proxy config), not under a top-level `[site.fastcgi]`:

```toml
# config/sites/example.com.toml
[proxy.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"
# or TCP: socket = "127.0.0.1:9000"

[proxy.fastcgi.params]
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
# Top-level [tcp] (also documented above under Flood Protection)
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

## Process Management

```toml
[process_manager]
min_workers = 2
max_workers = 16
unified_server_workers = 1
```

Bounds (fail-closed, Phase 41 — see `architecture/config_feature_contract.md`):

- Legacy pool: `min_workers`/`max_workers` `1..=1024`, `min <= max`.
- Data-plane pool: `unified_server_workers` `1..=256`, independent of
  `max_workers` (separate `workers` vs `unified_server_workers` pools).
- `pre_spawn_workers` / `warm_workers_target` must not exceed `max_workers`.
- Timeouts: second-granularity `1..=86400`; `restart_backoff_max_secs >=
  restart_cooldown_secs`; `control_api_addr` must parse as `host:port`.
- `worker_port_base + max_workers` must stay in u16 port range.
- Admin `PUT /config/process-manager` and `PUT /config/supervisor` validate
  and return 400 on invalid settings (never silently persist).

## Capability-gated sections (fail-closed)

Reduced-feature binaries reject sections they were not built with, even when
`enabled = false` (previously silently ignored):

- `[dns]` requires `--features dns`
- `[mesh]` and `[tunnel.mesh]` require `--features mesh`
- `[icmp_filter]` requires `--features icmp-filter`

Rebuild with the named feature or remove the unsupported section. Mesh
`[mesh.supervision]` / `[tunnel.mesh.supervision]` additionally rejects
`restart_enabled = true` and any non-default restart tuning (restart is not
implemented).

## DNS deferred features (fail-closed, Phase 45)

Inside the `dns` section, deferred features reject *activation* with a typed
`Unsupported { path }` error instead of being silently ignored. Defaults and
disabled values stay parseable; the admin `PUT /config/dns` endpoint enforces
the same validation (400):

- `dns.rpz.enabled`, `dns.prefetch.enabled`, `dns.trust_anchors.enabled`,
  `dns.anycast.enabled` must stay `false` (no runtime consumer / mesh wiring).
- `dns.settings.allow_transfer` must stay empty; `dynamic_update.enabled`,
  `notify.enabled`, `padding.enabled`, `qname_privacy.enabled` must stay
  `false`; transfer-knob deviations (`allow_wildcard_transfer = true`,
  `require_tsig = false`, `ixfr_enabled = false`, non-default
  `ixfr_history_size` / `ixfr_fallback_to_axfr`) are rejected. Until the
  zone-lifecycle design gate is satisfied, AXFR/IXFR/UPDATE/NOTIFY answer
  NOTIMP unconditionally.
- While `dns.firewall` (or `dns.recursive.firewall`) is enabled,
  `default_action` must stay `allow`, `max_rules` at default, and
  `rebinding_protection.enabled` must be explicitly `false` (unenforced).
- `dns.recursive.ecs.include_scope_in_response` must stay `false`.
- Enabled DoT/DoH/DoQ transports require an explicit parseable
  `bind_address` and non-zero port (validated before listener startup).

Full mapping: `architecture/dns_config_runtime_matrix.md` (Phase 45 section).
Example profiles: `examples/dns/` (`transfer_primary.toml` is a deferred
design reference — it parses but fails validation).

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

The tarpit is a **flat top-level `[tarpit]`** section (`TarpitDefaults`). There
are no `[tarpit.admission]`, `[tarpit.budget]`, `[tarpit.fingerprint]`, or
`[tarpit.redirect_policy]` sub-tables, and the scraper list key is
`scraper_user_agents`, not `scraper_patterns`. Tarpit is **enabled by default**
(`default_tarpit_enabled() == true`).

```toml
[tarpit]
enabled = true
max_depth = 10                       # Maximum crawl depth before loop
links_per_page = 50                  # Fake links generated per page
response_delay_ms = 100              # Delay between chunks (ms)
scraper_user_agents = [              # User-agent patterns that trigger tarpitting
  "scrapy", "curl", "wget", "python-requests",
  "python-urllib", "aiohttp", "httpx"
]
content_templates = []               # Optional response body templates

# Budget / admission limits (flat keys, not a [tarpit.budget] table)
max_concurrent_sessions = 256        # Global concurrent tarpit sessions
max_sessions_per_ip = 4              # Per-IP concurrent session limit
max_duration_secs = 600              # Max connection duration (10 min)
max_chunks = 500                     # Max HTML segments sent per response
max_bytes = 52428800                 # Max total bytes sent (50 MB)
max_idle_secs = 30                   # Idle timeout (no client activity)
write_timeout_ms = 5000              # Per-chunk write timeout (ms)

# Fingerprint resistance (flat keys, not a [tarpit.fingerprint] table)
min_chunk_delay_ms = 5               # Min delay between chunks (randomized)
max_chunk_delay_ms = 30              # Max delay between chunks (randomized)
```

## Honeypot Port Deception Layer

The port honeypot creates fake listening services (SSH, MySQL, Redis, FTP, etc.) on configurable ports to detect unauthorized internal port scanning, lateral movement, and reconnaissance.

The config surface is the **top-level `[honeypot_port]`** section, with exactly **four**
fields (`synvoid_config_model::honeypot_port::HoneypotPortConfig`, which is what
`MainConfig::honeypot_port` uses):

| Field | Type | Default |
|---|---|---|
| `enabled` | bool | **`true`** |
| `ports` | `Vec<u16>` | `[8080, 8443, 9090]` |
| `protocols` | `Vec<String>` | `["tcp", "udp"]` |
| `site_scope` | String | `"global"` |

> **The port honeypot is enabled by default.** A stock install therefore attempts to bind
> deception listeners on **8080, 8443 and 9090** — 8080 being the default HTTP data plane
> port and 9090 the default metrics port. On an unprivileged process the bind fails and
> SynVoid logs `Failed to initialize port honeypot runner: Permission denied` and continues;
> as root it can succeed and contend with those ports. If you do not want this, set
> `enabled = false` explicitly.

```toml
[honeypot_port]
enabled = false                # disable the port deception layer explicitly
ports = [22, 3306, 6379, 21]   # override the default port list
protocols = ["tcp"]
site_scope = "global"
```

There is **no** `[honeypot]` section, and none of `bind_address`, `min_port`, `max_port`,
`num_honeypot_ports`, or `rotation_interval_secs` is a config key — those were never
configurable and are silently ignored. Runtime-only settings such as `[honeypot.storage]`,
`[honeypot.response_mode]`, `[honeypot.ai]`, and `[honeypot.threat_intel.scoring]` are
constructed in code, not read from TOML.

The related URL-based honeypot defaults live under `[defaults.honeypot]` and
`[defaults.honeypot.block]` (values shown are the code defaults):

```toml
[defaults.honeypot]
endpoints_file = "config/honeypot_endpoints.txt"
paths_per_ip = 5
ttl_secs = 86400

[defaults.honeypot.block]
enabled = true
ban_duration = "24h"
```


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
token = "<64 hex characters from `synvoid --generatetoken`>"

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
token = "<64 hex characters from `synvoid --generatetoken`>"

# Attack detection is site-scoped — set it in config/sites/<domain>.toml:
#   [attack_detection]
#   enabled = true
#   paranoia_level = 2
#   action = "block"

[tcp]
enabled = true
syn_rate_per_ip = 20
connection_rate_per_ip = 50

[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 100
per_hour = 500

[defaults.bot]
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
token = "<64 hex characters from `synvoid --generatetoken`>"

# Attack detection is site-scoped — set it in config/sites/<domain>.toml:
#   [attack_detection]
#   enabled = true
#   paranoia_level = 2
#   action = "stall"

[defaults.ratelimit]
mode = "isolated"

[defaults.ratelimit.ip]
per_second = 50
per_minute = 500
per_hour = 5000

[defaults.ratelimit.global]
per_second = 10000

# API-specific: stricter limits go in config/sites/newapp.com.toml
# [ratelimit]
# mode = "isolated"
# [ratelimit.ip]
# per_second = 10
# per_minute = 100
```

### DDoS-Protected Service

A service requiring aggressive DDoS protection:

```toml
[server]
host = "0.0.0.0"
port = 80

# Attack detection is site-scoped — set it in config/sites/<domain>.toml:
#   [attack_detection]
#   enabled = true
#   paranoia_level = 3
#   action = "stall"

[tcp]
enabled = true
syn_rate_per_ip = 10
syn_rate_global = 5000
connection_rate_per_ip = 10
connection_rate_global = 5000
half_open_max = 100
half_open_per_ip_max = 2

[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 5
per_minute = 20
per_hour = 50

[threat_level]
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

`--config-path` takes the **directory** containing `main.toml` and `sites/` — not
the TOML file itself. Without the flag it defaults to the CWD-relative `./config/`.
`synvoid --configtest <dir>` validates `<dir>/main.toml` plus `<dir>/sites/*.toml`.

```
<config-dir>/                 # the directory passed to --config-path
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
├── cache/                   # Proxy cache
├── db/                     # SQLite database
└── certs/                  # TLS certificates
```

The repository's shipped `config/` directory matches this layout.

## Common Configuration Mistakes

| Mistake | Problem | Solution |
|---------|---------|----------|
| Passing the TOML file to `--config-path` | `--config-path` takes the **directory** holding `main.toml` + `sites/`, not the file | Pass the directory, e.g. `--config-path /etc/synvoid` |
| Omitting `[defaults.ratelimit.ip]` | Struct-level `#[serde(default)]` falls back to the derived all-zero `IpRateLimitConfig::default()`, so `len() >= per_second(0)` is always true and **every request gets 429** | Write `[defaults.ratelimit.ip]` explicitly with `per_second` |
| Using a placeholder admin token | Tokens must be ≥ 32 chars and free of weak patterns; short placeholders are **rejected at config load** | `synvoid --generatetoken` (64 hex chars) |
| Short/placeholder `access_log_dir` | A missing access-log directory is a hard `--configtest` failure (the shipped `/var/log/synvoid` usually does not exist) | Create the directory or repoint the key |
| Binding metrics off-loopback | Non-loopback `metrics.bind_address` is **rejected at config-load time**, not warned | Keep `127.0.0.1`; scrape through a local collector |
| `mode = "token_bucket"` in `[ratelimit]` | Only `shared` and `isolated` validate | Use one of those two |
| Setting `[defaults.attack_detection]` | No such field exists; the block is silently ignored | Configure `[attack_detection]` in the site file |
| TLS Passthrough bypassing WAF | When `tls_passthrough = true`, all L7 WAF inspection (SQLi, XSS, etc.) is bypassed unless enforcement is enabled | Keep `tls_passthrough_enforce_waf` unset or set it to `true`; set it to `false` only when bypass is intentional |
| Port conflicts | Default ports 8080, 8081, 9090 may be in use | Check ports are available before starting SynVoid |
| Trusted proxies misconfiguration | X-Forwarded-For header not working | Ensure client IP is in `trusted_proxies` list |
| Weak admin token | Using default or short tokens exposes admin API | Use a strong, random token in production |
| Mesh network isolation | Different mesh networks can see each other | Use `network_id` to isolate different mesh deployments |
| DNSSEC with non-recursive provider | DNSSEC validation requires recursive resolver | Use `"Recursive"` provider with `dnssec_validation = true` |
| ACME terms_of_service_agreed | Let's Encrypt ACME fails without agreement | Set `terms_of_service_agreed = true` in ACME config |
