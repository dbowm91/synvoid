# Security Hardening Guide

> Vulnerability reporting and supported versions: root `SECURITY.md` — this
> file is the operator hardening guide.

This guide covers security best practices for deploying SynVoid in production.

## Network Security

### Bind to Internal Interfaces

```toml
[server]
host = "127.0.0.1"  # Only accept local connections
port = 8080

[admin]
enabled = true
bind_address = "127.0.0.1"  # Admin API on localhost only (field: bind_address)
port = 8081
```

### Configure Trusted Proxies

```toml
[server]
trusted_proxies = [
    "10.0.0.0/8",      # Your internal network
    "172.16.0.0/12",   # Docker/Kubernetes network
    "192.168.0.0/16"   # Your LAN
]
```

**Do NOT use:** `trusted_proxies = ["0.0.0.0/0"]`

### Firewall Rules

```bash
# Allow only specific sources
iptables -A INPUT -p tcp --dport 80 -s 0.0.0.0/0 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -s 0.0.0.0/0 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -s 127.0.0.1 -j ACCEPT  # Admin local only
# Port 9090 (Prometheus) needs no rule: [metrics].bind_address is validated to
# be loopback, so the exporter is unreachable off-host by construction.
```

## Admin API Security

### Use Environment Variables for Tokens

```toml
[admin]
enabled = true
port = 8081
token_env_var = "SYNVOID_ADMIN_TOKEN"  # Don't store in config file
```

### Generate Strong Tokens

```bash
synvoid --generatetoken
# Output: a1b2c3d4e5f6... (64 character hex string)
```

### Restrict Admin Access

```toml
[admin]
enabled = true
bind_address = "127.0.0.1"  # Localhost only (the field is `bind_address`, not `host`)
port = 8081
```

For remote admin, use VPN or mesh tunnel.

### Shared Proxy Cache

The shared proxy cache is intentionally conservative. Requests with
`Authorization`, `Proxy-Authorization`, or `Cookie` bypass cache lookup, and
responses with `Set-Cookie`, `private`/`no-store`, `Vary: *`, or unsupported
`Vary` fields are not stored. If a site needs caching for personalized traffic,
configure an explicit, reviewed cache-key policy rather than relying on the
shared default.

## IPC Security

### Enable IPC Signing

```toml
[security]
ipc_enforce_signing = true
ipc_session_key_env = "SYNVOID_IPC_KEY"
```

Generate a key:
```bash
xxd -l 32 -p /dev/urandom
```

For process handoff, prefer the supervisor-managed temporary key file. It is
created with `0600`, consumed once, and rejected if it is not a regular file,
is not owned by the current Unix user, or has any group/world permission bits
(including read-only access). Signed frames are length-checked before HMAC and
nonce replay validation.

## TLS Configuration

### Protocol Floor

SynVoid has **no** `min_version`, `ciphers`, or `prefer_server_ciphers` keys. The
protocol floor is expressed by two booleans:

```toml
[tls]
enabled = true
port = 443
tls_1_3_only = true            # DEFAULT — TLS 1.3 only
enable_tls_12_fallback = false # opt back in to TLS 1.2 explicitly
```

Cipher selection is delegated to rustls (`synvoid-tls` always enables the
`prefer-post-quantum` feature), so inbound hybrid post-quantum key exchange is
always available. `prefer_post_quantum` exists in the config for telemetry only
and gates nothing.

### Enable HSTS

HSTS is set per site through the security-headers table, not a `[hsts]` section:

```toml
# config/sites/<site>.toml
[security_headers]
enabled = true
strict_transport_security = "max-age=31536000; includeSubDomains; preload"
```

### Enforce TLS Passthrough Policy

When `tls_passthrough = true` is set on a site, L7 WAF inspection remains enabled by default. If `tls_passthrough_enforce_waf = false` is set, encrypted traffic is forwarded directly to the origin without inspection; SQLi, XSS, RCE, and other application-layer attacks embedded in encrypted traffic are then not detected.

For hardened deployments, enable the strict passthrough policy to prevent unprotected sites from starting:

```toml
[security]
strict_tls_passthrough_policy = true  # Default: false
```

When enabled, worker validation **fails** at startup if any site explicitly disables TLS passthrough WAF enforcement (`tls_passthrough_enforce_waf = false`) and lacks rate limiting. WAF enforcement is on by default.

**Remediation per site** — `config/sites/<site>.toml`. `[proxy]` is a single
table, not an array, and `tls_passthrough*` are fields of it. Pick one option:

Option A — WAF inspects L7 traffic despite passthrough:

```toml
[proxy]
tls_passthrough = true
tls_passthrough_enforce_waf = true

[proxy.upstream]
servers = ["127.0.0.1:8443"]
```

Option B — rate limiting compensates for the lack of L7 inspection:

```toml
[proxy]
tls_passthrough = true

[ratelimit]
# "shared" or "isolated" — "token_bucket" is rejected by validate()
mode = "shared"

[ratelimit.ip]
per_second = 10
per_minute = 100
```

## Attack Protection

### Enable Comprehensive Detection

Attack detection is configured **per site** — there is no
`[defaults.attack_detection]` section in `main.toml`, and `cmd_injection` is
not a sub-table:

```toml
# config/sites/<site>.toml
[attack_detection]
enabled = true
paranoia_level = 2      # 1-3; out-of-range fails validate()
action = "block"        # "stall" | "block" | "log"

[attack_detection.sqli]
enabled = true

[attack_detection.xss]
enabled = true

[attack_detection.ssrf]
enabled = true

[attack_detection.rfi]
enabled = true

[attack_detection.path_traversal]
enabled = true
```

The code default for `action` is `stall`, not `block`.

### Configure Rate Limiting

`RateLimitDefaults` has no `enabled` flag — it is always on, and the site-level
`[ratelimit]` table is what scopes it:

```toml
[defaults.ratelimit]
mode = "shared"  # "shared" or "isolated"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
burst = 20
```

### Enable Bot Protection

`BotDefaults` has no `enabled` flag either; individual policies toggle it:

```toml
[defaults.bot]
block_ai_crawlers = true
enable_css_honeypot = true
enable_js_challenge = false
```

## Information Leakage Prevention

### Remove Server Headers

There is no `[server] remove_server_header` or `[server] server_tokens` key —
`ServerConfig` only holds `host`, `port`, `host_v6`, and `trusted_proxies`. Both
concerns are handled per site by the security-headers table:

```toml
# config/sites/<site>.toml
[security_headers]
enabled = true
# The Server header is emitted only when `server_token` is set. Omitting the
# key (or leaving it unset) sends no Server header; setting it to "" would send
# an empty one, so leave it out entirely.
# server_token = "my-waf"
```

### Silent Mode (Optional)

```toml
# config/sites/<site>.toml
[attack_detection]
action = "stall"  # Don't reveal blocked requests
```

## Process Security

### Run as Non-Root

```bash
# Create dedicated user
useradd -r -s /sbin/nologin synvoid

# Set ownership
chown -R synvoid:synvoid /etc/synvoid

# Run as user
su - synvoid -s /bin/bash -c "/usr/local/bin/synvoid"
```

### Set Proper Permissions

```bash
# Config files
chmod 600 /etc/synvoid/main.toml
chmod 600 /etc/synvoid/sites/*.toml

# Private keys
chmod 600 /etc/synvoid/certs/*.key

# Logs directory
chown -R synvoid:synvoid /var/log/synvoid
```

## Logging and Monitoring

### Enable Access Logging

```toml
[logging]
level = "info"
access_log = true
access_log_dir = "/var/log/synvoid"
access_log_format = "json"
retention_days = 30
```

### Monitor Security Events

Watch for attack patterns:

```bash
tail -f /var/log/synvoid/access.log | grep -i "attack\|blocked\|waf"
```

### Set Up Metrics

```toml
[metrics]
enabled = true
port = 9090
```

Prometheus metrics to monitor (dotted metric names are sanitized to
underscores and counters gain a `_total` suffix by the exporter):
- `synvoid_request_enforcement_source_total{source="attack_detection"}` - attack frequency
- `synvoid_request_enforcement_reason_total` - block/challenge/stall/drop decisions by bounded reason code
- `synvoid.requests.upstream_error` / `synvoid.requests.proxied` - upstream health ratio
- `synvoid.ratelimit.global_limited` - global rate limiter hits

## Docker Security

### Run as Non-Root Container

```yaml
services:
  synvoid:
    image: synvoid:latest
    user: "1000:1000"  # Run as non-root user
    read_only: true    # Read-only filesystem
    cap_drop:          # Drop capabilities
      - ALL
```

### Use Secrets for Tokens

```yaml
services:
  synvoid:
    environment:
      # Only consulted because [admin] token_env_var names this variable.
      - SYNVOID_ADMIN_TOKEN=${ADMIN_TOKEN}
    secrets:
      - admin_token
```

`SYNVOID_IPC_KEY` is generated and injected into worker/jail children by the
Supervisor itself at spawn time; it is not an operator-supplied environment
variable. Leave it unset.

## Regular Maintenance

### Keep Updated

```bash
# Check for updates
cargo outdated

# Update regularly
cargo update
cargo build --release
```

### Rotate Logs

```toml
[logging]
retention_days = 30  # Or use logrotate
```

### Review Blocklists

Regularly check and clean up stale IP blocklist entries.

## Security Checklist

Before production deployment:

- [ ] Admin API bound to localhost or behind VPN
- [ ] Strong admin token (environment variable, ≥ 32 characters)
- [ ] IPC signing enabled
- [ ] TLS 1.3 only (`[tls] tls_1_3_only = true`, the default); hybrid post-quantum key exchange is always offered
- [ ] Trusted proxies configured correctly
- [ ] Rate limiting enabled
- [ ] Attack detection enabled
- [ ] Bot protection enabled
- [ ] Server headers removed
- [ ] Logs enabled and monitored
- [ ] Running as non-root user
- [ ] File permissions set correctly
- [ ] Firewall configured

## See Also

- [SECURITY.md](../SECURITY.md) - Security policy and vulnerability reporting
- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [CONFIGURATION.md](./CONFIGURATION.md) - Configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Security issue debugging
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment
