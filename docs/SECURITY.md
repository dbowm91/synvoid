# Security Hardening Guide

This guide covers security best practices for deploying MaluWAF in production.

## Network Security

### Bind to Internal Interfaces

```toml
[server]
host = "127.0.0.1"  # Only accept local connections
port = 8080

[admin]
enabled = true
host = "127.0.0.1"  # Admin API on localhost only
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
```

## Admin API Security

### Use Environment Variables for Tokens

```toml
[admin]
enabled = true
port = 8081
token_env_var = "MALU_ADMIN_TOKEN"  # Don't store in config file
```

### Generate Strong Tokens

```bash
./maluwaf --generatetoken
# Output: a1b2c3d4e5f6... (64 character hex string)
```

### Restrict Admin Access

```toml
[admin]
enabled = true
host = "127.0.0.1"  # Localhost only
port = 8081
```

For remote admin, use VPN or mesh tunnel.

## IPC Security

### Enable IPC Signing

```toml
[security]
ipc_enforce_signing = true
ipc_session_key_env = "MALU_IPC_KEY"
```

Generate a key:
```bash
xxd -l 32 -p /dev/urandom
```

## TLS Configuration

### Use Strong Ciphers

```toml
[tls]
enabled = true
port = 443
min_version = "1.2"
ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
prefer_server_ciphers = true
```

### Enable HSTS

```toml
[site.hsts]
enabled = true
max_age = 31536000
include_subdomains = true
preload = true
```

### Disable Weak Protocols

```toml
[tls]
min_version = "1.2"  # Disable SSLv3, TLS 1.0, 1.1
```

## Attack Protection

### Enable Comprehensive Detection

```toml
[defaults.attack_detection]
enabled = true
paranoia_level = 2
action = "block"

[defaults.attack_detection.sqli]
enabled = true

[defaults.attack_detection.xss]
enabled = true

[defaults.attack_detection.ssrf]
enabled = true

[defaults.attack_detection.cmd_injection]
enabled = true
```

### Configure Rate Limiting

```toml
[defaults.ratelimit]
enabled = true
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
burst = 20
```

### Enable Bot Protection

```toml
[defaults.bot]
enabled = true
block_ai_crawlers = true
```

## Information Leakage Prevention

### Remove Server Headers

```toml
[server]
remove_server_header = true
```

### Disable Version Disclosure

```toml
[server]
server_tokens = false
```

### Silent Mode (Optional)

```toml
[defaults.attack_detection]
action = "stall"  # Don't reveal blocked requests
```

## Process Security

### Run as Non-Root

```bash
# Create dedicated user
useradd -r -s /sbin/nologin maluwaf

# Set ownership
chown -R maluwaf:maluwaf /etc/maluwaf

# Run as user
su - maluwaf -s /bin/bash -c "/usr/local/bin/maluwaf"
```

### Set Proper Permissions

```bash
# Config files
chmod 600 /etc/maluwaf/main.toml
chmod 600 /etc/maluwaf/sites/*.toml

# Private keys
chmod 600 /etc/maluwaf/certs/*.key

# Logs directory
chown -R maluwaf:maluwaf /var/log/maluwaf
```

## Logging and Monitoring

### Enable Access Logging

```toml
[logging]
level = "info"
access_log = true
access_log_dir = "/var/log/maluwaf"
access_log_format = "json"
retention_days = 30
```

### Monitor Security Events

Watch for attack patterns:

```bash
tail -f /var/log/maluwaf/access.log | grep -i "attack\|blocked\|waf"
```

### Set Up Metrics

```toml
[metrics]
enabled = true
port = 9090
```

Prometheus metrics to monitor:
- `maluwaf_attack_detected_total` - Attack frequency
- `maluwaf_ratelimit_exceeded_total` - Rate limit hits
- `maluwaf_waf_decision_total` - Block/challenge decisions

## Docker Security

### Run as Non-Root Container

```yaml
services:
  maluwaf:
    image: maluwaf:latest
    user: "1000:1000"  # Run as non-root user
    read_only: true    # Read-only filesystem
    cap_drop:          # Drop capabilities
      - ALL
```

### Use Secrets for Tokens

```yaml
services:
  maluwaf:
    environment:
      - MALU_ADMIN_TOKEN=${ADMIN_TOKEN}
      - MALU_IPC_KEY=${IPC_KEY}
    secrets:
      - admin_token
      - ipc_key
```

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
- [ ] Strong admin token (environment variable)
- [ ] IPC signing enabled
- [ ] TLS 1.2+ only with strong ciphers
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
