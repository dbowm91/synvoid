# Breaking Changes & Upgrade Guide

This document tracks breaking changes between versions and provides guidance for upgrading SynVoid.

## Version 1.0.0 (Initial Release)

As this is the initial release, there are no breaking changes from previous versions.

## Upgrading from Pre-1.0 Versions

### Configuration Changes

The following configuration options have changed their default values or behavior:

| Option | Old Behavior | New Behavior | Action Required |
|--------|-------------|-------------|----------------|
| `trusted_proxies` | Not set by default | Must be explicitly configured | Add your proxy/CDN IPs |
| `attack_detection.action` | `"block"` | `"stall"` | Update if you rely on 403 responses |
| `ratelimit.mode` | `"shared"` | `"shared"` | No change |

### Required Configuration for Production

Version 1.0+ requires explicit configuration for some features that were optional:

```toml
# Required: Configure trusted proxies
[server]
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]

# Required: Admin token
[admin]
token = "generate-a-secure-token"
```

### New Features That May Require Attention

1. **Threat Level System**: Now enabled by default with auto-scaling. Monitor for unexpected escalations.

2. **Bot Protection**: AI crawler blocking is enabled. Verify legitimate crawlers aren't blocked.

3. **Rate Limiting**: Uses sliding window algorithm. Verify burst allowances are appropriate.

## Pre-1.0 to 1.0 Migration Checklist

- [ ] Review and update `trusted_proxies` configuration
- [ ] Set admin token in configuration
- [ ] Test attack detection rules don't block legitimate traffic
- [ ] Verify rate limiting thresholds allow normal traffic
- [ ] Check bot protection allows legitimate crawlers
- [ ] Review threat level configuration for your traffic patterns
- [ ] Test upstream health checks work correctly

## Deprecation Notices

The following features are deprecated and will be removed in future versions:

| Feature | Deprecated In | Will Be Removed | Replacement |
|---------|--------------|-----------------|-------------|
| `old_logging_format` | 1.0.0 | 1.1.0 | Structured JSON logging |
| HTTP/1.0 fallback | 1.0.0 | 1.2.0 | HTTP/1.1 minimum |

## Known Issues After Upgrade

### High Memory Usage After Upgrade

If memory usage increases after upgrading:

1. Clear the threat level baseline:
   ```bash
   curl -X POST -H "Authorization: Bearer <token>" \
     http://localhost:8081/api/threat-level/reset
   ```

2. Restart with fresh rate limit counters:
   ```bash
   # Stop SynVoid completely, then restart
   ```

### Rate Limiting Too Aggressive

If rate limiting is too aggressive after upgrade:

```toml
# Increase defaults
[defaults.ratelimit.ip]
per_second = 20  # Was 10
per_minute = 100  # Was 60
```

### Bot Protection Blocking Legitimate Traffic

If bot protection is too aggressive:

```toml
[defaults.bot]
block_ai_crawlers = false  # Disable AI crawler blocking
enable_js_challenge = false  # Disable JavaScript challenges
```

## Upgrading in Production

### Zero-Downtime Upgrade

SynVoid supports zero-downtime upgrades using the upgrade system:

```bash
# Stage the new binary
./synvoid upgrade stage /path/to/new/synvoid

# Apply when ready
./synvoid upgrade apply

# Or use Admin API
curl -X POST -H "Authorization: Bearer <token>" \
  -d '{"binary_path": "/path/to/new/synvoid"}' \
  http://localhost:8081/api/upgrade
```

### Rollback

If the upgrade causes issues:

```bash
./synvoid upgrade rollback
```

### Manual Upgrade

For manual upgrades without the built-in system:

1. Stop the current instance
2. Replace the binary
3. Start the new instance
4. Monitor logs for errors

```bash
# Stop gracefully
./synvoid --stop

# Replace binary
cp /path/to/new/synvoid /usr/local/bin/synvoid

# Start
./synvoid --config /etc/synvoid/main.toml
```

## Configuration Version Compatibility

| Config Version | SynVoid Version | Notes |
|----------------|-----------------|-------|
| 1.0 | 1.0.0+ | Current format |

## Reporting Upgrade Issues

If you encounter issues during upgrade:

1. Check logs: `RUST_LOG=debug ./synvoid`
2. Verify configuration: `./synvoid --configtest`
3. Report issues at: https://github.com/synvoid/synvoid/issues
