# Troubleshooting

Common issues and solutions for SynVoid.

## Table of Contents

- [Connection Issues](#connection-issues)
  - [WAF Not Starting](#waf-not-starting)
  - [Upstream Connection Failures](#upstream-connection-failures)
  - [Slow Response Times](#slow-response-times)
- [Attack Detection Issues](#attack-detection-issues)
  - [False Positives](#false-positives)
  - [False Negatives](#false-negatives)
  - [431 Request Header Fields Too Large](#431-request-header-fields-too-large)
- [Performance Issues](#performance-issues)
  - [High Memory Usage](#high-memory-usage)
  - [High CPU Usage](#high-cpu-usage)
  - [Connection Limit Reached](#connection-limit-reached)
- [Configuration Issues](#configuration-issues)
  - [Token Authentication Failed](#token-authentication-failed)
  - [Config Not Reloading](#config-not-reloading)
- [Logging Issues](#logging-issues)
  - [Logs Not Writing](#logs-not-writing)
  - [Log Level Too Verbose](#log-level-too-verbose)
- [Metrics Issues](#metrics-issues)
- [SSL/TLS Issues](#ssltls-issues)
- [Debugging Steps](#debugging-steps)
- [Mesh/WAF Clustering Issues](#meshwaf-clustering-issues)

## Connection Issues

### WAF Not Starting

**Symptom**: `Address already in use` error

**Solution**:
```bash
# Check what's using the port
lsof -i :8080

# Stop the conflicting service or change port in config
```

### Upstream Connection Failures

**Symptom**: `upstream connection error` in logs

**Solutions**:
- Verify upstream service is running
- Check firewall rules
- Verify `trusted_proxies` includes WAF IP
- Check upstream health check configuration

### Slow Response Times

**Possible causes**:
- Upstream server overloaded
- Rate limiting too aggressive
- Connection pool too small
- Network latency

**Solutions**:
```toml
[http]
keep_alive_timeout_secs = 60
pipeline_limit = 32
```

## Attack Detection Issues

### False Positives

**Symptom**: Legitimate requests blocked

**Solutions**:
1. Lower paranoia level. Attack detection is configured **per site** (there is
   no `[defaults.attack_detection]` section), so edit the affected site's file:
```toml
# config/sites/<site>.toml
[attack_detection]
paranoia_level = 1
```

2. Disable specific detection:
```toml
# config/sites/<site>.toml
[attack_detection.ssrf]
enabled = false
```

3. Add domain to allowlist:
```toml
# config/sites/<site>.toml
[attack_detection.ssrf]
allowed_domains = ["api.yourdomain.com"]
```

### False Negatives

**Symptom**: Attacks not detected

**Solutions**:
1. Increase paranoia level (1–3; out-of-range values fail `validate()`):
```toml
# config/sites/<site>.toml
[attack_detection]
paranoia_level = 3
```

2. Enable additional detection:
```toml
# config/sites/<site>.toml
[attack_detection]
enabled = true

[attack_detection.sqli]
enabled = true
```

3. Add custom patterns:
```toml
# config/sites/<site>.toml
[attack_detection.path_traversal]
custom_patterns = ["/etc/passwd", "boot.ini"]
```

### 431 Request Header Fields Too Large

**Symptom**: Legitimate requests rejected with `431`

**Cause**: Aggregate parsed request-header bytes (header-name + header-value
bytes) exceed `http.max_header_size_ingress` (default 4096). Common with
large cookies or many headers.

**Solutions**:
- Raise the bound if the traffic is legitimate:
```toml
[http]
max_header_size_ingress = 8192
```
- Reduce header volume (cookie size/count) sent by clients.

## Performance Issues

### High Memory Usage

**Possible causes**:
- Too many tracked IPs in rate limiting
- Large proxy cache
- Memory leak

**Solutions**:
```toml
# `rate_limit_memory` is a top-level main.toml section (it also exists under
# [defaults]); the tracked-IP cap is `max_ip_entries`, not `max_ips`.
[rate_limit_memory]
max_ip_entries = 100000
cleanup_interval_secs = 30
```

Proxy cache is configured per site, not under [defaults]. To disable it for one
site:
```toml
# config/sites/<site>.toml
[proxy.cache]
enable = false
```

Reduce the tracked-IP cap instead of scaling memory when a site is under attack;
the limiter also emits `synvoid.ratelimit.global_limited` and
`synvoid.ratelimit.blackholed`, which are visible through the admin API at
`/api/stats/summary`.

### High CPU Usage

**Possible causes**:
- Too many concurrent connections
- Attack traffic
- Regex patterns too complex

**Solutions**:
- Enable traffic shaping
- Reduce connection limits
- Review custom patterns

### Connection Limit Reached

**Symptom**: `Too many open files` or connection errors

**Solutions**:
```bash
# Increase file descriptors
ulimit -n 65536
```

```toml
[defaults.ratelimit.global]
max_connections = 10000
```

## Configuration Issues

### Token Authentication Failed

**Symptom**: 401 Unauthorized responses

**Solution**: Verify token in header. Note that `/health` is the public,
unauthenticated liveness route — probing it will succeed even with a bad token,
so test an authenticated route instead:
```bash
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/stats/summary
```

Generate new token:
```bash
synvoid --generatenewtoken
```

### Config Not Reloading

**Symptom**: Changes to main.toml not taking effect

**Solution**:
```bash
curl -X POST -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/config/reload
```

Or restart the service.

## Logging Issues

### Logs Not Writing

**Possible causes**:
- Directory permissions
- Disk full
- Incorrect path

**Solutions**:
```bash
# Check directory exists and is writable
mkdir -p /var/log/synvoid
chown -R synvoid:synvoid /var/log/synvoid
```

### Log Level Too Verbose

**Solution**:
```bash
# Set log level
curl -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"level": "warn"}' \
  http://127.0.0.1:8081/api/config/log-level
```

Or set in environment:
```bash
RUST_LOG=warn synvoid
```

## Metrics Issues

### Prometheus Not Scraping

**Verify metrics endpoint**. The exporter binds loopback-only —
`MetricsConfig::validate()` rejects a non-loopback `bind_address`, so the port
is never reachable from another host:
```bash
curl http://127.0.0.1:9090/metrics
```

**Check configuration**:
```toml
[metrics]
enabled = true
port = 9090
bind_address = "127.0.0.1"  # loopback only; anything else fails validation
```

To scrape from a central Prometheus, run a host-local agent/sidecar or tunnel
over SSH. Do not widen `bind_address` — startup will fail rather than publish.

## SSL/TLS Issues

### Certificate Errors

**Symptom**: TLS handshake failures

**Solutions**:
- Verify certificate paths in config
- Check certificate expiration
- Ensure certificate and key match

### HTTPS Not Working

**Solution**:
```toml
[tls]
enabled = true
cert_path = "/etc/synvoid/certs/tls.crt"
key_path = "/etc/synvoid/certs/tls.key"
```

## Debugging Steps

### Enable Debug Logging

```bash
RUST_LOG=debug synvoid
```

### Check System Status

```bash
curl http://127.0.0.1:8081/api/stats/summary
```

### View Active Connections

```bash
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/stats/sites
```

### Monitor Real-time Metrics

```bash
# WebSocket for live metrics
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/ws/metrics
```

## Getting Help

If issues persist:
1. Check logs at `/var/log/synvoid/`
2. Enable debug logging
3. Review configuration
4. Open an issue on GitHub with:
   - Logs
   - Configuration (remove sensitive values)
   - Steps to reproduce
   - Expected vs actual behavior

## Mesh/WAF Clustering Issues

### Nodes Not Connecting

**Symptom**: Mesh peers not establishing connections

**Solutions**:
1. Check firewall allows the mesh listener. The mesh/control listener defaults to
   **TCP 50051** (`[mesh] port`, default `50051`); QUIC runs on `[mesh]
   quic_port` when set. Port 51820 is the WireGuard VPN default
   (`synvoid-tunnel`), not a mesh port:
   ```bash
   sudo ufw allow 50051/tcp
   # if [mesh] quic_port is configured, allow that UDP port too
   ```

2. Verify network connectivity:
   ```bash
   nc -zv peer.example.com 50051
   ```

3. Check time synchronization:
   ```bash
   timedatectl status
   ```

4. Verify network IDs match:
   ```toml
   [mesh]
   network_id = "production"
   ```

### Threat Intelligence Not Sharing

**Symptom**: Blocklists not synchronizing between nodes

**Solutions**:
1. Enable threat-intel sync. There is no `[tunnel.mesh.sync]` section — sync
   knobs live on `MeshConfig.threat_intel`:
   ```toml
   [tunnel.mesh.threat_intel]
   enabled = true
   push_enabled = true
   sync_enabled = true
   ```

2. Check sync interval (seconds, not a duration string):
   ```toml
   [tunnel.mesh.threat_intel]
   sync_interval_secs = 300
   threat_sync_interval_secs = 3600
   ```

3. Review mesh logs:
   ```bash
   RUST_LOG=debug synvoid 2>&1 | grep mesh
   ```

### High Memory Usage with Mesh

**Symptom**: Memory increases with mesh enabled

**Solutions**:
1. Limit peer connections:
   ```toml
   [tunnel.mesh.connection]
   max_peer_connections = 10
   min_peer_connections = 2
   ```

2. Bound per-peer streaming concurrency (the `MeshConnectionConfig` knobs that
   actually cap memory-per-peer):
   ```toml
   [tunnel.mesh.connection]
   max_concurrent_peer_streams = 32
   max_concurrent_datagram_handlers = 64
   peer_message_timeout_secs = 30
   ```

3. Reduce threat-intel sync frequency:
   ```toml
   [tunnel.mesh.threat_intel]
   max_indicators_per_message = 50
   sync_interval_secs = 900
   ```


## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Debugging false positives/negatives
- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level flood issues
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
- [WAF_MESH.md](./WAF_MESH.md) - Mesh network troubleshooting
- [FAQ.md](./FAQ.md) - Common questions and answers

