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
- [Performance Issues](#performance-issues)
  - [High Memory Usage](#high-memory-usage)
  - [High CPU Usage](#high-cpu-usage)
- [Configuration Issues](#configuration-issues)
  - [Config Validation Failures](#config-validation-failures)
  - [Site Not Loading](#site-not-loading)
- [Logging Issues](#logging-issues)
  - [Logs Not Appearing](#logs-not-appearing)
- [Mesh Network Issues](#meshwaf-clustering-issues)

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
1. Lower paranoia level:
```toml
[defaults.attack_detection]
paranoia_level = 1
```

2. Disable specific detection:
```toml
[defaults.attack_detection.ssrf]
enabled = false
```

3. Add domain to allowlist:
```toml
[defaults.attack_detection.ssrf]
allowed_domains = ["api.yourdomain.com"]
```

### False Negatives

**Symptom**: Attacks not detected

**Solutions**:
1. Increase paranoia level:
```toml
[defaults.attack_detection]
paranoia_level = 3
```

2. Enable additional detection:
```toml
[defaults.attack_detection]
enabled = true

[defaults.attack_detection.sqli]
enabled = true
```

3. Add custom patterns:
```toml
[defaults.attack_detection.path_traversal]
custom_patterns = ["/etc/passwd", "boot.ini"]
```

## Performance Issues

### High Memory Usage

**Possible causes**:
- Too many tracked IPs in rate limiting
- Large proxy cache
- Memory leak

**Solutions**:
```toml
[defaults.rate_limit_memory]
max_ips = 100000
cleanup_interval_secs = 30
```

```toml
[defaults.proxy_cache]
enabled = false
```

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

**Solution**: Verify token in header:
```bash
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/health
```

Generate new token:
```bash
./synvoid --generatenewtoken
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
RUST_LOG=warn ./synvoid
```

## Metrics Issues

### Prometheus Not Scraping

**Verify metrics endpoint**:
```bash
curl http://localhost:9090/metrics
```

**Check configuration**:
```toml
[metrics]
enabled = true
port = 9090
```

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
RUST_LOG=debug ./synvoid
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
1. Check firewall allows UDP port 51820:
   ```bash
   sudo ufw allow 51820/udp
   ```

2. Verify network connectivity:
   ```bash
   nc -zvu peer.example.com 51820
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
1. Enable sync in configuration:
   ```toml
   [tunnel.mesh.sync]
   share_ip_reputation = true
   share_blocklists = true
   ```

2. Check sync interval:
   ```toml
   [tunnel.mesh.sync]
   sync_interval = "5s"
   ```

3. Review mesh logs:
   ```bash
   RUST_LOG=debug ./synvoid 2>&1 | grep mesh
   ```

### High Memory Usage with Mesh

**Symptom**: Memory increases with mesh enabled

**Solutions**:
1. Limit peer connections:
   ```toml
   [tunnel.mesh.connection]
   max_peer_connections = 10
   ```

2. Reduce sync frequency:
   ```toml
   [tunnel.mesh.sync]
   sync_interval = "30s"
   full_sync_interval = "10m"
   ```

3. Limit bandwidth:
   ```toml
   [tunnel.mesh.limits]
   max_bandwidth_mbps = 50
   ```


## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Debugging false positives/negatives
- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level flood issues
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
- [WAF_MESH.md](./WAF_MESH.md) - Mesh network troubleshooting
- [FAQ.md](./FAQ.md) - Common questions and answers

