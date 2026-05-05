# Production Deployment Guide

This guide covers production deployment of SynVoid with security hardening, performance tuning, and operational best practices.

## Pre-Deployment Checklist

- [ ] Generate secure admin token
- [ ] Configure SSL/TLS termination
- [ ] Set up log rotation
- [ ] Configure Prometheus metrics scraping
- [ ] Test attack detection rules
- [ ] Validate upstream connectivity
- [ ] Configure firewall rules
- [ ] Set up monitoring alerts

## Security Hardening

### 1. Admin Token

Generate a secure random token using the built-in CLI command:

```bash
# Generate a new token and save it to config/main.toml
./target/release/synvoidwafwaf --generatenewtoken

# Generate and print a token (does not save to config)
./target/release/synvoidwafwaf --generatetoken

# Generate with custom config path
./target/release/synvoidwafwaf --generatenewtoken --config-path /etc/synvoidwafwaf
```

Alternatively, generate manually:

```bash
# Using openssl
openssl rand -hex 32

# Using /dev/urandom
head -c 32 /dev/urandom | xxd -p

# Add to config/main.toml manually
[admin]
token = "your-generated-token-here"
```

### 2. Network Security

Restrict access to admin and metrics ports:

```bash
# iptables rules
iptables -A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -j DROP

iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j DROP
```

### 3. File Permissions

```bash
# Create synvoidwaf user
useradd -r -s /bin/false synvoidwafwaf

# Set permissions
chown -R synvoidwaf:synvoidwaf /opt/synvoidwaf
chown -R synvoidwaf:synvoidwaf /var/log/synvoidwafwaf
chown -R synvoidwaf:synvoidwaf /etc/synvoidwafwaf

# Restrict config access
chmod 600 /etc/synvoidwafwaf/main.toml
```

### 4. Secrets Management

Never commit secrets to version control. Use environment variables or secrets management:

```bash
# Environment variable
export SYNVOID_ADMIN_TOKEN=$(cat /run/secrets/admin_token)

# In systemd service
[Service]
EnvironmentFile=/etc/synvoidwafwaf/secrets.env
```

## Performance Tuning

### System Limits

```bash
# /etc/security/limits.conf
synvoidwaf soft nofile 65536
synvoidwaf hard nofile 65536
synvoidwaf soft nproc 65535
synvoidwaf hard nproc 65535
```

### Kernel Parameters

Create `/etc/sysctl.d/99-synvoidwaf.conf`:

```ini
# Network buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Connection tracking
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1

# Port range
net.ipv4.ip_local_port_range = 1024 65535

# TCP tuning
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Disable swap (optional, for dedicated WAF servers)
vm.swappiness = 1
```

Apply changes:
```bash
sysctl -p /etc/sysctl.d/99-synvoidwaf.conf
```

### Memory Configuration

Tune rate limiting memory based on expected traffic:

```toml
[rate_limit_memory]
max_ips = 1000000           # 1M unique IPs tracked
cleanup_interval_secs = 60   # Cleanup frequency

[blocklist_limits]
max_entries = 100000        # Max blocked IPs
```

Memory calculation:
- Per IP tracking: ~100 bytes
- 1M IPs ≈ 100MB
- Adjust based on available RAM

## High Availability

### Active-Passive Setup

Use a load balancer (HAProxy, nginx, cloud LB) with health checks:

```yaml
# HAProxy example
backend synvoidwaf
    option httpchk GET /health
    http-check expect status 200
    server waf1 10.0.1.10:8080 check
    server waf2 10.0.1.11:8080 check backup
```

### Session Affinity

If using challenges, configure sticky sessions:

```haproxy
backend synvoidwaf
    balance source
    stick-table type ip size 1m expire 1h
    stick on src
```

## Monitoring

### Prometheus Alerts

```yaml
groups:
  - name: synvoidwaf
    rules:
      - alert: synvoidHighAttackRate
        expr: rate(synvoidwaf_attack_detected_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High attack detection rate"

      - alert: synvoidBlackholeActive
        expr: synvoidwaf_blackhole_active == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF in blackhole mode - possible DDoS"

      - alert: synvoidHighErrorRate
        expr: rate(synvoidwaf_requests_upstream_error_total[5m]) / rate(synvoidwaf_requests_proxied_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High upstream error rate"

      - alert: synvoidHalfOpenConnections
        expr: synvoidwaf_syn_flood_half_open_count > 500
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Possible SYN flood attack"
```

### Grafana Dashboard

Key panels to include:
1. Request rate by decision (pass, stall, tarpit)
2. Attack types distribution
3. Rate limiting effectiveness
4. Upstream latency
5. Active connections
6. Half-open connection count

## Log Management

### Log Rotation

Configure log rotation in `/etc/logrotate.d/synvoidwaf`:

```
/var/log/synvoidwaf/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 synvoid synvoid
    postrotate
        systemctl reload synvoid > /dev/null 2>&1 || true
    endpostrotate
}
```

### Log Aggregation

Ship logs to centralized logging:

```yaml
# Filebeat configuration
filebeat.inputs:
  - type: log
    paths:
      - /var/log/synvoidwaf/access.log
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "synvoid-%{+yyyy.MM.dd}"
```

## Capacity Planning

### Throughput Estimates

| Hardware | Requests/sec | Connections |
|----------|--------------|-------------|
| 2 vCPU, 2GB | ~10,000 | ~5,000 |
| 4 vCPU, 4GB | ~25,000 | ~10,000 |
| 8 vCPU, 8GB | ~50,000 | ~20,000 |
| 16 vCPU, 16GB | ~100,000 | ~50,000 |

*Estimates based on simple requests with attack detection enabled*

### Capacity Calculations

#### Memory Requirements

```
Rate Limiting Memory:
  Per IP tracking: ~100 bytes
  Formula: max_ips × 100 bytes = memory for rate limiting

  Example: 1,000,000 IPs × 100 bytes = 100 MB

Proxy Cache Memory:
  Formula: max_size_mb × 1.2 (overhead) = actual memory usage

  Example: 512 MB × 1.2 = ~615 MB

Static File Cache Memory:
  Formula: cache_max_entries × avg_file_size = memory usage

  Example: 10,000 entries × ~50KB avg = 500 MB (if files cached)
```

#### Connection Limits

```
Maximum Connections = (Available file descriptors) / safety margin

  Typical safety margin: 0.8-0.9
  Example: 65535 fds × 0.8 = ~52,000 max connections

Half-Open Connections (SYN flood protection):
  half_open_max should be 1-2% of max connections
  Example: 50,000 max × 0.02 = 1,000 half-open

Rate Limit Buckets:
  Each unique IP consumes ~100 bytes
  1M tracked IPs = 100 MB per rate limit mode (isolated)
```

#### Throughput Scaling

```
Baseline (per 2 vCPU):
  Simple requests: ~10,000 req/sec
  With attack detection: ~8,000 req/sec (-15-20%)

Scaling factors:
  +1 vCPU ≈ +40-50% throughput (diminishing returns after 8 cores)
  +1 GB RAM ≈ +20% connection capacity
  Enable caching: +100-300% effective throughput for cached content

Real-world example:
  Hardware: 8 vCPU, 8 GB RAM
  Expected: 50,000 req/sec simple, 40,000 req/sec with WAF
  Peak memory: ~4 GB (leaving headroom)
  Connection limit: ~52,000 (with 65K fds)
```

#### Estimating Requirements

```
Step 1: Determine peak requests per second
  Example: 25,000 req/sec expected

Step 2: Calculate required cores
  With WAF overhead: 25,000 / 8,000 per core = ~3.2 cores
  Safety factor 1.5×: 3.2 × 1.5 = ~5 cores → use 8 vCPU

Step 3: Calculate memory needs
  Rate limit (1M IPs): 100 MB
  Proxy cache (512 MB): 615 MB actual
  Static cache: 500 MB
  OS + buffer: 1 GB
  Total: ~2.2 GB minimum → use 4-8 GB

Step 4: Configure limits
  [defaults.ratelimit.global]
  per_second = 25000  # Handle expected peak × 1.5
  max_connections = 50000  # Based on file descriptor limit
```

### Scaling Guidelines

1. **CPU-bound**: Add more cores or instances
2. **Memory-bound**: Increase rate_limit_memory.max_ips
3. **Connection-bound**: Tune kernel parameters and increase max_connections
4. **Upstream latency**: Add more backend servers

## Troubleshooting

### High CPU Usage

1. Check attack detection patterns
2. Reduce paranoia level
3. Profile with `perf top`
4. Check regex complexity

### Memory Growth

1. Check rate limit cleanup
2. Verify blocklist expiration
3. Monitor IP tracking size
4. Check for connection leaks

### Connection Issues

```bash
# Check connection states
ss -s

# Check SYN backlog
netstat -s | grep SYN

# Check file descriptors
lsof -p $(pgrep synvoid) | wc -l
```

### Debug Mode

Enable debug logging:

```bash
# Temporary
RUST_LOG=debug cargo run

# Systemd override
[Service]
Environment=RUST_LOG=debug,synvoid=trace
```

## Maintenance

### Configuration Updates

```bash
# Validate configuration
./target/release/synvoid --configtest

# Reload without downtime
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/config/reload
```

### Backup

```bash
# Backup configuration
tar -czvf synvoid-config-$(date +%Y%m%d).tar.gz /etc/synvoid/

# Backup blocklist (stored in data directory)
cp /var/lib/synvoid/blocks.json blocks-backup-$(date +%Y%m%d).json
```

### Upgrade

```bash
# Build new version
cargo build --release

# Graceful upgrade
systemctl restart synvoid

# Or zero-downtime with two instances
# (deploy new version on standby server)
```

## Incident Response

### DDoS Attack

1. Check metrics for attack type
2. Verify blackhole mode status
3. Consider enabling stricter flood limits
4. Block persistent attacker IPs at firewall level

### False Positives

1. Identify affected pattern in logs
2. Add exception to site config
3. Reload configuration
4. Document exception reason

### Upstream Failure

1. Check health endpoints
2. Verify network connectivity
3. Check upstream server health
4. Review error logs for patterns

## Docker Deployment

### Basic Docker Run

```bash
# Pull or build image
docker pull synvoid/synvoid:latest

# Run with basic config
docker run -d \
  --name synvoid \
  -p 80:8080 \
  -p 443:8443 \
  -p 8081:8081 \
  -v /path/to/config:/etc/synvoid \
  -e RUST_LOG=info \
  synvoid/synvoid:latest
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  synvoid:
    image: synvoid/synvoid:latest
    container_name: synvoid
    ports:
      - "80:8080"
      - "443:8443"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config:/etc/synvoid
      - ./certs:/etc/synvoid/certs
      - ./logs:/var/log/synvoid
    environment:
      - RUST_LOG=info
      - SYNVOID_CONFIG_DIR=/etc/synvoid
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - waf-network

  upstream:
    image: nginx:alpine
    container_name: upstream
    networks:
      - waf-network

networks:
  waf-network:
    driver: bridge
```

### Docker with Environment Variables

```bash
docker run -d \
  --name synvoid \
  -p 80:8080 \
  -p 443:8443 \
  -e SYNVOID_ADMIN_TOKEN=${SYNVOID_ADMIN_TOKEN} \
  -e SYNVOID_IPC_KEY=${SYNVOID_IPC_KEY} \
  synvoid/synvoid:latest
```

## Kubernetes Deployment

### Deployment YAML

```yaml
# synvoid-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: synvoid
  labels:
    app: synvoid
spec:
  replicas: 3
  selector:
    matchLabels:
      app: synvoid
  template:
    metadata:
      labels:
        app: synvoid
    spec:
      containers:
      - name: synvoid
        image: synvoid/synvoid:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8443
          name: https
        - containerPort: 8081
          name: admin
        env:
        - name: RUST_LOG
          value: "info"
        - name: SYNVOID_ADMIN_TOKEN
          valueFrom:
            secretKeyRef:
              name: synvoid-secrets
              key: admin-token
        volumeMounts:
        - name: config
          mountPath: /etc/synvoid
        - name: certs
          mountPath: /etc/synvoid/certs
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: synvoid-config
      - name: certs
        secret:
          secretName: synvoid-certs
```

### Service YAML

```yaml
# synvoid-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: synvoid
spec:
  type: LoadBalancer
  selector:
    app: synvoid
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
```

### ConfigMap

```yaml
# synvoid-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: synvoid-config
data:
  main.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080

    [admin]
    enabled = true
    port = 8081
    token_env_var = "SYNVOID_ADMIN_TOKEN"

    [logging]
    level = "info"
```

### Ingress (for Kubernetes with Ingress Controller)

```yaml
# synvoid-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: synvoid-ingress
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: synvoid
            port:
              number: 80
```

### Horizontal Pod Autoscaler

```yaml
# synvoid-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: synvoid-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: synvoid
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [GETTING_STARTED.md](./GETTING_STARTED.md) - Quick start guide
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common deployment issues
- [CONFIGURATION.md](./CONFIGURATION.md) - Configuration reference
