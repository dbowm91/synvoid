# Production Deployment Guide

This guide covers production deployment of MaluWAF with security hardening, performance tuning, and operational best practices.

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
./target/release/maluwafwafwaf --generatenewtoken

# Generate and print a token (does not save to config)
./target/release/maluwafwafwaf --generatetoken

# Generate with custom config path
./target/release/maluwafwafwaf --generatenewtoken --config-path /etc/maluwafwafwaf
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
# Create maluwafwaf user
useradd -r -s /bin/false maluwafwafwaf

# Set permissions
chown -R maluwafwaf:maluwafwaf /opt/maluwafwaf
chown -R maluwafwaf:maluwafwaf /var/log/maluwafwafwaf
chown -R maluwafwaf:maluwafwaf /etc/maluwafwafwaf

# Restrict config access
chmod 600 /etc/maluwafwafwaf/main.toml
```

### 4. Secrets Management

Never commit secrets to version control. Use environment variables or secrets management:

```bash
# Environment variable
export MALUWAF_ADMIN_TOKEN=$(cat /run/secrets/admin_token)

# In systemd service
[Service]
EnvironmentFile=/etc/maluwafwafwaf/secrets.env
```

## Performance Tuning

### System Limits

```bash
# /etc/security/limits.conf
maluwafwaf soft nofile 65536
maluwafwaf hard nofile 65536
maluwafwaf soft nproc 65535
maluwafwaf hard nproc 65535
```

### Kernel Parameters

Create `/etc/sysctl.d/99-maluwafwaf.conf`:

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
sysctl -p /etc/sysctl.d/99-maluwafwaf.conf
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
backend maluwafwaf
    option httpchk GET /health
    http-check expect status 200
    server waf1 10.0.1.10:8080 check
    server waf2 10.0.1.11:8080 check backup
```

### Session Affinity

If using challenges, configure sticky sessions:

```haproxy
backend maluwafwaf
    balance source
    stick-table type ip size 1m expire 1h
    stick on src
```

## Monitoring

### Prometheus Alerts

```yaml
groups:
  - name: maluwafwaf
    rules:
      - alert: MaluWAFHighAttackRate
        expr: rate(maluwafwaf_attack_detected_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High attack detection rate"

      - alert: MaluWAFBlackholeActive
        expr: maluwafwaf_blackhole_active == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF in blackhole mode - possible DDoS"

      - alert: MaluWAFHighErrorRate
        expr: rate(maluwafwaf_requests_upstream_error_total[5m]) / rate(maluwafwaf_requests_proxied_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High upstream error rate"

      - alert: MaluWAFHalfOpenConnections
        expr: maluwafwaf_syn_flood_half_open_count > 500
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

Configure log rotation in `/etc/logrotate.d/maluwafwaf`:

```
/var/log/maluwafwaf/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 maluwaf maluwaf
    postrotate
        systemctl reload maluwaf > /dev/null 2>&1 || true
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
      - /var/log/maluwafwaf/access.log
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "maluwaf-%{+yyyy.MM.dd}"
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
lsof -p $(pgrep maluwaf) | wc -l
```

### Debug Mode

Enable debug logging:

```bash
# Temporary
RUST_LOG=debug cargo run

# Systemd override
[Service]
Environment=RUST_LOG=debug,maluwaf=trace
```

## Maintenance

### Configuration Updates

```bash
# Validate configuration
./target/release/maluwaf --configtest

# Reload without downtime
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/config/reload
```

### Backup

```bash
# Backup configuration
tar -czvf maluwaf-config-$(date +%Y%m%d).tar.gz /etc/maluwaf/

# Backup blocklist (stored in data directory)
cp /var/lib/maluwaf/blocks.json blocks-backup-$(date +%Y%m%d).json
```

### Upgrade

```bash
# Build new version
cargo build --release

# Graceful upgrade
systemctl restart maluwaf

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
docker pull maluwaf/maluwaf:latest

# Run with basic config
docker run -d \
  --name maluwaf \
  -p 80:8080 \
  -p 443:8443 \
  -p 8081:8081 \
  -v /path/to/config:/etc/maluwaf \
  -e RUST_LOG=info \
  maluwaf/maluwaf:latest
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  maluwaf:
    image: maluwaf/maluwaf:latest
    container_name: maluwaf
    ports:
      - "80:8080"
      - "443:8443"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config:/etc/maluwaf
      - ./certs:/etc/maluwaf/certs
      - ./logs:/var/log/maluwaf
    environment:
      - RUST_LOG=info
      - MALU_CONFIG_DIR=/etc/maluwaf
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
  --name maluwaf \
  -p 80:8080 \
  -p 443:8443 \
  -e MALU_ADMIN_TOKEN=${MALU_ADMIN_TOKEN} \
  -e MALU_IPC_KEY=${MALU_IPC_KEY} \
  maluwaf/maluwaf:latest
```

## Kubernetes Deployment

### Deployment YAML

```yaml
# maluwaf-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: maluwaf
  labels:
    app: maluwaf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: maluwaf
  template:
    metadata:
      labels:
        app: maluwaf
    spec:
      containers:
      - name: maluwaf
        image: maluwaf/maluwaf:latest
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
        - name: MALU_ADMIN_TOKEN
          valueFrom:
            secretKeyRef:
              name: maluwaf-secrets
              key: admin-token
        volumeMounts:
        - name: config
          mountPath: /etc/maluwaf
        - name: certs
          mountPath: /etc/maluwaf/certs
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
          name: maluwaf-config
      - name: certs
        secret:
          secretName: maluwaf-certs
```

### Service YAML

```yaml
# maluwaf-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: maluwaf
spec:
  type: LoadBalancer
  selector:
    app: maluwaf
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
# maluwaf-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: maluwaf-config
data:
  main.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080

    [admin]
    enabled = true
    port = 8081
    token_env_var = "MALU_ADMIN_TOKEN"

    [logging]
    level = "info"
```

### Ingress (for Kubernetes with Ingress Controller)

```yaml
# maluwaf-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: maluwaf-ingress
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
            name: maluwaf
            port:
              number: 80
```

### Horizontal Pod Autoscaler

```yaml
# maluwaf-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: maluwaf-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: maluwaf
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
