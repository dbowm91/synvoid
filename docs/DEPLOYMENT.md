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
- [ ] Create the dedicated `synvoid` service account and set directory ownership
- [ ] Run `systemd-analyze verify` and `systemd-analyze security` on the unit
- [ ] Build and scan the container image (if you deploy with Docker/Kubernetes)

## Security Hardening

### 1. Admin Token

Generate a secure random token using the built-in CLI command:

```bash
# Generate a new token and save it to config/main.toml
./target/release/synvoid --generatenewtoken

# Generate and print a token (does not save to config)
./target/release/synvoid --generatetoken

# Generate with custom config path
./target/release/synvoid --generatenewtoken --config-path /etc/synvoid
```

Alternatively, generate manually:

```bash
# Using openssl — 32 random bytes rendered as 64 hex characters
openssl rand -hex 32

# Using /dev/urandom
head -c 32 /dev/urandom | xxd -p

# Add to config/main.toml manually. The token must be at least 32 characters
# and must not match the weak-token patterns AdminConfig::validate() rejects.
[admin]
token = "<64-hex-char-token-from-the-command-above>"
```

Prefer `token_env_var` for production deployments (the shipped
`config/main.toml` uses `SYNVOID_ADMIN_TOKEN`) so the secret never lands in a
config file.

### 2. Network Security

Restrict access to admin and metrics ports:

```bash
# iptables rules — admin API (8081). Default bind is 127.0.0.1:8081;
# widen it with [admin] bind_address only if you need remote access.
iptables -A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -j DROP

# The Prometheus exporter port (9090) CANNOT be exposed off-host:
# `MetricsConfig::validate()` rejects any [metrics] bind_address that is not
# loopback (127.0.0.1 / ::1 / localhost), so startup fails rather than
# publishing metrics. Run the scraper as a host-local agent or sidecar, or
# tunnel over SSH — do not add a firewall rule expecting remote scrapes.
```

### 3. Service Account and Directory Ownership

The shipped unit runs as the dedicated `synvoid` account, not root. Binding
ports 80/443 is the only privileged operation, and it is granted with
`CAP_NET_BIND_SERVICE`.

```bash
# Dedicated system account and group.
sudo groupadd --system synvoid
sudo useradd --system --gid synvoid --home-dir /var/lib/synvoid \
  --shell /usr/sbin/nologin synvoid

# Read-only install tree.
sudo install -d -m 0755 -o root -g root /opt/synvoid
sudo install -d -m 0755 -o root -g root /opt/synvoid/admin-ui /opt/synvoid/config

# Writable state, log, cache and runtime directories.
sudo install -d -m 0700 -o synvoid -g synvoid \
  /etc/synvoid /var/lib/synvoid /var/log/synvoid /var/cache/synvoid /run/synvoid

# Binary and jail binaries must stay in the same directory: the jail resolver
# searches only next to the executable, never PATH or the working directory.
sudo install -m 0755 target/release/synvoid /usr/local/bin/synvoid
sudo install -m 0755 target/release/synvoid-wasm-jail /usr/local/bin/synvoid-wasm-jail
sudo install -m 0755 target/release/synvoid-yara-jail /usr/local/bin/synvoid-yara-jail

# Admin UI, static assets, YARA rules and DNS root hints.
sudo install -d /opt/synvoid/admin-ui/dist
sudo cp -a admin-ui/dist/. /opt/synvoid/admin-ui/dist/
sudo cp -a static rules root.hints /opt/synvoid/

# The unit's WorkingDirectory is /opt/synvoid, so relative paths in the
# shipped config (config/error_pages, config/mimes, and the legacy
# honeypot_endpoints.txt lookup) resolve inside the read-only install tree.
sudo cp -a config/error_pages config/mimes /opt/synvoid/config/
sudo install -m 0644 config/honeypot_endpoints.txt /opt/synvoid/config/honeypot_endpoints.txt
sudo install -m 0644 config/honeypot_endpoints.txt /opt/synvoid/honeypot_endpoints.txt

# Authoritative configuration consumed by --config-path /etc/synvoid.
sudo install -d -o synvoid -g synvoid -m 0700 /etc/synvoid/sites
sudo cp config/main.toml /etc/synvoid/main.toml
sudo cp -a config/sites/. /etc/synvoid/sites/
sudo chown -R synvoid:synvoid /etc/synvoid
sudo chmod -R go-rwx /etc/synvoid
```

**Why two config locations?** `/etc/synvoid` is what `--config-path` reads and
what the admin config editor rewrites. `/opt/synvoid/config` holds the shipped
relative-path defaults (`error_pages`, `mimes`) that the process resolves
against its working directory. Keep `/opt/synvoid` root-owned and read-only;
never make the whole install tree writable.

If the admin config editor is **not** used, `/etc/synvoid` may stay root-owned
and read-only: remove it from the unit's `ReadWritePaths=` and do not chown it
to `synvoid`. If the editor **is** used, `/etc/synvoid` must be owned by
`synvoid` (as above) so the service can write `main.toml` and `sites/`.
The editor also writes a legacy `.worker_reload` marker into the working
directory; because `/opt/synvoid` is read-only that marker write logs a
warning, but the handler still calls the Supervisor reload path and the
configuration change is applied through IPC.

### 4. systemd Hardening (Non-Root)

Install and start the shipped unit:

```bash
sudo cp contrib/systemd/synvoid.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now synvoid
```

The unit sets `User=synvoid`, `Group=synvoid`, `UMask=0077`,
`NoNewPrivileges=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`,
`ProtectKernelTunables=true`, `ProtectKernelModules=true`,
`ProtectControlGroups=true`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
`LockPersonality=true`, `RestrictRealtime=true`, and
`SystemCallArchitectures=native`. It creates `/var/lib/synvoid`,
`/var/log/synvoid`, `/var/cache/synvoid` and `/run/synvoid` with the correct
ownership through `StateDirectory=`, `LogsDirectory=`, `CacheDirectory=` and
`RuntimeDirectory=`.

`MemoryDenyWriteExecute` is deliberately **not** set: Wasmtime's JIT and the
dynamic plugin path require executable mappings. Deployments that disable both
may add it as an explicit drop-in.

**Opt-in capabilities.** `CAP_NET_ADMIN` is not granted by default. eBPF
flood/ICMP filtering and WireGuard tunnels need it, plus the matching address
families. Add a drop-in only for those deployments:

```ini
# /etc/systemd/system/synvoid.service.d/capabilities.conf
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET
```

**Verification evidence.** Validate the unit and record the exposure score on
the target host:

```bash
sudo systemd-analyze verify /etc/systemd/system/synvoid.service
systemd-analyze security --offline=yes --no-pager /etc/systemd/system/synvoid.service
```

Measured against this unit on systemd 255: `Overall exposure level …: 4.4 OK`.
The score varies slightly with the systemd version; the properties that matter
are the non-root account, the single capability, the read-only system
filesystem, and the absence of `AF_PACKET`/`AF_NETLINK`.

### 5. Secrets Management

Never commit secrets to version control. Use environment variables or secrets management:

```bash
# Environment variable
export SYNVOID_ADMIN_TOKEN=$(cat /run/secrets/admin_token)

# The shipped unit reads this optional file (a missing file is ignored):
#   EnvironmentFile=-/etc/synvoid/secrets.env
sudo install -m 0600 -o synvoid -g synvoid /dev/null /etc/synvoid/secrets.env
```

## Performance Tuning

### System Limits

```bash
# /etc/security/limits.conf
synvoid soft nofile 65536
synvoid hard nofile 65536
synvoid soft nproc 65535
synvoid hard nproc 65535
```

### Kernel Parameters

Create `/etc/sysctl.d/99-synvoid.conf`:

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
sysctl -p /etc/sysctl.d/99-synvoid.conf
```

### Memory Configuration

Tune rate limiting memory based on expected traffic:

```toml
[rate_limit_memory]
max_ip_entries = 1000000    # 1M unique IPs tracked
cleanup_interval_secs = 60   # Cleanup frequency
num_shards = 256             # Shard count (default)

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
# HAProxy example. The data-plane listener has no `/health` route; use the
# internal liveness path that the frontdoor classifies before WAF routing.
backend synvoid
    option httpchk GET /__internal__/health
    http-check expect status 200
    server waf1 10.0.1.10:8080 check
    server waf2 10.0.1.11:8080 check backup
```

### Session Affinity

If using challenges, configure sticky sessions:

```haproxy
backend synvoid
    balance source
    stick-table type ip size 1m expire 1h
    stick on src
```

## Monitoring

### Prometheus Alerts

```yaml
groups:
  - name: synvoid
    rules:
      - alert: synvoidHighAttackRate
        expr: rate(synvoid_request_enforcement_source_total{source="attack_detection"}[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High attack detection rate"

      - alert: synvoidBlackholeDrops
        expr: rate(synvoid_http_blackhole_drop_total[5m]) > 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Requests silently dropped by the WAF - possible DDoS"

      - alert: synvoidHighErrorRate
        expr: rate(synvoid_requests_upstream_error_total[5m]) / rate(synvoid_requests_proxied_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High upstream error rate"

      - alert: synvoidHalfOpenConnections
        expr: synvoid_syn_flood_half_open_count > 500
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

Configure log rotation in `/etc/logrotate.d/synvoid`:

```
/var/log/synvoid/*.log {
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
      - /var/log/synvoid/access.log
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "synvoid-%{+yyyy.MM.dd}"
```

## Capacity Planning

### Throughput Estimates

The repository does not publish an unqualified requests/sec table. Throughput
depends on the WAF policy, TLS, body size, cache hit rate, CPU/kernel and network
topology. For measured, same-host evidence:

```bash
python3 benchmarks/multi_service/driver.py \
  --workloads vhost-1,vhost-100,vhost-1000,h1-concurrent,waf-small,waf-body
```

Cite the dated directory under `benchmarks/multi_service/results/YYYY-MM-DD/`
together with the revision SHA, host CPU model, build profile and topology.
Loopback results are not production capacity and must not be compared across
hosts, kernels, architectures, build profiles or container runtimes.

### Process Model Assumptions

Capacity planning assumes **one `UnifiedServerWorker` per process**. The
`[defaults.worker_pool].workers` type default is `1`; values above `1` require
`allow_multi_worker = true` and are an advanced fault-isolation mode, not a
capacity lever. Scale a single process with `[process_manager].worker_threads`,
then tune `[tcp].worker_pool_size` for TCP accept concurrency. If one host must
serve more than one process, run separate instances with separate config
directories behind a load balancer and do not expect shared admin sessions,
CSRF tokens, rate-limit budgets, metrics or request logs.

### Capacity Calculations

#### Memory Requirements

```
Rate Limiting Memory:
  Per IP tracking: ~100 bytes
  Formula: max_ip_entries × 100 bytes = memory for rate limiting

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

Measure the target host instead of extrapolating from vCPU count:

- `--process-profiles threads-1,threads-4,threads-8` for Tokio-thread scaling;
- `--process-profiles default` for the canonical single-worker profile;
- `--waf-profile off|on|block` to separate proxy cost from detection/action
  cost;
- report medians over at least three repetitions and include the spread.

Keep the memory/file-descriptor calculations in this section, but feed them
connection rates measured on the target host. Do not present
`+1 vCPU ≈ +40–50% throughput` as a validated scaling law.

#### Estimating Requirements

```
Step 1: Determine peak requests per second
  Example: 25,000 req/sec expected

Step 2: Measure requests/sec per core on the target host
  Run the multi-service harness against the target CPU class and WAF policy.
  Use the measured p95 latency and error rate, not a per-core estimate.
  Apply a 1.5× safety factor to the measured concurrency.

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
2. **Memory-bound**: Increase `rate_limit_memory.max_ip_entries`
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

# Backup blocklist. The filename comes from the configured persistence
# directory: BlockStore writes `<data_dir>/blocks.json`, so with the shipped
# `[defaults.persistence] data_dir = "/var/lib/synvoid"` that is:
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

The repository ships a multi-stage `Dockerfile`. CI builds it in the
`docker-build` job (with a `--configtest` smoke run) but **does not publish
it**. There is no verified public image under `synvoid/synvoid`; build and tag
the image yourself, or push it to your own registry and substitute that
reference below.

```bash
docker build -t synvoid:latest .
```

The image:

- runs as the unprivileged `synvoid` user (UID/GID 10001), never root;
- ships the Supervisor and both jail binaries (`synvoid-wasm-jail`,
  `synvoid-yara-jail`) in `/usr/local/bin`;
- keeps `/opt/synvoid` read-only and writes state to `/var/lib/synvoid`,
  logs to `/var/log/synvoid`, cache to `/var/cache/synvoid`, and runtime data
  to `/run/synvoid`;
- reads configuration from `/etc/synvoid` and defaults to
  `--foreground --config-path /etc/synvoid`;
- exposes only the data-plane port `8080`. Admin (`127.0.0.1:8081`) and metrics
  (`127.0.0.1:9090`) stay loopback inside the container. Publish them only with
  a deliberate, authenticated front door.

Because the container runs as non-root, map host port 80 to container port
8080 as shown below. Binding a port below 1024 *inside* the container would
require `--cap-add NET_BIND_SERVICE`; the default image does not need it.

### Basic Docker Run

```bash
docker run -d \
  --name synvoid \
  -p 80:8080 \
  -e SYNVOID_ADMIN_TOKEN="$(openssl rand -hex 32)" \
  -v /path/to/config:/etc/synvoid \
  -v synvoid-data:/var/lib/synvoid \
  -v synvoid-logs:/var/log/synvoid \
  synvoid:latest
```

`--config-path` is the config **DIRECTORY** (`main.toml` + `sites/`), and the
image default already passes `/etc/synvoid`. `SYNVOID_ADMIN_TOKEN` is only
consulted when the config opts in with
`[admin] token_env_var = "SYNVOID_ADMIN_TOKEN"` (the shipped config does).

If `/path/to/config` is a host bind mount, the runtime user must be able to
read it. Chown it to `10001:10001` only if the admin config editor also needs
to write `main.toml`/`sites/`; otherwise a root-owned, read-only mount is
correct. The built-in healthcheck runs `synvoid --status` over the private
pidfile/IPC socket, so it works whether or not the admin listener is enabled
and never exposes the admin API.

### Docker Compose

```yaml
# docker-compose.yml
services:
  synvoid:
    image: synvoid:latest
    container_name: synvoid
    # The image CMD already runs `--foreground --config-path /etc/synvoid`.
    command: ["--foreground", "--config-path", "/etc/synvoid"]
    ports:
      - "80:8080"
      # Do not publish 8081/9090 here. Admin and metrics bind loopback inside
      # the container; reach them through an SSH tunnel or an authenticating
      # proxy if remote access is required.
    volumes:
      - ./config:/etc/synvoid
      - synvoid-data:/var/lib/synvoid
      - synvoid-logs:/var/log/synvoid
    environment:
      - RUST_LOG=info
      - SYNVOID_ADMIN_TOKEN=${SYNVOID_ADMIN_TOKEN}
    restart: unless-stopped
    # The image healthcheck uses `synvoid --status`, which does not require the
    # admin listener. Override only if you need a different liveness policy.
    networks:
      - waf-network

  upstream:
    image: nginx:alpine
    container_name: upstream
    networks:
      - waf-network

volumes:
  synvoid-data:
  synvoid-logs:

networks:
  waf-network:
    driver: bridge
```

For a read-only root filesystem, mount every writable path and add a tmpfs for
the runtime directory (and the cache, unless it is mounted):

```yaml
    read_only: true
    tmpfs:
      - /run/synvoid
    volumes:
      - ./config:/etc/synvoid
      - synvoid-data:/var/lib/synvoid
      - synvoid-logs:/var/log/synvoid
      - synvoid-cache:/var/cache/synvoid
```

### Docker with Environment Variables

```bash
docker run -d \
  --name synvoid \
  -p 80:8080 \
  -e RUST_LOG=info \
  -e SYNVOID_ADMIN_TOKEN=${SYNVOID_ADMIN_TOKEN} \
  -v synvoid-data:/var/lib/synvoid \
  -v synvoid-logs:/var/log/synvoid \
  synvoid:latest
```

`SYNVOID_ADMIN_TOKEN` is only consulted when the config opts in via
`[admin] token_env_var = "SYNVOID_ADMIN_TOKEN"` (the shipped `config/main.toml`
already sets it). `SYNVOID_IPC_KEY` is generated and passed to worker/jail
children by the Supervisor itself — do not set it by hand.

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
      # The image already defaults to UID/GID 10001; the explicit context keeps
      # the pod non-root even if a cluster policy overrides the image user.
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
      - name: synvoid
        image: synvoid:latest
        imagePullPolicy: IfNotPresent
        # --config-path takes the config DIRECTORY (main.toml + sites/).
        args: ["--foreground", "--config-path", "/etc/synvoid"]
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 443
          name: https
        # Admin stays on 127.0.0.1:8081 inside the pod and is intentionally
        # absent from the Service below.
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
        - name: data
          mountPath: /var/lib/synvoid
        - name: logs
          mountPath: /var/log/synvoid
        - name: cache
          mountPath: /var/cache/synvoid
        - name: run
          mountPath: /run/synvoid
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          # Do not probe the loopback-only admin port from the kubelet. The
          # private status check works with the admin listener enabled or not.
          exec:
            command: ["/bin/sh", "-c", "synvoid --status | grep -q 'Supervisor PID'"]
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command: ["/bin/sh", "-c", "synvoid --status | grep -q 'Supervisor PID'"]
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        # A ConfigMap is read-only. Use a PersistentVolumeClaim for
        # /etc/synvoid if the admin config editor must persist changes.
        configMap:
          name: synvoid-config
      - name: certs
        secret:
          secretName: synvoid-certs
      - name: data
        persistentVolumeClaim:
          claimName: synvoid-data
      - name: logs
        emptyDir: {}
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
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
    targetPort: 443
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
    bind_address = "127.0.0.1"
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
