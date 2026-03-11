# Overseer Process Management

MaluWAF uses a three-tier process architecture (Overseer → Master → Worker) for maximum reliability and upgrade flexibility. This document covers how to manage the overseer process using systemd or cron.

## Process Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         OVERSEER PROCESS                         │
│  - Top-level supervisor (PID 1 or systemd managed)              │
│  - Monitors master process health                                │
│  - Handles upgrades and rollbacks                                │
│  - Persists state to disk                                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ spawns and monitors
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                          MASTER PROCESS                          │
│  - Spawns and manages workers                                    │
│  - Handles IPC from workers and overseer                         │
│  - Coordinates graceful shutdown                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │ spawns and monitors
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                          WORKER PROCESSES                        │
│  - Unified Server Worker (HTTP/HTTPS/HTTP3)                     │
│  - Static File Worker (minification, compression)               │
│  - Handle actual traffic                                         │
└─────────────────────────────────────────────────────────────────┘
```

## Option 1: systemd (Recommended for Linux)

### Installation

1. Copy the service file:
```bash
sudo cp contrib/systemd/maluwaf.service /etc/systemd/system/
```

2. Reload systemd:
```bash
sudo systemctl daemon-reload
```

3. Enable and start:
```bash
sudo systemctl enable maluwaf
sudo systemctl start maluwaf
```

### Service Management

```bash
# Check status
sudo systemctl status maluwaf

# View logs
sudo journalctl -u maluwaf -f

# Restart service
sudo systemctl restart maluwaf

# Stop service
sudo systemctl stop maluwaf

# Reload configuration (sends SIGHUP)
sudo systemctl reload maluwaf
```

### systemd Watchdog

The service file includes watchdog support. The overseer will automatically restart if it becomes unresponsive for 30 seconds. To enable watchdog notifications from MaluWAF, set:

```bash
# In your environment or service file
NOTIFY_SOCKET=/run/systemd/notify
```

### Resource Limits

The default service file sets:
- `LimitNOFILE=65535` - Maximum open files
- `LimitNPROC=65535` - Maximum processes

Adjust these based on your expected traffic load.

## Option 2: cron (Non-systemd Systems)

For systems without systemd (Alpine Linux, older distributions, containers), use the built-in watchdog mode.

### Watchdog Mode

The `--watchdog` flag checks if an overseer is running and starts one if not:

```bash
maluwaf --watchdog
```

This is idempotent - safe to run multiple times.

### cron Configuration

Add to crontab (`crontab -e`):

```cron
# Check every minute
* * * * * /usr/local/bin/maluwaf --watchdog >> /var/log/maluwaf/watchdog.log 2>&1

# Or every 5 minutes
*/5 * * * * /usr/local/bin/maluwaf --watchdog >> /var/log/maluwaf/watchdog.log 2>&1
```

### cron with Log Rotation

Create `/etc/logrotate.d/maluwaf`:

```
/var/log/maluwaf/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
```

## Option 3: Docker/Kubernetes

### Docker

```dockerfile
FROM alpine:latest
COPY maluwaf /usr/local/bin/
CMD ["maluwaf", "--overseer", "--foreground"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: maluwaf
spec:
  replicas: 1
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
        image: maluwaf:latest
        command: ["maluwaf", "--overseer", "--foreground"]
        livenessProbe:
          exec:
            command: ["maluwaf", "--status"]
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          exec:
            command: ["maluwaf", "--status"]
          initialDelaySeconds: 5
          periodSeconds: 10
```

## Option 4: supervisord

For systems using supervisord:

```ini
[program:maluwaf]
command=/usr/local/bin/maluwaf --overseer --foreground
directory=/opt/maluwaf
user=root
autostart=true
autorestart=true
startsecs=5
startretries=3
stdout_logfile=/var/log/maluwaf/stdout.log
stderr_logfile=/var/log/maluwaf/stderr.log
environment=RUST_LOG="info"
```

## Lock File

The overseer creates a lock file at `~/.maluwaf/overseer.lock` containing its PID. This prevents multiple overseer instances and allows the watchdog to detect running instances.

## Health Checks

### Command Line

```bash
# Quick status check
maluwaf --status

# Returns exit code 0 if running, 1 if not
maluwaf --status && echo "Running" || echo "Not running"
```

### HTTP Health Endpoint

The unified server worker exposes:

- `GET /__internal__/health` - Basic health check
- `GET /__internal__/ready` - Readiness probe

## Upgrades

When using systemd or cron, upgrades are handled automatically:

1. Stage the new binary: `maluwaf upgrade stage /path/to/new/binary`
2. Apply the upgrade: `maluwaf upgrade apply`

The overseer coordinates zero-downtime upgrades by:
1. Spawning a new master with the upgraded binary
2. Validating the new master is healthy
3. Draining connections from the old master
4. Promoting the new master

## Troubleshooting

### Overseer won't start

1. Check if already running:
```bash
cat ~/.maluwaf/overseer.lock
ps aux | grep maluwaf
```

2. Remove stale lock file:
```bash
rm ~/.maluwaf/overseer.lock
```

3. Check logs:
```bash
# systemd
journalctl -u maluwaf -n 100

# cron
tail -f /var/log/maluwaf/watchdog.log
```

### Master keeps restarting

1. Check master crash logs:
```bash
cat /tmp/maluwaf-panic.log
```

2. Check configuration:
```bash
maluwaf --configtest
```

3. Increase restart limits in overseer state:
```bash
cat ~/.maluwaf/overseer-state.json
```

### Recovery from failed upgrade

The overseer automatically detects incomplete upgrades and attempts recovery:

1. On startup, it checks `~/.maluwaf/overseer-state.json`
2. If state is `DualMasterActive`, `DrainingOldMaster`, etc., it:
   - Checks if new master is alive → promotes it
   - Checks if old master is alive → restores it
   - If neither alive → starts fresh

Manual recovery:
```bash
maluwaf upgrade recover
```

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment
- [UPGRADE.md](./UPGRADE.md) - Upgrade procedures
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
