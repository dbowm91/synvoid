# Overseer Process Management

SynVoid uses a three-tier process architecture (Overseer → Master → Worker) for maximum reliability and upgrade flexibility. This document covers how to manage the overseer process using systemd or cron.

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
sudo cp contrib/systemd/synvoid.service /etc/systemd/system/
```

2. Reload systemd:
```bash
sudo systemctl daemon-reload
```

3. Enable and start:
```bash
sudo systemctl enable synvoid
sudo systemctl start synvoid
```

### Service Management

```bash
# Check status
sudo systemctl status synvoid

# View logs
sudo journalctl -u synvoid -f

# Restart service
sudo systemctl restart synvoid

# Stop service
sudo systemctl stop synvoid

# Reload configuration (sends SIGHUP)
sudo systemctl reload synvoid
```

### systemd Watchdog

The service file includes watchdog support. The overseer will automatically restart if it becomes unresponsive for 30 seconds. To enable watchdog notifications from SynVoid, set:

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
synvoid --watchdog
```

This is idempotent - safe to run multiple times.

### cron Configuration

Add to crontab (`crontab -e`):

```cron
# Check every minute
* * * * * /usr/local/bin/synvoid --watchdog >> /var/log/synvoid/watchdog.log 2>&1

# Or every 5 minutes
*/5 * * * * /usr/local/bin/synvoid --watchdog >> /var/log/synvoid/watchdog.log 2>&1
```

### cron with Log Rotation

Create `/etc/logrotate.d/synvoid`:

```
/var/log/synvoid/*.log {
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
COPY synvoid /usr/local/bin/
CMD ["synvoid", "--overseer", "--foreground"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: synvoid
spec:
  replicas: 1
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
        image: synvoid:latest
        command: ["synvoid", "--overseer", "--foreground"]
        livenessProbe:
          exec:
            command: ["synvoid", "--status"]
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          exec:
            command: ["synvoid", "--status"]
          initialDelaySeconds: 5
          periodSeconds: 10
```

## Option 4: supervisord

For systems using supervisord:

```ini
[program:synvoid]
command=/usr/local/bin/synvoid --overseer --foreground
directory=/opt/synvoid
user=root
autostart=true
autorestart=true
startsecs=5
startretries=3
stdout_logfile=/var/log/synvoid/stdout.log
stderr_logfile=/var/log/synvoid/stderr.log
environment=RUST_LOG="info"
```

## Lock File

The overseer creates a lock file at `~/.synvoid/overseer.lock` containing its PID. This prevents multiple overseer instances and allows the watchdog to detect running instances.

## IPC Session Key Architecture

The IPC session key secures communication between the master and worker processes. It is passed via a temporary file rather than an environment variable for security.

### Key Transfer Flow

```
1. Overseer spawns Master process
   └── Creates temp file with session key (mode 0600)

2. Master reads IPC key from temp file
   └── Deletes temp file immediately after reading

3. Master spawns Worker processes
   └── Passes IPC key via temp file (same pattern)

4. Worker reads IPC key from temp file
   └── Deletes temp file immediately after reading
```

### Security Properties

- **File permissions 0600**: Only the owner can read/write the key file
- **Immediate deletion**: Temp file is deleted after reading, leaving no trace
- **No env var exposure**: Keys don't appear in process environment (viewable via `/proc/PID/environ`)
- **Fallback**: Falls back to `SYNVOID_IPC_KEY` env var only if `allow_insecure_ipc_key = true` (default: fail-hard)

### Configuration

```toml
[process]
allow_insecure_ipc_key = false  # Default: false (fail if temp file unavailable)
```

### Troubleshooting

```bash
# Check if temp file exists during startup (race condition indicator)
ls -la /tmp/synvoid-ipc-key-* 2>/dev/null || echo "Temp file cleaned up (good)"

# Verify key file permissions if startup fails
strace -e trace=file synvoid 2>&1 | grep SYNVOID_IPC_KEY
```

## State Machine

The overseer maintains a state machine to coordinate upgrades, handle failures, and ensure reliability.

### State Diagram

```
                         ┌──────────────────┐
                         │     STARTING     │
                         │  (Initial state) │
                         └────────┬─────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   SINGLE_MASTER_ACTIVE  │
                    │  (Normal operation)     │
                    └────────┬────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────┐ ┌──────────────────┐ ┌─────────────────┐
│ UPGRADE_STAGING │ │ DUAL_MASTER_ACTIVE│ │   RECOVERING   │
│ (Binary staged) │ │ (New master up)  │ │ (From crash)   │
└────────┬────────┘ └────────┬─────────┘ └─────────────────┘
         │                   │                     │
         │                   │                     ▼
         │                   │           ┌─────────────────┐
         │                   │           │ SINGLE_MASTER_  │
         │                   │           │ ACTIVE          │
         │                   │           └─────────────────┘
         │                   │
         │                   ▼
         │         ┌──────────────────┐
         │         │ DRAINING_OLD_MASTER│
         │         │ (Graceful shutdown)│
         │         └────────┬───────────┘
         │                  │
         │                  ▼
         │        ┌─────────────────┐
         │        │ PROMOTING_NEW_MASTER│
         └───────►│ (Switchover)     │
                  └─────────────────┘
```

### State Descriptions

| State | Description |
|-------|-------------|
| `STARTING` | Overseer initializing, spawning initial master |
| `SINGLE_MASTER_ACTIVE` | Normal operation with one master process |
| `UPGRADE_STAGING` | New binary staged, awaiting activation |
| `DUAL_MASTER_ACTIVE` | Both old and new masters running during upgrade |
| `DRAINING_OLD_MASTER` | Old master gracefully shutting down connections |
| `PROMOTING_NEW_MASTER` | Switching control to new master |
| `RECOVERING` | Attempting to restore from partial failure state |

### Upgrade Flow (Normal)

1. **STAGING**: New binary placed, overseer validates it starts
2. **DUAL_MASTER_ACTIVE**: Old master continues serving, new master starts
3. **DRAINING_OLD_MASTER**: Old master stops accepting new connections
4. **PROMOTING_NEW_MASTER**: New master takes over
5. **SINGLE_MASTER_ACTIVE**: Old master exits, normal operation resumes

### Recovery Flow (From Failure)

1. Overseer reads `overseer-state.json` on startup
2. If state indicates incomplete upgrade:
   - Checks if new master is alive → promotes it
   - Checks if old master is alive → restores it
   - If neither alive → starts fresh
3. State is persisted every 15 seconds during normal operation

### State Persistence

The overseer persists state to `~/.synvoid/overseer-state.json`:

```json
{
  "state": "SINGLE_MASTER_ACTIVE",
  "master_pid": 12345,
  "upgraded_from": "1.2.3",
  "upgraded_to": "1.2.4",
  "last_update": "2024-01-15T10:30:00Z"
}
```

This enables recovery after crashes or power failures.

## Health Checks

### Command Line

```bash
# Quick status check
synvoid --status

# Returns exit code 0 if running, 1 if not
synvoid --status && echo "Running" || echo "Not running"
```

### HTTP Health Endpoint

The unified server worker exposes:

- `GET /__internal__/health` - Basic health check
- `GET /__internal__/ready` - Readiness probe

## Upgrades

When using systemd or cron, upgrades are handled automatically:

1. Stage the new binary: `synvoid upgrade stage /path/to/new/binary`
2. Apply the upgrade: `synvoid upgrade apply`

The overseer coordinates zero-downtime upgrades by:
1. Spawning a new master with the upgraded binary
2. Validating the new master is healthy
3. Draining connections from the old master
4. Promoting the new master

## Troubleshooting

### Overseer won't start

1. Check if already running:
```bash
cat ~/.synvoid/overseer.lock
ps aux | grep synvoid
```

2. Remove stale lock file:
```bash
rm ~/.synvoid/overseer.lock
```

3. Check logs:
```bash
# systemd
journalctl -u synvoid -n 100

# cron
tail -f /var/log/synvoid/watchdog.log
```

### Master keeps restarting

1. Check master crash logs:
```bash
cat /tmp/synvoid-panic.log
```

2. Check configuration:
```bash
synvoid --configtest
```

3. Increase restart limits in overseer state:
```bash
cat ~/.synvoid/overseer-state.json
```

### Recovery from failed upgrade

The overseer automatically detects incomplete upgrades and attempts recovery:

1. On startup, it checks `~/.synvoid/overseer-state.json`
2. If state is `DualMasterActive`, `DrainingOldMaster`, etc., it:
   - Checks if new master is alive → promotes it
   - Checks if old master is alive → restores it
   - If neither alive → starts fresh

Manual recovery:
```bash
synvoid upgrade recover
```

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment
- [UPGRADE.md](./UPGRADE.md) - Upgrade procedures
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
