# Supervisor Process Management

SynVoid uses a two-tier "Shared-Nothing Architecture" (Supervisor → Worker) for maximum performance, linear scalability, and robust security isolation. This document covers how to manage the supervisor process and its workers.

## Process Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SUPERVISOR PROCESS                        │
│  - Entry point and Control Plane hub                            │
│  - Monitors worker process health                               │
│  - Hosts gRPC Management API (proto/control.proto)              │
│  - Handles Raft consensus, DHT, and Mesh transport               │
│  - Manages zero-downtime worker rotations                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │ spawns and monitors
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                         WORKER PROCESSES                         │
│  - Isolated Data Plane engines                                  │
│  - Shared-Nothing: independent listeners (SO_REUSEPORT)          │
│  - Core-pinned for maximum performance (sched_setaffinity)      │
│  - Lightweight: focus strictly on request handling              │
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

# Reload configuration (triggers worker rotation)
sudo systemctl reload synvoid
```

### systemd Watchdog

The service file includes watchdog support. The supervisor will automatically restart if it becomes unresponsive. To enable watchdog notifications from SynVoid, set:

```bash
# In your environment or service file
NOTIFY_SOCKET=/run/systemd/notify
```

## Option 2: Docker/Kubernetes

### Docker

```dockerfile
FROM alpine:latest
COPY synvoid /usr/local/bin/
CMD ["synvoid", "--foreground"]
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
        command: ["synvoid", "--foreground"]
        livenessProbe:
          exec:
            command: ["synvoid", "status"]
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          exec:
            command: ["synvoid", "status"]
          initialDelaySeconds: 5
          periodSeconds: 10
```

## gRPC Control Plane

SynVoid exposes a formal gRPC API for remote management and CLI interaction. This API is the primary way to interact with the Supervisor.

- **API Definition:** `proto/control.proto`
- **Default Port:** 50051 (configurable)
- **Security:** Protected by TLS and mutual authentication (mTLS).

The CLI `CommandClient` automatically uses gRPC to communicate with the local or remote Supervisor.

## Shared-Nothing Data Plane

Workers operate in a shared-nothing environment to eliminate coordination overhead:

- **SO_REUSEPORT:** Each worker binds to the same listening ports. The kernel handles load balancing across workers.
- **CPU Pinning:** Workers are automatically pinned to specific CPU cores.
- **IPC Coordination:** The Supervisor pushes configuration and threat intelligence to workers via a high-speed binary IPC protocol.

## IPC Session Key Architecture

The IPC session key secures communication between the Supervisor and worker processes.

### Key Transfer Flow

```
1. Supervisor initializes
   └── Creates temp file with session key (mode 0600)

2. Supervisor spawns Worker processes
   └── Passes IPC key via temp file

3. Worker reads IPC key from temp file
   └── Deletes temp file immediately after reading
```

## State Machine

The supervisor maintains a state machine to coordinate worker rotations and upgrades.

### State Descriptions

| State | Description |
|-------|-------------|
| `STARTING` | Supervisor initializing, loading configuration |
| `ACTIVE` | Normal operation with workers handling traffic |
| `ROTATING` | Spawning new workers and draining old ones |
| `UPGRADING` | Supervisor itself is being replaced |
| `RECOVERING` | Attempting to restore from failure |

## Health Checks

### CLI

```bash
# Check status via gRPC
synvoid status
```

### HTTP Health Endpoint

Workers expose:
- `GET /__internal__/health` - Basic health check
- `GET /__internal__/ready` - Readiness probe

## Upgrades

Upgrades are coordinated by the Supervisor to ensure zero downtime:

1. **New Supervisor Start:** A new Supervisor process is started.
2. **Worker Rotation:** The new Supervisor spawns a new generation of workers.
3. **Old Worker Drain:** Old workers are signaled to finish existing connections and exit.
4. **Handoff:** The old Supervisor exits once all its workers have drained.

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
