# Supervisor Process Management

SynVoid uses a two-tier architecture (Supervisor control plane -> data-plane workers). The default data-plane contract is one UnifiedServerWorker for latency-sensitive I/O plus N CPU offload workers for heavy transforms. This document covers how to manage the supervisor process and its workers.

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
│  - UnifiedServerWorker: network I/O + cheap request-path work   │
│  - CPU workers: bounded heavy task execution                    │
│  - Core pinning where supported (sched_setaffinity)             │
│  - Supervisor-owned lifecycle, health, and rotation             │
└─────────────────────────────────────────────────────────────────┘
```

## Scaling Knobs

Use each knob for its specific scope:

- `worker_threads` configures tokio runtime parallelism inside a unified worker.
- `tcp.worker_pool_size` scales the connection accept path.
- CPU worker count scales bounded heavy task throughput.
- `unified_server_workers` is advanced mode only and should not be treated as the primary throughput knob.

## Advanced Multi-Unified-Worker Mode

`unified_server_workers > 1` is a specialized deployment mode for explicit process isolation needs.
It is not the default throughput strategy for SynVoid.

### Listener And Port-Check Semantics

- Shared-port startup (`SO_REUSEPORT`) is only valid when explicitly enabled for multi-worker mode.
- In shared-port multi-worker mode, listener bind is the source of truth.
- Pre-bind port conflict checks are skipped for that explicit shared-port path to avoid rejecting valid multi-bind startup.
- Outside shared-port multi-worker mode, normal pre-bind conflict checks still apply.

### State Semantics (Per-Worker vs Global)

Per-worker state (not automatically shared across unified workers):
- in-memory connection tracking and drain state
- per-process caches and hot objects
- local runtime counters before aggregation

Supervisor/global state:
- process lifecycle and worker health
- control-plane configuration distribution
- aggregated status and management-plane metrics

### Metrics Aggregation Contract

- Worker metrics are emitted per process.
- Supervisor is responsible for cross-worker aggregation surfaced by status/control APIs.
- Operator-facing totals should be interpreted from supervisor status, not from any single worker process.

### Cache Invalidation And Reload Semantics

- Config reload/rotation is coordinated by the supervisor.
- Each unified worker owns its local in-memory cache and refresh lifecycle.
- Invalidations are applied per worker during reload/rotation; they are not shared-memory invalidations.
- Operationally, treat cache convergence across multiple unified workers as eventual during coordinated reload.

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

## Data-Plane Responsibilities

Unified worker responsibilities:
- listener accept and protocol handling
- TLS orchestration and HTTP parsing
- routing, cheap WAF checks, and request streaming
- cache-hit response serving

CPU worker responsibilities:
- minification/compression/image transforms
- expensive body scanning and deep regex work
- plugin/WASM/serverless execution

Coordination model:
- Supervisor distributes config and control data over signed IPC.
- Unified worker offloads bounded heavy tasks to CPU workers.
- Queue and timeout policies prevent offload saturation from stalling request I/O.

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
