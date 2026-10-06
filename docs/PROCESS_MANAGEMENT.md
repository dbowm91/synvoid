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
│  - Manages supervised worker restarts and config reload         │
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

- `[tokio] worker_threads` configures tokio runtime parallelism inside a unified worker (`"auto"` or a number; a legacy `{ worker_threads = N }` table also parses).
- `[tcp] worker_pool_size` scales the connection accept path.
- CPU worker count scales bounded heavy task throughput.
- `[defaults.worker_pool] workers` is the effective `unified_server_workers` process count (the Supervisor copies it into `process_manager.unified_server_workers` at startup). It is advanced mode only and should not be treated as the primary throughput knob.

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

1. Create the runtime directories the unit expects. SynVoid writes access logs
   to `/var/log/synvoid` and threat-level history to `/var/lib/synvoid`, and
   `--configtest` fails if the access-log directory is missing:
```bash
sudo install -d -m 0755 /opt/synvoid /var/log/synvoid /var/lib/synvoid
```

2. Copy the service file:
```bash
sudo cp contrib/systemd/synvoid.service /etc/systemd/system/
```

3. Reload systemd:
```bash
sudo systemctl daemon-reload
```

4. Enable and start:
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

# Reload configuration and distribute it to workers.
# `systemctl reload synvoid` runs the unit's ExecReload, which is `synvoid --rehash`:
# it locates the Supervisor through its pidfile and sends
# `SupervisorCommand::ReloadConfig` over IPC. Do not `kill -HUP` the Supervisor —
# SynVoid has no inbound SIGHUP handler (SIGHUP only appears as an *outbound*
# signal inside `synvoid-ipc`), so a manual SIGHUP is a silent no-op.
synvoid --rehash
```

### systemd Watchdog

The shipped unit does **not** declare `WatchdogSec`. SynVoid does not implement
systemd notification: there is no `sd_notify`, `WATCHDOG=1`, or `NOTIFY_SOCKET`
handling anywhere in `src/` or `crates/` (the `sd-notify` dependency was
removed — see `plans/root_dependency_ownership.md`). Adding `WatchdogSec` to
this unit would make systemd consider the service wedged after the timeout and
restart it in a loop, because no watchdog notification is ever sent.

Use `Restart=always` plus `RestartSec` (already in the unit) and the
`/__internal__/health` data-plane path for liveness instead.

### Unit-file history

The unit shipped a broken `ExecStart` (`--overseer` is not a SynVoid flag, so the
process exited 2 before reading any configuration), an unread
`Environment=SYNVOID_CONFIG_PATH`, and the watchdog pair above. All were fixed
in `contrib/systemd/synvoid.service`; the audit record with reproduction
evidence is `architecture/quickstart_verification_findings.md` (F-4). The unit
also sets `Environment=XDG_DATA_HOME=/var/lib/synvoid` so that
`PidFileManager`'s `dirs::data_dir()` resolves somewhere `ProtectHome=true`
does not hide — without it the pidfile and IPC socket land under `/root` and
`--status` / `--stop` / `--rehash` cannot find the Supervisor.

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
            command: ["synvoid", "--status"]
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          exec:
            command: ["synvoid", "--status"]
          initialDelaySeconds: 5
          periodSeconds: 10
```

## gRPC Control Plane

SynVoid exposes a formal gRPC API for remote management and CLI interaction. This API is the primary way to interact with the Supervisor.

- **API Definition:** `proto/control.proto`
- **Default Bind:** `127.0.0.1:50051` (`[supervisor] control_api_addr`)
- **Security:** plaintext loopback by default. TLS is **opt-in** via
  `[supervisor] control_api_tls` (requires `cert_path` + `key_path`) and is
  **server-authenticated only** — `src/supervisor/api.rs` builds
  `ServerTlsConfig::new().identity(...)` and never requests a client
  certificate, so **mTLS is not implemented**. `--control-api-tls` only tells
  the CLI client to speak TLS to a control plane that is already configured for
  it; it does not configure the server.

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

The file handoff is accepted when the file is regular, owned by the current
Unix user, and has no group/world permission bits; the supervisor's owner-only
`0600` mode is valid. The loader applies `O_NOFOLLOW` and checks the opened
file descriptor's metadata to prevent symlink and replacement races.

Signed IPC uses one big-endian `u32` length prefix around each postcard
envelope. Receivers verify that the prefix exactly matches the bytes received,
then enforce the timestamp window, HMAC, and nonce replay cache. Transport
adapters that read the prefix before decoding restore it before invoking the
signed decoder.

## Worker Lifecycle

There is **no** `STARTING` / `ACTIVE` / `ROTATING` / `UPGRADING` / `RECOVERING`
state enum. `src/supervisor/state.rs` defines `SupervisorState` as a plain
struct of shared handles (config, shutdown broadcast, probe/suspicious-word/
upstream-error/threat-level trackers, block store, and — under the `mesh`
feature — the transport manager and org-key manager); `ProcessManager` tracks
worker PIDs and restarts directly.

What actually exists:

| Mechanism | Where | Behavior |
|-----------|-------|----------|
| Worker supervision | `supervisor::process` | Bounded restart with `Restart=always`-style backoff (`max_restart_attempts`, `restart_cooldown_secs` in `[process_manager]`) |
| Config reload | `POST /api/config/reload` or `synvoid --rehash` | Reloads `main.toml` and distributes it over signed IPC to running workers |
| Graceful drain | `synvoid --stop` / `__internal__/drain` | Loopback-only drain signalling; `GET /__internal__/health` then answers **503** with `{"status":"draining"}` |

## Health Checks

### CLI

```bash
# Check status via gRPC
synvoid --status
```

### HTTP Health Endpoints

The **data plane** (8080/443) exposes, handled by the `synvoid-http` frontdoor
before WAF routing:
- `GET /__internal__/health` - 200 `{"status":"healthy"}`, or 503 while draining
- `GET /__internal__/ready` - readiness probe

The **admin API** (8081) exposes a separate, public, unauthenticated
`GET /health` — there is no `/api/health` route.

## Upgrades

Upgrades are **not** supervisor-coordinated and **not** zero-downtime. There is
no new-supervisor-start / worker-rotation / drain / handoff sequence in the
code: `src/supervisor/` contains no upgrade task and the CLI has no `--upgrade`
flag. `[upgrade]` fields (`staged_dir`, `validation_retries`,
`drain_timeout_secs`, …) are declared configuration with no orchestrator
attached.

Use the manual procedure in [UPGRADE.md](./UPGRADE.md): stop, replace the
binary, start. For uninterrupted service, run two instances behind a load
balancer and move traffic yourself.

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance tuning
