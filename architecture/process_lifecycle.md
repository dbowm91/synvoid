# Process Lifecycle & Execution Model

SynVoid uses a "Shared-Nothing Architecture" to achieve maximum performance, linear scalability, and robust security isolation. The Supervisor is the single parent process that manages workers.

## The Hierarchy

### 1. Supervisor (Control Plane)

The Supervisor is the central parent process that spawns and monitors workers, provides the admin API, and coordinates zero-downtime upgrades.

- **Responsibilities:**
  - **Process Management:** Spawning and monitoring Worker processes via `ProcessManager`.
  - **Admin API:** Hosts the management interface.
  - **Block Store:** Manages persistent IP blocklists.
  - **IPC Coordination:** Broadcasts configuration and threat intelligence to workers.
  - **Zero-Downtime Upgrades:** Coordinating worker rotations and hot-reloads via `UpgradeOrchestrator`.
  - **gRPC Control Plane:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management.
- **Key Logic:** `src/supervisor/`
- **CLI Flag:** Running with no flags or `--foreground` starts the Supervisor (default mode).

### 2. Worker (Data Plane)

Workers are lightweight, "dumb" request-handling engines that operate in a shared-nothing environment. SynVoid uses three worker types:

- **UnifiedServerWorker:** Primary worker handling HTTP/HTTPS/HTTP3 + WAF + proxy via a single Tokio async event loop. Handles all site routing and security enforcement.
- **StaticWorker:** Dedicated worker for background tasks like CSS/JS minification and image compression. Communicates with the unified server via IPC.
- **Legacy Worker (BaseWorkerProcess):** Deprecated raw TCP/UDP proxy worker. Unused for HTTP traffic; requires further investigation to determine if it should be removed.

- **Isolation:** Each worker process is completely independent.
- **Kernel Load Balancing:** Uses `SO_REUSEPORT` during worker upgrades to allow kernel distribution across old and new workers. Initial workers use `reuse_port: false` (default). See `src/process/spawn.rs:43`.
- **CPU Pinning:** On Linux, workers are automatically assigned CPU affinity based on worker ID via `sched_setaffinity`. Not supported on macOS/BSD (logs warning).
- **Minimal Intelligence:** Workers focus strictly on request handling (WAF pipeline, proxying). They receive threat intelligence and configuration updates from the Supervisor.
- **Key Logic:** `src/worker/`

---

## Communication Flow (gRPC & IPC)

SynVoid utilizes a tiered communication strategy:

1.  **External Management (gRPC):** The CLI (`CommandClient`) and remote managers communicate with the Supervisor via gRPC (localhost only for local IPC).
2.  **Internal Coordination (IPC):** The Supervisor communicates with Workers using a high-speed, binary IPC protocol over Unix domain sockets or Windows named pipes.
3.  **Mesh Network:** Supervisors communicate with other Supervisors via the Mesh transport (QUIC) to maintain global state (Raft/DHT).

---

## Shared-Nothing Data Plane

The transition to a shared-nothing model ensures that the data plane can scale linearly with the number of CPU cores:

- **No Shared State:** Workers do not share memory or mutexes for request handling.
- **Independent Listeners:** Each worker opens its own set of listeners using `SO_REUSEPORT`.
- **Async Efficiency:** Each worker runs a dedicated Tokio runtime optimized for its assigned core.

---

## Zero-Downtime Upgrades

Upgrades are coordinated by the Supervisor via `UpgradeOrchestrator`:

1.  **Stage:** Binary is validated via preflight checks (startup time, config compatibility).
2.  **Apply:** Rolling restart of workers one at a time (configurable window size).
3.  **Health Check:** Each new worker must pass health check before old worker is drained.
4.  **Auto-Rollback:** If health check fails, the upgrade is automatically rolled back.

---

## Process State & Health Monitoring

The Supervisor provides a unified view of the system health:

- **Worker Monitoring:** The Supervisor monitors worker process exits and heartbeats.
- **Self-Healing:** If a worker fails, the Supervisor immediately spawns a replacement and pins it to the correct core.
- **gRPC Status:** The `CommandClient` queries the Supervisor via gRPC to retrieve detailed health and performance metrics.