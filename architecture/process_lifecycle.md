# Process Lifecycle & Execution Model

SynVoid uses a "Shared-Nothing Architecture" to achieve maximum performance, linear scalability, and robust security isolation. The model follows a three-tier hierarchy for maximum flexibility, with Supervisor consolidating legacy Overseer + Master responsibilities.

## The Hierarchy

### 1. Overseer (Legacy - Parent Process)
The Overseer is the top-level orchestrator that spawns and monitors the Master process and Mesh Agent. It handles system-wide health monitoring, recovery orchestration, and upgrade coordination.

- **Responsibilities:**
  - **Process Spawning:** Spawns the Master process and Mesh Agent at startup.
  - **Health Monitoring:** Monitors child process heartbeats and restarts failed processes.
  - **Recovery Orchestration:** Handles system recovery when faults occur.
  - **Upgrade Coordination:** Coordinates zero-downtime upgrades across the system.
- **Key Logic:** `src/overseer/`.

### 2. Master (Legacy - Mid-tier Process)
The Master runs as a child of Overseer and provides process management, admin API, block store, and IPC coordination for workers.

- **Responsibilities:**
  - **Process Management:** Spawns and monitors Worker processes via ProcessManager.
  - **Admin API:** Hosts the management interface.
  - **Block Store:** Manages persistent IP blocklists.
  - **IPC Coordination:** Broadcasts configuration and threat intelligence to workers.
- **Key Logic:** `src/startup/master.rs`, `src/master/`.

### 3. Supervisor (Consolidated Control Plane)
The Supervisor is a newer consolidated mode (2026) that merges Overseer + Master responsibilities into a single process for simpler deployments.

- **Modes:**
  - **Consolidated Mode (default):** Supervisor replaces Overseer + Master, spawning workers directly. This is the ONLY functional mode - no CLI flag exists to select Legacy Mode.
  - **Legacy Mode (code only, not selectable):** Overseer spawns Master which spawns workers. The code exists (`run_overseer_mode()` in `src/startup/master.rs`) but cannot be invoked - there's no CLI flag to enable it. This is legacy code preserved for reference.
- **Responsibilities:**
  - **Process Management:** Spawning and monitoring Worker processes.
  - **Zero-Downtime Upgrades:** Coordinating worker rotations and hot-reloads.
  - **Control Plane Coordination:** Handles Raft consensus, DHT routing, and Mesh transport.
  - **Configuration:** Loads and validates configuration using the `synvoid-config` crate.
  - **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management.
- **Key Logic:** `src/supervisor/`.
- **IPC Role:** Acts as the central hub for worker coordination.

### 4. Worker (The Data Plane)
Workers are lightweight, "dumb" request-handling engines that operate in a shared-nothing environment.

- **Isolation:** Each worker process is completely independent.
- **Kernel Load Balancing:** Uses `SO_REUSEPORT` during worker upgrades (via upgrade mode) to allow kernel distribution across old and new workers. Initial workers use `reuse_port: false` (default). See `src/overseer/spawn.rs:43`.
- **CPU Pinning:** On Linux, workers can be pinned to specific CPU cores via `sched_setaffinity`. CPU affinity is automatically assigned based on worker ID (not manually configured). Not supported on macOS/BSD (logs warning).
- **Minimal Intelligence:** Workers focus strictly on request handling (WAF pipeline, proxying). They receive threat intelligence and configuration updates from the Supervisor.
- **Key Logic:** `src/worker/`.

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

Upgrades are coordinated by the Supervisor:

1.  A new Supervisor process can be started to replace the old one.
2.  The new Supervisor takes over the gRPC management interface.
3.  Workers are rotated: new workers are spawned by the new Supervisor, and old workers are signaled to drain.
4.  `SO_REUSEPORT` allows both old and new workers to coexist during the transition without dropping connections.

---

## Process State & Health Monitoring

The Supervisor provides a unified view of the system health:

- **Worker Monitoring:** The Supervisor monitors worker process exits and heartbeats.
- **Self-Healing:** If a worker fails, the Supervisor immediately spawns a replacement and pins it to the correct core.
- **gRPC Status:** The `CommandClient` queries the Supervisor via gRPC to retrieve detailed health and performance metrics.
