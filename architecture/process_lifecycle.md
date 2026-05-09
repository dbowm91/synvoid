# Process Lifecycle & Execution Model

SynVoid uses a "Shared-Nothing Architecture" to achieve maximum performance, linear scalability, and robust security isolation. The model follows a two-tier **Supervisor → Worker** pattern, managed via a gRPC-based Control Plane.

## The Hierarchy

### 1. Supervisor (The Control Plane)
The Supervisor is the long-lived entry point process. It merges the responsibilities of the legacy Overseer and Master processes into a single, high-performance orchestration engine.

- **Responsibilities:**
  - **Process Management:** Spawning and monitoring Worker processes.
  - **Zero-Downtime Upgrades:** Coordinating worker rotations and hot-reloads of the Supervisor itself.
  - **Control Plane Relegation:** Handles heavy coordination protocols, including Raft consensus, DHT routing, and Mesh transport.
  - **Configuration:** Loads and validates configuration using the `synvoid-config` crate. Distributes config to workers via high-speed IPC.
  - **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management and CLI interactions.
- **Key Logic:** `src/supervisor/`, `src/control_plane/`.
- **IPC Role:** Acts as the central hub for worker coordination.

### 2. Worker (The Data Plane)
Workers are lightweight, "dumb" request-handling engines that operate in a shared-nothing environment.

- **Isolation:** Each worker process is completely independent.
- **Kernel Load Balancing:** Uses `SO_REUSEPORT` to allow the kernel to distribute incoming connections across workers with zero coordination overhead.
- **CPU Pinning:** On Linux, workers are automatically pinned to specific CPU cores via `sched_setaffinity`, eliminating jitter and cache thrashing.
- **Minimal Intelligence:** Workers focus strictly on request handling (WAF pipeline, proxying). They receive threat intelligence and configuration updates from the Supervisor.
- **Key Logic:** `src/worker/`.

---

## Communication Flow (gRPC & IPC)

SynVoid utilizes a tiered communication strategy:

1.  **External Management (gRPC):** The CLI (`CommandClient`) and remote managers communicate with the Supervisor via gRPC over TLS.
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
