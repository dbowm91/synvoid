# Architectural Deep Dive Review

Based on a comprehensive analysis of the foundational layers (1, 2, 3, and 7), here is a detailed review of SynVoid's architecture, security posture, and performance characteristics.

## Layer 1: Process & Lifecycle Management (gRPC & Shared-Nothing)

**Are we achieving zero downtime updates?**
Yes. SynVoid achieves zero-downtime updates through a combination of its **Shared-Nothing Architecture** and `SO_REUSEPORT`. The Supervisor coordinates the rotation of workers: new workers are spawned and bind to the same ports using the kernel's `SO_REUSEPORT` load balancer, while old workers are signaled via IPC to enter drain mode. This ensures that no incoming connections are dropped during the transition.

**Is the IPC mechanism secure?**
Highly secure. The architecture strictly isolates the control plane from the data plane:
1.  **Authentication:** Supervisor-to-Worker IPC messages are cryptographically signed using an HMAC session key.
2.  **Key Distribution:** Session keys are distributed to workers via highly restricted temporary files (0600 permissions) rather than command-line arguments, preventing exposure via `ps`.
3.  **Anti-Spoofing:** On Unix, the Supervisor uses `SO_PEERCRED` to verify that the PID claimed by a worker in its initial handshake strictly matches the actual PID of the socket peer, preventing malicious local processes from spoofing WAF workers.
4.  **Control Plane gRPC:** The management interface is now a formal gRPC API (`proto/control.proto`) for local IPC, providing a robust and typed interface for remote management. Note: gRPC binds to localhost only — TLS is not required for local process communication.

**Architectural Soundness:**
The two-tier hierarchy (Supervisor → Worker) simplifies process management while maintaining strong security boundaries. By relegating heavy control plane logic (Raft, DHT, Mesh) to the Supervisor, Workers remain lightweight and performant. Even if a zero-day vulnerability in the WAF engine compromises a Worker, the attacker is confined to an isolated, unprivileged data plane process without access to the global control state or management credentials.

## Layer 2: WAF & Security (Protection Layer)

**Are we missing any attack vectors? Is it highly secure?**
The WAF engine (`src/waf/attack_detection/`) provides enterprise-grade, comprehensive coverage. It protects against SQLi, XSS, SSRF, SSTI, XXE, JWT manipulation, and HTTP Request Smuggling. 
*   **Hybrid Detection:** It smartly combines fast static pattern matching (Aho-Corasick) with deep lexical analysis (`libinjection`), making it highly resilient against obfuscation techniques.
*   **Anti-Bot:** It includes sophisticated bot mitigation, utilizing PoW challenges, CSS honeypots, JA3/JA4 TLS fingerprinting, and Markov-chain based tarpitting to exhaust attacker resources.

**Does it adjust to attacks in real time?**
Yes. The `ThreatLevelManager` tracks anomaly scores and automatically scales the system's "paranoia" level in real-time. Furthermore, the Supervisor handles global coordination via the Mesh network, sharing threat intelligence across nodes to enable near-instant, globally coordinated defense.

**Scalability:**
The WAF is built for streaming inspection and scales linearly thanks to the shared-nothing model. Each worker handles its own traffic independently, pinned to a specific CPU core to maximize cache locality and minimize context switching.

## Layer 3: Proxy & Routing (Traffic Layer)

**Are the architectural decisions sound?**
The proxy layer is structurally sound and follows a shared-nothing concurrency model. There is a clean separation of concerns between domain/path routing (`Router`), upstream connection management and health checking (`UpstreamPool`), and the actual request forwarding and caching (`ProxyServer`).

**Performance & Scalability Bottlenecks:**
The transition to `SO_REUSEPORT` and CPU pinning has eliminated many previous bottlenecks:
1.  **Zero Coordination:** Workers do not need to coordinate for connection acceptance, allowing the kernel to handle load balancing efficiently.
2.  **Cache Locality:** Core affinity (`sched_setaffinity`) ensures that the worker's memory and CPU caches remain hot for its assigned traffic.
3.  **Config Distribution:** The Supervisor uses the `synvoid-config` crate to provide a unified configuration view, pushing updates to workers via lock-free IPC channels.

## Layer 7: Core Utilities & System (Foundation)

**How are OS-specific abstractions handled?**
SynVoid leverages deep OS integration:
*   **Linux/Unix:** First-class citizen. Leverages `SO_REUSEPORT`, `sched_setaffinity`, and advanced sandboxing (Landlock, Pledge).
*   **Windows:** Supports shared-nothing execution using `SO_REUSEPORT` (available in modern Windows versions) and named pipe IPC.

**Security Flaws at the Foundation Level:**
The primary focus remains on **Sandbox Parity**. While Linux WAF processes are strictly confined by Landlock, Windows processes rely on more standard security descriptors. The move to a gRPC control plane has significantly improved the security of the management interface by providing a well-defined, auditable API boundary.

**Performance Improvements:**
The memory foundation is excellent. The `BufferPool` remains a high-performance asset, and the use of `rkyv` for zero-copy serialization in the IPC and Mesh layers ensures that control plane communication remains fast even as the system scales to thousands of nodes.