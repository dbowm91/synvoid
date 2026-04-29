# Architectural Deep Dive Review

Based on a comprehensive analysis of the foundational layers (1, 2, 3, and 7), here is a detailed review of MaluWAF's architecture, security posture, and performance characteristics.

## Layer 1: Process & Lifecycle Management (IPC & Orchestration)

**Are we achieving zero downtime updates?**
Yes. MaluWAF successfully achieves zero-downtime updates on Unix/Linux systems. This is implemented via a "Dual-Master" handoff phase where the `Overseer` process uses Unix Domain Sockets and `SCM_RIGHTS` (`src/process/socket_fd.rs` and `src/overseer/socket_handoff.rs`) to pass listening file descriptors from the old Master to the new one. The new version can start accepting connections before the old one is gracefully drained.

**Is the IPC mechanism secure?**
Highly secure. The architecture strictly isolates the control plane from the data plane:
1.  **Authentication:** Master-to-Worker IPC messages are cryptographically signed using an HMAC session key (`src/process/ipc_signed.rs`).
2.  **Key Distribution:** Session keys are distributed to workers via highly restricted temporary files (0600 permissions) rather than command-line arguments, preventing exposure via `ps`.
3.  **Anti-Spoofing:** On Unix, the Master uses `SO_PEERCRED` to verify that the PID claimed by a worker in its initial handshake strictly matches the actual PID of the socket peer, preventing malicious local processes from spoofing WAF workers.

**Architectural Soundness:**
The three-tier hierarchy (Overseer → Master → Worker) is robust. Even if a zero-day vulnerability in the WAF engine compromises a Worker, the attacker does not gain direct control over the Master or the administrative layer.

## Layer 2: WAF & Security (Protection Layer)

**Are we missing any attack vectors? Is it highly secure?**
The WAF engine (`src/waf/attack_detection/`) provides enterprise-grade, comprehensive coverage. It protects against SQLi, XSS, SSRF, SSTI, XXE, JWT manipulation, and HTTP Request Smuggling. 
*   **Hybrid Detection:** It smartly combines fast static pattern matching (Aho-Corasick) with deep lexical analysis (`libinjection`), making it highly resilient against obfuscation techniques.
*   **Anti-Bot:** It includes sophisticated bot mitigation, utilizing PoW challenges, CSS honeypots, JA3/JA4 TLS fingerprinting, and Markov-chain based tarpitting to exhaust attacker resources.

**Does it adjust to attacks in real time?**
Yes. The `ThreatLevelManager` tracks anomaly scores and automatically scales the system's "paranoia" level in real-time. Furthermore, integration with the P2P Mesh (`ThreatIntelligenceManager`) allows WAF nodes to share blocked IPs via a DHT, enabling near-instant, globally coordinated defense.

**Scalability:**
The WAF is built for streaming inspection, meaning it can detect attacks without buffering massive payloads in memory. Configuration reloads are lock-free, utilizing `arc-swap`.

## Layer 3: Proxy & Routing (Traffic Layer)

**Are the architectural decisions sound?**
The proxy layer is structurally sound and heavily inspired by Nginx. There is a clean separation of concerns between domain/path routing (`Router`), upstream connection management and health checking (`UpstreamPool`), and the actual request forwarding and caching (`ProxyServer`).

**Performance & Scalability Bottlenecks:**
While designed for 500K+ RPS, there are a few potential bottlenecks at extreme scale:
1.  **Routing Complexity:** Exact domain matches are O(1) (HashMaps), but wildcard/suffix domains and Regex-based paths require linear iteration (`O(n)`). Heavy reliance on complex Regex routing will impact throughput.
2.  **Upstream Locks:** `UpstreamPool` uses `parking_lot::RwLock` for managing backend server lists. While efficient for read-heavy workloads, extremely high concurrent request rates paired with highly dynamic backend health state changes could introduce thread contention.
3.  **Memory Allocations:** There is notable use of `Arc` and `String` cloning in the routing hot path (e.g., `RouteTarget`). Migrating to more zero-copy string references (`&'a str` or `bytes::Bytes`) in the routing tree could yield measurable CPU savings at peak load.

## Layer 7: Core Utilities & System (Foundation)

**How are OS-specific abstractions handled?**
There is a stark contrast between Unix/Linux and Windows support:
*   **Linux/Unix:** First-class citizen. Leverages advanced OS features like native FD passing, efficient `epoll`/`io_uring` (via Tokio), native signal handling, and state-of-the-art sandboxing (Landlock, Pledge, Capsicum).
*   **Windows:** Treated as a functional fallback. It lacks native FD passing (falling back to `WSADuplicateSocketW`), relies on `taskkill` for process signals, and, most critically, lacks advanced sandboxing.

**Security Flaws at the Foundation Level:**
The primary foundational security flaw is the **Sandbox Parity on Windows**. While Linux WAF processes are strictly confined by Landlock (restricting filesystem access regardless of user privileges), Windows processes currently run with standard permissions without additional OS-level confinement. Additionally, secure directory creation on Windows only applies a 'readonly' attribute rather than the strict ACLs equivalent to Unix's `0o700`.

**Performance Improvements:**
The memory foundation is excellent. The `BufferPool` utilizes a sharded, multi-tiered design (Small/Medium/Large/Jumbo) with thread-local caching, drastically reducing global allocator pressure at scale. Furthermore, the use of `rkyv` for zero-copy serialization ensures that passing complex WAF rules or state between processes incurs minimal CPU overhead. To push performance further, the buffer pool could potentially transition from sharded `Mutex` locks to a fully lock-free implementation.