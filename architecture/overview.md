# SynVoid Architectural Modules

This document categorizes the discrete modules of the SynVoid codebase into logical layers to facilitate understanding and future code reviews.

### 1. Process & Lifecycle Management (The Orchestration Layer)
These modules handle the hierarchical process model and ensure the system remains stable and updatable.
*   **`overseer/`**: The supervisor layer. Manages zero-downtime upgrades, process health monitoring, and the complex `SCM_RIGHTS` socket handoff between generations of the application.
*   **`master/`**: The coordinator. Acts as the parent to worker processes, handling signals and managing IPC channels.
*   **`worker/`**: The execution layer. Contains the logic for the `UnifiedServer`, which is the main entry point for request processing.
*   **`startup/`**: Bootstrapping logic for different process modes (Overseer, Master, Worker).
*   **`process/`**: Internal IPC communication protocols and process state management.

### 2. WAF & Security (The Protection Layer)
The core security engine that inspects traffic and makes decisions.
*   **`waf/`**: The central WAF coordinator.
    *   `attack_detection/`: Specialized detectors for SQLi, XSS, SSRF, Command Injection, etc., utilizing both pattern matching and `libinjection`.
    *   `flood/`: Connection and rate-based flood mitigation (including eBPF hooks).
    *   `ratelimit/`: Granular rate limiting (sliding window, leaky bucket) at the IP and site levels.
    *   `bot.rs`: Bot detection using User-Agent analysis and JA3/JA4 TLS fingerprinting.
    *   `rule_feed.rs`: Management of dynamic security rules and YARA signatures.
*   **`integrity/`**: Request and response integrity checks.
*   **`captcha/` & `challenge/`**: Mechanisms for JavaScript challenges and CAPTCHA-based verification.
*   **`tarpit/`**: "Slow-HTTP" mitigation and silent stalling to waste attacker resources.

### 3. Proxy & Routing (The Traffic Layer)
Handles how requests are received, parsed, and forwarded to upstreams.
*   **`proxy/`**: The reverse proxy engine. Manages request/response header transformations, retries, and buffering.
*   **`router/`**: Domain and path-based routing that maps incoming requests to specific `SiteConfig` objects.
*   **`upstream/`**: Load balancing and health checking for backend servers.
*   **`listener/`**: Protocol-agnostic listener pool (TCP, UDP, QUIC) that feeds connections into the worker.
*   **`http/` & `http3/`**: Implementations and wrappers for HTTP/1.1, H2, and H3/QUIC protocols.
*   **`tls/`**: TLS termination, SNI handling, and ACME (Let's Encrypt) integration.

### 4. Application Handlers (The Content Layer)
Built-in servers for specific types of content, reducing the need for external backends.
*   **`static_files/`**: High-performance static content serving with minification (`lightningcss`) and compression.
*   **`php/` & `fastcgi/`**: Native FastCGI client for PHP-FPM and other CGI-based apps.
*   **`app_server/`**: Support for "Granian-style" Python (ASGI/WSGI) hosting.
*   **`serverless/` & `spin/`**: Experimental WASM-based serverless function execution.

### 5. Mesh & Distributed Systems (The P2P Layer)
The most complex part of the system, enabling multi-node collaboration.
*   **`mesh/`**: The root of the P2P system.
    *   `dht/`: Distributed Hash Table for peer discovery and threat intelligence sharing.
    *   `transport/`: QUIC-based WAF-to-WAF communication.
    *   `topology/`: Tracking the health and routes of the global mesh network.
    *   `kem/` & `ml_dsa.rs`: Post-Quantum Cryptography implementations for secure peer identity.
*   **`tunnel/`**: Logic for established secure tunnels between WAF nodes or WAF-to-VPN clients.

### 6. Admin & Observability (The Management Layer)
*   **`admin/`**: The Axum-based REST API for configuring the WAF and retrieving stats.
*   **`metrics/`**: Prometheus-compatible metrics collection for every sub-component.
*   **`logging/`**: Structured JSON logging and real-time log streaming via WebSockets.
*   **`geoip/`**: MaxMind integration for location-based filtering.

### 7. Core Utilities & System (The Foundation)
*   **`config/`**: TOML configuration parsing and validation with hot-reloading support.
*   **`serialization/`**: Optimized data handling using `rkyv` (zero-copy) and `postcard`.
*   **`buffer/`**: Specialized memory management for request/response bodies.
*   **`utils/`**: Shared error types, URL encoding helpers, and common extensions.
*   **`platform/`**: OS-specific abstractions (Linux-specific optimizations vs. Windows fallbacks).
