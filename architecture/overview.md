# SynVoid Architectural Overview

SynVoid is a high-performance Web Application Firewall (WAF) and reverse proxy written in Rust. It is designed to be highly modular, scalable, and resilient, utilizing a multi-process model and a unified async worker architecture.

## Bird's Eye View

The system is organized around three primary process types and several core functional subsystems.

### 1. Process Model & Lifecycle
SynVoid employs a hierarchical process model to ensure high availability and zero-downtime operations.

- **[Process Lifecycle & Execution Model](process_lifecycle.md)**: The supervisor-coordinator-worker hierarchy.
- **[Worker Architecture & Unified Server](worker_architecture.md)**: The high-performance data plane.

### 2. Networking & Protocol Layer
Handles the low-level communication and protocol negotiation.

- **[Networking & Protocols](networking_deep_dive.md)**: Support for HTTP/1, HTTP/2, HTTP/3, and TLS.

### 3. Core Proxy Logic
The engine that routes and manages requests.

- **[Request Routing & Upstream Management](routing_deep_dive.md)**: Domain-based routing and load balancing.

### 4. WAF & Security Pipeline
Multi-layered protection against various threats.

- **[WAF Security Pipeline](waf_deep_dive.md)**: The core security engine and protection layers.

### 5. Mesh & Distributed Systems
Optional capabilities for clustering and P2P CDN functionality.

- **[SynVoid Mesh & P2P Networking](mesh_deep_dive.md)**: Distributed DDoS defense and threat intelligence sharing.

### 6. Application Handlers
Native support for various application types.

- **[Application Handlers](app_handlers.md)**: Static files, PHP-FPM, Python, and WASM.

### 7. Management & Observability
- **[Admin API & UI](admin.md)**: RESTful API and a dedicated Tailwind-based frontend for management.
- **[Metrics & Logging](observability.md)**: Prometheus metrics and structured JSON logging.

---

## Detailed Component Documentation Index

| Component | Documentation | Primary Source Path |
|-----------|---------------|---------------------|
| Process Lifecycle | [Supervisor & Worker Deep Dive](process_lifecycle.md) | `src/supervisor/`, `src/process/` |
| Unified Worker | [Worker Architecture](worker_architecture.md) | `src/worker/`, `src/server/` |
| Networking | [Transport & Protocols](networking_deep_dive.md) | `src/listener/`, `src/http/`, `src/http3/` |
| Security | [WAF Security Pipeline](waf_deep_dive.md) | `src/waf/`, `src/filter/`, `src/challenge/` |
| Mesh | [Mesh & P2P Networking](mesh_deep_dive.md) | `src/mesh/` |
| Routing | [Request Routing & Upstreams](routing_deep_dive.md) | `src/router/`, `src/upstream/` |
| App Handlers | [Application Support](app_handlers.md) | `src/static_files/`, `src/php/`, `src/serverless/` |

*This overview is intended as a living document to guide developers through the SynVoid architecture.*
