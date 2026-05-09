# SynVoid Architecture

A production-ready WAF and reverse proxy built for high-performance, high-availability deployments with mesh networking capabilities.

## Overview

SynVoid combines a nginx-inspired reverse proxy concurrency model with a sophisticated WAF (Web Application Firewall) system. It utilizes a **Shared-Nothing Architecture** to achieve linear scalability and zero-jitter performance.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SynVoid Architecture                            │
└─────────────────────────────────────────────────────────────────────────────┘

                                     Internet
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Supervisor Node                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • gRPC Control Plane (proto/control.proto)                         │   │
│  │  • Mesh Transport & Global State (Raft/DHT)                          │   │
│  │  • Worker Lifecycle & Rotation Management                            │   │
│  │  • Unified Configuration (synvoid-config)                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
            │                           │                           │
            ▼                           ▼                           ▼
    ┌───────────────┐           ┌───────────────┐           ┌───────────────┐
    │  Worker 1     │           │  Worker 2     │           │  Worker 3     │
    │ (Core Pinned) │           │ (Core Pinned) │           │ (Core Pinned) │
    │ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │
    │ │ SO_REUSE- │ │           │ │ SO_REUSE- │ │           │ │ SO_REUSE- │ │
    │ │ PORT      │ │           │ │ PORT      │ │           │ │ PORT      │ │
    │ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │
    └───────────────┘           └───────────────┘           └───────────────┘
            │                           │                           │
            └───────────────────────────┼───────────────────────────┘
                                        │
                                        ▼
                              ┌─────────────────┐
                              │  Upstream Apps  │
                              │  • Static Files │
                              │  • PHP-FPM      │
                              │  • Granian      │
                              │  • FastCGI      │
                              │  • WASM         │
                              └─────────────────┘
```

## Core Components

### 1. Reverse Proxy (Tokio + Hyper)

The reverse proxy layer is heavily inspired by nginx's event-driven architecture, made possible by:

- **Tokio** - Asynchronous runtime for efficient I/O handling
- **Hyper** - HTTP/1.1 and HTTP/2 protocol implementation
- **Quinn** - QUIC/HTTP3 support

This combination provides:
- Non-blocking I/O for maximum concurrency
- Connection pooling and keep-alive
- HTTP/2 multiplexing
- HTTP/3 (QUIC) support

### Request Flow Through Components

When a request arrives, it passes through these components in sequence within a Worker:

```
1. Listener (TCP/UDP/QUIC + SO_REUSEPORT)
      │
      ▼
2. Connection Handler (TLS termination, HTTP parsing)
      │
      ▼
3. Router (domain-based routing to site config)
      │
      ▼
4. WAF Pipeline (attack detection, bot detection, rate limiting)
      │
      ▼
5. Request Handler (static files, FastCGI, proxy, app server)
      │
      ▼
6. Upstream Pool (backend selection, connection pooling)
      │
      ▼
7. Response Handler (caching, compression, header modification)
      │
      ▼
8. Client Response
```

### 2. WAF Protection Layers

The WAF implements multiple protection layers, executed independently by each worker:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          WAF Protection Pipeline                            │
└─────────────────────────────────────────────────────────────────────────────┘

  Client Request
          │
          ▼
┌─────────────────────────┐
│  1. Connection Layer   │
│  • Connection Limits    │
│  • Rate Limiting       │
│  • IP Reputation       │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│  2. Protocol Layer    │
│  • HTTP Parsing        │
│  • Header Validation   │
│  • Method Filtering    │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│  3. Request Layer      │
│  • SQL Injection       │
│  • XSS Detection       │
│  • Path Traversal      │
│  • RFI/SSRF Blocking   │
│  • Custom Rules        │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│  4. Bot Detection      │
│  • AI Crawler Blocking │
│  • Scraper Detection   │
│  • Honeypot Endpoints  │
│  • JS Challenge        │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│  5. Response Layer     │
│  • Header Sanitization │
│  • Response Filtering   │
│  • Information Leakage │
└─────────────────────────┘
          │
          ▼
    Allow / Stall / Block / Tarpit / Challenge
```

### 3. Supervisor -> Worker Model (Shared-Nothing)

SynVoid uses a hierarchical two-tier model to separate the control plane from the data plane.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Supervisor-Worker Hierarchy                          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                               Supervisor Cluster                             │
│                                                                             │
│    ┌──────────┐      ┌──────────┐      ┌──────────┐                      │
│    │Supervisor│◄────►│Supervisor│◄────►│Supervisor│                      │
│    │  Leader  │      │ Follower │      │ Follower │                      │
│    └──────────┘      └──────────┘      └──────────┘                      │
│         │                                                        (Raft)     │
└─────────┼───────────────────────────────────────────────────────────────────┘
          │
          │ Spawns & Monitors
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                 Workers                                     │
│                                                                             │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐                      │
│  │  Worker 1  │    │  Worker 2  │    │  Worker 3  │                      │
│  │ ┌────────┐ │    │ ┌────────┐ │    │ ┌────────┐ │                      │
│  │ │Data    │ │    │ │Data    │ │    │ │Data    │ │                      │
│  │ │Plane   │ │    │ │Plane   │ │    │ │Plane   │ │                      │
│  │ └────────┘ │    │ └────────┘ │    │ └────────┘ │                      │
│  └────────────┘    └────────────┘    └────────────┘                      │
│                                                                             │
│  Shared-Nothing Architecture:                                               │
│  • Kernel-level LB via SO_REUSEPORT                                         │
│  • CPU core affinity for zero-jitter                                        │
│  • Independent request handling loops                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Process Communication

```
┌─────────────────┐    gRPC      ┌─────────────────┐
│      CLI        │◄────────────►│   Supervisor    │
│ (CommandClient) │              │ (Control Plane) │
└─────────────────┘              └────────┬────────┘
                                           │ IPC
                                           ▼
                                  ┌─────────────────┐
                                  │    Workers      │
                                  │  (Data Plane)   │
                                  └─────────────────┘
```

**Communication Mechanisms:**
- **gRPC (TLS)**: Robust, typed API for remote management and CLI control.
- **Local IPC**: High-speed binary protocol for configuration and threat feed distribution.
- **QUIC Streams**: Mesh communication between Supervisors for global state.

### 4. WAF-WAF Mesh Networking

Supervisors communicate via QUIC to maintain a globally distributed protection mesh:

- **Distributed DDoS Mitigation** - Coordinated rate limiting.
- **Threat Intelligence** - P2P attack pattern sharing via DHT.
- **YARA Rules** - Global distribution of security signatures.

### 5. Deployment Modes

#### 1. Standalone / Supervisor Mode

The default execution mode (`synvoid`) runs a Supervisor and its managed workers.

```
Internet ──► [SO_REUSEPORT Workers] ──► Upstreams
```

#### 2. High Availability Cluster

Multiple Supervisor nodes participating in a Raft consensus cluster.

```
           ┌─────────────────┐
           │   Load Balancer │
           └────────┬────────┘
                    │
       ┌────────────┼────────────┐
       │            │            │
       ▼            ▼            ▼
┌───────────┐ ┌───────────┐ ┌───────────┐
│Supervisor │ │Supervisor │ │Supervisor │
└─────┬─────┘ └─────┬─────┘ └─────┬─────┘
      │             │             │
      ▼             ▼             ▼
   Workers       Workers       Workers
```

## Quick Start

```bash
# Start SynVoid (Supervisor + Workers)
./synvoid

# Reload configuration via gRPC
./synvoid reload

# Connect to WAF mesh
./synvoid --mesh --seeds global-node:5001
```

## Next Steps

- [Getting Started](./GETTING_STARTED.md) - Get started with SynVoid
- [Process Management](./PROCESS_MANAGEMENT.md) - Supervisor & Worker details
- [Configuration Reference](./CONFIGURATION.md) - Full configuration options
- [Attack Detection](./ATTACK_DETECTION.md) - WAF detection rules
- [WAF Mesh](./WAF_MESH.md) - Mesh networking
