# MaluWAF Strategic Roadmap (2026-2027)

This document outlines the long-term architectural evolution of MaluWAF, focusing on extreme scalability, quantum-resistance, and autonomous decentralized intelligence.

## Wave 1: Performance & Low-Latency Foundation
**Goal**: Reduce memory pressure and time-to-first-byte (TTFB) while scaling to 1M+ RPS.

### 1.1 Streaming WAF Engine
- **Objective**: Scan request bodies incrementally instead of collecting them in full.
- **Implementation**:
  - Update `AttackDetector` to support a `scan_chunk(&mut self, chunk: &[u8]) -> WafDecision` API.
  - Implement "Windowed Aho-Corasick": maintain state across chunks to detect patterns split across packet boundaries.
  - Integrate with `Http3Server` and `HttpServer` to forward chunks to upstream immediately while scanning in parallel.
- **Benefit**: Near-zero memory overhead for large requests and dramatically lower latency.

### 1.2 DHT Neighborhood Persistence
- **Objective**: Accelerate mesh "warm-up" and reduce bootstrap traffic.
- **Implementation**:
  - Implement a persistent storage layer for `src/mesh/dht/record_store.rs` using the established JSON persistence pattern.
  - On startup, load the "closest" DHT records to the local node's MeshID.
  - Implement background pruning of expired persisted records.
- **Benefit**: Faster cluster recovery and reduced bandwidth consumption during node restarts.

---

## Wave 2: Security Hardening & Platform Maturity
**Goal**: Protect against future quantum threats and expand deployment flexibility.

### 2.1 Hybrid Post-Quantum Mesh Signatures
- **Objective**: Secure internal mesh orchestration against quantum adversaries.
- **Implementation**:
  - Introduce `HybridSignature` type combining `Ed25519` and `ML-DSA` (Dilithium).
  - Update `MeshMessage` to support hybrid signatures for `ThreatAnnounce`, `OrgKeyAnnounce`, and `DhtRecord`.
  - Maintain backward compatibility via a feature flag `pqc-mesh`.
- **Benefit**: "Quantum-safe" cluster state and decentralized authority.

### 2.2 Windows Service & DX Improvement
- **Objective**: Make MaluWAF a first-class citizen on Windows.
- **Implementation**:
  - Add `src/platform/windows_service.rs` using the `windows-service` crate.
  - Implement an Interface Resolver: map Windows UUID/Friendly Names (e.g., "Ethernet 1") to WFP `InterfaceIndex`.
  - Automate firewall rule injection for the HTTP/3 QUIC port.
- **Benefit**: Simplified deployment for enterprise Windows fleets.

---

## Wave 3: Intelligent & Autonomous Mesh
**Goal**: Move from reactive rule-matching to proactive behavioral protection.

### 3.1 Federated Behavioral Intelligence
- **Objective**: Share anonymized attack patterns instead of just static IPs.
- **Implementation**:
  - Define `BehavioralFingerprint` based on header timing, entropy, and request sequence.
  - Use the DHT to broadcast "High Scoring Behaviors" across the mesh.
  - Update `AttackDetector` to dynamically adjust the `paranoia_level` for requests matching shared fingerprints.
- **Benefit**: Protection against 0-day attacks and distributed botnets without human intervention.

### 3.2 Real-time Topology Visualizer
- **Objective**: Provide a "God's eye view" of the decentralized mesh health.
- **Implementation**:
  - Create a new Admin API endpoint `/api/mesh/topology` that aggregates data from `src/mesh/topology.rs`.
  - Implement a D3.js or Sigma.js based force-directed graph in the `admin-ui`.
  - Visualize regional hubs, peer latencies, and trust-chain propagation status.
- **Benefit**: Rapid root-cause analysis for network partitions and peering issues.

---

## Key Constraints & Standards
1. **Zero-Allocation in Hot Paths**: Every feature in Waves 1 & 2 must adhere to the allocation limits defined in `AGENTS.md`.
2. **Decentralized First**: Avoid any feature that requires a single "Leader" or "Primary" node (No Raft).
3. **Fail-Closed Security**: All streaming and behavioral features must default to blocking if internal buffers or scoring engines overflow.

---
**Last Updated**: 2026-04-26
**Status**: DRAFT - Proposed for implementation phase.
