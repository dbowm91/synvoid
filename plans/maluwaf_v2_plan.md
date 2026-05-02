# MaluWAF V2 Implementation Plan: Performance, Multi-Tenancy, and Resilience

**Status**: Approved
**Last Updated**: 2026-04-28

---

## Objective

Evolve MaluWAF into a highly scalable, fully multi-tenant edge proxy capable of handling 1000K+ RPS with zero-copy proxying, secure WASM component plugins, and robust threat intelligence integration. This plan addresses the technical debt (God modules) and architecture limitations (DHT routing, Site Isolation) identified during previous implementation cycles.

## Background & Motivation

MaluWAF has a sophisticated multi-process architecture (Overseer -> Master -> Workers) and a decentralized DHT mesh. However, it currently suffers from severe "God module" bloat (`metrics`, `transport`, `http/server`), excessive buffer allocations in HTTP proxy paths, incomplete site isolation (tenant data leakage risk), and relies on an outdated, non-component WASM ABI. To achieve its massive scalability and security targets, these structural and performance bottlenecks must be resolved in a controlled, phased approach.

## Scope & Impact

*   **Files Affected**: `src/metrics/*`, `src/mesh/transport.rs`, `src/http/server.rs`, `src/plugin/wasm_runtime.rs`, `src/mesh/dht/routing/table.rs`, `fuzz/*`.
*   **Impact**: High. Changes involve core HTTP proxying, mesh routing, and the WASM execution environment. 
*   **Risk**: High (specifically for module splitting). Strict adherence to "no capability reversions" requires surgical extractions and rigorous testing at each step.

---

## Phased Implementation Plan

Agents should execute this plan sequentially, verifying each item before moving to the next wave.

### Wave 1: Codebase Health & Testing Foundations

This wave establishes the foundation for safe refactoring by breaking down massive files and setting up continuous fuzzing.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **W1.1** | `metrics/mod.rs` | Strategic Module Split | 1. Create `src/metrics/payloads.rs` for structs (`WorkerMetricsPayload`, `SiteMetricsPayload`). 2. Create `src/metrics/collection.rs` for atomic counters. 3. Re-export in `metrics/mod.rs` to keep the public API identical. |
| **W1.2** | `fuzz/` | Continuous Fuzzing Integration | 1. Add `cargo-fuzz` targets for `src/serialization.rs`, `src/http/early_parse.rs`, and `src/mesh/protocol_proto_decode.rs`. 2. Ensure targets compile via `cargo +nightly fuzz build`. |
| **W1.3** | E2E Tests | Fault Injection Tests | Add a new test in `tests/integration_test.rs` that simulates a worker process crash mid-request to verify Overseer recovery and socket handoff. |

### Wave 2: Performance & Scalability

Focuses on reducing CPU cycles and memory allocations per request.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **W2.1** | `http/server.rs` | Zero-Copy Proxying | Replace full body buffering (`body::to_bytes`) with hyper's `Body::map_frame` or `Stream` traits to pipe response bodies directly from the upstream `Response` to the downstream `Response` for files > 1MB. |
| **W2.2** | `http3/server.rs` | HTTP/3 Zero-Copy | Apply the same streaming body optimization to the QUIC proxy paths. |
| **W2.3** | `routing/table.rs` | DHT Routing Optimization | Refactor `RoutingTable::find_closest`. Instead of iterating through all peers in $K$ buckets, introduce an LRU cache (`moka` or `LruCache`) for frequently queried target prefixes to achieve $O(1)$ lookups for hot paths. |
| **W2.4** | `MeshPeerConnection`| QUIC Stream Pooling | Modify mesh peer connection logic to maintain a pool of open QUIC streams per peer, rather than opening/closing streams per message. |

### Wave 3: Multi-Tenancy & Plugins

Ensures strict isolation between tenants and modernizes the plugin system.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **W3.1** | Core State | Comprehensive Site Isolation | Audit `src/waf/ratelimit.rs`, `src/waf/rule_feed.rs`, and `WorkerMetrics`. Ensure all global `DashMap`s are keyed by `site_id` (e.g., `DashMap<String, RateLimitBucket>`). No tenant should be able to exhaust another's quota. |
| **W3.2** | `wasm_runtime.rs` | WASM Component Model Integration | 1. Define a `WIT` file (`plugin.wit`) specifying the host exports (e.g., `get_header`, `set_body`). 2. Use `wasmtime-wit-bindgen` to generate host bindings. 3. Update `load_component` to instantiate the component using the generated bindings. |

### Wave 4: Security & Resilience

Integrates automated, dynamic threat responses.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **W4.1** | Threat Intel | Automated Feed Ingestion | 1. Create `src/waf/threat_intel/feed_client.rs`. 2. Implement a background task in the Master process that periodically fetches, verifies (Ed25519 signature), and parses a centralized JSON/binary threat feed. |
| **W4.2** | DHT | Feed Distribution | 3. Broadcast the verified threat feed updates to all Worker processes via IPC, and to edge nodes via the DHT using the `SiteScoped` keys. |

---

## Verification & Testing

For every wave, the following verification must be performed:
1.  **Compilation Check**: `cargo test --lib --no-run` must pass.
2.  **Unit & Integration Tests**: `cargo test` and `cargo test --test integration_test` must pass.
3.  **Benchmarking (Wave 2)**: Run `cargo bench` before and after W2.1/W2.2 to verify reductions in allocations and latency.
4.  **No Capability Reversion**: When splitting modules (W1.1), ensure the exact same functions, structs, and traits are exposed publicly.

## Migration & Rollback

*   **WASM Plugins**: The new Component Model (W3.2) will break existing `.wasm` plugins compiled against the old ABI. Ensure `load_plugin` (legacy) and `load_component` (new) coexist during a deprecation period.
*   **Rollback**: All tasks are designed to be atomic commits. If a capability regression is detected (e.g., God module split fails), revert the specific commit immediately. Do not attempt to rewrite complex logic from scratch.
