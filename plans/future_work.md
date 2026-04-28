# MaluWAF Future Work Recommendations

Based on the recent completion of the implementation plan and a deep dive into the codebase, here are the recommended areas for future improvement, categorized by focus area.

## 1. Performance & Scalability

*   **DHT Routing Optimization:** While we fixed the $O(N)$ lookup in the record store (D3), Kademlia bucket routing in `RoutingTable::find_closest` still iterates through all peers in buckets. For extreme scales (100k+ nodes), this should be optimized using a more advanced data structure or caching closest peers for frequent targets.
*   **Zero-Copy Proxying:** The HTTP and HTTP/3 proxy paths (`src/http/server.rs`, `src/http3/server.rs`) do a lot of buffer allocation. Investigate hyper's `body::to_bytes` usage and look for opportunities to stream request/response bodies directly between sockets where possible, especially for large file uploads/downloads.
*   **Mesh Connection Pooling:** `MeshPeerConnection` currently establishes QUIC streams per request in some paths. Implementing a robust multiplexed stream pool or using datagrams for small control messages could significantly reduce mesh latency.

## 2. Multi-tenancy & Plugins

*   **Full WASM Component Model Integration (D8 Follow-up):** The experimental `load_component` API was added, but the ABI is incompatible with the host exports. We need to define a formal `WIT` (Wasm Interface Type) for MaluWAF plugins and generate the host bindings using `wasmtime-wit-bindgen`. This will allow secure, language-agnostic plugins.
*   **Comprehensive Site Isolation:** We introduced `SiteScoped` DHT keys (D9). The next step is to enforce this isolation throughout the entire application lifecycle. This means ensuring WAF rules, rate limits, and metrics are strictly partitioned by `site_id` in memory (e.g., using sharded `DashMap`s keyed by site) to prevent noisy neighbor problems and cross-tenant data leaks.

## 3. Codebase Health & Testing

*   **Strategic Module Splitting (D7 Follow-up):** The "God modules" (`metrics/mod.rs`, `mesh/transport.rs`, `http/server.rs`) are too large (3k-4k lines each). Since automated splitting proved risky due to complex trait bounds and re-exports, this needs a careful, manual refactoring plan.
    *   *Recommendation:* Start with `metrics/mod.rs`. Extract the pure data structures (payloads) first, then the collection logic, and finally the reporting/formatting logic.
*   **Integration Test Coverage for Edge Cases:** The core paths are well-tested, but edge cases like network partitions during a quorum request, or a worker process crashing mid-request, need more robust E2E tests using simulated network failures or fault injection.

## 4. Security & Resilience

*   **Continuous Fuzzing Integration:** The `fuzz/` directory exists, but it should be integrated into the CI/CD pipeline using `cargo-fuzz`. Focus fuzzing efforts on the `serialization` module, the `http/early_parse.rs` logic, and the `mesh/protocol_proto_decode.rs` to ensure resilience against malformed packets.
*   **Automated Threat Intel Feed Integration:** The WAF currently relies on static YARA rules or manually distributed lists. Implementing an automated, signature-verified ingestion pipeline for real-time threat intelligence feeds (e.g., from a central trusted authority) would vastly improve zero-day protection.
