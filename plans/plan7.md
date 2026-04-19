# MaluWAF Serverless Architecture Improvement Plan

## 1. Objective
Enhance MaluWAF to support a comprehensive "serverless style architecture" that operates seamlessly in both standalone and mesh modes. This includes turning MaluWAF nodes into distributed execution environments ("Origin servers" for serverless functions) with mesh-wide discovery, routing, and a more robust WASM ABI.

## 2. Background & Motivation
MaluWAF currently supports local WASM-based serverless functions (`src/serverless/manager.rs`). While `ServerlessFunctionAnnounce` exists in the mesh protocol (`src/mesh/protocol.rs`), execution is limited to the local node. If a node receives a request for a function it lacks, it cannot forward it. Furthermore, the WASM ABI (`src/plugin/wasm_runtime.rs`) only provides basic request/response capabilities, lacking integration with the wider mesh intelligence (e.g., DHT, threat feeds).

The goal is to evolve this into a true distributed edge-computing platform.

## 3. Scope & Impact
- **Mesh Routing**: Enable nodes to discover which peers host specific functions and route requests to them.
- **Node Roles**: Allow nodes to act explicitly as "Origin Servers" for serverless functions, handling offloaded execution.
- **WASM ABI Expansion**: Provide functions with access to mesh state (DHT, threat intelligence).
- **Standalone Optimization**: Create a fast-path for serverless execution that bypasses unnecessary WAF checks when acting purely as a compute node.
- **Event-Driven Execution**: Support invoking functions based on internal mesh events, not just HTTP requests.

## 4. Proposed Solution & Implementation Steps

### Phase 1: Standalone Optimization & ABI Expansion
**Goal**: Improve local execution performance and capability.
1.  **Fast-Path Routing**: Introduce a configuration option (e.g., `serverless_only = true` per-site) in `src/config/site.rs` and `src/router.rs`. When active, `src/http/server.rs` and `src/tls/server.rs` should bypass the L7 WAF pipeline (SQLi, XSS) and route the request directly to the `ServerlessManager`.
2.  **ABI Enhancements**: Update `src/plugin/wasm_runtime.rs` to expose new host functions to the WASM guest:
    *   `mesh_query_dht(key_ptr, key_len, out_ptr, out_max) -> i32`
    *   `mesh_check_threat(ip_ptr, ip_len) -> i32`
    *   `mesh_emit_event(topic_ptr, topic_len, data_ptr, data_len) -> i32`
3.  **Documentation**: Update `docs/WASM-ABI.md` to reflect the new capabilities.

### Phase 2: Mesh Integration & Function Discovery
**Goal**: Allow nodes to advertise and discover function hosting capabilities.
1.  **Origin Role Definition**: Extend `MeshNodeRole` in `src/mesh/config.rs` to explicitly flag nodes that are willing to accept remote serverless executions (e.g., `MeshNodeRole::SERVERLESS_ORIGIN`).
2.  **DHT Registration**: Modify `src/mesh/transport_peer.rs` (`handle_serverless_function_announce`) and `src/serverless/manager.rs` to ensure that when a node loads a function, it registers its `node_id` as an active provider for that function in the DHT.
3.  **Hierarchical Routing Integration**: Update `src/mesh/hierarchical_routing.rs` to treat serverless function names as routable upstreams, allowing regional hubs to aggregate function availability.

### Phase 3: Mesh-Wide Remote Execution (Proxying)
**Goal**: Route requests for missing functions to the appropriate origin node.
1.  **Protocol Extension**: Ensure `UpstreamProtocol` (`src/mesh/protocol.rs`) includes a `Serverless` variant.
2.  **Remote Execution Dispatch**: Modify `src/serverless/manager.rs` (`handle_serverless_function`). If `find_matching_route` fails locally:
    *   Query the `MeshProxy` or `HierarchicalRoutingManager` for the function name.
    *   If a remote provider is found, utilize `MeshProxy` to forward the HTTP request to the target node's `ServerlessManager`.
3.  **Proxy Handler Updates**: Update `src/mesh/proxy.rs` to handle incoming remote execution requests, routing them securely to the local WASM runtime and returning the response over the QUIC tunnel.

### Phase 4: Event-Driven Triggers
**Goal**: Move beyond HTTP-only invocation.
1.  **Event Subscription**: Add a mechanism in `ServerlessManager` for functions to subscribe to mesh event topics (e.g., `mesh.threat_detected`, `node.joined`).
2.  **Event Dispatch**: When the mesh layer (`src/mesh/transport_peer.rs`) receives these events, dispatch a serialized payload to the subscribed WASM functions via a new exported ABI function (e.g., `handle_event(topic_ptr, topic_len, data_ptr, data_len)`).

## 5. Verification & Testing
- **Standalone Fast-Path Test**: Verify that requests to a `serverless_only` site bypass the attack detector and reach the function with lower latency.
- **ABI Expansion Test**: Create a test WASM module that queries the DHT and validates the response.
- **Remote Execution Test**: Deploy two nodes (Edge and Origin). Send a request for a function to the Edge node; verify it is correctly proxied to and executed by the Origin node, with the response returned.
- **Event Dispatch Test**: Trigger a mock threat event and verify that a subscribed serverless function executes and logs the event.

## 6. Migration & Rollback
-   **Configuration Compatibility**: Ensure all new fields (`serverless_only`, new mesh roles) are optional with sensible defaults (false/disabled) to maintain backward compatibility.
-   **ABI Versioning**: The new host functions will be optional imports for existing WASM modules. Old modules without these imports will continue to function normally.
-   **Rollback Strategy**: If remote execution causes instability, it can be disabled via mesh configuration without affecting local serverless execution.
