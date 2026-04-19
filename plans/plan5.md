# Plan 5: Plugin Architecture Improvements

This plan outlines a series of architectural improvements for the WASM and Native plugin systems in `rustwaf`, focusing on security, developer ergonomics, and mesh performance.

## 1. Transition to WASM Component Model (WIT)

The current WASM ABI relies on raw pointers and manual serialization, which is error-prone and limits interoperability.

### Proposed Changes
- **WIT Definitions:** Create `.wit` files defining the host-guest interface for Filtering, Response Transformation, and Serverless Request Handling.
- **`wasmtime` Component Support:** Refactor `WasmRuntime` and `WasmPluginManager` to use `wasmtime::component`.
- **Guest SDKs:** Provide a `rustwaf-plugin-sdk` for Rust and other languages (Go, TinyGo) that generates bindings from the WIT files.
- **Type Safety:** Eliminate `serialize_headers` and manual memory management in favor of WIT's high-level types.

### Addressing Memory Management
The current fallback to a fixed `1024` offset in `write_to_guest_memory` is fragile. The new system will:
- **Mandatory `guest_alloc`:** Require plugins to export allocation functions or use the Component Model's built-in memory management.
- **Linear Memory Safety:** Use `wasmtime`'s memory view for safer host-to-guest copies without manual pointer arithmetic where possible.

## 2. "Safe" Native Plugins (Out-of-Process Axum)

Currently, native Axum plugins run in the same process as the WAF, posing a security and stability risk.

### Proposed Changes
- **Worker Process Pattern:** Allow Axum plugins to run in a dedicated child process.
- **Shared Memory IPC:** Use shared memory (e.g., via the `shared_memory` or `iceoryx-rs` crates) for high-performance request/response handoff between the WAF and the plugin worker.
- **Unix Domain Sockets (Fallback):** Use UDS for control plane and small payload transfers.
- **Process Isolation:** Use namespaces or cgroups (where available) to limit the resources of the plugin worker process.

## 3. Advanced Mesh Caching & Distribution

WASM modules are currently stored in the DHT and retrieved on-demand. This can lead to latency during "cold starts" in the mesh.

### Proposed Changes
- **Local Persistent Cache:** Implement a disk-backed cache for WASM modules retrieved from the mesh to avoid DHT lookups after restarts.
- **Prefetching Policy:** Allow sites to define a list of "critical" plugins that should be prefetched and kept warm on all nodes in a cluster.
- **Incremental Syncing:** Only pull WASM modules if the local checksum differs from the global DHT record (currently somewhat implemented, but needs more robust delta syncing).

## 4. Enhanced Resource Management & Observability

While fuel and memory limits exist, they are not easily visible or adjustable at runtime.

### Proposed Changes
- **Dynamic Limits:** Allow the Admin UI to adjust fuel and memory limits for a running plugin without reloading it (requires updating the `wasmtime::Store` configuration).
- **Per-Plugin Metrics:** Expose detailed metrics (CPU time, fuel consumed, memory peaks) to Prometheus and the Admin UI for every individual plugin instance.
- **Flamegraphs:** Add support for generating execution flamegraphs for WASM plugins to help authors identify bottlenecks.

## 5. Unified Plugin Lifecycle & Loading

The separation between filtering plugins and serverless functions is currently a bit fragmented.

### Proposed Changes
- **Unified Loader:** Create a single `PluginRegistry` that manages both `filter` and `serverless` modules, allowing a single `.wasm` file to export both types of functionality.
- **Hot-Reloading for Native Plugins:** Implement a strategy for reloading native plugins by spawning a new worker (if out-of-process) and seamlessly routing new requests to it while draining the old one.
- **Dependency Management:** Allow plugins to declare dependencies on other plugins or host-provided capabilities (e.g., a "shared cache" plugin).

---

## Implementation Phases

### Phase 1: Stabilization & Observability (Quick Wins)
- Implement per-plugin Prometheus metrics.
- Expose dynamic resource limits via the Admin API.
- Add local persistent caching for mesh modules.

### Phase 2: Mesh Performance
- Implement prefetching policy for site-specific plugins.
- Refine DHT syncing to use deltas for WASM module updates.

### Phase 3: The Component Model Pivot
- Draft WIT definitions and release the first version of the `rustwaf-plugin-sdk`.
- Migrating `WasmRuntime` to `wasmtime::component`.
- Deprecate the legacy raw-pointer ABI.

### Phase 4: Out-of-Process Native Plugins
- Develop the child-process worker wrapper for Axum plugins.
- Implement shared-memory IPC for request/response bodies.
- Integrate with `systemd` or `cgroups` for resource isolation of workers.

---

## Success Criteria
- [ ] Successful execution of a WIT-based WASM plugin with zero raw pointer usage in host code.
- [ ] Benchmarking "Safe" Native Plugins vs. in-process plugins shows <5% latency overhead for typical payloads.
- [ ] WASM module prefetching reduces cold-start latency in the mesh by >80%.
- [ ] Per-plugin resource metrics (fuel, memory) are visible in the Admin UI in real-time.
- [ ] Native plugins can be reloaded without dropping active HTTP connections.
