# Traffic Layer Architecture Improvements Plan

## Overview
This document outlines the implementation plan for the 9 targeted improvements to the synvoid traffic layer. The plan is designed to transition the system from "optimistic performance" to "resilient scalability."

## Guardrails
- **Leverage Existing Codebase:** Implementations will heavily reuse existing structures (`DashMap`, `moka`, `matchit`, `mmap2`) to prevent code duplication.
- **Pure Rust:** No C-bindings will be introduced. We will rely on the existing Rust ecosystem (`tokio`, `regex`, `hyper`).
- **No Outside Dependencies:** External services like Redis are explicitly avoided. All shared state (like load balancing connection counts) will continue to use IPC/mmap primitives or fast concurrent in-memory structures to ensure the proxy remains a self-contained, high-performance binary.

---

## 1. Global Cache Resource Governor
**Goal:** Prevent OOM errors from unbounded `TeeBody` buffering under cache-miss floods.
- **Approach:** Introduce a `GlobalCacheGovernor` using `std::sync::atomic::AtomicUsize`.
- **Implementation:** 
  - Define a `MAX_INFLIGHT_CACHE_BYTES` static.
  - In `TeeBody::new()`, attempt to reserve the bytes specified by `Content-Length`. If the reserve fails (exceeds global quota), bypass `TeeBody` and stream directly to the client without attempting to cache the response.
  - Ensure bytes are released when the stream ends or errors out.
- **Dependencies:** Pure Rust (`std::sync::atomic`).

## 2. "Fast-Path" WAF Pre-Screening
**Goal:** Reduce CPU overhead by skipping complex detectors for clean traffic.
- **Approach:** Use a multi-pattern scanner before executing sequential heavy detectors.
- **Implementation:**
  - Utilize `regex::RegexSet` (already in the dependency tree via `regex`) to compile a single, highly optimized state machine of high-risk signatures (e.g., `'`, `<`, `UNION SELECT`).
  - Add a `pre_scan` method to `AttackDetector`. If `pre_scan` returns no match, skip the execution of the 20+ specialized deep-packet inspection detectors.
- **Dependencies:** Existing `regex` crate.

## 3. Unified Host Routing Index
**Goal:** Eliminate the $O(\text{Sites} \times \text{Domains})$ routing bottleneck.
- **Approach:** Consolidate domain lookup logic into a single $O(1)$ global index.
- **Implementation:**
  - In `src/router.rs`, deprecate the linear scan within `is_host_valid_for_site`.
  - Build a global `AHashMap<Arc<str>, Arc<SiteConfig>>` for exact domain matches and leverage the existing `matchit::Router` solely for wildcards, irrespective of the specific listener IP (unless explicit IP isolation is required by config, in which case compound keys like `IP:Host` can be used).
- **Dependencies:** Existing `ahash` and `matchit` crates.

## 4. "Secure-by-Default" Cache Whitelisting
**Goal:** Prevent sensitive application data leakage in the proxy cache.
- **Approach:** Convert the cache header filter from a blacklist to a whitelist.
- **Implementation:**
  - In `src/proxy/cache.rs` (`filter_sensitive_headers`), replace the `SENSITIVE_HEADERS` list with a `SAFE_HEADERS` whitelist (e.g., `Content-Type`, `Cache-Control`, `ETag`, `Last-Modified`).
  - Any header not in the whitelist is stripped before caching.
  - Introduce an `allowed_cache_headers` array in the `ProxyCacheConfig` to allow users to opt-in specific custom headers.
- **Dependencies:** Pure Rust.

## 5. Worker Liveness in Shared State (Ghost Connection Fix)
**Goal:** Prevent load balancer biases caused by crashed worker processes leaving stale connection counts.
- **Approach:** Add heartbeat tracking to the `mmap2` shared table.
- **Implementation:**
  - Expand the memory layout of `SharedConnectionTable` in `src/upstream/shared_state.rs` to include a `last_heartbeat` (AtomicU64 representing UNIX timestamp) alongside connection counters.
  - Each worker spawns a background Tokio task to update its heartbeat every second.
  - In `pool.rs`, the load balancer checks the heartbeat before factoring in a worker's connection count. If the heartbeat is stale (>5s), the worker is considered dead and its connections are ignored.
- **Dependencies:** Existing `mmap2` and `std::time::SystemTime`.

## 6. Deduplicated Background Revalidation
**Goal:** Prevent "Thundering Herd" on slow upstreams during the `stale-while-revalidate` window.
- **Approach:** Track active background revalidations.
- **Implementation:**
  - Add an `inflight_revalidations: Arc<DashMap<CacheKey, ()>>` to `ProxyCache`.
  - In `trigger_revalidation()`, attempt to insert the `CacheKey`. If it already exists, silently return (revalidation is already happening).
  - Remove the key from the map upon success or failure of the upstream request.
- **Dependencies:** Existing `dashmap` crate.

## 7. Fragment-Aware Multipart Parsing
**Goal:** Harden the streaming WAF against boundary-splitting exploits.
- **Approach:** Implement a sliding window buffer in the streaming WAF.
- **Implementation:**
  - In `StreamingState` (`src/waf/attack_detection/streaming.rs`), allocate a `sliding_window` buffer.
  - At the end of processing a 4KB chunk, retain the last $N$ bytes (where $N$ is the max length of a signature + boundary).
  - When the next chunk arrives, prepend the retained bytes to the scan buffer. This ensures malicious strings split precisely at chunk boundaries are caught.
- **Dependencies:** Pure Rust (`bytes::Bytes` or `PooledBuf`).

## 8. End-to-End Protocol Mirroring
**Goal:** Preserve QUIC (HTTP/3) head-of-line blocking elimination down to the upstream.
- **Approach:** Negotiate the highest possible protocol with upstreams.
- **Implementation:**
  - Enhance `HttpClient` pooling to dynamically select H2 streams for upstreams that support ALPN `h2`.
  - Ensure multiplexing over the same upstream connection is prioritized to prevent the proxy from falling back to a pool of blocked HTTP/1.1 connections when a QUIC client is pushing concurrent streams.
- **Dependencies:** Existing `hyper` and `quinn` crates.

## 9. Architectural "Pressure Valve" (Degraded Mode)
**Goal:** Keep the system alive during massive DDoS attacks by shedding load.
- **Approach:** Implement a global liveness monitor that forces graceful degradation.
- **Implementation:**
  - Create `SystemHealthMonitor` that tracks internal latency (e.g., time taken to acquire a lock or tokio schedule delay).
  - Expose an `AtomicU8` state (0=Normal, 1=Warning, 2=Critical).
  - **Warning State:** `Router` forces `TeeBody` to bypass (disables caching).
  - **Critical State:** `WafCore` bypasses behavioral checks and relies entirely on the `RegexSet` Fast-Path pre-scanner.
- **Dependencies:** Pure Rust (internal timings).