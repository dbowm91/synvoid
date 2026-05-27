# SynVoid Implementation Plan

> **Note**: This file contains detailed implementation plans for remaining items.
> Each section has specific code locations, implementation steps, and verification methods.

---

## Priority Key
- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Active Implementation Items

### MESH-15: Quorum Deadlock Risk During Partition

**Priority**: P1 (Security/Correctness)
**Status**: NOT DEFERRED - Active work item

#### Problem Analysis

The deadlock occurs in `src/mesh/dht/quorum.rs` due to:

1. **`is_request_complete()` at lines 412-430** holds a write lock while returning `false`:
   ```rust
   pub async fn is_request_complete(&self, request_id: &str) -> bool {
       let mut pending_raft = self.pending_raft_requests.write().await;
       if let Some(rx) = pending_raft.get_mut(request_id) {
           if let Ok(result) = rx.try_recv() {  // Returns Empty - lock still held!
               // cleanup
               return true;
           }
           false  // LOCK STILL HELD!
       } else {
           true  // LOCK STILL HELD!
       }
   }
   ```

2. **No partition detection** before attempting Raft writes - `check_network_partition()` exists but isn't used in quorum path

3. **5-second timeout** in `client.rs:186-213` causes spawned tasks to exit without proper cleanup

#### Implementation Steps

**Step 1: Fix `is_request_complete()` lock release** (MESH-15-FIX-1)
- Location: `src/mesh/dht/quorum.rs:412-430`
- Change to use read lock for checking, only write lock for cleanup:
  ```rust
  pub async fn is_request_complete(&self, request_id: &str) -> bool {
      // First check WITHOUT holding lock
      let should_remove = {
          let pending_raft = self.pending_raft_requests.read().await;
          if let Some(rx) = pending_raft.get(request_id) {
              match rx.try_recv() {
                  Ok(result) => true,
                  Err(TryRecvError::Empty) => return false,  // No lock held!
                  Err(TryRecvError::Closed) => true,
              }
          } else {
              true
          }
      };
      
      if should_remove {
          let mut pending_raft = self.pending_raft_requests.write().await;
          pending_raft.remove(request_id);
      }
      
      should_remove
  }
  ```

**Step 2: Add partition detection to `start_request()`** (MESH-15-FIX-2)
- Location: `src/mesh/dht/quorum.rs:358-410`
- Before spawning Raft task, check `self.topology.check_network_partition()`
- If partition detected, return error immediately instead of spawning deadlocking task

**Step 3: Add background cleanup for stale requests** (MESH-15-FIX-3)
- Add periodic task to clean up `pending_raft_requests` entries older than timeout
- Prevents accumulated stale state during long partitions

**Step 4: Add retry with exponential backoff to `MeshRaftNetwork::send_raw()`** (MESH-15-FIX-4)
- Location: `src/mesh/raft/network.rs:53-91`
- Implement retry logic for transient failures
- Detect partition and signal back to openraft

#### Verification
```bash
cargo test --lib quorum
cargo test --test mesh_quorum_test  # if exists
```

#### Dependencies
- MESH-14 (Source Node ID Binding) - separate issue, not blocking

---

### APP-15: FastCGI Response True Streaming

**Priority**: P1 (Performance/Architecture)
**Status**: NOT DEFERRED - Active work item

#### Problem Analysis

**Buffering occurs at `src/fastcgi/mod.rs:132-164`:**
```rust
fn parse_response(
    stdout: Option<Vec<u8>>,  // <-- Entire stdout collected
    stderr: Option<Vec<u8>>,
) -> Result<FastCgiResponse, FastCgiError> {
    let stdout = stdout.unwrap_or_default();  // <-- Collects all into Vec
    let body = Bytes::from(body_bytes.to_vec());  // <-- Another copy
}
```

**Root cause**: `fastcgi-client` crate (v0.10) returns complete `Output` with `stdout: Option<Vec<u8>>`

#### Implementation Steps

**Step 1: Implement streaming FastCGI client** (APP-15-FIX-1)
- Location: `src/fastcgi/streaming.rs` (new file)
- Create `FastCgiResponseStream` that yields `Bytes` chunks as FCGI records arrive
- Requires implementing FCGI protocol record parsing (8-byte header + content)

**Step 2: Update pool interface** (APP-15-FIX-2)
- Location: `src/fastcgi/pool.rs:178-207`
- Add `execute_stream()` method alongside existing `execute()`
- `execute_stream()` returns `impl Stream<Item = Result<Bytes, FastCgiError>>`

**Step 3: Update HTTP handlers for streaming** (APP-15-FIX-3)
- Locations: `src/http/server.rs:2561-2695`, `src/tls/server.rs:1523-1537`
- Change from `Full<Bytes>` body to streaming `Body`
- Apply WAF transforms incrementally (not on complete body)
- Apply minification and image poisoning in chunk-based manner

**Step 4: Add feature flag for backwards compatibility** (APP-15-FIX-4)
- Add `fastcgi_streaming` feature flag
- Default to existing buffered behavior for stability
- Streaming mode opt-in for performance-critical deployments

#### Key Code Locations
| File | Purpose |
|------|---------|
| `src/fastcgi/mod.rs:98-103` | `execute_unix()` - buffering call |
| `src/fastcgi/mod.rs:124-129` | `execute_tcp()` - buffering call |
| `src/fastcgi/mod.rs:132-164` | `parse_response()` - collects entire stdout |
| `src/fastcgi/pool.rs:178-207` | `execute()` - pool interface |
| `src/http/server.rs:2505-2717` | FastCGI HTTP handler |

#### Risks
| Risk | Mitigation |
|------|------------|
| Breaking API changes | Provide both streaming and buffered modes |
| WAF transform compatibility | Redesign transforms for chunk-based processing |
| Dependency replacement | Implement protocol manually if no streaming crate available |

#### Verification
```bash
cargo test --lib fastcgi
# Integration test with actual FastCGI backend
```

---

### PL-5: DrainManager Porting to Supervisor

**Priority**: P1 (Zero-Downtime Upgrades)
**Status**: NOT DEFERRED - Active work item

#### Problem Analysis

**Overseer's DrainManager provides** (`src/overseer/drain_manager.rs`):
- Per-worker connection tracking (active/idle counts)
- Unique drain ID generation
- Coordinated drain protocol via IPC (DrainRequest, StopAccepting, PollDrainStatus)
- Dynamic drain timeout based on actual progress

**Supervisor's `ProcessManager::graceful_shutdown()` provides** (`src/process/manager.rs:1605-1625`):
- Broadcasts SIGTERM
- Blind wait with fixed 5-second timeout
- No connection awareness

#### Implementation Steps

**Step 1: Add DrainManager to SupervisorProcess** (PL-5-FIX-1)
- Location: `src/supervisor/process.rs`
- Add `drain_manager: Arc<DrainManager>` field to struct
- Initialize in `SupervisorProcess::new()`

**Step 2: Port DrainManager if needed** (PL-5-FIX-2)
- The `DrainManager` in `src/overseer/drain_manager.rs` is designed for Overseer's pool workers
- Supervisor uses `UnifiedServerWorkerProcess` with different IPC message types
- May need to adapt `DrainProtocol` for Supervisor's worker type
- Alternative: Create new `SupervisorDrainManager` that uses existing `DrainStatus` types

**Step 3: Replace graceful_shutdown with drain-aware shutdown** (PL-5-FIX-3)
- Location: `src/supervisor/process.rs:177`
- Current: `self.process_manager.graceful_shutdown().await;`
- Replace with drain-aware logic:
  ```rust
  async fn drain_workers_with_tracking(&self, timeout_secs: u64) {
      let drain_id = self.drain_manager.start_drain(timeout_secs);
      let ipcs = self.process_manager.get_all_unified_server_worker_ipc();
      for ipc in ipcs {
          // Use DrainProtocol or adapted version to:
          // 1. Send DrainRequest
          // 2. Send StopAccepting
          // 3. Poll for DrainStatusResponse until drain_complete
      }
      self.drain_manager.wait_for_drain(timeout_secs).await;
  }
  ```

**Step 4: Wire up ProcessManager integration** (PL-5-FIX-4)
- `ProcessManager` already has `drain_unified_server_worker_async()` (line 833)
- Either extend `ProcessManager` to use `DrainManager` internally
- Or have Supervisor orchestrate both

#### Key Code Locations
| File | Lines | Purpose |
|------|-------|---------|
| `src/overseer/drain_manager.rs` | 20-25 | DrainManager struct |
| `src/overseer/drain_manager.rs` | 189-368 | DrainProtocol |
| `src/supervisor/process.rs` | 17-26 | Current module docs (has limitation note) |
| `src/supervisor/process.rs` | 163 | Current shutdown call |
| `src/process/manager.rs` | 1605-1625 | graceful_shutdown() |
| `src/drain/mod.rs` | 13-93 | DrainStatus, WorkerDrainState (reusable) |

#### Dependencies
- PL-3 (Overseer fate) - Should be resolved before investing in porting

#### Verification
```bash
cargo test --lib process
# Integration test for zero-downtime upgrade scenario
```

---

### WRK-BUG-1: HTTP/2 Hardcoded in Proxy Paths

**Priority**: P1 (HTTP/2 Support)
**Status**: NOT DEFERRED - Active work item

#### Problem Analysis

**`ProxyServer::with_http2()` exists** but is never called:
- `tls/server.rs:1722` creates `ProxyServer` without calling `.with_http2()`
- All paths default to `is_http2: false`

**Hardcoded paths** that don't use configurable HTTP/2:
| Location | File | Issue |
|----------|------|-------|
| `proxy/executor.rs:209` | `send_request_with_body_headers_and_timeout` | No `is_http2` param |
| `proxy/executor.rs:306` | `trigger_revalidation` | No `is_http2` param |
| `proxy/dispatch.rs:49` | `dispatch_to_upstream` | No `is_http2` param |

**Configuration exists but not wired**: `site/proxy.rs:161` has `ProxyUpstreamConfig.http2` but it's never read

#### Implementation Steps

**Step 1: Wire `site_config.proxy.http2` to `ProxyServer`** (WRK-BUG-1-FIX-1)
- Location: `src/tls/server.rs:1722`
- Read `target.site_config.proxy.http2` and call `.with_http2(http2_enabled)`

**Step 2: Add `is_http2` to executor paths** (WRK-BUG-1-FIX-2)
- Location: `src/proxy/executor.rs`
- Option A: Add `is_http2` parameter to `send_request_with_body_headers_and_timeout`
- Option B: Use `send_request_erased_streaming` instead (already supports `is_http2`)

**Step 3: Add `is_http2` to dispatch path** (WRK-BUG-1-FIX-3)
- Location: `src/proxy/dispatch.rs:49`
- Similar change to executor

#### Key Code Locations
| File | Lines | Purpose |
|------|-------|---------|
| `src/proxy/mod.rs` | 73-95 | ProxyServer struct with `is_http2` field |
| `src/proxy/mod.rs` | 223-226 | `with_http2()` builder method |
| `src/proxy/mod.rs` | 1246 | send_single_request uses `self.is_http2` |
| `src/tls/server.rs` | 1722 | ProxyServer creation (missing `.with_http2()`) |
| `crates/synvoid-config/src/site/proxy.rs` | 161 | `ProxyUpstreamConfig.http2` config |

#### Verification
```bash
cargo test --lib proxy
# Integration test verifying HTTP/2 connection pool usage
```

---

### HTTP/2 Pooling Infrastructure

**Priority**: P2 (Performance Milestone)
**Status**: NOT DEFERRED - Active work item

#### Problem Analysis

**Three-tier infrastructure exists but HTTP/2 path is stub:**

| Component | Status |
|-----------|--------|
| `typed_pool.rs` | Complete but never instantiated |
| `erased_pool.rs` | `Http2PooledConnection` is empty stub |
| `mod.rs` | Always falls back to HTTP/1.1 |

**Key issues:**
1. `Http2PooledConnection` (erased_pool.rs:125-127) only has `authority` field - no actual connection
2. `is_http2` passed to `ErasedHttpClient::send_request()` but ignored
3. `http2_only(false)` hardcoded in client builders

#### Implementation Steps

**Step 1: Implement `Http2PooledConnection` properly** (HTTP2-POOL-1)
- Location: `src/http_client/erased_pool.rs:125-127`
- Add connection fields: `io`, `sender`, `driver` task
- Implement proper HTTP/2 connection handshake

**Step 2: Add HTTP/2 pool to `ErasedConnectionPool`** (HTTP2-POOL-2)
- Location: `src/http_client/erased_pool.rs`
- Add `inner_h2` HashMap for HTTP/2 connections
- Update `checkout()` to route based on `key.is_http2`

**Step 3: Wire HTTP/2 checkout in `ErasedHttpClient::send_request()`** (HTTP2-POOL-3)
- Location: `src/http_client/erased_pool.rs:426-450`
- Use `is_http2` to select HTTP/1.1 or HTTP/2 pool

**Step 4: Update client builders** (HTTP2-POOL-4)
- Location: `src/http_client/mod.rs:374,420`
- Remove hardcoded `http2_only(false)` or make configurable

#### Key Code Locations
| File | Lines | Purpose |
|------|-------|---------|
| `src/http_client/typed_pool.rs` | 113-171 | `create_typed_client()` with HTTP/2 |
| `src/http_client/erased_pool.rs` | 125-127 | `Http2PooledConnection` (stub) |
| `src/http_client/erased_pool.rs` | 275-312 | `checkout()` - only HTTP/1.1 |
| `src/http_client/erased_pool.rs` | 426-450 | `send_request()` - ignores `is_http2` |

#### Verification
```bash
cargo test --lib http_client
cargo test --lib erased_pool
```

---

### TunnelBackend Cleanup

**Priority**: P3 (Dead Code Removal)
**Status**: NOT DEFERRED - Cleanup item

#### Problem Analysis

**Two `TunnelBackend` types exist:**
| Type | Location | Status |
|------|----------|--------|
| `tunnel::router::TunnelBackend` (enum) | `src/tunnel/router.rs:200` | ACTIVE - used by `resolve_tunnel_backend()` |
| `tunnel::upstream::TunnelBackend` (struct) | `src/tunnel/upstream.rs:127` | DEPRECATED - completely unused |

**The deprecated struct is never called anywhere** - zero external references.

#### Implementation Steps

**Step 1: Remove deprecated `TunnelBackend` struct** (TUNNEL-FIX-1)
- Location: `src/tunnel/upstream.rs:125-146`
- Delete the entire struct and its impl block
- The `use crate::upstream::pool::{Backend, BackendProtocol};` import on line 123 may become unused
- `#![allow(unused_variables, dead_code)]` on line 1 can be removed if no other dead code

**Step 2: Update module docs** (TUNNEL-FIX-2)
- Update documentation at `src/tunnel/upstream.rs:11-21` to remove reference to removed struct

#### Verification
```bash
cargo build --lib
cargo test --lib tunnel
```

---

## Implementation Status (2026-05-27)

### Completed Items

| ID | Item | Status | Notes |
|----|------|--------|-------|
| MESH-15-FIX-1 | is_request_complete() lock release | ✅ DONE | Fixed in quorum.rs:412-430 |
| MESH-15-FIX-4 | MeshRaftNetwork::send_raw() retry | ✅ DONE | Added exponential backoff (100ms/200ms/400ms) |
| WRK-BUG-1-FIX-1 | HTTP/2 config wiring to ProxyServer | ✅ DONE | site_config.proxy.http2 now wired |
| WRK-BUG-1-FIX-2/3 | is_http2 to executor/dispatch paths | ✅ DONE | Uses send_request_erased_streaming |
| PL-5-FIX-1-4 | DrainManager port to Supervisor | ✅ DONE | Drain-aware shutdown implemented |
| APP-15-FIX-1-4 | FastCGI Streaming | ✅ DONE | New streaming.rs module, feature flag added |
| TUNNEL-FIX | Deprecated TunnelBackend removal | ✅ DONE | Struct removed from upstream.rs |

### Deferred/Cancelled Items

| ID | Item | Reason |
|----|------|--------|
| MESH-15-FIX-2 | Partition detection in start_request() | Not feasible - QuorumManager has no topology access |
| MESH-15-FIX-3 | Background cleanup for stale requests | Not needed - existing timeout handles cleanup |
| HTTP2-POOL-1-4 | ErasedHttpClient HTTP/2 pooling | Reverted - hyper http2_client::handshake() API incompatible |

### Notes

1. **HTTP/2 Pooling**: `typed_pool.rs` has proper HTTP/2 support via `Client::builder().http2_only()`. The `ErasedHttpClient` path needs further investigation - the `http2_client::handshake(io)` API requires TokioIo to implement traits not available in current hyper-util version.

2. **MESH-15-FIX-2**: The plan specified checking `self.topology.check_network_partition()` in `start_request()`, but QuorumManager doesn't have topology access. The partition detection would need to happen at a higher level before requests are sent to QuorumManager.

---

## Deferred Items (Architectural Changes Required)

These items require significant architectural work and are tracked separately:

| ID | Issue | Reason |
|----|-------|--------|
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change |
| **MESH-14** | Source Node ID Binding Validation | Fundamental TLS/cert identity binding |
| **SUP-1** | gRPC Control Plane TLS | Intentional - localhost IPC |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | Requires hyper-util API investigation |

---

## Implementation Order Recommendation

1. **MESH-15** (Quorum deadlock) - Security/correctness ✅
2. **WRK-BUG-1** (HTTP/2) - Configuration wiring ✅
3. **HTTP/2 Pooling** - Partially complete, blocked by hyper API issue
4. **PL-5** (DrainManager) - Zero-downtime upgrades ✅
5. **APP-15** (FastCGI Streaming) - Larger change, tested ✅
6. **TunnelBackend** - Cleanup ✅

---

## Quick Reference: Key Files

| Component | File | Lines |
|-----------|------|-------|
| QuorumManager | `src/mesh/dht/quorum.rs` | 316-430 |
| RaftClient | `src/mesh/raft/client.rs` | 186-213 |
| FastCGI Client | `src/fastcgi/mod.rs` | 98-164 |
| DrainManager | `src/overseer/drain_manager.rs` | 20-368 |
| SupervisorProcess | `src/supervisor/process.rs` | 17-26, 163-177 |
| ProxyServer | `src/proxy/mod.rs` | 73-226 |
| ErasedHttpClient | `src/http_client/erased_pool.rs` | 415-456 |

---

*Last Updated: 2026-05-27*
*Wave implementation complete - HTTP2-POOL deferred pending hyper API investigation*