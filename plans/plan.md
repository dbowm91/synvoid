# SynVoid Implementation Plan

> **Note**: This file contains implementation plans for remaining items.
> Completed items have been pruned. See git history for completed item details.

---

## Priority Key
- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Active Implementation Items

### HTTP/2 Pooling Infrastructure

**Priority**: P2 (Performance Milestone)
**Status**: DEFERRED - hyper-util API incompatible

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

## Deferred Items (Architectural Changes Required)

These items require significant architectural work and are tracked separately:

| ID | Issue | Reason |
|----|-------|--------|
| **MESH-14** | Source Node ID Binding Validation | Fundamental TLS/cert identity binding |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | Requires hyper-util API investigation |
| **SUP-1** | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change |

---

## Quick Reference: Key Files

| Component | File | Lines |
|-----------|------|-------|
| QuorumManager | `src/mesh/dht/quorum.rs` | 316-437 |
| RaftClient | `src/mesh/raft/client.rs` | 186-213 |
| FastCGI Client | `src/fastcgi/mod.rs` | 98-164 |
| DrainManager | `src/overseer/drain_manager.rs` | 20-368 |
| SupervisorProcess | `src/supervisor/process.rs` | 186-249 |
| ProxyServer | `src/proxy/mod.rs` | 73-226 |
| ErasedHttpClient | `src/http_client/erased_pool.rs` | 415-456 |

---

## Implementation Status (2026-05-27)

### Completed Items (Pruned - See Git History)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| MESH-15-FIX-1 | is_request_complete() lock release | ✅ DONE | Fixed with early return using read lock |
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
| HTTP2-POOL-1-4 | ErasedHttpClient HTTP/2 pooling | Deferred - hyper http2_client::handshake() API incompatible |

---

*Last Updated: 2026-05-27*
*Plan pruned - all completed items moved to git history*