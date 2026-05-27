# SynVoid Implementation Plan

> **Note**: This file is the consolidated implementation plan for remaining items.
> Completed items have been pruned from this file. See git history for completed item details.

---

## Priority Key

- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Deferred Items (Architectural Changes Required)

These items require significant architectural work and are tracked separately:

| ID | Issue | Reason |
|----|-------|--------|
| **MESH-14** | Source Node ID Binding Validation | Partial validation exists (node_id vs peer_id via TLS), but no TLS cert chain validation - requires breaking changes |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | `Http2PooledConnection` is empty stub - hyper-util API investigation needed |
| **SUP-1** | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change - no signature field |
| **DNS-QUERY** | QueryCoalescer max_wait_ms | Documented limitation, may not be fixable (underscore prefix = unused) |
| **PR-6** | ProxyHeadersConfig not passed through send_single_request | Enhancement, not a bug |
| **BUG-PL-4** | macOS Seatbelt implementation incomplete | Feature-gated, returns false by default |

---

## HTTP/2 Pooling Implementation Plan (When Resolved)

**Status**: DEFERRED - hyper-util API incompatible

When the hyper-util API issue is resolved, implement HTTP/2 pooling:

### Step 1: HTTP2-POOL-1
- Location: `src/http_client/erased_pool.rs:125-127`
- Add connection fields: `io`, `sender`, `driver` task
- Implement proper HTTP/2 connection handshake

### Step 2: HTTP2-POOL-2
- Add `inner_h2` HashMap for HTTP/2 connections
- Update `checkout()` to route based on `key.is_http2`

### Step 3: HTTP2-POOL-3
- Use `is_http2` to select HTTP/1.1 or HTTP/2 pool

### Step 4: HTTP2-POOL-4
- Remove hardcoded `http2_only(false)` or make configurable

---

## Quick Reference: Key Files

| Component | File | Lines |
|-----------|------|-------|
| QuorumManager | `src/mesh/dht/quorum.rs` | 316-437 |
| RaftClient | `src/mesh/raft/client.rs` | 186-213 |
| FastCGI Client | `src/fastcgi/mod.rs` | 98-164 |
| DrainManager | `src/supervisor/process.rs` | 186-257 |
| ProxyServer | `src/proxy/mod.rs` | 73-226 |
| ErasedHttpClient | `src/http_client/erased_pool.rs` | 415-456 |
| ML-KEM Key Exchange | `src/mesh/ml_kem_key_exchange.rs` | 204-265 |
| Spin Runtime | `src/spin/runtime.rs` | 289-303 |
| WafCore | `src/waf/mod.rs` | 172-199 |
| HickoryRecursor DNSSEC | `src/dns/resolver.rs` | 693-702 |
| HTTP/3 Body Collection | `src/http3/server.rs` | 340-398 |
| collect_body_with_chunk_waf | `src/http/server.rs` | 4666-4700 |

---

*Last Updated: 2026-05-27*
*All completed items pruned. Deferred items remain under active tracking.*
*See git history for completed item details (commits 2026-05-27).*

(End of file - ~75 lines)