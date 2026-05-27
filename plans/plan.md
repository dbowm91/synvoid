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

## Deferred Items (Requires Architectural/Complex Work)

These items require significant architectural work or are deferred due to complexity:

| ID | Issue | Reason | Effort | Status |
|----|-------|--------|--------|--------|
| **MESH-14** | Source Node ID Binding Validation | Partial validation exists (node_id bound to TLS), but no TLS cert chain validation for global nodes. Requires PKI hierarchy, trust model changes. | VeryHigh | Correctly Deferred |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | `Http2PooledConnection` is empty stub. hyper-util API requires background task management per connection. | VeryHigh | Correctly Deferred |
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change - no signature field. Coordinated rollout required. | High | Correctly Deferred |
| **DNS-QUERY** | QueryCoalescer max_wait_ms | **FIXABLE** - requires async redesign of `get_or_wait()`. "Documented limitation" claim is incorrect. | Medium | Should Fix |
| **PR-6** | ProxyHeadersConfig not passed through | Enhancement with dead code (`dispatch_to_upstream`, `ProxyExecutor`). Simple field addition but architecture unclear. | Low-Medium | Investigate & Fix |
| **SUP-1** | gRPC Control Plane TLS | **NOT Intentional** - TLS infra exists in codebase. Low effort ~150-200 LOC. | Low | Should Implement |
| **BUG-PL-4** | macOS Seatbelt incomplete | **MISLEADING** - implementation exists but is feature-gated, causes silent failure (no sandbox applied). Should add runtime detection like other platforms. | Low-Medium | Should Fix |

---

## Detailed Findings (Deep Dive 2026-05-27)

### MESH-14: Source Node ID Binding Validation

**Location**: `src/mesh/dht/signed.rs`, `src/mesh/transport_peer.rs:1344-1361`

**Current State**:
- `validate_peer_node_id_binding()` exists and binds `node_id` to TLS connection
- Edge nodes get org cert chain validation via `validate_member_certificate()`
- **Global nodes bypass cert chain validation** - only Ed25519 signature validation used

**Complete Implementation Requires**:
1. TLS Certificate Chain Validation for ALL node types (global + edge)
2. PKI hierarchy establishment (trusted root CAs, intermediate certs)
3. Cert's `mesh_id` field must match claimed `node_id`
4. Revocation status checking against `GlobalNodeRevocationList`

**Breaking Changes**: PKI hierarchy, trust model unification, protocol changes

**Verdict**: Correctly deferred - VeryHigh effort, requires breaking changes

---

### HTTP2-POOL: ErasedHttpClient HTTP/2 Support

**Location**: `src/http_client/erased_pool.rs:125-127`

**Current State**:
- `Http2PooledConnection` has only `authority` field - is_available() returns false
- HTTP/1.1 pooling works fine (`Http1PooledConnection` fully implemented)
- `TypedConnectionPool` already supports HTTP/2 via `.http2_only(is_http2)` at typed_pool.rs:169

**Why Deferred**:
- HTTP/2 requires active background task per connection (connection driver)
- hyper-util's `Client` manages this internally but doesn't expose manual pooling
- No reference implementation for type-erased body with manual H2 pooling

**Alternative Approach**: Consider using `hyper_util::client::legacy::Client` with `pool_max_idle_per_host` instead of building manual pooling infrastructure

**Verdict**: Correctly deferred - VeryHigh effort, no reference implementation

---

### MR-4: DhtSyncRequest Has No Auth

**Location**: `src/mesh/protocol.rs:869-873`, `src/mesh/transport_peer.rs:687-705`

**Current State**:
```rust
DhtSyncRequest {
    request_id: ArcStr,
    node_id: ArcStr,
    from_version: u64,
},  // NO signature, NO signer_public_key, NO timestamp
```

**Partial Protection**: `validate_peer_node_id_binding()` binds node_id to TLS identity

**Complete Implementation Requires**:
1. Protobuf change: Add `signature`, `signer_public_key`, `timestamp` fields
2. New signable struct for DhtSyncRequest
3. Signature verification in `handle_dht_sync_request`
4. Coordinated rollout (all nodes must update simultaneously)

**Verdict**: Correctly deferred - High effort, breaking protobuf change

---

### DNS-QUERY: QueryCoalescer max_wait_ms (FIXABLE)

**Location**: `src/dns/query_coalesce.rs:117-124`

**Current State**:
```rust
pub fn with_config(_max_wait_ms: u64, ...) {
    // _max_wait_ms IGNORED - underscore prefix means unused
}
```

**Why Parameter Unused**: Implementation chose non-blocking `try_recv()` semantics instead of bounded wait

**Fix Requires**:
1. Store `max_wait` field in struct
2. Change `get_or_wait()` from sync to async fn
3. Use `tokio::time::timeout(max_wait, receiver.recv())`
4. Update callers in `query.rs` to `.await`

**Claim "Documented Limitation"**: INCORRECT - this is fixable with ~70 lines of changes

**Verdict**: Should fix - Medium effort, async redesign needed but not architecturally complex

---

### PR-6: ProxyHeadersConfig Not Passed Through

**Location**: `src/proxy/mod.rs:1175-1263`, `src/proxy/executor.rs:98-107`, `src/proxy/dispatch.rs:42-68`

**Current State**:
- `ProxyServer` has no `proxy_headers_config` field
- `send_single_request` uses simple `headers.cloned().unwrap_or_default()`
- `build_forward_headers()` exists but is not called

**Dead Code Discovery**:
- `ProxyExecutor` and `dispatch_to_upstream` are defined but **never instantiated**
- `dispatch_to_upstream` already has proper `ProxyHeadersConfig` handling
- This suggests an abandoned refactoring

**Fix Options**:
- **A**: Add `proxy_headers_config` field to `ProxyServer`, use in `send_single_request`
- **B**: Investigate if `dispatch_to_upstream` should be used/completed or removed as dead code

**Verdict**: Should investigate and fix - Low-Medium effort, includes dead code cleanup

---

### SUP-1: gRPC Control Plane TLS (Should Implement)

**Location**: `src/supervisor/api.rs:138-141`, `src/process/command.rs:77`

**Current State**:
- Server uses plain `tonic::transport::Server::builder()` with no TLS
- Client connects with `format!("http://{}", addr)` - hardcoded `http://`
- Binds to `127.0.0.1:50051` (localhost-only)

**Why "Intentional" is Misleading**:
- TLS infrastructure (`rustls`, `InternalTlsConfig`) already exists in codebase
- Tonic's TLS support is well-documented
- localhost-only binding reduces risk but doesn't eliminate it

**Fix Requires** (~150-200 lines):
1. Add `control_api_tls: Option<TlsConfig>` to SupervisorConfig
2. Modify `start_grpc_server()` to accept TLS config
3. Use `tonic::transport::Server::builder().tls(tls_config)`
4. Update client to detect TLS vs non-TLS from config

**Verdict**: Should implement - Low effort, "intentional" is weak reasoning

---

### BUG-PL-4: macOS Seatbelt Incomplete (Should Fix)

**Location**: `src/platform/sandbox.rs:1021-1154`

**Current State**:
- Feature-gated implementation (`#[cfg(feature = "macos-sandbox")]`)
- Without feature: `is_supported()` returns `false`, but `apply_sandbox_impl()` returns `Ok(())`
- **Silent failure**: Users think sandboxing works when it doesn't

**Inconsistency with Other Platforms**:
| Platform | Feature Gate | Runtime Detection |
|----------|--------------|-------------------|
| Linux | None | `is_landlock_available()` |
| FreeBSD | None | `is_capsicum_available()` |
| Windows | None | Always supported |
| **macOS** | **Full impl behind feature** | N/A - just returns false |

**Fix Requires** (~50-80 lines):
1. Remove `#[cfg(feature = "macos-sandbox")]` around implementation
2. Add runtime availability detection (like other platforms)
3. Fix silent `Ok(())` to proper error/warning when feature disabled

**Verdict**: Should fix - Low-Medium effort, causes silent failure, inconsistent with other platforms

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
*Deep dive analysis completed. Items marked "Should Fix" are fixable without major architectural changes.*
*See git history for completed item details (commits 2026-05-27).*

(End of file - ~200 lines)