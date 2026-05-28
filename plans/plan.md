# SynVoid Implementation Plan

> **Status**: All actionable items (Waves 1-6) completed and verified 2026-05-28.
> Only deferred items requiring major architectural work remain.
> See git history for completed item details.

---

## Deferred Items (Requires Major Architectural Work)

These items require significant architectural work and are correctly deferred:

| ID | Issue | Reason | Effort |
|----|-------|--------|--------|
| **MESH-14** | Source Node ID Binding Validation | `verify_peer_certificate()` exists at `src/mesh/cert.rs:790-872` but is **never called**. Default mesh TLS config is permissive (no CA = accept all). Requires PKI hierarchy, trust model changes, and wiring into connection establishment. | VeryHigh |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | `ErasedHttpClient` streaming path remains HTTP/1.1-only. HTTP/2 works via `TypedConnectionPool` for `Full<Bytes>` bodies only. hyper-util API requires background task management per connection for full streaming HTTP/2 support. | VeryHigh |
| **MR-4** | DhtSyncRequest has no auth | `DhtSyncRequest` proto (`mesh.proto:897-901`) and Rust struct (`protocol.rs:848-852`) have no `signature`/`signer_public_key` fields. Breaking protobuf protocol change requiring coordinated rollout across all mesh nodes. | High |

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
| CertResolver | `src/tls/cert_resolver.rs` | 215-253 |
| filter.rs | `src/filter/common.rs` | 74-96 (deny/allow check) |
| BlockStore | `src/waf/block_store.rs` | 64-shard Vec<RwLock<AHashMap>> |

---

## Completed Work Summary

All 183 items across 6 waves were completed and verified 2026-05-28:

| Wave | Category | Items | Status |
|------|----------|-------|--------|
| 1 | Security-Critical Fixes (P0) | 4 | ALL RESOLVED |
| 2 | Code Bug Fixes (P1) | 8 | ALL RESOLVED |
| 3 | Dead Code Cleanup (P1) | 9 | ALL REMOVED |
| 4 | Feature Wiring (P1-P2) | 4 | ALL WIRED |
| 5 | Documentation Updates (P2-P3) | 148 | ALL UPDATED |
| 6 | Cross-Module Conflicts (P2) | 7 | ALL RESOLVED |
| — | Deferred Items | 3 | DEFERRED |
| **Total** | | **186** | **183 done, 3 deferred** |

---

*Last Updated: 2026-05-28*
*All actionable items completed. Only deferred architectural items remain.*
