# MaluWAF Implementation Plan

This document tracks remaining work. All Waves 1-5 items have been completed.

## Quick Reference

| Category | Items | Status |
|----------|-------|--------|
| Future Work (Deferred) | 13 | 🔄 Pending |
| Open Items | 3 | ⚠️ Partial/Open |

**Legend**: 🔄 = Pending | ⚠️ = Partial/Open | ❌ = Open

---

## Future Work (13 items)

The following items were identified during implementation and deferred for future work:

---

### F.1 ShardedZoneStore is_empty() Optimization

**Status**: 🔄 Pending

**Location**: `src/dns/server/sharded_store.rs`

**Issue**: `is_empty()` iterates all 64 shards O(n).

**Fix**: Short-circuit on first non-empty shard (O(1)).

---

### F.2 DHT Metrics and Observability

**Status**: 🔄 Pending

**Location**: `src/mesh/dht/`, `src/metrics/mod.rs`

**Issue**: Limited observability into DHT operations.

**Fix**: Add per-bucket peer counts, record count by type, announce queue depth, store/get operations, peer discovery metrics, propagation hop tracking.

---

### F.3 Configuration Documentation for DhtConfig

**Status**: 🔄 Pending

**Location**: `src/mesh/dht/mod.rs`

**Issue**: DhtConfig fields lack documentation.

**Fix**: Add doc comments to all 27 DhtConfig fields explaining purpose, valid values, and defaults.

---

### F.4 CSS Honeypot Enhancement - Path Tracking

**Status**: 🔄 Pending

**Location**: `src/challenge/honeypot.rs`, `src/admin/handlers/honeypot.rs`

**Issue**: Honeypot doesn't track which app_path served the trap.

**Fix**: Add `HoneypotTrapPath` struct, extend `HoneypotEntry` with per-path tracking, add `get_path_stats()`.

---

### F.5 Metrics for Threat Intel DHT Operations

**Status**: 🔄 Pending

**Location**: `src/metrics/mod.rs`, `src/mesh/threat_intel.rs`

**Issue**: No observability into Threat Intel DHT publish/lookup/sync operations.

**Fix**: Add THREAT_INTEL_DHT_PUBLISH_TOTAL/FAILED, LOOKUP_HITS/MISSES, SYNC_TOTAL/SUCCESS/FAILED/ADDED/REMOVED metrics.

---

### F.6 Unified Announcement Mechanism Cleanup

**Status**: 🔄 Pending

**Location**: `src/mesh/`

**Issue**: Dead `UpstreamRegistrationRequest` code still present.

**Fix**: Remove message type, handlers, protobuf, encoding/decoding. Keep `UpstreamAnnounce` as active mechanism.

---

### F.7 DHT Key Type Consistency - Remove is_global_signature_required()

**Status**: 🔄 Pending

**Location**: `src/mesh/dht/keys.rs`

**Issue**: Orphaned `is_global_signature_required()` function never called.

**Fix**: Remove the function.

---

### F.8 Reputation System Bug - Hardcoded 50

**Status**: 🔄 Pending

**Location**: `src/mesh/transport_dht.rs`

**Issue**: Hardcoded `50` reputation threshold instead of actual `rep_score`.

**Fix**: Replace hardcoded threshold with actual peer reputation value.

---

### F.9 Global Node Liveness and Quorum Monitoring

**Status**: 🔄 Pending

**Location**: `src/mesh/dht/`, `src/mesh/transport_global.rs`, `src/mesh/transport.rs`

**Issue**: No heartbeat mechanism for global node liveness.

**Fix**: Add `GlobalNodeHeartbeat` DHT key type, publish at 30s interval with 90s TTL.

---

### F.10 IPv6 Zone ID SSRF Bypass

**Status**: 🔄 Pending

**Location**: `src/waf/attack_detection/ssrf.rs`

**Issue**: `looks_like_ip()` doesn't strip zone IDs (e.g., `fe80::1%eth0`).

**Fix**: Strip zone ID before parsing. Add IPv6 parsing path in `is_private_ip()`.

---

### F.11 Homoglyph Normalization Gaps

**Status**: 🔄 Pending

**Location**: `src/waf/attack_detection/normalizer.rs`

**Issue**: Missing Cyrillic and Greek character normalizations.

**Fix**: Add Cyrillic Т (U+0422) → T. Add Greek letter normalizations: α→a, Α→A, τ→t, Τ→T, ο→o, Ο→O, ι→i, Ι→I, ν→v, Ν→N.

---

### F.12 TODO Comments - File Manager

**Status**: 🔄 Pending

**Location**: `src/http/file_manager.rs`

**Issue**: TODO comments still present, routes commented out.

**Fix**: Remove TODO comments, uncomment routes, add `#[axum::debug_handler]` to handlers.

---

### F.13 O.4: ConnectionMeta Trait and Unified Handler Foundation

**Status**: ✅ Foundation Complete (remaining migration is Future Work)

**Location**: `src/server/request_handler.rs`

**Fix**: Created `ConnectionMeta` trait with implementations for `HttpConnection` and `HttpsConnection`. Created `TlsContext` struct to carry ja4_hash and protocol through the pipeline.

**What was done**:
- `ConnectionMeta` trait with `request_drop()`, `should_drop()`, `get_ja4()`, `supports_websocket()`, `protocol()`, `tls_context()`
- `TlsContext` struct carrying TLS metadata
- `UnifiedHandlerConfig` for per-connection configuration
- Implementations for both connection types

**Remaining (deferred to future work)**:
- Migrate request processing from both servers to use unified handler
- Remove duplicate code from `tls/server.rs`
- Wire JA4 to WAF bot detection

---

## Open Items (4)

Items requiring architectural changes:

---

### O.1 JA4 Fingerprint Wired to WAF Bot Detection

**Status**: ⚠️ Partial

**Location**: `src/tls/server.rs:53-63`, `src/waf/bot.rs:164-169`, `src/waf/mod.rs:1175-1209`

**Issue**: JA4 hash is computed from TLS ClientHello but `check_bot_protection()` only passes `user_agent`. `check_with_ja4()` exists but is never called.

**Fix Required**: Pass `ja4_hash` from `HttpsConnection` through to `check_bot_protection()` and call `bot_detector.check_with_ja4()`.

---

### O.2 Stream Large Request Bodies

**Status**: ❌ Open

**Location**: `src/http/server.rs`

**Issue**: Full request body is buffered in memory.

**Fix Required**: Chunk-based WAF processing.

---

### O.3 Response Streaming

**Status**: ❌ Open

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: Responses are fully buffered before sending.

**Fix Required**: Stream responses using chunked transfer encoding.

---

(End of file)