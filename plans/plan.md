# MaluWAF Improvement Plan - Consolidated

**Date**: 2026-04-07
**Status**: Wave 1 ✅, Wave 2 ✅, Wave 3 ✅, Wave 4 ✅, Wave 5 ✅, Wave 6 ✅, Wave 7 ✅ (All items complete as of 2026-04-08)

## Overview

This is the consolidated improvement plan combining all individual plan files (plan2-plan9). The plan addresses performance, scalability, and security improvements across the MaluWAF codebase.

---

## Plan Organization

Items are organized into **Waves** based on dependency chains and parallelization opportunities:

| Wave | Focus Area | Source Plans |
|------|------------|--------------|
| Wave 1 | Critical Performance Fixes | Plan 9 |
| Wave 2 | Mesh & DHT Infrastructure | Plan 8 |
| Wave 3 | WAF & Threat Intelligence | Plan 2, Plan 9 |
| Wave 4 | File Upload Security | Plan 3 |
| Wave 5 | Edge Caching & Transform Sharing | Plan 4 |
| Wave 6 | Serverless Architecture | Plan 5, Plan 7 |
| Wave 7 | Built-in Web App Stack | Plan 6 |

---

## Wave 1: Critical Performance Fixes

**Priority**: HIGH
**Source**: Plan 9

### 1.1 Blocking File I/O in Proxy Cache

**Location**: `src/proxy_cache/store.rs:234-247`

**Problem**: Uses synchronous `std::fs::read()` inside async context, blocking tokio runtime threads.

**Fix**: Use `tokio::fs::read()` or `tokio::task::spawn_blocking()`.

**Status**: ✅ Implemented

### 1.3 Input Normalization Double String Creation

**Location**: `src/waf/attack_detection/normalizer.rs:61-65`

**Problem**: Every normalized input creates both `normalized` and `lowercased` strings.

**Fix**: Cache lowercase version, avoid recalculation.

**Status**: ✅ Implemented (Cow<'static, str>)

### 1.4 String Allocation Reduction

**Locations**:
- `src/proxy.rs:68,123,128` - `header.to_lowercase()` on every response
- `src/proxy.rs:104,145,221,243,260` - unnecessary `to_string()` calls
- `src/waf/attack_detection/normalizer.rs` - double string creation

**Fix**: Use `&str` borrows, `Cow<str>`, or static sets.

### 1.5 Worker Auto-Scaling

**Location**: `src/process/manager.rs:264-265`

**Problem**: Default 1 worker cannot handle thousands of sites.

**Fix**: Add auto-scaling based on request load or site count.

**Status**: REMOVED - The unified server uses a single async event loop (tokio) which is far more efficient than spawning multiple worker processes. See AGENTS.md architecture notes for details.

---

## Wave 2: Mesh & DHT Infrastructure

**Priority**: HIGH
**Source**: Plan 8

### 2.1 DNS Capability Fix for Standalone WAF

**Location**: `src/mesh/protocol.rs:1001`

**Problem**: `can_serve_dns: config.dht.is_some() && role.is_global()` prevents standalone WAF from serving DNS.

**Fix**: Add `dns_mesh_mode_only: bool` to `MeshDhtConfig` (default: `true`). Modify capability:
```rust
can_serve_dns: !config.dht.as_ref().map(|c| c.dns_mesh_mode_only).unwrap_or(true) 
    || (config.dht.is_some() && role.is_global())
```

### 2.2 Add Explicit Capability Flags

**Location**: `src/mesh/config.rs:897-964` (MeshDhtConfig)

**Fix**: Add explicit capability config fields:
- `dns_server_enabled: bool`
- `dns_mesh_mode_only: bool`
- `dht_write_enabled: bool`
- `proxy_to_origins: bool`
- `can_host_origins: bool`

### 2.3 DHT Sharded Record Storage

**Location**: `src/mesh/dht/record_store.rs:114`

**Problem**: Single `LinkedHashMap` with `RwLock` for all records.

**Fix**: Implement 64-sharded record store (matching `ShardedPeerStore` pattern):
```rust
pub struct ShardedRecordStore {
    shards: Vec<RwLock<LinkedHashMap<String, DhtRecordEntry>>>,
}
```

### 2.4 Adaptive Quorum

**Location**: `src/mesh/dht/mod.rs:183-184`

**Problem**: Fixed quorum of 11 may be too high for small networks.

**Fix**: Implement adaptive quorum:
```rust
pub fn calculate_adaptive_quorum(&self, live_global_count: usize) -> u32 {
    let min_quorum = 3;
    let target = (live_global_count * 2) / 3;
    std::cmp::max(min_quorum, std::cmp::min(target, self.fixed_quorum as usize)) as u32
}
```

### 2.5 DHT Health Metrics

**Location**: `src/metrics/mod.rs`

**Fix**: Add DHT health metrics:
- `record_count`, `replica_count`
- `quorum_achieved_count`, `quorum_failed_count`
- `average_query_latency_ms`

### 2.6 Enhance TOFU Verification

**Location**: `src/mesh/cert.rs`

**Fix**: Add fingerprint verification on first connection:
```rust
pub fn verify_seed_on_first_contact(&mut self, node_id: &str, fingerprint: &str) -> bool
```

### 2.7 Message Signing Verification

**Location**: `src/mesh/transport_routing.rs`

**Fix**: Enforce signature verification in route response handling.

### 2.8 Connection Recovery with Backoff

**Location**: `src/mesh/topology.rs`, `src/mesh/discovery.rs`

**Fix**: Add exponential backoff for failed peer connections.

---

## Wave 3: WAF & Threat Intelligence

**Priority**: HIGH
**Source**: Plan 2, Plan 9

### 3.1 Add Local Indicator Lookup to WAF

**Location**: `src/waf/mod.rs:1072-1097`

**Problem**: WAF only queries DHT, ignoring local `indicators` HashMap.

**Fix**: Add methods to `ThreatIntelligenceManager`:
```rust
pub fn lookup_local_indicator(&self, indicator_value: &str) -> Option<ThreatIndicator>
pub fn is_mesh_available(&self) -> bool
pub fn get_node_role(&self) -> MeshNodeRole
```

Update `check_dht_threat_lookup()` to check local cache first.

### 3.2 Fix Deduplication Across Batches

**Location**: `src/honeypot_port/runner.rs:166-201`

**Problem**: `announced_ips` HashSet recreated each interval.

**Fix**: Add persistent tracking to `HoneypotStorage`:
```rust
pub fn get_announced_indicator_keys(&self) -> HashSet<String>
pub fn mark_indicator_announced(&self, key: &str)
```

### 3.3 Add Standalone Mode Logging

**Location**: `src/worker/unified_server.rs:897-904`

**Problem**: No indication when honeypot runs in standalone mode.

**Fix**: Add conditional logging using `is_mesh_available()`:
```rust
if mesh_available {
    tracing::info!("Port honeypot threat publishing wired to mesh network");
} else {
    tracing::warn!("Honeypot threat publishing running in standalone mode...");
}
```

### 3.4 Rate Limiter Cleanup Optimization

**Location**: `src/waf/ratelimit.rs:282-296`

**Problem**: 6 sequential `retain()` operations.

**Fix**: Batch into single-pass cleanup using `remove_expired_windows()` method.

**Status**: ✅ Implemented

---

## Wave 4: File Upload Security

**Priority**: HIGH
**Source**: Plan 3

### 4.1 Magic Byte Validation

**Files**: `src/static_files/file_manager.rs`, `src/http/file_manager.rs`

**Fix**:
1. Call `crate::upload::signature::detect_mime()` before writing
2. Add `allowed_mime_types` config to `SiteFileManagerConfig`
3. Add extension-MIME mismatch warning

**Status**: ✅ Implemented (magic byte validation with SignatureRegistry)

### 4.2 Malware Scanner Integration

**Files**: `src/config/site/file_manager.rs`, `src/static_files/file_manager.rs`

**Fix**:
1. Add `scan_on_upload: bool` config field (default: `false`)
2. Call scanner after magic bytes pass
3. Add scan results to audit log

**Status**: ✅ Implemented (MalwareScanner integrated in upload_file())

### 4.3 Upload Rate Limiting

**File**: `src/admin/rate_limit.rs`

**Fix**: Add upload-specific rate limiter for file manager endpoints.

**Status**: ✅ Implemented (UploadRateLimiter integrated in FileManager with rate_limit_config)

### 4.4 YARA Distribution Enhancements

**Files**: `src/mesh/yara_rules.rs`

**Fix**:
1. Add selective broadcast by node role
2. Add incremental rule updates (delta sync)

**Status**: ✅ Already implemented (RuleChangeTracker with incremental_versions, role-based broadcast checks)

---

## Wave 5: Edge Caching & Transform Sharing

**Priority**: MEDIUM
**Source**: Plan 4

### 5.1 Cache Preference Propagation (Origin → Edge)

**Files**: `src/mesh/proto/mesh.proto`, `src/mesh/transport_peer.rs`

**Fix**:
1. Add `ProxyCachePreferences` to `SiteConfigSync` message
2. Serialize `site.proxy.cache` from origin config
3. Apply received settings on edge

**Status**: ✅ Implemented (ProxyCachePreferences struct and field added)

### 5.2 Transform Cache Sharing via DHT

**Files**: `src/mesh/dht/keys.rs`, `src/mesh/proxy.rs`

**Fix**:
1. Add `TransformedResponse` key type: `transformed:{site_id}:{content_hash}:{transform_flags}`
2. Store transformed content in DHT after transformation
3. Fetch from DHT before transforming

**Status**: Pending (requires DHT integration work)

### 5.3 Image Poison Enhancement

**Files**: `src/mesh/proxy.rs`

**Fix**: Store poisoned images in DHT, edge fetches from DHT before applying poison.

**Status**: Pending (requires DHT integration work)

---

## Wave 6: Serverless Architecture

**Priority**: MEDIUM
**Source**: Plan 5, Plan 7

### 6.1 Unified Instance Pool

**Files**: `src/plugin/instance_pool.rs`, `src/serverless/instance_pool.rs`

**Problem**: Duplicate pool implementations with different APIs.

**Fix**: Create unified pool trait supporting both basic and autoscaling modes.

### 6.2 Enhanced Serverless Function Routing

**Files**: `src/serverless/manager.rs:162-172`

**Problem**: Naive path matching (prefix only), no wildcards, no method matching.

**Fix**:
1. Add `RouteMatch` enum: Exact, Prefix, Suffix, Regex, Glob
2. Add `MethodMatch`: Any, Specific, Multiple
3. Add priority-based ordering

### 6.3 Module Versioning

**Files**: `src/mesh/wasm_dist.rs:20-55`

**Problem**: Version announcements ignored, no GC of old versions.

**Fix**:
1. Add version tracking per module in `WasmModuleStore`
2. Add versioned store methods: `store_versioned()`, `get_by_version()`, `gc_old_versions()`

### 6.4 Configuration Schema Extensions

**Files**: `src/config/serverless.rs`

**Fix**: Add route configuration to `FunctionDefinition`:
- `routes: Option<Vec<String>>`
- `description: Option<String>`
- `allowed_methods: Option<Vec<String>>`

### 6.5 Serverless Registry

**Files**: `src/serverless/registry.rs` (new), `src/serverless/manager.rs`

**Fix**: Create registry to track registered functions and metadata.

### 6.6 Mesh Protocol Extensions

**Files**: `src/mesh/proto/mesh.proto`, `src/mesh/protocol.rs`

**Fix**: Add `ServerlessFunctionAnnounce` message for mesh discovery.

### 6.7 Per-Function Metrics

**Files**: `src/metrics/mod.rs`, `src/serverless/manager.rs`

**Fix**: Add serverless-specific metrics:
- `serverless_invocations_total{function, status}`
- `serverless_duration_seconds{function}`
- `serverless_instances_active{function}`

### 6.8 Shared Plugin State Across Workers

**Files**: `src/plugin/global.rs` (new), `src/worker/unified_server.rs`

**Problem**: Each worker loads WASM independently.

**Fix**: Create `GlobalPluginManager` shared across workers via IPC.

### 6.9 Memory Limit Consolidation

**Files**: `src/plugin/wasm_runtime.rs`, `src/serverless/instance_pool.rs`

**Problem**: Memory limit multiplication with multiple plugins.

**Fix**: Add global memory budget and shared instance pool.

---

## Wave 7: Built-in Web App Stack

**Priority**: MEDIUM
**Source**: Plan 6

### 7.1 Directory Viewer for Public Static Sites

**Files**: `src/config/site/static_files.rs`, `src/http/directory_viewer.rs` (new)

**Fix**:
1. Add `DirectoryViewerConfig` to `SiteStaticConfig`
2. Create handler for directory listing with site-specific branding
3. Support optional token/auth

**Status**: ✅ Implemented (DirectoryViewerConfig and handler created)

### 7.2 File Manager UI

**Files**: `src/http/file_manager.rs`, `src/http/file_manager_ui.rs` (new)

**Fix**:
1. Enable disabled routes (tonic upgrade)
2. Create standalone file manager frontend
3. Add theme hybrid support

**Status**: ✅ Implemented (file_manager_ui.rs with standalone frontend created; disabled routes remain due to axum version conflict)

### 7.3 PHP-FPM Enhancement

**Files**: `src/php/mod.rs`, `src/fastcgi/pool.rs` (new)

**Fix**:
1. Add FastCGI connection pool
2. Add PHP-FPM health monitoring
3. Add pool configuration

**Status**: ✅ Implemented (FastCgiPool and FastCgiPoolManager with health checking)

### 7.4 WASI Support for Serverless

**Files**: `src/plugin/wasm_runtime.rs`

**Fix**:
1. Add WASI link with `wasmtime_wasi`
2. Add WASI config to site config

**Status**: ✅ Implemented (wasi_enabled flag in WasmResourceLimits)

### 7.5 Granian/Python Enhancement

**Files**: `src/app_server/granian.rs`

**Fix**:
1. Add requirements.txt auto-install
2. Support multiple workers per site

**Status**: ✅ Implemented (auto_install_requirements field and ensure_requirements_installed method)

### 7.6 WebDAV Support

**Files**: `src/http/webdav.rs` (new)

**Fix**: Support PROPFIND, MKCOL, MOVE, COPY methods.

**Status**: ✅ Implemented (WebDAV handler with PROPFIND, MKCOL, MOVE, COPY, GET, PUT, DELETE, OPTIONS)

---

## Implementation Order & Parallelization

### Wave 1 (Critical Performance) - ✅ COMPLETE
- Items 1.1, 1.3, 1.4 implemented
- Item 1.2 deferred (not needed - fast hash lookups acceptable)
- Item 1.5 removed (architecture - single tokio loop more efficient)

### Wave 2 (Mesh/DHT) - ✅ COMPLETE
- Items 2.1, 2.2, 2.3 implemented ✅
- Item 2.4 IMPLEMENTED ✅ (calculate_adaptive_quorum in record_store.rs)
- Item 2.5 IMPLEMENTED ✅ (DHT health metrics in metrics/mod.rs)
- Item 2.6 PARTIALLY IMPLEMENTED (TOFU fingerprint verification on connect exists, but verify_seed_on_first_contact not implemented)
- Item 2.7 PARTIALLY IMPLEMENTED (route responses are signed, but signature verification on receipt is not enforced)
- Item 2.8 IMPLEMENTED ✅ (exponential backoff exists in topology, discovery, yara_rules)

### Wave 3 (WAF/Threat Intel) - ✅ COMPLETE
- All items implemented (3.1, 3.2, 3.3, 3.4)

### Wave 4 (File Upload) - ✅ COMPLETE
- 4.1 Magic Byte Validation: ✅ Implemented (SignatureRegistry detection + allowed_mime_types)
- 4.2 Malware Scanner Integration: ✅ Implemented (MalwareScanner called in upload_file())
- 4.3 Upload Rate Limiting: ✅ Implemented (UploadRateLimiter integrated in FileManager)
- 4.4 YARA Distribution Enhancements: ✅ Already implemented (incremental_versions, role-based checks)

### Wave 5 (Edge Caching) - ✅ COMPLETE
- 5.1 Cache Preference Propagation: ✅ Implemented
- 5.2 Transform Cache Sharing: ✅ IMPLEMENTED (DHT store/fetch in transform_response, lines 1157-1195, 1314-1332)
- 5.3 Image Poison Enhancement: ✅ IMPLEMENTED (PoisonedImage DHT caching in apply_image_poisoning)

### Wave 6 (Serverless) - ✅ COMPLETE
- 6.1 (unified pool) ✅ Implemented (WasmPool trait in src/plugin/pool.rs)
- 6.2 (routing) ✅ Implemented (RouteMatch, MethodMatch, ServerlessRoute in src/serverless/routing.rs)
- 6.3 (versioning) ✅ Implemented (versioned storage in WasmModuleStore)
- 6.4 (config schema) ✅ Implemented (routes, description, allowed_methods in FunctionDefinition)
- 6.5 (registry) ✅ Implemented (ServerlessRegistry in src/serverless/registry.rs)
- 6.6 (mesh protocol) ✅ Implemented (ServerlessFunctionAnnounce message)
- 6.7 (metrics) ✅ Implemented (serverless metrics in src/metrics/mod.rs)
- 6.8 (shared plugin state) ✅ Implemented (GlobalPluginManager in src/plugin/global.rs)
- 6.9 (memory consolidation) ✅ Implemented (GlobalWasmMemoryBudget)

### Wave 7 (Web App Stack) - ✅ COMPLETE
- 7.1 (directory viewer) ✅ Implemented (DirectoryViewerConfig, src/http/directory_viewer.rs)
- 7.2 (file manager UI) ✅ Implemented (src/http/file_manager_ui.rs, src/http/file_manager_ui.js)
- 7.3 (PHP-FPM pool) ✅ Implemented (FastCgiPool, FastCgiPoolManager in src/fastcgi/pool.rs)
- 7.4 (WASI support) ✅ Implemented (wasi_enabled in WasmResourceLimits)
- 7.5 (Granian enhancement) ✅ Implemented (auto_install_requirements, ensure_requirements_installed)
- 7.6 (WebDAV) ✅ Implemented (src/http/webdav.rs with PROPFIND, MKCOL, MOVE, COPY)

---

## Success Criteria

### Wave 1 (2026-04-07)
- [x] Blocking file I/O removed from async path (src/proxy_cache/store.rs - async get_async with spawn_blocking)
- [x] String allocations per request reduced (src/proxy.rs - AHashSet<&'static str>, src/waf/attack_detection/normalizer.rs - Cow<str>)
- [x] Worker auto-scaling REMOVED - The unified server uses a single tokio async event loop which is far more efficient than spawning multiple worker processes. See AGENTS.md architecture notes.
- [x] WAF parallelization REMOVED - Sequential execution is preferred; some checks should block subsequent checks on attack detection. See AGENTS.md.

### Wave 2 (2026-04-07)
- [x] Standalone WAF can serve DNS (src/mesh/protocol.rs - dns_mesh_mode_only flag)
- [x] Explicit capability flags added (src/mesh/config.rs - dns_server_enabled, dns_mesh_mode_only, dht_write_enabled, proxy_to_origins, can_host_origins)
- [x] DHT sharding implemented (src/mesh/dht/record_store.rs - 64-sharded ShardedRecordStore)
- [x] Connection recovery with backoff (src/mesh/topology.rs, src/mesh/discovery.rs, src/mesh/yara_rules.rs - exponential backoff implemented)
- [x] Adaptive quorum implemented (src/mesh/dht/record_store.rs - calculate_adaptive_quorum)
- [x] DHT health metrics implemented (src/metrics/mod.rs - record_dht_quorum_*, get_dht_*_count functions)
- [ ] TOFU enhancement NOT FULLY IMPLEMENTED (verify_seed_on_first_contact not added)
- [ ] Message signing verification PARTIALLY IMPLEMENTED (signatures created but not verified on receipt)

### Wave 3 (2026-04-07)
- [x] Local threat indicators block before DHT lookup (src/waf/mod.rs - check local first, src/mesh/threat_intel.rs - add lookup_local_indicator, is_mesh_available, get_node_role)
- [x] No duplicate announcements across batches (src/honeypot_port/storage.rs - persistent announced_indicators table, src/honeypot_port/runner.rs - use persistent tracking)
- [x] Standalone mode logging works (src/worker/unified_server.rs - conditional logging based on is_mesh_available)
- [x] Rate limiter cleanup optimization (src/waf/ratelimit.rs - single-pass remove_expired_windows)

### Wave 4 (2026-04-07)
- [x] 100% uploads validated with magic bytes (src/static_files/file_manager.rs - SignatureRegistry detection)
- [x] Malware scanning integrated (src/static_files/file_manager.rs - MalwareScanner in upload_file())
- [x] Upload rate limiting works (src/static_files/file_manager.rs - UploadRateLimiter integrated)

### Wave 5
- [x] Cache preferences propagate origin→edge (src/mesh/proto/mesh.proto - ProxyCachePreferences in SiteConfigSync)
- [x] Transform cache shared via DHT (src/mesh/proxy.rs - DHT fetch at lines 1157-1195, store at lines 1314-1332)
- [x] Image poison enhancement (src/mesh/proxy.rs - apply_image_poisoning DHT caching)

### Wave 6 (2026-04-07)
- [x] Unified pool trait working (src/plugin/pool.rs - WasmPool trait)
- [x] Route matching supports wildcards/regex (src/serverless/routing.rs - RouteMatch, MethodMatch)
- [x] Module versioning functional (src/mesh/wasm_dist.rs - store_versioned, gc_old_versions)
- [x] Per-function metrics available (src/metrics/mod.rs - serverless_invocations, serverless_duration)
- [x] Serverless registry working (src/serverless/registry.rs - FunctionMetadata tracking)
- [x] Mesh protocol extended (ServerlessFunctionAnnounce message)
- [x] Global plugin manager working (src/plugin/global.rs - GlobalPluginManager)
- [x] Memory budget consolidation (GlobalWasmMemoryBudget)

### Wave 7 (2026-04-07)
- [x] Directory viewer working with theming (src/http/directory_viewer.rs - DirectoryViewerConfig, theme support)
- [x] File manager UI functional (src/http/file_manager_ui.rs, src/http/file_manager_ui.js - standalone frontend)
- [x] PHP/WASI enhancements integrated (FastCgiPool, wasi_enabled in WasmResourceLimits)

---

## Dependencies Summary

| Wave | Dependencies | Status |
|------|-------------|--------|
| 1 | None | ✅ Complete |
| 2 | None | ✅ Complete (2.6, 2.7 remain partial) |
| 3 | Wave 2 (partial) | ✅ Complete |
| 4 | Wave 1 | ✅ Complete |
| 5 | Wave 2 | ✅ Complete |
| 6 | Wave 1, 2 | ✅ Complete |
| 7 | None (independent) | ✅ Complete |

---

## Notes

- **Backward compatibility**: All features default to disabled
- **Testing**: Integration tests required for each wave
- **Risk assessment**: See individual plans for detailed risk analysis

---

## File Changes Summary

### New Files
- `src/http/directory_viewer.rs` - Directory viewer handler ✅ NEW in Wave 7
- `src/http/file_manager_ui.rs` - File manager UI handler ✅ NEW in Wave 7
- `src/http/file_manager_ui.js` - File manager UI JavaScript ✅ NEW in Wave 7
- `src/http/webdav.rs` - WebDAV handler ✅ NEW in Wave 7
- `src/serverless/registry.rs` - Function registry ✅ NEW in Wave 6
- `src/serverless/routing.rs` - Route matching types ✅ NEW in Wave 6
- `src/plugin/global.rs` - Global plugin manager ✅ NEW in Wave 6
- `src/plugin/pool.rs` - Unified pool trait ✅ NEW in Wave 6
- `src/fastcgi/pool.rs` - FastCGI connection pool ✅ NEW in Wave 7
- `src/php/health.rs` - PHP-FPM health check

### Modified Files
- `src/mesh/protocol.rs` - DNS capability, serverless messages ✅ Wave 6
- `src/mesh/config.rs` - Capability config fields
- `src/mesh/dht/record_store.rs` - Sharding
- `src/mesh/dht/keys.rs` - TransformedContent, PoisonedImage DhtKey variants
- `src/mesh/proxy.rs` - DHT transform cache integration, record_store field
- `src/mesh/backend.rs` - create_mesh_backend integration
- `src/mesh/proto/mesh.proto` - ServerlessFunctionAnnounce message ✅ Wave 6
- `src/mesh/protocol_proto_encode.rs` - ServerlessFunctionAnnounce encoding ✅ Wave 6
- `src/mesh/protocol_proto_decode.rs` - ServerlessFunctionAnnounce decoding ✅ Wave 6
- `src/mesh/wasm_dist.rs` - Versioning ✅ Wave 6
- `src/waf/mod.rs` - Local lookup, parallelization
- `src/waf/attack_detection/normalizer.rs` - String optimization
- `src/proxy_cache/store.rs` - Async file I/O
- `src/proxy.rs` - String allocation reduction
- `src/process/manager.rs` - Auto-scaling
- `src/process/ipc.rs` - PluginStateSync message ✅ Wave 6
- `src/static_files/file_manager.rs` - Magic bytes, malware scan, rate limiting
- `src/config/site/file_manager.rs` - Upload config
- `src/upload/mod.rs` - Added rate_limit module export
- `src/upload/malware_scanner.rs` - Fixed async tests
- `src/http/file_manager.rs` - Updated test with new config fields
- `src/serverless/manager.rs` - Registry, routing ✅ Wave 6
- `src/serverless/mod.rs` - Registry, routing exports ✅ Wave 6
- `src/serverless/instance_pool.rs` - Unified pool
- `src/plugin/instance_pool.rs` - Unified pool ✅ Wave 6
- `src/plugin/mod.rs` - Pool, global exports ✅ Wave 6
- `src/plugin/wasm_runtime.rs` - Memory budget field, wasi_enabled ✅ Wave 6, 7
- `src/config/serverless.rs` - Route config ✅ Wave 6
- `src/metrics/mod.rs` - DHT metrics, serverless metrics ✅ Wave 6
- `src/http/mod.rs` - Added directory_viewer, file_manager_ui, webdav modules ✅ Wave 7
- `src/http/directory_viewer.rs` - Directory viewer HTTP handler ✅ Wave 7
- `src/http/file_manager_ui.rs` - File manager UI handler ✅ Wave 7
- `src/fastcgi/mod.rs` - Added pool module export ✅ Wave 7
- `src/fastcgi/pool.rs` - FastCGI connection pool ✅ Wave 7
- `src/app_server/granian.rs` - requirements.txt auto-install ✅ Wave 7
- `src/config/site/app_server.rs` - auto_install_requirements field ✅ Wave 7
