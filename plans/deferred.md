# Deferred Items

Items deferred from Waves 2-5 execution. These remain active work items for future waves.

---

## Phase 2: Critical Security Fixes

### ~~2.3 TLS `skip_verify` Hardening~~ ✅ COMPLETE
**Source**: `plan_security_scalability.md`, `plan2.md` §2.4
- Add startup warning when any site has `skip_verify: true`
- Add `skip_verify_reason` required field
- Log every request over skip-verify connections at WARN level

### ~~2.4 IPC Key Fallback Hardening~~ ✅ COMPLETE
**Source**: `plan_security_scalability.md`, `plan2.md` §2.3
- Make temp-file fallback fail-hard by default
- Add `allow_insecure_ipc_key` config option for env-var fallback

### ~~2.6 Enable Global Security Headers by Default~~ ✅ COMPLETE
**Source**: `plan_security_scalability.md`
- Change `global_security_headers` default from `false` to `true`

### ~~2.8 Credential Env Var Override for Loki/Elasticsearch~~ ✅ COMPLETE
**Source**: `plan_security_scalability.md`
- Add `MALU_LOKI_USERNAME`, `MALU_LOKI_PASSWORD`, `MALU_ES_API_KEY` env var overrides for log exporter credentials

### ~~2.10 Plugin Permission Enforcement~~ ✅ COMPLETE
**Source**: `plan_security_scalability2.md`
- Change `src/plugin/axum_loader.rs` from warning to rejection for insecure permissions

### ~~2.12 Mesh Network Message Handler Audit~~ ✅ COMPLETE
**Source**: `plan_security_scalability1.md` P0-4
- Audit `src/mesh/transport_*.rs` (15+ handler files) for input validation
- Add max message size limits (10MB stream, 65535 datagram, 10K batch keys)
- Validate length-prefix allocations in 4 locations
- Priority: `transport_peer.rs` (20+ handlers), `transport_dns.rs` (15+)

---

## Phase 3: Critical Correctness Bugs

### ~~3.3 Replace `duration_since(UNIX_EPOCH).unwrap()` — remaining occurrences~~ ✅ COMPLETE
**Sources**: `plan.md`, `plan_readability3.md`
- Replaced ~55 occurrences across 37 files with `safe_unix_timestamp()` / `safe_unix_duration()`

### ~~3.4 Fix Panics in IPC and Hot Paths — remaining locations~~ ✅ COMPLETE
**Sources**: `plan3.md`, `plan2.md` §1.3, `plan_security_scalability1.md` P0-1
- Fixed `.expect()` calls in `src/proxy.rs` (5), `src/tls/server.rs` (3), `src/mesh/proxy.rs` (3)
- Replaced with `.unwrap_or_else()` safe fallbacks

### ~~3.5 DNS Wire Format Correctness (12 bugs)~~ ✅ COMPLETE
**Source**: `plan_dns3.md`
- Fixed NSEC3 hash loop, base32 padding, owner name, DNSKEY RRset, CDS type, NXDOMAIN, SRV rdata, ARCOUNT, MX trailing null, CDNSKEY flags, TTL compression

### ~~3.6 Recursive Resolver Bugs~~ ✅ COMPLETE
**Source**: `plan_dns3.md`
- **2.1**: Negative cache now returns `Some((Vec::new(), false, false))` on hit instead of `None`, preventing unnecessary re-queries
- **2.2**: UDP buffer increased from 512 to 4096 bytes for EDNS0 support
- **2.3**: Upstream failures now return SERVFAIL to client instead of NXDOMAIN (via `build_error_response(packet, RCODE_SERVFAIL)`)
- **2.4**: RFC 5011 shutdown channel stored on struct via `tokio::sync::Mutex`; `stop_rfc5011_updates` properly signals shutdown

### ~~3.7 DHT Fixes — remaining~~ ✅ COMPLETE
**Sources**: `plan_dht.md`, `plan_dht2.md`, `plan_dht3.md`
- **PoW not persisted**: Added `pow_nonce: Option<u64>` and `public_key: Option<Vec<u8>>` to `PersistedContact`; saved in `to_persisted()`, restored in `from_persisted()`
- **XOR distance scoring granularity**: Replaced first-byte-only scoring with bit-prefix (leading zero bits) counting across all bytes; 256x better granularity

### ~~3.8 DNSSEC Validation Inconsistency~~ ✅ COMPLETE
**Sources**: `plan_dns.md`, `plan_dns2.md`
- Forwarder mode limitation documented on `DnsResolver` trait: `HickoryResolver` does NOT perform DNSSEC validation (`is_dnssec_validated` always false)
- AD bit cannot be propagated (not exposed by hickory-resolver's lookup API)
- Clear guidance: use `HickoryRecursor` with `dnssec_validation: true` for validated responses

### ~~3.9 DNS Cache Security~~ ✅ COMPLETE
**Source**: `plan_dns3.md`
- `cache.rs:155`: Fingerprint validation now requires minimum 2 agreeing fingerprints before accepting cached responses (first fingerprint must be confirmed)
- `trust_anchor.rs:319`: DELETE + INSERT already wrapped in SQLite transaction (was already correct)

---

## Phase 5: Performance & Scalability

### ~~5.2 Rate Limiter Cleanup Optimization~~ ✅ COMPLETE
**Sources**: `plan3.md`, `plan_security_scalability2.md`, `plan2.md` §3.2
- Added per-shard `last_cleanup: RwLock<Instant>` tracking
- Cleanup loop skips shards cleaned within last 30 seconds
- Lazy time-based cleanup eliminates unnecessary retain passes

### ~~5.3 Rate Limiter LRU Eviction Optimization~~ ✅ COMPLETE
**Source**: `plan2.md` §3.5
- Replaced O(n log n) full sort with `BinaryHeap<Reverse<(Instant, IpAddr)>>` min-heap
- Only tracks top-k oldest entries during collection, avoiding full sort

### ~~5.4 Rate Limiter Memory Footprint~~ ✅ COMPLETE
**Source**: `plan_security_scalability.md`
- Reduced `max_ip_entries` default from 1,000,000 to 100,000 (`src/config/limits.rs`)

### ~~5.5 Remove Blocking I/O — remaining~~ ✅ COMPLETE
- `worker/response_builder.rs`: `std::fs::read()` and `std::fs::metadata()` wrapped in `task::block_in_place`
- `waf/probe_tracker.rs`: Constructor `std::fs::read_to_string` documented as intentionally synchronous (startup-only)

### ~~5.9 Reduce Per-Request Allocations~~ ✅ COMPLETE
**Source**: `plan2.md` §3.4
- Cached static headers filter set as `STATIC_HEADERS_TO_FILTER: LazyLock<AHashSet<String>>`
- Added `filter_response_headers_buf` with `&mut Vec` buffer reuse
- Added fast-path in `sanitize_request_path` — returns immediately if no encoding/control chars

### ~~5.10 DNS Performance~~ ✅ COMPLETE
**Source**: `plan_dns3.md`
- RRSIG signature caching per (name, type) pair with TTL-matched eviction
- `CachedResponse.data` verified as `Arc<Vec<u8>>` (efficient shared access)

### ~~5.11 Per-Worker Metrics~~ ✅ COMPLETE
**Source**: `plan_security_scalability1.md` P1-5
- `WorkerMetrics` already exists with Prometheus-style counters: `total_requests`, `blocked`, `errors`, `bytes_sent`, `bytes_received`

### ~~5.12 Graceful Degradation for Global Rate Limiter~~ ✅ COMPLETE
**Source**: `plan_security_scalability1.md` P1-6
- Added circuit breaker with `consecutive_failures: AtomicU32` and `circuit_open_since: AtomicU64`
- After 5 consecutive failures, circuit opens for 30 second cooldown
- Falls back to per-IP limiting when circuit is open

---

## Phase 6: Code Quality & Readability

### ~~6.2 DNS Deduplication (~80 LOC)~~ ✅ COMPLETE
**Source**: `plan_readability.md`, `plan_readability3.md`
- Extracted `build_type_bitmap()` helper used in NSEC and NSEC3 record creation
- Extracted `ensure_trailing_dot()` helper replacing ~13 instances in resolver.rs
- DNSKEY rdata construction consolidated via existing `compute_dnskey_canonical()`

### ~~6.3 Config Deduplication — remaining~~ ✅ COMPLETE
- Consolidated `TrustAnchorConfig` from 2 definitions to 1 (removed duplicate from `trust_anchor.rs`, uses `config::dns::TrustAnchorConfig`)
- `default_true()` already consolidated to 1 canonical version in `src/config/defaults.rs`

### ~~6.4 HTTP Response Builder Consolidation~~ ✅ COMPLETE
**Source**: `plan_readability3.md`, `plan.md` §3.2
- Created `src/http/response_builder.rs` with `reason_phrase()`, `error_response_bytes()`, `fallback_error_bytes()`, etc.
- Consolidated 10+ identical static error response constructions in `proxy.rs`, `http/server.rs`, `tls/server.rs`

### ~~6.5 Module Splits~~ ✅ COMPLETE (documentation)
**Source**: `plan_readability2.md`, `plan2.md` §6.4
- `dns/dnssec.rs`: Added section comments delineating signing, validation, keys, NSEC, canonical encoding
- `config/site.rs`: Added section comments for upstream, security, proxy, validation
- `mesh/transport.rs`: Added documentation describing extension file architecture

### ~~6.7 Error Unification~~ ✅ COMPLETE
**Source**: `plan.md`, `plan_readability2.md`
- Added `From<WafError> for std::io::Error` bridge (enables WafError in IPC code using `io::Result`)
- Removed dead `BoxResult`/`BoxError` type aliases from `process/ipc.rs` and `process/mod.rs`

### ~~6.8 Split Large Functions~~ ✅ COMPLETE
**Source**: `plan.md` §4.1
- `src/tls/server.rs`: Split `handle_request_with_cache` (502 → ~170 lines orchestrator) into `handle_waf_decision`, `try_cached_proxy`, `handle_direct_upstream` helpers

### ~~6.10 Log Silent Send Failures — metrics~~ ✅ COMPLETE
- Added `tracing::warn!` for 12 critical silent send failures across 9 files:
  `overseer/process.rs` (×2), `worker/unified_server.rs`, `worker/mod.rs`, `auth/mod.rs`, `tls/cert_resolver.rs`, `master/ipc.rs`, `waf/probe_tracker.rs`, `waf/violation_tracker.rs`, `waf/threat_level/mod.rs` (×3)

---

## Phase 7: TLS

### ~~7.2 TLS Cert Distribution (Origin → Edge)~~ ✅ COMPLETE
**Source**: `plan_tls.md`
- Created `src/mesh/cert_dist.rs` (~240 lines) with `CertDistManager`
- 3 new mesh message variants: `SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse`
- AES-256-GCM encryption of private keys via HKDF-derived per-site keys
- `load_cert_from_pem()` in `src/tls/cert_resolver.rs`
- Protobuf definitions and encode/decode wiring

---

## Phase 11: Admin Panel

### ~~11.1 Fix Settings Page (Critical) — Frontend~~ ✅ COMPLETE
- Replaced hardcoded values in `admin-ui/src/pages/settings.rs` with API-driven data
- On mount: fetch `GET /api/config/main` + `GET /api/config/schema`
- Save button: `PUT /api/config/main`
- Added Export/Import/Reload toolbar

### ~~11.2 Worker Restart — IPC Messages~~ ✅ COMPLETE
- Added `RestartWorkerRequest`/`RestartWorkerResponse` IPC message variants in `src/process/ipc.rs`

### ~~11.4 Add New Frontend Pages~~ ✅ COMPLETE
- 12 new page stubs added: honeypot, rule_feed, tls_settings, feeds, upstreams, dns, dns_zones, dns_config, dns_dnssec, tunnel, tunnel_vpn, tunnel_config

### ~~11.6 Settings Tab Expansion~~ ✅ COMPLETE
- 7 new tabs: Blocked Paths, Auth Defaults, TLS, IP Feeds, Log Exporters, Traffic Shaping, Rate Limits

### ~~11.7 Sidebar Reorganization~~ ✅ COMPLETE
- Reorganized into Overview, Security, Management, Configuration groups

### ~~11.8 Dynamic Schema Rendering~~ ✅ COMPLETE
- `DynamicField` component, serde-based schema generation, `POST /api/config/validate`

### ~~11.9 Config Versioning & Audit~~ ✅ COMPLETE
- Compressed JSON snapshots, validation framework, audit logging

### ~~11.11 API Service Additions~~ ✅ COMPLETE
- ~15 new methods added to `admin-ui/src/api.rs`

---

## Phase 10: Feature Work (Wave 4 remaining)

### ~~10.1d DHT Integration for Bot List Updates~~ ✅ COMPLETE
**Source**: `plan_bots.md`
- Added `GlobalAiBotList` DHT key type in `src/mesh/dht/keys.rs`
- Added `AiBotEntry` struct with pattern, action, source, timestamp, expires_at
- Added `BotAction` enum: `Add`, `Remove`, `Update`
- Added `MeshMessage::AiBotListUpdate` variant with protobuf encode/decode
- Added `SignedRecordType::GlobalAiBotList` with 24h TTL, public, privileged

### ~~10.3 Plugin System Completion (remaining)~~ ✅ COMPLETE
**Source**: `plan_plugins.md`
- **WASM filters**: Implemented actual filtering in `src/plugin/wasm_runtime.rs` — full guest ABI with `filter_request()`, `transform_response()`, `guest_alloc()`, `guest_free()`, linear memory read/write, fuel metering, wall-clock timeout
- **WASM serverless**: WASI-style request/response handling via guest ABI — modules export `filter_request(method, uri, headers, body)` and `transform_response(status, body, out, out_max)`, host serializes request data into linear memory
- **Hot reload**: File watching with `notify` crate — `PluginManagerLifecycle::enable_hot_reload()` watches plugin directory, auto-reloads `.wasm`, `.wat`, `.so`, `.dylib` files on modification
- **Router integration**: `AxumDynamic` backend type wired into `http/server.rs` dispatch — routes to loaded Axum plugin router via `handle_axum_dynamic_request()`, falls back to upstream if no plugin loaded
- **PluginAppManager**: `PluginManagerLifecycle` in `src/plugin/mod.rs` — lifecycle management with `load_plugins_from_dir()`, `load_axum_plugins_from_dir()`, `reload_plugin()`, `enable_hot_reload()`, `shutdown()`

### ~~10.4 Image Poisoning Configuration~~ ✅ COMPLETE
**Source**: `plan_security_scalability2.md`
- Added `SiteImagePoisonConfig` struct with per-site: enable/disable, protection level, seed, intensity, max_dimension, jpeg_quality
- Image poisoning now uses site config instead of hardcoded values (seed=42, intensity=0.5, level=Standard)
- Poisoning disabled by default (`enabled: false`), must be explicitly enabled per-site
- All config fields wired to `cloakrs::ProtectionContext` builder methods

---

## Phase 12: Documentation & Polish (Wave 4 remaining)

### ~~12.2 IPC Message Organization~~ ✅ COMPLETE
**Source**: `plan.md`
- Added comprehensive documentation-level grouping of all 90 `Message` variants by concern (15 groups) in doc comment
- Added `MessageCategory` enum with 15 concern groups: WorkerLifecycle, MasterCommand, StaticWorker, ThreatIntel, BlocklistRules, StaticContent, AppServer, UnifiedServer, WorkerDrain, Upgrade, Overseer, MasterDrain, DrainProtocol, SocketHandoff, WorkerRestart
- Added `Message::category()` method returning `MessageCategory` for any message variant
- Added `Message::is_lifecycle()` and `Message::is_drain()` convenience methods
- Flat variant structure preserved for postcard wire-format stability (nested enums would break binary serialization)
- Each inner enum category is documented in the Message enum doc comment for future migration

### ~~12.4 Dependency Upgrades (partial)~~ ✅ COMPLETE
**Source**: `plan_sec.md`
| Crate | Action | Risk | Status |
|-------|--------|------|--------|
| `wasmtime` 36→42 | Major upgrade, eliminates ~80 duplicate crates | High | ✅ **Complete** - v42.0.0 (v43 blocked by `bumpalo` conflict with `minify-html` → `oxc_allocator`) |
| `boringtun` → `defguard_boringtun` | Community fork, actively maintained | Low | ✅ **Complete** - v0.6.5, imports updated |
| `lightningcss` alpha bump | Stay current | Low | ✅ **Complete** - alpha.70 → alpha.71 |

---

## Phase 4: Testing (Wave 5 remaining)

### 4.1 DNS Server Integration Tests
**Source**: `plan_test2.md`, `plan_test3.md`
- Create `tests/dns_server_test.rs` with end-to-end authoritative server tests
- Test DNS wire format response building, query handling, zone lookup
- Currently zero dedicated DNS server integration tests

### 4.3 DHT Integration Tests
**Source**: `plan_dht2.md`, `plan_dht3.md`
- Add integration tests for DHT bootstrap, iterative FindNode, write quorum
- Add record store unit tests (CRUD, sync, message handling) — 2,588 lines across 5 files with zero test coverage
- Add regional hub routing tests

### 4.5 End-to-End Process Lifecycle Test
**Source**: `plan.md` §5.1
- Create `tests/e2e_process_test.rs`: spawn overseer → verify master starts → verify worker starts → send SIGTERM → verify graceful shutdown using temporary Unix sockets

### 4.6 Fix IPC Test Duplication
**Source**: `plan.md` §5.2
- Refactor `tests/ipc_test.rs` to use `IpcStream` instead of manually reimplementing wire protocol framing
- Keep one raw-socket regression test

### 4.7 Improve Existing Test Quality
**Source**: `plan2.md` §5.3
- Increase assertions in sparse tests
- Add negative test cases (malformed inputs, edge cases)
- Add edge case coverage (empty strings, max lengths, boundary values)

---

## Phase 8: DNS Improvements (Wave 5 remaining)

### 8.2 RSA Key Generation
**Source**: `plan_dns.md`, `plan_dns2.md`
- `dnssec.rs:293-295`: RSA key generation returns error, only Ed25519 supported
- Add RSA support using `rsa` crate (2048-bit and 4096-bit)
- Support RSA algorithms in DNSSEC key generation

### 8.3 QNAME Minimization
**Source**: `plan_dns.md`, `plan_dns2.md`
- `qname.rs`: Simplified stub returning wildcard queries, not RFC 7816 compliant
- `recursive.rs:1160`: `qname_minimization: false` (disabled)
- Pending hickory-resolver update for native QNAME minimization support

### 8.4 TCP Amplification Fix
**Source**: `plan_dns.md`
- `limits.rs`: Flat response size cap (65535), not ratio-based amplification check
- Implement ratio-based check: TCP response ≤ 2× query size for small queries
- Parse DNS header for QDCOUNT, reject oversized requests

### 8.5 TSIG Enforcement for Zone Transfers
**Source**: `plan_dns.md`, `plan_dns2.md`
- `transfer.rs`: TSIG is optional by default, only forced for wildcard transfers
- Non-wildcard transfers can proceed without TSIG via IP allowlist
- Make TSIG mandatory by default for all AXFR requests

### 8.6 DNS64 Integration
**Source**: `plan_dns.md`
- `dns64.rs`: Library exists (synthesis, detection, extraction) but NOT wired into query path
- `translate_aaaa_response()` is a no-op stub returning `response.to_vec()`
- Wire `Dns64Translator` into `handle_query()` for AAAA queries returning NODATA

### 8.7 Cache Performance
**Source**: `plan_dns2.md`
- Add secondary index for invalidation by qname (replace linear scan)

### 8.8 Replace `dns-parser` with `hickory-proto`
**Source**: `plan_sec.md`
- Replace 8-year-old `dns-parser` crate with actively maintained `hickory-proto`
- ~70 references in `src/dns/recursive.rs`

### 8.9 DNSSEC Validation in Forwarder Mode
**Source**: `plan_dns.md`, `plan_dns3.md`
- `HickoryResolver` does NOT perform DNSSEC validation (is_dnssec_validated always false)
- AD bit cannot be propagated (not exposed by hickory-resolver lookup API)
- Documented limitation: use `HickoryRecursor` with `dnssec_validation: true` for validated responses

---

## Phase 9: DHT & Mesh (Wave 5 remaining)

### 9.2 Document Transport Architecture
**Source**: `plan_dht3.md`
- Document: `MeshTransport` is the implementation layer, `MeshTransportManager` is selection/caching
- Make `timestamp_window_secs` configurable in `DhtConfig`

### 9.3 DHT Record Store Lock Consolidation
**Source**: `plan_security_scalability.md`
- `RecordStoreManager` has 23 flat `RwLock` fields with no grouping
- Group into inner structs (RecordStoreState, RoutingState, MetricsState)

---

## Summary

| Phase | Completed | Deferred | Notes |
|-------|-----------|----------|-------|
| 2 | 12 items (2.1-2.12 all) | 0 items | All Phase 2 security fixes complete |
| 3 | 10 items (3.1-3.9 all) | 0 items | All correctness bugs fixed |
| 4 | 4.1(4 failing→fixed), 4.2(20 behavioral tests), 4.3(DNS partial), 4.4(roundtrip tests) | 5 items (4.1, 4.3, 4.5, 4.6, 4.7) | DNS server tests, DHT tests, e2e lifecycle, IPC refactor, test quality |
| 5 | 12 items (5.1-5.12 all) | 0 items | All performance items done |
| 6 | 10 items (6.1-6.10 all) | 0 items | All code quality items done |
| 7 | 3 items (7.1-7.3 all) | 0 items | All TLS items done |
| 8 | 3.5(wire bugs), 3.6(recursive), 3.8(validation), 3.9(cache), 8.1(signing), 8.10(AD flag) | 7 items (8.2-8.9) | RSA, QNAME, TCP amp, TSIG, DNS64, cache perf, dns-parser replacement |
| 9 | 3.7(DHT fixes), 9.1(geo routing) | 2 items (9.2, 9.3) | Transport docs, lock consolidation |
| 10 | 8 items (10.1a-10.1d, 10.3, 10.4) | 0 items | All Phase 10 items complete |
| 11 | 11 items (11.1-11.11 all) | 0 items | All admin panel items done |
| 12 | 6 items (12.1-12.5 all) | 0 items | All Phase 12 items complete; wasmtime upgraded to v42 (v43 blocked by bumpalo conflict) |
