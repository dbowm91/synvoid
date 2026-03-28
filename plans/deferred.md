# Deferred Items

Items deferred from Wave 2 execution. These remain active work items for future waves.

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

### 3.6 Recursive Resolver Bugs
**Source**: `plan_dns3.md`

| Task | File | Bug |
|------|------|-----|
| 2.1 | `recursive_cache.rs:229` | Negative cache returns `None` on hit (triggers re-query) |
| 2.2 | `recursive.rs:151` | UDP buffer hardcoded to 512 bytes (EDNS0 clients need 4096+) |
| 2.3 | `recursive.rs:475` | Upstream failure returns empty vec instead of SERVFAIL |
| 2.4 | `resolver.rs:663` | RFC 5011 shutdown channel immediately dropped |

### 3.7 DHT Fixes — remaining
**Sources**: `plan_dht.md`, `plan_dht2.md`, `plan_dht3.md`
- **PoW not persisted** (`table.rs:539`): Add `pow_nonce` and `public_key` to `PersistedContact`, verify on restore
- **XOR distance scoring granularity** (`geo_distance.rs:117`): Use bit-prefix (leading zero bits) instead of first byte only

### 3.8 DNSSEC Validation Inconsistency
**Sources**: `plan_dns.md`, `plan_dns2.md`
- Forwarder mode (`HickoryResolver`) does NOT perform DNSSEC validation
- Either: add validation to forwarder, or document limitation clearly
- Propagate AD bit from upstream response to `is_dnssec_validated` flag

### 3.9 DNS Cache Security
**Source**: `plan_dns3.md`
- `cache.rs:155`: Require minimum 2 agreeing fingerprints before accepting cached response
- `trust_anchor.rs:319`: Wrap DELETE + INSERT in SQLite transaction

---

## Phase 5: Performance & Scalability

### 5.2 Rate Limiter Cleanup Optimization
**Sources**: `plan3.md`, `plan_security_scalability2.md`, `plan2.md` §3.2
- Move cleanup to per-shard lazy check (time-based, skip if cleaned recently)
- Eliminate global O(n) retain across all shards
- Consider combining 6 sequential retain passes into single pass
- Benchmark current cleanup duration with realistic data first

### 5.3 Rate Limiter LRU Eviction Optimization
**Source**: `plan2.md` §3.5
- Use partial sort (top-k) instead of full sort for eviction
- Consider per-shard eviction instead of global

### 5.4 Rate Limiter Memory Footprint
**Source**: `plan_security_scalability.md`
- Reduce `max_ip_entries` from 1,000,000 to 100,000
- Consolidate 6 `RingBuffer<Instant>` into single time-bucketed structure
- Target: <4KB per IP entry

### 5.5 Remove Blocking I/O — remaining
- `worker/response_builder.rs`: `std::fs::read()` in async context
- `waf/probe_tracker.rs`: Persistence read

### 5.9 Reduce Per-Request Allocations
**Source**: `plan2.md` §3.4
- Cache base headers filter set (`src/proxy.rs:77-99`)
- Reuse HashMap for HTTP/TLS requests (`src/tls/server.rs:213,256`)
- Cache normalized inputs across detector checks

### 5.10 DNS Performance
**Source**: `plan_dns3.md`
- Cache RRSIG signatures per (name, type) pair with TTL-matched eviction
- Move rate limiter cleanup to timer task instead of inline per-request
- Fix sharded cache allocation on hit (store `Arc<Vec<u8>>` not `Vec<u8>`)
- Add secondary index for ANY queries (O(1) name lookup)

### 5.11 Per-Worker Metrics
**Source**: `plan_security_scalability1.md` P1-5
- Add `WorkerMetrics` struct with per-worker Prometheus labels

### 5.12 Graceful Degradation for Global Rate Limiter
**Source**: `plan_security_scalability1.md` P1-6
- Add circuit breaker pattern to `GlobalRateLimiter`
- Fallback to per-IP limiting if global fails

---

## Phase 6: Code Quality & Readability

### 6.2 DNS Deduplication (~80 LOC)
**Source**: `plan_readability.md`, `plan_readability3.md`
- Extract `build_dnskey_rdata()` helper (4 instances)
- Extract `build_type_bitmap()` helper (NSEC + NSEC3)
- Extract `ensure_trailing_dot()` helper (9 instances in resolver.rs)
- Extract generic `lookup_records()` helper (5 similar methods)
- Consolidate duplicate `TokenBucket` implementations

### 6.3 Config Deduplication — remaining
- Consolidate 7 `default_true()` functions (needs investigation — some return `Option<bool>`, not `bool`)
- Remove duplicate `parse_size_string` from `site.rs` (only 1 definition found — verify)
- Consolidate `TrustAnchorConfig` (defined in 2 places → 1)

### 6.4 HTTP Response Builder Consolidation
**Source**: `plan_readability3.md`, `plan.md` §3.2
- Create `ResponseBuilder` in `src/http/response_builder.rs`
- Consolidate `status_reason_phrase()` mapping
- Consolidate 8+ identical static 500 response constructions

### 6.5 Module Splits
**Source**: `plan_readability2.md`, `plan2.md` §6.4
- `dns/dnssec.rs` (2,152 lines) — Split into signing, validation, keys, algorithms, nsec
- `config/site.rs` (1,831 lines) — Split into upstream, security, proxy, validation
- `mesh/transport.rs` (1,889 lines) — Document architecture of extension files

### 6.7 Error Unification
**Source**: `plan.md`, `plan_readability2.md`
- Adopt `WafError` across the codebase or remove dead `error.rs`
- Replace `Result<_, String>` and `Box<dyn Error>` (16 call sites) with `WafResult`

### 6.8 Split Large Functions
**Source**: `plan.md` §4.1
- `src/proxy.rs` — `handle_request` (>500 lines)
- `src/tls/server.rs` — TLS handshake handler (~400 lines)
- `src/waf/mod.rs` — `check_request_full` (~300 lines)
- `src/mesh/transport.rs` — connection handler (~300 lines)
- `src/dns/dnssec.rs` — signing function (~250 lines)

### 6.10 Log Silent Send Failures — metrics
- Add metrics for dropped events (logging done, metrics deferred)

---

## Phase 7: TLS

### 7.2 TLS Cert Distribution (Origin → Edge)
**Source**: `plan_tls.md`
- Create `src/mesh/cert_dist.rs` (~250 lines)
- 3 new mesh message variants in `src/mesh/protocol.rs`
- AES-256-GCM encryption of private keys via HKDF-derived per-site keys
- `load_cert_from_pem()` in `src/tls/cert_resolver.rs`
- Depends on 7.1 (ACME) — now complete

---

## Phase 11: Admin Panel

### 11.1 Fix Settings Page (Critical) — Frontend
- Replace all hardcoded values in `admin-ui/src/pages/settings.rs` with API-driven data
- On mount: fetch `GET /api/config/main` + `GET /api/config/schema`
- Save button: `PUT /api/config/main`
- Add Export/Import/Reload toolbar

### 11.2 Worker Restart — IPC Messages
- Add `RestartWorkerRequest`/`RestartWorkerResponse` IPC messages (SIGTERM-based restart works for now)

### 11.4 Add New Frontend Pages
12 new pages: honeypot, rule_feed, tls_settings, feeds, upstreams rewrite, dns, dns_zones, dns_config, dns_dnssec, tunnel, tunnel_vpn, tunnel_config

### 11.6 Settings Tab Expansion
- 7 new tabs: Blocked Paths, Auth Defaults, TLS, IP Feeds, Log Exporters, Traffic Shaping, Rate Limits

### 11.7 Sidebar Reorganization
- Reorganize into Overview, Security, Management, Configuration groups

### 11.8 Dynamic Schema Rendering
- `DynamicField` component, serde-based schema generation, `POST /api/config/validate`

### 11.9 Config Versioning & Audit
- Compressed JSON snapshots, validation framework, audit logging

### 11.11 API Service Additions
- ~15 new methods to `admin-ui/src/api.rs`

---

## Summary

| Phase | Completed | Deferred | Notes |
|-------|-----------|----------|-------|
| 2 | 12 items (2.1-2.12 all) | 0 items | All Phase 2 security fixes complete |
| 3 | 6 items (3.1-3.5, 3.7 partial) | 4 items (3.6, 3.7, 3.8, 3.9) | DNS/DHT remaining |
| 5 | 4 items (5.1, 5.5 partial, 5.6, 5.8) | 8 items | Rate limiter, blocking I/O, allocations deferred |
| 6 | 3 items (6.1, 6.3 partial, 6.6, 6.9, 6.10 partial) | 5 items | Splits/errors/split-functions deferred |
| 7 | 2 items (7.1, 7.3) | 1 item (7.2) | Cert distribution deferred |
| 11 | 4 items (11.2, 11.3, 11.5, 11.10) | 7 items | All frontend items deferred |
