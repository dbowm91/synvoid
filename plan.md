# MaluWAF Implementation Plan

> Consolidated from all pending plan files
> Generated: 2026-04-02
> Status: ~93 unique pending items across Security, Performance, Correctness, Features, Testing, Cleanup, and Documentation

---

## Executive Summary

This plan consolidates all remaining implementation work identified across multiple review cycles. The original plan (waves 0-6) was completed; this plan covers newly identified items.

| Category | Items | Est. Effort | Parallel Agents |
|----------|-------|------------|----------------|
| Security | 18 | 3-5 days | 2 |
| Performance | 13 | 3-5 days | 2 |
| Correctness | 15 | 2-3 days | 1 |
| Features | 28 | 8-12 days | 3 |
| Testing | 8 | 2-3 days | 1 |
| Cleanup | 8 | 1-2 days | 1 |
| Documentation | 3 | 0.5 days | 1 |

**Total: ~93 unique items, ~20-30 days sequential, ~8-15 days with parallelization**

---

## Wave 1: Critical Security (Parallel Agents A-B)

### 1A: HTTPS and Proxy Security

#### 1A.1 HTTPS Proxy Request Body Forwarding (CRITICAL)

**Problem**: The HTTPS server (`src/tls/server.rs`) never forwards request bodies to upstreams. Two paths both fail:
- Cache path: `body: None` always passed
- Non-cache path: `send_request_with_timeout_and_headers()` uses empty body

**Files**: `src/tls/server.rs`, `src/http_client/mod.rs`

**Fix**: Pass `body_bytes.clone()` to `handle_request_with_cache()` and use `send_request_with_body_and_timeout()` for non-cache path.

**Verification**: POST 10KB body → upstream receives 10KB; POST 5MB body → upstream receives 5MB.

---

#### 1A.2 Upload Validation in TLS Path (CRITICAL)

**Problem**: Upload validation (malware scanning, content-type checking) in `src/http/server.rs` not replicated in TLS server path. HTTPS uploads bypass malware scanning.

**Files**: `src/tls/server.rs:580`

**Fix**: Insert upload validation block before cache logic at line 580, mirroring `http/server.rs:1391-1460`.

---

#### 1A.3 X-Forwarded-For Chain Depth Limit and Validation (HIGH)

**Problem**: XFF header appended without validating length or content. Spoofed chains possible.

**Files**: `src/proxy.rs:1375-1385`

**Fix**: 
1. Cap chain at 10 entries (`MAX_XFF_CHAIN_LENGTH = 10`)
2. Validate each entry is a valid IP
3. Truncate existing chain if exceeds limit

---

#### 1A.4 SSRF Octal/Decimal IP Detection (HIGH)

**Problem**: `parse_ipv4_flexible()` doesn't detect octal (`0177.0.0.1`) or decimal (`2130706433`) representations.

**Files**: `src/waf/attack_detection/ssrf.rs:48-69, 240-253`

**Fix**: 
1. Parse octal components (base 8) when component starts with `0` and has multiple digits
2. Parse decimal IPs (single numeric string → 32-bit integer conversion)

---

#### 1A.5 Streaming Response Body Size Enforcement (MEDIUM)

**Problem**: Chunked responses downloaded fully before size check fires. Malicious upstream can exhaust memory.

**Files**: `src/proxy.rs:1174-1260`, `src/mesh/transport.rs:1911-2084`

**Fix**: Wrap response stream in `Take`-like reader tracking bytes read, abort at limit.

---

#### 1A.6 HTTP Request Body Silent Truncation (MEDIUM)

**Problem**: Bodies truncated to 1MB for WAF inspection, truncated body forwarded to upstream.

**Files**: `src/http/server.rs:536-554`

**Fix**: Separate WAF-inspected body from forwarded body. Pass full body upstream.

---

#### 1A.7 CORS Wildcard Enforcement (MEDIUM)

**Problem**: `Access-Control-Allow-Origin: *` behavior differs between debug/release builds.

**Files**: `src/http/headers.rs:66-89`

**Fix**: Add explicit `allow_wildcard_cors: bool` config (default `false`). Log warning in all profiles.

---

### 1B: Mesh Security

#### 1B.1 PoW Bypass via Direct Role Equality (CRITICAL)

**Problem**: Five locations use `== MeshNodeRole::Edge` instead of `.is_edge()`. Composite role `GLOBAL_EDGE` (0b011) bypasses PoW.

**Files**: 
- `src/mesh/discovery.rs:319`
- `src/mesh/transport.rs:899, 1170`
- `src/mesh/config_mesh.rs:6`
- `src/worker/unified_server.rs:595`

**Fix**: Replace all `== MeshNodeRole::Edge` with `.is_edge()`.

---

#### 1B.2 Unconfigured Global Node Key Bypass (MEDIUM)

**Problem**: `validate_peer_role()` returns `Ok(())` when local node has no `global_node_key`. Any peer can impersonate global.

**Files**: `src/mesh/peer_auth.rs:17-32`

**Fix**: When peer claims global role and local has no `global_node_key`, reject with error.

---

#### 1B.3 Discovery/Transport Auth Path Alignment (MEDIUM)

**Problem**: Discovery logs warning but proceeds without public key; QUIC transport rejects. Inconsistent.

**Files**: `src/mesh/discovery.rs:314-317`

**Fix**: Make discovery reject connections without public key (matching QUIC transport).

---

## Wave 2: Performance (Parallel Agents C-D)

### 2A: Proxy and Transport Performance

#### 2A.1 Route Query Early Return (HIGH)

**Problem**: Polls `collected_providers` every 100ms even when responses arrive immediately. Up to 100ms unnecessary latency.

**Files**: `src/mesh/transport.rs:1602-1620`

**Fix**: Replace polling loop with `tokio::select!` using `tokio::sync::watch` channel notification.

---

#### 2A.2 Short-Circuit Input Normalization (MEDIUM)

**Problem**: `normalize_all()` allocates normalized strings for ALL inputs before any detector runs.

**Files**: `src/waf/attack_detection/mod.rs:177-183`

**Fix**: Use lazy normalization with `OnceCell` wrappers. Each detector normalizes only what it needs.

---

#### 2A.3 Cache LocationMatcher Per Site (MEDIUM)

**Problem**: `LocationMatcher` recompiled on every request for sites with regex location directives.

**Files**: `src/router.rs:299-301`

**Fix**: Cache compiled `LocationMatcher` instances per site, invalidate on config reload.

---

#### 2A.4 Reuse Health Check HTTP Client (LOW)

**Problem**: New `reqwest::Client` created per health check cycle.

**Files**: `src/upstream/health.rs:175-179`

**Fix**: Store client as field on `HealthChecker`, reuse across cycles.

---

#### 2A.5 Pre-Create ProxyServer Instances (MEDIUM)

**Problem**: `ProxyServer` lazily created on first HTTPS request, causing write-lock contention.

**Files**: `src/tls/server.rs:588-636`

**Fix**: Pre-create instances during worker startup.

---

### 2B: Mesh Lock Refactoring

#### 2B.1 Remove Await-Held Locks in Mesh Proxy (HIGH)

**Problem**: 14 `#[allow(clippy::await_holding_lock)]` annotations. Transport/topo locks held across I/O.

**Files**: `src/mesh/proxy.rs`, `src/mesh/transports/manager.rs`

**Fix**: Clone Arc before await, release lock, then perform I/O.

---

#### 2B.2 Route Query Throttling and Pre-Warming (MEDIUM)

**Problem**: Route queries fan out to 3 peers × 3 hops = 27 messages per query.

**Files**: `src/mesh/transport_routing.rs:82-240`, `src/mesh/proxy.rs:560`

**Fix**: Add per-upstream rate limit on queries, pre-warm on config change.

---

#### 2B.3 Default Unified Server Worker Count (MEDIUM)

**Problem**: `unified_server_workers` defaults to 1.

**Files**: `src/process/manager.rs:236-256`

**Fix**: Default to `num_cpus::get().min(4)` or at minimum 2.

---

#### 2B.4 Route Fast-Fail on Connection Error (MEDIUM)

**Problem**: Stale cached routes served for up to 60s after provider failure.

**Files**: `src/mesh/proxy.rs:294-333, 580+`

**Fix**: Evict cache entry immediately on connection error, retry with fresh query.

---

## Wave 3: Correctness (Parallel Agent E)

### 3A: Whitelist and DHT Fixes

#### 3A.1 Whitelist Semantics Fix (HIGH)

**Problem**: Image protection whitelist matches against `upstream_id` instead of `request_path`.

**Files**: `src/mesh/proxy.rs:1095`

**Fix**: Change `is_match(upstream_id)` to `is_match(request_path)`.

---

#### 3A.2 Remove Dead `build_dnssec_response()` (LOW)

**Problem**: Function returns `None`-like path but is never called.

**Files**: `src/dns/server/dnssec_impl.rs:562-579`

**Fix**: Delete the function.

---

#### 3A.3 Fix Merkle Tree Proof for Binary Tree (HIGH)

**Problem**: 16-ary Merkle tree implementation only captures 2 siblings per level, not 15.

**Files**: `src/mesh/dht/merkle.rs:332-379, 64-117`

**Fix**: Switch to binary Merkle tree (simpler, standard, smaller proofs).

---

#### 3A.4 Write Quorum: Count Confirmed Stores (MEDIUM)

**Problem**: Quorum counts transport sends, not confirmed stores.

**Files**: `src/mesh/dht/record_store_sync.rs`, `src/mesh/protocol.rs`

**Fix**: Add `DhtRecordStoreAck` message, count confirmed stores toward quorum.

---

#### 3A.5 Wire Reputation System into Record Store (MEDIUM)

**Problem**: Record reputation hardcoded to 75/100, bypasses actual `reputation.rs`.

**Files**: `src/mesh/dht/record_store_message.rs:4-13`, `record_store_sync.rs:199,574`

**Fix**: Replace hardcoded values with actual reputation lookups.

---

#### 3A.6 Reconcile Signable Content Format (LOW)

**Problem**: Two different signable formats: CRUD (`key:source:timestamp:json`) vs signed.rs (CSV-like).

**Files**: `src/mesh/dht/record_store_crud.rs:32-37`, `signed.rs`

**Fix**: Use canonical JSON format for both.

---

## Wave 4: Honeypot and Threat Intel (Parallel Agent F)

### 4A: Critical Wiring

#### 4A.1 Wire Port Honeypot to Mesh Threat Publishing (CRITICAL)

**Problem**: `start_mesh_threat_publishing()` exists but is never called.

**Files**: `src/worker/unified_server.rs`

**Fix**: Add wiring after mesh/threat_intel initialization.

---

#### 4A.2 Fix Threat Type Mapping (HIGH)

**Problem**: All `IndicatorType` map to `ThreatType::SuspiciousActivity`.

**Files**: `src/honeypot_port/runner.rs:164-169`

**Fix**: Map `SourceIp` → `ThreatType::IpBlock`.

---

#### 4A.3 Use Actual Site Scope (MEDIUM)

**Problem**: Hardcoded `"global"` as site scope.

**Files**: `src/honeypot_port/runner.rs:193`, `config.rs`

**Fix**: Add `site_scope` to `PortHoneypotConfig`.

---

#### 4A.4 Remove Dead `self.threat_intel` in WafCore (LOW)

**Problem**: `self.threat_intel` always `None`, `set_threat_intel()` never called.

**Files**: `src/waf/mod.rs:519-540`

**Fix**: Remove dead code path, keep global singleton.

---

### 4B: Structural Improvements

#### 4B.1 Deduplicate Background Task Logic (MEDIUM)

**Problem**: `start_background_tasks()` re-implements message construction that exists in `broadcast_pending_threats()`.

**Files**: `src/mesh/threat_intel.rs:1115-1208`

**Fix**: Replace inline code with call to `broadcast_pending_threats()`.

---

#### 4B.2 Implement Active Threat Sync (MEDIUM)

**Problem**: Sync protocol exists but background task never sends sync requests.

**Files**: `src/mesh/threat_intel.rs` (integrated with 4B.1)

**Fix**: Send `ThreatSyncRequest` to peers when sync interval elapses.

---

#### 4B.3 Respect `hub_only_mode` (LOW)

**Problem**: `hub_only_mode` checked in reputation but not in push queue logic.

**Files**: `src/mesh/threat_intel.rs:482-489, 492`

**Fix**: Add check in `queue_for_push()` and `publish_indicator_to_dht()`.

---

#### 4B.4 Remove Redundant DHT Re-Publish (MEDIUM)

**Problem**: Every accepted incoming threat re-published to DHT. Redundant with anti-entropy.

**Files**: `src/mesh/threat_intel.rs:682`

**Fix**: Remove re-publish line.

---

#### 4B.5 Add Honeypot Record Deduplication (LOW)

**Problem**: Same IP can generate duplicate announcements per cycle.

**Files**: `src/honeypot_port/runner.rs:160-199`

**Fix**: Track announced IPs per cycle with `HashSet`.

---

#### 4B.6 Add Warning Logs for Silent Drops (LOW)

**Problem**: Three methods silently return when transport unavailable.

**Files**: `src/mesh/threat_intel.rs:498-499, 983-994, 1190-1201`

**Fix**: Add `tracing::debug` logs.

---

#### 4B.7 Remove Dead `standalone_mode` Config (LOW)

**Problem**: `standalone_mode` field never read.

**Files**: `src/config/defaults.rs:583`

**Fix**: Delete the field.

---

## Wave 5: YARA Mesh Distribution (Parallel Agent G)

### 5A: Critical Bug Fix

#### 5A.1 Fix `drop(msg)` in Periodic Sync (CRITICAL)

**Problem**: Periodic sync task creates `YaraRuleSyncRequest` but drops it instead of sending.

**Files**: `src/worker/unified_server.rs:679-682`

**Fix**: Send via mesh_sender channel.

---

#### 5A.2 Add `get_mesh_sender()` Accessor (CRITICAL)

**Files**: `src/mesh/yara_rules.rs`

**Fix**: Add accessor method returning clone of sender from read lock.

---

### 5B: Security Hardening

#### 5B.1 Sign `YaraRuleSyncResponse` (MEDIUM)

**Problem**: Sync response sent with `signature: Vec::new()`.

**Files**: `src/mesh/yara_rules.rs:575-583`

**Fix**: Sign response content same way `broadcast_approved_rules` does.

---

#### 5B.2 Verify Signatures on Sync Response (MEDIUM)

**Problem**: Handler ignores `signature` field entirely.

**Files**: `src/mesh/yara_rules.rs:588-610`

**Fix**: Verify signature before calling `handle_incoming_rules`.

---

#### 5B.3 Add `require_signature` Config (MEDIUM)

**Problem**: Unsigned rules accepted silently.

**Files**: `src/mesh/config.rs`, `src/mesh/yara_rules.rs:536-541`

**Fix**: Add config field defaulting to `true`.

---

#### 5B.4 Fix `allow_edge_submissions` Default (LOW)

**Problem**: `#[serde(default)]` gives `false`, `impl Default` gives `true`.

**Files**: `src/mesh/config.rs:135-146`

**Fix**: Align defaults.

---

### 5C: Admin API

#### 5C.1 Create YARA Admin Handler (MEDIUM)

**Problem**: No admin API for YARA submission management.

**Files**: `src/admin/handlers/yara_rules.rs` (new)

**Fix**: Create handler with 7 endpoints: status, submissions, approve, reject, broadcast, sync.

---

### 5D: Broadcast Reliability

#### 5D.1 Add `broadcast_to_all_peers` (MEDIUM)

**Problem**: YARA rule distribution needs guaranteed delivery.

**Files**: `src/mesh/transport.rs`

**Fix**: Add method that sends to ALL connected peers (not random sample).

---

#### 5D.2 Use Targeted Broadcast for YARA (MEDIUM)

**Problem**: Current fanout is probabilistic (50%).

**Files**: `src/mesh/yara_rules.rs:320-356`

**Fix**: Use `broadcast_to_all_peers` for YARA rules.

---

### 5E: Observability

#### 5E.1 Add YARA Metrics (LOW)

**Problem**: No metrics for YARA operations.

**Files**: `src/metrics/mod.rs`, `src/mesh/yara_rules.rs`

**Fix**: Add counters: broadcast, received, scan, match, submission, sync_failure, verify_fail.

---

## Wave 6: Backend Dispatch and WASM (Parallel Agent H)

### 6A: Backend Dispatch

#### 6A.1 CGI Dispatch (MEDIUM)

**Problem**: `BackendType::Cgi` defined but not dispatched.

**Files**: `src/http/server.rs`, `src/cgi/mod.rs` (new)

**Fix**: Create `CgiClient`, add dispatch block.

---

#### 6A.2 Fix Granian `forward_request` (MEDIUM)

**Problem**: Builds full request then ignores it, uses hardcoded GET instead.

**Files**: `src/app_server/granian.rs:776-825`

**Fix**: Actually use the built request with correct method/headers/body.

---

#### 6A.3 Non-Mesh Transform Fallback (MEDIUM)

**Problem**: Transforms silently skipped when mesh unavailable.

**Files**: `src/http/server.rs:1579`

**Fix**: Add else branch using local site config.

---

### 6B: WASM Instance Pooling

#### 6B.1 Wire WASM Instance Pool (MEDIUM)

**Problem**: Pool exists but never used.

**Files**: `src/plugin/instance_pool.rs`, `src/plugin/wasm_runtime.rs`

**Fix**: Add pool to `WasmRuntime`, modify `filter_request()` to use pool.

---

### 6C: Config and TLS

#### 6C.1 Wire `prefer_post_quantum` to Crypto (MEDIUM)

**Problem**: Config field only used for log message.

**Files**: `src/tls/cert_resolver.rs:259`

**Fix**: Conditionally select provider based on config.

---

#### 6C.2 Fix ACME Challenge Cleanup (MEDIUM)

**Problem**: Token/domain key mismatch; no Drop guard for cleanup.

**Files**: `src/tls/acme.rs:278-280`

**Fix**: Track token→domain mapping, add Drop guard.

---

#### 6C.3 Config Schema Generation (MEDIUM)

**Problem**: 918-line hardcoded schema.

**Files**: `src/admin/handlers/config.rs:41-959`

**Fix**: Use `schemars` derive to generate schema.

---

## Wave 7: Cache and Image Poison (Parallel Agent I)

### 7A: DHT Distribution of Full Poison Config

#### 7A.1 Add SiteImagePoisonConfig DHT Key (MEDIUM)

**Files**: `src/mesh/dht/keys.rs`, `signed.rs`

**Fix**: Add new `DhtKey` variant and `SignedRecordType`.

---

#### 7A.2 Origin Publishes Poison Config (MEDIUM)

**Files**: `src/mesh/transports/manager.rs`

**Fix**: Add `publish_site_poison_config()` method.

---

#### 7A.3 Edge Retrieves Poison Config (MEDIUM)

**Files**: `src/mesh/transports/manager.rs`

**Fix**: Add cache fields and `get_site_poison_config()` method.

---

### 7B: Transform Cache and ProxyCache

#### 7B.1 Transform Cache Key Granularity (MEDIUM)

**Problem**: Key doesn't include poison parameters.

**Files**: `src/mesh/proxy.rs:1016-1022`

**Fix**: Include level, intensity, seed in key.

---

#### 7B.2 Wire ProxyCache in Mesh Mode (MEDIUM)

**Problem**: Mesh proxy has unused `_cache_config` parameter.

**Files**: `src/mesh/proxy.rs`

**Fix**: Initialize and use `ProxyCache` in mesh proxy.

---

## Wave 8: Web App Stack (Parallel Agent J)

### 8A: Themed Directory Listing

#### 8A.1 Add Theme to SiteStaticConfig (MEDIUM)

**Files**: `src/config/site.rs:1272`

**Fix**: Add `theme: Option<SiteThemeConfig>`.

---

#### 8A.2 Create DirectoryListingTemplate (MEDIUM)

**Files**: `src/theme/template.rs`

**Fix**: Create template using `ThemeRenderer` CSS variables.

---

#### 8A.3 Wire Theme Through Static Handler (MEDIUM)

**Files**: `src/static_files/mod.rs`, `directory.rs`

**Fix**: Accept `&ThemeConfig`, use template for HTML rendering.

---

### 8B: File Manager (Future Work)

#### 8B.1 File Manager API

**Files**: `src/static_files/file_manager.rs` (new)

**Status**: Planned but deferred.

---

### 8C: Performance

#### 8C.1 HTTP Range Request Support (MEDIUM)

**Problem**: `_range_header` parameter unused.

**Files**: `src/static_files/mod.rs:351-570`

**Fix**: Implement proper range parsing and 206 responses.

---

#### 8C.2 Zero-Copy / sendfile Streaming (MEDIUM)

**Problem**: `zero_copy_path` set but not used.

**Files**: `src/http/server.rs:1135-1147`

**Fix**: Stream file using `tokio::fs::File` + `ReaderStream`.

---

## Wave 9: Testing (Parallel Agent K)

### 9A: Integration Tests

#### 9A.1 WAF Body Inspection Test
#### 9A.2 DNSSEC Signed Zone Test
#### 9A.3 Upload Scanning Test
#### 9A.4 Mesh Threat Propagation Test

---

### 9B: Benchmarks

#### 9B.1 WASM Pool vs Fresh Instance Benchmark
#### 9B.2 Broadcast Latency at Scale

---

### 9C: Unit Tests

#### 9C.1 Atomic Counter Safety
#### 9C.2 Signature Verification Edge Cases
#### 9C.3 XFF Validation
#### 9C.4 Whitelist Semantics

---

## Wave 10: Cleanup and Documentation

### 10A: Dead Code Cleanup

#### 10A.1 Reduce `#[allow(dead_code)]` Annotations

**Current**: ~76 across ~48 files
**Target**: <60

---

### 10B: Documentation

#### 10B.1 WASM-ABI Documentation

**Files**: `docs/WASM-ABI.md` (new)

---

## Parallelization Strategy

```
Agent A (Critical Security)     ── 1A.1, 1A.2, 1A.3, 1A.4, 1A.5, 1A.6, 1A.7
Agent B (Mesh Security)        ── 1B.1, 1B.2, 1B.3
Agent C (Performance A)      ── 2A.1, 2A.2, 2A.3, 2A.4, 2A.5
Agent D (Performance B)        ── 2B.1, 2B.2, 2B.3, 2B.4
Agent E (Correctness)         ── 3A.1, 3A.2, 3A.3, 3A.4, 3A.5, 3A.6
Agent F (Honeypot)           ── 4A.1, 4A.2, 4A.3, 4A.4, 4B.1, 4B.2, 4B.3, 4B.4, 4B.5, 4B.6, 4B.7
Agent G (YARA)               ── 5A.1, 5A.2, 5B.1, 5B.2, 5B.3, 5B.4, 5C.1, 5D.1, 5D.2, 5E.1
Agent H (Backend/WASM)       ── 6A.1, 6A.2, 6A.3, 6B.1, 6C.1, 6C.2, 6C.3
Agent I (Cache/Poison)       ── 7A.1, 7A.2, 7A.3, 7B.1, 7B.2
Agent J (Web Stack)          ── 8A.1, 8A.2, 8A.3, 8C.1, 8C.2
Agent K (Testing)            ── 9A.1, 9A.2, 9A.3, 9A.4, 9B.1, 9B.2, 9C.1, 9C.2, 9C.3, 9C.4

Agent L (Cleanup/Docs)       ── 10A.1, 10B.1

Total: 11 agents. Agents A-B (critical security) MUST run first.
```

---

## Dependencies

```
CRITICAL PATH:
  Agent A (1A.1 HTTPS body) must precede 1A.6 (body truncation)
  2B.1 (mesh lock refactor) must precede 2B.2 (route throttling)
  
AGENT DEPENDENCIES:
  Agent H (6A.1 CGI) can run anytime (no deps)
  Agent I (7A-C cache) depends on mesh transport basics
  Agent J (8A-C web) depends on theme system existing
  Agent K (9A-C testing) runs LAST after all code changes
```

---

## Verification Checklist

After each agent:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test --lib --no-run
cargo test --test integration_test
```

After all waves:
```bash
cargo test
rg "NOT IMPLEMENTED" src/ --include '*.rs' | grep -v "test"
rg '#\[allow\(dead_code\)\]' src/ --count | wc -l
```

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| HTTPS body forwarding breaks proxy | Test both cache and non-cache paths |
| Lock refactor introduces race | Run integration tests after |
| WASM pool breaks existing plugins | Fresh path as fallback |
| CGI dispatch security risk | Admin-configured only, add timeout |
| Config schema breaks frontend | Keep same response format |
