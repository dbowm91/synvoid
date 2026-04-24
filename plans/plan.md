# MaluWAF Implementation Consolidated Plan

**Last updated**: 2026-04-24
**Status**: ⚠️  PARTIAL VERIFICATION COMPLETE - Security fixes and tiered cache applied
**Source**: Consolidation of 35 individual plan files (plan3.md through plan35.md, fix_c5.md)

---

## Verification Note (2026-04-24)

This plan was previously marked 100% complete but automated verification revealed discrepancies.
A subset of critical fixes have been re-applied and verified. Full verification of remaining items
would require additional agent sessions.

---

## Completed Waves

| Wave | Items | Status | Commit |
|------|-------|--------|--------|
| Wave 1 | W1-1 through W1-8 (8 items) | ✅ COMPLETE | 7e71d44, 060a781 |
| Wave 2 | W2-1 through W2-7 (7 items) | ✅ COMPLETE | 7e71d44 |
| W3-1 | ViolationTracker sharding | ✅ COMPLETE | 85dbf04 |
| W3-13 | WASM VecDeque pool | ✅ COMPLETE | 85dbf04 |
| Wave 3 | W3-2 through W3-16 (15 items) | ✅ COMPLETE | 5e82c83 |
| Wave 4 | W4-1 through W4-17 (17 items) | ✅ COMPLETE | 907f8b0 |
| Wave 5 | W5-1 through W5-6 (6 items) | ✅ COMPLETE | f758a65 |
| Wave 6 | W6-1 through W6-4 (4 items) | ✅ COMPLETE | 5e91d6f |
| Wave 7 | W7-1 through W7-9 (9 items) | ✅ COMPLETE | 2136f7d |
| Wave 8 | W8-1 through W8-6 (6 items) | ✅ COMPLETE | 2136f7d |
| Wave 9 | W9-1 through W9-7 (7 items) | ✅ COMPLETE | b37331a |
| Wave 10 | W10-1 through W10-6 (6 items) | ✅ COMPLETE | b37331a, 060a781 |
| Wave 11 | W11-1 through W11-7 (7 items) | ✅ COMPLETE | 9231ea4 |
| Wave 12 | W12-1 through W12-4 (4 items) | ✅ COMPLETE | 9231ea4 |
| Wave 13 | W13-1 through W13-5 (5 items) | ✅ COMPLETE | c7c8f60 |

**Most waves completed.**

---

## How to Use This Plan

This plan is organized into **Waves**. Within each wave, items can be parallelized across sub-agents. Each wave depends on the previous wave being complete.

**For sub-agents**: Each item contains enough context to implement independently. Read the "Problem", "Location", and "Fix" sections. Run `cargo check` and `cargo clippy --lib -- -D warnings` after completing each item.

**Verification after any change**:
```bash
cargo check
cargo clippy --lib -- -D warnings
cargo fmt
cargo test --test integration_test
```

---

## Previously Verified as Already Fixed

These items from original plans were verified as already resolved in the current codebase:

| Item | Original Plan | Status |
|------|--------------|--------|
| JSON→postcard migration compilation errors | fix_c5.md | Code compiles cleanly |
| DNS recursive_cache uses wrong `len()` | plan35.md | Code correctly uses `entry_count()` |
| ThreatIntel re_announce_local_indicators() | plan27.md M-15 | Function exists and is called |
| CRLF injection | plan18.md #11 | Already good |
| QUIC DoS RUSTSEC-2026-0037 | plan24.md | Already patched |
| Wasmtime RUSTSEC-2026-0096/0086 | plan24.md | Already patched |

---

## Items Removed as Inaccurate

| Item | Original Plan | Reason |
|------|--------------|--------|
| Dead `lowercased` field (H-4) | plan23.md | Field IS used via `as_lowercased()` called from `detector_common.rs:531,541,557` |
| Serverless proxy unreachable (H-13) | plan26.md | Function IS reachable via `upstream_id.starts_with("serverless:")` at `transport_peer.rs:2577` |
| LRU rate limiter dead code (M-8) | plan18.md | `lru_order` and `ip_requests` are actively used in cleanup/eviction |
| DNS redundant to_lowercase (M-10) | plan23.md | Code correctly reuses `qname_lower` at `query.rs:670,719` |

---

## Wave 1: Critical Security Fixes

These are independent and can be parallelized across sub-agents.

### W1-1: PoW Iteration Cap Blocks Edge Nodes

**Source**: plan19.md Phase 1
**Severity**: CRITICAL
**Files**: `src/mesh/dht/routing/node_id.rs`

**Problem**: `NODE_ID_POW_DIFFICULTY = 64` bits with `MAX_ITERATIONS = 10_000_000`. Probability of finding a valid nonce is ~5.4x10^-13. Edge nodes literally cannot connect to the mesh.

**Fix**: At line 10, change:
```rust
pub const NODE_ID_POW_DIFFICULTY: u32 = 16; // Was: 64
```

**Verification**: `cargo test --lib mesh::peer_auth::tests::test_edge_node_with_valid_pow_passes` (should pass in <1s)

---

### W1-2: Path Traversal in Custom Template Loading

**Source**: plan6.md Phase 1
**Severity**: CRITICAL
**Files**: `src/static_files/directory.rs`

**Problem**: `load_directory_template()` at lines 30-37 reads custom template paths directly via `fs::read_to_string(template_path)` with no path traversal validation. An attacker who can set the template path can read arbitrary files on the system.

**Fix**: Add path validation:
1. Canonicalize the template path and an allowed base directory
2. Verify the canonicalized path starts with the allowed directory prefix
3. Reject symlinks that escape the allowed directory
4. Add `X-Content-Type-Options: nosniff` header to template responses

**Verification**: Test with paths like `/etc/passwd`, `../etc/passwd`, symlink escapes, and valid paths.

---

### W1-3: Stored XSS in Directory Listing

**Source**: plan24.md C1
**Severity**: CRITICAL
**Files**: `src/static_files/directory.rs`, `src/theme/dir_listing.rs`

**Problem**: User-controlled filenames rendered in HTML without escaping. `entry.name` is interpolated directly into HTML via `format!()` at:
- `src/static_files/directory.rs:120-127`
- `src/theme/dir_listing.rs:509-520`

Note: `escape_html()` exists in the codebase (used in `src/waf/endpoints.rs`) but is not used in directory listing.

**Fix**: Apply `escape_html()` to `entry.name` (and any other user-controlled strings) before rendering in both locations.

**Verification**: Upload a file with `<script>alert(1)</script>` in the name, verify it appears escaped in directory listing HTML.

---

### W1-4: Blocking Call Deadlock in Honeypot

**Source**: plan25.md C1
**Severity**: CRITICAL
**Files**: `src/honeypot_port/responders/mod.rs`

**Problem**: `AiHoneypotResponder::respond()` at lines 159-160 calls `tokio::runtime::Handle::current().block_on()`. If called from within a tokio async context, this deadlocks.

**Fix**: Override `respond_async()` to call the AI responder directly without going through the sync `respond()` method. The async version should use `self.ai_responder.generate_response().await` directly.

**Verification**: Test that the honeypot responder works when called from an async context without hanging.

---

### W1-5: YARA Zero-Key Fallback

**Source**: plan25.md C3
**Severity**: CRITICAL (defensive)
**Files**: `src/mesh/yara_rules.rs`

**Problem**: At lines 771 and 934, public key conversion uses `.try_into().unwrap_or([0u8; 32])`. When bytes can't convert to 32-byte array, silently falls back to a zero key, creating a `MeshMessageSigner` with a useless key. This masks bugs rather than surfacing them.

**Fix**: Replace `unwrap_or([0u8; 32])` with proper error handling:
```rust
let pk_bytes: [u8; 32] = pk_bytes.clone().try_into()
    .map_err(|_| anyhow::anyhow!("Invalid public key length: expected 32 bytes, got {}", pk_bytes.len()))?;
```
Propagate the error so callers handle it explicitly.

**Verification**: Test with invalid key lengths (0, 31, 33, 64 bytes) — should return error, not zero key.

---

### W1-6: IPv4-Mapped IPv6 SSRF Bypass

**Source**: plan18.md #3
**Severity**: HIGH
**Files**: `src/waf/attack_detection/ssrf.rs`

**Problem**: `check_is_private_ip()` at lines 132-150 does NOT check for IPv4-mapped IPv6 format. Addresses like `::ffff:192.168.1.1` or `::ffff:127.0.0.1` bypass the SSRF detector because they fall into the `IpAddr::V6` branch and don't match any V6 private ranges.

**Additional bug**: The 172.16.0.0/12 check at line 137 uses `(octets[1] & 0xF0) == 16` which is incorrect. It should be `octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31`.

**Fix**:
1. In the `IpAddr::V6` branch, add: `if let Some(ipv4) = ip.to_ipv4_mapped() { return check_v4_private(&ipv4); }`
2. Fix the 172.16/12 range check to use correct octet comparison

**Verification**: Test with `::ffff:192.168.1.1`, `::ffff:10.0.0.1`, `::ffff:127.0.0.1`, `::ffff:172.20.0.1` — all should be detected as private.

---

### W1-7: RSA 1024 in DNSSEC Key Generation

**Source**: plan24.md C2
**Severity**: HIGH
**Files**: `src/dns/dnssec_key_mgmt.rs`

**Problem**: At line 240, `if !matches!(bits, 1024 | 2048 | 4096)` allows RSA 1024, which is below NIST minimum security (112 bits) and explicitly NOT RECOMMENDED by RFC 8624.

**Fix**: Auto-upgrade RSA 1024 to 2048 with a warning log:
```rust
let effective_bits = match bits {
    1024 => { tracing::warn!("RSA 1024 is insecure, auto-upgrading to 2048"); 2048 }
    2048 | 4096 => bits,
    _ => return Err(/* invalid */),
};
```

**Verification**: Generate a 1024-bit key, verify warning is logged and actual key is 2048-bit.

---

### W1-8: ThreatIntel Re-Announcement Bug

**Source**: plan28.md 1.1
**Severity**: HIGH
**Files**: `src/mesh/threat_intel.rs`

**Problem**: `re_announce_local_indicators()` at lines 1787-1790 filters by `local_origin` flag, meaning indicators received from other nodes (via DHT sync) are never re-announced. This causes indicators to expire from the DHT even though they should be propagated.

**Fix**: Remove the `local_origin` check so ALL non-expired indicators are re-announced:
```rust
// Change: filter to only non-expired (remove local_origin check)
if !entry.is_expired(now) {
    self.publish_indicator_to_dht(&entry.indicator).await;
}
```

**Verification**: Sync an indicator from another node, verify it gets re-announced.

---

## Wave 2: WASM Security & Capability Wiring

These items can be parallelized across sub-agents.

### W2-1: Wire verify_caller_permission()

**Source**: plan7.md S1.1-S1.5, plan26.md 3.1, plan10.md Issue #3
**Severity**: CRITICAL
**Files**: `src/serverless/manager.rs`

**Problem**: `verify_caller_permission()` at lines 190-282 is defined but never called. All serverless permission checks are bypassed. Any mesh peer can invoke any serverless function.

**Fix**:
1. Define `CallerContext` struct with `node_id`, `role`, `org_id`, `tier` fields
2. Update `handle_serverless_function()` signature to accept `CallerContext`
3. Call `verify_caller_permission()` at entry points (HTTP server at `src/http/server.rs:1854`, TLS server at `src/tls/server.rs:1077`, mesh at `src/mesh/transport_peer.rs:2953`)
4. Extract caller identity from mesh transport connection metadata
5. Add `public_function: bool` config flag to bypass permission check for public endpoints

**Verification**: Test that untrusted nodes are blocked from invoking protected functions.

---

### W2-2: WASM DHT Access Control

**Source**: plan7.md S1.6-S1.7
**Severity**: CRITICAL
**Files**: `src/plugin/wasm_runtime.rs`

**Problem**: `mesh_query_dht()` at lines 563-621 reads ANY DHT key directly from the global record store with no capability verification. Any WASM plugin can read sensitive data like `threat_indicator:*`, `yara_rule:*`, etc.

**Fix**:
1. Add per-plugin allowed DHT key prefixes in plugin config
2. In `mesh_query_dht()`, check the requested key against allowed prefixes before calling `get_record()`
3. Log and deny unauthorized access attempts

**Verification**: Test that a plugin without DNS capability cannot read `dns_zone:*` keys.

---

### W2-3: Implement WASM ResourceLimiter

**Source**: plan7.md S1.9
**Severity**: HIGH
**Files**: `src/plugin/wasm_runtime.rs`

**Problem**: wasmtime's `ResourceLimiter` trait is not implemented. The code at lines 820-838 does manual memory bounds checking, but WASM can bypass limits via `memory.grow`. Without the trait implementation, wasmtime's built-in enforcement doesn't apply.

**Fix**: Implement wasmtime's `ResourceLimiter` trait:
```rust
struct WasmResourceLimiter { max_memory: usize }
impl ResourceLimiter for WasmResourceLimiter {
    fn memory_growing(&mut self, current: usize, desired: usize, maximum: Option<usize>) -> Result<bool> {
        Ok(desired <= self.max_memory)
    }
}
```
Wire this into the wasmtime engine configuration.

**Verification**: Test that a WASM module cannot grow memory beyond the configured limit.

---

### W2-4: Capability Verifier NOT Wired

**Source**: plan12.md 1.1-1.3, plan27.md Phase 1
**Severity**: HIGH
**Files**: `src/mesh/backend.rs`, `src/mesh/dht/record_store.rs`

**Problem**: `CapabilityAccessVerifier` exists but `RecordStoreManager` is created with `capability_verifier: None` at `src/mesh/backend.rs:55-62`. The `set_capability_verifier()` method exists at `record_store.rs:359` but is never called. Capability-based write authorization is never enforced.

**Fix**:
1. Create `CapabilityAccessVerifier` instance in `src/mesh/backend.rs` where `RecordStoreManager` is created
2. Wrap in `RwLock` for interior mutability
3. Call `set_capability_verifier()` after construction
4. Ensure global nodes self-publish "waf" capability attestations on startup
5. Exempt ThreatIntel indicators from capability check in `record_store_crud.rs` (or add a "threat_intel" capability)
6. Add admin API endpoint `POST /api/mesh/attest-capability` for manual attestation

**Verification**: Test that non-global nodes cannot write `yara_rules_manifest:*` keys. Test that global nodes with valid attestation can.

---

### W2-5: DNS DHT Records Need Capability Protection

**Source**: plan8.md Issue #1
**Severity**: HIGH
**Files**: `src/mesh/dht/capability_access.rs`

**Problem**: DNS-related DHT keys (`dns_zone:*`, `dns_record:*`, `dns_domain_reg:*`) are not in the `key_requires_capability()` function at lines 34-42. Any node can write DNS records to the DHT.

**Fix**: Add DNS key mappings to `key_requires_capability()`:
```rust
key.starts_with("dns_zone:") => Some("dns"),
key.starts_with("dns_record:") => Some("dns"),
key.starts_with("dns_domain_reg:") => Some("dns"),
```
Add corresponding "dns" capability attestation for authorized nodes.

**Verification**: Unit tests for DNS capability mapping. Test that unauthorized nodes cannot write DNS records.

---

### W2-6: ThreatIntel Threat Type Parsing Bug

**Source**: plan28.md 1.2
**Severity**: HIGH
**Files**: `src/mesh/threat_intel.rs`, `src/mesh/protocol_types.rs`

**Problem**: Threat type parsing has bugs at 3 locations:
- `src/mesh/threat_intel.rs:1019-1025` — parsing issue
- `src/mesh/threat_intel.rs:1383-1389` — parsing issue
- `src/mesh/protocol_types.rs:535-541` — protobuf mapping bug

These cause threat types to be lost or misidentified during DHT storage/retrieval.

**Fix**: Investigate each location and fix the parsing logic. Ensure threat types are correctly serialized/deserialized in both the DHT path and protobuf path.

**Verification**: Test that all threat types (IpBlock, Malware, Spam, etc.) survive a round trip through DHT store→retrieve.

---

### W2-7: Honeypot Announcement Inconsistency

**Source**: plan28.md 1.3
**Severity**: MEDIUM-HIGH
**Files**: `src/waf/mod.rs`, `src/mesh/threat_intel.rs`

**Problem**: HTTP honeypot blocking at `src/waf/mod.rs:546-564` calls `block_ip_for_honeypot()` which uses `announce_local_block()` — this publishes an unsigned indicator. Should use `announce_honeypot_indicator()` for signed indicators that other nodes can verify.

**Fix**: Change `block_ip_for_honeypot()` to use the signed announcement path.

**Verification**: Verify honeypot blocks result in signed DHT indicators.

---

## Wave 3: Performance Optimizations

These are independent and can be parallelized.

### W3-1: ViolationTracker Sharding

**Source**: plan4.md F2.1
**Severity**: HIGH (performance)
**Files**: `src/waf/violation_tracker.rs`

**Problem**: Global `RwLock<HashMap>` at line 58 (`store: Arc<RwLock<HashMap<String, ViolationEntry>>>`) acquired on every violation. At 500K rps with 5% violation rate = 25K lock acquisitions/sec under a single coarse lock.

**Fix**: Implement 64-sharded ViolationTracker following the pattern in `src/dns/server/sharded_store.rs`:
1. Create array of 64 `RwLock<HashMap>` shards
2. Hash IP address to determine shard index
3. Each operation only locks one shard

**Verification**: Load test comparing lock contention before/after.

---

### W3-2: DHT JSON to Postcard Migration

**Source**: plan23.md C1, plan25.md C5
**Severity**: HIGH (performance)
**Files**: `src/mesh/dht/record_store_crud.rs`, `src/mesh/dht/record_store_message.rs`

**Problem**: `serde_json::to_string()` used for DHT record serialization at `record_store_crud.rs:33-40` and `record_store_message.rs:557-562,700-705`. At scale this creates ~1M unnecessary allocations/sec.

**Fix**: Replace `serde_json::to_string()` with `crate::serialization::serialize()` (postcard) for all DHT record serialization. Update `MeshMessageSigner::verify()` signature to accept `&[u8]` instead of `&str` where needed.

**Verification**: `cargo test --test dht_integration_test`

---

### W3-3: WAF Per-Header Arc Clone

**Source**: plan23.md C2
**Severity**: HIGH (performance)
**Files**: `src/waf/attack_detection/mod.rs`

**Problem**: At line 302, `InputLocation::Header(name.clone())` where `name` is `Arc<str>`. At 500K rps with ~20 headers per request = ~10M Arc reference count operations/sec. While cheap individually, they compound.

**Fix**: Change detector function signatures to accept `&InputLocation` instead of `InputLocation` where possible. Where ownership is needed, keep the clone.

**Verification**: Benchmark WAF detection throughput before/after.

---

### W3-4: Proxy Cache O(n) Invalidation

**Source**: plan23.md C4
**Severity**: HIGH (performance)
**Files**: `src/proxy_cache/store.rs`

**Problem**: `invalidate_by_pattern()` at lines 556-562 iterates ALL cache entries with `.iter().filter().map().collect()` on every call. This is O(n) where n is total cache size.

**Fix**: Add `uri_prefix_index: DashMap<String, Vec<CacheKey>>` for O(1) prefix-based lookups:
1. Maintain a secondary index mapping URI prefixes to cache keys
2. On insert, add to prefix index
3. On invalidate, look up prefix in index instead of scanning all entries

**Verification**: Benchmark invalidation with 10K, 100K, 1M cached entries.

---

### W3-5: Thread-Local Response Header Buffers

**Source**: plan4.md F1.1-F1.2
**Severity**: HIGH (performance)
**Files**: `src/http/server.rs`, `src/tls/server.rs`

**Problem**: Fresh `Vec::new()` allocated for filtered response headers at 4 locations:
- `http/server.rs:2644` — `let mut filtered_headers_buf = Vec::new();`
- `http/server.rs:2741` — `let mut headers = Vec::new();`
- `tls/server.rs:1449` — `let mut filtered_headers_buf = Vec::new();`
- `tls/server.rs:1599` — `let mut filtered_headers_buf = Vec::new();`

**Fix**: Use thread-local buffers:
```rust
thread_local! {
    static RESPONSE_HEADER_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}
```
Clear and reuse the buffer instead of allocating new ones per request.

**Verification**: Benchmark proxy throughput. Verify no buffer contamination between requests.

---

### W3-6: String Allocations in Hot Paths

**Source**: plan4.md F1.3-F1.5
**Severity**: HIGH (performance)
**Files**: `src/http/server.rs`, `src/tls/server.rs`

**Problem**: Multiple unnecessary `.to_string()` allocations per request:
- `method.to_string()` at 8+ locations — should use `method.as_str()`
- `site_id.to_string()` at 2+ locations — should use `site_id.as_str()`
- Duplicate `path_str` allocation at lines 2073, 2826, 2901

**Fix**: Replace `.to_string()` with `.as_str()` for `method` and `site_id`. Reuse the `path_str` variable instead of re-allocating.

**Verification**: Count allocations before/after with profiling.

---

### W3-7: WebSocket Empty HashMap Allocations

**Source**: plan4.md F1.7
**Severity**: MEDIUM (performance for WebSocket)
**Files**: `src/http/server.rs`

**Problem**: Empty `HashMap::new()` created for `headers` and `metadata` on every WebSocket frame at 8 locations (lines ~3337, 3340, 3412, 3415, 3547, 3550, 3618, 3625). Two allocations per frame across 4 relay loops.

**Fix**: Use static empty map constants or lazily-initialized thread-local empty maps:
```rust
static EMPTY_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);
```

**Verification**: WebSocket load test.

---

### W3-8: Proxy Headers Excessive Allocations

**Source**: plan23.md H3
**Severity**: HIGH (performance)
**Files**: `src/proxy/headers.rs`

**Problem**: `build_forward_headers()` at lines 343-400 returns `Vec<(String, String)>` with `.to_string()` per header entry.

**Fix**: Use `http::HeaderMap` instead of `Vec<(String, String)>` to avoid duplicating header names and values.

**Verification**: Benchmark proxy header building.

---

### W3-9: Cache Write Lock Contention

**Source**: plan23.md M1
**Severity**: MEDIUM (performance)
**Files**: `src/proxy_cache/store.rs`

**Problem**: `host_index.write()` acquired on every cache insert at line 524.

**Fix**: Replace `RwLock<HashMap>` with `DashMap` for the host index.

**Verification**: Benchmark concurrent cache inserts.

---

### W3-10: Mesh Seen Messages Lock Contention

**Source**: plan23.md M4
**Severity**: MEDIUM (performance)
**Files**: `src/mesh/transport.rs`

**Problem**: `seen_messages` at line 118 is `Arc<RwLock<LruCache<String, Instant>>>`. Every message check+mark acquires locks at lines 961-968.

**Fix**: Replace with `DashMap<String, Instant>` with TTL-based eviction.

**Verification**: Benchmark mesh message throughput.

---

### W3-11: Rate Limiter O(bucket_count) Rotation

**Source**: plan23.md H6
**Severity**: HIGH (performance)
**Files**: `src/waf/ratelimit/core.rs`

**Problem**: At lines 176-180, all buckets are summed sequentially on every `get_count()` call:
```rust
for i in 0..self.bucket_count {
    total += self.buckets[idx].load(Ordering::Acquire);
}
```

**Fix**: Maintain a `running_sum: AtomicU64` that is incremented on each request and decremented when buckets rotate. This makes `get_count()` O(1) instead of O(bucket_count).

**Verification**: Benchmark rate limit checking at high rps.

---

### W3-12: DNS Zone Clone on Get

**Source**: plan23.md H5
**Severity**: HIGH (performance for DNS)
**Files**: `src/dns/server/sharded_store.rs`

**Problem**: `get()` at line 67 returns `Option<Zone>` via `.cloned()`, causing a full Zone clone on every DNS query.

**Fix**: Change internal storage to `Arc<Zone>` and return `Option<Arc<Zone>>` to avoid cloning the entire zone data structure on every lookup. This requires updating all callers.

**Verification**: DNS query benchmark.

---

### W3-13: WASM Instance Pool Linear Search

**Source**: plan20.md 2.2
**Severity**: HIGH (performance for WASM)
**Files**: `src/plugin/instance_pool.rs`

**Problem**: Instance pool uses linear search through all instances. Since all instances for a given function are identical, just use `pop()` to grab any available instance.

**Fix**: Replace Vec-based pool with a VecDeque or stack where `pop()` retrieves an instance and `push()` returns it.

**Verification**: Benchmark WASM instance acquisition under load.

---

### W3-14: Cookie format!() Allocations

**Source**: plan23.md H2
**Severity**: MEDIUM (performance)
**Files**: `src/http/server.rs:1219`, `src/waf/mod.rs:818,825`

**Problem**: Cookie parsing uses `format!()` for every cookie, creating allocations per request.

**Fix**: Use zero-alloc cookie parsing with `Cow<str>` or pre-parsed structures.

**Verification**: Benchmark request parsing with many cookies.

---

### W3-15: to_lowercase() Per Header Per Request

**Source**: plan25.md H5
**Severity**: MEDIUM (performance)
**Files**: `src/proxy/headers.rs:136`

**Problem**: Header names are lowercased per request with `.to_lowercase()`. These should be pre-computed or compared case-insensitively.

**Fix**: Use `http::header::HeaderName` comparison which is already case-insensitive, or pre-compute lowercase versions.

**Verification**: Benchmark header processing.

---

### W3-16: URL format!() Per Request

**Source**: plan25.md H6
**Severity**: MEDIUM (performance)
**Files**: `src/http/server.rs:2528`

**Problem**: URL construction uses `format!()` per request.

**Fix**: Pre-parse `Uri` or use `http::uri::Builder` for zero-alloc URL construction where possible.

**Verification**: Benchmark request handling.

---

## Wave 4: Mesh & DHT Architecture

### W4-1: Domain Ownership Verification

**Source**: plan19.md Phase 1
**Severity**: CRITICAL
**Files**: `src/mesh/verification.rs`, `src/mesh/transport_peer.rs`

**Problem**: Any node can announce `verified_upstream` for any domain without proving DNS ownership. `handle_upstream_ownership_challenge()` at `transport_peer.rs:1914-2017` never actually serves HTTP-01 challenges.

**Fix**: Implement the verification loop:
1. Origin stores the challenge when requested
2. Global node verifies via HTTP request to the domain
3. Only after successful verification does the upstream become "verified"
4. Handle `UpstreamChallengeProof` on the global side

**Verification**: Integration test for HTTP-01 challenge flow.

---

### W4-2: broadcast_pending_records() Never Called

**Source**: plan13.md Issue #1
**Severity**: HIGH
**Files**: `src/mesh/dht/record_store_sync.rs`

**Problem**: `broadcast_pending_records()` at line 618 is defined but never called. DHT records are stored locally but never broadcast to peers, defeating the purpose of DHT propagation.

**Fix**: Call `broadcast_pending_records()` after storing records, ideally on a timer (e.g., every 30 seconds) and immediately after high-priority writes.

**Verification**: Store a record on node A, verify node B receives it via broadcast.

---

### W4-3: Global-Only Restriction for Threat Intel Sync

**Source**: plan13.md Issue #2
**Severity**: HIGH
**Files**: `src/mesh/threat_intel.rs`

**Problem**: Threat intel sync at lines 1319-1332 restricts to global-only mode. Edge and origin nodes cannot sync threat intelligence, limiting the mesh's collective defense capability.

**Fix**: Allow edge nodes with `trusted_signers` config to sync threat intel. Add a configurable allowlist of trusted signer public keys.

**Verification**: Test that edge nodes with trusted signers can receive and apply threat intel.

---

### W4-4: In-Memory Revocation List Lost on Restart

**Source**: plan19.md Phase 1
**Severity**: HIGH
**Files**: `src/mesh/peer_auth.rs`

**Problem**: Revocation list at `peer_auth.rs:12-53` is in-memory only. When a node restarts, all revocations are lost, allowing revoked nodes to reconnect.

**Fix**: Persist revocation list to disk. Load on startup, save on modification. Use `postcard` serialization.

**Verification**: Restart node, verify previously revoked nodes are still rejected.

---

### W4-5: Serverless DHT Key Mismatch

**Source**: plan10.md Issue #1
**Severity**: HIGH
**Files**: `src/serverless/manager.rs`, `src/http/server.rs`

**Problem**: DHT key lookup uses wrong key format. Storage uses `serverless_function:{name}` (at `manager.rs:354`) but lookup uses `serverless:{name}` (at `manager.rs:723-725`, `http/server.rs:1900`).

**Fix**: Unify key format to `serverless_function:{name}` everywhere. Update all lookup sites.

**Verification**: Integration test for function discovery via DHT.

---

### W4-6: Missing node_id in Serverless DHT Records

**Source**: plan10.md Issue #2
**Severity**: HIGH
**Files**: `src/serverless/manager.rs`

**Problem**: DHT records stored at `manager.rs:354-368` are missing the `node_id` field. Consumers at `http/server.rs:1900-1903` expect `node_id` to determine which node hosts the function.

**Fix**: Add `node_id` field to the DHT record struct and include it during storage.

**Verification**: Verify edge nodes can extract `node_id` from DHT records.

---

### W4-7: announce_serverless() Not Implemented

**Source**: plan10.md Issue #4
**Severity**: HIGH
**Files**: `src/mesh/transport.rs`

**Problem**: `discover_serverless_functions()` exists at `transport.rs:637-684` but is never called. No `announce_serverless()` method exists. Serverless functions are never announced to or discovered by other mesh nodes.

**Fix**:
1. Create `announce_serverless()` method in `MeshTransport`
2. Call during `ServerlessManager::initialize()`
3. Wire `discover_serverless_functions()` into mesh connection lifecycle
4. Add `node_id` to `ServerlessFunctionAnnounce` in protocol.rs

**Verification**: Test multi-node function discovery.

---

### W4-8: Edge Discovery Not Integrated

**Source**: plan10.md Issue #5
**Severity**: HIGH
**Files**: `src/mesh/transport.rs`

**Problem**: `discover_serverless_functions()` is defined but never called from mesh connection flow. Edge nodes cannot discover origin-hosted serverless functions.

**Fix**:
1. Wire `discover_serverless_functions()` into mesh connection establishment
2. Add local cache field to `MeshTransport` for discovered functions
3. Implement periodic refresh loop
4. Remove dead code `register_function_routing()` at `manager.rs:414-425`

**Verification**: Test that edge can route to origin serverless function.

---

### W4-9: Mesh Topology Cache Scaling

**Source**: plan9.md Issue #2
**Severity**: HIGH
**Files**: `src/mesh/topology.rs`

**Problem**: Cache capacities at lines 58-66 are too small for 100K+ sites:
- `route_cache`: 10K capacity
- `verified_upstream_cache`: 1K capacity
- `policy_cache` in `proxy.rs:261-265`

**Fix**:
1. Scale `route_cache` from 10K to 100K
2. Scale `verified_upstream_cache` from 1K to 50K
3. Scale `policy_cache` proportionally
4. Replace `get_all_records()` scan at lines 739-842 with indexed `get_by_prefix()`

**Verification**: Load test with 100K upstream entries.

---

### W4-10: Mesh Graceful Degradation

**Source**: plan9.md Issue #3
**Severity**: HIGH
**Files**: `src/mesh/proxy.rs`, `src/mesh/discovery.rs`

**Problem**: No fallback when DHT is degraded or unreachable. Requests fail instead of serving stale cached content.

**Fix**:
1. Add peer-to-peer DHT query when degraded
2. Serve stale cached content during degradation
3. Add fallback chain in `resolve_upstream()`

**Verification**: Test behavior when global nodes are unreachable.

---

### W4-11: Per-Site Rate Limiting

**Source**: plan9.md Issue #1
**Severity**: HIGH
**Files**: `src/waf/mod.rs`, `src/waf/ratelimit/core.rs`

**Problem**: Rate limiting is global, not per-site. A site with aggressive rate limits affects all other sites sharing the same worker.

**Fix**:
1. Add `site_id: &str` parameter to `check_request_full()` and downstream
2. Create per-site rate limiting with separate buckets or site-keyed approach
3. Wire `SiteRateLimitConfig` overrides

**Verification**: Test that site A's rate limit doesn't affect site B.

---

### W4-12: WasmDistManager Decision Required

**Source**: plan20.md 1.1
**Severity**: MEDIUM (architecture)
**Files**: `src/mesh/wasm_dist.rs`

**Problem**: `WasmDistManager` at `wasm_dist.rs:8-11,293` is never initialized — it's dead code. The `WasmModuleAnnounce` message type exists in `protocol.rs:948-1004` but is never handled.

**Decision needed**: Option A — Remove all dead code (5-9 days). Option B — Complete the WASM distribution feature (9-14 days).

**Fix (Option A recommended for now)**: Remove `WasmDistManager`, `WasmModuleAnnounce` handling code, and related dead code. This can be re-implemented later if needed.

**Verification**: `cargo check` after removal.

---

### W4-13: Axum Raw Pointer Use-After-Free Risk

**Source**: plan20.md 1.3
**Severity**: HIGH
**Files**: `src/plugin/axum_loader.rs`

**Problem**: Axum dynamic plugin uses a raw pointer factory `*mut Router<()>` at lines 10-13, 135-150. This is a use-after-free risk if the plugin is reloaded.

**Fix**: Replace raw pointer with `Arc<Mutex<Router<()>>>` or similar safe reference counting.

**Verification**: Test plugin reload/unload scenarios.

---

### W4-14: Router Clone Per Request

**Source**: plan20.md 2.1
**Severity**: HIGH (performance)
**Files**: `src/http/server.rs`

**Problem**: Router is cloned per request at line ~3719, an O(n) operation proportional to the number of routes.

**Fix**: Use `Arc<Router>` or route trie to avoid cloning the full router on each request.

**Verification**: Benchmark with 100+ routes.

---

### W4-15: Origin Attestation Key Bug

**Source**: plan19.md Phase 2
**Severity**: HIGH
**Files**: `src/mesh/transport.rs`

**Problem**: Origin attestation at lines 1661-1669 has a key handling bug that may prevent proper attestation.

**Fix**: Investigate and fix the key derivation/lookup at the referenced lines.

**Verification**: Test origin attestation flow end-to-end.

---

### W4-16: ThreatIntel Timestamp and Content Validation

**Source**: plan27.md Phase 3
**Severity**: MEDIUM
**Files**: `src/mesh/threat_intel.rs`

**Problem**: No validation of timestamps or content integrity for ThreatIntel indicators received from other nodes.

**Fix**:
1. Add timestamp bounds validation (future: reject >60s ahead, past: reject >24h old)
2. Add content hash verification for indicators
3. Add `trusted_signers` config for ThreatIntel allowlist

**Verification**: Test with forged timestamps and invalid hashes.

---

### W4-17: DHT Store Rate Limiting

**Source**: plan19.md Phase 3
**Severity**: MEDIUM
**Files**: `src/mesh/dht/record_store_crud.rs`, `src/mesh/dht/record_store.rs`

**Problem**: `is_rate_limited()` exists at `record_store.rs:371-377` but is NOT called from `store_record()`. Any node can flood the DHT with writes.

**Fix**: Call `is_rate_limited()` at the beginning of `store_record()` in `record_store_crud.rs`.

**Verification**: Test that excessive writes are throttled.

---

## Wave 5: Reverse Proxy Security

### W5-1: TLS Passthrough WAF Enforcement

**Source**: plan18.md #1
**Severity**: HIGH
**Files**: `src/worker/unified_server.rs`, `src/tls/server.rs`

**Problem**: For sites with TLS passthrough, the WAF enforcement is incomplete. The `proxy_raw_tcp()` function exists at `tls/server.rs:1800` but may not be fully wired into the request handling path. The config field `tls_passthrough_enforce_waf` IS used for conditional logic (lines 257-262 of `unified_server.rs`) but the enforcement gap is in the raw TCP proxy path.

**Fix**:
1. Verify `proxy_raw_tcp()` is called for passthrough sites
2. Ensure Layer 3/4 checks (IP rate limiting, connection limits) are applied
3. Log at ERROR level (not WARN) when passthrough is used without enforcement
4. Require rate limiting to be configured for passthrough sites

**Verification**: Test TLS passthrough with rate limiting enabled/disabled.

---

### W5-2: JWT Algorithm Confusion Attack

**Source**: plan18.md #2
**Severity**: HIGH
**Files**: `src/waf/attack_detection/jwt.rs`

**Problem**: JWT detector is pattern-based only. Cannot detect algorithm switching from RS256 to HS256 (where the public key becomes the HMAC secret). This is a known attack class.

**Fix**: Add algorithm family tracking:
1. Track whether the JWT header specifies symmetric or asymmetric algorithm
2. Detect when algorithm family changes between tokens from the same issuer
3. Flag algorithm confusion attempts

**Verification**: Test with RS256→HS256 switch in JWT header.

---

### W5-3: DNS Rebinding SSRF

**Source**: plan18.md #4
**Severity**: HIGH
**Files**: `src/waf/attack_detection/ssrf.rs`

**Problem**: SSRF detector does NOT perform DNS resolution. Attacker can register a domain resolving to a public IP initially, then change it to a private IP after the initial check. DNS rebinding bypasses the SSRF protection.

**Fix**: Add DNS resolver capability:
1. Perform DNS resolution on detected URLs
2. Check resolved IPs against private ranges
3. Cache results with short TTL
4. Use mesh DNS resolver with fallback to system resolver

**Verification**: Test with a domain that resolves to different IPs over time.

---

### W5-4: Global Rate Limiter Blackhole Per-IP

**Source**: plan18.md #7
**Severity**: MEDIUM
**Files**: `src/waf/ratelimit/core.rs`

**Problem**: Blackhole is global (not per-IP). One abusive client can trigger a blackhole that affects all clients.

**Fix**: Add per-IP blackhole tracking with:
1. Individual IP blackhole state
2. Admin API reset endpoint
3. Configurable blackhole duration

**Verification**: Test that one IP's blackhole doesn't affect another IP.

---

### W5-5: Connection Pool Configurability

**Source**: plan18.md #6
**Severity**: MEDIUM
**Files**: `src/config/limits.rs`, `src/upstream/pool.rs`, `src/http_client/mod.rs`

**Problem**: Connection pool defaults hardcoded at 100 (`max_connections: 100` at `pool.rs:113`, `pool_max_idle_per_host(100)` at `mod.rs:463`, `connection_pool_size: 100` at `limits.rs:46`). Not exposed via site config.

**Fix**: Expose via site proxy config with sensible defaults:
- `max_connections` (default: 100)
- `pool_max_idle_per_host` (default: 100)
- `pool_idle_timeout` (default: 30s)

**Verification**: Configure different values per site, verify they're applied.

---

### W5-6: GeoIP Cache Size

**Source**: plan18.md #8
**Severity**: LOW
**Files**: `src/config/defaults.rs`

**Problem**: Default 10,000 entry GeoIP/ASN cache may thrash at 500K rps with diverse client IPs.

**Fix**: Increase default to 100,000 entries.

**Verification**: Cache hit rate under load with diverse IPs.

---

## Wave 6: DNS & DNSSEC

### W6-1: SHA-1 Deprecation for DNSSEC

**Source**: plan24.md H1a-H1c
**Severity**: HIGH
**Files**: `src/dns/tsig.rs`, related DNSSEC files

**Problem**: RFC 9905 (Nov 2025) deprecates SHA-1 for DNSSEC. TSIG HMAC-SHA1 is still used. DS records may default to SHA-1 digest.

**Fix**:
1. Add HMAC-SHA-256 support for TSIG at `tsig.rs:8,15`
2. Default to SHA-256 for DS record digests
3. Migrate DNSKEY signing algorithm to ECDSA256SHA256 where appropriate

**Verification**: Test HMAC-SHA-256 signing/verification. Test DS records use SHA-256.

---

### W6-2: DNS Cache Poisoning Confirmation Threshold

**Source**: plan3.md B.1
**Severity**: MEDIUM
**Files**: `src/dns/cache.rs`

**Problem**: Confirmation threshold at line 193 is `if confirmations < 2`. A threshold of 2 may be too low to prevent cache poisoning in adversarial environments.

**Fix**: Increase threshold from 2 to 3. Make it configurable.

**Verification**: `cargo test --test dns_recursive_test`

---

### W6-3: DNS Cookie Key Truncation

**Source**: plan3.md B.2
**Severity**: LOW (documentation)
**Files**: `src/dns/cookie.rs`

**Problem**: At line 47, `secret_key[..16]` truncates a 32-byte key to 16 bytes. This may be intentional for DNS cookie design (RFC 7873) or may weaken security.

**Fix**: Document the design intent. If intentional per RFC 7873, add a comment explaining why. If not, use the full key.

**Verification**: Verify against RFC 7873 requirements.

---

### W6-4: QUIC 0-RTT Configuration

**Source**: plan3.md C.1
**Severity**: MEDIUM (documentation)
**Files**: `src/mesh/cert.rs`, `src/mesh/config.rs`

**Problem**: QUIC 0-RTT may be disabled. Need to confirm this is intentional for production use.

**Fix**: Document the design decision. Verify `quic_enable_0rtt` config exists and is appropriately defaulted.

**Verification**: `grep -n "quic_enable_0rtt" src/mesh/config.rs`

---

## Wave 7: Code Quality & Reliability

### W7-1: Additional RNG Hardening

**Source**: plan25.md H1-H2, M6, L4
**Severity**: HIGH
**Files**: Multiple

**Problem**: Several locations use `ThreadRng` (via `rand::rng()`) for security-sensitive operations:
- HMAC session key at `src/process/ipc_signed.rs:555`
- Tier key generation at `src/mesh/transport_org.rs:132-135`
- Encryption nonce at `src/mesh/config_identity.rs:391-392`
- HMAC nonce at `src/process/ipc_signed.rs:83`

**Note**: In modern `rand` 0.9+, `rand::rng()` uses `OsRng` as entropy source, so these are actually CSPRNGs. However, defense-in-depth recommends using `OsRng` directly for cryptographic key material.

**Fix**: Replace `rand::rng()` with `rand::rngs::OsRng` for key/nonce generation at the listed locations.

**Verification**: `cargo test --lib` after changes.

---

### W7-2: Lock Poisoning Recovery

**Source**: plan25.md H3
**Severity**: MEDIUM
**Files**: `src/process/ipc_signed.rs`

**Problem**: At line 69, lock acquisition doesn't handle poisoning. If a thread panics while holding the lock, all subsequent accesses panic.

**Fix**: Use `lock().unwrap_or_else(|e| e.into_inner())` pattern or replace with `parking_lot` locks which don't poison.

**Verification**: Test that a panic in one thread doesn't permanently deadlock the lock.

---

### W7-3: O(n) Vec to HashSet in Probe Tracker

**Source**: plan25.md H4
**Severity**: MEDIUM
**Files**: `src/waf/probe_tracker.rs`

**Problem**: Lines 55-62 use `Vec` for containment checks that are O(n). Should use `HashSet` for O(1) lookups.

**Fix**: Replace `Vec` with `HashSet` for the lookup data structure.

**Verification**: Benchmark probe tracker with many entries.

---

### W7-4: Redundant block_in_place + block_on

**Source**: plan25.md H7
**Severity**: MEDIUM
**Files**: `src/mesh/threat_intel.rs`

**Problem**: At lines 1321-1323, uses `tokio::task::block_in_place()` wrapping `Handle::current().block_on()`. This is redundant — use a sync getter or fully async approach.

**Fix**: Either make the path fully async or provide a synchronous accessor that doesn't need both wrappers.

**Verification**: Test that the call works without the redundant wrapping.

---

### W7-5: Attack Detection Function Duplication

**Source**: plan25.md M1
**Severity**: MEDIUM (maintainability)
**Files**: `src/waf/attack_detection/mod.rs`

**Problem**: Lines 285-908 contain ~20 nearly identical check function invocations. This is a maintainability issue.

**Fix**: Define a trait `AttackDetector` with a `check()` method, implement for each detector type, and iterate over a list of detectors.

**Verification**: All existing WAF tests pass with the refactored code.

---

### W7-6: Buffer Pool .expect() Hardening

**Source**: plan25.md M2
**Severity**: MEDIUM
**Files**: `src/buffer/pool.rs`

**Problem**: `.expect()` calls at lines 377, 381, 434 will panic in production if assertions fail.

**Fix**: Replace with `debug_assert!()` in release builds and proper error returns.

**Verification**: `cargo test --lib` after changes.

---

### W7-7: Silent Error Handling Improvements

**Source**: plan25.md M4-M5
**Severity**: MEDIUM
**Files**: `src/mesh/cert.rs`, `src/mesh/transport.rs`

**Problem**:
- Silent cert rotation rename errors at `cert.rs:655,659` — should warn
- Silent JSON deserialization failures in DHT at `transport.rs:802` — should warn

**Fix**: Add `tracing::warn!()` for these silent failure cases.

**Verification**: Trigger the error paths and verify warnings are logged.

---

### W7-8: HTTP Status Code .expect() Hardening

**Source**: plan25.md M3
**Severity**: MEDIUM
**Files**: `src/http/file_manager.rs`

**Problem**: `.expect()` at lines 113, 128 will panic if status code conversion fails.

**Fix**: Replace with `.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)`.

**Verification**: `cargo test --lib` after changes.

---

### W7-9: TLS Skip Verify Documentation

**Source**: plan25.md L2
**Severity**: LOW
**Files**: Related TLS config

**Problem**: `skip_verify` TLS option lacks documentation about security implications.

**Fix**: Add documentation comments explaining the security tradeoffs.

**Verification**: Code review.

---

## Wave 8: Dead Code & Stub Removal

### W8-1: Remove Platform Stubs

**Source**: plan14.md 1.1-1.3
**Severity**: MEDIUM
**Files**: `src/platform/`

**Problem**: Dead stub code:
- `StubProcessControl`/`StubSignalHandler` at `src/platform/process.rs:42-87`
- `StubIpcListener`/`StubIpcStream` at `src/platform/ipc.rs:40-109`
- Entire `src/platform/service/` directory

**Fix**: Remove unused stubs. Verify no code references them.

**Verification**: `cargo check` after removal.

---

### W8-2: HTTP/3 Backend Routing Implementation

**Source**: plan14.md 3.1-3.2, plan29.md Phase 1
**Severity**: MEDIUM
**Files**: `src/http3/server.rs`

**Problem**: HTTP/3 server at lines 473-476 has a placeholder response instead of actual backend routing. `src/http3/handler.rs` is an unused stub file.

**Fix**:
1. Add `RouteResult` handling to HTTP/3 server
2. Implement backend handlers (static, PHP, FastCGI, upstream, mesh) mirroring `http/server.rs` patterns
3. Add `ConnectionMeta` for HTTP/3
4. Wire up metrics
5. Remove unused `handler.rs`

**Verification**: `curl -k --http3` test against various backends.

---

### W8-3: Remove Dead Code in OpenAPI

**Source**: plan30.md Phase 2
**Severity**: LOW
**Files**: `src/admin/openapi.rs`

**Problem**: Dead functions at lines 363-405: `get_docs()`, `router()`, `get_openapi()` — superseded by swagger-ui integration.

**Fix**: Remove dead code after confirming no callers.

**Verification**: `cargo check`.

---

### W8-4: Remove Dead Nested cfg(test)

**Source**: plan35.md Phase 7
**Severity**: LOW
**Files**: `tests/integration_test.rs`

**Problem**: Nested `#[cfg(test)]` inside `mod tests` at lines 4-5, 427, 478, 853 makes 42 tests unreachable.

**Fix**: Remove the redundant inner `#[cfg(test)]` attributes.

**Verification**: `cargo test --test integration_test --no-run 2>&1 | grep -E "warning:|never used"` — expect 0 warnings.

---

### W8-5: Unbounded WASM Scale-Up Spawn

**Source**: plan20.md 3.2
**Severity**: MEDIUM
**Files**: `src/serverless/instance_pool.rs`

**Problem**: `scale_up` at lines 272-303 spawns instances in a tight loop without bounds. Under burst, can exhaust resources.

**Fix**: Add maximum instance cap and rate limiting on spawn.

**Verification**: Test under burst load.

---

### W8-6: backend_plugin Config Ignored

**Source**: plan20.md 2.3
**Severity**: MEDIUM
**Files**: `src/plugin/mod.rs`

**Problem**: `backend_plugin` config at `config/site/backend.rs:117-123` is ignored. Multi-plugin routing is broken — `get_axum_router()` at `mod.rs:100-102` just returns the first match.

**Fix**: Implement per-location plugin routing using the `backend_plugin` config field.

**Verification**: Configure multiple plugins per site, verify correct routing.

---

## Wave 9: Admin API & UI

### W9-1: Upgrade Swagger UI

**Source**: plan30.md Phase 1-3
**Severity**: HIGH
**Files**: `Cargo.toml`, `src/admin/openapi.rs`, `src/admin/mod.rs`

**Problem**:
1. `utoipa-swagger-ui` at version "7" needs upgrade to "9" for axum 0.8 compat (`Cargo.toml:205`)
2. No embedded Swagger UI — need to add `SwaggerUi::new("/api/docs")` merge to main admin router (`admin/mod.rs:555-574`)
3. OpenAPI servers array at `openapi.rs:43-46` has hardcoded `localhost:8080` instead of generic `/`

**Fix**:
1. Upgrade `utoipa-swagger-ui` from "7" to "9" in Cargo.toml
2. Add SwaggerUi merge in `admin/mod.rs`
3. Remove dead code in `openapi.rs` (lines 363-405)
4. Fix server URL to `/`

**Verification**:
- `curl -I http://localhost:8081/api/docs` → 301 redirect
- `curl http://localhost:8081/api/docs/` → Swagger UI HTML
- `curl http://localhost:8081/api/openapi.json | jq '.servers'` → correct URLs

---

### W9-2: Remove TCP/UDP Listeners Admin Page

**Source**: plan32.md Phase 1A
**Severity**: MEDIUM
**Files**: `admin-ui/src/`

**Problem**: TCP/UDP listeners page references non-existent backend API.

**Fix**:
1. Remove route from `admin-ui/src/app.rs:9,35,118`
2. Remove NavItem from `admin-ui/src/components/layout/sidebar.rs:55`
3. Remove module from `admin-ui/src/pages/mod.rs:17,40`
4. Delete `admin-ui/src/pages/tcp_udp.rs`

**Verification**: Admin UI compiles and navigates without TCP/UDP page.

---

### W9-3: Fix Tier Keys "Issue New Key" Modal

**Source**: plan32.md Phase 1B
**Severity**: MEDIUM
**Files**: `admin-ui/src/pages/tier_keys.rs`, `src/admin/handlers/tier_keys.rs` (NEW)

**Problem**: "Issue New Key" modal at `tier_keys.rs:91-98` has non-functional form inputs.

**Fix**:
1. Add form state fields to TierKeys struct
2. Add message variants for org_id and tier input
3. Wire input handlers
4. Create backend handler `src/admin/handlers/tier_keys.rs` with 4 endpoints (GET /tier-keys, POST /issue, POST /revoke, POST /unbind)
5. Register routes in `src/admin/mod.rs`
6. Add `list_tier_keys()` to `OrganizationManager`

**Verification**: Test tier key issuance via admin UI.

---

### W9-4: Rule Feed Configuration API

**Source**: plan32.md Phase 2A
**Severity**: MEDIUM
**Files**: `src/admin/handlers/config.rs`, `admin-ui/src/`

**Problem**: No API endpoint for rule feed configuration.

**Fix**:
1. Add GET/PUT `/api/config/rule-feed` endpoints
2. Add frontend API methods and settings UI section

**Verification**: `curl` against `/api/config/rule-feed` endpoints.

---

### W9-5: Tarpit Hardcoded Values

**Source**: plan32.md Phase 2B
**Severity**: MEDIUM
**Files**: `src/waf/mod.rs`

**Problem**: Tarpit response at `mod.rs:1405-1416` uses hardcoded values (10/50) instead of config from `TarpitDefaults` in `src/config/network.rs:253-300`.

**Fix**: Store `TarpitDefaults` in `WafCore` struct and use config values in `generate_tarpit_response()`.

**Verification**: Configure custom tarpit values, verify they're applied.

---

### W9-6: OpenAPI Schema Examples

**Source**: plan15.md
**Severity**: MEDIUM
**Files**: 19 handler files in `src/admin/handlers/`

**Problem**: Only 2 of 128 schemas have examples (at `stats.rs:19,24`). Missing `#[schema(example = ...)]` annotations.

**Fix**: Add `#[schema(example = ...)]` to schemas across all handler files. Pattern: `#[schema(example = json!(...))]`

**Verification**: `cargo test --lib test_openapi` (14 existing tests should still pass).

---

### W9-7: Admin API Config Expansion

**Source**: plan16.md
**Severity**: MEDIUM
**Files**: `src/admin/handlers/`, `src/admin/mod.rs`

**Problem**: Many config sections not exposed via API. Currently only partial config endpoints exist.

**Fix (Phase 1 — Global Config)**:
1. GET/PUT server config
2. GET/PUT admin config (token write-only)
3. GET/PUT persistence config
4. GET/PUT tarpit defaults
5. GET/PUT static config

**Fix (Phase 2 — Site Sub-Configs)**: 22 site sub-config endpoints following the pattern in `src/admin/handlers/config.rs:1415-1457`.

**Verification**: Each endpoint returns proper JSON and persists to TOML.

---

## Wave 10: Edge Caching & Proxy Architecture

### W10-1: Image Poison Edge-Only Mode

**Source**: plan11.md, plan33.md Phase 1
**Severity**: MEDIUM
**Files**: `src/config/site/misc.rs`, `src/mesh/transport.rs`, `src/mesh/transports/manager.rs`

**Problem**: Image poisoning may be applied on origin (double-poisoning) as well as edge. Need `edge_only` flag to clarify intent.

**Fix**:
1. Add `edge_only: Option<bool>` to `SiteImagePoisonConfig` at `misc.rs:21-36`
2. Publish to DHT in `transport.rs:864-875`
3. Parse in `manager.rs:1022-1065`
4. Verify no image poisoning in origin path

**Verification**: Enable image poison on origin, request through edge, verify single poison.

---

### W10-2: X-MaluWaf-Transformed Header

**Source**: plan33.md Phase 2
**Severity**: MEDIUM
**Files**: `src/mesh/transport_peer.rs`, `src/mesh/proxy.rs`, `src/http/server.rs`

**Problem**: No way for edge to know what transforms origin already applied. This causes double-transformation (e.g., image poison applied twice).

**Fix**:
1. Define header format: `X-MaluWaf-Transformed: min,gzip,br` (transform tokens)
2. Add header on origin outgoing responses
3. Parse header in MeshProxy `transform_response()` to skip already-applied transforms

**Verification**: Request through edge, verify no double-transformation.

---

### W10-3: Tiered Transform Caching

**Source**: plan33.md Phase 3
**Severity**: MEDIUM
**Files**: `src/mesh/proxy.rs`

**Problem**: Single-level transform cache. For L1/L2 (hot/warm) architecture with promotion.

**Fix**:
1. Define `TieredTransformCache` with L1 (in-memory, hot) and L2 (larger, warm) tiers
2. Promote from L2 to L1 on access
3. Add metrics (`TRANSFORM_CACHE_L1_HITS`, etc.)
4. Replace existing `transform_cache` usage

**Verification**: Benchmark cache hit rates.

---

### W10-4: RFC 7234 Proxy Cache

**Source**: plan33.md Phase 5
**Severity**: MEDIUM
**Files**: `src/proxy_cache/store.rs`, `src/proxy_cache/key.rs`

**Problem**: Current proxy cache doesn't fully implement RFC 7234 (Cache-Control, Vary, stale-while-revalidate).

**Fix**:
1. Define RFC 7234 `CacheKey` with Vary support
2. Update `ProxyCacheEntry` with RFC 7234 fields
3. Implement proper `get()` with Vary handling and stale-while-revalidate
4. Implement proper `insert()` with Cache-Control parsing

**Verification**: Test RFC 7234 compliance with various Cache-Control headers.

---

### W10-5: Global Upstream Connection Pooling

**Source**: plan9.md Issue #5
**Severity**: MEDIUM
**Files**: `src/upstream/pool.rs`

**Problem**: Per-site connection pools mean sites with identical backends use separate pools.

**Fix**: Add global pool registry (DashMap keyed by backend URL). Share pools for sites with identical backends.

**Verification**: Configure two sites with same backend, verify shared pool.

---

### W10-6: Connection Limits Configurability

**Source**: plan9.md Issue #4
**Severity**: MEDIUM
**Files**: `src/tcp/listener.rs`

**Problem**: TCP backlog at line 357 is hardcoded to 1024. Should be configurable.

**Fix**: Add `tcp_backlog` config option with default 4096. Document OS-level tuning (`net.core.somaxconn` on Linux).

**Verification**: Configure custom backlog, verify applied.

---

## Wave 11: Testing & Coverage

### W11-1: Fix Failing Drain Test

**Source**: plan34.md Phase 1
**Severity**: HIGH
**Files**: `src/worker/drain_state.rs`

**Problem**: `test_drain_completes_on_last_connection_decrement` at lines 293-307 expects `drain_complete=true` without calling `stop_accepting()` first. The test logic is wrong.

**Fix (Option A — recommended)**: Update test to call `stop_accepting()` before checking `drain_complete`.

**Verification**: `cargo test --lib -- worker::drain_state::tests --test-threads=1` — expect 8 passed.

---

### W11-2: Socket Handoff E2E Tests

**Source**: plan34.md Phase 2
**Severity**: MEDIUM
**Files**: NEW `tests/socket_handoff_test.rs`

**Problem**: No E2E tests for socket handoff (critical for zero-downtime upgrades).

**Fix**: Create test file covering: server bind, client connect, FD transfer, dual-master handoff.

**Verification**: `cargo test --test socket_handoff_test`.

---

### W11-3: Upgrade Flow E2E Tests

**Source**: plan34.md Phase 3-4
**Severity**: MEDIUM
**Files**: NEW `tests/upgrade_flow_test.rs`

**Problem**: No E2E tests for upgrade protocol. Only 6 unit tests for rollback.

**Fix**: Create test file with 12+ scenarios: stage→apply→drain→commit, failure injection, rollback, dual-master, state transitions.

**Verification**: `cargo test --test upgrade_flow_test`.

---

### W11-4: Health Checker Async Tests

**Source**: plan34.md Phase 5
**Severity**: MEDIUM
**Files**: `tests/integration_test.rs`

**Problem**: Health checker async methods are untested (only struct-level tests exist).

**Fix**: Add 5 async test scenarios using mock HTTP server.

**Verification**: `cargo test --test integration_test -- health_checker_tests`.

---

### W11-5: Overseer→Master IPC Tests

**Source**: plan35.md Phase 2
**Severity**: MEDIUM
**Files**: NEW `tests/overseer_health_check_test.rs`

**Problem**: No tests for overseer→master IPC health check flow.

**Fix**: Create test file with 7 scenarios using mock master.

**Verification**: `cargo test --test overseer_health_check_test`.

---

### W11-6: WASM Regex Pre-compilation

**Source**: plan7.md P2.1-P2.4
**Severity**: MEDIUM
**Files**: `src/serverless/routing.rs`

**Problem**: Regex at lines 22-26 compiled on every route match. At 500K rps this is significant overhead.

**Fix**:
1. Add `compiled_regex` field to `ServerlessRoute`
2. Pre-compile on route registration
3. Add route caching with `DashMap`

**Verification**: Benchmark route matching.

---

### W11-7: Remote Execution Retries

**Source**: plan7.md P2.5-P2.7
**Severity**: MEDIUM
**Files**: `src/http/server.rs`, `src/mesh/transports/manager.rs`

**Problem**: Remote WASM execution at `http/server.rs:1854-1917` has no retry logic. Single provider failure = request failure.

**Fix**:
1. Add exponential backoff retry for remote execution
2. Add multi-provider selection (weighted random)
3. Add timeout to mesh invocation

**Verification**: Test with provider failures.

---

## Wave 12: Dependency Updates

### W12-1: hickory-recursor Migration

**Source**: plan31.md
**Severity**: HIGH (security — RUSTSEC-2026-0106)
**Files**: `Cargo.toml`, `src/dns/resolver.rs`

**Problem**: RUSTSEC-2026-0106 — DNS cache poisoning vulnerability. `hickory-recursor` is deprecated.

**Fix**: Migrate to `hickory-resolver 0.26` with `recursor` feature:
1. Update `Cargo.toml` dependencies (lines 113-115)
2. Update `HickoryRecursor` import at `resolver.rs:585-586`
3. Update constructor at `resolver.rs:668-681`
4. Update resolve call at `resolver.rs:889-893`
5. Update DNSSEC validation at `resolver.rs:905-918`
6. Update error type imports

**Verification**:
- `cargo test --test dns_server_test --features dns`
- `cargo test --test dns_recursive_test --features dns`
- `cargo test --lib --features dns -- --test-threads=1`

---

### W12-2: utoipa 4 → 5 Upgrade

**Source**: plan17.md 1.1
**Severity**: MEDIUM
**Files**: `Cargo.toml`, `src/admin/`

**Problem**: utoipa 4 has `proc-macro-error` dependency (RUSTSEC-2024-0370). Need upgrade to utoipa 5.

**Fix**: Update Cargo.toml, update any deprecated API usage across admin handlers.

**Verification**: `cargo check` after upgrade.

---

### W12-3: Monitor yara-x/wasmtime

**Source**: plan31.md, plan17.md
**Severity**: INFO (monitoring)
**Files**: `Cargo.toml`

**Problem**: yara-x 1.15.0 pulls wasmtime 40.0.4 (vulnerable). Direct dependency is wasmtime 42.0.2 (patched).

**Fix**: Wait for yara-x 1.16.0 with wasmtime 43.0.1+. No action needed now — direct wasmtime patch is in place.

---

### W12-4: SECURITY.md Update

**Source**: plan31.md
**Severity**: LOW
**Files**: `SECURITY.md`

**Fix**: Add DNS cache poisoning entry, update yara-x/wasmtime section, add wasm-pow KyberSlash assessment, add hickory migration note.

---

## Wave 13: Platform & Documentation

### W13-1: BSD Service Module

**Source**: plan29.md Phase 2
**Severity**: LOW
**Files**: NEW `src/platform/service/bsd_service.rs`

**Problem**: BSD service management at `stub_service.rs:166-179` returns "not implemented".

**Fix**: Create BSD service module with rc.d script generation (FreeBSD), sysrc support, rcctl support (OpenBSD).

**Verification**: Manual testing on BSD VM.

---

### W13-2: Cross-Platform Sandbox Investigation

**Source**: plan29.md Phase 3
**Severity**: LOW
**Files**: `src/platform/sandbox.rs`

**Problem**: `StubSandbox` at lines 138-177 provides no enforcement on non-Linux platforms.

**Fix**: Investigate `nono` crate for cross-platform sandboxing. Create PlatformSandbox trait extension with macOS Seatbelt, FreeBSD Capsicum.

**Verification**: Test sandbox restrictions on each platform.

---

### W13-3: Documentation Updates

**Source**: plan22.md 5.1-5.2, plan5.md
**Severity**: LOW
**Files**: Documentation files

**Fix**:
1. Update `AGENTS.md` compile blocker notice (lines 357-364 — already fixed but notice may remain)
2. Document mesh module architecture
3. Document DNS module architecture
4. Create `docs/WEB_APP_STACK.md`
5. Create `docs/MESH_SECURITY_MODEL.md` and `docs/CAPABILITIES.md`
6. Update `docs/THREAT_INTEL.md:327` (discrepancy resolved by W4-1 fix)

---

### W13-4: Per-Site Memory Limits

**Source**: plan9.md Issue #6
**Severity**: LOW
**Files**: `src/proxy_cache/store.rs`

**Problem**: No per-site cache quotas. One site can monopolize cache memory.

**Fix**: Add per-site cache quotas and memory tracking.

**Verification**: Test that site A cannot exceed its quota.

---

### W13-5: WAF Check Timing Metrics

**Source**: plan9.md Issue #8
**Severity**: LOW
**Files**: `src/waf/mod.rs`

**Problem**: No timing histograms for individual WAF checks. Hard to identify which checks are slow.

**Fix**: Add timing metrics to each WAF check function.

**Verification**: Verify timing metrics in admin API.

---

## Implementation Notes for Sub-Agents

### Parallelization Strategy

Items within the same wave are **independent** and can be assigned to different sub-agents simultaneously. Waves are ordered by dependency:

1. **Wave 1** (Security): No dependencies, start immediately
2. **Wave 2** (WASM): No dependencies on Wave 1, can run in parallel with Wave 1
3. **Wave 3** (Performance): Independent of Waves 1-2, can run in parallel
4. **Wave 4** (Mesh): W4-1 depends on W2-4; others independent
5. **Wave 5** (DNS): Independent
6. **Wave 6** (Proxy): W5-1 depends on W1-6; others independent
7. **Wave 7** (Quality): Independent
8. **Wave 8** (Dead Code): Independent
9. **Wave 9** (Admin): Independent
10. **Wave 10** (Caching): W10-4 depends on W3-4; others independent
11. **Wave 11** (Testing): W11-1 should be done early
12. **Wave 12** (Dependencies): W12-1 is security-critical, can start early
13. **Wave 13** (Platform/Docs): Lowest priority

### Recommended Parallel Execution

**Batch A** (can all run simultaneously):
- W1-1, W1-2, W1-3, W1-4, W1-5 (security, independent)
- W1-6, W1-7 (security, independent)
- W11-1 (quick test fix)

**Batch B** (can run after Batch A or in parallel with unrelated items):
- W2-1 through W2-7 (WASM security)
- W3-1 through W3-16 (performance)
- W12-1 (dependency security)

**Batch C** (can run after Batch B):
- W4-1 through W4-17 (mesh)
- W5-1 through W5-6 (proxy)
- W6-1 through W6-4 (DNS)

**Batch D** (can run in parallel with Batch C):
- W7-1 through W7-9 (code quality)
- W8-1 through W8-6 (dead code)
- W9-1 through W9-7 (admin)
- W11-2 through W11-7 (testing)

**Batch E** (lower priority):
- W10-1 through W10-6 (caching)
- W12-2 through W12-4 (dependencies)
- W13-1 through W13-5 (platform/docs)

### Per-Item Checklist for Sub-Agents

For each item:
1. Read the referenced source file and understand the context
2. Implement the fix as described
3. Run `cargo check` to verify compilation
4. Run `cargo clippy --lib -- -D warnings` to verify no warnings
5. Run `cargo fmt` to format
6. Run relevant tests as specified in the item
7. Report: what was changed, any deviations from the plan, any issues found

---

*This consolidated plan was created by analyzing all 35 individual plan files (plan3.md through plan35.md, fix_c5.md) and verifying claims against the current codebase. Inaccurate items have been removed and corrections applied.*
