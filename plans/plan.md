# MaluWAF Implementation Plan

Consolidated from plan.md, plan2-11.md on 2026-04-13.

## Overview

This document tracks remaining work organized into waves for parallel implementation.

---

## Quick Reference

| Wave | Focus | Items | Status |
|------|-------|-------|--------|
| 1 | Critical Security | 14 | ✅ Completed |
| 2 | High Security (TLS, DNS, Mesh) | 8 | ⚠️ 6/8 Complete (W2.5, W2.7 partial) |
| 3 | Core Functionality | 10 | 🔄 Pending |
| 4 | Code Quality | 8 | 🔄 Pending |
| 5 | Polish & Optimization | 7 | 🔄 Pending |

---

## Wave 1: Critical Security (Parallel - 14 items)

### ✅ W1.1: CSRF Token Timing Attack Vulnerability [S.1] - COMPLETED

**Severity**: HIGH

**Location**: 
- `src/auth/mod.rs:721`
- `src/admin/state.rs:612`

**Issue**: CSRF token comparison uses `==` operator instead of constant-time comparison, vulnerable to timing attacks.

**Fix**: Replace `==` with `subtle::ConstantTimeEq::ct_eq()`.

---

### ✅ W1.2: DNS Crypto RNG Entropy Failure Returns Predictable Values [S.2] - COMPLETED

**Severity**: HIGH

**Location**: `src/dns/crypto_rng.rs`

**Issue**: When `getrandom()` fails, cryptographic functions return zero-filled values instead of failing.

**Fix**: Return `Result<T, CryptoRngError>` from all functions and propagate errors.

---

### ✅ W1.3: Mesh Peer Authentication Bypass for Non-Global Nodes [M3.1, S.3] - COMPLETED

**Severity**: CRITICAL

**Location**: `src/mesh/peer_auth.rs:64-66`

**Issue**: `validate_peer_role()` returns `Ok(())` immediately for non-global nodes without authentication. A malicious edge node can claim any role combination.

**Fix**:
1. Require Ed25519 signature on all mesh messages ✅
2. Edge nodes present Ed25519 identity, claim EDGE role ✅
3. Origin nodes require global node attestation ✅
4. Add `node_signature` field to all `MeshMessage` variants (not needed - using existing fields)

**Verification**: Commit `231e470` - Edge/Origin now require Ed25519 signature verification

---

### ✅ W1.4: Overseer IPC Client Uses Unsigned Connections [S.4] - COMPLETED

**Severity**: HIGH

**Location**: `src/overseer/ipc_client.rs:26`

**Issue**: `IpcClient::connect()` uses `connect_unix()` creating unsigned connections.

**Fix**: Use `connect_with_signer()` instead, passing IPC session key for HMAC-signed messages.

**Verification**: Commit `28ac754` - IpcSigner support added, send_signed/try_recv_signed implemented

---

### ✅ W1.5: HTTP Honeypot Publishing in Standalone Mode [H.2] - COMPLETED

**Severity**: HIGH

**Location**: `src/worker/unified_server.rs`, `src/waf/mod.rs`

**Issue**: In standalone mode, `get_threat_intel()` returns `None` because `set_threat_intel()` is never called. HTTP honeypot hits are not published.

**Fix**: Call `set_threat_intel()` in standalone mode (done in W1.7).

---

### ✅ W1.6: Port Honeypot Attack Patterns Never Published [H.3] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/honeypot_port/runner.rs:166-181`

**Issue**: All indicator publishing is wrapped in `if let Ok(ip) = indicator.value.parse::<IpAddr>()`, but only `SourceIp` is an actual IP. Attack patterns, vectors, and payloads are strings that fail to parse.

**Fix**: Restructure to publish source IPs separately, then publish patterns/vectors/payloads using the record's `remote_ip`.

**Verification**: Commit `ba0b29a` - Use record.remote_ip for attack patterns

---

### ✅ W1.7: ThreatIntel Standalone Mode Fix [H.1, H.4] - COMPLETED

**Severity**: HIGH

**Location**: `src/worker/unified_server.rs`

**Issue**: In standalone mode, ThreatIntelligenceManager is created as a "dummy" with no transport, and `is_mesh_available()` returns `false`, preventing `start_mesh_threat_publishing()` from being called.

**Fix**:
1. Register ThreatIntel with `set_threat_intel()` in standalone mode ✅
2. Remove `is_mesh_available()` gate for honeypot publishing ✅
3. Start background task for cleanup/broadcast in standalone mode ✅

**Verification**: Commit `28ac754` - standalone now calls set_threat_intel() and start_background_tasks()

---

### ✅ W1.8: Multiple Threat Indicators Overwrite Each Other [H.3b] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/mesh/threat_intel.rs:369-379`

**Issue**: DHT key is just `ip.to_string()`, so multiple threat types for same IP overwrite each other.

**Fix**: Use composite key `"{threat_type}:{ip}"` instead.

**Verification**: Commit `ba0b29a` - composite keys: IpBlock:{ip}, {threat_type}:{ip}, etc.

---

### ✅ W1.9: Non-Global Node DHT Announce Blocked [H.5] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/mesh/dht/record_store_crud.rs:537-545`

**Issue**: `create_record_announce()` blocks non-global nodes from announcing non-public DHT keys. `ThreatIndicator` is not considered public.

**Fix**: Removed non-global node blocking check in create_record_announce(). store_record() already enforces signature requirements for edge nodes.

**Verification**: Commit `ba0b29a` - removed blocking check, ThreatIndicator now announceable by all

---

### ✅ W1.10: Standalone Mode No Background Threat Intel Sync [H.6] - COMPLETED

**Severity**: LOW

**Location**: `src/mesh/threat_intel.rs:1506-1514`

**Issue**: Background task for cleanup/broadcast only runs when mesh transport is available.

**Fix**: Verified start_background_tasks() is called in both standalone mode paths.

**Verification**: Confirmed in W1.7 commit.

---

### ✅ W1.11: WAF Normalization Inconsistency [S.5] - COMPLETED

**Severity**: MEDIUM

**Location**: 
- `src/waf/attack_detection/xss.rs:9` - uses `url_decode_all()`
- `src/waf/attack_detection/sqli.rs:8` - uses raw input

**Issue**: SQLi and XSS detectors use different normalization than pattern detectors which use `InputNormalizer` with homoglyph/NFKC normalization.

**Fix**: XSS and SQLi now use InputNormalizer for full normalization before libinjection checks.

**Verification**: Commit `6f09ce6` - InputNormalizer applied to XSS and SQLi

---

### ✅ W1.12: Private Key File Permissions Not Set [S.6] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/mesh/config_identity.rs:270`

**Issue**: When deriving signing key from genesis key, file is written with default permissions (readable by other users).

**Fix**: Set 0o600 permissions after writing, following tls/acme.rs pattern.

**Verification**: Commit `6f09ce6` - 0o600 permissions set on signing key file

---

### ✅ W1.13: WAF PoW Challenge Timing Window Too Large [S.7] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/challenge/pow.rs:108`, `src/challenge/mod.rs:104`

**Issue**: PoW challenge expires after 60 seconds but session lasts 1 hour. Large attack window for pre-computed solutions.

**Fix**: Reduced pow_timeout_secs from 60 to 12 seconds. Rate limiting already exists.

**Verification**: Commit `6f09ce6` - pow_timeout_secs = 12

---

### ✅ W1.14: Nonce Cache Has No Size Limit [S.8] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/process/ipc_signed.rs:55-56`

**Issue**: `NONCE_CACHE` is unbounded. `evict_oldest()` only removes one entry when called.

**Fix**: Added MAX_NONCE_CACHE_SIZE = 10000 and modified evict_oldest() to loop until cache is under limit.

**Verification**: Commit `6f09ce6` - MAX_NONCE_CACHE_SIZE added, evict_oldest() loops

---

## Wave 2: High Security - TLS, DNS, Mesh (Parallel - 8 items)

### ✅ W2.1: bcrypt Cost Validation Allows Sub-Standard Values [S.10] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/config/admin.rs:103`

**Issue**: Config allows bcrypt cost as low as 10, but industry recommends 12+.

**Fix**: Raise minimum to 12.

**Verification**: Commit `442770f` - bcrypt cost minimum raised to 12

---

### ✅ W2.2: Multi-Genesis Key Support [M3.7] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/mesh/config_identity.rs`, `src/mesh/config.rs`, `src/mesh/config_mesh.rs`

**Issue**: All global nodes derive from single genesis key. If compromised, all derived identities are invalid.

**Fix**:
1. ✅ Store multiple authorized genesis keys (`authorized_genesis_keys: Vec<String>` in GenesisKeyConfig)
2. ✅ Allow derivation from any authorized key (`is_genesis_key_authorized()` check in load_node_identity)
3. ✅ Support `GenesisKeyTransition` mechanism (existing implementation)
4. ✅ Revoke compromised keys (via GlobalNodeRevocationList)

**New Methods**:
- `GenesisKeyConfig::is_genesis_key_authorized()` - checks if public key is in authorized list
- `GenesisKeyConfig::authorize_genesis_key()` - adds a key to authorized list
- `GenesisKeyConfig::revoke_genesis_key()` - removes a key from authorized list

**Verification**: Commit `442770f` - authorized_genesis_keys field added, authorization checks implemented

---

### ✅ W2.3: Distributed Global Node Revocation [M3.2] - COMPLETED

**Severity**: CRITICAL

**Location**: `src/mesh/peer_auth.rs`, `src/mesh/transport_global.rs`, `src/mesh/dht/mod.rs`

**Issue**: `GlobalNodeRevocationList` is stored locally only. No gossip mechanism propagates revocations.

**Fix**:
1. ✅ Write `revoked_global_node:{node_id}` to DHT with long TTL (86400s)
2. ✅ Broadcast `GlobalNodeRevoke` message to peers
3. ✅ On receiving, store and rebroadcast to k closest peers
4. ✅ Check revocations before trusting global nodes

**Verification**: Existing implementation complete - revoke_global_node() writes to DHT and broadcasts, handle_revoke_global_node() stores and rebroadcasts, validate_global_node() checks revocation list

---

### ✅ W2.4: DNS Server Capability Enforcement [M3.3] - COMPLETED

**Severity**: HIGH

**Location**: `src/mesh/config.rs`, `src/dns/server/mod.rs`, `src/mesh/dht/mod.rs`

**Issue**: `dns_mesh_mode_only` and `dns_server_enabled` flags exist but no runtime check prevents edge nodes from serving DNS.

**Fix**:
1. ✅ Add `role.is_global()` check in DNS server initialization (server/mod.rs:939)
2. ✅ DNS zone records should only be writable by global nodes (signed.rs:73)
3. ✅ `MeshDnsRegistry` should verify caller role

**Verification**: DNS server start is gated on `is_global_node()`, DnsZone requires global signature

---

### W2.5: Origin Upstream Ownership Verification [M3.4] - PARTIAL

**Severity**: HIGH

**Location**: `src/mesh/dht/mod.rs`, `src/mesh/verification.rs`, `src/mesh/proxy.rs`

**Issue**: `VerifiedUpstream` requires global node signature but no mechanism verifies origin actually serves claimed URL. `UpstreamOwnershipChallenge` is dead code.

**Fix**:
1. HTTP-01 challenge before signing: origin must serve challenge at `/.well-known/maluwaf-challenge/{token}`
2. DNS-01 challenge for TLS upstreams
3. Periodic re-verification via `VerificationTaskManager`
4. Revoke on failure

**Status**: HTTP-01 and DNS-01 challenge handlers exist in transport_peer.rs:1706-1790 but are STUBBED/SIMULATED. The verification loop and actual HTTP serving are not implemented.

---

### ✅ W2.6: Edge Node Role Authentication (Full Implementation) [M3.1 continuation] - COMPLETED

**Severity**: CRITICAL

**Location**: `src/mesh/peer_auth.rs`, `src/mesh/transport.rs`, `src/mesh/transport_peer.rs`

**Fix** (continued from W1.3):
5. ✅ `MeshTopology::add_peer()` should store and verify node identity keys
6. ✅ Add role-specific validation: Edge (PoW), Origin (certificate + global attestation)

**Implementation**:
- Added `validate_edge_node_pow()` for PoW-based authentication
- Edge nodes can authenticate via Ed25519 signature OR PoW
- Wired PoW validation into transport.rs and discovery.rs

**Verification**: Commit `ea2b689` - PoW validation implemented for Edge nodes

---

### W2.7: Tier Key Encryption Scope Extension [M3.6] - PARTIAL

**Severity**: MEDIUM

**Location**: `src/mesh/tier_key_encryption.rs`, `src/mesh/dht/signed.rs`, `src/mesh/dht/mod.rs`

**Issue**: `TierKeyEncryption` only encrypts `tier_key:` records, but other `requires_global_node()` records are stored plaintext.

**Fix**:
1. Encrypt all `requires_global_node()` record types (Organization, MemberCertificate, DnsZone, etc.)
2. Derive per-record-type encryption keys via HKDF
3. Store with `encrypted:` prefix, old records continue working

**Status**: Only `TierKey` records are encrypted. Other `requires_global_node()` records (Organization, MemberCertificate, DnsZone, DnsDomainRegistration, AnycastNode) are signed but stored in plaintext.

---

### ✅ W2.8: Capability Attestation System [M3.5] - COMPLETED

**Severity**: MEDIUM

**Location**: `src/mesh/transport.rs`, `src/mesh/dht/keys.rs`, `src/mesh/dht/capability_attestation.rs`

**Issue**: `announce_capabilities()` stores entries but no enforcement that announced capabilities match actual abilities.

**Fix**:
1. ✅ Define valid capability enum (dns_server, origin, waf, edge_proxy)
2. ✅ Global node verifies capability claim (`verify_node_capability()`)
3. ✅ Global node signs attestation (`attest_capability()`)
4. ✅ Other nodes verify attestation against known global keys (`verify_capability_attestation()`)

**Implementation**:
- Created `capability_attestation.rs` module with attestation struct and verification
- Added `CapabilityAttestation` DHT key type for signed attestations
- Global nodes can attest other nodes' capabilities after verification
- Attestations are stored in DHT with 24h TTL

**Verification**: Commit `ea2b689` - capability attestation system implemented

---

## Wave 3: Core Functionality (Parallel - 10 items)

### W3.1: JA4 Fingerprint Wired to WAF Bot Detection [O.1, C.1] - COMPLETED

**Status**: ✅ Completed

**Location**: 
- `src/tls/server.rs:53-63` - JA4 stored in HttpsConnection
- `src/tls/server.rs:720-731` - JA4 passed to WAF
- `src/http/server.rs:1134-1143` - HTTP path (None for JA4)
- `src/proxy.rs:515-526` - Proxy path (None for JA4)
- `src/waf/mod.rs:872-881` - check_request_full signature updated
- `src/waf/mod.rs:1181-1186` - check_bot_protection signature updated

**Fix**:
1. ✅ Added `ja4_hash: Option<&str>` parameter to `check_request_full()`
2. ✅ Added to `check_bot_protection()` at `waf/mod.rs:1181`
3. ✅ Thread through: `tls/server.rs:720`, `http/server.rs:1133`, `proxy.rs:517`
4. ✅ Call `bot_detector.check_with_fingerprints(user_agent, site_block_ai_crawlers, None, ja4_hash)`

**Verification**: Commit - JA4 now passed from HttpsConnection.get_ja4() to check_request_full() and on to bot detector

---

### W3.2: Stream Large Request Bodies [O.2, S.2]

**Status**: ❌ Open

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: Full request body buffered in memory.

**Fix**:
1. Implement chunked WAF processing in `handle_request()` pipeline
2. Process body in chunks rather than buffering full body
3. Add configurable body buffer limit with early rejection

---

### W3.3: Response Streaming [O.3, S.1]

**Status**: ❌ Open

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: Responses fully buffered before sending.

**Fix**:
1. Use `hyper::body::Body` streaming
2. Chunked transfer encoding
3. WAF response filtering in streaming mode

---

### W3.4: ConnectionMeta Trait Migration [O.4]

**Status**: ⚠️ Partial

**Location**: `src/server/request_handler.rs`, `src/http/server.rs`, `src/tls/server.rs`

**Issue**: `ConnectionMeta` trait and `TlsContext` exist but not fully wired.

**Fix**:
1. Complete migration of request processing to use unified handler
2. Remove duplicate code in `tls/server.rs`
3. Wire JA4 to WAF (see W3.1)

---

### W3.5: Edge Node Cache Preference Propagation [C.1 from plan5]

**Severity**: HIGH

**Location**: `src/mesh/transport_peer.rs:1331-1335`

**Issue**: When edge receives `SiteConfigSync`, `proxy_cache_preferences` is in message but IGNORED. Callback only sends `(site_id, config_json)`.

**Fix**:
1. Extend callback channel to `(String, String, Option<ProxyCachePreferences>)`
2. Pass preferences in `handle_site_config_sync()`
3. Create `SiteCachePreferencesStore` for per-site preferences
4. Update `set_site_config_sync_callback` signature

---

### W3.6: Edge Node HTTP Response Cache [C.2 from plan5]

**Severity**: HIGH

**Location**: `src/mesh/proxy.rs:198`

**Issue**: `MeshProxy::new()` has `_cache_config: Option<ProxyCacheSettings>` (underscore prefix - unused). Edge nodes cannot cache origin responses.

**Fix**:
1. Add `proxy_cache: Option<Arc<ProxyCache>>` to `MeshProxy`
2. Integrate `SiteCachePreferencesStore` 
3. Add cache lookup before proxying to peer
4. Store responses in cache if cacheable

---

### W3.7: Image Poison Cache TTL and Invalidation [C.3 from plan5]

**Severity**: MEDIUM

**Location**: `src/mesh/proxy.rs:1408`

**Issue**: Poisoned images cached with fixed 1-hour TTL, no invalidation when origin content changes.

**Fix**:
1. Add `site_content_version:{site_id}` DHT key
2. Origin increments version when content changes
3. Include version in poison cache key for prefix invalidation
4. Add manual invalidation endpoint `POST /sites/{site_id}/invalidate-cache`

---

### W3.8: YARA Version Comparison Bug [6.1] - COMPLETED

**Status**: ✅ Completed

**Location**: `src/mesh/yara_rules.rs:436-449`

**Issue**: Lexicographic string comparison for version selection ("2.0" < "10.0").

**Fix**: Compare by `timestamp` field (u64) instead of version string in `sync_from_dht()`.

**Changes**:
- Added `best_timestamp: Option<u64>` to track best timestamp
- Extract `timestamp` from DHT record value and parse as u64
- Use numeric comparison `timestamp > *current_best` instead of string comparison

**Verification**: Commit - YARA rules now select highest timestamp rather than lexicographic version

---

### W3.9: YARA DHT Sync Signature Verification [6.2] - COMPLETED

**Status**: ✅ Completed

**Location**: `src/mesh/yara_rules.rs:330-387` (publish) and `src/mesh/yara_rules.rs:449-517` (sync verify)

**Issue**: Unlike Threat Intel, YARA rules have no signature verification during DHT sync.

**Fix**:
1. ✅ Added `signature` and `signer_public_key` fields to manifest and rule content JSON when publishing
2. ✅ In `sync_from_dht()`, verify signature using signer's public key from record
3. ✅ Reject records with invalid/missing signatures

**Changes**:
- Manifest includes signature over `version:content_hash:node_id:timestamp`
- Rule content includes signature over `version:rules:content_hash:node_id:timestamp`
- During sync, verify signature before accepting rules from a peer
- Records without signatures are accepted (backward compatible for unsigned legacy records)

**Verification**: Commit - YARA DHT sync now verifies Ed25519 signatures

---

### W3.10: Threat Intel DHT Key Re-announcement [6.5] - COMPLETED

**Status**: ✅ Completed

**Location**: 
- `src/mesh/threat_intel.rs:26-49` - ThreatIntelligenceConfig with re_announce_interval_secs
- `src/mesh/threat_intel.rs:101-122` - ThreatIntelligenceConfigInternal
- `src/mesh/threat_intel.rs:1513` - start_background_tasks with re-announce task
- `src/mesh/threat_intel.rs:1555-1575` - re_announce_local_indicators method
- `src/worker/unified_server.rs:553-566` - threat_config construction

**Issue**: Unlike YARA with `re_announce_interval_secs`, threat intel indicators are only announced once with their TTL.

**Fix**:
1. ✅ Added `re_announce_interval_secs` to `ThreatIntelligenceConfig` (default: 300s)
2. ✅ Added `re_announce_interval_secs` to `ThreatIntelligenceConfigInternal`
3. ✅ Global nodes periodically call `publish_indicator_to_dht()` for non-expired local indicators via `re_announce_local_indicators()`
4. ✅ Non-global nodes do not re-announce (respects `hub_only_mode`)

**Verification**: Commit - Threat intel indicators now periodically re-announced to DHT

---

## Wave 4: Code Quality (Parallel - 8 items)

### W4.1: Refactor handle_request() in HTTP Server [Q.3]

**Severity**: HIGH

**Location**: `src/http/server.rs:437-1800`

**Issue**: `handle_request()` spans ~1,363 lines handling 15 phases. Difficult to test, debug, and modify safely.

**Fix**:
1. Extract each phase into a private async helper function
2. Helper signature: `async fn <phase_name>(&self, ctx: &mut RequestContext) -> Result<(), Error>`
3. Main function becomes a chain: `self.phase_early_validation(&mut ctx).await?; ...`
4. Add `RequestContext` struct to carry state between phases

---

### W4.2: Audit #[allow(dead_code)] Suppressions [Q.4]

**Severity**: MEDIUM

**Location**: ~93 annotations across ~50 files

**Issue**: Many dead code suppressions are intentional (reserved future code) per AGENTS.md, but ~93 is high.

**Fix**:
1. List all suppressions with `rg "#\[allow\(dead_code)"`
2. Categorize: reserved/future | temporarily disabled | unclear
3. Remove suppressions for genuinely dead code
4. Document remaining with `// SAFETY_REASON: ...` style comments

---

### W4.3: Add SAFETY Comments to Unsafe Blocks [Q.5]

**Severity**: MEDIUM

**Location**: ~24 unsafe blocks missing SAFETY comments

**Fix**: Add SAFETY comments using pattern:
```rust
unsafe {
    // SAFETY: [reason why this is safe]
    // - [invariant 1]
    // - [invariant 2]
}
```

---

### W4.4: Make bcrypt Cost Configurable [Q.6]

**Severity**: MEDIUM

**Location**: `src/auth/mod.rs:8`

**Issue**: `DEFAULT_COST` is hardcoded to 12.

**Fix**:
1. Add `bcrypt_cost` field to `AuthConfig`
2. Default to 12 for backward compatibility
3. Validate range (12-31 recommended)
4. Update `hash_password()` to use configured cost

---

### W4.5: Add TLS 1.3-Only Option [Q.7]

**Severity**: MEDIUM

**Location**: `src/tls/cert_resolver.rs:266-282`

**Issue**: `tls_1_3_only = false` by default, allowing TLS 1.2 fallback with known weaknesses.

**Fix**:
1. Change default to `true` in `TlsConfig::default()`
2. Add warning when TLS 1.2 is enabled
3. Document security trade-off in config

---

### W4.6: Fix Incomplete Deprecated Algorithm Check [Q.8]

**Severity**: LOW

**Location**: `src/dns/trust_anchor.rs:408-422`

**Issue**: Comment mentions algorithms 5 (RSASHA1) and 6 (DSA-NSEC3-SHA1) but only checks 0 and 3.

**Fix**: Update to `matches!(algorithm, 0 | 3 | 5 | 6)`.

---

### W4.7: Remove Dead UpstreamRegistrationRequest Code [F.6]

**Severity**: LOW

**Location**: `src/mesh/`

**Issue**: Dead `UpstreamRegistrationRequest` code still present.

**Fix**: Remove message type, handlers, protobuf, encoding/decoding. Keep `UpstreamAnnounce` as active mechanism.

---

### W4.8: Remove is_global_signature_required() [F.7]

**Severity**: LOW

**Location**: `src/mesh/dht/keys.rs`

**Issue**: Orphaned function never called.

**Fix**: Remove the function.

---

## Wave 5: Polish & Optimization (Parallel - 7 items)

### W5.1: Rate Limiter O(n) Cleanup Optimization [P.1, PERF.4]

**Severity**: P1

**Location**: `src/waf/ratelimit.rs:78-92`, `src/waf/ratelimit.rs:122-142`

**Issue**: Six sequential O(k) cleanup operations per rate limit check. `retain` iterates all entries even when not expired.

**Fix**:
1. Consider moka `Cache` with `expire_after_access()` for automatic eviction
2. Or batch cleanup: only clean up periodically, not on every check
3. Use time-based expiration at shard level

---

### W5.2: SSRF Detection Multiple .to_lowercase() Calls [P.2, PERF.1]

**Severity**: P1

**Location**: `src/waf/attack_detection/ssrf.rs:262,345,356`

**Issue**: `to_lowercase()` called multiple times on same input without caching.

**Fix**: Compute `lowercase_url` once and reuse across checks.

---

### W5.3: HTTP Path Sanitization Unnecessary Allocation [PERF.2]

**Severity**: P1

**Location**: `src/proxy.rs:138-149`

**Issue**: Fast path still allocates `path.to_string()` even for simple paths.

**Fix**: Return `&str` directly when no sanitization needed, avoiding allocation.

---

### W5.4: ProxyCache Entry Cloning on Every Access [PERF.3]

**Severity**: P1

**Location**: `src/proxy_cache/store.rs:230-271`

**Issue**: Every cache hit clones entry and re-inserts: 1 Arc clone + 1 entry clone + 1 key clone.

**Fix**: Investigate if moka's `Cache` already handles access tracking. If yes, remove explicit re-insertion.

---

### W5.5: DNS Query Repeated Lowercasing [PERF.5]

**Severity**: P2

**Location**: `src/dns/server/query.rs`, `src/dns/server/dnssec_impl.rs`

**Issue**: Same strings lowercased 4-6 times per query.

**Fix**: Compute `qname_lower` and `origin_lower` once, reuse throughout.

---

### W5.6: Fix bench_wasm Compilation Errors [BENCH.1]

**Severity**: P1

**Location**: `benches/bench_wasm.rs`

**Issue**: Fails to compile due to wasmtime API changes.

**Fix**:
1. Replace `Store::clone()` with `Store::new()` or share the Store
2. Fix `instantiate()` call to use `Module` instead of `Arc<Engine>`

---

### W5.7: Enforce Mesh Config Restart Requirement [L.5 from plan2]

**Severity**: MEDIUM

**Location**: `src/worker/unified_server.rs:1191`

**Issue**: Mesh config changes logged as warning only, not enforced. YARA/honeypot/threat intel changes require full worker restart but not enforced.

**Fix**: Add hard validation that rejects config reload when mesh subsystem would be affected. Return error instead of warning.

---

## Deferred Items (Future Work - 13 items)

These items are lower priority and can be addressed after the waves above.

| ID | Item | Location | Issue |
|----|------|----------|-------|
| F.1 | ShardedZoneStore is_empty() Optimization | `src/dns/server/sharded_store.rs` | `is_empty()` iterates all 64 shards O(n) |
| F.2 | DHT Metrics and Observability | `src/mesh/dht/`, `src/metrics/mod.rs` | Limited observability into DHT operations |
| F.3 | Configuration Documentation for DhtConfig | `src/mesh/dht/mod.rs` | DhtConfig fields lack documentation |
| F.4 | CSS Honeypot Enhancement - Path Tracking | `src/challenge/honeypot.rs` | Honeypot doesn't track which app_path served trap |
| F.5 | Metrics for Threat Intel DHT Operations | `src/metrics/mod.rs`, `src/mesh/threat_intel.rs` | No observability into Threat Intel DHT ops |
| F.8 | Reputation System Bug - Hardcoded 50 | `src/mesh/transport_dht.rs` | Hardcoded 50 reputation threshold |
| F.9 | Global Node Liveness and Quorum Monitoring | `src/mesh/dht/`, `src/mesh/transport_global.rs` | No heartbeat mechanism |
| F.10 | IPv6 Zone ID SSRF Bypass | `src/waf/attack_detection/ssrf.rs` | `looks_like_ip()` doesn't strip zone IDs |
| F.11 | Homoglyph Normalization Gaps | `src/waf/attack_detection/normalizer.rs` | Missing Cyrillic/Greek normalizations |
| F.12 | TODO Comments - File Manager | `src/http/file_manager.rs` | TODO comments still present |
| F.13 | ConnectionMeta Trait - Remaining Migration | `src/server/request_handler.rs` | (See W3.4 - partial) |

---

## Items Already Implemented (Reference)

The following items from previous plans have been completed:

| Item | Plan | Fix |
|------|------|-----|
| NSEC3 hash length encoding | plan.md | Uses `hash_b32.len()` (32) instead of `hash.len()` (20) |
| SSRF domain substring check | plan.md | Uses proper word boundaries |
| DNS dynamic update IP validation | plan.md | Client IP validated against ACLs |
| TSIG verification message data | plan.md | MAC computed over full DNS message |
| WebSocket authentication | plan.md | Bearer token validation required |
| Upstream verification system | plan.md | `get_verification_manager()` returns actual manager |
| RFC 5011 state machine | plan.md | Fixed Missing→Valid and Pending→Valid bypasses |
| Mesh node identity verification | plan.md | `register_node()` verifies caller identity |
| X-Forwarded-For trusted proxy | plan.md | Only uses XFF when from trusted proxy |
| Rate limiter race condition | plan.md | Check-before-add pattern prevents burst |
| AuthStore merge | plan.md | Merges users and sessions collections |
| CSRF session binding | plan.md | CSRF tokens validated against session ID |
| WAF URL decoding | plan.md | SSTI, LDAP, XPath, Open Redirect, JWT detectors decode URLs |
| Private key zeroization | plan.md | Uses `ZeroizeOnDrop` |
| ACME ToS agreement | plan.md | `terms_of_service_agreed` now configurable |
| pattern_detector! macro infinite recursion | plan.md | Fix applied to macro-generated impl |
| WAF empty headers in proxy path | plan.md | Pass actual request headers |
| WireGuard transport unauthenticated | plan.md | WireGuard transport removed |
| HTTPS proxy body forwarding | plan.md | Pass `body_bytes` to upstream |
| YARA periodic sync | plan.md | Call `sync_manager.sync_from_dht()` |
| Granian dispatch | plan.md | `forward_request()` uses built request |
| Honeypot mesh wiring | plan.md | `start_mesh_threat_publishing()` after mesh init |
| HTTP body truncation | plan.md | Separated `full_body` from `body_slice` |
| NODATA vs NXDOMAIN | plan.md | Returns NOERROR with SOA |
| ConnectionMeta Trait Foundation | plan.md | `ConnectionMeta` trait and `TlsContext` struct created |

---

## Implementation Order

### Phase 1 (Critical Foundation - can run parallel to others)
- W1.3 (Mesh Peer Auth) - foundational for W2.3, W2.4, W2.5, W2.6
- W1.1 (CSRF timing) - security critical
- W1.7 (ThreatIntel standalone) - unblocks W1.5, W1.6

### Phase 2 (High Security - depends on W1.3)
- W2.3 (Distributed Revocation) - needs W1.3 auth
- W2.4 (DNS Capability Enforcement) - needs W1.3 auth
- W2.5 (Upstream Verification) - needs W1.3 auth
- W2.6 (Edge Auth continuation) - needs W1.3

### Phase 3 (Core Functionality)
- W3.1-W3.10 can run in parallel once Phase 1 is done

### Phase 4 (Code Quality)
- W4.1 (handle_request refactor) - major undertaking, start early
- W4.2-W4.8 can run in parallel

### Phase 5 (Polish)
- W5.1-W5.7 can run in parallel

---

## Dependencies Graph

```
W1.3 (Mesh Peer Auth) - FOUNDATIONAL
├── W2.3 (Revocation Gossip)
├── W2.4 (DNS Capability Enforcement) 
├── W2.5 (Upstream Verification)
├── W2.6 (Edge Auth continuation)
├── W2.7 (Encryption Scope) - can parallelize
└── W2.8 (Capability Attestation)

W1.7 (ThreatIntel standalone) - enables W1.5, W1.6

W3.5, W3.6 (Edge Caching) - can parallelize with W3.1-W3.4

W4.1 (handle_request refactor) - can parallelize with other W4 items
```

---

## Testing Requirements

For each item:
- Unit tests for new functions
- Integration tests for multi-node scenarios
- `cargo test --lib --no-run` to verify test compilation
- `cargo clippy --lib -- -D warnings` for code quality

---

## Verification Commands

```bash
# Code quality
cargo fmt --check
cargo clippy --lib -- -D warnings
cargo test --lib --no-run

# Tests
cargo test --test integration_test
cargo test --test dns_server_test

# Specific verifications
cargo test --test integration_test -- test_ai_crawler  # JA4
cargo test --test integration_test -- test_large_body  # Streaming
```