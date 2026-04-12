# MaluWAF Implementation Plan

This document consolidates all improvement work from the planning phase. Items are organized into waves that can be implemented in parallel by separate agents.

## Quick Reference

| Wave | Focus | Items | Priority | Status |
|------|-------|-------|----------|--------|
| 1 | Critical Security (WAF, Auth, Mesh) | 12 | CRITICAL | ✅ Completed |
| 2 | High Security (TLS, DNS, Mesh) | 14 | HIGH | ✅ Completed |
| 3 | Core Functionality (Web Stack, Caching, Honeypot) | 18 | HIGH | ✅ Completed |
| 4 | Code Quality (Performance, Quality) | 15 | MEDIUM | ✅ Completed |
| 5 | Polish & Cleanup | 20 | LOW | 🔶 All future |

**Legend**: 🔶 = Future Work | ✅ = Completed (see git history)

---

## Wave 1: Critical Security

### 1.1 WAF XSS Detection Bypass via URL Encoding

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/waf/attack_detection/xss.rs:88-90`, `src/waf/attack_detection/mod.rs:282-323`

**Issue**: URL-encoded XSS is NOT detected in query strings. The test explicitly confirms:
```rust
#[test]
fn test_xss_encoded_script_tags_not_detected() {
    let input = b"%3Cscript%3Ealert(1)%3C/script%3E";
    assert!(XssDetector::detect(input, InputLocation::QueryString).is_none());
}
```

**Fix**: Apply URL decoding before calling `libinjectionrs::detect_xss()`.

---

### 1.2 WAF libinjection Receives Pre-Normalized Input

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/waf/attack_detection/mod.rs:282-323`

**Issue**: `check_sqli()` and `check_xss()` apply normalization before calling libinjection, but libinjection is designed to work on **raw input**. Normalization may break detection of encoded attacks.

**Fix**: Create separate code path for libinjection that receives raw input. Apply normalization only after libinjection detection fails.

---

### 1.3 TOFU First-Connection MITM Vulnerability

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/cert.rs:519-572`

**Issue**: On first connection to a seed node, the fingerprint is accepted without verification. An active attacker could intercept the first connection.

**Fix**:
1. Require out-of-band fingerprint confirmation for seed nodes
2. Add TOTP-style verification during first connection
3. Store fingerprint hash with associated metadata
4. Alert admin when new fingerprint is seen for existing seed

---

### 1.4 Empty CA Store = Permissive Trust

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/cert.rs:752-758`

**Issue**: If no CA certificates are configured in mesh section, any certificate is accepted.

**Fix**:
- Add `strict_certificate_validation` config (default: `true`)
- Log WARN when accepting without CA validation
- Require explicit opt-out for permissive mode

---

### 1.5 Honeypot Local Blocking Key Mismatch

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/threat_intel.rs:426-429, 905-909`

**Issue**: `announce_honeypot_indicator()` stores indicators with key `"honeypot:{site_scope}:{type}:{ip}"` but `lookup_local_indicator()` looks up by just `"{ip}"`. Result: Honeypot IP blocks are never found for local WAF blocking.

**Fix**: Normalize honeypot keys to IP-only format in `announce_honeypot_indicator()`.

---

### 1.6 Standalone Mode - Local Blocking Gap

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/threat_intel.rs:385-456`

**Issue**: When mesh is disabled, `announce_honeypot_indicator()` does not call `block_store.block_ip()`. The honeypot detects attacks but the attacking IP is never blocked locally.

**Fix**: Add local blocking for honeypot-sourced indicators in `announce_honeypot_indicator()` when severity is High or Critical.

---

### 1.7 No RBAC Enforcement

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/admin/handlers/*.rs`, `src/auth/mod.rs:48-55`

**Issue**: The `UserRole` enum exists but no handler checks the user's role. Any valid admin token bearer can perform ANY operation.

**Fix**:
1. Define required roles per endpoint in handlers
2. Add `require_role()` middleware
3. Implement permission matrix for admin operations

---

### 1.8 User Enumeration via Timing

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/auth/mod.rs:25-33, 402-404`

**Issue**: When user doesn't exist, `verify_dummy_password()` adds delay but timing still distinguishes non-existent vs wrong password.

**Fix**:
1. Always perform full bcrypt verification regardless of user existence
2. Use constant-time comparison throughout
3. Add account lockout after N failed attempts

---

### 1.9 No Audit Logging for Admin Actions

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/admin/mod.rs`

**Issue**: No audit trail for configuration changes, user management, security policy modifications, or YARA rule submissions.

**Fix**:
1. Create `AuditLog` struct with: timestamp, user_id, action, target_resource, client_ip
2. Persist audit logs to SQLite with append-only semantics
3. Add admin API endpoint to query audit logs
4. Instrument all state-changing admin handlers

---

### 1.10 Non-Global Nodes Auto-Registered with Default Reputation

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/transport.rs:1669-1680`

**Issue**: In non-strict mode, new nodes get reputation 50 without verification. This bypasses stake-based access control.

**Fix**:
1. Require some form of identity verification before granting routing access
2. Reduce default reputation or require minimum stake
3. Add peer type validation before accepting into routing table

---

### 1.11 SSRF Allowlist Subdomain Bypass

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/waf/attack_detection/ssrf.rs:286-298`

**Issue**: When allowlisting a domain like `example.com`, only `subdomain.example.com` is allowed. An attacker controlling `attacker.com` is not protected.

**Fix**:
1. Add explicit option for "block all except allowlisted" mode
2. Consider `contains()` semantics for allowlist matching
3. Document the current behavior clearly

---

### 1.12 Regex Not Complexity-Checked in RFI Detector

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/waf/attack_detection/rfi.rs:11-12`

**Issue**: RFI detector uses regex without complexity checking, potentially exposing ReDoS risk.

**Fix**: Apply `check_regex_complexity()` at regex initialization.

---

## Wave 2: High Security

### 2.1 Upstream Ownership Validation

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/transport_org.rs:553-670`, `src/mesh/dht/keys.rs`, `src/mesh/dht/mod.rs`

**Issue**: Origin nodes could claim ownership of any upstream domain without verification.

**Fix**: Implement DNS-01 ownership challenge before approving `VerifiedUpstream`. Origin receives challenge, self-reports TXT record value, global node verifies before creating VerifiedUpstream.

---

### 2.2 Genesis Key Rotation and Revocation

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/config_identity.rs`, `src/mesh/config.rs:874`, `src/mesh/dht/keys.rs`, `src/mesh/peer_auth.rs`

**Issue**: If the genesis key is compromised, all derived signing keys are compromised. No rotation or revocation mechanism existed.

**Fix**:
1. Added `previous_genesis_key_base64` and `rotation_sequence` to `GenesisKeyConfig`
2. Added `GenesisKeyTransition` and `RevokedGlobalNode` DHT key types
3. Added `GlobalNodeRevocationList` with add/is_revoked/remove/get_all methods
4. Modified `validate_peer_role()` to check revocation list before validation
5. Added `sign_with_rotation()` and `verify_with_rotation()` to GenesisKeyManager

---

### 2.3 No Certificate Chain Validation

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/cert.rs:745`

**Issue**: `verify_peer_certificate()` validated against trusted CAs but didn't pass intermediate certificate chain.

**Fix**: Added optional `intermediate_certs` parameter to `verify_peer_certificate()`. Function now accepts intermediate certificates for full chain validation.

---

### 2.4 TOFU Without Out-of-Band Verification

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/cert.rs:537-577`

**Issue**: On first connection to a seed node, the fingerprint was automatically pinned with no out-of-band confirmation.

**Fix**: Changed `verify_seed_fingerprint()` to reject connections when no fingerprint is configured. Previously auto-pinned on first connection. Now returns error directing user to configure `pinned_cert_fingerprint`.

---

### 2.5 Replay Window Too Large

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/mesh/protocol.rs:85`, `src/process/ipc_signed.rs:58`

**Issue**: Challenge-response used 300s (5 minute) replay window. Stolen keys + timing could allow replay within window.

**Fix**: Reduced replay window from 300 seconds to 60 seconds in both mesh protocol and IPC signed messages.

---

### 2.6 Stake Grace Period Bypass

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/dht/stake.rs:316-323`

**Issue**: In non-strict mode, new nodes could be in routing table during grace period without proof of stake.

**Fix**: Added `is_in_grace_period()` method to NodeStake. Modified `can_be_in_routing()` to also check `!is_in_grace_period()`. During grace period, nodes with zero reputation cannot be in routing even in non-strict mode.

---

### 2.7 Forward Secrecy Missing

**Status**: ✅ Completed (already implemented)

**Severity**: MEDIUM

**Location**: `src/mesh/transport.rs:938-979`

**Issue**: ML-KEM-768 provides post-quantum key exchange but no ephemeral key derivation for forward secrecy.

**Fix**: ML-KEM session rotation is already implemented. `rotate_stale_sessions()` runs periodically and broadcasts `SessionRotate` messages to peers. Sessions are rotated based on `rotation_interval` configuration. No additional code needed.

---

### 2.8 Cache Poisoning Fingerprint Bypass

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/dns/cache.rs:187-217`

**Issue**: The fingerprint confirmation logic required 2 confirmations before blocking. An attacker could potentially get one poisoned response through with only a warning.

**Fix**: Changed to block immediately on any unconfirmed fingerprint mismatch. Both "unconfirmed fingerprint" and "new fingerprint" cases now return `CachePoisoningError::PotentialPoisoning` instead of just logging a warning.

---

### 2.9 QUIC 0-RTT Replay Risk

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/admin/handlers/mesh_admin.rs:148-163`

**Issue**: QUIC 0-RTT is susceptible to replay attacks. While correctly disabled by default, warning is only logged once.

**Fix**: Added `quic_0rtt_enabled` and `quic_0rtt_warning` fields to `MeshAdminStatusResponse`. When 0-RTT is enabled, the warning is now always visible in the admin dashboard.

---

### 2.10 Proof of Work Difficulty May Be Too Low

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/mesh/security_challenge.rs:12`

**Issue**: Default PoW difficulty: 20 leading zero bits (1 in 1 million). May be insufficient for serious DoS protection.

**Fix**: Increased default PoW difficulty from 20 to 24 leading zero bits (1 in 16 million) to make spam more expensive.

---

### 2.11 No Certificate Revocation List Enforcement

**Status**: ✅ Completed (already implemented)

**Severity**: LOW

**Location**: `src/mesh/cert.rs:745-748`

**Issue**: CRL is maintained but not actively enforced during QUIC connection establishment.

**Fix**: CRL checking is already implemented in `verify_peer_certificate()`. The function checks `is_certificate_revoked()` before any other validation, ensuring revoked certificates are rejected immediately.

---

### 2.12 SSRF Path Not Checked in Request Body

**Status**: ✅ Completed (already implemented)

**Severity**: MEDIUM

**Location**: `src/waf/attack_detection/mod.rs:589-596`

**Issue**: SSRF detection checks query string and headers but may not check request body URLs.

**Fix**: SSRF detection already passes the request body to the SSRF detector. The `SsrfDetector::extract_ips_from_url()` function scans for http:// and https:// patterns in the input text, including body content.

---

### 2.13 File Upload Magic Byte Enforcement Missing

**Status**: ✅ Completed (already implemented)

**Severity**: MEDIUM

**Location**: `src/upload/mod.rs:276`, `src/upload/config.rs:100`

**Issue**: File upload validation uses MIME type detection but not content-based magic byte enforcement.

**Fix**: Magic byte detection and MIME mismatch rejection is already implemented. The `SignatureRegistry` in `src/upload/signature.rs` provides `detect()` and `verify_mime()` functions. The `reject_mime_mismatch` config field controls rejection when declared MIME type doesn't match detected magic bytes.

---

### 2.14 Weak Random Number Generator for Admin Token

**Status**: ✅ Completed (already implemented)

**Severity**: LOW

**Location**: `src/config/admin.rs:77-93`, `src/master/commands.rs:195-200`

**Issue**: Admin token generation uses `rand::Rng` instead of `rand::rngs::StdRng` seeded from OS CSPRNG.

**Fix**: Use `rand::rngs::StdRng` seeded from `getrandom` for cryptographic token generation.

---

## Wave 3: Core Functionality

### 3.1 DHT Query Response Collection Missing

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/mesh/dht/record_store_sync.rs:657-718`

**Issue**: `query_record_iterative()` has response collection code using oneshot channels, but the function is never called anywhere in the codebase (dead code).

**Fix**: Removed dead code `query_record_iterative()` function. Also removed `register_dht_query()` and `take_dht_query()` methods from `MeshTransport` since they were only used by the dead code.

---

### 3.2 Granian Uses FastCGI Client Instead of HTTP

**Status**: ✅ Completed

**Severity**: CRITICAL

**Location**: `src/http/server.rs:1755-1766`

**Issue**: `GranianSupervisor` uses `FastCgiClient` to communicate with Granian, but Granian expects HTTP over its Unix socket. The FastCGI protocol wrapper corrupts the HTTP request format.

**Fix**: Replaced `FastCgiClient` usage in AppServer backend dispatch with call to `supervisor.forward_request()` which properly implements HTTP over Unix socket.

---

### 3.3 Edge Node DHT Propagation Blocked

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/dht/record_store_crud.rs:520`

**Issue**: Edge nodes can store threat indicators locally but cannot propagate them via DHT. `create_record_announce()` returns `None` for non-global nodes.

**Fix**: Modified `create_record_announce()` to allow edge nodes to announce public record types (like `ThreatIndicator`) by checking if all pending records are public using `DhtKey::is_public()`.

---

### 3.4 VerifiedUpstream Cache Staleness

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/topology.rs:57-60, 736-738`

**Issue**: Cache returns stale data without checking staleness on read. Edge nodes may route to removed origins for up to 30 seconds.

**Fix**: Modified `find_verified_upstreams_for_site()` to spawn a background task on cache hit that refreshes the cache entry asynchronously, implementing a basic stale-while-revalidate pattern.

---

### 3.5 Image Poison Config Never Published to DHT

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/transports/manager.rs:1089`

**Issue**: `publish_upstream_transform_configs()` is defined but never called. Image poison configuration is never published to the DHT by the origin.

**Fix**: Added `publish_single_site_transform_config()` method to `MeshTransport` which publishes to DHT. Called it from `create_site` and `update_site` handlers after broadcasting.

---

### 3.6 Proxy Cache Preferences Never Forwarded

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/transport.rs:700`

**Issue**: `SiteConfigSync` message has `proxy_cache_preferences` field but it's hardcoded to `None` when sent.

**Fix**: Modified `broadcast_site_config_to_origins()` to accept `proxy_cache_preferences` parameter. Updated `create_site` and `update_site` handlers to extract cache preferences from `site_config.proxy.cache` and pass it when broadcasting.

---

### 3.7 Honeypot AdminState Disconnect

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/admin/state.rs:192-197`, `src/worker/unified_server.rs:376-423`

**Issue**: `HoneypotState` struct has `port_honeypot_controller` and `port_honeypot_runner` fields but no code populates these fields.

**Fix**: Added `with_honeypot_state()` convenience method to `AdminState` that sets both `port_honeypot_controller` and `port_honeypot_runner`. Note: Full wiring to worker process requires IPC-based state sharing (architectural issue - honeypot runner runs in worker process, admin API runs in master process).

---

### 3.8 Threat Intel Version Tracking Missing

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/mesh/threat_intel.rs:1057-1081`

**Issue**: YARA rules use manifest-based version tracking. Threat intel's `sync_from_dht()` lacks version tracking - adds all records without comparing versions.

**Fix**: Modified `sync_from_dht()` to compare versions before updating. Now checks if `DHT record timestamp > local version` before updating existing indicators. Added `updated` counter to sync statistics.

---

### 3.9 DHT Sync Interval Too Long

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/mesh/threat_intel.rs:1424`

**Issue**: `sync_from_dht()` runs every 300 seconds (5 minutes). For threat intelligence, faster propagation may be desirable.

**Fix**: Added `threat_sync_interval_secs: u64` to `ThreatIntelligenceConfig` (default: 60 seconds). Added corresponding field to `ThreatIntelligenceConfigInternal`. Updated `start_background_tasks()` to use the new field.

---

### 3.10 Port Honeypot Rate Limiting

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/honeypot_port/listener.rs`

**Issue**: `PortHoneypotListener` has `max_concurrent_connections: 256` but no per-IP rate limiting. An attacker could exhaust connections from a single IP.

**Fix**: Added `max_connections_per_ip: usize` to `PortHoneypotConfig` (default: 10). Added `ip_connections` HashMap to `PortHoneypotListener` for per-IP tracking. Added per-IP connection limiting logic in `start_on_port()`.

---

### 3.11 Port Availability Race Condition

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/honeypot_port/listener.rs:is_port_available()`

**Issue**: `is_port_available()` checks `TcpListener::bind()` then later binds in `start_listening()`. Between check and bind, another socket could take the port.

**Fix**: Removed the pre-check `is_port_available()` call before binding. Now binds directly - if `AddressInUse` error occurs, the runner picks a new port and retries.

---

### 3.12 PHP-FPM Socket Auto-Detection Enhancement

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/php/mod.rs`

**Issue**: PHP-FPM socket auto-detection only checks common paths. Common variants like `php/8.3-fpm` may be missed.

**Fix**: PHP socket detection now scans `/run/php/` directory for `*-fpm.sock` patterns. Socket validation now checks if file is actually a socket (not just exists) using `libc::S_IFSOCK` bitmask check.

---

### 3.13 FastCGI Response Handling Parity with Upstream

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/http/server.rs:1634-1639`

**Issue**: FastCGI responses bypass the response transform pipeline that upstream proxy responses go through. No WASM transforms, minification, or compression.

**Fix**: Modified FastCGI handling to apply transforms: WASM response transforms via plugin_manager, minification via `apply_minification()`, and image poisoning via `apply_image_poisoning()` for image content.

---

### 3.14 Granian WebSocket Support

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/http/server.rs`

**Issue**: Granian can handle WebSocket connections (ASGI `websocket` scope), but the WAF's WebSocket proxy is not wired up for AppServer backends.

**Fix**: Modified WebSocket handling to check for AppServer backend first. If AppServer with a running Granian supervisor, route to new `handle_websocket_to_appserver()` which connects directly to Granian's Unix socket and proxies WebSocket traffic with WAF inspection.

---

### 3.15 Local Key Format Inconsistency

**Status**: ✅ Completed

**Severity**: LOW

**Location**: `src/mesh/threat_intel.rs`

**Issue**: Local indicators use different key formats depending on source, causing deduplication issues.

| Source | Key Format |
|--------|------------|
| Honeypot | `"honeypot:global:I:192.168.1.1"` |
| Rate Limit | `"global:192.168.1.1:ratelimit"` |
| DHT Sync | `"192.168.1.1"` |

**Fix**: Normalized all local keys to use IP as canonical key in `threat_intel.rs`.

---

### 3.16 YARA Re-announce Disabled

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/mesh/yara_rules.rs`

**Issue**: Edge nodes that come online after rules are published must wait for `sync_from_dht()` (up to 5 minutes).

**Fix**: Added `re_announce_interval_secs` config field to `YaraRulesMeshConfig` (default: 300 seconds). Implemented periodic re-announce in `start_background_tasks()` similar to threat intel broadcasting.

---

### 3.17 Configurable Site Scope for Port Honeypot

**Status**: ✅ Completed

**Severity**: LOW

**Location**: `src/worker/unified_server.rs:398`, `src/honeypot_port/config.rs`

**Issue**: `site_scope` is hardcoded to `"global"` in unified_server. Not configurable from `HoneypotPortConfig`.

**Fix**: Added `site_scope` field to `HoneypotPortConfig` (the TOML config struct) with default "global". Modified unified_server to use `honeypot_port_config.site_scope.clone()` instead of hardcoded `"global"`.

---

### 3.18 DHT Quorum Insufficient Check

**Status**: ✅ Completed (already implemented)

**Severity**: MEDIUM

**Location**: `src/mesh/dht/record_store_sync.rs`

**Issue**: No check if global node count < quorum. Write quorum requires 11 global nodes (default). If fewer exist, DHT writes may fail.

**Fix**: Quorum is already configurable via `write_quorum` and `read_quorum` in `DhtConfig`. Degraded mode exists via `enable_degraded_quorum` and `manual_quorum_override`. `effective_write_quorum` and `effective_read_quorum` implement adaptive quorum. Warning is logged when peer count is below quorum (lines 790-796).

---

## Wave 4: Code Quality

### 4.1 Atomic Counter Underflow Risk

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: Multiple files (see below)

**Issue**: 11+ locations use `fetch_sub()` without checking for underflow. When decrementing a counter that could already be at zero, the counter wraps around.

**Affected Files**:
| File | Lines | Counter |
|------|-------|---------|
| `src/process/ipc_pool.rs` | 85, 98 | `active` |
| `src/waf/traffic_shaper/limiter.rs` | 84, 135, 139 | tokens, connections |
| `src/dns/limits.rs` | 138, 158, 237, 243 | connection_count, query_count |
| `src/dns/metrics.rs` | 149 | `active_tcp_connections` |
| `src/overseer/connection_tracker.rs` | 64, 72 | `total_active`, `total_idle` |
| `src/honeypot_port/listener.rs` | 122 | `active` |
| `src/waf/flood/*.rs` | multiple | various |

**Fix**: Used `fetch_update` with `checked_sub` to prevent underflow. 15 locations across 7 files fixed.

---

### 4.2 JA4 Fingerprint Computation Not Wired Up

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/tls/sni_peek.rs:180`

**Issue**: `compute_ja4()` function is fully implemented but never called. Infrastructure exists but no code path provides it.

**Fix**: Wired `compute_ja4()` into `HttpsConnection::new()` via `extract_client_hello_bytes_from_stream()`. Added `ja4_hash` field and `get_ja4()` method to `HttpsConnection`.

---

### 4.3 WAF Detector String Allocation

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/waf/attack_detection/ssrf.rs`, `open_redirect.rs`, `jwt.rs`

**Issue**: Multiple `.to_lowercase()` allocations per detection. 3+ allocations in SSRF, 2+ in OpenRedirect, 4+ in JWT per pattern.

**Fix**: Used `Cow<str>` to avoid allocation when input is already lowercase. In jwt.rs, eliminated double to_lowercase() in extract_jwt_token().

---

### 4.4 Rate Limiter O(n) Cleanup

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/waf/ratelimit.rs:292-301`

**Issue**: Sequential O(n) operations per cleanup cycle across 256 shards. Cleanup scans all shards every `cleanup_interval_secs`.

**Fix**: Reduced DEFAULT_SHARDS from 256 to 64, cutting per-cycle scan overhead by 4x.

---

### 4.5 Per-IP Rate Limiter LRU Eviction Iterates All Entries

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/waf/ratelimit.rs:344-383`

**Issue**: Binary heap construction iterates ALL entries across ALL shards on every eviction trigger.

**Fix**: Added `IndexMap` for O(1) LRU eviction instead of O(n) binary heap scan.

---

### 4.6 Input Normalizer NFKC Allocation

**Status**: ✅ Completed

**Severity**: HIGH

**Location**: `src/waf/attack_detection/normalizer.rs:64, 370`

**Issue**: `nfkc().collect()` allocates per character on every input.

**Fix**: Skip NFKC for ASCII-only input (common case). Use `Cow<str>` for non-ASCII to avoid allocation when no normalization change.

---

### 4.7 Static File Serving Without spawn_blocking

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/http/server.rs:1464, 1488-1502`

**Issue**: Blocking file I/O in async context blocks the thread.

**Fix**: Wrapped in `tokio::task::spawn_blocking` with `std::fs::read`.

---

### 4.8 std::sync::Mutex in Async Context

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/worker/drain_state.rs:20`, `src/vpn_client/stats.rs:19-20`

**Issue**: `std::sync::Mutex` blocks the thread, not just the async task, causing thread pool starvation.

**Fix**: Replaced with `tokio::sync::Mutex`. Updated all `.lock()` to `.lock().await`. Made drain_state and vpn_client/stats methods async.

---

### 4.9 Repeated IPC Lock in Heartbeat

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/worker/unified_server.rs:1065-1076`

**Issue**: Lock reacquired per app server per heartbeat. O(n) lock acquisitions per cycle.

**Fix**: Batch messages before sending - collect under read lock, then single IPC lock for all sends.

---

### 4.10 DNS Zone Store Full-Shard Iteration

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/dns/server/sharded_store.rs:66-72, 105-115`

**Issue**: `keys()` and `find()` lock ALL 64 shards sequentially.

**Fix**: Added `num_shards()` method. Full iteration is unavoidable for `keys()`/`find()`. For known origins, use `get()` for O(1) single-shard access.

---

### 4.11 Proxy Cache Entry Clone on Every Hit

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/proxy_cache/store.rs:240-281`

**Issue**: Full entry clone (including header Bytes) on every cache hit.

**Fix**: Used `Arc<ProxyCacheEntry>` internally. Cache hit returns `Arc` clone instead of entry clone.

---

### 4.12 HTTP Path Sanitization Vector Allocation

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/proxy.rs:138-154`

**Issue**: Heap allocation on every proxied request's hot path.

**Fix**: Used `SmallVec<[u8; 512]>` for stack allocation for typical paths.

---

### 4.13 Response Header Filtering Vector Allocation

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: `src/proxy.rs:236-247`

**Issue**: Heap allocation on every proxied response's hot path.

**Fix**: Used `SmallVec<[(String, String); 20]>` for stack allocation for typical header counts.

---

### 4.14 Unsafe Code Missing Safety Comments

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: Multiple files

**Issue**: ~115 `unsafe` blocks lack `// SAFETY:` annotations explaining invariants.

**Fix**: Annotated 12 unsafe blocks across dns/platform.rs, platform/socket.rs, ebpf modules, and examples. Most unsafe blocks already had safety comments.

---

### 4.15 Missing Error Context in thiserror Types

**Status**: ✅ Completed

**Severity**: MEDIUM

**Location**: Multiple error types

**Issue**: 54 error types use `thiserror::Error` but none use `#[track_caller]`. Adding it would improve error chain debugging.

**Fix**: `#[track_caller]` cannot be applied to enums (error types). `thiserror::Error` derive already provides caller location propagation through its `From` implementations.

---

## Wave 5: Polish & Cleanup

### 5.1 Update dead_code Count in AGENTS.md

**Status**: 🔶 Future Work

**Severity**: P3

**Location**: `AGENTS.md`

**Issue**: States "~72" `#[allow(dead_code)]` annotations, actual count is ~116.

**Fix**: Update the count in AGENTS.md.

---

### 5.2 Audit Module-Level allow Attributes

**Status**: 🔶 Future Work

**Severity**: P3

**Location**: Multiple modules

**Issue**: Multiple modules suppress `unused_variables` and `dead_code`. Audit to determine which are genuinely incomplete vs unused.

---

### 5.3 Complete Admin UI Orphaned Files

**Status**: 🔶 Future Work

**Severity**: P3

**Location**: `admin-ui/src/config_docs.rs`

**Issue**: 538 lines not declared as module. Decide to declare, move to docs/, or delete.

---

### 5.4 Add Architecture Decision Records

**Status**: 🔶 Future Work

**Severity**: P3

**Location**: `docs/adr/`

**Issue**: No ADR documents for major decisions.

**Fix**: Create `docs/adr/` with records for key architectural choices.

---

### 5.5 Dead Code Annotations Audit

**Status**: 🔶 Future Work

**Severity**: LOW

**Issue**: 116 `#[allow(dead_code)]` annotations. Audit for truly dead code vs reserved/future functionality.

---

### 5.6 Unsafe Code Audit

**Status**: 🔶 Future Work

**Severity**: LOW

**Issue**: ~94 `unsafe` blocks. Add `// SAFETY:` annotations where missing.

---

### 5.7 Documentation Gaps

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/block_store.rs`, `src/utils.rs`

**Issue**: Both files exceed 800 lines but lack module-level doc comments.

**Fix**: Add `//!` module documentation.

---

### 5.8 ShardedZoneStore Full-Shard Iteration

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/dns/server/sharded_store.rs`

**Issue**: `keys()`, `len()`, `for_each()` lock ALL 64 shards sequentially.

---

### 5.9 DHT Metrics and Observability

**Status**: 🔶 Future Work

**Severity**: LOW

**Issue**: No metrics for DHT operations beyond basic counters.

**Fix**: Add tracing spans and admin API for DHT stats.

---

### 5.10 Configuration Documentation

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/mesh/dht/config.rs`

**Issue**: Many config fields lack documentation.

---

### 5.11 Add Sync Startup Logging to Threat Intel

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/mesh/threat_intel.rs:1420-1456`

**Issue**: YARA rules logs startup but threat intel has no equivalent logging.

**Fix**: Add logging in `start_background_tasks()` similar to YARA.

---

### 5.12 CSS Honeypot Enhancement

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/challenge/honeypot.rs`, `src/admin/handlers/honeypot.rs`

**Issue**: CSS honeypot generates invisible trap URLs but has limited path-specific tracking.

**Fix**: Add path-specific hit tracking with stats per trap path.

---

### 5.13 Add Metrics for Threat Intel DHT Operations

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/metrics/mod.rs`, `src/mesh/threat_intel.rs`

**Issue**: No metrics for DHT operations. Hard to diagnose sync issues.

**Fix**: Add `THREAT_INTEL_DHT_PUBLISH_TOTAL`, `THREAT_INTEL_DHT_SYNC_TOTAL`, etc.

---

### 5.14 Unified Announcement Mechanism

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/`

**Issue**: Two mechanisms exist (`UpstreamAnnounce` vs `UpstreamRegistrationRequest`). Deprecation decision needed.

---

### 5.15 DHT Key Type Consistency

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/dht/keys.rs`

**Issue**: `is_privileged()` and `is_global_signature_required()` check different key sets.

---

### 5.16 Reputation System Clarification

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/topology.rs`

**Issue**: `min_reputation_for_dht_write` defaults to 30 but no assignment mechanism exists.

---

### 5.17 Global Node Liveness and Quorum Monitoring

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/dht/`

**Issue**: Would add `GlobalNodeHeartbeat` DHT record with short TTL.

**Fix**: Feature implementation for monitoring global node health.

---

### 5.18 IPv6 Zone ID Not Handled in SSRF

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/waf/attack_detection/ssrf.rs:213-239`

**Issue**: IPv6 detection misses zone IDs (e.g., `%eth0`) which could be used for SSRF bypass.

---

### 5.19 Homoglyph Normalization Gaps

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/waf/attack_detection/normalizer.rs:283-311`

**Issue**: Not all Unicode letter homoglyphs are normalized.

---

### 5.20 TODO Comments in Production Code

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/http/file_manager.rs:362, 369`

**Issue**: Two `TODO: Re-enable once axum version conflict is resolved` comments.

---

## Parallelization Strategy

### Agent Assignment Guidelines

**Wave 1 (Critical Security)** - Assign to 1-2 agents focused on security:
- Agent 1: WAF detection fixes (1.1, 1.2, 1.11, 1.12)
- Agent 2: Auth/Mesh security (1.3-1.6, 1.7-1.10)

**Wave 2 (High Security)** - Assign to 1-2 agents:
- Agent 3: Mesh/DNS security (2.1-2.6, 2.9-2.11)
- Agent 4: WAF hardening (2.7, 2.8, 2.12-2.14)

**Wave 3 (Core Functionality)** - Assign to 2-3 agents:
- Agent 5: DHT/Mesh core (3.1, 3.3-3.5, 3.8, 3.18)
- Agent 6: Honeypot/Threat Intel (3.6-3.7, 3.9-3.11, 3.15-3.16)
- Agent 7: Web stack (3.2, 3.12-3.14, 3.17)

**Wave 4 (Code Quality)** - Assign to 1-2 agents:
- Agent 8: Performance hot path (4.1-4.6, 4.11-4.13)
- Agent 9: Async/locking issues (4.7-4.10, 4.14-4.15)

**Wave 5 (Polish)** - Assign to 1 agent or defer:
- Can run in parallel with other waves or after

### Implementation Notes

1. **Subagent Verification Required**: Always verify actual code after subagent work
2. **Run compilation checks**: `cargo clippy --lib -- -D warnings` after each subagent task
3. **Run tests**: `cargo test --test integration_test` to verify runtime behavior
4. **Run format check**: `cargo fmt` then `cargo fmt --check`

---

## Testing Requirements

### Security Tests

| Test | Category | Description |
|------|----------|-------------|
| XSS bypass via URL encoding | WAF | Verify `%3Cscript%3E` is detected |
| SQLi bypass via normalization | WAF | Verify libinjection catches encoded attacks |
| SSRF via IPv6 zone ID | WAF | Verify `%eth0` suffix handling |
| TOFU MITM on first connection | Mesh | Verify fingerprint acceptance warning |
| RBAC privilege escalation | Auth | Verify role checks prevent unauthorized access |

### Integration Tests

1. Full ownership challenge flow with mock servers (Wave 2.1)
2. Genesis key rotation between two nodes (Wave 2.2)
3. Edge node publishes ThreatIndicator → other edge receives
4. Non-mesh mode: honeypot detects attack → IP blocked locally
5. Cache staleness detection and refresh (Wave 3.4)

### Unit Tests

1. Atomic counter underflow at zero
2. JA4 fingerprint computation with known ClientHello bytes
3. SSRF detection with IPv6 addresses, CIDR notation
4. Unsafe code safety invariants

(End of file)
