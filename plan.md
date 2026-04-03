# MaluWAF Consolidated Improvement Plan

> Consolidated: 2026-04-03
> Sources: plan2.md through plan10.md (9 plans merged)
> Previous: plan.md (Waves 1-7, 113 items — all complete as of 2026-04-03)
> Status: **PENDING APPROVAL**

---

## Executive Summary

After completing all 113 items from the previous remediation plan, **9 specialized review plans** identified **~180 remaining improvement items** across the codebase. This consolidated plan merges all items, deduplicates overlaps, and organizes them into **8 waves** for parallel sub-agent execution.

| Wave | Focus | Items | Est. Effort | Parallel Agents |
|------|-------|-------|-------------|-----------------|
| 1 | Build & Compilation Blockers | 10 | 1-2 days | 3 |
| 2 | Critical Security & Correctness | 20 | 4-6 days | 5 |
| 3 | Mesh & DHT Security/Correctness | 25 | 5-8 days | 4 |
| 4 | WAF Engine & Proxy Correctness | 22 | 4-6 days | 4 |
| 5 | DNS Protocol Correctness | 14 | 3-5 days | 3 |
| 6 | Web App Stack & Admin Panel | 22 | 5-8 days | 4 |
| 7 | YARA, Honeypot & Threat Intel | 22 | 4-7 days | 3 |
| 8 | Code Quality, Safety & Performance | 30 | 6-10 days | 4 |

**Total sequential: 32-52 days**
**Total with parallelization: 10-18 days (5-7 agents)**

### Cross-Wave Dependencies

| Wave | Depends On | Notes |
|------|-----------|-------|
| Wave 1 | None | Must complete first (blocking) |
| Wave 2 | Wave 1 | Security fixes need clean build |
| Wave 3 | None | Fully independent of Waves 1-2 |
| Wave 4 | None | Fully independent |
| Wave 5 | None | Fully independent |
| Wave 6 | None | Fully independent |
| Wave 7 | None | Fully independent |
| Wave 8 | Waves 1-7 | Cleanup validates all prior changes |

**Optimized execution:** Waves 2-7 can overlap significantly (run agents from different waves simultaneously). Wave 1 must complete first. Wave 8 should run last to verify final state.

---

## Wave 1: Build & Compilation Blockers

*Must be completed first — each item prevents successful compilation.*

### 1A: Fix Duplicate `TunReader`/`TunWriter` Definitions

**Severity:** Critical (blocks compilation)
**Files:** `src/tunnel/wireguard/tun.rs:238,474,590,642`
**Problem:** Two `pub use {TunReader, TunWriter}` re-exports exist: line 238 (Linux-gated) and line 474 (BSD-gated). Struct definitions at lines 590/642 are gated for all platforms including Linux. On Linux, the `pub use` at 238 and the struct at 590 both exist → `E0255`.
**Fix:**
1. Remove the `pub use` at line 238 (Linux doesn't need it — uses `AsyncTunDevice`)
2. Remove `target_os = "linux"` from cfg on struct definitions at 590/642 (Linux uses `AsyncTunDevice`, not these BSD-style structs)
**Verification:** `cargo check` shows no E0255 for these types.

### 1B: Fix Unused `SockLevel` Import

**Severity:** Critical (blocks compilation)
**Files:** `src/dns/platform.rs:18`
**Problem:** `use nix::sys::socket::{setsockopt, sockopt, SockLevel}` — `SockLevel` removed in nix 0.29 and never used in this file.
**Fix:** Remove `SockLevel` from import.
**Verification:** `cargo check` shows no E0432 for `SockLevel`.

### 1C: Fix Unresolved `wireguard_control` Module

**Severity:** Critical (blocks compilation)
**Files:** `src/tunnel/wireguard/kernel.rs:13-14`
**Problem:** Import gated by `#[cfg(target_os = "linux")]` (line 13) but NOT `feature = "wireguard"`. On Linux without wireguard feature, platform gate passes but `wireguard_control` (from `defguard_boringtun`) is not available.
**Fix:**
1. Change cfg to `#[cfg(all(target_os = "linux", feature = "wireguard"))]`
2. Add `use std::time::Duration;` (missing, used at line 334)
**Verification:** `cargo check` shows no E0432 for `wireguard_control`.

### 1D: Fix Duplicate `test_build_json_response` Function

**Severity:** Critical (blocks compilation)
**Files:** `src/http/shared_handler.rs:287,336`
**Problem:** Two test functions with identical name.
**Fix:** Remove duplicate at lines 336-347.
**Verification:** `cargo test --lib --no-run` compiles.

### 1E: Fix Missing `Arc` Import in tun.rs

**Severity:** Critical (blocks compilation)
**Files:** `src/tunnel/wireguard/tun.rs:591,643`
**Problem:** `TunReader`/`TunWriter` structs use `Arc` but `std::sync::Arc` not imported.
**Fix:** Add `use std::sync::Arc;` at top of file.

### 1F: Fix ProtectionLevel Variant Mismatch

**Severity:** High
**Files:** `src/worker/image_poisoning.rs`
**Problem:** Code uses `ProtectionLevel::Standard/Strong/Light/Enhanced/Disabled` but external `cloakrs` crate defines `L1, L2, L3`.
**Fix:** Update image_poisoning.rs to use `L1, L2, L3` variants, or add mapping layer.

### 1G: Fix Missing Fields on Structs

**Severity:** High
**Files:** Multiple
**Problem:** Several struct initializers missing required fields:
- `SiteConfig` missing `file_manager` field (`src/router.rs:1011`)
- `Router` missing `location_matchers` field
- `DhtRecord` missing `sequence_number` field
- `FunctionDefinition` missing `pre_warm_instances`, `min_instances`, `max_instances`, `idle_timeout_seconds`
**Fix:** Add missing fields to struct definitions or initializers with sensible defaults.

### 1H: Fix `ProtectionContext` Missing `Default`

**Severity:** High
**Files:** `src/serverless/`
**Problem:** `ProtectionContext::default()` called but `Default` not implemented.
**Fix:** Add `#[derive(Default)]` or implement `Default` manually.

### 1I: Fix `MeshCapabilities` Missing `Default`

**Severity:** High
**Files:** `src/mesh/protocol.rs`
**Problem:** `MeshCapabilities::default()` called but `Default` not satisfied.
**Fix:** Add `#[derive(Default)]` or implement `Default`.

### 1J: Fix `LocationMatcher` Missing `Clone`

**Severity:** High
**Files:** `src/router.rs`
**Problem:** `Clone` trait bound not satisfied for `LocationMatcher`.
**Fix:** Add `Clone` derive or wrap in `Arc<>`.

---

## Wave 2: Critical Security & Correctness

*Must be completed after Wave 1. Each item causes security bypass, data loss, or complete feature failure.*

### 2A: Fix `pattern_detector!` Macro Infinite Recursion

**Severity:** P0 — Stack overflow
**Files:** `src/waf/attack_detection/detector_common.rs:85-87,199-201`
**Problem:** Macro-generated `impl PatternDetector` calls `self.detect()` — which is the method being defined. Infinite recursion. Same bug in `url_decode_detector!` macro.
**Fix:** Generated impl should delegate to wrapped detector field (e.g., `self.inner.detect()`).
**Verification:** Unit test through `Box<dyn PatternDetector>` — no stack overflow.

### 2B: Fix WAF Receiving Empty Headers in Proxy Path

**Severity:** P0 — All header-based WAF rules bypassed
**Files:** `src/proxy.rs:486`
**Problem:** `check_request_full` receives `&http::HeaderMap::new()` — empty header map. Bad User-Agent detection, security header checks, all header-based attack detection bypassed.
**Fix:** Pass actual request headers from incoming request to `check_request_full`.

### 2C: Fix `sanitize_request_path` Destroying Dots in Segments

**Severity:** P0 — Breaks versioned API paths
**Files:** `src/proxy.rs:172-178`
**Problem:** `/foo.bar` becomes `/foobar`, `/api/v1.0/users` becomes `/api/v10/users`.
**Fix:** Preserve `.` characters within segments. Only strip `.` and `..` navigation segments.

### 2D: Fix Dynamic Worker Server Stub

**Severity:** P0 — Workers don't handle requests
**Files:** `src/worker/mod.rs:261-343`
**Problem:** `run_worker` accepts TCP connections but immediately drops stream and sleeps 10ms. Placeholder code never replaced.
**Fix:** Wire actual request handler into dynamic worker's TCP listener, or deprecate in favor of unified server.

### 2E: Fix DNS NXDOMAIN/NODATA Response ID Mismatch

**Severity:** P0 — DNS clients reject responses
**Files:** `src/dns/server/query.rs:1015,1121`
**Problem:** `build_nxdomain_response` and `build_nodata_response` generate random transaction IDs instead of echoing query's ID.
**Fix:** Accept query ID as parameter, use it in response header.

### 2F: Fix DNS Cache Bypass in UDP Handlers

**Severity:** P0 — Complete cache bypass
**Files:** `src/dns/server/startup.rs:319-366,651-701`
**Problem:** Cache key constructed with `String::new()` (empty qname) and `RecordType::NULL`. No real query matches.
**Fix:** Extract actual qname and qtype from incoming DNS query for cache key.

### 2G: Fix SSRF `allowed_domains` Substring Matching Bypass

**Severity:** P0 — SSRF protection bypass
**Files:** `src/waf/attack_detection/ssrf.rs:278-285`
**Problem:** `is_allowed_domain` uses `input_lower.contains(domain)`. `"evil-example.com"` passes when `"example.com"` is whitelisted.
**Fix:** Check for exact domain match OR proper suffix match with preceding `.` or start-of-string.

### 2H: Fix ACME Credentials Written World-Readable

**Severity:** P0 — Private key exposure
**Files:** `src/tls/acme.rs:154-161`
**Problem:** Account credentials written via `std::fs::write` with default permissions (typically `0644`).
**Fix:** Use `File::create()` + `set_permissions()` with `0o600`.

### 2I: Sign Worker→Master IPC Messages

**Severity:** P1 — Any process can impersonate a worker
**Files:** `src/worker/connect.rs:179-186`, `worker/mod.rs:77-85`
**Problem:** Workers use `connect_to_master_async()` (unsigned). `IpcSigner` generated but never used.
**Fix:** Use `connect_to_master_signed()` with session key.

### 2J: Add IPC Replay Protection

**Severity:** P1 — Signed messages replayable indefinitely
**Files:** `src/process/ipc_signed.rs`
**Problem:** HMAC covers only serialized payload — no nonce, timestamp, or sequence number.
**Fix:** Add timestamp + nonce to signed payload. Reject messages outside time window. Maintain nonce cache.

### 2K: Fix `SignedReader` No-Op Pass-Through

**Severity:** P1 — False sense of security
**Files:** `src/process/ipc_signed.rs:89-93`
**Problem:** `SignedReader::read()` just calls `self.inner.read(buf)` — no signature verification.
**Fix:** Implement actual signature verification or remove `SignedReader`.

### 2L: Fix `SignedWriter` Partial Write Protocol Desync

**Severity:** P1 — Protocol corruption on partial writes
**Files:** `src/process/ipc_signed.rs:64-68`
**Problem:** `write()` calls `write_all(&hmac)` then `write(buf)` (may be partial). Partial write creates protocol desync.
**Fix:** Buffer entire payload, compute HMAC once, write atomically.

### 2M: Fix IPC Key Temp File Lifecycle

**Severity:** P1 — Key persists on disk after worker crash
**Files:** `src/process/manager.rs:562-587`
**Problem:** Master writes IPC key to temp file but never deletes it. On restart with same PID, `create_new(true)` fails.
**Fix:** Register cleanup handler. Use unique filename per worker. Add stale file fallback.

### 2N: Fix `SignedIpcMessage::deserialize_signed` Length Validation

**Severity:** P1 — Potential panic on malicious input
**Files:** `src/process/ipc_signed.rs:155`
**Problem:** Slice math relies on `len >= HMAC_SIZE`. If `len < HMAC_SIZE`, panics.
**Fix:** Add explicit validation. Simplify slice to `&data[4 + HMAC_SIZE..4 + len]`.

### 2O: Fix Worker Spawn Race Condition

**Severity:** P1 — Placeholder observable during spawn gap
**Files:** `src/process/manager.rs:627-647`
**Problem:** Worker placeholder inserted, write lock dropped, then `cmd.spawn()` runs. Another thread could observe placeholder.
**Fix:** Keep write lock during spawn (fast enough), or use two-phase insert with `Starting` status.

### 2P: Remove Legacy Plaintext Token Support

**Severity:** P1 — Weak token exploitation
**Files:** `src/admin/auth.rs:26-32`
**Problem:** Tokens prefixed with `__plaintext__:` compared directly without bcrypt verification.
**Fix:** Remove plaintext prefix handling. All tokens must be bcrypt-hashed. Add migration path.

### 2Q: Add Config Validation to Update Handlers

**Severity:** P1 — Invalid configs crash workers
**Files:** `src/admin/handlers/config.rs` (all 15+ handlers)
**Problem:** Config update handlers modify in-memory config, serialize, write, broadcast — but never call `validate()`.
**Fix:** Call `validate()` before persisting. Add `force: bool` parameter to bypass.

### 2R: Fix Config Drift on Disk Write Failure

**Severity:** P1 — In-memory/disk config mismatch
**Files:** `src/admin/handlers/config.rs:1476-1481`
**Problem:** In-memory config modified before disk write. If disk write fails, in-memory has new values but file has old.
**Fix:** Write to disk first, then update in-memory. Or use atomic temp file + rename.

### 2S: Fix `from_config` Ignoring TLS skip_verify Setting

**Severity:** P1 — Config setting silently ignored
**Files:** `src/proxy.rs:447`
**Problem:** `from_config` constructor ignores TLS config entirely — always uses native roots, `skip_verify: false`.
**Fix:** Read TLS config from site config, use appropriate `UpstreamTlsConfig`.

### 2T: Fix New Upstream Client Per Request

**Severity:** P1 — TLS connector created every request
**Files:** `src/tls/server.rs:819-824`
**Problem:** In non-cache path, `create_upstream_client` called on every request, defeating DashMap caching.
**Fix:** Use cached upstream client from DashMap, keyed by config hash.

---

## Wave 3: Mesh & DHT Security/Correctness

*Can run in parallel with Waves 2, 4, 5, 6, 7. Independent domain.*

### 3A: WireGuard Transport Authentication

**Severity:** P0 — Any UDP source can forge messages
**Files:** `src/mesh/transports/wireguard.rs`
**Problem:** Raw UDP listener with zero authentication. `runtime` always `None`. Messages are plaintext protobuf over raw UDP with no MAC, no signature, no encryption.
**Fix:**
1. Wire up `WireGuardMeshRuntime` in transport constructor
2. Enforce peer public key validation
3. Mirror QUIC authentication checks (public_key, network_id, auth_token, PoW, timestamp)
4. Add message-level integrity (HMAC-SHA256 or Ed25519)
5. If cannot be secured, remove transport entirely

### 3B: Global Node Key Authentication

**Severity:** P0 — Shared secret compromises entire trust model
**Files:** `src/mesh/peer_auth.rs:11-38`
**Problem:** `global_node_key` is single shared secret validated with plain string comparison. Transmitted in plaintext as protobuf field.
**Fix:**
1. Replace with Ed25519 challenge-response
2. Maintain authorized global node public key list
3. Add challenge-response to handshake protocol
4. Deprecate shared `global_node_key` field

### 3C: Fix DHT Query Response Handling

**Severity:** P0 — DHT read path non-functional for remote lookups
**Files:** `src/mesh/dht/record_store_message.rs:119-131`, `record_store_sync.rs:657-718`
**Problem:** `DhtRecordResponse` handler discards every field. `query_record_iterative()` sends datagrams and returns `None` immediately without waiting for responses.
**Fix:**
1. Wire up `DhtQuery` with pending-response table
2. Implement pending-response correlation via oneshot channels
3. Implement quorum-based read (send to write_quorum peers, wait for responses)
4. Handle `DhtRecordResponse` properly — extract fields, verify signature, update cache

### 3D: Record Sync Signature Verification

**Severity:** P1 — Malicious peers can inject forged records
**Files:** `src/mesh/dht/record_store_sync.rs`
**Problem:** `apply_sync()` accepts records without verifying Ed25519 signatures.
**Fix:** Verify each record's Ed25519 signature before accepting. Reject invalid signatures, emit slashing event.

### 3E: Session Key Rotation Synchronization

**Severity:** P1 — Communication breaks after every rotation cycle
**Files:** `src/mesh/session/manager.rs`
**Problem:** Key rotation derives new keys locally. Peer never notified. After rotation, both sides derive different keys.
**Fix:**
1. Add key version negotiation to session protocol
2. Implement proper key ratchet with peer-contributed entropy
3. Add explicit `SessionRotate` / `SessionRotateAck` messages
4. Implement session revocation and max session limit

### 3F: Certificate Rotation Preserves Node Identity

**Severity:** P1 — Peers see rotated cert as entirely new node
**Files:** `src/mesh/cert.rs`
**Problem:** `rotate_certificates()` generates new node ID with timestamp suffix. Breaks identity continuity.
**Fix:**
1. Separate node identity from certificate identity (persistent Ed25519 keypair)
2. Preserve node ID across certificate rotation
3. Add certificate pre-expiry alerting

### 3G: Anti-Entropy Runs When Routing Is Enabled

**Severity:** P2 — DHT state can diverge undetected
**Files:** `src/mesh/dht/record_store_message.rs`
**Problem:** Anti-entropy cycle skips when `is_routing_enabled()` is true.
**Fix:** Remove skip condition. Run regardless of routing mode. Adjust interval by node role.

### 3H: Fix `MeshGlobalRateLimiter` Ignoring Constructor Params

**Severity:** P1 — Rate limiting not configurable
**Files:** `src/mesh/transport.rs:170-175`
**Problem:** Constructor parameters unused. Always uses hardcoded 10 msg/s and 60 msg/min.
**Fix:** Use constructor parameters to configure `AtomicSlidingWindow` instances.

### 3I: Fix 18 Duplicate `#[cfg(feature = "dns")]` Attributes

**Severity:** P1 — Copy-paste/merge artifact
**Files:** `src/mesh/transport.rs:874-891`
**Problem:** 18 consecutive `#[cfg(feature = "dns")]` lines before `start()`.
**Fix:** Remove 17 duplicates.

### 3J: Fix `datagram_tx` Receiver Dropped

**Severity:** P1 — Datagram transport non-functional
**Files:** `src/mesh/transport.rs:312`
**Problem:** Receiver immediately dropped. All datagrams silently lost.
**Fix:** Wire up receiver for datagram channel, or remove if not needed.

### 3K: Fix Role Bitmask Equality Checks

**Severity:** P1 — Peer filtering broken for composite roles
**Files:** `src/mesh/transport.rs:909,1180`
**Problem:** Direct equality comparisons on bitmask role type (e.g., `self.config.role == MeshNodeRole::Edge`). Composite roles like `GLOBAL_EDGE` (0b011) won't match `Edge` (0b001).
**Fix:** Use `self.role.is_edge()` or `self.role.contains(role)` instead of direct `==`.

### 3L: Fix `CertificateInfo::days_until_expiry` Inverted Logic

**Severity:** P1 — Certificate expiry monitoring broken
**Files:** `src/mesh/cert.rs:1105-1110`
**Problem:** `duration_since(self.not_after)` returns `Err` when cert is still valid. Returns `None` for valid certs, negative for expired — opposite of intended.
**Fix:** Use `self.not_after.duration_since(SystemTime::now())` and map to `Option<i64>`.

### 3M: Fix `seen_messages` Not Shared on Clone

**Severity:** P1 — Message deduplication defeated
**Files:** `src/mesh/transport.rs:146-151`
**Problem:** When `MeshTransport` cloned, `seen_messages` recreated as fresh empty LRU cache.
**Fix:** Share via `Arc` instead of recreating on clone.

### 3N: Fix `set_tofu_enabled` No-Op

**Severity:** P2 — TOFU cannot be disabled at runtime
**Files:** `src/mesh/cert.rs:458-463`
**Problem:** Setter takes `&self` and does nothing. `tofu_enabled` is plain `bool`, not behind `RwLock`.
**Fix:** Make `tofu_enabled` an `RwLock<bool>` or remove setter.

### 3O: Fix `announce_upstream` Not Actually Announcing

**Severity:** P2 — No mesh announcement
**Files:** `src/mesh/transport.rs:1756-1765`
**Problem:** Broadcast loop only logs "Would announce..." — no actual mesh message sent.
**Fix:** Send actual mesh announcement message.

### 3P: Consolidate Duplicate `MeshTransportError` Types

**Severity:** P2 — Confusion about which to use
**Files:** `src/mesh/transports/mod.rs:44-60`, `transport_core/error.rs`
**Problem:** Two different `MeshTransportError` types exist.
**Fix:** Consolidate into single type. Re-export from canonical location.

### 3Q: Extract Generic DHT Cache Fetch Pattern

**Severity:** P3 — Code duplication
**Files:** `src/mesh/transports/manager.rs:925-1250`
**Problem:** Three nearly identical cache-fetch patterns for image protection, compression, and minification configs.
**Fix:** Extract generic `fetch_cached_config<T>()` helper.

### 3R: Sharded Topology Store

**Severity:** P2 — Lock contention under load
**Files:** `src/mesh/topology.rs`
**Problem:** 15+ independent `tokio::sync::RwLock`s. `get_scored_peers()` is O(n log n) with 4+ lock acquisitions per peer.
**Fix:** Adopt `ShardedZoneStore` pattern with 64 shards. Consolidate per-field locks into per-shard locks.

### 3S: Parallel Broadcast Fanout

**Severity:** P2 — Sequential sends for large meshes
**Files:** `src/mesh/transports/manager.rs`
**Problem:** `broadcast_datagram_fanout()` sends to peers sequentially in a for loop.
**Fix:** Use `futures::future::join_all()` with semaphore for concurrency limiting.

### 3T: Prune Stale Peer State

**Severity:** P3 — Memory leak proportional to peer churn
**Files:** `src/mesh/topology.rs`, `transports/manager.rs`
**Problem:** `peer_states`, `connection_failures`, `connection_successes`, `latency_history` never pruned.
**Fix:** Add `prune_stale_peers()` to maintenance loop. Cap `latency_history` with bounded deque.

### 3U: Configurable DHT Routing Table Size

**Severity:** P3 — Hard cap at 5,120 peers
**Files:** `src/mesh/dht/routing/table.rs`, `bucket.rs`
**Problem:** `BUCKET_COUNT = 256` and `K_SIZE = 20` hardcoded. `split_bucket()` never called.
**Fix:** Make configurable via `MeshDhtConfig`. Implement adaptive bucket splitting.

### 3V: Increase PoW Difficulty

**Severity:** P3 — Negligible Sybil resistance
**Files:** `src/mesh/dht/routing/node_id.rs`
**Problem:** `NODE_ID_POW_DIFFICULTY = 24` bits — trivially computable in milliseconds.
**Fix:** Increase to 32 bits default. Make configurable. Allow dynamic adjustment by global nodes.

### 3W: Split Massive MeshMessage Enum

**Severity:** P3 — Maintainability
**Files:** `src/mesh/protocol.rs`
**Problem:** 60+ variants in single enum definition.
**Fix:** Adopt two-level message hierarchy with category-specific sub-enums.

### 3X: Make DHT Quorums Dynamically Adjustable

**Severity:** High — Fixed quorum requires 11+ global nodes
**Files:** `src/mesh/dht/record_store.rs:19-22`
**Problem:** Write quorum = 11, read quorum = 11, replication = 20. With fewer than 11 global nodes, writes fail.
**Fix:** Make quorum values configurable. Add auto-scaling: quorum = max(3, N/2 + 1). Add degraded quorum mode.

### 3Y: Reduce Route Query Flood with Hierarchical Routing

**Severity:** Medium — O(N^hops) messages in large mesh
**Files:** `src/mesh/proxy.rs:291-412`
**Problem:** Route queries use flood-based approach with max 3 hops and fanout=3.
**Fix:** Implement hierarchical routing with regional hubs. Add bloom filter-based route advertisements.

### 3Z: Add Global Node High Availability

**Severity:** High — Single point of failure
**Files:** `src/mesh/config.rs:805-842`, `topology.rs:514-525`
**Problem:** Global nodes are single source of truth. If unavailable, edge nodes enter degraded mode.
**Fix:** Implement global node clustering (Raft-like consensus). Leader/follower with promotion on failure.

---

## Wave 4: WAF Engine & Proxy Correctness

*Can run in parallel with Waves 2, 3, 5, 6, 7.*

### 4A: Fix `check_early` Whitelist Bypass

**Severity:** P1 — Whitelisted IPs can be blocked
**Files:** `src/waf/mod.rs:717`
**Problem:** `check_early` does NOT check IP whitelist. Early check can block whitelisted IP.
**Fix:** Add whitelist check at top of `check_early`.

### 4B: Fix `reload_attack_detector` Stale Config

**Severity:** P2 — Subsequent reloads merge from stale config
**Files:** `src/waf/mod.rs:642-676`
**Problem:** Method reloads `AttackDetector` but never updates `self.attack_detection_config`.
**Fix:** Update `self.attack_detection_config` after reloading.

### 4C: Fix `get_legacy_config` Hardcoded Values

**Severity:** P2 — Fiction returned as config
**Files:** `src/waf/threat_level/mod.rs:448-466`
**Problem:** Returns entirely hardcoded config values, ignoring actual manager state.
**Fix:** Return actual config from manager, or deprecate method.

### 4D: Fix `ViolationTracker::schedule_persist` Store Swap

**Severity:** P2 — Brief window with zero violations
**Files:** `src/waf/violation_tracker.rs:226-237`
**Problem:** Every `record_violation` call does `std::mem::swap` on entire HashMap. Concurrent `check_violations` sees zero violations during swap.
**Fix:** Use copy-on-write approach or lock-free queue for pending violations.

### 4E: Fix `ProbeTracker::trigger_persist` Same Swap Issue

**Severity:** P2 — Same as 4D
**Files:** `src/waf/probe_tracker.rs:385-408`
**Problem:** Identical issue — store emptied via swap on every probe event.
**Fix:** Same as 4D.

### 4F: Fix `build_pattern_automaton` O(n²) Containment Check

**Severity:** P2 — Performance degradation with large pattern sets
**Files:** `src/waf/attack_detection/detector_common.rs:500-505`
**Problem:** `if !patterns.contains(&pattern_lower) { patterns.push(...) }` is O(n²).
**Fix:** Use `HashSet` for deduplication, then convert to `Vec`.

### 4G: Fix `RingBuffer::retain` Performance

**Severity:** P2 — O(n) per call
**Files:** `src/waf/ratelimit.rs:130-150`
**Problem:** The `retain` implementation uses correct modular arithmetic but is O(n) per call. Under high load with many IPs, cleanup becomes expensive.
**Fix:** Consider replacing `RingBuffer<Instant>` with count-based sliding window that only stores count and window start time. This eliminates the need for `retain` entirely.

### 4H: Fix `parse_duration` Negative Value Handling

**Severity:** P2 — Negative durations accepted as positive
**Files:** `src/waf/mod.rs:678-702`
**Problem:** `take_while(|c| c.is_ascii_digit())` skips leading `-`. `"-5h"` returns `Some(18000)` instead of `None`.
**Fix:** Reject strings starting with `-`.

### 4I: Fix `check_bot_protection` Unused `_client_ip`

**Severity:** P3 — Incomplete feature
**Files:** `src/waf/mod.rs:1044-1068`
**Problem:** `_client_ip` parameter unused — IP-based bot tracking planned but never implemented.
**Fix:** Implement IP-based bot tracking or remove parameter.

### 4J: Fix `tarpit_generator` Always `Some`

**Severity:** P3 — Unnecessary Option wrapper
**Files:** `src/waf/mod.rs:149,488`
**Problem:** Field is `Option<...>` but always initialized to `Some(...)`.
**Fix:** Change field type from `Option<T>` to `T`.

### 4K: Fix `record_suspicious_words` Overhead

**Severity:** P3 — Unnecessary work on every request
**Files:** `src/waf/mod.rs:999-1018`
**Problem:** Called on every request even when word tracker is `None`.
**Fix:** Add early check for `self.suspicious_words.is_none()`.

### 4L: Fix `check_rate_limit_detailed` Dead Code

**Severity:** P3 — Duplicate logic
**Files:** `src/waf/ratelimit.rs:414-525`
**Problem:** ~110-line method duplicates logic from `check_global` + `check_rate_limit`. Never called.
**Fix:** Delete or wire into request path.

### 4M: Implement Anomaly Scoring Mode

**Severity:** Medium — First-match semantics misses combined attacks
**Files:** `src/waf/attack_detection/mod.rs:143-274`
**Problem:** Detection pipeline uses first-match semantics. No cumulative scoring like ModSecurity.
**Fix:** Add `AnomalyScoringConfig`. Optionally run ALL detectors and accumulate scores. Opt-in via config.

### 4N: Fix Header Validation Dead Code

**Severity:** Medium — 4 of 5 tests `#[ignore]`
**Files:** `src/waf/attack_detection/header_validation.rs:199-248`
**Problem:** CRLF injection, null bytes, empty host checks unreachable (hyper rejects at parse time).
**Fix:** Remove unreachable checks. Keep and fix duplicate header check (only reachable one).

### 4O: Add HTTP/2 Request Smuggling Detection

**Severity:** Medium — No HTTP/2-specific checks
**Files:** `src/waf/attack_detection/request_smuggling.rs`
**Problem:** Only checks HTTP/1.1 headers. No HTTP/2 smuggling checks.
**Fix:** Add HTTP/2 checks: `Content-Length` in H2, `Transfer-Encoding` in H2, `:authority`/`Host` mismatch, header field splitting.

### 4P: Add TLS Fingerprinting (JA3/JA4) to Bot Detection

**Severity:** Medium — Bot detection is UA-only
**Files:** `src/waf/mod.rs:888-890`, `src/waf/bot.rs`
**Problem:** Sophisticated bots spoof user agents. No TLS fingerprinting.
**Fix:** Extract JA3/JA4 fingerprints from TLS ClientHello. Add `known_bot_ja3_hashes` config. Block or challenge known bot fingerprints.

### 4Q: Add Challenge Attempt Rate Limiting

**Severity:** Low-Medium — DoS via challenge generation
**Files:** `src/waf/mod.rs:1148-1184`
**Problem:** Challenge re-issued on every request if cookie not set. Attacker can force repeated challenge generation.
**Fix:** Add per-IP challenge attempt counter. After N attempts, return 429. After M failures, block IP.

### 4R: Harden Open Redirect Detector

**Severity:** Medium — High false-positive rate
**Files:** `src/waf/attack_detection/patterns.rs:905-1086`
**Problem:** 90 base patterns include common parameter names (`url=`, `page=`, `redirect=`). Any legitimate URL with these triggers false positives.
**Fix:** Validate redirect target is actually external domain. Add `allowed_redirect_domains` whitelist.

### 4S: Eliminate Duplicate WAF Checks

**Severity:** Medium — Redundant AND less effective
**Files:** `src/http/server.rs:841`, `src/proxy.rs:479-490`
**Problem:** HTTP server runs `check_request_full()`, then calls proxy which runs it again with empty `HeaderMap`.
**Fix:** Add `skip_waf_check` parameter to `ProxyServer::handle_request()`. Set `true` when caller already ran WAF.

### 4T: Stream Large Request Bodies Through WAF

**Severity:** High — DoS vector via large uploads
**Files:** `src/http/server.rs:559-571`, `src/tls/server.rs:440-456`
**Problem:** Entire body collected into memory BEFORE WAF inspection. 10MB+ uploads exhaust memory regardless of block decision.
**Fix:** Run `check_early()` before collecting body. Collect in chunks, running WAF on each chunk. Drop blocked connections early.

### 4U: Fix XFF Truncation Dropping Original Client IP

**Severity:** P2 — Wrong IP used for rate limiting
**Files:** `src/proxy.rs:96-107`
**Problem:** When XFF chain exceeds `MAX_XFF_CHAIN_LENGTH`, keeps last N entries but discards first ones (original client IP).
**Fix:** Keep first N entries (original client IPs), discard newest ones.

### 4V: Fix Cache PURGE No Authentication

**Severity:** P2 — Any client can clear cache
**Files:** `src/proxy.rs:811-851`
**Problem:** Any client can send `PURGE /*` to clear entire cache. No authentication.
**Fix:** Require authentication or IP allowlist. Add `cache_purge_enabled` config (default: false).

### 4W: Add Response Streaming Support

**Severity:** Medium — Full buffering of upstream responses
**Files:** `src/http/server.rs:1699-1754`, `src/tls/server.rs:789-930`
**Problem:** All upstream responses fully buffered before sending to client. Large responses consume proportional memory.
**Fix:** Add `stream_response: bool` config. Use `hyper::body::Body` streaming. Pipe upstream response directly to client.

### 4X: Lazy Normalization for Disabled Detectors

**Severity:** Low-Medium — Unnecessary normalization work
**Files:** `src/waf/attack_detection/mod.rs:216-222`, `normalizer.rs:404-438`
**Problem:** `normalize_all()` runs even when only SQLi/XSS enabled (which use libinjection, don't need normalization).
**Fix:** Add `needs_normalization()` check. Skip normalization when no enabled detector requires it.

---

## Wave 5: DNS Protocol Correctness

*Can run in parallel with Waves 2, 3, 4, 6, 7. Independent domain.*

### 5A: Fix NSEC3 Base32hex Alphabet

**Severity:** P1 — NSEC3 proofs broken
**Files:** `src/dns/dnssec_signing.rs:259-282`
**Problem:** NSEC3 requires RFC 4648 base32hex (`0-9a-v`), but implementation uses standard base32 (`A-Z2-7`).
**Fix:** Implement base32hex encoding per RFC 4648 Section 6. Add test vectors from RFC 5155 Appendix B.

### 5B: Fix DNS Response NXDOMAIN for Non-Existent Types

**Severity:** P1 — Protocol compliance
**Files:** `src/dns/recursive.rs:670-681`
**Problem:** When name exists but requested type doesn't, returns NXDOMAIN. Should return NOERROR with 0 answers (NODATA).
**Fix:** Distinguish "name doesn't exist" (NXDOMAIN) vs "name exists but type doesn't" (NODATA). Include SOA in authority section.

### 5C: Fix CNAME/SOA/CAA/TLSA Wire Format Encoding

**Severity:** P1 — Malformed DNS records
**Files:** `src/dns/recursive.rs:586-618`, `server/response.rs:192-200`
**Problem:** Multiple record types store RDATA as raw strings instead of proper DNS wire format.
**Fix:** Encode domain names using DNS label encoding. Encode CAA flags/tag/value. Encode TLSA usage/selector/matching type.

### 5D: Fix `build_type_bitmap` Window Trimming

**Severity:** P2 — RFC 4034 violation
**Files:** `src/dns/dnssec_signing.rs:72-100`
**Problem:** Trailing zero bytes not trimmed from previous block's bitmap when transitioning between windows.
**Fix:** Trim trailing zero bytes after populating each window block. Update block length.

### 5E: Remove Dead DNSSEC Code

**Severity:** P2 — Dead code maintenance burden
**Files:** `src/dns/dnssec_validation.rs:352-596`, `dnssec.rs:231-551`
**Problem:** `DnsSecValidator` trait, `MeshTrustAnchorAdapter`, `ZoneSigner` defined but never used.
**Fix:** Delete unused types or wire into signing pipeline. If keeping as reserved, add `#[allow(dead_code)]` with TODO.

### 5F: Fix TCP Shutdown Channel Receiver Dropped

**Severity:** P2 — TCP listener can't shut down gracefully
**Files:** `src/dns/server/startup.rs:401`
**Problem:** `(shutdown_tx, _) = tokio::sync::broadcast::channel(1)` — receiver immediately dropped.
**Fix:** Keep receiver and pass to TCP listener task.

### 5G: Fix `String::from_utf8_lossy` in QName Parsing

**Severity:** P2 — Unexpected strings from malicious labels
**Files:** `src/dns/server/query.rs:647`
**Problem:** DNS labels are binary data, not necessarily UTF-8. `from_utf8_lossy` replaces invalid bytes with replacement character.
**Fix:** Validate labels are printable ASCII before converting. Reject non-ASCII with FORMERR.

### 5H: Fix Duplicate `qname.to_lowercase()` Calls

**Severity:** P3 — Unnecessary allocation
**Files:** `src/dns/server/query.rs:657,666`
**Problem:** `qname.to_lowercase()` called twice.
**Fix:** Reuse result from first call.

### 5I: Fix Dead Code `len > 65535` Check

**Severity:** P3 — Impossible condition
**Files:** `src/dns/server/query.rs:108-113`, `recursive.rs:295-299`
**Problem:** `len` cast from `u16` to `usize`, can never exceed 65535.
**Fix:** Remove check or change type of `len`.

### 5J: Fix Trust Anchor Event Dead Code

**Severity:** P3 — Dead code
**Files:** `src/dns/trust_anchor.rs:830-837`
**Problem:** `TrustAnchorEvent` enum superseded by `Rfc5011Event`.
**Fix:** Delete unused enum.

### 5K: Fix `parse_soa_serial` Fragility

**Severity:** P3 — Brittle parsing
**Files:** `src/dns/server/mod.rs:139-146`
**Problem:** SOA serial extracted by splitting on whitespace at index [2]. Position-dependent.
**Fix:** Use proper SOA record parser.

### 5L: Fix `LookupResult` Dead Code

**Severity:** P3 — Dead code
**Files:** `src/dns/resolver.rs:571-583`
**Problem:** `LookupResult` struct used internally but never exported.
**Fix:** Export and use, or inline and delete.

### 5M: Eliminate Repeated `.to_lowercase()` in Detectors

**Severity:** Low-Medium — Unnecessary allocation
**Files:** `src/waf/attack_detection/detector_common.rs:438,494`
**Problem:** Each detector's `detect_internal` calls `to_lowercase()` independently. Same string lowercased 8 times.
**Fix:** Pre-lowercase in `NormalizedInputs::normalize_all()`. Store alongside original.

### 5N: Optimize Rate Limiter Cleanup

**Severity:** Medium — O(n) per shard
**Files:** `src/waf/ratelimit.rs:246-263`
**Problem:** 6 sequential `retain` calls per shard on `RingBuffer<Instant>`. Each `retain` is O(n).
**Fix:** Replace with count-based sliding window. Use epoch-based cleanup. Stagger shard cleanup.

---

## Wave 6: Web App Stack & Admin Panel

*Can run in parallel with Waves 2-5, 7. Independent domain.*

### 6A: Fix X-Forwarded-For IP Spoofing

**Severity:** P2 — Rate limiting bypass
**Files:** `src/admin/middleware.rs:25-32`
**Problem:** Client IP extracted from `X-Forwarded-For` without checking trusted proxy. Attacker can spoof with `X-Forwarded-For: 127.0.0.1`.
**Fix:** Only trust XFF from known proxy IPs. Add `trusted_proxies: Vec<IpNetwork>` config.

### 6B: Stop Logging Generated Admin Tokens

**Severity:** P2 — Token exposure in logs
**Files:** `src/config/admin.rs:121`
**Problem:** Generated admin token logged: `tracing::info!("Generated admin token: {}", generated)`.
**Fix:** Remove token value from log. Log only that token was generated.

### 6C: Add Automatic CSRF Token Cleanup

**Severity:** P2 — Memory leak
**Files:** `src/admin/state.rs:562-569`
**Problem:** `cleanup_expired_csrf_tokens()` exists but never called automatically.
**Fix:** Spawn background task calling cleanup periodically (every 5 minutes).

### 6D: Add Path Sanitization to Config Import

**Severity:** P2 — Arbitrary file path injection
**Files:** `src/admin/handlers/config.rs:1143-1186`
**Problem:** `import_config` endpoint parses raw TOML directly. No validation of path values.
**Fix:** After parsing, validate all path fields. Reject paths to sensitive system files.

### 6E: Fix Admin Rate Limiter Blocking Lock

**Severity:** P3 — Async runtime blocking
**Files:** `src/admin/rate_limit.rs:57`
**Problem:** Uses `parking_lot::RwLock` in async context. Under high load, blocks Tokio runtime.
**Fix:** Replace with `tokio::sync::RwLock` or lock-free rate limiter.

### 6F: Fix `build_server_config` Panic on Missing Provider

**Severity:** P2 — Startup panic
**Files:** `src/tls/cert_resolver.rs:262-264`
**Problem:** `CryptoProvider::get_default().expect("...")` panics if no global crypto provider set.
**Fix:** Return `Err` instead of panicking.

### 6G: Fix `AcmeManager::get_state` Stub

**Severity:** P3 — Always returns empty state
**Files:** `src/tls/acme.rs:463-465`
**Problem:** Always returns `AcmeState::default()` — no actual data populated.
**Fix:** Populate with actual data (last order, pending orders, errors).

### 6H: Fix `filter_response_headers` Allocation in Hot Path

**Severity:** P3 — Unnecessary allocation
**Files:** `src/proxy.rs:230-242`
**Problem:** Allocates `(String, String)` tuples for every header. `_buf` variant exists but unused.
**Fix:** Use `_buf` variant in hot path.

### 6I: Fix `is_connection_error` String Matching

**Severity:** P3 — Fragile error classification
**Files:** `src/proxy.rs:1176-1188`
**Problem:** Uses `.to_lowercase().contains(...)` for error classification.
**Fix:** Match on error types directly (`std::io::ErrorKind`).

### 6J: Fix `proxy_raw_tcp` Small Buffer Size

**Severity:** P3 — Suboptimal throughput
**Files:** `src/tls/server.rs:1034,1046`
**Problem:** Uses 8KB buffers for raw TCP proxy.
**Fix:** Increase to 32KB or make configurable.

### 6K: Fix `watch_for_cert_changes` No Event Coalescing

**Severity:** P3 — Multiple reloads for single change
**Files:** `src/tls/cert_resolver.rs:477`
**Problem:** 100ms debounce but no coalescing. Cert + key written together triggers two reloads.
**Fix:** Use longer debounce (500ms) or coalesce events with `HashSet` of changed files.

### 6L: Fix `evict_lru_entries` Lock Contention

**Severity:** P2 — Lock contention under high load
**Files:** `src/waf/ratelimit.rs:314-353`
**Problem:** LRU eviction iterates all shards while holding read locks, then acquires write locks per IP.
**Fix:** Collect eviction candidates under read lock, release, then evict under individual write locks.

### 6M: Fix `NormalizedInputs::normalize_all` Header Allocation

**Severity:** P2 — Allocation pressure
**Files:** `src/waf/attack_detection/normalizer.rs:411-438`
**Problem:** Every header value gets full `NormalizedInput` with its own `String`.
**Fix:** Use borrowed references to thread-local buffer where possible.

### 6N: Fix `handle_request_logs` O(n) Vec Removal

**Severity:** P2 — Performance under high load
**Files:** `src/process/manager.rs:1157-1163`
**Problem:** `logs.remove(0)` on Vec with 10,000 entries triggers memmove of 9,999 elements.
**Fix:** Use `VecDeque` or ring buffer.

### 6O: Fix `MasterStatus` Hardcoded Zero Fields

**Severity:** P2 — Monitoring unreliable
**Files:** `src/process/manager.rs:2010-2029`
**Problem:** `started_at`, `uptime_secs`, `challenged_last_hour`, `active_blocks`, `active_violations`, etc. all hardcoded to zero.
**Fix:** Populate from actual state.

### 6P: Fix `drain_worker_async` Hardcoded Timeout

**Severity:** P2 — Ignores configured timeout
**Files:** `src/process/manager.rs:978`
**Problem:** Hardcoded 10s timeout ignores `timeout_secs` parameter.
**Fix:** Use `timeout_secs` parameter.

### 6Q: Fix `update_config` Drop During Spawn

**Severity:** P2 — Race condition
**Files:** `src/process/manager.rs:454-461`
**Problem:** Between `drop(dynamic)` and re-acquiring lock, another thread could modify config.
**Fix:** Use read-modify-write pattern that doesn't drop lock, or channel for spawn requests.

### 6R: Fix Duplicate App Server Init

**Severity:** P2 — Granian servers initialized twice
**Files:** `src/worker/unified_server.rs:205-235,858-888`
**Problem:** Second init shadows first `app_servers` HashMap. First initialization's results lost.
**Fix:** Remove duplicate or merge them.

### 6S: Fix `calculate_backoff` Effectively Linear After Attempt 3

**Severity:** P3 — Backoff not exponential
**Files:** `src/proxy.rs:1190-1193`
**Problem:** Cap at 30s with `attempt.min(5)` means 5s→10s→20s→30s→30s→30s.
**Fix:** Increase cap or remove `min(5)` constraint.

### 6T: Fix `recv_with_timeout` Unused `_signer`

**Severity:** P3 — Misleading code
**Files:** `src/process/ipc_transport.rs:391`
**Problem:** `signer` variable bound but never used.
**Fix:** Remove unused binding or use it if intended.

### 6U: Fix `handle_unified_workers_restart` Dead Vec Allocation

**Severity:** P3 — Dead code
**Files:** `src/process/manager.rs:1460-1538`
**Problem:** `dead` vector created, never populated, discarded.
**Fix:** Remove dead code.

### 6V: Unify HTTPS Server Feature Set with HTTP Server

**Severity:** Medium — HTTPS lacks many HTTP features
**Files:** `src/tls/server.rs:640-930`
**Problem:** HTTPS server lacks: WebSocket, serverless (WASM), FastCGI/PHP/CGI, WASM plugins, YARA upload scanning, AppServer dispatch, static file serving.
**Fix:** Refactor request handling pipeline into shared `RequestHandler` trait/function used by both servers.

---

## Wave 7: YARA, Honeypot & Threat Intelligence

*Can run in parallel with Waves 2-6. Independent domain.*

### 7A: Submit YARA Rules Admin Endpoint

**Severity:** Medium — Edge nodes can only submit programmatically
**Files:** `src/admin/handlers/yara_rules.rs`, `src/mesh/yara_rules.rs`
**Problem:** `submit_rule_for_approval()` exists but not exposed via HTTP.
**Fix:** Add `POST /yara/submit` endpoint. Validate rules, call submit, return submission_id.

### 7B: Apply Rules Directly (Global-Only) Endpoint

**Severity:** Medium — Global nodes cannot push rules without submission flow
**Files:** `src/admin/handlers/yara_rules.rs`, `src/mesh/yara_rules.rs`
**Problem:** No direct apply + broadcast for emergency rule deployment.
**Fix:** Add `POST /yara/apply` endpoint. Global-node-only. Generate version, apply, broadcast.

### 7C: Delete Submission Endpoint

**Severity:** Medium — No way to remove stale submissions
**Files:** `src/admin/handlers/yara_rules.rs`, `src/mesh/yara_rules.rs`
**Problem:** No way to remove stale or erroneous submissions.
**Fix:** Add `DELETE /yara/submissions/{id}`. Only deletable if Pending or Rejected.

### 7D: Broadcast Retry on Channel Full

**Severity:** Medium — Messages silently dropped
**Files:** `src/mesh/yara_rules.rs`
**Problem:** `broadcast_submission()` and `broadcast_approved_rules()` silently drop when mesh channel full.
**Fix:** Add bounded retry logic (3 attempts, 100ms backoff). Add dropped broadcast counter to metrics.

### 7E: Broadcast Confirmation Tracking

**Severity:** Medium — No way to know which peers received broadcast
**Files:** `src/mesh/yara_rules.rs`
**Problem:** `broadcast_approved_rules()` does not start `BroadcastAckTracker`.
**Fix:** Generate unique `request_id`, call `start_broadcast_tracking()` with peer list from transport.

### 7F: Pre-Compile Rules on Apply

**Severity:** Medium — Recompilation on every upload
**Files:** `src/mesh/yara_rules.rs`, `src/upload/mod.rs`
**Problem:** Rules stored as `String`. Each upload triggers recompilation.
**Fix:** Compile immediately on `apply_rules()`. Add `YaraScanner::reload_with_compiled_rules()` accepting `Arc<yara_x::Rules>`.

### 7G: Rate Limiting on YARA Admin Endpoints

**Severity:** Medium — Broadcast endpoint could flood mesh
**Files:** `src/admin/handlers/yara_rules.rs`
**Problem:** All YARA endpoints use `OptionalAuth` with no per-endpoint rate limiting.
**Fix:** Add per-IP sub-limits: submit 10/min, broadcast/apply 5/min, approve 10/min.

### 7H: YARA Rule Syntax Validation on Submission

**Severity:** Medium — Malformed rules only caught at apply time
**Files:** `src/admin/handlers/yara_rules.rs`, `src/mesh/yara_rules.rs`
**Problem:** Rules accepted at submission without compilation validation.
**Fix:** Attempt `yara_x::compile()` during submission. Reject with 400 and error details if invalid.

### 7I: Submission Content Validation

**Severity:** Low — No quality validation
**Files:** `src/mesh/yara_rules.rs`
**Problem:** No validation of rule content quality — empty rules, no conditions, trivially-matching rules accepted.
**Fix:** Validate at least one `rule` declaration. Warn if no `meta` fields or >100 rules in single submission.

### 7J: Content-Hash Deduplication

**Severity:** Low — Duplicate submissions waste resources
**Files:** `src/mesh/yara_rules.rs`
**Problem:** Identical rule submissions create separate entries.
**Fix:** Compute SHA-256 hash on submission. Check for matching hash + Pending status. Return existing `submission_id` if duplicate.

### 7K: Idempotent Rule Re-Application

**Severity:** Low — Prevents recovery scenarios
**Files:** `src/mesh/yara_rules.rs`
**Problem:** `handle_incoming_rules()` rejects rules when `is_newer_version()` returns false for equal versions.
**Fix:** Change version check to newer-or-equal. For equal versions, return success without recompiling.

### 7L: Truncated Rule Preview in Submissions List

**Severity:** Low — Wasteful response size
**Files:** `src/admin/handlers/yara_rules.rs`
**Problem:** `GET /yara/submissions` returns full rule text for every submission.
**Fix:** Add `rules_preview` (first 500 chars) and `rules_length` to list response. Keep full rules in individual endpoint.

### 7M: Enhanced MIME Validation for Uploads

**Severity:** Medium — MIME type bypass possible
**Files:** `src/upload/mod.rs`, `src/http/server.rs`, `src/tls/server.rs`
**Problem:** Upload validation uses MIME detection but doesn't cross-validate against declared `Content-Type`.
**Fix:** Add `reject_mime_mismatch` config. Compare declared vs detected MIME. Reject mismatch when enabled.

### 7N: Wire DHT Threat Lookup into WAF Request Path

**Severity:** High — DHT threat lookup has zero callers
**Files:** `src/waf/mod.rs`, `src/mesh/threat_intel.rs:701-746`
**Problem:** `lookup_threat_indicator_in_dht()` fully implemented but never called. WAF only checks local `BlockStore`.
**Fix:** After local block store check, add DHT lookup. Add `dht_threat_lookup: bool` config flag.

### 7O: Persistent Publish Cursor for Honeypot Records

**Severity:** Medium — All records re-published on restart
**Files:** `src/honeypot_port/runner.rs:140-223`
**Problem:** `last_timestamp` is in-memory variable. Resets on restart, re-publishing all records.
**Fix:** Add `published` column to SQLite schema. Use `get_unpublished_records()` / `mark_records_as_published()`.

### 7P: Improve Honeypot Attack Detection

**Severity:** Medium — High false-positive rates
**Files:** `src/honeypot_port/threat_intel.rs:47-96`
**Problem:** Naive substring matching. `"select from"` matches legitimate URLs. `"admin" + "login"` matches `/about/admin-login-page`.
**Fix:** Use regex patterns with contextual boundaries. Add confidence scores. Only emit above threshold.

### 7Q: Reconcile ThreatIntelligenceManager HashMap with DHT

**Severity:** Medium — Two parallel stores can diverge
**Files:** `src/mesh/threat_intel.rs:133`, `dht/record_store_crud.rs`
**Problem:** `ThreatIntelligenceManager.indicators` HashMap and `RecordStoreManager` (DHT) never reconciled.
**Fix:** Make `ThreatIntelligenceManager` single source of truth. Add `sync_from_dht()` for periodic reconciliation.

### 7R: Sign DHT Threat Records with Ed25519

**Severity:** Medium — DHT records have no cryptographic provenance
**Files:** `src/mesh/threat_intel.rs:497-545`
**Problem:** `publish_indicator_to_dht()` stores JSON with `signature: Vec::new()`.
**Fix:** Include signature and signer_public_key in DHT record JSON. Verify on lookup.

### 7S: Local Threat Intel Persistence for Standalone Mode

**Severity:** Medium — Threat intel lost on restart in standalone
**Files:** `src/mesh/threat_intel.rs`, `src/worker/unified_server.rs:355-379`
**Problem:** Standalone mode uses dummy threat intel manager. Never persisted.
**Fix:** Add `LocalThreatStore` (SQLite). Save indicators when transport is None. Load on initialization.

### 7T: Add Threat Intel Metrics and Observability

**Severity:** Low — Limited observability
**Files:** `src/mesh/threat_intel.rs`, `src/metrics/mod.rs`
**Problem:** Only honeypot-specific metrics exist.
**Fix:** Add counters for published, received, rejected, DHT lookups/hits, sync requests/responses. Expose via admin API.

---

## Wave 8: Code Quality, Safety & Performance

*Should run last — validates and cleans up all prior changes.*

### 8A: Audit Unsafe Blocks in tunnel/wireguard/tun.rs

**Severity:** High — ~20 unsafe blocks need documentation
**Files:** `src/tunnel/wireguard/tun.rs`
**Problem:** Unsafe blocks for TUN device operations lack SAFETY comments.
**Fix:** Document each unsafe block with SAFETY comments. Verify all pointer casts and FFI calls.

### 8B: Audit Unsafe Blocks in platform/unix.rs and windows_impl.rs

**Severity:** High — Raw FD to TcpListener/TcpStream conversion
**Files:** `src/platform/unix.rs`, `src/platform/windows_impl.rs`
**Problem:** `from_raw_fd`/`from_raw_socket` inherently unsafe.
**Fix:** Create `SafeTcpListener`/`SafeTcpStream` wrappers. Centralize unsafe operations with SAFETY documentation.

### 8C: Audit Unsafe Blocks in process/ipc.rs (Windows Named Pipes)

**Severity:** High — Windows API calls
**Files:** `src/process/ipc.rs:1331-1415`
**Problem:** Windows named pipe handling uses unsafe for Windows API calls.
**Fix:** Wrap in safe abstraction. Ensure all unsafe blocks have SAFETY comments.

### 8D: Audit eBPF Unsafe Blocks

**Severity:** Medium — Direct memory access to packet buffers
**Files:** `ebpf-flood/src/xdp.rs`, `ebpf-icmp/src/icmp.rs`, `ebpf-icmp/src/maps.rs`
**Problem:** eBPF code inherently uses unsafe for packet buffer access.
**Fix:** Add SAFETY documentation. Verify bounds checking before unsafe dereferences.

### 8E: Reduce `#[allow(dead_code)]` Annotations

**Severity:** Medium — Currently 72, target <60
**Files:** ~48 files
**Problem:** 72 annotations across ~48 files. Many are reserved protocol modules.
**Fix:** Audit each annotation. Remove truly dead code. Gate with `#[cfg(feature = "...")]` where appropriate. Keep reserved modules with explanatory comments.

### 8F: Replace `unwrap()` in Core Request Path

**Severity:** Medium — ~790 unwrap calls across codebase
**Files:** `src/process/ipc.rs`, `src/waf/mod.rs`, `src/proxy.rs`, and others
**Problem:** unwrap() calls in hot path can cause panics on unexpected input.
**Fix:** Replace with `?` propagation or `expect()` with context in request hot path. Test unwrap() acceptable.

### 8G: Fix `MeshTransport::initialize_component_transports` Expensive Clone

**Severity:** P2 — Clones entire ~30-field struct
**Files:** `src/mesh/transport.rs:480-488`
**Problem:** Creates `Arc::new(self.clone())` — clones entire `MeshTransport`.
**Fix:** Wrap `MeshTransport` in `Arc` at creation time. Clone `Arc` instead.

### 8H: Fix `HttpsConnection` Unnecessary Mutex

**Severity:** P3 — Unnecessary overhead
**Files:** `src/tls/server.rs:44-70`
**Problem:** `io` field wrapped in `parking_lot::Mutex` but only accessed from spawned task that owns connection.
**Fix:** Remove `Mutex` — `Option` is sufficient.

### 8I: Fix `broadcast_shutdown` PID Collection Race

**Severity:** P3 — Minor race
**Files:** `src/process/manager.rs:1574-1608`
**Problem:** PIDs collected under read lock, worker could exit between collection and signal delivery.
**Fix:** Acceptable as-is (silently ignored ESRCH). Add comment documenting expected behavior.

### 8J: Fix `transport.rs` Module Size

**Severity:** P3 — Maintainability
**Files:** `src/mesh/transport.rs` (2,197 lines)
**Problem:** Despite being "split into 11 submodules," main file still enormous.
**Fix:** Continue extracting methods into existing submodules. Target: <1,000 lines.

### 8K: Fix `config.rs` Suppression Annotations

**Severity:** P3 — Structural issues
**Files:** `src/mesh/config.rs` (1,485 lines)
**Problem:** Has `#![allow(unused_variables, non_snake_case, non_upper_case_globals)]` at top.
**Fix:** Address underlying naming/structural issues rather than suppressing warnings.

### 8L: Fix `MeshDataEncryption` Minimally Used

**Severity:** P3 — Dead code risk
**Files:** `src/mesh/network_security.rs:297-376`
**Problem:** AES-256-GCM encrypt/decrypt provided but `config` field is `#[allow(dead_code)]`.
**Fix:** Wire into transport path or remove.

### 8M: Fix `verify_post_quantum_tls` Debug-Only

**Severity:** P3 — No enforcement
**Files:** `src/mesh/cert.rs:69-121`
**Problem:** Gated behind `#[cfg(feature = "verify-pq")]` and only logs — doesn't enforce.
**Fix:** Either enforce PQ TLS verification or remove feature.

### 8N: Fix `ProbeTracker` HashSet Allocation

**Severity:** P3 — Unnecessary allocation
**Files:** `src/waf/probe_tracker.rs:246-251`
**Problem:** Allocates HashSet, immediately converts to Vec, just to get `.len()`.
**Fix:** Use `HashSet::len()` directly.

### 8O: Replace `unwrap()` in HTTP Server

**Severity:** Medium — ~50-70 unwrap/expect calls
**Files:** `src/http/server.rs`
**Problem:** Unwrap calls in request parsing, upstream connection, response handling paths.
**Fix:** Replace with `?` propagation. Add context to `expect()` calls.

### 8P: Replace `unwrap()` in Mesh Transport

**Severity:** Medium — ~40-60 unwrap/expect calls
**Files:** `src/mesh/transport.rs`
**Problem:** Unwrap in message serialization, peer connection, route query handling.
**Fix:** Use `TransportError` variants for proper error propagation.

### 8Q: Replace `unwrap()` in Process Manager

**Severity:** Medium — ~30-50 unwrap/expect calls
**Files:** `src/process/manager.rs`
**Problem:** Unwrap in worker spawn, IPC channel creation, health check responses.
**Fix:** Use `anyhow::Context` for error chain.

### 8R: Replace `unwrap()` in WAF Core

**Severity:** Medium — ~80-100 unwrap/expect calls
**Files:** `src/waf/mod.rs`, `src/waf/attack_detection/*.rs`
**Problem:** Unwrap in pattern matching, regex compilation, IP feed loading.
**Fix:** Use domain-specific error types for proper propagation.

### 8S: Replace `unwrap()` in TLS/ACME

**Severity:** Medium — ~40-60 unwrap/expect calls
**Files:** `src/tls/acme.rs`, `src/tls/cert_resolver.rs`
**Problem:** Unwrap in certificate generation, ACME challenge validation, key parsing.
**Fix:** Return errors instead of panicking.

### 8T: Replace `unwrap()` in DNS Server

**Severity:** Medium — ~50-70 unwrap/expect calls
**Files:** `src/dns/server/*.rs`, `src/dns/trust_anchor.rs`
**Problem:** Unwrap in zone file parsing, DNSSEC signing, record storage.
**Fix:** Add domain-specific `DnsError` types.

### 8U: Replace `unwrap()` in Proxy

**Severity:** Medium — ~60-80 unwrap/expect calls
**Files:** `src/proxy.rs`
**Problem:** Unwrap in upstream connection, header parsing, response streaming.
**Fix:** Use `ProxyError` variants for proper propagation.

### 8V: Replace `unwrap()` in Config Loading

**Severity:** Medium — ~70-90 unwrap/expect calls
**Files:** `src/config/*.rs`, `src/config/site.rs`, `src/config/dns.rs`
**Problem:** Unwrap in TOML parsing, default value filling, validation.
**Fix:** Use `ConfigError` variants for clear error messages.

---

## Parallelization Strategy

```
Wave 1 (Build Blockers) ─────────────────────────────────────────────────
  Agent A: 1A, 1B, 1C (wireguard/tun fixes)              ── 3 items ── 0.5 day
  Agent B: 1D, 1E, 1F (test dup, Arc, ProtectionLevel)   ── 3 items ── 0.5 day
  Agent C: 1G, 1H, 1I, 1J (missing fields/traits)        ── 4 items ── 0.5 day

Wave 2 (Critical Security & Correctness) ────────────────────────────────
  Agent A: 2A, 2B, 2C (macro recursion, empty headers, path dots) ── 3 items ── 1 day
  Agent B: 2D, 2E, 2F (worker stub, DNS ID, DNS cache)   ── 3 items ── 1 day
  Agent C: 2G, 2H (SSRF bypass, ACME perms)              ── 2 items ── 0.5 day
  Agent D: 2I-2N (IPC security: signing, replay, reader, writer, key, length) ── 6 items ── 2 days
  Agent E: 2O-2T (spawn race, plaintext tokens, config validation/drift, TLS skip, client per request) ── 5 items ── 1.5 days

Wave 3 (Mesh & DHT) ─────────────────────────────────────────────────────
  Agent A: 3A, 3B, 3C (WireGuard auth, global node auth, DHT query) ── 3 items ── 2 days
  Agent B: 3D-3G (sync sig, session rotation, cert rotation, anti-entropy) ── 4 items ── 1.5 days
  Agent C: 3H-3P (rate limiter, cfg dup, datagram, bitmask, cert expiry, seen_messages, TOFU, announce, error types, cache pattern) ── 9 items ── 2 days
  Agent D: 3Q-3Z (sharding, broadcast, prune, routing table, PoW, enum split, quorums, hierarchical routing, global HA) ── 9 items ── 2.5 days

Wave 4 (WAF & Proxy) ────────────────────────────────────────────────────
  Agent A: 4A-4H (whitelist, stale config, hardcoded config, violation/probe swap, O(n²) pattern, ring buffer, negative duration) ── 8 items ── 1.5 days
  Agent B: 4I-4L (bot protection unused, tarpit, suspicious words, dead rate limit) ── 4 items ── 0.5 day
  Agent C: 4M-4R (anomaly scoring, header validation, H2 smuggling, TLS fingerprinting, challenge rate limit, open redirect) ── 6 items ── 2 days
  Agent D: 4S-4X (duplicate WAF, stream bodies, XFF truncation, cache purge, response streaming, lazy normalization) ── 6 items ── 1.5 days

Wave 5 (DNS) ────────────────────────────────────────────────────────────
  Agent A: 5A, 5B, 5C (NSEC3, NODATA, wire format)       ── 3 items ── 1.5 days
  Agent B: 5D, 5E, 5F (bitmap trimming, dead code, TCP shutdown) ── 3 items ── 0.5 day
  Agent C: 5G-5N (UTF8, lowercase dup, dead checks, trust anchor, SOA, LookupResult, detector lowercase, rate limiter) ── 8 items ── 1 day

Wave 6 (Web Stack & Admin) ──────────────────────────────────────────────
  Agent A: 6A-6E (XFF spoofing, token logging, CSRF cleanup, path sanitization, rate limiter lock) ── 5 items ── 1 day
  Agent B: 6F-6K (provider panic, ACME state, header alloc, connection error, TCP buffer, cert watch) ── 6 items ── 1 day
  Agent C: 6L-6R (LRU lock, header alloc, request logs, MasterStatus, drain timeout, config drop, duplicate init) ── 7 items ── 1.5 days
  Agent D: 6S-6V (backoff, unused signer, dead vec, HTTPS unification) ── 4 items ── 1 day

Wave 7 (YARA, Honeypot, Threat Intel) ───────────────────────────────────
  Agent A: 7A-7F (YARA admin endpoints, broadcast retry/tracking, pre-compile) ── 6 items ── 2 days
  Agent B: 7G-7M (rate limiting, syntax validation, content validation, dedup, idempotent, preview, MIME) ── 7 items ── 1.5 days
  Agent C: 7N-7T (DHT threat lookup, honeypot cursor, attack detection, reconcile stores, sign DHT, standalone persistence, metrics) ── 7 items ── 2 days

Wave 8 (Code Quality, Safety & Performance) ─────────────────────────────
  Agent A: 8A-8D (unsafe audits: tun, platform, IPC, eBPF) ── 4 items ── 2 days
  Agent B: 8E, 8F (dead code, unwrap reduction overview)   ── 2 items ── 2 days
  Agent C: 8G-8N (expensive clone, unnecessary mutex, broadcast race, transport size, config suppression, encryption, PQ TLS, HashSet alloc) ── 8 items ── 1.5 days
  Agent D: 8O-8V (unwrap replacement across HTTP, mesh, process, WAF, TLS, DNS, proxy, config) ── 8 items ── 3 days
```

### Cross-Wave Parallelization

Waves 2-7 are largely independent and can be executed simultaneously across different agents:

```
Day 1:  Wave 1 (all agents)
Day 2:  Wave 2 (Agents A-E) + Wave 3 (Agents A-D) + Wave 4 (Agents A-D) + Wave 5 (Agents A-C) + Wave 6 (Agents A-D) + Wave 7 (Agents A-C)
Day 3-8: Continue Waves 2-7 in parallel (each wave completes on its own timeline)
Day 9-10: Wave 8 (all agents) — cleanup, unsafe audit, unwrap reduction
Day 11: Final verification — cargo fmt, clippy, test
```

**Estimated total with 7 agents: 10-14 days**

---

## Verification

After each wave:

```bash
# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Compile test code
cargo test --lib --no-run

# Run integration tests
cargo test --test integration_test
```

After all waves:

```bash
# Verify no "NOT IMPLEMENTED" in production
rg "NOT IMPLEMENTED" src/ --include '*.rs'

# Verify dead code count
rg '#\[allow\(dead_code\)\]' src/ --count

# Full test suite with DNS
cargo test --features dns

# Full build with all features
cargo build --features "dns,mesh,socket-handoff,post-quantum,wireguard"
```

---

## Risk Assessment

| Risk | Wave | Mitigation |
|------|------|-----------|
| Pattern detector macro change breaks all detectors | 2A | Add comprehensive unit tests before and after |
| DNS response ID change breaks existing clients | 2E | Verify with `dig` against running server |
| Worker→master signing breaks existing workers | 2I | Backward-compatible: accept both signed and unsigned during transition |
| NSEC3 base32hex change breaks existing zones | 5A | Only affects new NSEC3 records; existing zones need re-signing |
| Config validation rejects valid but unusual configs | 2Q | Add `force: bool` bypass parameter |
| XFF trusted proxy list misconfigured | 6A | Default to "no trusted proxies" (safe) |
| Ring buffer fix changes rate limiting behavior | 4G | Add benchmark to verify rate limiting accuracy |
| Upstream client caching changes TLS behavior | 2T | Verify TLS config hash includes all relevant fields |
| Cache PURGE auth breaks existing automation | 4U | Default to disabled; require explicit enable |
| WireGuard transport removal breaks deployments | 3A | Feature-gate; keep as optional with clear warning |
| Global node auth change breaks mesh | 3B | Backward compatibility mode with shared key fallback |
| Session rotation sync breaks all peer communication | 3E | Extensive testing, gradual rollout with opt-in flag |
| DHT persistence schema migration issues | 7S | Versioned schema, migration scripts, fallback to in-memory |
| PoW difficulty increase ejecting existing nodes | 3V | Grace period for recomputation, gradual increase |

---

## Items Noted But Deferred

| Item | Reason | Files |
|------|--------|-------|
| Config Schema Generation (schemars) | ~918 lines of hardcoded schema, low urgency | `src/admin/handlers/config.rs` |
| `http/server.rs` at 2,851 lines | Large but functional; split is non-trivial | `src/http/server.rs` |
| `config/site.rs` at 1,910 lines | Large but functional; split is non-trivial | `src/config/site.rs` |
| `config/dns.rs` at 1,838 lines | Large but functional; split is non-trivial | `src/config/dns.rs` |
| Protocol enum size (60+ variants) | Generated from protobuf; splitting is complex | `src/mesh/protocol.rs` |
| Shared request handler extraction | Large refactoring, low ROI | `src/http/server.rs`, `src/tls/server.rs`, `src/http3/server.rs` |
| Dead code cleanup target <60 | Many reserved protocol modules added | Multiple files |

---

## Source Plan Mapping

| Source Plan | Waves | Key Items |
|-------------|-------|-----------|
| `plan2.md` | 1, 8 | Build errors, missing fields, trait bounds, StatusCode conversion |
| `plan3.md` | 2, 3, 4, 5, 6, 8 | Macro recursion, empty headers, path dots, worker stub, DNS ID/cache, SSRF, ACME perms, IPC security, DNS correctness, admin security, mesh correctness, WAF correctness, TLS/proxy, code quality |
| `plan4.md` | 1, 8 | Compilation errors, large file splits, dead code, unwrap reduction, test coverage |
| `plan5.md` | 4, 8 | Scalability (topology sharding, cert eviction, connection pooling, stream bodies, duplicate WAF), security hardening (anomaly scoring, header validation, H2 smuggling, TLS fingerprinting, challenge rate limit, open redirect), performance (rate limiter, lowercase, header vec, path sanitization, response streaming, lazy normalization), architecture (HTTPS unification, AppServer, legacy worker, IPC contention, mesh body streaming, YARA delta sync), mesh control plane (quorums, hierarchical routing, global HA, topology delta, mesh metrics) |
| `plan6.md` | 3, 8 | WireGuard auth, global node auth, DHT query response, sync signature, session rotation, cert rotation, anti-entropy, topology sharding, broadcast fanout, stale peer pruning, routing table size, PoW difficulty, MeshMessage enum split, DHT persistence, expired cleanup, circuit breaker, CRL distribution |
| `plan7.md` | 6, 8 | Dead code cleanup, Granian dispatch, FastCGI pooling, IPC static worker, file browser, integration testing |
| `plan8.md` | 7, 8 | YARA admin endpoints, broadcast retry/tracking, compiled rule caching, rate limiting, syntax/content validation, deduplication, idempotent re-application, truncated preview, MIME mismatch detection |
| `plan9.md` | 7, 8 | DHT threat lookup, honeypot persistent cursor, attack detection improvement, cross-correlate signals, async AI responders, reconcile stores, standalone persistence, threat metrics |
| `plan10.md` | 1, 8, 3 | Compilation fixes (tun, SockLevel, wireguard_control, test dup, Arc/Duration), unsafe audits, dead code, unwrap reduction, performance hot spots, large file refactoring |

---

## Notes

- Many errors are interconnected — fixing Wave 1 will resolve cascading errors in later waves
- Feature flags may need adjustment for some builds (especially `wireguard`, `dns`, `mesh`)
- The `protoc` protobuf compiler is required for full compilation but not available in all environments
- Items marked as "already fixed" in source plans have been verified against current codebase and removed from this plan
- Cross-wave dependencies are minimal — Waves 2-7 can largely proceed in parallel
