# MaluWAF Code Review Improvement Plan

> **Created:** 2026-04-06
> **Source:** Comprehensive codebase review (all modules audited)
> **Status:** NEW — Items ready for implementation
> **Note:** This plan is ADDITIVE to the existing `plan.md` (which tracks 158 items at 99%+ completion). Items here are newly discovered or were previously deferred.

---

## Executive Summary

A full codebase review identified **42 new improvement items** across 6 waves, organized by severity and dependency. The existing remediation plan (`plan.md`) tracks 158 items that are ~99% complete. This plan captures remaining gaps and newly discovered issues.

**Key findings:**
- 4 P0 items (security bypass, deadlock, protocol correctness)
- 20 P1 items (mesh security, IPC, config, DNS/TLS correctness)
- 12 P2 items (HTTP architecture, performance, observability)
- 6 P3 items (cleanup, dead code, defense-in-depth)

| Wave | Focus | Items | Priority |
|------|-------|-------|----------|
| 1 | Critical Security & Stability | 4 | P0 |
| 2 | High-Severity Security & Correctness | 12 | P1 |
| 3 | Mesh Security Hardening | 8 | P1-P2 |
| 4 | HTTP/Proxy Architecture | 6 | P2 |
| 5 | DNS/TLS Correctness | 6 | P1-P2 |
| 6 | Code Quality & Maintainability | 6 | P3 |
| **TOTAL** | | **42** | |

---

## Wave 1: Critical Security & Stability

*Must be fixed immediately — each item causes security bypass, system crash, or protocol failure.*

### 1A: Fix Expired Mesh Timestamp Bounds

**Severity:** P0 — All mesh timestamp validation failing
**Files:** `src/mesh/transport_core/time.rs:4-5`
**Problem:** `MAX_REASONABLE_TIMESTAMP` is set to `1767225600` (January 1, 2026). Current date is April 6, 2026. Any message with a timestamp after this bound is rejected, breaking all mesh communication that validates timestamps.
**Fix:**
1. Update `MAX_REASONABLE_TIMESTAMP` to a far-future value (e.g., January 1, 2030)
2. Alternatively, make the bound dynamic: `current_time + 5 * 365 * 24 * 3600` (5 years ahead)
3. Add a test to verify bounds don't expire
**Verification:** `cargo test --test integration_test` — mesh messages pass timestamp validation.

### 1B: Fix Worker Restart Deadlock

**Severity:** P0 — Guaranteed deadlock on worker crash recovery
**Files:** `src/process/manager.rs:1528-1603`
**Problem:** `handle_unified_workers_restart` acquires `unified_server_workers.write()` at line 1529 and holds it for the entire iteration. Inside the loop, it calls `self.spawn_unified_server_worker_with_id()` which tries to acquire the same `unified_server_workers.write()` lock at line 845. `parking_lot::RwLock` is not reentrant → **deadlock**.
**Fix:**
1. Collect dead worker IDs while holding the lock
2. Drop the write lock
3. Spawn replacements outside the lock
4. Re-acquire lock to update worker state after spawn completes
**Verification:** Kill a unified server worker and verify it restarts without deadlock.

### 1C: Implement Global Node Invitation Signature Verification

**Severity:** P0 — Any attacker can forge global node invitation
**Files:** `src/mesh/transport_global.rs:326-364`
**Problem:** `validate_global_node_invitation()` decodes the invitation, checks expiration, but **never verifies the cryptographic signature**. Comment at line 362: "For now, we trust the invitation if it parses correctly."
**Fix:**
1. Extract the signature from the invitation
2. Retrieve the genesis public key
3. Verify Ed25519 signature over the invitation data
4. Return error if signature verification fails
**Verification:** Test with valid and forged invitations — only valid ones accepted.

### 1D: Fix DNS Response ID to Match Query

**Severity:** P0 — DNS clients reject all normal responses
**Files:** `src/dns/server/response.rs:20`
**Problem:** `build_response` generates a random response ID via `Self::generate_random_id()` instead of copying the transaction ID from the query. Per RFC 1035 Section 4.1.1, response ID MUST match query ID.
**Fix:**
1. Pass the query bytes or query ID to `build_response`
2. Extract transaction ID from query: `wire::get_message_id(query)`
3. Use extracted ID in response header
4. Verify `build_nxdomain_response` and `build_nodata_response` already do this correctly (they use `wire::get_message_id(query).unwrap_or_else(Self::generate_random_id)`)
**Verification:** Run DNS server and query with `dig` — response ID matches query ID.

---

## Wave 2: High-Severity Security & Correctness

*Must be fixed after Wave 1. Each item causes security bypass, data loss, or feature failure.*

### 2A: Implement OAuth DNS Challenge Verification

**Severity:** P1 — Any node claiming OAuth challenge is auto-trusted
**Files:** `src/mesh/transport_dns.rs:1128-1146`
**Problem:** `verify_oauth_challenge()` is a stub that always returns `true`:
```rust
tracing::debug!("Would perform OAuth DNS challenge verification for {}", domain);
true
```
**Fix:** Implement actual OAuth DNS challenge verification:
1. Query DNS for the expected OAuth challenge record
2. Verify the record matches the expected value
3. Return false if verification fails
**Verification:** Test with valid and invalid OAuth challenges.

### 2B: Reject Unsigned Site Config Sync Messages

**Severity:** P1 — Arbitrary config injection into mesh
**Files:** `src/mesh/transport_peer.rs:1189-1195`
**Problem:** When `signature.is_empty()`, site config sync is accepted without authentication:
```rust
} else {
    tracing::debug!("Site config sync from {} has no signature - accepting (backward compatible)", source_node_id);
    true
};
```
**Fix:**
1. Require signatures on all site config sync messages
2. Remove the backward-compatible unsigned path
3. Verify signature against sender's public key
4. Reject messages with empty signatures
**Verification:** Test with signed and unsigned config sync messages.

### 2C: Sign Organization and Tier Key Messages

**Severity:** P1 — Cannot verify org/tier messages
**Files:** `src/mesh/transport_org.rs:212,388-389`
**Problem:** Organization registration responses and tier key announce messages are sent with empty signatures (`Vec::new()` / `vec![]`).
**Fix:**
1. Sign org registration responses with node's Ed25519 key
2. Sign tier key announce messages with node's Ed25519 key
3. Verify signatures on receipt
**Verification:** Test message signing and verification round-trip.

### 2D: Verify Key Exchange Signatures

**Severity:** P1 — Key exchange responses not verified
**Files:** `src/mesh/transport_global.rs:591-615`
**Problem:** `handle_key_signed()` receives `_origin_ed25519_pubkey`, `_server_x25519_pubkey`, and `_origin_signature` but all parameters are prefixed with underscores and **never used**. The method logs completion without verifying the cryptographic signature.
**Fix:**
1. Remove underscore prefixes from parameters
2. Verify `_origin_signature` against `_origin_ed25519_pubkey`
3. Return error if signature verification fails
**Verification:** Test with valid and forged key exchange signatures.

### 2E: Call `message.validate()` in IPC Handler

**Severity:** P1 — Rogue worker can flood master with oversized messages
**Files:** `src/master/ipc.rs:360-524`
**Problem:** `handle_worker_connection` receives and processes messages but never calls `message.validate()`. The `Message::validate()` method exists to prevent memory exhaustion from maliciously large IPC messages.
**Fix:**
1. Call `message.validate()` after deserializing each message
2. Reject messages that fail validation with appropriate error
3. Log validation failures for monitoring
**Verification:** Send oversized IPC message — it should be rejected.

### 2F: Fix ZIP Extraction Path Traversal

**Severity:** P1 — Crafted ZIP can write outside destination directory
**Files:** `src/static_files/file_manager.rs:767-810`
**Problem:** ZIP extraction joins entry names directly with destination path without validating that the resolved path stays within the destination:
```rust
let outpath = dest.join(file.name());
```
A crafted ZIP with `../../../etc/passwd` as an entry name could write outside the destination directory.
**Fix:**
1. Canonicalize the output path
2. Verify it starts with the destination directory prefix
3. Reject entries that would escape the destination
4. Use `tar` crate's `unpack_in` pattern for ZIP (or implement equivalent)
**Verification:** Test with crafted ZIP containing path traversal entries.

### 2G: Fix WAF Body Inspection Truncation Bypass

**Severity:** P1 — Attack hidden after 1MB of benign data
**Files:** `src/http/server.rs:704-711`
**Problem:** If a request body exceeds 1MB (`MAX_WAF_BODY_SIZE`), only the first 1MB is sent to the WAF. An attacker can prepend 1MB of benign data followed by a malicious payload.
**Fix:**
1. Implement chunked WAF inspection that scans the entire body in segments
2. Use the existing `check_body_only()` method for incremental scanning
3. Set a reasonable maximum body size for full inspection (e.g., 10MB)
4. Reject bodies exceeding the maximum
**Verification:** Test with 2MB body containing attack at offset 1.5MB.

### 2H: Fix Chunk WAF Block Decision Propagation

**Severity:** P1 — Blocked requests may still proceed to upstream
**Files:** `src/http/server.rs:1643-1649` (HTTP), `src/tls/server.rs` (HTTPS)
**Problem:** When chunk WAF blocks a request during streaming body collection, `collect_body_with_chunk_waf` returns `Bytes::new()` (empty body) rather than propagating the block decision. The caller proceeds with an empty body and may still forward to upstream.
**Fix:**
1. Return a `Result` or enum that distinguishes between "empty body" and "blocked"
2. When blocked, return an error response immediately
3. Do not proceed to upstream forwarding
**Verification:** Test chunk WAF block — request should be rejected, not forwarded.

### 2I: Fix `unreachable!()` Panic on Upstream Body Error

**Severity:** P1 — Panics on upstream body stream errors
**Files:** `src/http/server.rs:2018-2021`
**Problem:**
```rust
.map_err(|e| {
    tracing::warn!("Upstream body stream error: {}", e);
    unreachable!()
})
```
The `unreachable!()` will panic if the upstream body stream produces an error.
**Fix:**
1. Change the error type from `Infallible` to a proper error type
2. Return an error response instead of panicking
3. Or use `BoxBody<Bytes, Box<dyn Error + Send + Sync>>` and handle errors gracefully
**Verification:** Simulate upstream body stream error — should return error response, not panic.

### 2J: Fix Config Reload Not Reinitializing Subsystems

**Severity:** P1 — Mesh/YARA/upload config changes silently ignored
**Files:** `src/worker/unified_server.rs:1109-1132`
**Problem:** When `MasterConfigReload` is received, the worker reloads the `ConfigManager` but does not reinitialize dependent subsystems (mesh, threat intel, YARA rules, upload validator, honeypot, etc.).
**Fix:**
1. Identify which subsystems need reinitialization on config change
2. Add reinitialization logic to the config reload handler
3. For subsystems that cannot be hot-reloaded, log a warning requiring restart
4. Document which config fields require full restart vs. hot-reload
**Verification:** Change mesh config via admin API — verify worker picks up changes.

### 2K: Fix Duplicate `UnifiedServerWorkerReady` Message

**Severity:** P1 — Duplicate state transitions and event emissions
**Files:** `src/worker/unified_server.rs:912,994`
**Problem:** `UnifiedServerWorkerReady` message is sent twice — once at line 912 (after blocklist request) and again at line 994 (after state construction).
**Fix:** Remove one of the two sends. The send at line 994 (after full state construction) is the correct one.
**Verification:** Monitor master logs — should see only one `WorkerReady` event per worker.

### 2L: Fix Nonce Cache Eviction Policy

**Severity:** P1 — Replay attack possible if nonce evicted before time window
**Files:** `src/process/ipc_signed.rs:15-33`
**Problem:** `NONCE_CACHE` uses `HashSet` with fixed capacity of 10,000. When full, evicts via `cache.iter().next()` — but `HashSet` has no ordering guarantee, so the evicted entry is arbitrary, not temporally oldest.
**Fix:**
1. Use `LinkedHashMap` or `LruCache` for nonce cache to ensure LRU eviction
2. Or use a time-bounded approach: store `(nonce, timestamp)` tuples and evict by timestamp
3. Add test to verify eviction order
**Verification:** Test replay attack with nonce cache at capacity.

---

## Wave 3: Mesh Security Hardening

*Can run in parallel with Waves 2, 4, 5, 6. Independent domain.*

### 3A: Fix TOFU Fingerprint Race Condition

**Severity:** P1 — Race condition in Trust On First Use
**Files:** `src/mesh/cert.rs:476-503`
**Problem:** `verify_seed_fingerprint()` reads the fingerprints map, drops the lock, then re-acquires it to pin a new fingerprint. Between the read and write, another thread could pin a different fingerprint.
**Fix:**
1. Use a single lock acquisition for both read and write
2. Or use `entry()` API to atomically check-and-insert
3. Add test for concurrent fingerprint pinning
**Verification:** Test concurrent TOFU pinning — only first fingerprint should be accepted.

### 3B: Fix Mutual TLS Not Enforced on Client Side

**Severity:** P1 — Client certificates loaded but never used
**Files:** `src/mesh/cert.rs:370-417`
**Problem:** `build_client_config()` loads `cert_path` and `key_path` (lines 371-382) but builds the client config with `.with_no_client_auth()` (line 399). The `enforce_mutual_tls` config option is contradicted.
**Fix:**
1. When `enforce_mutual_tls` is true and client cert/key are available, use `.with_client_auth_cert()`
2. Only fall back to `.with_no_client_auth()` when no client cert is configured
3. Log a warning if mutual TLS is enforced but no client cert is available
**Verification:** Test mesh connection with mutual TLS enabled — client cert should be sent.

### 3C: Fix Route Response Signature Verification

**Severity:** P1 — Route responses have empty signatures
**Files:** `src/mesh/transport_routing.rs:151,181,348,395`
**Problem:** All `RouteResponse` messages are created with `signature: vec![]`, despite `requires_signature()` indicating that `RouteResponse` should require signatures.
**Fix:**
1. Sign route responses with node's Ed25519 key
2. Verify signatures on receipt
3. Reject unsigned route responses
**Verification:** Test route query/response with signature verification.

### 3D: Fix Busy-Wait Loop for Peer Datagrams

**Severity:** P1 — CPU-intensive, doesn't scale with peer count
**Files:** `src/mesh/transport_peer.rs:50-72`
**Problem:** `wait_for_peer_datagrams()` iterates all peer connections sequentially, and if none have data, sleeps for 1ms and retries. With N peers, each iteration takes O(N) async calls.
**Fix:**
1. Use `tokio::select!` with all peer datagram futures
2. Or use a shared channel that peers push datagrams into
3. Eliminate the 1ms busy-wait sleep
**Verification:** Monitor CPU usage with 10+ peers — should be near-zero when idle.

### 3E: Fix `handle_peer_message()` Ignoring 33+ Message Types

**Severity:** P1 — Silent message drops for most message types
**Files:** `src/mesh/transport_peer.rs:1707-1709`
**Problem:** The stream-based `handle_peer_message()` only handles ~7 message types, while the datagram handler handles 40+. Any message sent via stream that is not one of the 7 handled types is silently dropped.
**Fix:**
1. Add handling for all message types in the stream-based handler
2. Or delegate to the same dispatch logic as the datagram handler
3. Log unhandled message types for debugging
**Verification:** Send each message type via stream — all should be handled or logged.

### 3F: Fix `proactive_cache_warm()` Removing Pending Queries

**Severity:** P1 — Cache warming responses have no receiver
**Files:** `src/mesh/transport_routing.rs:621-639`
**Problem:** Query is registered and then immediately removed (`take`), so even if a response arrives, there is no receiver to handle it.
**Fix:**
1. Do not call `take()` immediately after registering the query
2. Let the response handler clean up the pending query
3. Or use a fire-and-forget approach that doesn't register a pending query
**Verification:** Test proactive cache warming — responses should be processed.

### 3G: Fix `derive_public_key()` Misleading Name

**Severity:** P2 — SHA-256 hash is not an Ed25519 public key
**Files:** `src/mesh/config.rs:1195-1200`
**Problem:** `derive_public_key()` computes a SHA-256 hash, not an Ed25519 public key derivation. The function name is misleading.
**Fix:**
1. Rename to `derive_node_id_from_key()` or similar
2. Or implement actual Ed25519 public key derivation
3. Add documentation explaining the purpose
**Verification:** No functional change — rename only.

### 3H: Fix `MeshGlobalRateLimiter` Hardcoded Values

**Severity:** P2 — Constructor parameters ignored
**Files:** `src/mesh/transport_types.rs:12-18`
**Problem:** Constructor parameters are unused (prefixed with `_`). Rate limiter always uses hardcoded window sizes.
**Fix:**
1. Use the constructor parameters to configure the sliding windows
2. Remove underscore prefixes from parameters
**Verification:** Test rate limiter with different configurations.

---

## Wave 4: HTTP/Proxy Architecture

*Can run in parallel with Waves 2, 3, 5, 6.*

### 4A: Split Monolithic `handle_request` Function

**Severity:** P2 — 2,165-line function is unmaintainable
**Files:** `src/http/server.rs:366-2530`
**Problem:** Single async function handles: connection limits, bandwidth checks, WAF, routing, WebSocket, static files, FastCGI, PHP, serverless, proxy, transforms, and logging. Impossible to test in isolation.
**Fix:**
1. Extract into a pipeline of middleware-like stages
2. Each stage returns a `Result<Response, StageError>` with early return
3. Stages: `connection_limit` → `bandwidth_check` → `waf_early` → `body_collection` → `route_resolution` → `waf_full` → `backend_dispatch` → `response_transform` → `logging`
4. Each stage is a separate function with focused responsibility
**Verification:** Each stage should have unit tests.

### 4B: Eliminate Duplicated Response Builder Code

**Severity:** P2 — Parallel implementations in `server.rs` and `shared_handler.rs`
**Files:** `src/http/server.rs:2671-2731`, `src/http/shared_handler.rs:60-122`
**Problem:** `build_response_with_alt_svc` and `build_response_with_cookie` are implemented identically in both modules.
**Fix:**
1. Extract shared response builders into a single module
2. Both `HttpServer` and `SharedRequestHandler` delegate to the shared module
3. Remove duplicate implementations
**Verification:** `cargo clippy -- -D warnings` — no duplicate code warnings.

### 4C: Eliminate Duplicated Minification/Compression Logic

**Severity:** P2 — Copy-pasted between mesh and static config paths
**Files:** `src/http/server.rs:2144-2416`
**Problem:** Minification/compression/image poisoning logic is duplicated between the mesh-transport path (lines 2144-2281) and the static-config path (lines 2284-2416).
**Fix:**
1. Extract into a `apply_body_transforms()` function
2. Pass configuration source as a parameter
3. Single implementation handles both paths
**Verification:** Test minification and compression in both paths.

### 4D: Fix Zero-Copy Streaming Being Defeated

**Severity:** P2 — Static files fully buffered despite "ZeroCopy" label
**Files:** `src/http/server.rs:1314-1363`, `src/tls/server.rs:924-961`
**Problem:** `ZeroCopy` variant reads entire file into a `Vec` before returning, defeating the purpose of streaming.
**Fix:**
1. Return a `StreamBody<ReaderStream<File>>` directly without buffering
2. Change response body type to support streaming
3. Only buffer when body transforms are required
**Verification:** Monitor memory usage when serving large files — should be constant.

### 4E: Fix `build_headers_to_filter` Cloning Static Set Every Request

**Severity:** P2 — Unnecessary allocation on hot path
**Files:** `src/proxy.rs:110-127`
**Problem:** Clones entire `AHashSet<String>` and allocates new `String`s for every request.
**Fix:**
1. Use `&'static` set for static headers
2. Only allocate for dynamic headers
3. Use `Cow` or similar to avoid cloning when no dynamic headers
**Verification:** Benchmark header filtering — should show reduced allocations.

### 4F: Add Tests for `server.rs`

**Severity:** P2 — 3,253 lines with zero unit tests
**Files:** `src/http/server.rs`
**Problem:** No `#[cfg(test)]` module. Critical code paths (body collection, WAF integration, backend dispatch, response building) are untested.
**Fix:**
1. Add unit tests for response builders
2. Add unit tests for header filtering
3. Add integration tests for request pipeline
4. Add tests for body collection with chunk WAF
5. Add tests for backend dispatch routing
**Verification:** `cargo test --lib` — new tests pass.

---

## Wave 5: DNS/TLS Correctness

*Can run in parallel with Waves 2, 3, 4, 6. Independent domain.*

### 5A: Fix NSEC3 SHA-256 Silently Falling Back to SHA-1

**Severity:** P1 — Wrong hash algorithm for NSEC3
**Files:** `src/dns/dnssec_signing.rs:197-211`
**Problem:** NSEC3 with SHA-256 (algorithm 2) falls back to SHA-1 with an admission comment. Produces SHA-1 hashes but claims algorithm 2.
**Fix:**
1. Implement proper SHA-256 hashing for NSEC3
2. Or return an error if SHA-256 is requested but not supported
3. Do not silently fall back to SHA-1
**Verification:** Test NSEC3 with SHA-256 — hashes should use SHA-256.

### 5B: Fix DNS Firewall Missing IPv6 and Loopback Blocks

**Severity:** P1 — Incomplete DNS firewall
**Files:** `src/dns/server/mod.rs:682-716`
**Problem:** Blocks RFC 1918 addresses but NOT:
- 127.0.0.0/8 (loopback)
- 169.254.0.0/16 (link-local)
- ::1/128 (IPv6 loopback)
- fc00::/7 (IPv6 ULA)
- fe80::/10 (IPv6 link-local)
**Fix:**
1. Add all private/reserved address ranges to the firewall
2. Include both IPv4 and IPv6 ranges
3. Add test for each blocked range
**Verification:** Query DNS for records pointing to blocked addresses — should be filtered.

### 5C: Fix Wildcard TLS Certificate Matching

**Severity:** P1 — Wildcard certs don't match subdomains
**Files:** `src/tls/cert_resolver.rs:323-336`
**Problem:** Cert resolver does exact SNI matching only. `*.example.com` will NOT match `api.example.com`.
**Fix:**
1. Implement wildcard matching: `*.example.com` matches `api.example.com` but not `foo.api.example.com`
2. Check for wildcard cert after exact match fails
3. Use longest-match semantics (exact > wildcard > default)
**Verification:** Test with wildcard certificate — subdomains should match.

### 5D: Fix `parse_all_dnskey_records` Only Parsing One Record

**Severity:** P1 — Only first DNSKEY loaded from file
**Files:** `src/dns/trust_anchor.rs:730-744`
**Problem:** Despite the name `parse_all_dnskey_records`, only a single DNSKEY record is parsed.
**Fix:**
1. Split content by lines
2. Parse each line that contains "DNSKEY"
3. Return all parsed records
**Verification:** Test with file containing multiple DNSKEY records — all should be loaded.

### 5E: Fix `prefer_post_quantum` Flag Having No Effect

**Severity:** P2 — Config flag is misleading
**Files:** `src/tls/cert_resolver.rs:259-264`
**Problem:** Both branches of the `prefer_post_quantum` check call `default_provider()`. The flag only increments a counter.
**Fix:**
1. When `prefer_post_quantum` is true, use a PQ-enabled provider
2. Or remove the flag if PQ is always enabled via `rustls` features
3. Update documentation to reflect actual behavior
**Verification:** Test with `prefer_post_quantum` true/false — should show different providers.

### 5F: Fix ACME Credentials File Race Condition

**Severity:** P2 — Credentials briefly world-readable
**Files:** `src/tls/acme.rs:157-171`
**Problem:** File is created with default permissions, then permissions are changed, then content is written. Brief window where file exists with default permissions (typically 0644).
**Fix:**
1. Write to a temp file with 0600 permissions
2. Rename temp file to final path (atomic on POSIX)
3. Or use `OpenOptions` to set mode before writing
**Verification:** Check file permissions during creation — should always be 0600.

---

## Wave 6: Code Quality & Maintainability

*Should run last — validates and cleans up all prior changes.*

### 6A: Remove Module-Level `#![allow(dead_code, unused_mut)]`

**Severity:** P3 — Masks potential issues
**Files:** `src/tls/server.rs:1`
**Problem:** Module-level allow suppresses all dead code and unused mut warnings for the entire 1,000+ line file.
**Fix:**
1. Remove module-level allow
2. Add targeted `#[allow(...)]` annotations on specific items that need them
3. Fix or remove actual dead code
**Verification:** `cargo clippy -- -D warnings` — no new warnings.

### 6B: Remove Deprecated `run_worker` Function

**Severity:** P3 — Non-functional stub still compiles
**Files:** `src/worker/mod.rs:62-364`
**Problem:** `#[deprecated]` function contains a full (non-functional) implementation that binds to `127.0.0.1:{port}` and drops all connections. Not gated from being called internally.
**Fix:**
1. Remove the entire `run_worker` function
2. Update any remaining references to use the unified server
**Verification:** `cargo check --lib` — no references to `run_worker`.

### 6C: Fix Supervisor Being a Stub

**Severity:** P3 — Auto-scaler and health monitor non-functional
**Files:** `src/supervisor/supervisor.rs:99-150`
**Problem:** `Supervisor` spawns fake workers that just sleep in a loop. Does not spawn child processes or handle real work.
**Fix:**
1. Either implement real worker supervision
2. Or remove the module and document that supervision is not yet implemented
3. If removing, update any code that depends on it
**Verification:** Depends on decision — either test real supervision or verify no references remain.

### 6D: Fix `FileManagerState` Unused `config` Field

**Severity:** P3 — Dead field
**Files:** `src/http/file_manager.rs:74`
**Problem:** `config: Arc<TokioRwLock<ConfigManager>>` is stored but never accessed by any handler.
**Fix:** Remove the field from `FileManagerState`.
**Verification:** `cargo clippy -- -D warnings` — no dead code warnings.

### 6E: Fix `file_manager_handler` Being a Stub

**Severity:** P3 — Always returns 404
**Files:** `src/http/file_manager.rs:366-372`
**Problem:** Function always returns `StatusCode::NOT_FOUND`. Actual routing is done by `create_file_manager_router`.
**Fix:**
1. Remove the stub function
2. Or implement it to delegate to the router
**Verification:** File manager routes should work as expected.

### 6F: Fix Overseer Using External `kill` Command

**Severity:** P3 — Inconsistent with rest of codebase
**Files:** `src/overseer/process.rs:368-373`
**Problem:** Uses `std::process::Command::new("kill").arg("-0")` instead of `nix::sys::signal::kill` which is already used elsewhere in the same file.
**Fix:** Use `nix::sys::signal::kill(Pid::from_raw(pid), None)` to check if process is alive.
**Verification:** Recovery should work without external `kill` binary.

---

## Parallelization Strategy

```
Wave 1 (Critical) ───────────────────────────────────────────────────────
  Agent A: 1A (timestamp bounds) + 1D (DNS response ID)     ── 2 items
  Agent B: 1B (worker restart deadlock)                      ── 1 item
  Agent C: 1C (global node invitation signature)             ── 1 item

Wave 2 (High Security) ──────────────────────────────────────────────────
  Agent A: 2A (OAuth) + 2B (unsigned config) + 2C (org signing) ── 3 items
  Agent B: 2D (key exchange) + 2E (IPC validation) + 2F (ZIP traversal) ── 3 items
  Agent C: 2G (WAF truncation) + 2H (chunk WAF block) + 2I (upstream panic) ── 3 items
  Agent D: 2J (config reload) + 2K (duplicate ready) + 2L (nonce cache) ── 3 items

Wave 3 (Mesh Security) ──────────────────────────────────────────────────
  Agent A: 3A (TOFU race) + 3B (mTLS client) + 3C (route signatures) ── 3 items
  Agent B: 3D (busy-wait) + 3E (ignored messages) + 3F (cache warm) ── 3 items
  Agent C: 3G (derive_public_key rename) + 3H (rate limiter) ── 2 items

Wave 4 (HTTP/Proxy) ─────────────────────────────────────────────────────
  Agent A: 4A (split handle_request)                          ── 1 item (large)
  Agent B: 4B (response builders) + 4C (minification/compression) ── 2 items
  Agent C: 4D (zero-copy streaming) + 4E (header filtering) + 4F (tests) ── 3 items

Wave 5 (DNS/TLS) ────────────────────────────────────────────────────────
  Agent A: 5A (NSEC3 SHA-256) + 5B (DNS firewall) + 5C (wildcard certs) ── 3 items
  Agent B: 5D (DNSKEY parsing) + 5E (PQ flag) + 5F (ACME race) ── 3 items

Wave 6 (Code Quality) ───────────────────────────────────────────────────
  Agent A: 6A (module allow) + 6B (deprecated worker) + 6C (supervisor) ── 3 items
  Agent B: 6D (unused field) + 6E (stub handler) + 6F (kill command) ── 3 items
```

### Cross-Wave Parallelization

```
Day 1:  Wave 1 (all agents — critical path)
Day 2:  Wave 2 (Agents A-D) + Wave 3 (Agents A-C) + Wave 5 (Agents A-B)
Day 3:  Continue Waves 2, 3, 5
Day 4:  Wave 4 (Agents A-C) + Wave 6 (Agents A-B)
Day 5:  Continue Wave 4 (4A is large) + Wave 6
Day 6:  Final verification — cargo fmt, clippy, test
```

**Estimated total with 5 agents: 5-6 days**

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
# Full test suite
cargo test

# Build with all features
cargo build --features "dns,mesh,socket-handoff,post-quantum"
```

---

## Risk Assessment

| Risk | Wave | Mitigation |
|------|------|-----------|
| Worker restart deadlock fix breaks other restart paths | 1B | Test all restart scenarios (regular + unified workers) |
| DNS response ID change breaks existing clients | 1D | Verify with `dig` against running server |
| Global node signature verification breaks existing mesh | 1C | Add migration path with unsigned fallback (time-limited) |
| ZIP path traversal fix breaks legitimate archives | 2F | Test with valid archives containing nested directories |
| `handle_request` split introduces regression | 4A | Extensive integration tests before and after |
| NSEC3 SHA-256 fix breaks existing zones | 5A | Only affects new NSEC3 records; existing zones need re-signing |
| Wildcard cert matching breaks exact-match priority | 5C | Test exact > wildcard > default ordering |

---

## Relationship to Existing Plan

This plan is **additive** to `plan.md`. The existing plan tracks 158 items across 8 waves at ~99% completion. Items in this plan are:

1. **Newly discovered** during the comprehensive code review
2. **Previously deferred** items that were noted in AGENTS.md but not tracked
3. **Higher-priority** than remaining deferred items in the existing plan

Items from this plan should be prioritized over the "Items Noted But Deferred" section in `plan.md`.

---

## Notes

- Items in Wave 1 are **blocking** — no other work should proceed until they are fixed
- Items in Waves 2-5 are largely independent and can be executed in parallel
- Wave 6 items are cleanup and should run after all functional fixes
- Several items (4A, 4D) require architectural changes — plan for additional testing time
- The `protoc` protobuf compiler is required for mesh-related changes
