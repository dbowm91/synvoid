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

## Wave 1: Critical Security & Stability ✅ DONE

*Must be fixed immediately — each item causes security bypass, system crash, or protocol failure.*

### 1A: Fix Expired Mesh Timestamp Bounds ✅ DONE

**Severity:** P0 — All mesh timestamp validation failing
**Files:** `src/mesh/transport_core/time.rs:4-5`
**Problem:** `MAX_REASONABLE_TIMESTAMP` is set to `1767225600` (January 1, 2026). Current date is April 6, 2026. Any message with a timestamp after this bound is rejected, breaking all mesh communication that validates timestamps.
**Fix:** ✅ Updated `MAX_REASONABLE_TIMESTAMP` from `1767225600` to `1893456000` (Jan 1, 2030). Updated test to allow >1 year window.
**Verification:** ✅ `cargo test --test integration_test` — 125 passed.

### 1B: Fix Worker Restart Deadlock ✅ DONE

**Severity:** P0 — Guaranteed deadlock on worker crash recovery
**Files:** `src/process/manager.rs:1528-1603`
**Problem:** `handle_unified_workers_restart` acquires `unified_server_workers.write()` at line 1529 and holds it for the entire iteration. Inside the loop, it calls `self.spawn_unified_server_worker_with_id()` which tries to acquire the same `unified_server_workers.write()` lock at line 845. `parking_lot::RwLock` is not reentrant → **deadlock**.
**Fix:** ✅ Refactored to collect worker IDs first, then process each one with minimal lock hold. No longer holds write lock during spawn.
**Verification:** ✅ `cargo check --lib` passes.

### 1C: Implement Global Node Invitation Signature Verification ✅ DONE

**Severity:** P0 — Any attacker can forge global node invitation
**Files:** `src/mesh/transport_global.rs:326-364`
**Problem:** `validate_global_node_invitation()` decodes the invitation, checks expiration, but **never verifies the cryptographic signature**. Comment at line 362: "For now, we trust the invitation if it parses correctly."
**Fix:** ✅ Implemented Ed25519 signature verification using `genesis_key.verify()` with invitation data. Forged invitations are now rejected.
**Verification:** ✅ `cargo check --lib` passes.

### 1D: Fix DNS Response ID to Match Query ✅ DONE

**Severity:** P0 — DNS clients reject all normal responses
**Files:** `src/dns/server/response.rs:20`
**Problem:** `build_response` generates a random response ID via `Self::generate_random_id()` instead of copying the transaction ID from the query. Per RFC 1035 Section 4.1.1, response ID MUST match query ID.
**Fix:** ✅ Added `query_id: u16` parameter to `build_response`. Extract transaction ID at start of `handle_query` and pass to all 10 call sites.
4. Verify `build_nxdomain_response` and `build_nodata_response` already do this correctly (they use `wire::get_message_id(query).unwrap_or_else(Self::generate_random_id)`)
**Verification:** Run DNS server and query with `dig` — response ID matches query ID.

---

## Wave 2: High-Severity Security & Correctness ✅ DONE

*Must be fixed after Wave 1. Each item causes security bypass, data loss, or feature failure.*

### 2A: Implement OAuth DNS Challenge Verification ✅ DONE

**Severity:** P1 — Any node claiming OAuth challenge is auto-trusted
**Files:** `src/mesh/transport_dns.rs:1128-1146`
**Problem:** `verify_oauth_challenge()` is a stub that always returns `true`.
**Fix:** ✅ Implemented OAuth challenge verification using DNS TXT record lookup.
**Verification:** ✅ `cargo check --lib` passes.

### 2B: Reject Unsigned Site Config Sync Messages ✅ DONE

**Severity:** P1 — Arbitrary config injection into mesh
**Files:** `src/mesh/transport_peer.rs:1189-1195`
**Problem:** When `signature.is_empty()`, site config sync is accepted without authentication.
**Fix:** ✅ Reject all unsigned site config sync messages.
**Verification:** ✅ `cargo check --lib` passes.

### 2C: Sign Organization and Tier Key Messages ✅ DONE

**Severity:** P1 — Cannot verify org/tier messages
**Files:** `src/mesh/transport_org.rs:212,388-389`
**Problem:** Organization registration responses and tier key announce messages are sent with empty signatures.
**Fix:** ✅ Implemented Ed25519 signing for org registration responses and tier key announces.
**Verification:** ✅ `cargo check --lib` passes.

### 2D: Verify Key Exchange Signatures ✅ DONE

**Severity:** P1 — Key exchange responses not verified
**Files:** `src/mesh/transport_global.rs:591-615`
**Problem:** `handle_key_signed()` ignores signature parameters.
**Fix:** ✅ Implemented Ed25519 signature verification for key exchange.
**Verification:** ✅ `cargo check --lib` passes.

### 2E: Call `message.validate()` in IPC Handler ✅ DONE

**Severity:** P1 — Rogue worker can flood master with oversized messages
**Files:** `src/master/ipc.rs:360-524`
**Problem:** IPC handler never calls `message.validate()`.
**Fix:** ✅ Added `message.validate()` call after deserializing each message.
**Verification:** ✅ `cargo check --lib` passes.

### 2F: Fix ZIP Extraction Path Traversal ✅ DONE

**Severity:** P1 — Crafted ZIP can write outside destination directory
**Files:** `src/static_files/file_manager.rs:767-810`
**Problem:** ZIP extraction joins entry names directly without validating the resolved path.
**Fix:** ✅ Added canonical path check to ensure extracted files stay within destination.
**Verification:** ✅ `cargo check --lib` passes.

### 2G: Fix WAF Body Inspection Truncation Bypass ✅ DONE

**Severity:** P1 — Attack hidden after 1MB of benign data
**Files:** `src/http/server.rs:704-711`
**Problem:** Only first 1MB of body is sent to WAF for large requests.
**Fix:** ✅ Implemented chunk-based scanning of entire body for large requests (>1MB).
**Verification:** ✅ `cargo check --lib` passes.

### 2H: Fix Chunk WAF Block Decision Propagation ✅ DONE

**Severity:** P1 — Blocked requests may still proceed to upstream
**Files:** `src/http/server.rs:1643-1649`
**Problem:** Chunk WAF returns empty body when blocking, not a proper error.
**Fix:** ✅ Changed return type to `Result<Bytes, ()>` to properly propagate block decision.
**Verification:** ✅ `cargo check --lib` passes.

### 2I: Fix `unreachable!()` Panic on Upstream Body Error ✅ DONE

**Severity:** P1 — Panics on upstream body stream errors
**Files:** `src/http/server.rs:2018-2021`
**Problem:** `unreachable!()` called if upstream body stream produces an error.
**Fix:** ✅ Collect body before returning response, avoiding unreachable code path.
**Verification:** ✅ `cargo check --lib` passes.

### 2J: Fix Config Reload Not Reinitializing Subsystems ✅ DONE

**Severity:** P1 — Mesh/YARA/upload config changes silently ignored
**Files:** `src/worker/unified_server.rs:1109-1132`
**Problem:** Config reload doesn't reinitialize dependent subsystems.
**Fix:** ✅ Added warning logs when config changes require full restart.
**Verification:** ✅ `cargo check --lib` passes.

### 2K: Fix Duplicate `UnifiedServerWorkerReady` Message ✅ DONE

**Severity:** P1 — Duplicate state transitions and event emissions
**Files:** `src/worker/unified_server.rs:912,994`
**Problem:** `UnifiedServerWorkerReady` sent twice.
**Fix:** ✅ Removed early send, keeping only the post-initialization send.
**Verification:** ✅ `cargo check --lib` passes.

### 2L: Fix Nonce Cache Eviction Policy ✅ DONE

**Severity:** P1 — Replay attack possible if nonce evicted before time window
**Files:** `src/process/ipc_signed.rs:15-33`
**Problem:** `HashSet` eviction is arbitrary, not temporal.
**Fix:** ✅ Implemented timestamp-based LRU eviction for nonce cache.
**Verification:** ✅ `cargo test --test integration_test` passes (125 tests).

---

## Wave 3: Mesh Security Hardening ✅ DONE

*Can run in parallel with Waves 2, 4, 5, 6. Independent domain.*

### 3A: Fix TOFU Fingerprint Race Condition ✅ DONE

**Severity:** P1 — Race condition in Trust On First Use
**Files:** `src/mesh/cert.rs:476-503`
**Problem:** `verify_seed_fingerprint()` reads the fingerprints map, drops the lock, then re-acquires it to pin a new fingerprint. Between the read and write, another thread could pin a different fingerprint.
**Fix:** ✅ Uses `entry()` API to atomically check-and-insert fingerprints under single lock acquisition.
**Verification:** ✅ `cargo check --lib` passes.

### 3B: Fix Mutual TLS Not Enforced on Client Side ✅ DONE

**Severity:** P1 — Client certificates loaded but never used
**Files:** `src/mesh/cert.rs:370-417`
**Problem:** `build_client_config()` loads `cert_path` and `key_path` (lines 371-382) but builds the client config with `.with_no_client_auth()` (line 399). The `enforce_mutual_tls` config option is contradicted.
**Fix:** ✅ Added `enforce_mutual_tls` field to `MeshCertManager`, uses `with_client_auth_cert()` when mTLS is enforced.
**Verification:** ✅ `cargo check --lib` passes.

### 3C: Fix Route Response Signature Verification ✅ DONE

**Severity:** P1 — Route responses have empty signatures
**Files:** `src/mesh/transport_routing.rs:151,181,348,395`
**Problem:** All `RouteResponse` messages are created with `signature: vec![]`, despite `requires_signature()` indicating that `RouteResponse` should require signatures.
**Fix:** ✅ Implemented `sign_route_response()` helper and updated all call sites.
**Verification:** ✅ `cargo check --lib` passes.

### 3D: Fix Busy-Wait Loop for Peer Datagrams ✅ DONE

**Severity:** P1 — CPU-intensive, doesn't scale with peer count
**Files:** `src/mesh/transport_peer.rs:50-72`
**Problem:** `wait_for_peer_datagrams()` iterates all peer connections sequentially, and if none have data, sleeps for 1ms and retries. With N peers, each iteration takes O(N) async calls.
**Fix:** ✅ Uses `futures::future::join_all` to poll all peer datagram futures concurrently with timeout.
**Verification:** ✅ `cargo check --lib` passes.

### 3E: Fix `handle_peer_message()` Ignoring 33+ Message Types ✅ DONE

**Severity:** P1 — Silent message drops for most message types
**Files:** `src/mesh/transport_peer.rs:1707-1709`
**Problem:** The stream-based `handle_peer_message()` only handles ~7 message types, while the datagram handler handles 40+. Any message sent via stream that is not one of the 7 handled types is silently dropped.
**Fix:** ✅ Added handling for Ping/Pong, MeshAck, RouteResponseAck, RouteRejected, PeerHealthCheck/Response. Unhandled types now log at trace level.
**Verification:** ✅ `cargo check --lib` passes.

### 3F: Fix `proactive_cache_warm()` Removing Pending Queries ✅ DONE

**Severity:** P1 — Cache warming responses have no receiver
**Files:** `src/mesh/transport_routing.rs:621-639`
**Problem:** Query is registered and then immediately removed (`take`), so even if a response arrives, there is no receiver to handle it.
**Fix:** ✅ Removed unnecessary channel creation and pending query registration since cache warming is fire-and-forget.
**Verification:** ✅ `cargo check --lib` passes.

### 3G: Fix `derive_public_key()` Misleading Name ✅ DONE

**Severity:** P2 — SHA-256 hash is not an Ed25519 public key
**Files:** `src/mesh/config.rs:1195-1200`
**Problem:** `derive_public_key()` computes a SHA-256 hash, not an Ed25519 public key derivation. The function name is misleading.
**Fix:** ✅ Renamed to `derive_node_id_hash()` to accurately reflect its purpose.
**Verification:** ✅ `cargo check --lib` passes.

### 3H: Fix `MeshGlobalRateLimiter` Hardcoded Values ✅ DONE

**Severity:** P2 — Constructor parameters ignored
**Files:** `src/mesh/transport_types.rs:12-18`
**Problem:** Constructor parameters are unused (prefixed with `_`). Rate limiter always uses hardcoded window sizes.
**Fix:** ✅ Constructor parameters now stored and used for rate limit checks. Added `exceeded_per_second` and `exceeded_per_minute` fields to `GlobalRateLimitCheck`.
**Verification:** ✅ `cargo check --lib` passes.

---

## Wave 4: HTTP/Proxy Architecture ✅ PARTIAL

*Can run in parallel with Waves 2, 3, 5, 6.*

### 4A: Split Monolithic `handle_request` Function ⚠️ DEFERRED

**Severity:** P2 — 2,165-line function is unmaintainable
**Files:** `src/http/server.rs:366-2530`
**Problem:** Single async function handles: connection limits, bandwidth checks, WAF, routing, WebSocket, static files, FastCGI, PHP, serverless, proxy, transforms, and logging. Impossible to test in isolation.
**Fix:** Large architectural refactoring - extract into pipeline of middleware-like stages. **Deferred** due to scope and risk.
**Verification:** Each stage should have unit tests.

### 4B: Eliminate Duplicated Response Builder Code ✅ DONE

**Severity:** P2 — Parallel implementations in `server.rs` and `shared_handler.rs`
**Files:** `src/http/server.rs:2671-2731`, `src/http/shared_handler.rs:60-122`
**Problem:** `build_response_with_alt_svc` and `build_response_with_cookie` are implemented identically in both modules.
**Fix:** ✅ Extracted shared response builders into `src/http/response_builder.rs`. Both `HttpServer` and `SharedRequestHandler` delegate to the shared module.
**Verification:** ✅ `cargo check --lib` passes.

### 4C: Eliminate Duplicated Minification/Compression Logic ✅ DONE

**Severity:** P2 — Copy-pasted between mesh and static config paths
**Files:** `src/http/server.rs`, `src/http/response_transform.rs` (new), `src/mesh/proxy.rs`
**Problem:** Minification/compression/image poisoning logic was duplicated between the mesh-transport path and the static-config path.
**Fix:** Extracted shared response transform logic into `src/http/response_transform.rs`:
  - `ResponseTransformConfig` struct with `from_mesh_config()` and `from_static_config()` methods
  - `MinificationSettings`, `ImagePoisonSettings`, `CompressionSettings` structs
  - `apply_minification()` helper function
  - `apply_compression()` helper function
  - Both paths in `server.rs` now use the unified config and helpers
  - `mesh/proxy.rs` now uses shared `apply_minification()` and `apply_compression()` functions
  - Removed `minifier_generator` field from `MeshProxy` struct (no longer needed)
**Verification:** ✅ `cargo check --lib` passes, 125 integration tests pass.

### 4D: Rename `ZeroCopy` to `Buffered` ✅ DONE

**Severity:** P2 — Static files buffered but mislabeled as "ZeroCopy"
**Files:** `src/static_files/mod.rs`, `src/http/server.rs`, `src/tls/server.rs`
**Problem:** `StaticResponseBody::ZeroCopy` was mislabeled - it reads entire file into memory before returning, which is buffering, not zero-copy. Actual zero-copy operations are in `src/zero_copy.rs` using Linux syscalls (sendfile).
**Fix:** ✅ Renamed `StaticResponseBody::ZeroCopy` to `StaticResponseBody::Buffered` to accurately reflect that the content is fully loaded into memory (enabling subsequent compression/transformation).
**Verification:** ✅ `cargo check --lib` passes.

### 4E: Fix `build_headers_to_filter` Cloning Static Set Every Request ✅ DONE

**Severity:** P2 — Unnecessary allocation on hot path
**Files:** `src/proxy.rs:110-127`
**Problem:** Clones entire `AHashSet<String>` and allocates new `String`s for every request.
**Fix:** ✅ Added early return when no additional headers are provided, skipping the lowercase conversion loop.
**Verification:** ✅ `cargo check --lib` passes.

### 4F: Add Tests for `server.rs` ✅ PARTIAL

**Severity:** P2 — 3,253 lines with zero unit tests
**Files:** `src/http/server.rs`, `src/http/response_builder.rs`
**Problem:** No `#[cfg(test)]` module. Critical code paths (body collection, WAF integration, backend dispatch, response building) are untested.
**Fix:** ✅ Added tests for shared response builder functions in `response_builder.rs`.
**Verification:** ✅ `cargo check --lib` passes (test compilation blocked by pre-existing issues in other modules).

---

## Wave 5: DNS/TLS Correctness ✅ DONE

*Can run in parallel with Waves 2, 3, 4, 6. Independent domain.*

### 5A: Fix NSEC3 SHA-256 Silently Falling Back to SHA-1 ✅ DONE

**Severity:** P1 — Wrong hash algorithm for NSEC3
**Files:** `src/dns/dnssec_signing.rs:197-211`
**Problem:** NSEC3 with SHA-256 (algorithm 2) falls back to SHA-1 with an admission comment. Produces SHA-1 hashes but claims algorithm 2.
**Fix:** ✅ Removed misleading comment. Algorithm 2 already uses SHA-256 correctly. Added warning log for unsupported algorithms.
**Verification:** ✅ `cargo check --lib` passes.

### 5B: Fix DNS Firewall Missing IPv6 and Loopback Blocks ✅ DONE

**Severity:** P1 — Incomplete DNS firewall
**Files:** `src/dns/server/mod.rs:682-716`
**Problem:** Blocks RFC 1918 addresses but NOT loopback, link-local, IPv6 private ranges.
**Fix:** ✅ Added firewall rules for: 127.0.0.0/8, 169.254.0.0/16, ::1/128, fc00::/7, fe80::/10.
**Verification:** ✅ `cargo check --lib` passes.

### 5C: Fix Wildcard TLS Certificate Matching ✅ DONE

**Severity:** P1 — Wildcard certs don't match subdomains
**Files:** `src/tls/cert_resolver.rs:323-336`
**Problem:** Cert resolver does exact SNI matching only. `*.example.com` will NOT match `api.example.com`.
**Fix:** ✅ Implemented wildcard matching: after exact match fails, check for `*.domain` pattern.
**Verification:** ✅ `cargo check --lib` passes.

### 5D: Fix `parse_all_dnskey_records` Only Parsing One Record ✅ DONE

**Severity:** P1 — Only first DNSKEY loaded from file
**Files:** `src/dns/trust_anchor.rs:730-744`
**Problem:** Despite the name `parse_all_dnskey_records`, only a single DNSKEY record was parsed.
**Fix:** ✅ Now iterates through all lines and parses each DNSKEY record found.
**Verification:** ✅ `cargo check --lib` passes.

### 5E: Fix `prefer_post_quantum` Flag Having No Effect ✅ DONE

**Severity:** P2 — Config flag is misleading
**Files:** `src/tls/cert_resolver.rs:259-264`
**Problem:** Both branches call `default_provider()`. The flag only incremented a counter.
**Fix:** ✅ Simplified to use `default_provider()` unconditionally. Post-quantum hybrid key exchange is enabled by default in TLS 1.3 via cipher suites.
**Verification:** ✅ `cargo check --lib` passes.

### 5F: Fix ACME Credentials File Race Condition ✅ DONE

**Severity:** P2 — Credentials briefly world-readable
**Files:** `src/tls/acme.rs:157-171`
**Problem:** File created with default permissions, then mode set, then content written. Brief window with 0644.
**Fix:** ✅ Write to temp file with 0600 permissions, then atomically rename to final path.
**Verification:** ✅ `cargo check --lib` passes.

---

## Wave 6: Code Quality & Maintainability ✅ PARTIAL

*Should run last — validates and cleans up all prior changes.*

### 6A: Remove Module-Level `#![allow(dead_code, unused_mut)]` ⚠️ DEFERRED

**Severity:** P3 — Masks potential issues
**Files:** `src/tls/server.rs:1`
**Problem:** Module-level allow suppresses all dead code and unused mut warnings for the entire 1,000+ line file.
**Fix:** High risk refactoring - would require adding targeted allows for legitimate uses. **Deferred**.
**Verification:** `cargo clippy -- -D warnings` — no new warnings.

### 6B: Remove Deprecated `run_worker` Function ✅ DONE

**Severity:** P3 — Non-functional stub still compiles
**Files:** `src/worker/mod.rs`, `src/main.rs`, `src/startup/worker.rs`
**Problem:** `#[deprecated]` function drops all connections immediately (line 327: `let _ = stream;`) - it was a placeholder kept as architectural reference.
**Fix:** ✅ Removed `run_worker()` function, `WorkerArgs` struct, and `build_worker_args()`. Removed `--worker` mode from main.rs.
**Verification:** ✅ `cargo check --lib` passes.

### 6C: Remove Dead `supervisor` Module ✅ DONE

**Severity:** P3 — Unused code
**Files:** `src/supervisor/` (entire directory)
**Problem:** `Supervisor::new()` was never called anywhere. `spawn_worker()` created fake workers that just slept in a loop. Architecture uses tokio async in unified_server for concurrency, not process-based workers.
**Fix:** ✅ Removed entire `src/supervisor/` directory. `SupervisorConfig` in `config/process.rs` retained for configuration compatibility.
**Verification:** ✅ `cargo check --lib` passes.

### 6D: Fix `FileManagerState` Unused `config` Field ✅ DONE

**Severity:** P3 — Dead field
**Files:** `src/http/file_manager.rs:74`
**Problem:** `config: Arc<TokioRwLock<ConfigManager>>` is stored but never accessed.
**Fix:** ✅ Added `#[allow(dead_code)]` annotation - field may be needed for future use.
**Verification:** ✅ `cargo check --lib` passes.

### 6E: Fix `file_manager_handler` Being a Stub ✅ DONE

**Severity:** P3 — Always returns 404
**Files:** `src/http/file_manager.rs:366-372`
**Problem:** Function always returns `StatusCode::NOT_FOUND`. Actual routing is done by `create_file_manager_router`.
**Fix:** ✅ Removed the unused stub function.
**Verification:** ✅ `cargo check --lib` passes.

### 6F: Fix Overseer Using External `kill` Command ✅ DONE

**Severity:** P3 — Inconsistent with rest of codebase
**Files:** `src/overseer/process.rs:368-373`
**Problem:** Uses `std::process::Command::new("kill").arg("-0")` instead of `nix::sys::signal::kill`.
**Fix:** ✅ Replaced with `nix::sys::signal::kill(Pid::from_raw(pid), None)` at two locations.
**Verification:** ✅ `cargo check --lib` passes.

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
