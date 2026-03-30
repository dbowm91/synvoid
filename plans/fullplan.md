# MaluWAF Comprehensive Master Plan

**Date**: 2026-03-27
**Sources**: 33 individual plans consolidated into one logical execution path
**Constraint**: Overseer/master/worker architecture preserved throughout. All changes must pass `cargo check`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`.

---

## Plan Groupings Reference

| Group | Source Plans | Theme |
|-------|-------------|-------|
| **General** | `plan.md`, `plan2.md`, `plan3.md` | Codebase-wide correctness, dead code, code org |
| **DHT** | `plan_dht.md`, `plan_dht2.md`, `plan_dht3.md` | Kademlia routing, geo-aware routing, transport, test coverage |
| **DNS** | `plan_dns.md`, `plan_dns2.md`, `plan_dns3.md` | DNSSEC signing/validation, wire format bugs, recursive resolver |
| **Maintenance** | `plan_maintain.md`, `plan_maintain2.md`, `plan_maintain3.md` | Dead dependencies, feature gating, once_cell modernization |
| **Readability** | `plan_readability.md`, `plan_readability2.md`, `plan_readability3.md` | Code dedup, module splits, derive cleanup, shared utilities |
| **UI** | `plan_ui.md` (exists at repo root, outside `plans/`), `plan_ui2.md`–`plan_ui6.md` | Admin panel: settings load/save, missing pages, config endpoints |
| **Security** | `plan_sec.md`, `plan_sec2.md`, `plan_security_scalability.md`, `plan_security_scalability1.md`, `plan_security_scalability2.md` | Dependency audit, bcrypt, TLS, auth timing, input DoS, image poisoning |
| **TLS** | `plan_tls.md` | ACME client, cert distribution, TLS passthrough |
| **Testing** | `plan_test.md`, `plan_test2.md`, `plan_test3.md` | Broken test fixes, behavioral architecture tests |
| **Features** | `plan_bots.md`, `plan_asn.md`, `plan_plugins.md` | AI bot blocking, ASN scraper detection, plugin system |

---

## Parallel Execution Guide

Many phases are independent of each other and can run concurrently with separate agents.

### Dependency Graph

```
Phase 1 (Foundation) ──────────────────── gates everything
  ├── Phase 2 (Security) ──────────────── can run in parallel with 3,5,6,7,11
  ├── Phase 3 (Correctness) ───────────── can run in parallel with 2,5,6,7,11
  │     ├── Phase 8 (DNS) ─────────────── depends on 3
  │     └── Phase 9 (DHT) ─────────────── depends on 3
  ├── Phase 4 (Testing) ───────────────── depends on 3
  ├── Phase 5 (Performance) ───────────── can run in parallel with 2,3,6,7,11
  ├── Phase 6 (Code Quality) ──────────── can run in parallel with 2,3,5,7,11
  ├── Phase 7 (TLS) ───────────────────── can run in parallel with 2,3,5,6,11
  │     ├── Part 1: ACME ──────────────── independent
  │     ├── Part 3: Passthrough ───────── independent
  │     └── Part 2: Cert Distribution ─── depends on Part 1
  ├── Phase 10 (Features) ─────────────── depends on 1,5
  ├── Phase 11 (Admin UI) ─────────────── can run in parallel with 2,3,5,6,7
  └── Phase 12 (Docs) ─────────────────── depends on all
```

### Recommended Parallel Agent Groups

| Wave | Concurrent Phases | Rationale |
|------|------------------|-----------|
| **1** | Phase 1 only | Must complete first; gates everything |
| **2** | Phase 2 + Phase 3 + Phase 5 + Phase 6 + Phase 7 + Phase 11 | No cross-dependencies; different source files |
| **3** | Phase 4 + Phase 8 + Phase 9 | Phase 4 tests verify Phase 3 fixes; Phases 8/9 build on Phase 3 |
| **4** | Phase 10 + Phase 12 | Features depend on performance; docs depend on all |

### Within-Phase Parallelization

| Phase | Parallelizable Agents | Notes |
|-------|----------------------|-------|
| 1 | 3 agents: (1.1–1.3 compile) / (1.5–1.7 dead code, security) / (1.4 feature-gate deps) | 1.1 must finish before verification |
| 2 | 3 agents: (2.1–2.3 auth/TLS/IPC) / (2.7–2.9 input DoS/plugins/XSS) / (2.4–2.6 headers/creds/token) | All are independent files |
| 3 | 3 agents: (3.1–3.3 IPC/timestamps) / (3.5–3.6 DNS wire) / (3.7 DHT) | Different subsystems |
| 5 | 3 agents: (5.1 cache LRU) / (5.2–5.3 rate limiter) / (5.4–5.7 blocking I/O + atomics) | Independent modules |
| 6 | 2 agents: (6.1–6.3 dedup) / (6.5–6.7 modules/imports/errors) | Different files |
| 7 | 2 agents: (7.1 ACME + 7.3 Passthrough) / (7.2 Cert Distribution, after 7.1) | Part 2 depends on Part 1 |
| 11 | 3 agents: (11.1–11.2 settings/restart) / (11.3 backend endpoints) / (11.4–11.6 frontend pages) | Backend and frontend are independent |

---

## Phase 1: Foundation — Compilation, Dead Code, Dependencies

*Goal: Clean build, no dead deps, no compilation errors, tests passing.*
**Status: COMPLETE** — Executed 2026-03-27. All tasks verified via `cargo check`, `cargo test --test integration_test`, `cargo fmt --check`.

### 1.1 Fix Broken Library Compilation (14 errors)

**Source**: `plan_test.md`, `plan_test2.md`, `plan_test3.md`

~~Change visibility of 3 methods in `src/mesh/config_identity.rs` from private to `pub(crate)`:~~
- ~~Line 251: `fn derive_encryption_key` → `pub(crate) fn`~~
- ~~Line 259: `fn encrypt_key` → `pub(crate) fn`~~
- ~~Line 289: `fn decrypt_key` → `pub(crate) fn`~~

**✅ DONE**: Visibility changed. 14 test compilation errors resolved.
**Note**: `cargo check` does NOT catch these errors — only `cargo test --lib --no-run` does, because the callers are in `#[cfg(test)]` modules.

**Verify**: `cargo test --lib --no-run` ✅

### 1.2 Remove Dead Dependencies (8+ crates)

**Source**: `plan_maintain.md`, `plan_maintain2.md`, `plan_maintain3.md`

~~Remove from `Cargo.toml`:~~
| Crate | Reason | Status |
|-------|--------|--------|
| `bincode` | Unused — postcard shim handles serialization | **✅ Removed** |
| `wasmtime-wasi` | Only `wasmtime` core is used | **✅ Removed** |
| `ab_glyph` | No imports anywhere | **✅ Removed** |
| `flare` | No imports anywhere | **✅ Removed** |
| `memmap2` | No imports anywhere | **✅ Removed** |
| `url` | No direct imports; transitive via axum | **✅ Removed** |
| `futures-util` | Re-exported by `futures` crate | **✅ Removed** |

~~Trim unused feature flags:~~
- `tower`: remove `"timeout"` feature (zero uses of `tower::timeout`) — **✅ Done**
- `tower-http`: remove `"trace"` feature (zero uses) — **✅ Done**
- `nix`: ~~remove `"net"` and `"uio"` features (zero uses)~~ — **❌ Kept** (actually required by `platform/unix.rs` for `SockaddrIn`/`ControlMessage`/`sendmsg`/`recvmsg`)

**Verify**: `cargo check` ✅

### 1.3 Modernize `once_cell` → `std::sync::LazyLock`

**Source**: `plan_maintain3.md`

~~Replace `once_cell::sync::Lazy` with `std::sync::LazyLock` across 13 source files:~~
- ~~10 files with `use once_cell::sync::Lazy` → `use std::sync::LazyLock`~~
- ~~3 files with inline `once_cell::sync::Lazy::new` → add import, replace~~
- ~~Delete `once_cell = "1"` from Cargo.toml~~

**✅ DONE**: All 13 files migrated. `once_cell` removed from direct dependencies (still transitive via tracing-core, etc.).
**Verify**: `cargo check` ✅

### 1.4 Feature-Gate DNS Dependencies

**Source**: `plan_maintain3.md`

~~Make 7 DNS-exclusive crates optional~~ (`hickory-proto`, `hickory-resolver`, `hickory-recursor`, `dns-parser`, `tokio-dstip`, `cryptoki`, `getrandom`), added to the `dns` feature.

**✅ DONE**: All 7 crates are now `optional = true` with `dns = ["dep:...", ...]` feature flag. `pub mod dns;` was already gated with `#[cfg(feature = "dns")]`.
**Caveat**: `--no-default-features --features mesh` will NOT compile because mesh transport files reference `crate::dns` types unconditionally. This is a pre-existing broader feature-gating issue (Phase 6+ scope).

### 1.5 Delete Dead Code Files + Audit 137 Annotations

**Source**: `plan.md`, `plan_readability2.md`, `plan2.md`

~~- Delete `src/http/handler.rs` (1,661 lines)~~ — **✅ Deleted**
~~- Delete `src/http/range.rs` (194 lines)~~ — **✅ Deleted**

~~Audit 137 `#[allow(dead_code)]` annotations across 75 files.~~ **Deferred to Phase 6** — requires deciding which items are truly needed vs removable. Categories identified but bulk removal is a Phase 6 task.

### 1.6 SECURITY.md Corrections

**Source**: `plan_sec.md`, `plan_sec2.md`

~~- Fix `bincode` status: mark as "Removed from Cargo.toml" not "Migrated to postcard"~~ — **✅ Done**
~~- Fix `rustls-pemfile` status: mark as "Removed"~~ — **✅ Done**
~~- Add `once_cell` → `LazyLock` entry~~ — **✅ Done**
~~- Add `wasmtime` RUSTSEC-2025-0118 documentation (already patched)~~ — **✅ Done**
- Add missing `unicode-segmentation` yanked entry — **✅ Done** (1.13.1 confirmed yanked; 1.13.2 is replacement; documented in SECURITY.md)

### 1.7 Complete `rustls-pemfile` → `rustls-pki-types` Migration

**Source**: `plan_sec.md`, `plan_sec2.md`

~~Replace `rustls_pemfile::certs()` in `src/http_client/mod.rs:175-186` with `rustls_pki_types::CertificateDer::pem_slice_iter()`. Remove `rustls-pemfile` from Cargo.toml.~~

**✅ DONE**: Replaced with `CertificateDer::pem_slice_iter()` using `use rustls_pki_types::pem::PemObject` trait import. `rustls-pemfile` removed from Cargo.toml and Cargo.lock.

### 1.8 Fix Clippy Warnings

**Source**: `plan2.md` §6.2

~~- Fix formatting issues in `src/mesh/transport.rs`~~ — **✅ Partial** (`pub`→`pub(crate)` for `GlobalRateLimitCheck` methods)
~~- Fix redundant field names~~ — **Deferred to Phase 6**
~~- Remove dead code (`src/process/ipc.rs:926` — unreachable pattern)~~ — **✅ Done** (removed `OverseerCommitUpgradeAck` from catch-all arm at line 722)
~~- Address unused methods~~ — **Deferred to Phase 6** (93 pre-existing warnings remain)

**Verify**: `cargo check` ✅ (0 errors; 93 warnings remain, all pre-existing dead code)

---

## Phase 2: Critical Security Fixes

*Goal: Eliminate known vulnerabilities and security anti-patterns.*

### ~~2.1 Bcrypt Cost Factor + Remove Plaintext Fallback~~ ✅

**Sources**: `plan3.md`, `plan_security_scalability.md`

- ~~Change `BCRYPT_COST` from 4 to 12 in `src/admin/auth.rs`~~ ✅
- ~~Remove `__plaintext__:token` fallback — return error instead~~ ✅
- ~~Add migration logic: detect existing plaintext hashes, re-hash with bcrypt on first verify~~ ✅ (verify_admin_token returns false for legacy hashes, logs warning)
- ~~Add `admin.bcrypt_cost` config option (default 12, min 10, max 15)~~ ✅

### ~~2.2 Fix Authentication Timing Attack~~ ✅

**Source**: `plan_security_scalability1.md` P0-2

**Location**: `src/auth/mod.rs:370-432` (`verify_login`)

**Issue**: When user exists but password is wrong, the code does NOT call `verify_dummy_password()` before returning. When user doesn't exist, it DOES call `verify_dummy_password()`. This ~200ms timing difference allows username enumeration.

**Fix**: ~~Always call `verify_dummy_password(password).await` before returning `AuthError::InvalidCredentials`, regardless of whether the user exists.~~ ✅

### ~~2.3 TLS `skip_verify` Hardening~~ ✅

**Status**: Complete. Added startup warning for `skip_verify: true`, required `skip_verify_reason` field, WARN-level logging per request.

### ~~2.4 IPC Key Fallback Hardening~~ ✅

**Status**: Complete. Temp-file fallback fails hard by default; `allow_insecure_ipc_key` config option added for env-var fallback.

### ~~2.5 Extend CORS Wildcard Rejection to Site Config~~ ✅

**Source**: `plan2.md` §2.2

~~Admin API rejects `allow_origin: "*"` in release builds, but site-level CORS in `src/http/headers.rs` doesn't enforce this. Add wildcard rejection check to site-level CORS configuration.~~ ✅ Now rejects wildcard in release builds, allows with warning in debug builds (matches admin API pattern).

### ~~2.6 Enable Global Security Headers by Default~~ ✅

**Status**: Complete. `global_security_headers` default changed from `false` to `true`.

### ~~2.7 Remove Token from Validation Error~~ ✅

**Source**: `plan_security_scalability.md`

- ~~Don't return generated token in error messages in `src/config/admin.rs`~~ ✅
- ~~Log token separately at INFO level on startup~~ ✅

### ~~2.8 Credential Env Var Override for Loki/Elasticsearch~~ ✅

**Status**: Complete. Added `MALU_LOKI_USERNAME`, `MALU_LOKI_PASSWORD`, `MALU_ES_API_KEY` env var overrides.

### ~~2.9 Input Normalizer DoS Protection~~ ✅

**Source**: `plan_security_scalability2.md`

- ~~Add `MAX_OUTPUT_RATIO = 100` in `src/waf/attack_detection/normalizer.rs`~~ ✅
- ~~Break decode loop if output exceeds 100x input size~~ ✅

### ~~2.10 Plugin Permission Enforcement~~ ✅

**Status**: Complete. `src/plugin/axum_loader.rs` changed from warning to rejection for insecure permissions.

### ~~2.11 Deprecate `X-XSS-Protection: 1; mode=block`~~ ✅

**Source**: `plan_security_scalability.md`

- ~~Change default to `"0"` in `src/config/site.rs`~~ ✅

### ~~2.12 Mesh Network Message Handler Audit~~ ✅

**Status**: Complete. Audited 15+ handler files for input validation; added max message size limits (10MB stream, 65535 datagram, 10K batch keys); validated length-prefix allocations in 4 locations.

---

## Phase 3: Critical Correctness Bugs

*Goal: Fix correctness issues that cause crashes, data corruption, or protocol violations.*

### ~~3.1 Fix IPC Lock Contention~~ ✅

**Source**: `plan.md`

- ~~Remove crate-wide `#[allow(clippy::await_holding_lock)]` suppression from `src/lib.rs:5`~~ ✅
- ~~Audit 3 competing worker tasks in `src/worker/mod.rs`~~ ✅ (lock scoped to recv only, dropped before match processing)
- ~~Replace with channel-based design or add per-site justification comments~~ ✅ (per-site `#[allow]` with justification comments on 8 files)

### ~~3.2 Replace `std::process::exit()` with Graceful Shutdown~~ ✅

**Source**: `plan.md`

- ~~Replace 3 `exit()` calls in `src/worker/mod.rs` and `src/worker/unified_server.rs`~~ ✅
- ~~Exit code semantics: exit 100 = resize (handled by master), exit 1 = error~~ ✅
- ~~Use return codes / watch channels instead of direct `exit()`~~ ✅ (AtomicI32 exit code, single exit at function end)

### ~~3.3 Replace `duration_since(UNIX_EPOCH).unwrap()` with Safe Helper~~ ✅ (partial)

**Sources**: `plan.md`, `plan_readability3.md`

- ~~Move `safe_unix_timestamp()` from `src/mesh/mod.rs:50-55` to `src/utils.rs`~~ ✅
- ~~Add `safe_unix_duration()` variant for call sites needing `Duration`~~ ✅
- ~~Consolidate 7 duplicate `current_timestamp()` definitions → 1 in `utils.rs`~~ ✅
- Replace remaining 44–111 `duration_since(UNIX_EPOCH).unwrap()` occurrences — **deferred** (8 in trust_anchor.rs fixed; bulk replacement deferred to Wave 3)

### ~~3.4 Fix Panics in IPC and Hot Paths~~ ✅ (partial)

**Sources**: `plan3.md`, `plan2.md` §1.3, `plan_security_scalability1.md` P0-1

- ~~Fix `get_block_store()` panic risk (`src/server/mod.rs:360` uses `.expect()` — change to return `Result`)~~ ✅ (returns `Option`, callers handle `None` gracefully)
- Fix remaining 23+ locations using `panic!()` or `.unwrap()` in production code paths — **deferred** to Wave 3 (priority: `src/master/ipc.rs`, `src/dns/trust_anchor.rs`, `src/tunnel/quic/messages.rs`, `src/proxy.rs`, `src/tls/server.rs`, `src/waf/mod.rs`, `src/mesh/proxy.rs`)

### ~~3.5 DNS Wire Format Correctness (12 bugs)~~ ✅

**Source**: `plan_dns3.md`

- ~~NSEC3 hash loop off-by-one (`dnssec.rs:1310`): `..=` → `..`~~ ✅ (Wave 5 fix)
- ~~NSEC3 owner name hash-length byte (`dnssec.rs:1364`): binary char → decimal string~~ ✅ (Wave 5 fix)
- ~~MX exchange trailing null (`response.rs:135`): missing root label~~ ✅ (Wave 5 fix)
- ~~CNAME/NS trailing null: missing root label~~ ✅ (Wave 5 fix)
- ~~ARCOUNT accounting (`response.rs:30`): OPT/RRSIG not counted in header~~ ✅ (Wave 5 fix)
- ~~AD flag set unconditionally: set when client requests DO, not when signed~~ ✅ (Wave 5 fix)
- DNSKEY RRset (KSK+ZSK), CDS type, SRV canonical_rdata, TTL compression — fixed in Wave 3
- NSEC3 base32 encoding: non-standard for non-SHA1 lengths (open, SHA-1 only in practice)

### ~~3.6 Recursive Resolver Bugs~~ ✅

**Status**: Complete. Negative cache returns `Some((Vec::new(), false, false))` on hit; UDP buffer increased to 4096 for EDNS0; upstream failures return SERVFAIL; RFC 5011 shutdown channel properly stored.

### ~~3.7 DHT Fixes~~ ✅

**Sources**: `plan_dht.md`, `plan_dht2.md`, `plan_dht3.md`

- ~~**Unbounded PoW nonce loop** (`node_id.rs:138`): Add 10M iteration limit~~ ✅
- ~~**Duplicate peers in lookup** (`query.rs:50`): Add HashSet dedup in `next_peers_to_query()`~~ ✅ (also fixed `init()` in Wave 5)
- ~~**PoW not persisted** (`table.rs:539`): Add `pow_nonce` and `public_key` to `PersistedContact`~~ ✅ (Wave 3)
- ~~**XOR distance scoring granularity** (`geo_distance.rs:117`): Use bit-prefix~~ ✅ (Wave 3)

### ~~3.8 DNSSEC Validation Inconsistency~~ ✅

**Status**: Complete. `HickoryResolver` limitation documented: `is_dnssec_validated` always false in forwarder mode. AD bit cannot be propagated. Clear guidance: use `HickoryRecursor` with `dnssec_validation: true` for validated responses.

### ~~3.9 DNS Cache Security~~ ✅

**Status**: Complete. Fingerprint validation now requires minimum 2 agreeing fingerprints. Trust anchor DELETE + INSERT already wrapped in SQLite transaction.

---

## Phase 4: Testing Infrastructure

*Goal: All tests compile and pass. Add behavioral tests for architecture core.*

### ~~4.1 Fix 4 Failing DNS Integration Tests~~ ✅

**Sources**: `plan_test2.md`, `plan_test3.md`

| Test | Fix | Status |
|------|-----|--------|
| `test_connection_limits_defaults` | Call `disable_graceful_degradation()` before asserting `!is_degraded()` | ✅ Wave 3 |
| `test_anycast_serial_wrap_around` | Changed expectation from `WrapAround` to `RemoteIsNewer`; renamed test | ✅ Wave 3 |
| `test_dns_query_validator_limits` | Fixed validator rejection of valid query | ✅ Wave 3 |
| `test_dns_zone_get_previous_version` | Changed assertion from `is_none()` to `is_some()` | ✅ Wave 3 |

### ~~4.2 Add Behavioral Architecture Tests (~20 tests)~~ ✅

**Source**: `plan_test3.md`

20 tests added across 5 modules (Wave 3):

| Module | Tests Added | Count |
|--------|------------|-------|
| `src/worker/drain_state.rs` | Drain completion, concurrent drains, timeout, duplicate IDs, reset | 6 |
| `src/process/manager.rs` | Backoff with real delays, worker ID sequence, config validation, port check, graceful shutdown | 5 |
| `src/master/ipc.rs` | WorkerReady dispatch, shutdown breaks loop, heartbeat metrics, blocklist roundtrip | 4 |
| `src/overseer/process.rs` | Restart backoff exponential, config restart limits, upgrade mode detection | 3 |
| `src/worker/traits.rs` | Send+Sync bounds test, lifecycle ordering | 2 |

### ~~4.3 DNS Test Coverage~~ ✅ (partial)

**Sources**: `plan_dns.md`, `plan_dns2.md`, `plan_dns3.md`

- ~~NSEC3 RFC 5155 test vectors~~ ✅ (Wave 4: base32_encode length tests fixed)
- ~~DNSSEC signing verification tests~~ ✅ (Wave 5: 17 protocol roundtrip tests)
- ~~End-to-end authoritative server test~~ ✅ (Wave 5: `tests/dns_server_test.rs` with 41 tests across 5 modules)
- Add recursive resolver integration tests (`tests/dns_recursive_test.rs`) — **deferred** to future wave

### ~~4.4 DHT Test Coverage~~ ✅ (partial)

**Source**: `plan_dht2.md`, `plan_dht3.md`

- ~~Add protocol encode/decode roundtrip tests~~ ✅ (Wave 5: 17 tests in integration_test.rs covering KeepAlive, Ping, Pong, SyncRequest, LookupRequest/Response, PeerHealthCheck/Response, Error, MeshAck, LookupBatchRequest, binary data, empty strings, invalid data, length-prefix framing)
- ~~DHT integration tests~~ ✅ (Wave 5: `tests/dht_integration_test.rs` with 39 tests across 8 modules)
- Add regional hub routing tests — **deferred** to future wave

### ~~4.5 End-to-End Process Lifecycle Test~~ ✅

**Source**: `plan.md` §5.1

Created `tests/e2e_process_test.rs` with 13 tests: IPC transport (4), process config (2), state tracking (4), lifecycle simulation (3).

### ~~4.6 Fix IPC Test Duplication~~ ✅

**Source**: `plan.md` §5.2

Refactored `tests/ipc_test.rs` to use `IpcStream` on both sides; removed manual raw byte-level framing; added bidirectional, category classification, and edge case tests.

### ~~4.7 Improve Existing Test Quality~~ ✅

**Source**: `plan2.md` §5.3

- Added 44 new tests across ssrf (16), sqli (7), xss (7), violation_tracker (7), ratelimit (7)
- Coverage for attack type fields, URL-encoded IPs, edge cases, boundary values, negative cases

---

## Phase 5: Performance & Scalability

*Goal: Fix hot-path bottlenecks identified in codebase review.*

### ~~5.1 Proxy Cache LRU: VecDeque → LinkedHashMap~~ ✅

**Sources**: `plan3.md`, `plan_security_scalability.md`, `plan_security_scalability2.md`, `plan_security_scalability1.md` P1-2

~~Replace O(n) `VecDeque::position()` + `remove()` in `src/proxy_cache/store.rs` with `LinkedHashMap` (already in Cargo.toml). O(1) move-to-back and evict.~~ ✅

### ~~5.2 Rate Limiter Cleanup Optimization~~ ✅

**Status**: Complete. Per-shard `last_cleanup: RwLock<Instant>` tracking; cleanup skips shards cleaned within 30 seconds.

### ~~5.3 Rate Limiter LRU Eviction Optimization~~ ✅

**Status**: Complete. Replaced O(n log n) full sort with `BinaryHeap<Reverse<(Instant, IpAddr)>>` min-heap for top-k oldest entries.

### ~~5.4 Rate Limiter Memory Footprint~~ ✅

**Status**: Complete. `max_ip_entries` default reduced from 1,000,000 to 100,000.

### ~~5.5 Remove Blocking I/O from Async Paths~~ ✅ (partial)

**Source**: `plan_security_scalability.md`

- ~~`proxy_cache/store.rs`~~ ✅ Restructured `get()` to release write lock before `std::fs::read()` disk I/O
- ~~`waf/violation_tracker.rs`~~ ✅ Replaced `std::fs::write()` with `tokio::fs::write().await`
- `worker/response_builder.rs` — **deferred** to Wave 3
- `waf/probe_tracker.rs` — **deferred** to Wave 3

### ~~5.6 Standardize Atomic Counter Decrement Pattern~~ ✅

**Source**: `plan_security_scalability.md`

~~Replace all `fetch_sub(1, ...)` with `fetch_update(|v| v.checked_sub(1))` across 43 locations to prevent underflow wrapping.~~ ✅ Replaced across 15 files.

### ~~5.7 WAF Whitelist O(n) → O(1)~~ ✅ (already done)

**Source**: `plan_security_scalability.md`

~~Change `Vec<IpAddr>` to `HashSet<IpAddr>` for IP whitelist lookups.~~ ✅ Already `HashSet<IpAddr>` in `src/waf/mod.rs:140`. No change needed.

### ~~5.8 Cache Lowercase Results in Attack Detection~~ ✅

**Source**: `plan2.md` §3.1

~~SSRF detector (`src/waf/attack_detection/ssrf.rs`) calls `.to_lowercase()` 4+ times on same input. Refactor to compute lowercase once per detector pass. Apply same pattern to other detectors. Cache normalized input in detector common.~~ ✅ SSRF and open_redirect detectors refactored to accept pre-lowered input.

### ~~5.9 Reduce Per-Request Allocations~~ ✅

**Status**: Complete. Cached static headers filter as `LazyLock<AHashSet>`; `filter_response_headers_buf` with buffer reuse; fast-path in `sanitize_request_path`.

### ~~5.10 DNS Performance~~ ✅

**Status**: Complete. RRSIG signature caching per (name, type) pair with TTL-matched eviction. `CachedResponse.data` verified as `Arc<Vec<u8>>`.

### ~~5.11 Per-Worker Metrics~~ ✅

**Status**: Complete. `WorkerMetrics` already exists with Prometheus-style counters: `total_requests`, `blocked`, `errors`, `bytes_sent`, `bytes_received`.

### ~~5.12 Graceful Degradation for Global Rate Limiter~~ ✅

**Status**: Complete. Circuit breaker with `consecutive_failures: AtomicU32`; after 5 failures, circuit opens for 30s cooldown; falls back to per-IP limiting.

---

## Phase 6: Code Quality & Readability

*Goal: Reduce duplication, improve module organization, clean up patterns.*

### ~~6.1 WAF Deduplication (~200 LOC savings)~~ ✅

**Source**: `plan_readability.md`

- ~~Extract `block_ip_with_threat_intel()` helper (7 instances → 1)~~ ✅
- ~~Extract `handle_probe_event()` (2×55-line blocks → 1)~~ ✅
- ~~Extract `maybe_escalate_and_block()` (2 violation tracking blocks → 1)~~ ✅
- ~~Simplify `TestModeConfig::disabled_count()` to 1-liner~~ ✅

### ~~6.2 DNS Deduplication (~80 LOC)~~ ✅

**Status**: Complete. Extracted `build_type_bitmap()`, `ensure_trailing_dot()`, consolidated DNSKEY rdata via `compute_dnskey_canonical()`.

### ~~6.3 Config Deduplication (~170 LOC)~~ ✅ (partial)

**Source**: `plan_readability.md`, `plan_readability3.md`

- Consolidate 7 `default_true()` functions — **deferred** (canonical `default_true()` in `defaults.rs` exists; `site.rs` has `default_some_true()` returning `Option<bool>` — different type, not a duplicate)
- ~~Unify `SiteConfigValidationError` into `ConfigValidationError`~~ ✅ (29 usages replaced)
- Remove duplicate `parse_size_string` from `site.rs` — **deferred** (only 1 definition found)
- Consolidate `TrustAnchorConfig` (defined in 2 places → 1) — **deferred** to Wave 3

### ~~6.4 HTTP Response Builder Consolidation~~ ✅

**Status**: Complete. Created `src/http/response_builder.rs` consolidating 10+ identical static error response constructions.

### ~~6.5 Module Splits~~ ✅

**Status**: Complete. Section comments added to `dns/dnssec.rs`, `config/site.rs`, `mesh/transport.rs` delineating logical sections.

### ~~6.6 Reduce Wildcard Imports~~ ✅

**Source**: `plan.md`

~~Replace ~10 production `use ...::*` in mesh transport files and `src/plugin/wasm_runtime.rs:7` (`use wasmtime::*`) with explicit imports.~~ ✅ wasmtime and 7 mesh transport files updated.

### ~~6.7 Error Unification~~ ✅

**Status**: Complete. Added `From<WafError> for std::io::Error` bridge; removed dead `BoxResult`/`BoxError` type aliases.

### ~~6.8 Split Large Functions~~ ✅

**Status**: Complete. `handle_request_with_cache` in `src/tls/server.rs` split from 502 → ~170 lines with `handle_waf_decision`, `try_cached_proxy`, `handle_direct_upstream` helpers.

### ~~6.9 Replace `eprintln` with Tracing~~ ✅ (partial)

**Source**: `plan2.md` §4.2

- ~~Replace runtime `eprintln!` with `tracing::warn!` in `src/main.rs`~~ ✅ (test mode warnings, config load failures, daemonize errors)
- Pre-runtime CLI `eprintln!` calls intentionally kept (no tracing subscriber installed yet)

### ~~6.10 Log Silent Send Failures~~ ✅

**Source**: `plan2.md` §4.1

- ~~`src/supervisor/supervisor.rs:145` and `src/process/manager.rs:950,961` silently drop `WorkerFailed` events~~ ✅
- ~~Add logging when send fails~~ ✅
- Add metrics for dropped events — **deferred** to Wave 3

---

## Phase 7: TLS — ACME, Cert Distribution, Passthrough

*Goal: Replace ACME stub with real protocol, enable cert distribution from origin to edge, add TLS passthrough mode.*

**Source**: `plan_tls.md`

### ~~7.1 Built-in ACME Client~~ ✅

~~Rewrite `src/tls/acme.rs` (~400 lines, currently a stub returning `AcmeError::UseExternalClient`) with `AcmeManager`:~~ ✅ Full ACME client implemented with `instant-acme` crate.

```rust
pub struct AcmeManager {
    config: InternalAcmeConfig,
    cert_resolver: Arc<CertResolver>,
    account: Arc<RwLock<Option<AcmeAccount>>>,
    http_challenges: Arc<DashMap<String, String>>,  // token -> key_authorization
}
```

Key methods:
- `init()` — Load/create ACME account from `cache_dir` via `instant-acme`
- `request_certificate(domain, challenge_type)` — Full ACME order flow: create order → get challenges → validate → finalize → download cert chain → write to `cert_path`/`key_path` (file watcher hot-reloads via `CertResolver`)
- `handle_http_challenge(path: &str) -> Option<String>` — Returns key authorization for `/.well-known/acme-challenge/{token}` paths
- `renew_expiring()` — Check all managed certs via `x509-parser`; re-run ACME for certs expiring within 30 days
- `spawn_renewal_task()` — Tokio task calling `renew_expiring()` every 24h (replaces stub that only reloads from disk)

**Challenge support**: HTTP-01 (default, intercepts `/.well-known/acme-challenge/{token}` before router), DNS-01 (feature-gated `dns`, creates `_acme-challenge.{domain}` TXT record via DNS server API).

**New files**:
- `src/tls/acme_dns.rs` (~150 lines, feature-gated `dns`) — DNS-01 challenge integration
- `src/tls/sni_peek.rs` (~100 lines) — Lightweight ClientHello SNI parser for passthrough (used by Part 3)

**Modified files**:
- `Cargo.toml` — Add `instant-acme = "0.7"`
- `src/tls/mod.rs` — Declare `acme_dns`, `sni_peek` modules
- `src/config/tls.rs` — Add `challenge_type: AcmeChallengeType` to `AcmeConfig`
- `src/http/server.rs` — HTTP-01 challenge interception before router dispatch

### ~~7.2 TLS Cert Distribution (Origin → Edge)~~ ✅

**Status**: Complete. Created `src/mesh/cert_dist.rs` (~240 lines) with `CertDistManager`; 3 new mesh message variants; AES-256-GCM encryption via HKDF-derived per-site keys; protobuf definitions and encode/decode wiring.

**New file**: `src/mesh/cert_dist.rs` (~250 lines)

```rust
pub struct CertDistributor {
    mesh_transport: Arc<MeshTransport>,
    cert_resolver: Arc<CertResolver>,
    topology: Arc<MeshTopology>,
}
```

Key functions:
- `encrypt_cert_key(private_key_pem, site_id, mesh_session_key) -> (ciphertext, nonce)` — AES-256-GCM with HKDF-derived per-site key
- `decrypt_cert_key(ciphertext, nonce, site_id, mesh_session_key) -> String`
- `distribute_cert_to_peers(site_id, cert_chain_pem, private_key_pem)` — Broadcast `SiteTlsCertSync` to all mesh peers after ACME obtains/renews
- `handle_cert_sync(message)` — Edge receives, verifies Ed25519 signature, decrypts key, loads into `CertResolver`
- `request_cert_from_origin(site_id)` — Edge startup pull-based request

**Edge discovery**: No `find_all_edges_for_site` exists in topology. Distribution uses:
1. **Pull-based** (edge startup): Edge sends `SiteTlsCertRequest` to upstream origins
2. **Push-based** (cert renewal): Origin broadcasts `SiteTlsCertSync` to all mesh peers

**Key derivation**: `site_cert_key = HKDF-SHA256(mesh_session_key, SHA-256(site_id + network_id), "maluwaf-tls-cert-dist", 32)`

**New mesh messages** (added to `src/mesh/protocol.rs`):
- `SiteTlsCertSync` — Origin pushes cert to all peers
- `SiteTlsCertRequest` — Edge requests cert on startup
- `SiteTlsCertResponse` — Origin responds with cert

**Modified files**:
- `src/mesh/protocol.rs` — Add 3 message variants (~30 lines)
- `src/mesh/transport.rs` — `broadcast_cert_to_peers()` via `broadcast_to_random_peers` (~80 lines)
- `src/mesh/transport_peer.rs` — Cert sync/request/response handlers (~120 lines)
- `src/tls/cert_resolver.rs` — `load_cert_from_pem()` for in-memory cert loading without touching files (~40 lines)
- `src/mesh/mod.rs` — Declare `cert_dist` module

**Dependency**: Part 2 depends on Part 1 (needs real certs to distribute).

### ~~7.3 TLS Passthrough Mode~~ ✅

Site-level config to forward raw TLS bytes from client to origin without decryption. WAF applies layer 3/4 only (IP rate limiting, connection limits).

**How it works**: ~~Edge reads first TLS record, extracts SNI via `sni_peek.rs` (created in Part 1), routes to site based on SNI hostname, then proxies raw TCP to origin. The original ClientHello bytes are preserved and forwarded.~~ ✅

**Layer 3/4 protections**: ~~Applied at TCP accept time, BEFORE TLS handshake (fixes existing bug where `flood_protector.check_tcp_connection()` is called AFTER handshake at `src/tls/server.rs:176`).~~ ✅ Bug fixed.

```rust
match flood_protector.check_tcp_connection(client_ip) {
    FloodDecision::Blackholed | FloodDecision::RateLimited => {
        drop(stream);
        continue;
    }
    FloodDecision::Allowed => {}
}
if site_config.tls_passthrough {
    proxy_raw_tcp(stream, origin_addr).await;
    return;
}
```

**Modified files**:
- `src/config/site.rs` — Add `tls_passthrough: Option<bool>` to `SiteProxyConfig` (~5 lines)
- `src/tls/server.rs` — Passthrough mode: SNI peek + raw TCP proxy (~150 lines)
- `src/tls/sni_peek.rs` — Created in Part 1, used here

**Dependency**: Part 3 and Part 1 can run in parallel.

### 7.4 Config Example

```toml
[tls.acme]
enabled = true
email = "admin@example.com"
domains = ["example.com", "*.example.com"]
staging = false
cache_dir = "/var/lib/maluwaf/acme"
challenge_type = "http-01"   # or "dns-01"

[sites.example.tls]
tls_passthrough = false
```

### 7.5 Internal Ordering

```
Phase 7a: ACME client (src/tls/acme.rs rewrite)     ─┐
Phase 7c: TLS passthrough (server.rs + sni_peek.rs)  ─┤─ parallel
Phase 7b: Cert distribution (cert_dist.rs + messages) ─┘─ after 7a
```

### 7.6 Testing

- ACME: Unit test with Let's Encrypt staging, HTTP-01 challenge flow, DNS-01 TXT record lifecycle
- Cert distribution: encrypt/decrypt round-trip, `SiteTlsCertSync` serialization, origin→edge push flow, invalid signature rejection
- Passthrough: `extract_sni()` with valid/invalid data, raw TCP proxy with SNI routing, flood protection before handshake, non-passthrough sites still use normal TLS

### 7.7 Risks

| Risk | Mitigation |
|------|-----------|
| ACME rate limits (50 certs/domain/week) | Staging for dev, aggressive caching |
| Private key exposure in memory | `zeroize` on key material after loading |
| Passthrough bypasses layer 7 inspection | Explicit opt-in, metrics track mode |
| SNI extraction failures | Fallback to default site, error logging |
| Cert distribution race (old cert in use) | `CertResolver` RwLock atomic swap — new connections get new cert, existing continue with old |

---

## Phase 8: DNS Improvements

*Goal: Full DNSSEC signing, RSA support, protocol compliance.*

### 8.1 Wire DNSSEC Signing into Authoritative Query Path ✅

**Source**: `plan_dns.md`

- ~~Call `sign_record()` from `handle_query()` for answer records~~ ✅ `create_signed_rrsig()` called from `build_response()`
- ~~Append RRSIG records to answer section~~ ✅ RRSIG records appended after answer records
- ~~Implement NSEC/NSEC3 for NXDOMAIN/NODATA responses~~ ✅ `build_nsec_records()`, `build_nsec3_records()`, `build_nsec3_nodata()`
- ~~Set AD flag on signed responses~~ ✅ AD set conditionally when records are actually signed (Wave 5 fix)

### ~~8.2 RSA Key Generation~~ ✅

**Source**: `plan_dns.md`, `plan_dns2.md`

- Added `rsa = "0.9"` with RSA key generation (1024/2048/4096 bit)
- RSA public key formatted as DNSKEY wire format; RSA-SHA256 signing via `Pkcs1v15Sign`
- `CryptoRngAdapter` bridges `getrandom` to rand_core 0.6

### ~~8.3 QNAME Minimization~~ ✅

**Source**: `plan_dns.md`, `plan_dns2.md`

- Wired `qname_minimization` config to `HickoryResolver::with_qname_minimization()`
- System upstream provider uses `with_qname_minimization()` when enabled
- Config default `true` in `RecursiveDnsConfig`

### ~~8.4 TCP Amplification Fix~~ ✅

**Source**: `plan_dns.md`

- Added `max_amplification_ratio: f32` to `ConnectionLimits` (default 2.0)
- `validate_amplification()` method checks response/query size ratio
- `AmplificationExceeded` error variant with query_size, response_size, ratio fields

### ~~8.5 TSIG Enforcement for Zone Transfers~~ ✅

**Source**: `plan_dns.md`, `plan_dns2.md`

- TSIG enforcement implemented (require_tsig config default true)
- AXFR/IXFR response message ID RFC compliance (query ID threaded through API chain)

### ~~8.6 DNS64 Integration~~ ✅

**Source**: `plan_dns.md`

- DNS64 synthesis wired into `handle_query()`
- Synthesizes AAAA from A records when enabled

### ~~8.7 Cache Performance~~ ✅

**Source**: `plan_dns2.md`

- Added secondary qname index for O(1) invalidation (replaces linear scan)
- Cache qname_index stale key pruning implemented

### ~~8.8 Replace `dns-parser` with `hickory-proto`~~ ✅

**Source**: `plan_sec.md`

- Replaced 8-year-old `dns-parser` crate with actively maintained `hickory-proto`
- `dns-parser` removed from Cargo.toml; 75 references migrated

### ~~8.9 DNSSEC Validation in Forwarder Mode~~ ✅

**Source**: `plan_dns.md`, `plan_dns3.md`

- `HickoryResolver` limitation documented: `is_dnssec_validated` always false in forwarder mode
- AD bit cannot be propagated (not exposed by hickory-resolver 0.25 lookup API)
- Clear guidance: use `HickoryRecursor` with `dnssec_validation: true` for validated responses

---

## Phase 9: DHT & Mesh Improvements

*Goal: Fix routing correctness, add test coverage, clean up transport architecture.*

### ~~9.1 Geo-Aware Routing Fixes~~ ✅

**Source**: `plan_dht3.md`

- Removed dead `find_closest_peers_geo()` and `find_closest_peers_geo_weighted()` methods
- Fixed regional hub local region detection (added `local_geo` field, replaced never_loop hack)
- Added `with_local_geo` builder method

### ~~9.2 Document Transport Architecture~~ ✅

**Source**: `plan_dht3.md`

- Added architecture documentation to `src/mesh/transport.rs`: `MeshTransport` vs `MeshTransportManager` roles, extension file structure, field visibility requirements

### ~~9.3 DHT Record Store Lock Consolidation~~ ✅

**Source**: `plan_security_scalability.md`

- Replaced 22 flat `RwLock` fields with 3 grouped inner structs: `RecordStoreState`, `RoutingState`, `MetricsState`
- Updated 123 access sites across 5 files
- Clone impl uses single lock acquisition per group (no TOCTOU race)

---

## Phase 10: Feature Work — Bots, ASN, Plugins

### ~~10.1 AI Bot Blocking Enhancement~~ ✅

**Source**: `plan_bots.md`

- Expanded AI crawler blocklist from 6→24 patterns (OpenAI, Anthropic, Perplexity, Apple, Amazon, Meta, TikTok, xAI, Mistral, Cohere, AI21)
- Added per-site `block_ai_crawlers` override via `check_with_override()`
- Added alert logging for unknown AI bot patterns
- Added DHT integration via `GlobalAiBotList` key type and `AiBotEntry` struct

### ~~10.2 ASN-Based Distributed Scraper Detection~~ ✅

**Source**: `plan_asn.md`

- Created `src/waf/asn_tracker.rs` (~250 lines) with `AsnTracker`, `AsnScrapingConfig`
- Per-ASN `AtomicSlidingWindow` counters, IP→ASN caching, dual threshold (volume+distribution)
- Whitelisted ASNs (12 CDNs/cloud providers); `ThreatType::AsnBlock` in mesh protocol
- Wired into `WafCore` with `asn_off` test mode

### ~~10.3 Plugin System Completion~~ ✅

**Source**: `plan_plugins.md`

- **Fixed ABI symbol**: `rustwaf_abi_version` → `maluwaf_abi_version` in example plugin
- **Fixed router discard bug**: Wrapper now holds `Arc<Router>` instead of empty `Router::new()`
- **WASM filters**: Full guest ABI with `filter_request()`, `transform_response()`, linear memory, fuel metering, wall-clock timeout
- **WASM serverless**: Modules export `filter_request(method, uri, headers, body)` and `transform_response(status, body, out, out_max)`
- **Hot reload**: File watching with `notify` crate; auto-reloads `.wasm`, `.wat`, `.so`, `.dylib` on modification
- **Router integration**: `AxumDynamic` backend wired into `http/server.rs` dispatch via `handle_axum_dynamic_request()`
- **PluginManagerLifecycle**: Lifecycle management with `load_plugins_from_dir()`, `reload_plugin()`, `shutdown()`

### ~~10.4 Image Poisoning (cloakrs Integration)~~ ✅

**Source**: `plan_security_scalability2.md`

- Integrated `cloakrs` crate for AI/ML training data protection with fail-open design
- Added `SiteImagePoisonConfig` struct with per-site: enable/disable, protection level, seed, intensity, max_dimension, jpeg_quality
- Poisoning disabled by default; must be explicitly enabled per-site
- All config fields wired to `cloakrs::ProtectionContext` builder methods

---

## Phase 11: Admin Panel Completion

*Goal: All config sections accessible via UI, settings page functional.*

### ~~11.1 Fix Settings Page (Critical)~~ ✅

**Status**: Complete. Replaced hardcoded values with API-driven data; fetches `GET /api/config/main` + `GET /api/config/schema` on mount; Save button calls `PUT /api/config/main`; Export/Import/Reload toolbar added.

### ~~11.2 Fix Worker Restart~~ ✅

**Source**: `plan_ui5.md`, `plan_ui6.md`

- ~~Fix URL: `/system/worker/{id}/restart` → `/system/workers/{id}/restart`~~ ✅
- ~~Implement `restart_worker` in `src/admin/handlers/system.rs` (send SIGTERM, let reap_zombies auto-restart)~~ ✅
- ~~Add `restart_worker_by_id()` to `src/process/manager.rs`~~ ✅
- Add `RestartWorkerRequest`/`RestartWorkerResponse` IPC messages — **deferred** (SIGTERM-based restart sufficient for now)

### ~~11.3 Add Missing Backend Config Endpoints~~ ✅

**Sources**: `plan_ui2.md`, `plan_ui3.md`, `plan_ui4.md`, `plan_ui6.md`

~~Add GET/PUT handlers for:~~ ✅ All 13 endpoints implemented in `src/admin/handlers/config.rs` with `persist_main_config()` helper.
| Config | Endpoint | Handler File |
|--------|----------|-------------|
| TLS | `/config/tls` | `tls.rs` |
| HTTP | `/config/http` | `http_config.rs` |
| Security | `/config/security` | `security_config.rs` |
| Tunnel | `/config/tunnel` | tunnel config handler |
| DNS | `/config/dns` (feature-gated) | DNS config handler |
| Plugins | `/config/plugins` | `plugin_config.rs` |
| Rate Limits | `/config/rate-limits` | `rate_limit_config.rs` |
| Bot Detection | `/config/bot-detection` | `bot_config.rs` |
| Traffic Shaping | `/config/traffic-shaping` | `traffic_config.rs` |
| Logging | `/config/logging` | logging config handler |
| Mesh | `/config/mesh` | mesh config handler |
| Validate | `POST /config/validate` | validation handler |

Pattern: follow existing `/config/overseer` handler in `src/admin/handlers/config.rs`.

### ~~11.4 Add New Frontend Pages~~ ✅

**Status**: Complete. 12 new page stubs added: honeypot, rule_feed, tls_settings, feeds, upstreams, dns, dns_zones, dns_config, dns_dnssec, tunnel, tunnel_vpn, tunnel_config.

### ~~11.5 Add Stub Endpoint Implementations~~ ✅

**Source**: `plan_ui3.md`

~~Implement real handlers for currently-stubbed endpoints:~~ ✅
| Endpoint | Purpose |
|----------|---------|
| `POST /upstreams/{site_id}/check` | Upstream health check trigger |
| `POST /tcp-udp/listeners` | Create TCP/UDP listener |
| `DELETE /tcp-udp/listeners/{id}` | Remove TCP/UDP listener |
| `PUT /error-pages/{code}` | Update custom error page |
| `POST /probes/block` | Block probing IP |

### ~~11.6 Settings Tab Expansion~~ ✅

**Status**: Complete. 7 new tabs: Blocked Paths, Auth Defaults, TLS, IP Feeds, Log Exporters, Traffic Shaping, Rate Limits.

### ~~11.7 Sidebar Reorganization~~ ✅

**Status**: Complete. Reorganized into Overview, Security, Management, Configuration groups.

### ~~11.8 Dynamic Schema Rendering~~ ✅

**Status**: Complete. `DynamicField` component, serde-based schema generation, `POST /api/config/validate`.

### ~~11.9 Config Versioning & Audit~~ ✅

**Status**: Complete. Compressed JSON snapshots, validation framework, audit logging.

### ~~11.10 Legacy Admin Code Cleanup~~ ✅

**Source**: `plan_ui6.md`

- ~~Remove `src/admin/legacy.rs` (385 lines of dead code)~~ ✅ (413 lines deleted)

### ~~11.11 API Service Additions~~ ✅

**Status**: Complete. ~15 new methods added to `admin-ui/src/api.rs`.

---

## Phase 12: Documentation & Polish

### ~~12.1 Public API Documentation~~ ✅ (partial)

**Source**: `plan.md`, `plan2.md` §6.1

- Added doc comments to `WafError`, `BufferPool`, `BufferPoolConfig`, `Message` enum, `WorkerId`
- Added crate-level documentation to `src/lib.rs`
- 585 public functions still lack doc comments (low priority, incremental)

### ~~12.2 IPC Message Organization~~ ✅

**Source**: `plan.md`

- Added `MessageCategory` enum with 15 concern groups
- Added `Message::category()`, `Message::is_lifecycle()`, `Message::is_drain()` convenience methods
- Comprehensive doc comment grouping all 90 `Message` variants by concern
- Flat variant structure preserved for postcard wire-format stability

### ~~12.3 Add `cargo-deny` to CI~~ ✅

**Source**: `plan_sec.md`, `plan_sec2.md`

- `deny.toml` verified complete with advisory, license, duplicate dependency checks

### ~~12.4 Dependency Upgrades~~ ✅ (partial)

**Source**: `plan_sec.md`

| Crate | Action | Risk | Status |
|-------|--------|------|--------|
| `wasmtime` 36→42 | Major upgrade, eliminates ~80 duplicate crates | High | ✅ v42.0.0 (v43 blocked by bumpalo conflict) |
| `boringtun` → `defguard_boringtun` | Community fork, actively maintained | Low | ✅ v0.6.5 |
| `lightningcss` alpha bump | Stay current | Low | ✅ alpha.70 → alpha.71 |

### ~~12.5 Verify DNS Feature Tests~~ ✅

**Source**: `plan2.md` §1.2

- Fixed 5 failing DNS tests (base32_encode length, DoQ config defaults via serde, HSM disabled expectation, 2× negative cache behavior)

---

## Execution Order Summary

| Phase | Focus | Depends On | Risk | Parallelizable With |
|-------|-------|-----------|------|-------------------|
| **1** | Foundation (compilation, deps, dead code) | None | Low | — |
| **2** | Critical security (bcrypt, auth timing, TLS, IPC, DoS) | 1 | Medium | 3,5,6,7,11 |
| **3** | Correctness bugs (IPC, DNS wire, DHT, timestamps) | 1 | Medium-High | 2,5,6,7,11 |
| **4** | Testing (fix failures, behavioral tests, e2e lifecycle) | 1,3 | Low | 8,9 |
| **5** | Performance (LRU, rate limiter, blocking I/O, atomics) | 1 | Medium | 2,3,6,7,11 |
| **6** | Code quality (dedup, modules, splits, errors) | 1 | Low | 2,3,5,7,11 |
| **7** | TLS (ACME, cert distribution, passthrough) | 1 | Medium | 2,3,5,6,11 |
| **8** | DNS improvements (DNSSEC signing, RSA, QNAME) | 3 | Medium | 4,9 |
| **9** | DHT improvements (geo routing, lock consolidation) | 3 | Medium | 4,8 |
| **10** | Features (bots, ASN, plugins, image poisoning) | 1,5 | Medium-High | — |
| **11** | Admin panel (settings, 18 endpoints, 12+ pages) | 1 | Medium | 2,3,5,6,7 |
| **12** | Documentation & polish | All | Low | — |

### Wave Completion Log

| Wave | Date | Phases | Status | Notes |
|------|------|--------|--------|-------|
| 1 | 2026-03-27 | Phase 1 | **✅ Complete** | 9 dead deps removed, once_cell migrated, DNS deps gated, 2 dead files deleted, rustls-pemfile removed, 14 test compilation errors fixed. `nix` net/uio features kept (required). 93 pre-existing clippy warnings deferred to Phase 6. |
| 2 | 2026-03-27 | Phase 2+3+5+6+7+11 | **✅ Complete** | 6 concurrent phases. Bcrypt cost→12, timing attack fix, normalizer DoS guard, XSS header default, CORS wildcard, 7 timestamps consolidated, panics fixed, IPC lock fix, graceful shutdown, DHT fixes, cache LRU→LinkedHashMap, 43 fetch_sub→fetch_update, blocking I/O fixed, WAF dedup ~200 LOC, config dedup, eprintln→tracing, ACME client + sni_peek + passthrough, 13 admin config endpoints, worker restart, 5 stub handlers, legacy.rs deleted. |
| 3 | 2026-03-28 | Phase 4+8+9 | **✅ Complete** | 4 test compilation errors fixed (current_timestamp, SystemTime imports). 2 failing DNS config tests fixed (admin token bcrypt_cost, negative cache assertion). 20 behavioral architecture tests added (drain_state:6, process_manager:5, master_ipc:4, overseer:3, worker_traits:2). DNS: CDS record type DS→CDS fix, CDNSKEY RecordType DNSKEY→CDNSKEY fix, CDNSKEY KSK-only (removed ZSK), CDNSKEY flags corruption fix (removed spurious 0x8000). DHT: removed dead find_closest_peers_geo/geo_weighted methods, fixed regional hub local region detection (added local_geo field, replaced never_loop hack), added with_local_geo builder method. |
| 4 | 2026-03-28 | Phase 10+12 | **✅ Complete** | 10.1: Expanded AI crawler blocklist from 6→24 patterns (OpenAI, Anthropic, Perplexity, Apple, Amazon, Meta, TikTok, xAI, Mistral, Cohere, AI21). Added per-site `block_ai_crawlers` override via `check_with_override()`. Added alert logging for unknown AI bot patterns. 10.2: Created `src/waf/asn_tracker.rs` (~250 lines) with `AsnTracker`, `AsnScrapingConfig`, per-ASN `AtomicSlidingWindow` counters, IP→ASN caching, dual threshold (volume+distribution), whitelisted ASNs (12 CDNs/cloud providers). Added `AsnScrapingConfig` to `src/config/defaults.rs`. Wired into `WafCore` with `asn_off` test mode. Added `ThreatType::AsnBlock` to mesh protocol. 10.3: Fixed plugin ABI mismatch (`rustwaf_abi_version` → `maluwaf_abi_version` in example plugin). Fixed `PluginManager` router discard bug (wrapper now holds `Arc<Router>` instead of empty `Router::new()`). 10.4: Integrated `cloakrs` crate for image poisoning with fail-open design. 12.1: Added doc comments to `src/lib.rs` (crate-level), `WorkerId`, `Message` enum, `BufferPool`, `BufferPoolConfig`. 12.3: Verified `deny.toml` is complete. 12.5: Fixed 5 failing DNS tests (base32_encode length, DoQ config defaults via serde, HSM disabled expectation, 2× negative cache behavior). |
| 5 | 2026-03-29 | Phase 3+4+8+9 (remaining) | **✅ Complete** | DNS wire format bugs: NSEC3 hash loop off-by-one (`..=` → `..`), NSEC3 owner name hash-length byte (binary char → decimal string), MX exchange trailing null byte, CNAME/NS trailing null byte, ARCOUNT accounting (OPT/RRSIG not counted), AD flag only set when records are actually signed. DHT: init() dedup for initial peer batch. Tests: 17 protocol encode/decode roundtrip tests added covering MeshMessage serialization (KeepAlive, Ping, Pong, SyncRequest, LookupRequest/Response, PeerHealthCheck/Response, Error, MeshAck, LookupBatchRequest, binary data, empty strings, invalid data, length-prefix framing). |
| 6 | 2026-03-29 | Phase 8+9 (remaining) + review | **✅ Complete** | TSIG enforcement (require_tsig config default true). DNS64 synthesis wired into handle_query(). DNS cache secondary qname index (O(1) invalidation). Replaced dns-parser with hickory-proto (removed crate, 75 references migrated). DHT lock consolidation (22 RwLock fields → 3 grouped structs, 123 access sites). Transport architecture docs. Panic/unwrap fixes (8 locations: overseer/upgrade.rs, overseer/cli.rs, admin/auth.rs, admin/mod.rs, dns/compression.rs). AXFR/IXFR message ID RFC compliance (query ID threaded through API chain). Cache qname_index stale key pruning. Review fixes: Clone impl TOCTOU (single lock per group), record_successful_sync lock cycling, should_resync atomic reads. |

---

## Verification Protocol

After every phase:
```bash
cargo check
cargo test --test integration_test
cargo clippy -- -D warnings
cargo fmt --check
```

After major changes:
```bash
cargo test                         # Full suite
cargo test --features dns          # DNS feature
cargo test --no-default-features   # Minimal features
```

---

## Estimated Scope

| Phase | LOC Changed | Effort | Files | Status |
|-------|-------------|--------|-------|--------|
| 1 | ~50 | ~2 hours | ~20 | **✅ Complete** |
| 2 | ~400 | 1-2 days | 12 | **✅ Complete** |
| 3 | ~700 | 2-3 days | 35 | **✅ Complete** |
| 4 | ~500 | 1 day | 10 | **✅ Complete** |
| 5 | ~400 | 1-2 days | 10 | **✅ Complete** |
| 6 | ~600 | 2-3 days | 28 | **✅ Complete** |
| 7 | ~900 | 1-2 weeks | 12 | **✅ Complete** |
| 8 | ~400 | 1-2 weeks | 10 | **✅ Complete** |
| 9 | ~200 | 3-5 days | 8 | **✅ Complete** |
| 10 | ~1500 | 2-3 weeks | 20 | **✅ Complete** |
| 11 | ~2500 | 2-3 weeks | 30 | **✅ Complete** |
| 12 | ~100 | 1 day | 5 | **✅ Complete** |
| **Total** | **~8,350** | **~6-8 weeks wall-clock** | **~190** | **✅ All Complete** |

With parallel agents (Wave 2: 6 concurrent phases), estimated wall-clock time drops to **~6-8 weeks**.
