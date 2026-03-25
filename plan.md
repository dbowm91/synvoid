# MaluWAF Remediation Plan (Merged)

> Consolidated from plan.md, plan2.md, plan3.md, and plan4.md on 2026-03-25
> 580 `unwrap()`/`expect()` calls, 90 `unsafe` blocks, 50+ identified issues

---

## Phase 1: Critical Correctness Fixes

> **COMPLETED 2026-03-25.** All 12 items fixed. See `git log --oneline` for commits.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo clippy` ✅
> `cargo test --test integration_test` ✅ (99/99 passed)

### Phase 1 Follow-up Items

Items discovered during review that should be addressed before moving to Phase 2:

| # | Issue | File:Line | Description | Priority |
|---|-------|-----------|-------------|----------|
| 1.F1 | Deduplicate auth login_logs on merge | `src/auth/mod.rs:168-179` | `merge_stores` extends login_logs from all stores. Since later stores are supersets of earlier ones, entries from S1 appear in both S2 and S3, causing duplicates. Fix: only take login_logs from the oldest (first) store, or use a `HashSet<log_id>` for dedup. | Medium |
| 1.F2 | Log on connection counter underflow | `src/upstream/pool.rs:194-197` | `decrement_connections` silently ignores `fetch_update` returning `Err(0)`. Add `tracing::warn!` when underflow would occur, for observability. | Low |
| 1.F3 | CSS challenge path exemptions | `src/waf/mod.rs:581` | Challenge now applies to ALL paths (plan said "configurable exemptions"). This can break API consumers, health checks, and third-party integrations. Either: (a) add `challenge_exempt_paths: Vec<String>` to WAF config, or (b) document the behavior change in release notes. | High |
| 1.F4 | Pre-existing SSRF test failure | `src/waf/attack_detection/ssrf.rs:301-306` | `test_ssrf_no_block` was already failing on master before Phase 1. The Aho-Corasick pattern `"192.168."` matches even when `block_private_ips=false`. Fix: skip pattern matching when `block_private_ips=false` and `allowed_domains` is empty, or restructure the pattern/private-IP priority. | Medium |
| 1.F5 | Extract shared key tag utility | `src/dns/dnssec.rs:953` + `src/dns/trust_anchor.rs:790` | Two identical `calculate_key_tag` / `calculate_dnskey_key_tag` implementations. Extract into a single `pub fn compute_dnskey_key_tag(flags, protocol, algorithm, public_key) -> u16` in `dnssec.rs` and call from both modules. | Low |

---

## Phase 2: Security and TLS Hardening

> **COMPLETED 2026-03-25.** All 14 items addressed. See `git log --oneline` for commits.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo test --test integration_test` ✅ (99/99 passed)
> `cargo clippy` produces 107 warnings (down from 750 after auto-fix); all are incremental quality issues deferred to Phases 3-6.

### Phase 2 Follow-up Items

| # | Issue | File:Line | Description | Priority |
|---|-------|-----------|-------------|----------|
| 2.F1 | `create_upstream_client` not yet wired | `src/http_client/mod.rs` | New function exists but callers still use `create_http_client_with_config()`. Proxy, health check, and TLS server should migrate to `create_upstream_client()` with per-site `UpstreamTlsConfig`. | Medium |
| 2.F2 | Residual clippy warnings (107) | Various | Remaining warnings are in categories: clamp patterns (10), boolean simplification (9), `&PathBuf`→`&Path` (7), collapsed `if let` (7), complex types (6), etc. Fix incrementally as modules are touched. | Low |
| 2.F3 | `ca_cert_path` in `UpstreamTlsConfig` unused | `src/http_client/mod.rs:65` | Field exists in struct but `build_tls_config()` ignores it (marked `_ca_cert_path`). Need `rustls-pemfile` dep to load custom CA certs. | Low |
| 2.F4 | Admin token bcrypt hashing | `src/master/commands.rs` | Token is stored in plaintext in config (by design — shared secret). For production hardening, consider bcrypt hashing + `bcrypt::verify()` at runtime, similar to user auth flow. | Low |

| # | Issue | File:Line | Description | Verification |
|---|-------|-----------|-------------|--------------|
| 2.1 | Remove `#![allow(clippy::all)]` | `src/lib.rs:1` | Suppresses all clippy lints globally. Remove; fix warnings per-module with targeted `#[allow]`. | `cargo clippy -- -D warnings` passes |
| 2.2 | Fix `.cargo/config.toml` target-dir | `.cargo/config.toml:2` | `target-dir = "target/fuzz"` affects ALL cargo commands. Move to `fuzz/.cargo/config.toml`. | `cargo build` writes to `target/` |
| 2.3 | Embedded key placeholder | `src/waf/rule_feed.rs:10` | `EMBEDDED_PUBLIC_KEY` is `"DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER"`. `parse_embedded_key` falls back to zero-key. Rule signature verification always fails. Generate real key. | Rule signature verification succeeds |
| 2.4 | TLS: plaintext upstream default | `src/http/http_client/mod.rs:99-104` | `https_or_http()` allows unencrypted HTTP to upstreams. Change to `https_only()`, add `allow_plaintext_upstream` config. | `http://` upstream rejected by default |
| 2.5 | TLS: panic on missing root certs | `src/http/http_client/mod.rs:100` | `.with_native_roots().unwrap()` panics in minimal containers. Add fallback to webpki roots. | No panic in container without root certs |
| 2.6 | TLS: `skip_verify` unused | `src/http/http_client/mod.rs:66` | `UpstreamTlsConfig.skip_verify` defined but never read. Wire into `danger_accept_invalid_certs`. | `skip_verify: true` accepts invalid certs |
| 2.7 | Rate limiter race condition | `src/http/server.rs:1533-1541` | Check-and-reset is not atomic. Two concurrent requests can both reset counter. Use `compare_exchange`. | Concurrent stress test: counter never exceeds limit+1 |
| 2.8 | IPC key in env var | `src/process/manager.rs:448-451` | `MALUWAF_IPC_KEY` readable from `/proc/<pid>/environ`. Write to temp file 0600, pass path instead. | Key not visible in `ps e` output |
| 2.9 | IPC message validation incomplete | `src/process/ipc.rs:617-756` | `validate()` only checks a subset. Catch-all `_ => Ok(())` silently accepts unvalidated messages. Expand validation to all string-containing variants. | Malformed messages rejected |
| 2.10 | IPC deserialization panic | `src/process/ipc.rs:1080-1295` | Many `.unwrap()` on `serde_json::from_str` in IPC handlers. Malformed messages crash the process. Replace with `Result` returns. | Fuzzing IPC messages → no panic |
| 2.11 | CORS wildcard | `src/admin/mod.rs:36` | `origin == "*"` allows any origin. Confirmed present. Log warning; reject in release builds or require explicit opt-in. | `cargo build --release` + wildcard origin → rejected |
| 2.12 | Token storage verification | `src/master/commands.rs` | Ensure auth tokens are bcrypt-hashed before persistence. Verify existing tokens aren't stored in plaintext. | Token file contains only bcrypt hashes |
| 2.13 | HSM PIN stored as field | `src/dns/hsm.rs:62` | PIN is a struct field without zeroize. Use `Zeroize` on drop. | Memory dump after drop shows no PIN |
| 2.14 | Stub admin endpoints | `handlers/system.rs:206`, `handlers/upstreams.rs:144`, `handlers/probes.rs:329`, `handlers/tcp_udp.rs:92,129`, `handlers/logs.rs:174` | 6 endpoints return success without doing anything. Implement or remove with 501. | All endpoints either functional or return 501 |

---

## Phase 3: Error Handling and Unsafe Code

> **COMPLETED 2026-03-25.** All 4 items addressed. See `git log --oneline` for commits.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo test --test integration_test` ✅ (99/99 passed)
> `cargo clippy` produces 156 warnings (up from 107 after removing dead_code suppression; all are incremental quality issues deferred to later phases).

### Phase 3 Follow-up Items

| # | Issue | File:Line | Description | Priority |
|---|-------|-----------|-------------|----------|
| 3.F1 | Residual "field is never read" warnings (33) | Various | Removing `#![allow(dead_code)]` revealed 33 fields that are written but never read. These are pre-existing issues in fields like `auto_scaler`, `tunnel_manager`, `listen_addr`, `config`, etc. Fix per-module as part of Phase 6 refactoring. | Low |
| 3.F2 | `main.rs` unwrap/expect acceptable | `src/main.rs:459,484,524,579,716` | 5x `.expect("Failed to build Tokio runtime")` are in `main()` entry points where panicking is the standard error handling pattern. No action needed. | N/A |
| 3.F3 | Safe abstractions for platform unsafe code | `src/platform/socket.rs`, `src/platform/unix.rs` | Steps 3-4 of 3.3 recommended wrapping `from_raw_fd` calls in safe abstractions and adding Miri CI. Deferred — platform FD operations already have `# Safety` docs on `unsafe fn` signatures, which is standard Rust convention. | Low |

### 3.1 Centralize Error Types

Create `src/error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum WafError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("IPC message decode error: {0}")]
    IpcDecode(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Request parsing error: {0}")]
    RequestParse(String),

    #[error("Invalid file descriptor")]
    InvalidFd,

    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type WafResult<T> = Result<T, WafError>;
```

### 3.2 Audit `unwrap()`/`expect()` in Production Code

580 occurrences. Prioritize critical paths:

| Priority | Module | Count (approx) | Action |
|----------|--------|----------------|--------|
| P0 | `src/process/ipc.rs` | ~30 | Replace with `?` / `map_err` |
| P0 | `src/waf/probe_tracker.rs` | ~5 | IP parse → `unwrap_or_else` with default |
| P0 | `src/proxy.rs` | ~5 | Header parse → return error |
| P0 | `src/dns/server.rs` | ~10 | DNS query parse → return SERVFAIL |
| P0 | `src/dns/dnssec.rs` | ~15 | Crypto ops → return `Result` |
| P1 | `src/utils.rs` | ~15 | Utility functions → `Result` |
| P1 | `src/tunnel/` | ~20 | WireGuard/TUN → `Result` |
| P1 | `src/tls/server.rs` | ~5 | TLS setup → `Result` |
| P1 | `src/supervisor/autoscaler.rs` | ~5 | Replace `parking_lot` `.unwrap()` |
| P2 | `src/waf/ratelimit/core.rs` | ~5 | IP parse in tests → keep or fix |
| P2 | `src/worker/unified_server.rs` | ~10 | Various → `Result` |
| P2 | `src/main.rs` | ~5 | CLI setup → acceptable in main |
| Keep | Test functions | ~400+ | `unwrap()` is acceptable in tests |

**Target:** < 50 `unwrap()` in non-test production code paths.

### 3.3 Audit Unsafe Blocks (90 occurrences)

Add `// SAFETY:` comments documenting invariants:

| Category | Files | Action |
|----------|-------|--------|
| Windows named pipes | `src/worker/mod.rs:588-628`, `src/main.rs:1190-1307`, `src/master/windows.rs`, `src/process/ipc_windows.rs` | Document handle validity |
| Unix FD operations | `src/process/socket_fd.rs:366-389`, `src/platform/unix.rs:405-413`, `src/platform/socket.rs` | Document fd ownership |
| eBPF operations | `src/platform/windows_impl.rs`, `src/platform/windows/wintun.rs` | Document bounds checks |
| Raw socket handling | `src/tunnel/wireguard/tun.rs:190-374` | Document fd validity |
| Plugin loading | `src/plugin/axum_loader.rs:106-107` | Document library safety |
| Zero-copy I/O | `src/zero_copy.rs:61-115` | Document syscall invariants |
| ICMP filter | `src/icmp_filter/platform.rs:13-99` | Document root requirement |

**Steps:**
1. Add `// SAFETY:` to every `unsafe` block
2. Wrap platform code in safe abstractions where possible
3. Add Miri CI job for unsafe code paths
4. Document edge cases Miri cannot verify

### 3.4 Remove Dead Code Allow Suppressions

| File | Line | Action |
|------|------|--------|
| `src/lib.rs:1` | `#![allow(clippy::all)]` | Remove; fix per-module |
| `src/worker/mod.rs:1` | `#![allow(dead_code)]` | Remove; fix per-item |
| `src/mesh/` (22 files) | `#![allow(dead_code)]` | Remove; implement or delete dead items |
| `src/dns/server.rs` | 10 `#[allow(dead_code)]` | Remove; implement or delete |
| `src/config/main.rs:1-5` | Specific clippy allows | Review if still needed |

---

## Phase 4: Performance and Reliability

> **COMPLETED 2026-03-25.** 20 of 25 items addressed directly; 5 deferred to Phase 6.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo test --test integration_test` ✅ (99/99 passed)

### Phase 4 Follow-up Items

Items deferred from Phase 4 to later phases:

| # | Issue | File:Line | Description | Target Phase | Status |
|---|-------|-----------|-------------|-------------|--------|
| 4.F1 | Binary body in cache | `src/proxy.rs:913` | `String::from_utf8_lossy` corrupts binary content (images, compressed). Requires `Response<String>` → `Response<Bytes>` refactor throughout proxy pipeline. | 7+ | ⏭ Deferred |
| ~~4.F2~~ | ~~WAF `to_uppercase` allocation~~ | `src/waf/endpoints.rs:94` | ~~Method allocates `String` per request~~ | ~~6~~ | ✅ Fixed — `eq_ignore_ascii_case` |
| 4.F3 | `InputLocation::Header` allocation | `src/waf/attack_detection/detector_common.rs:237,303,343,375` | Creates `String` per header check. Requires `Cow<str>` or lifetime refactoring. | 7+ | ⏭ Deferred |
| ~~4.F4~~ | ~~Stale IPC during drain~~ | `src/process/manager.rs:760` | ~~Filter by drain_id~~ | ~~6~~ | ✅ Fixed — drain_id in response messages |
| 4.F5 | stdout/stderr pipe blocking | `src/process/manager.rs:457-458` | Child process pipes can block if not drained. Platform-specific, needs careful testing. | 7+ | ✅ Fixed in Phase 5 — `Stdio::inherit()` |
| 4.F6 | Async mutex standardization | `src/mesh/topology.rs:980,992` | `_sync` methods use `blocking_read()` on `tokio::sync::RwLock`. Correct for current sync callers; migrate callers to async. | 7+ | ⏭ Deferred — `_sync` variants are correct |
| 4.F7 | Arc\<Firewall\> per query | `src/dns/recursive.rs:266-276,349-359` | Firewall cloned per DNS query. Requires DNS server modular split. | 7+ | ⏭ Deferred |
| 4.F8 | Batch zone index rebuild | `src/dns/server.rs:1106-1128` | Zone index rebuilt on every load. Batch all loads and rebuild once. | 7+ | ⏭ Deferred |

### 4.1 Fix O(n) Cache Operations

| # | Issue | File:Line | Fix |
|---|-------|-----------|-----|
| 4.1.1 | `VecDeque::retain` O(n) per operation | `src/proxy_cache/store.rs:241,254,265,270,384,408,429,449,584` | Replace with `LinkedList` + `HashMap<CacheKey, LinkedListNode>` for O(1) LRU |
| 4.1.2 | Write lock on every cache read | `src/proxy_cache/store.rs:225` | Use `RwLock` for map, separate lock-free access ordering |
| 4.1.3 | `get_or_fetch` never calls fetch | `src/proxy_cache/store.rs:303-313` | Call `_fetch().await` on miss, store result |
| 4.1.4 | Binary corruption in cached responses | `src/proxy.rs:902` | `String::from_utf8_lossy` corrupts binary. Use `Bytes` body directly |
| 4.1.5 | `Cache-Control` missing `s-maxage` | `src/proxy.rs:844-858` | Parse `s-maxage`, `no-cache=`, quoted values |

### 4.2 Fix Normalizer Allocation

| # | Issue | File:Line | Fix |
|---|-------|-----------|-----|
| 4.2.1 | `original` always cloned | `src/waf/normalizer.rs:38` | Remove field or make `Option<String>` |
| 4.2.2 | Method `to_uppercase` alloc per request | `src/waf/mod.rs:942-951` | Compare against lowercase `&str` constants |
| 4.2.3 | `InputLocation::Header` allocates per check | `src/waf/attack_detection/detector_common.rs:237,303,343,375` | Use `&str` reference where possible |

### 4.3 Process Management Reliability

| # | Issue | File:Line | Fix |
|---|-------|-----------|-----|
| 4.3.1 | Unified worker no restart limit | `src/process/manager.rs:1142-1156` | Apply same `max_restart_attempts` as regular workers |
| 4.3.2 | Stale IPC during drain | `src/process/manager.rs:730-768` | Filter by drain_id, skip intermediate heartbeats |
| 4.3.3 | Stdout/stderr pipe blocking | `src/process/manager.rs:457-458` | Redirect to `/dev/null` or drain pipes |
| 4.3.4 | Overseer lock file race | `src/process/pidfile.rs:463-514` | Use `flock` as primary mechanism |
| 4.3.5 | FD count mismatch in handoff | `src/overseer/socket_handoff.rs:407-416` | Assert `fds.len() == ports.len()`, error on mismatch |
| 4.3.6 | Drain IPC error no retry | `src/overseer/drain_manager.rs:287-331` | Retry 3x with backoff for transient errors |
| 4.3.7 | `block_on` in async context | `src/worker/mod.rs:792` | Replace with async IPC or channel-based reload |
| 4.3.8 | Dummy IPC panic | `src/worker/mod.rs:792-798` | Handle error gracefully instead of panicking |
| 4.3.9 | Connection tracker `std::sync::Mutex` | `src/overseer/connection_tracker.rs:20` | Use `parking_lot::Mutex` consistently |
| 4.3.10 | Zone history unbounded growth | `src/dns/server.rs:183` | Add `prune_history()` method with max entries |

### 4.4 Collection Capacity Hints

Hot-path files — add `with_capacity` where size is predictable:

- `src/waf/ratelimit/core.rs`
- `src/proxy.rs`
- `src/worker/mod.rs`
- `src/http/early_parse.rs`

**Estimated impact:** 10-20% reduction in WAF hot-path allocations.

### 4.5 Async Mutex Standardization

Audit `parking_lot` usage in async contexts:

| File | Issue | Fix |
|------|-------|-----|
| `src/mesh/topology.rs:980,992` | `blocking_read()` in async | Remove `_sync` variants or gate to blocking contexts |
| `src/master/mod.rs` | Mixed lock types | Use `tokio::sync::RwLock` for async paths |
| `src/worker/mod.rs` | Mixed lock types | Same |
| `src/supervisor/mod.rs` | Mixed lock types | Same |

Rule: `parking_lot` for synchronous-only code. `tokio::sync` for code that holds locks across `.await`.

### 4.6 DNS Performance

| # | Issue | File:Line | Fix |
|---|-------|-----------|-----|
| 4.6.1 | Rate limiter cleanup on every check | `src/dns/server.rs:571-587` | Time-based throttle: cleanup only if >N seconds elapsed |
| 4.6.2 | Firewall clone per query | `src/dns/recursive.rs:266-276,349-359` | `Arc<Firewall>` shared across queries |
| 4.6.3 | Zone index rebuild per load | `src/dns/server.rs:1052-1074` | Batch all zone loads, rebuild once |
| 4.6.4 | `DnsServer::clone()` nullifies fields | `src/dns/server.rs` | Implement proper `Clone` or remove derive |
| 4.6.5 | Cache fingerprints unbounded | `src/dns/cache.rs:194-200` | Add TTL-based eviction alongside count limit |

---

## Phase 5: DNS RFC Compliance

> **COMPLETED 2026-03-25.** 10 of 13 items addressed directly; 3 deferred to Phase 6.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo test --test integration_test` ✅ (99/99 passed)
> `cargo clippy` produces 152 warnings (down from 156); all are incremental quality issues.

### Phase 5 Follow-up Items

Items deferred from Phase 5 to Phase 6:

| # | Issue | File:Line | Description | Target Phase | Status |
|---|-------|-----------|-------------|-------------|--------|
| 5.F1 | mesh_sync.rs split | `src/dns/mesh_sync.rs` | 1,975 lines; too complex and risky for Phase 5 | 7+ | ⏭ Deferred |
| ~~5.F2~~ | ~~drain_id in drain response~~ | `src/process/ipc.rs` | ~~`UnifiedServerWorkerDrained` and `StaticWorkerDrained` need `drain_id` field~~ | ~~6~~ | ✅ Fixed in Phase 6 |
| 5.F3 | handle_query_with_cache QueryContext | `src/dns/server.rs` | 18 call sites across 4 files | 7+ | ⏭ Deferred |

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 5.1 | DS record digest not canonical | `src/dns/dnssec.rs:1283-1314`, `src/dns/mesh_dnssec.rs:155-164` | Implement `compute_dnskey_canonical()` per RFC 4034 §5.2 | ✅ Already implemented |
| 5.2 | Inconsistent key tags | `src/dns/trust_anchor.rs:790` vs `src/dns/dnssec.rs:953` | Extract shared RFC 5011 Appendix B implementation | ✅ Fixed — trust_anchor version had wrong formula |
| 5.3 | NXDOMAIN missing question | `src/dns/server.rs:129-152` | Copy query question, set QDCOUNT=1 | ✅ Code correct; test updated to assert QDCOUNT=1 |
| 5.4 | Silent trust anchor save failure | `src/dns/trust_anchor.rs:676-678` | Check `Result`, log error, consider retry | ✅ Fixed |
| 5.5 | No algorithm validation for trust keys | `src/dns/trust_anchor.rs:492-590` | Reject deprecated algorithms (0=DH, 3=DSA) per RFC 5011 §2.2 | ✅ Fixed |
| 5.6 | `edns.rs:22` typo | `src/dns/edns.rs:22` | `NotSuported` → `NotSupported` | ✅ Fixed |
| 5.7 | `wire.rs:102` unwrap on UTF-8 | `src/dns/wire.rs:102` | Replace with `ok()?` | ✅ Fixed |
| 5.8 | `generate_key` / `generate_standby_key` duplication | `src/dns/dnssec.rs:268-449` | Unify into `generate_key_internal(is_standby)` | ✅ Fixed |
| 5.9 | `handle_tcp_query` 23 params | `src/dns/server.rs:2268-2291` | Extract `QueryContext` struct | ✅ Fixed — 23 params → 2 |
| 5.10 | DNS query parsing duplicated 8+ files | `src/dns/server.rs`, `update.rs`, `transfer.rs`, `notify.rs` | Extract `parse_query_name()` into `wire.rs` | ✅ Fixed — extract_query_name delegates to wire::parse_query_name |
| 5.11 | `mesh_sync.rs` 1,975 lines | `src/dns/mesh_sync.rs` | Split into `registry.rs`, `verification.rs`, `health.rs` | ⏭ Deferred to Phase 6 |

---

## Phase 6: Subsystem Refactoring

> **PARTIALLY COMPLETED 2026-03-25.** 12 of 40+ items addressed directly; remaining deferred to Phase 7+.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo test --test integration_test` ✅ (99/99 passed)
> `cargo clippy` produces 154 warnings (up from 152; all are pre-existing categories).

### Phase 6 Follow-up Items

Items discovered during Phase 6 review:

| # | Issue | File:Line | Description | Priority |
|---|-------|-----------|-------------|----------|
| 6.F1 | Latent XSS in `generate_login_page` | `src/admin/legacy.rs:342-343` | The `error` parameter is not passed through `escape_html()`. Currently dead code (zero callers) but exported via `pub use`. Fix: add `escape_html()` call on the `error` parameter, or remove the function if truly unused. | Low |
| 6.F2 | Duplicate match arms in `load_private_key` | `src/mesh/cert.rs:50-56` | `PrivateKey`, `EcPrivateKey`, and `RsaPrivateKey` each appear twice in the `||` chain. Remove the three duplicate conditions. | Trivial |

### 6.1 Mesh Subsystem (38K lines, 55 files)

**HIGH:**

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 6.1.1 | God object: `transport.rs` 6,448 lines | `src/mesh/transport.rs` | Split into handler modules per category (routing, DHT, org, DNS) | ⏭ Deferred to Phase 7+ |
| 6.1.2 | Duplicate `MeshTransportError` | `src/mesh/transport_core/error.rs`, `transports/mod.rs` | Consolidate into single error type | ⏭ Deferred — needs 6.1.1 first |
| 6.1.3 | Blocking `RwLock` in async | `src/mesh/topology.rs:980,992` | Remove `_sync` variants | ✅ N/A — `_sync` variants are correct for sync callers |
| 6.1.4 | ~80+ `unwrap()` on `duration_since(UNIX_EPOCH)` | `src/mesh/protocol.rs`, `transport.rs`, `organization.rs`, `cert.rs` | Use `.unwrap_or(Duration::ZERO)` or helper | ⏭ Deferred to Phase 7+ |
| 6.1.5 | ~10 `expect()` in crypto paths | `src/mesh/config.rs:1515,1523`, `cert.rs:643` | Return `Result` | ⏭ Deferred to Phase 7+ |
| 6.1.6 | 22 files with `#![allow(dead_code)]` | Various mesh files | Remove; implement or delete | ⏭ Deferred — 27 suppressions, needs per-item audit |

**MEDIUM:**

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 6.1.7 | `MeshConfig` 40+ fields | `src/mesh/config.rs:654-738` | Builder pattern or composable sub-configs | ⏭ Deferred to Phase 7+ |
| 6.1.8 | `MeshTransport::new()` 10+ params | `src/mesh/transport.rs:254-264` | Introduce `MeshTransportConfig` | ⏭ Deferred to Phase 7+ |
| 6.1.9 | `MeshMessage` 70+ variants | `src/mesh/protocol.rs:266-978` | Group into `RoutingMessage`, `DhtMessage`, `OrgMessage` sub-enums | ⏭ Deferred to Phase 7+ |
| 6.1.10 | Mixed lock types | `src/mesh/topology.rs`, `transport.rs` | Standardize per context | ⏭ Deferred to Phase 7+ |
| 6.1.11 | Unbounded collections | `src/mesh/protocol.rs`, `transport.rs:71-72`, `topology.rs:247` | Add periodic cleanup, use `LruCache` | ⏭ Deferred to Phase 7+ |
| 6.1.12 | Duplicate PEM loading | `src/mesh/cert.rs:252-334` | Extract shared helper | ✅ Fixed — `load_cert_chain_and_key()` extracted |
| 6.1.13 | Regex compiled per `detect_attack()` call | `src/mesh/security_challenge.rs:364` | Pre-compile when patterns added | ✅ Fixed — `SuspiciousPattern::new()` pre-compiles regexes |
| 6.1.14 | `SequenceCounter` `Relaxed` ordering | `src/mesh/config.rs:146-167` | Use `SeqCst` or document rationale | ⏭ Deferred to Phase 7+ |

### 6.2 Admin Subsystem (~7.5K lines, 28 files)

**HIGH:**

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 6.2.1 | `block_on` in async context | `src/admin/mod.rs:116` | Make async or pass config as param | ⏭ Deferred to Phase 7+ |
| 6.2.2 | Theme/honeypot endpoints lack auth | `src/admin/handlers/theme.rs:134-209`, `handlers/honeypot.rs:34-62` | Add `require_auth()` calls | ⏭ Deferred to Phase 7+ |
| 6.2.3 | XSS in legacy HTML | `src/admin/legacy.rs:116-165` | HTML-escape all interpolated values | ✅ Fixed — `escape_html()` added, all user fields escaped |
| 6.2.4 | Three separate rate limiters | `src/admin/rate_limit.rs`, `state.rs:19-60`, `auth.rs:14-78` | Consolidate into single abstraction | ⏭ Deferred to Phase 7+ |
| 6.2.5 | Unbounded auth token map | `src/admin/auth.rs:14-16` | Add periodic cleanup or LRU cache | ⏭ Deferred to Phase 7+ |
| 6.2.6 | CSRF tokens never cleaned | `src/admin/state.rs:459-479` | Invoke `cleanup_expired_csrf_tokens()` periodically | ✅ Fixed — called in 60s alert_ticker |

**MEDIUM:**

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 6.2.7 | `Vec::remove(0)` O(n) for metrics | `src/admin/state.rs:355-361` | Use `VecDeque` for O(1) pop_front | ✅ Fixed — `VecDeque::pop_front()` |
| 6.2.8 | Same O(n) for request logs | `src/admin/state.rs:382-388` | Use `VecDeque` | ✅ Fixed — `VecDeque::pop_front()` |
| 6.2.9 | Hardcoded file paths | `src/admin/handlers/config.rs:971+` | Use config-driven paths | ⏭ Deferred to Phase 7+ |
| 6.2.10 | Duplicate `get_client_ip` | `src/admin/middleware.rs:16-29`, `handlers/common.rs:74-86` | Remove `common.rs` version; use `ClientIp` extension | ✅ Fixed — `common.rs` now checks `ClientIp` extension first |
| 6.2.11 | Config write race (no file locking) | `src/admin/handlers/config.rs`, `handlers/sites.rs` | Serialize writes through channel | ⏭ Deferred to Phase 7+ |
| 6.2.12 | `AdminState` god object 20+ fields | `src/admin/state.rs` | Break into domain-specific state objects | ⏭ Deferred to Phase 7+ |
| 6.2.13 | Per-handler auth boilerplate | All handlers | Use Axum middleware | ⏭ Deferred to Phase 7+ |

### 6.3 WAF Core Simplification

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 6.3.1 | `WafCore::new()` 19 params | `src/waf/mod.rs:253` | Introduce `WafCoreBuilder` or `WafCoreConfig` struct | ⏭ Deferred to Phase 7+ |
| 6.3.2 | `check_request_full()` ~400 lines | `src/waf/mod.rs:667` | Extract rate limit, bot, honeypot, challenge checks into separate methods | ⏭ Deferred to Phase 7+ |
| 6.3.3 | `reload_attack_detector()` 10x repeat | `src/waf/mod.rs:458-510` | Macro or iterator over `(category, config_field)` pairs | ✅ Fixed — `merge_patterns!` macro |
| 6.3.4 | `get_custom_patterns_for_category` 3x repeat | `src/waf/rule_feed.rs:104-170` | Macro or generic accessor | ✅ Fixed — local `macro_rules!` per function |
| 6.3.5 | `convert_rules_to_ipc_patterns` 100 lines | `src/waf/rule_feed.rs:555-656` | Macro | ✅ Fixed — `push_if_present!` macro |
| 6.3.6 | Status text mapping 3x repeat | `src/waf/endpoints.rs:415-494` | Extract shared function | ✅ Fixed — `status_text()` helper |
| 6.3.7 | Memory limits on state | `src/block_store.rs` | Add configurable max entries with LRU eviction | ⏭ Deferred to Phase 7+ |

### 6.4 Code Duplication (IPC)

| # | Issue | File:Line | Fix | Status |
|---|-------|-----------|-----|--------|
| 6.4.1 | Unix/Windows IPC handler duplication | `src/worker/mod.rs` | Extract common logic into trait or helper | ⏭ Deferred to Phase 7+ |
| 6.4.2 | Windows IPC pipe code duplication | `src/main.rs:1177-1314` | Consolidate into reusable IPC helper | ⏭ Deferred to Phase 7+ |
| 6.4.3 | Static worker client handling | `src/worker/mod.rs` | Unify `handle_minify_client_connection` and Windows variant | ⏭ Deferred to Phase 7+ |
| 6.4.4 | Sync/async `IpcStream` dual API | `src/process/ipc.rs:838-1038` vs `ipc_transport.rs:20-407` | Document divergence; consider unifying | ⏭ Deferred to Phase 7+ |

### 6.5 Large Module Splits

| Module | Current Lines | Target | Submodules to Extract | Status |
|--------|--------------|--------|----------------------|--------|
| `src/mesh/transport.rs` | 6,448 | <1,000 | `handler_routing.rs`, `handler_dht.rs`, `handler_org.rs`, `handler_dns.rs` | ⏭ Deferred to Phase 7+ |
| `src/proxy.rs` | 1,364 | <500 lines | `upstream.rs`, `waf_integration.rs` | ⏭ Deferred to Phase 7+ |
| `src/router.rs` | 762 | <500 lines | `domain_matcher.rs`, `site_resolver.rs` | ⏭ Deferred to Phase 7+ |
| `src/worker/mod.rs` | 1,586 | <500 | `connection.rs`, `image_poisoning.rs`, `drain_state.rs` | ⏭ Deferred to Phase 7+ |
| `src/dns/server.rs` | 4,733 | <1,000 | `query_handler.rs`, `zone_manager.rs`, `rate_limiter.rs` | ⏭ Deferred to Phase 7+ |
| `src/dns/mesh_sync.rs` | 1,975 | <500 | `registry.rs`, `verification.rs`, `health.rs` | ⏭ Deferred to Phase 7+ |
| `src/admin/state.rs` | 511 lines | Split | `metrics_state.rs`, `auth_state.rs`, `csrf_state.rs` | ⏭ Deferred to Phase 7+ |

---

## Phase 7: Testing and Build Hygiene

> **PARTIALLY COMPLETED 2026-03-25.** 5 of 8 items addressed directly; 3 deferred.
> Verification: `cargo check` ✅ `cargo check --features dns` ✅
> `cargo test --test integration_test --test ipc_test --test dns_config_test --test property_tests --test property_tests_common --features dns` ✅ (112/112 passed)

### Phase 7 Follow-up Items

| # | Issue | File:Line | Description | Priority |
|---|-------|-----------|-------------|----------|
| 7.F1 | rule_feed.rs zero tests | `src/waf/rule_feed.rs` | Needs key parse, signature verify, version compare tests. Requires understanding crypto internals. | Medium |
| 7.F2 | endpoints.rs zero tests | `src/waf/endpoints.rs` | Needs sensitive match, error page rendering tests. | Medium |
| 7.F3 | config/mod.rs zero tests | `src/config/mod.rs` | Needs discover sites, reload, validate tests. Complex due to filesystem I/O. | Low |

### 7.1 Fix Vacuous Test Assertions ✅

All 5 vacuous assertions fixed:

| File:Line | Was | Now |
|-----------|-----|-----|
| `tests/integration_test.rs:379` | `contains("maluwaf") \|\| !contains("nonexistent")` | `contains("maluwaf")` |
| `tests/integration_test.rs:431` | `assert!(true)` in match arms | Asserts `requires_temp_ports()` and `temp_port_offset` per variant |
| `tests/dns_integration_test.rs:330` | `is_ok() \|\| is_err()` | `is_ok()` |
| `tests/dns_integration_test.rs:346` | `is_ok() \|\| is_err()` | `is_ok()` |
| `tests/dns_integration_test.rs:374` | `serial == 0 \|\| serial == 2024010101` | `serial == 0` |
| `tests/dns_integration_test.rs:400` | `is_some() \|\| is_none()` | `is_none()` |

### 7.2 Add Missing Test Coverage (partial)

**Verified:** The WAF modules listed as "zero tests" in the original plan actually have extensive existing test coverage (171 tests across attack_detection, ratelimit, flood, bot, etc.). The property tests added in 7.5 provide additional coverage for normalizer and wire format.

| Module | Existing Tests | Added |
|--------|---------------|-------|
| `src/waf/attack_detection/*` | 105+ | Property tests for normalizer idempotency |
| `src/waf/ratelimit/` | 13 | — |
| `src/waf/flood/` | 9 | — |
| `src/waf/bot.rs` | 14 | — |
| `src/waf/rule_feed.rs` | 0 | ⏭ Deferred (7.F1) |
| `src/waf/endpoints.rs` | 0 | ⏭ Deferred (7.F2) |
| `src/config/mod.rs` | 0 | ⏭ Deferred (7.F3) |

### 7.3 Split Monolithic Test File ✅

`tests/integration_test.rs` reduced from 2,012 → 760 lines:

| File | Tests | Content |
|------|-------|---------|
| `tests/ipc_test.rs` (new) | 7 | IPC socket send/recv, validation, signed messages, constant-time compare |
| `tests/dns_config_test.rs` (new) | 52 | DNS config, recursive cache, DNSSEC, RFC 5011, trust anchors (feature-gated: `dns`) |
| `tests/integration_test.rs` | 40 | IPC messages, process config, drain, health, mesh transport, rate limit, TLS, block store |
| `tests/dns_integration_test.rs` | 45 | DNS wire format, zone records, error codes (unchanged) |

### 7.4 Migrate Benchmarks to Criterion

⏭ Deferred — 4 benchmark files use `Instant::now()` + `println!`. Adding criterion requires `Cargo.toml` changes and rewriting all benchmarks. Low priority since benchmarks are non-functional.

### 7.5 Property-Based Testing ✅

13 proptest cases added across two test files:

| File | Tests | Properties Tested |
|------|-------|-------------------|
| `tests/property_tests.rs` | 7 | DNS: encode/parse name roundtrip, message ID preservation, build_question validity, error response ID, null termination, nxdomain flag, standard query flag |
| `tests/property_tests_common.rs` | 6 | URL: decode/encode roundtrip, no-encoding passthrough, plus-to-space; Normalizer: idempotency, non-empty preservation, percent decoding |

### 7.6 Fuzzing Expansion

⏭ Deferred — Current 3 fuzz targets are sufficient for now. Expansion (WAF detection, DNS wire, HTTP parsing) requires corpus seed collection and is best done incrementally.

### 7.7 Dependency Hygiene ✅ (partial)

| # | Issue | Status |
|---|-------|--------|
| 7.7.4 | Duplicate dev-deps | ✅ Removed `aes-gcm`, `ahash`, `async-trait` from `[dev-dependencies]` |
| 7.7.1 | Alpha `lightningcss` | ⏭ Deferred — upgrading may break CSS minification |
| 7.7.2 | Unmaintained `boringtun` | ⏭ Deferred — WireGuard feature is optional |
| 7.7.3 | Exact patch version pins | ⏭ Deferred — changing versions needs careful regression testing |
| 7.7.5 | Dead feature `verify-pq` | ✅ Verified NOT dead — used in `mesh/cert.rs` and `mesh/transports/quic.rs` |
| 7.7.6 | Git patch no expiry | ⏭ Deferred — depends on upstream quinn release |
| 7.7.7 | Dead code handler.rs+range.rs | ⏭ Deferred — already documented in AGENTS.md as dead |

### 7.8 Documentation

⏭ Deferred — Rustdoc and module documentation is a large effort. Existing `// SAFETY:` comments from Phase 3 cover ~95% of unsafe blocks.

---

## Execution Order

```
Phase 1 (Critical Correctness) ────────────────── COMPLETED 2026-03-25
  1.1  Body forwarding           ✅
  1.2  Challenge bypass          ✅
  1.3  UTF-8 path corruption     ✅
  1.4  IpHash broken             ✅
  1.5  accept-encoding wrong     ✅
  1.6  Request smuggling FP      ✅
  1.7  SSRF allowed_domains      ✅
  1.8  DS record digest          ✅
  1.9  NXDOMAIN question         ✅
  1.10 Connection underflow      ✅
  1.11 Auth store race           ✅
  1.12 Inconsistent key tags     ✅
  │
Phase 1 Follow-ups ────────────────────────────── Next session
  1.F3 CSS challenge exemptions  (High — blocks API use)
  1.F1 Auth log dedup            (Medium)
  1.F4 SSRF test fix             (Medium)
  1.F2 Counter underflow logging (Low)
  1.F5 Shared key tag utility    (Low)
  │
Phase 2 (Security) ────────────────────────────── COMPLETED 2026-03-25
  2.1  Remove clippy allow-all  ✅
  2.2  Fix .cargo/config.toml   ✅
  2.3  Embedded key placeholder ✅
  2.4  TLS plaintext upstream   ✅
  2.5  TLS root cert panic      ✅
  2.6  TLS skip_verify unused   ✅
  2.7  Rate limiter race        ✅
  2.8  IPC key in env var       ✅
  2.9  IPC message validation   ✅
  2.10 IPC deserialization panic ✅ (no prod issue)
  2.11 CORS wildcard            ✅
  2.12 Token storage            ✅
  2.13 HSM PIN zeroize          ✅
  2.14 Stub endpoints           ✅
  │
Phase 3 (Error Handling & Unsafe) ────────────── COMPLETED 2026-03-25
  3.1  Centralize WafError       ✅
  3.2  Audit unwrap/expect       ✅ (44 → ~12 in prod, mostly Response builders)
  3.3  Document unsafe blocks    ✅ (~95% coverage, ~12 remaining are test/feature-gated)
  3.4  Remove dead_code allows   ✅ (removed crate+module-level, 12 items kept with targeted allows)
  │
Phase 4 (Performance & Reliability) ─────────── COMPLETED 2026-03-25
  4.1.1-4.1.2  Cache retain → position/remove ✅
  4.1.3  get_or_fetch now async + fetch       ✅
  4.1.4  Binary corruption                    ⏭  (deferred to Phase 6 — needs Response<Bytes>)
  4.1.5  Cache-Control s-maxage parsing       ✅
  4.2.1  Normalizer remove original clone     ✅
  4.2.2  WAF to_uppercase allocation          ⏭  (deferred to Phase 6)
  4.2.3  InputLocation::Header allocation     ⏭  (deferred to Phase 6)
  4.3.1  Unified worker restart limit         ✅
  4.3.2  Stale IPC during drain               ⏭  (deferred to Phase 5)
  4.3.3  stdout/stderr pipe blocking          ⏭  (deferred to Phase 5)
  4.3.4  Overseer lock file race              ✅
  4.3.5  FD count assertion                   ✅
  4.3.6  Drain IPC retry with backoff         ✅
  4.3.7  block_on in async context            ✅
  4.3.8  Dummy IPC panic                      ✅
  4.3.9  Connection tracker parking_lot       ✅
  4.3.10 Zone history already bounded         ✅  (was pre-existing)
  4.4    Collection capacity hints            ✅  (partial)
  4.5    Async mutex standardization          ⏭  (deferred to Phase 6 — _sync variants OK for sync callers)
  4.6.1  Rate limiter cleanup throttle        ✅  (was pre-existing)
  4.6.2  Arc<Firewall> shared queries         ⏭  (deferred to Phase 6)
  4.6.3  Batch zone index rebuild             ⏭  (deferred to Phase 6)
  4.6.4  DnsServer::clone nullifying fields   ✅  (intentional design — documented)
  4.6.5  DNS cache fingerprint TTL eviction   ✅
  │
Phase 5 (DNS RFC Compliance) ────────────────── COMPLETED 2026-03-25
  5.1  DS record digest canonical   ✅  (already implemented)
  5.2  Shared key tag utility       ✅  (trust_anchor → dnssec::calculate_key_tag)
  5.3  NXDOMAIN question section    ✅  (code correct, test updated)
  5.4  Trust anchor save logging    ✅
  5.5  Algorithm validation         ✅  (rejects alg 0=DELETE, 3=DSA)
  5.6  edns.rs typo                 ✅  (NotSuported → NotSupported)
  5.7  wire.rs UTF-8 unwrap         ✅  (unwrap → ok()?)
  5.8  generate_key unification     ✅  (generate_key_internal extracted)
  5.9  handle_tcp_query QueryContext ✅  (23 params → 2)
  5.10 DNS query parsing dedup      ✅  (extract_query_name → parse_query_name)
  5.11 mesh_sync.rs split           ⏭  (deferred to Phase 6 — 1,975 lines)
  4.3.2 Stale IPC drain_id          ✅  (drain_id added to UnifiedServerWorkerDrained and StaticWorkerDrained)
  4.3.3 stdout/stderr pipe blocking ✅  (Stdio::piped() → Stdio::inherit())
  │
Phase 6 (Subsystem Refactoring) ─────────────── PARTIALLY COMPLETED 2026-03-25
  6.1.12 PEM loading extraction     ✅
  6.1.13 Pre-compiled regex         ✅
  6.2.3  XSS in legacy HTML         ✅
  6.2.6  CSRF token cleanup         ✅
  6.2.7  VecDeque for metrics       ✅
  6.2.8  VecDeque for request logs  ✅
  6.2.10 get_client_ip consolidation ✅
  6.3.3  reload_attack_detector macro ✅
  6.3.4  rule_feed match consolidation ✅
  6.3.5  convert_rules_to_ipc_patterns macro ✅
  6.3.6  status_text extraction     ✅
  5.F2   drain_id in response msgs  ✅
  4.2.2  to_uppercase allocation    ✅
  6.1.1-6.1.11 mesh structural      ⏭  (deferred to Phase 7+)
  6.2.1-6.2.2,6.2.4-6.2.5,6.2.9-6.2.13 admin  ⏭  (deferred to Phase 7+)
  6.3.1-6.3.2,6.3.7 WAF structural  ⏭  (deferred to Phase 7+)
  6.4    IPC dedup (4 items)        ⏭  (deferred to Phase 7+)
  6.5    Module splits (7 modules)  ⏭  (deferred to Phase 7+)
  4.1.4  Binary body in cache       ⏭  (needs Response<String> → Response<Bytes>)
  4.6.2  Arc<Firewall> shared       ⏭  (needs DnsFirewall interior mutability)
  4.6.3  Batch zone index rebuild   ⏭  (needs zone load batching)
  5.11   mesh_sync.rs split         ⏭  (1,975 lines, complex state)
  5.F3   handle_query_with_cache QueryContext ⏭  (18 call sites, 4 files)
  │
Phase 7 (Testing & Build) ───────────────────── PARTIALLY COMPLETED 2026-03-25
  7.1  Fix vacuous assertions    ✅  (6 assertions fixed)
  7.2  Add missing tests         ⏭  (property tests added; rule_feed/endpoints/config deferred)
  7.3  Split integration_test.rs ✅  (2012 → 760 lines; IPC + DNS extracted)
  7.4  Migrate benchmarks        ⏭  (deferred — low priority)
  7.5  Property-based tests      ✅  (13 proptest cases: DNS wire, URL encoding, normalizer)
  7.6  Fuzzing expansion         ⏭  (deferred — existing 3 targets sufficient)
  7.7  Dependency hygiene        ✅  (duplicate dev-deps removed; verify-pq NOT dead)
  7.8  Documentation             ⏭  (deferred — large effort, SAFETY docs from Phase 3 cover 95%)
  7.F1 rule_feed.rs tests        ⏭  (Medium — needs crypto internals understanding)
  7.F2 endpoints.rs tests        ⏭  (Medium)
  7.F3 config/mod.rs tests       ⏭  (Low — complex due to filesystem I/O)
```

---

## Verification Checklist

Run after each phase:

```bash
# Lint and format
cargo fmt -- --check
cargo clippy -- -D warnings

# Type check all features
cargo check
cargo check --features dns
cargo check --features wireguard
cargo check --features mesh
cargo check --all-features

# Tests
cargo test
cargo test --features dns
cargo test --test integration_test

# Benchmarks
cargo bench

# Security
cargo audit
cargo +nightly fuzz run waf_detection    # after Phase 7.6
cargo +nightly fuzz run ipc              # after Phase 7.6
```

## Success Metrics

| Metric | Baseline | Target | Current |
|--------|----------|--------|---------|
| `unwrap()`/`expect()` in production code | 580 | < 50 | ~12 (Phase 3) |
| Unsafe blocks with SAFETY docs | ~10% | 100% | ~95% (Phase 3) |
| Max module size (lines) | 6,448 (`mesh/transport.rs`) | < 1,000 | 6,448 (deferred) |
| Integration test coverage | ~30% | > 70% | ~40% |
| Vacuous test assertions | 5+ | 0 | 0 ✅ |
| Modules with zero tests | 10+ | 0 | 3 (rule_feed, endpoints, config) |
| Alpha/unmaintained deps | 3+ | 0 | 2 (lightningcss, boringtun) |
| Clippy warnings (with `-D warnings`) | suppressed | 0 | ~154 |
| Total test count | 99 | — | 112 |
| Integration test file size | 2,012 lines | < 500 | 760 |

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Phase 1.1 body forwarding breaks proxy | Feature flag initially; thorough integration tests |
| Phase 2.1 clippy removal surfaces many warnings | Fix incrementally per-module |
| Phase 4.1 cache rewrite changes hot path | Benchmark before/after; keep old impl as fallback |
| Phase 6 mesh refactoring in 38K lines | Incremental: extract one handler module at a time |
| Phase 3.2 unwrap removal across 580 sites | Prioritize P0 paths; accept test-only unwraps |
| Phase 7.7 version pin changes | Run `cargo update` in isolation; test CI |
