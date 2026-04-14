# AGENTS.md - Developer Guide for AI Agents

This document provides guidance for AI agents working on the MaluWAF codebase.

## Project Overview

MaluWAF is a WAF (Web Application Firewall) with a multi-process architecture:
- **Overseer** (`src/overseer/`): Manages master process lifecycle, upgrades, health monitoring
- **Master** (`src/master/`): Parent process that spawns/manages workers, handles IPC
- **Worker** (`src/worker/`): Handles HTTP requests and communicates via IPC

## Running Tests

### Quick Test Commands

```bash
# Run integration tests only (fast, ~5 seconds)
cargo test --test integration_test

# Run without DNS feature (default)
cargo test

# Run with specific feature
cargo test --features dns

# Verify tests compile WITHOUT running them (important: cargo check does NOT compile test code)
cargo test --lib --no-run
```

### Test Categories

| Category | Command | Expected Time |
|----------|---------|---------------|
| Integration Tests | `cargo test --test integration_test` | ~5s |
| DNS Recursive Tests | `cargo test --test dns_recursive_test` | ~1s |
| DHT Integration Tests | `cargo test --test dht_integration_test` | ~1s |
| DNS Server Tests | `cargo test --test dns_server_test` | ~1s |
| E2E Process Tests | `cargo test --test e2e_process_test` | ~1s |
| IPC Tests | `cargo test --test ipc_test` | ~1s |
| All Tests (no DNS) | `cargo test` | ~3-5 min |
| DNS Feature Tests | `cargo test --features dns` | Varies |
| Unit Tests Only | `cargo test --lib` | ~3 min |
| Benchmarks | `cargo test --bench bench_*` | Varies |

### Common Issues

**Test Timeouts**: Full test suite can take 3+ minutes. Use targeted tests during development.

**`cargo check` vs test compilation**: `cargo check` does NOT compile `#[cfg(test)]` code. Always run `cargo test --lib --no-run` to verify test code compiles. Visibility errors in cross-module test access (e.g., sibling modules calling private methods) will only surface during test compilation.

## Codebase Structure

### Key Modules

- `src/process/` - IPC communication, process management
- `src/overseer/` - Master process orchestration
- `src/master/` - Parent process implementation  
- `src/worker/` - Worker process implementation
- `src/supervisor/` - Worker supervision
- `tests/` - Integration and benchmark tests

### Architecture Pattern

The overseer/master/worker architecture uses:
- Unix domain sockets for IPC
- `Message` enum in `src/process/ipc.rs` (re-exported via `src/process/mod.rs`) for communication
- `ProcessManager` for worker lifecycle
- Health checks via IPC heartbeat messages

## Adding Tests

### Integration Tests Location

Add tests to `tests/integration_test.rs` for architecture-level coverage:

```rust
#[test]
fn test_new_feature() {
    use maluwaf::module::Type;
    // Test implementation
}
```

### Unit Tests Location

Add `#[cfg(test)]` modules to source files:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_unit() {
        // Test implementation
    }
}
```

### IPC Socket Tests

When testing actual socket communication, use temporary directories:

```rust
use tempfile::TempDir;

#[test]
fn test_ipc_socket() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    // Test socket communication
}
```

## Lint and Format

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy -- -D warnings

# Check without building
cargo check
```

**`cargo fmt` prerequisites**: `src/platform/windows.rs` must exist (even as a stub) or `cargo fmt` will fail with "failed to resolve mod `windows`". The file exists as a stub gated by `#[cfg(windows)]`.

## Feature Flags

Key features that affect testing:
- `dns` - DNS server functionality (optional, conditionally compiled)
- `socket-handoff` - Socket transfer between processes
- `post-quantum` - Post-quantum cryptography
- `wireguard` - WireGuard VPN support
- Serverless functions use WASM (wasmtime), not Deno

## Common Patterns

### Testing IPC Messages

```rust
use maluwaf::process::Message;

// Serialize/deserialize
let msg = Message::WorkerStarted { id: 1, pid: 12345, .. };
let json = serde_json::to_string(&msg).unwrap();
let decoded: Message = serde_json::from_str(&json).unwrap();
```

### Testing Worker Lifecycle

```rust
use maluwaf::worker::drain_state::WorkerDrainState;

let state = WorkerDrainState::new();
state.start_drain(1);
assert!(state.is_draining());
```

### Testing Overseer Config

```rust
use maluwaf::overseer::process::OverseerConfig;

let config = OverseerConfig::default();
assert!(config.auto_restart);
```

### Testing Trust Anchor State Transitions

```rust
use maluwaf::dns::trust_anchor::{TrustAnchorManager, TrustAnchorConfig, Rfc5011Event};

// Create manager with custom timeouts
let config = TrustAnchorConfig {
    pending_observation_days: 30,
    revocation_grace_days: 30,
    extended_removal_days: 60,
    trust_anchor_retention_days: 7,
    ..TrustAnchorConfig::default()
};
let manager = TrustAnchorManager::new(config);

// Observe a new key
let event = manager.observe_dnskey_at_root(key_tag, algorithm, &public_key, false);
assert!(matches!(event, Rfc5011Event::NewKeySeen { .. }));

// Check trust anchor with CDS digest
let event = manager.trust_anchor_check(key_tag, algorithm, digest_type, &digest);
assert!(matches!(event, Rfc5011Event::KeyPending { .. }));

// Process RFC 5011 updates
let events = manager.process_rfc5011_updates();
```

### Dropped Event Metrics

Global counters for silently dropped channel send failures live in `src/metrics/mod.rs`. Pattern:

```rust
// 1. Add global static counter
static DROPPED_FOO_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

// 2. Add record/get functions
pub fn record_dropped_foo_event() {
    DROPPED_FOO_EVENTS.fetch_add(1, Ordering::Relaxed);
}
pub fn get_dropped_foo_events() -> u64 {
    DROPPED_FOO_EVENTS.load(Ordering::Relaxed)
}

// 3. Instrument call site
if sender.send(event).is_err() {
    crate::metrics::record_dropped_foo_event();
    tracing::warn!("Failed to send foo event");
}
```

Query via `get_dropped_event_counts() -> DroppedEventCounts` (per-category breakdown + total).

## File Naming Conventions

- Source files: `snake_case.rs`
- Test files: `snake_case_test.rs` or in `tests/` directory
- Modules: `mod.rs` for module aggregation

## DNSSEC and RFC 5011

### Trust Anchor Configuration

The `TrustAnchorConfig` struct supports separate timeout configuration for RFC 5011 state transitions:

| Field | Default | Purpose |
|-------|---------|---------|
| `pending_observation_days` | 30 | Time a new key spends in Pending state before becoming Valid (RFC 5011 Section 3.2) |
| `revocation_grace_days` | 30 | Time a revoked key spends before being Removed (RFC 5011 Section 4) |
| `extended_removal_days` | 60 | Time a removed key spends before being Purged from storage |
| `trust_anchor_retention_days` | 7 | Time a Valid key can be absent before being marked Missing |

### RFC 5011 State Machine

Keys transition through these states:
1. **Seen** - Key observed in DNSKEY RRset but not validated
2. **Pending** - Key validated via CDS/CDNSKEY digest, awaiting observation period
3. **Valid** - Key is trusted for DNSSEC validation
4. **Revoked** - Key has REVOKE bit set
5. **Removed** - Revoked key waiting for extended confirmation
6. **Missing** - Valid key not seen for retention period

## Important Notes

1. **Never commit secrets** - Use `.gitignore` for credentials
2. **Test isolation** - Use temp dirs for socket tests
3. **Async tests** - Use `#[tokio::test]` for async code
4. **Platform-specific tests** - Use `#[cfg(unix)]` or `#[cfg(windows)]`
5. **Key tag calculation** - Use `crate::dns::dnssec::calculate_key_tag` for RFC 4034 compliant key tags

## Subagent Execution Best Practices

When using subagents to make code changes:
1. **Always verify the actual code** — subagents may claim a fix was applied but the code still shows the old version. Always read the file directly to confirm.
2. **Run compilation checks** — `cargo clippy --lib -- -D warnings` to catch type errors
3. **Run tests** — `cargo test --test integration_test` to verify runtime behavior
4. **Run format check** — `cargo fmt` then `cargo fmt --check` to catch drift

**Critical verification step**: After any subagent reports completion:
```bash
# Check if file was actually modified
git diff HEAD -- <file>
# Or grep for the expected fix
rg "expected_pattern" <file>
```

Common failure mode: subagent reports success but code wasn't actually modified, or was modified incorrectly. This is especially common with:
- Complex refactoring requiring multi-file changes
- Architectural changes requiring wiring new components
- Proto file changes requiring code generation
- Cases where fix requires understanding existing code patterns

For complex changes, prefer direct implementation or verify each step incrementally.

### Module Splitting Decisions

- **Do NOT split cohesive request pipelines** like `http/server.rs` and `tls/server.rs` - these handle a single logical flow
- **Do NOT rewrite files from scratch** - incremental changes are safer
- **Prefer section comments** over refactoring for readability
- **Verify each subagent change compiles** before moving to the next

### Tonic Upgrade Gotchas

When upgrading tonic from 0.12 to 0.14:
- `tonic_build::configure()` API removed - use `tonic-prost-build` crate instead
- Add `tonic-prost` dependency for generated code codec
- Update `build.rs` to use `tonic_prost_build::configure()`

## Known Code Quality Context

### Clippy and Dead Code Suppressions

Crate-level suppressions in `src/lib.rs`:
- `elided_lifetimes_in_paths` — compiler style preference
- `mismatched_lifetime_syntaxes` — compiler style preference

`#[allow(dead_code)]` annotations: ~93 across ~50 files. Notable per-module breakdown:
- `src/mesh/transport_*.rs` — ~6 items (reserved protocol handlers)
- `src/mesh/` — ~14 items
- `src/dns/server/` — ~4 items
- `src/waf/` — ~4 items
- `src/tunnel/` — ~5 items
- `src/admin/handlers/` — ~6 items
- `src/overseer/` — ~9 items

Note: Many `#[allow(dead_code)]` annotations are on reserved/future-use code paths within already-shipped modules (e.g., `transport_dns.rs` for future DNS mesh protocol). These are intentional design patterns for future extensibility. All intentional suppressions documented with `// SAFETY_REASON: ...` comments.

`cargo clippy -- -D warnings` passes clean.

### Build Configuration

`Cargo.toml` uses relaxed version pins (e.g., `"0.11"`).

### Dependency Cleanup

The following dead dependencies were removed:
- `bincode` — never imported; `serialize_bincode`/`deserialize_bincode` shims use `postcard` internally
- `wasmtime-wasi` — unused (only `wasmtime` core needed)
- `ab_glyph`, `flare`, `memmap2` — zero imports anywhere
- `url` — transitive via axum; no direct imports
- `futures-util` — re-exported by `futures` crate
- `once_cell` — replaced with `std::sync::LazyLock` across 13 files
- `rustls-pemfile` — replaced with `rustls_pki_types::pem::PemObject`

Feature flags trimmed: `tower` removed `"timeout"`, `tower-http` removed `"trace"`.

**DNS dependencies are now optional** behind the `dns` feature: `hickory-proto`, `hickory-resolver`, `hickory-recursor`, `dns-parser`, `tokio-dstip`, `cryptoki`, `getrandom`.

**Note**: `nix` features `"net"` and `"uio"` are REQUIRED despite initial assessment they were unused. `platform/unix.rs` needs `"net"` for `SockaddrIn`/`SockaddrIn6` and `"uio"` for `ControlMessage`/`sendmsg`/`recvmsg`.

**Note**: `once_cell` and `bincode` still appear in `Cargo.lock` as transitive dependencies (via tracing-core, gloo-worker, etc.). This is expected.

### Error Handling Status

`src/error.rs` has been deleted. `WafError`, `WafResult`, and `WafErrorExt` no longer exist. Every module uses `anyhow`, `Box<dyn Error>`, or custom types.

### Duplicate Timestamp Utility

All duplicate `current_timestamp()` definitions have been consolidated into `src/utils.rs`. Use `crate::utils::current_timestamp()` as the canonical version.

## Known Bugs (Quick Reference)

### Remaining Open Issues

| Bug | Location | Impact | Status |
|-----|----------|--------|--------|
| — | — | — | — |

### Fixed Issues

| Bug | Location | Fix |
|-----|----------|-----|
| CSRF token timing attack | `src/auth/mod.rs`, `src/admin/state.rs` | Constant-time comparison with `subtle::ConstantTimeEq::ct_eq()` |
| DNS crypto RNG fallback zeros | `src/dns/crypto_rng.rs` | Functions return `Result<T, CryptoRngError>` instead of zero fallback |
| Mesh peer auth bypass | `src/mesh/peer_auth.rs` | Edge/Origin nodes require Ed25519 signature verification |
| Overseer IPC unsigned connections | `src/overseer/ipc_client.rs` | Use `connect_with_signer()` for HMAC-signed messages |
| HTTP honeypot standalone mode | `src/worker/unified_server.rs` | `set_threat_intel()` called in standalone mode |
| Port honeypot patterns not published | `src/honeypot_port/runner.rs` | Use `remote_ip` for attack pattern indicators |
| Threat indicators overwrite | `src/mesh/threat_intel.rs` | Composite keys `{threat_type}:{ip}` |
| Non-global DHT announce blocked | `src/mesh/dht/record_store_crud.rs` | Removed non-global node blocking check |
| Standalone threat sync missing | `src/mesh/threat_intel.rs` | `start_background_tasks()` called in standalone |
| WAF normalization inconsistency | `src/waf/attack_detection/xss.rs`, `sqli.rs` | Use `InputNormalizer` like pattern detectors |
| Private key permissions too open | `src/mesh/config_identity.rs` | Set 0o600 permissions after writing |
| PoW challenge window too large | `src/challenge/mod.rs` | Reduced timeout from 60s to 12s |
| Nonce cache unbounded | `src/process/ipc_signed.rs` | Added MAX_NONCE_CACHE_SIZE = 10000 |
| JA4 fingerprinting not passed to WAF | `src/tls/server.rs`, `src/waf/mod.rs` | JA4 now wired via `check_request_full()` |
| NSEC3 hash length encoding | `src/dns/dnssec_signing.rs:232` | Added `nsec3.push(next_hash.len() as u8)` per RFC 5155 Section 3.2 |
| Dead code cleanup (Wave 5) | `src/mesh/transport.rs`, `src/waf/ratelimit.rs` | Removed PendingQueryManager::complete/cleanup, get_global_rate_limit_status, get_shard |
| ConnectionMeta trait migration | `src/server/request_handler.rs:31-99` | Implemented for HttpConnection and HttpsConnection |
| SSRF domain substring check | `src/waf/attack_detection/ssrf.rs:243` | Uses proper word boundaries for localhost/.local checks |
| DNS dynamic update IP validation | `src/dns/update.rs` | Client IP validated against ACLs; require_tsig=true by default |
| TSIG verification message data | `src/dns/transfer.rs:262-281` | TSIG MAC computed over full DNS message, not just qname |
| WebSocket authentication | `src/admin/ws/mod.rs` | Bearer token validation required; 401 on failure |
| Upstream verification system | `src/mesh/transport_peer.rs:1639-1643` | `get_verification_manager()` returns actual manager |
| Verification response signatures | `src/mesh/transport_peer.rs:1575-1585` | Responses signed with global node signing key |
| TLS passthrough startup warning | `src/config/site/proxy.rs` | Added `tls_passthrough_warn_only` config and startup warning |
| 0-RTT disabled by default | `src/mesh/cert.rs` | Added `quic_enable_0rtt` config (default: false) |
| RFC 5011 state machine | `src/dns/trust_anchor.rs` | Fixed Missing→Valid and Pending→Valid bypasses |
| Mesh node identity verification | `src/mesh/dht/stake.rs` | `register_node()` now verifies caller identity |
| X-Forwarded-For trusted proxy | `src/admin/middleware.rs` | Only uses XFF when from trusted proxy; validates IP format |
| Rate limiter race condition | `src/admin/auth.rs` | Check-before-add pattern prevents burst past limit |
| AuthStore merge | `src/auth/mod.rs` | Merges users and sessions collections |
| CSRF session binding | `src/admin/state.rs` | CSRF tokens now validated against session ID |
| WAF URL decoding | `src/waf/attack_detection/*.rs` | SSTI, LDAP, XPath, Open Redirect, JWT detectors decode URLs |
| Private key zeroization | `src/mesh/cert.rs` | Uses `ZeroizeOnDrop` for private key storage |
| ACME ToS agreement | `src/tls/acme.rs` | `terms_of_service_agreed` now configurable |
| Multi-worker ACME coordination | `src/process/ipc.rs`, `src/process/manager.rs`, `src/master/ipc.rs`, `src/server/mod.rs`, `src/worker/unified_server.rs` | Workers run AcmeManager with IPC-based cert reload broadcast |
| `pattern_detector!` macro infinite recursion | `src/waf/attack_detection/detector_common.rs` | Fix applied to macro-generated impl |
| WAF empty headers in proxy path | `src/proxy.rs:486` | Pass actual request headers to check_request_full |
| Dynamic worker server stub | `src/worker/mod.rs` | Deprecated; unified server handles requests |
| Duplicate AppServer init | `src/worker/unified_server.rs` | Duplicate block removed |
| WireGuard transport unauthenticated | `src/mesh/transports/wireguard.rs` | WireGuard transport removed entirely |
| HTTPS proxy body forwarding | `src/tls/server.rs` | Pass `body_bytes` to upstream |
| YARA periodic sync | `src/worker/unified_server.rs` | Call `sync_manager.sync_from_dht()` (DHT-primary) |
| Granian dispatch | `src/app_server/granian.rs` | `forward_request()` uses built request |
| Honeypot mesh wiring | `src/worker/unified_server.rs` | `start_mesh_threat_publishing()` after mesh init |
| HTTP body truncation | `src/http/server.rs` | Separated `full_body` from `body_slice` |
| NODATA vs NXDOMAIN | `src/dns/server/query.rs` | Returns NOERROR with SOA when name exists but type doesn't |
| HTTP server.rs | - | Ergonomics improved with helper functions and RequestMetrics |
| Threat intel signature bypass | `src/mesh/threat_intel.rs:709-716` | Verification format now matches signing format |
| Tier key plaintext fallback | `src/mesh/transport_org.rs:249-261` | Tier keys only sent when ML-KEM session exists |
| Origin self-attestation bypass | `src/mesh/discovery.rs:425-430` | Origin nodes must use real global node attestation |
| Edge PoW key unbinding | `src/mesh/peer_auth.rs:191-196` | PoW public key must match identity public key |
| HTTP honeypot bypass | `src/http/server.rs:903-908` | `block_ip_with_threat_intel()` wired into honeypot handler |
| Upstream ownership verification | `src/mesh/transport.rs`, `src/http/server.rs:555-580` | Actual HTTP-01/DNS-01 challenge serving |
| Tier key encryption scope | `src/mesh/tier_key_encryption.rs` | Extended to all privileged record types |
| DHT key collision | `src/mesh/dht/keys.rs:36,159,287` | Composite keys `threat_indicator:{ip}:{threat_type}` |
| sync_from_dht key mismatch | `src/mesh/threat_intel.rs:1148-1149` | Store with full composite key format |
| SSRF allowlist bypass | `src/waf/attack_detection/ssrf.rs:267-294` | Word boundary checks instead of substring matching |
| Open redirect bypass | `src/waf/attack_detection/open_redirect.rs:114-133` | Newline and homograph attack protection |
| Transfer-Encoding bypass | `src/waf/attack_detection/request_smuggling.rs:12-40` | Proper comma-separated TE header parsing |
| JWT algorithm confusion | `src/waf/attack_detection/jwt.rs:125-186` | Proper JSON parsing with algorithm whitelist |
| Unicode normalization | `src/proxy.rs:10,144-236` | NFKC normalization in sanitize_request_path |
| Revocation bypass edge/origin | `src/mesh/peer_auth.rs:116-132,223-240` | Revocation checks added to edge/origin validation |
| DHT churn handling | `src/mesh/dht/routing/manager.rs` | ping_peers_loop() background task implemented |
| Bucket refresh never triggered | `src/mesh/dht/routing/manager.rs` | refresh_sparse_buckets() with FindNode requests |
| find_closest premature return | `src/mesh/dht/routing/table.rs:274` | Removed early break, scans all buckets |
| Edge resync single-homed | `src/mesh/transport_dht.rs:386-397` | Iterates all global nodes, not just [0] |
| Unused access control | `src/mesh/dht/record_store_crud.rs:79-90` | require_global_node() wired into store_record() |
| SuspiciousWordTracker write lock | `src/waf/probe_tracker.rs:475-513` | Pre-computed lowercased words at init; no to_lowercase() per request |
| EndpointBlocker O(n) linear search | `src/waf/endpoints.rs:135-193` | HashSet for O(1) exact match lookups |
| CSRF token unbounded storage | `src/admin/state.rs:633-657` | MAX_CSRF_TOKENS_PER_SESSION=10 limits tokens per session |
| DHT pending_announces O(n) | `src/mesh/dht/record_store.rs:208` | VecDeque for O(1) pop_front() instead of Vec remove(0) |
| Proxy cache SWR redundant lock | `src/proxy_cache/store.rs:240-255` | Entry API returns directly; no insert+get pattern |
| WAF double normalization | `src/waf/attack_detection/sqli.rs`, `xss.rs` | Detectors accept optional normalizer; callers pass shared Arc |
| Heartbeat N+1 lock contention | `src/worker/unified_server.rs:1087-1098` | Collect health data first, then batch send with single lock |
| DHT routing JoinHandle leak | `src/mesh/dht/routing/manager.rs` | Added shutdown_tx and shutdown() method |
| Worker unified server JoinHandle leak | `src/worker/unified_server.rs` | Added task_handles; tasks aborted on shutdown |
| Proxy cache JoinHandle leak | `src/proxy_cache/store.rs` | Added cleanup_shutdown_tx and shutdown() method |
| PHP-FPM open_basedir bypass | `src/php/mod.rs` | open_basedir now uses PHP_ADMIN_VALUE |
| PHP-FPM location-level security | `src/config/site/backend.rs` | Security options (disable_functions, open_basedir, etc.) now per-location |
| Static files per-location theme | `src/config/site/static_files.rs` | Theme can now be set per static location |
| Process manager JoinHandle leak | `src/process/manager.rs` | Health monitor handle stored and aborted on shutdown |
| Probe tracker unbounded events | `src/waf/probe_tracker.rs` | MAX_EVENTS_PER_IP sliding window with 1000 limit |
| Metrics Vec O(n) front removal | `src/metrics/mod.rs:61,77` | DHT_QUERY_LATENCIES and DHT_PROPAGATION_HOPS use VecDeque |
| Upstream client cache bounded | `src/http_client/mod.rs` | Replaced DashMap with moka::sync::Cache (max 100, TTL 300s) |
| Verified upstream cache TTL | `src/mesh/topology.rs:58` | TTL increased from 30s to 300s |
| TLS passthrough WAF bypass | `src/worker/unified_server.rs` | Added tls_passthrough_enforce_waf config and metrics |
| Connection limiter slot collisions | `src/waf/flood/connection_limiter.rs` | Increased CONNECTION_TRACKER_SLOTS from 65536 to 262144 |
| Revocation list not passed in discovery | `src/mesh/discovery.rs:439` | Now passes revocation list to validate_peer_role |
| SSTI HTML entity bypass | `src/waf/attack_detection/ssti.rs` | Replaced url_decode_all with InputNormalizer |
| SSRF subdomain spoofing bypass | `src/waf/attack_detection/ssrf.rs` | Added matches_localhost_lookalike function |
| Weak TLS cipher suites warning | `src/tls/cert_resolver.rs` | Enhanced warning messages for CBC/BEAST |
| Genesis key empty list permits any | `src/mesh/config_identity.rs:238` | Now denies by default with warning |
| Rate limiting race condition | `src/admin/auth.rs:35` | Atomic check-after-add pattern |
| Cache invalidation O(n) full scan | `src/proxy_cache/store.rs:451` | Secondary index for O(1) host lookups |
| IPC double-poll delay | `src/worker/mod.rs:295` | Removed redundant sleep(50ms) |
| Mesh broadcast unbounded spawns | `src/worker/unified_server.rs:729` | Semaphore with max 10 concurrent broadcasts |
| Serial HTTP proxy streams | `src/mesh/proxy.rs:785` | Concurrent provider requests, first-success-wins |
| Route usage tracker unbounded | `src/mesh/topology.rs:1528` | Added start_background_tasks() for cleanup |
| NONCE_CACHE O(n) eviction | `src/process/ipc_signed.rs:40` | HashMap + BTreeMap for O(log n) |
| Connection tracker non-atomic | `src/overseer/connection_tracker.rs:79` | Atomic delta updates |
| MockIpcStream dead code | `src/master/ipc.rs:16` | Removed |
| Metrics per_site unbounded | `src/metrics/mod.rs:900` | MAX_PER_SITE_ENTRIES = 10000 |
| Threat intel indicators unbounded | `src/mesh/threat_intel.rs:153` | VecDeque with MAX_PENDING_INDICATORS = 10000 |
| YARA submissions unbounded | `src/mesh/yara_rules.rs:235` | cleanup_expired_submissions() with TTL |
| Honeypot metrics | `src/metrics/mod.rs` | HONEYPOT_HTTP_TRAPS_HIT, PORT_HONEYPOT_CONNECTIONS_CAPTURED |
| Silent DHT publish standalone | `src/mesh/threat_intel.rs:626` | tracing::warn once per session |
| Eclipse attack warning | `src/mesh/dht/routing/manager.rs` | Warning when bootstrapping with <3 seeds |
| PoW difficulty increased | `src/mesh/dht/routing/node_id.rs:7` | NODE_ID_POW_DIFFICULTY from 32 to 40 bits |
| WASM configurable defaults | `src/config/serverless.rs` | default_memory_mb, default_cpu_fuel, default_timeout_seconds |
| Granian socket path isolation | `src/app_server/granian.rs` | UUID in socket path |
| Threat intel key format | `src/mesh/threat_intel.rs:25-27,379,451,517,581,978,1077` | `make_indicator_key()` standardizes composite keys |
| Threat intel O(n) iteration | `src/mesh/dht/record_store_crud.rs:383-396` | `get_by_prefix()` instead of get_all_records |
| Peer score decay wired | `src/mesh/threat_intel.rs:1590` | `apply_periodic_decay()` called in background loop |
| TOFU expiry reduced | `src/mesh/cert.rs:81-82` | MAX_TOOF_FINGERPRINT_AGE_DAYS from 90 to 30 |

## Performance Hot Paths

**Architecture Note - Worker Process Scaling:**

The unified worker uses a single `tokio` async event loop which is far more efficient than spawning multiple worker processes:
- **Single async process**: A single `UnifiedServer` with one tokio runtime handles thousands of sites concurrently via cooperative scheduling
- **Internal parallelism**: Use `tokio::spawn()` and async concurrency primitives (semaphores, channels) within the worker, NOT process-level parallelism
- **Why NOT multi-process scaling**: Multiple worker processes compete for CPU cores, increase context switching, and add IPC overhead
- **TcpListenerPool**: The worker uses an internal thread pool (`worker_pool_size: 4`) for accepting connections, but this runs within the single async context

**Do NOT increase `unified_server_workers` for scaling purposes.** Instead, tune `tcp.worker_pool_size` or use async primitives within the existing event loop.

**Architecture Note - WAF Sequential Checks:**

WAF checks run sequentially, not in parallel. This is intentional:
- **Attack blocking**: Some checks should block subsequent checks when an attack is detected (e.g., SQL injection found → don't waste time on XSS checks)
- **Fast checks**: WAF checks are fast hash lookups and string comparisons, not I/O-bound
- **No lifetime issues**: Parallelizing with `tokio::spawn` would require `'static` lifetimes for closures, complicating the architecture

Agents modifying these areas should be aware of performance characteristics:

| Area | Concern | Location |
|------|---------|----------|
| WAF detection | Runs ~20+ checks per request, lock acquisition per request | `src/waf/mod.rs:660-700` |
| Cache lookups | O(1) via `moka::Cache`; eviction-based cleanup | `src/proxy_cache/store.rs` |
| Input normalization | Pre-computed lowercased words at init | `src/waf/probe_tracker.rs:475` |
| Rate limiting | Lock-free atomic bitset for slot tracking | `src/waf/ratelimit/core.rs` |
| HTTP path sanitization | Not called in request path | `src/proxy.rs:139` |
| Response header filtering | Vec allocation on every proxied response | `src/proxy.rs:244-256` |
| SSRF detection | `Cow<str>` optimization to avoid repeated lowercasing | `src/waf/attack_detection/ssrf.rs` |
| DNS zone store | 64-sharded `RwLock`; prefer single-shard ops over full iteration | `src/dns/server/sharded_store.rs` |

## Module Size Guide

| Module | Lines | Status |
|--------|-------|--------|
| `src/mesh/transport.rs` | ~2,609 | Already split into 9 submodules |
| `src/mesh/protocol_proto_encode.rs` | ~2,024 | Generated protobuf pattern — acceptable |
| `src/http/server.rs` | ~3,238 | **Exception**: Cohesive request pipeline with section comments |
| `src/tls/server.rs` | ~1,747 | **Exception**: Mirrors http/server.rs, same reasoning |
| `src/mesh/config.rs` | ~1,545 | Already fragmented with sibling files |
| `src/mesh/topology.rs` | ~1,516 | Already split with types.rs |
| `src/mesh/protocol.rs` | ~1,196 | Split into submodules |
| `src/dns/server/mod.rs` | ~763 | Split into submodules |
| `src/worker/mod.rs` | ~786 | Split into submodules |
| `src/admin/state.rs` | ~561 | Split into submodules |

**Note on large files**: `http/server.rs` and `tls/server.rs` are exceptions to the size guidelines. They contain cohesive request handling pipelines where splitting would introduce risk without meaningful benefit. Section comments delineate the 15 distinct phases within `handle_request()`.

## Key Implementation Details

### Atomic Counter Safety

When decrementing atomic counters, use `fetch_update` with `checked_sub` to prevent underflow:

```rust
// BEFORE (wraps on underflow)
self.current_connections.fetch_sub(1, Ordering::Relaxed);

// AFTER (no-op at zero)
let _ = self.current_connections
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
```

### TLS Client Architecture

Three-tier HTTP client hierarchy:

| Function | TLS | Use Case |
|----------|-----|----------|
| `create_http_client()` | `https_or_http()`, native roots + webpki fallback | Internal: honeypot, alerting |
| `create_http_client_with_config()` | `https_only()`, native roots + webpki fallback | Default: proxy, TLS server |
| `create_upstream_client()` | Configurable via `UpstreamTlsConfig` | Per-site upstream with `skip_verify`/`allow_plaintext` |

Upstream TLS clients are cached by config hash in a `DashMap` for reuse across requests.

**NoVerifier replacement**: `HostnameSkippingVerifier` wraps `WebPkiServerVerifier` — validates certificate chain and signatures, only skips hostname verification. Logs WARN on every use.

### ACME HTTP-01 Challenge Serving

ACME HTTP-01 challenges work across edge/origin mesh topologies. When an origin needs a certificate, the edge node must be able to serve the challenge response.

**Two serving paths:**

1. **Direct HTTP** (`src/http/server.rs:551-579`): The edge's HTTP server handles incoming ACME requests directly from the ACME server (port 80/TCP). The global node has already pushed `UpstreamOwnershipChallenge{Http01{token, key_authorization}}` to all registered edges via mesh QUIC. The edge stores this in its `ownership_challenge_store` and serves it when the ACME server probes.

2. **Mesh QUIC stream** (`src/mesh/transport_peer.rs:2345-2366`): When the global node proxies ACME requests through mesh QUIC (with `Host: origin-host`), `handle_http_proxy_stream()` checks for `GET /.well-known/acme-challenge/{token}` and serves directly from the challenge store — without proxying to a backend.

**Flow:**
```
Origin initiates ACME order
    → Global Node sends UpstreamOwnershipChallenge to all edges (mesh QUIC)
    → Edges store token → key_authorization in LRU cache (5 min TTL)
    → ACME server probes edge IP: GET /.well-known/acme-challenge/{token}
    → Edge serves key_authorization from store
```

**Threat model:** Only serves challenges the edge received via HMAC-signed mesh messages. Cannot forge challenges since it only has the public `key_authorization` string (the ACME server verifies using the origin's private key). Race condition risk if edge is offline when global node pushes the challenge.

### ACME Client

`src/tls/acme.rs` implements a full ACME client using the `instant-acme` crate. Supports HTTP-01 and DNS-01 (feature-gated `dns`) challenges. Certificate renewal runs every 24h via `spawn_renewal_task()`. Config under `[tls.acme]` in TOML.

### TLS Passthrough

Site-level config to forward raw TLS bytes from client to origin without decryption. WAF applies layer 3/4 only (IP rate limiting, connection limits). SNI is extracted via `src/tls/sni_peek.rs` before TLS handshake. Enabled via `tls_passthrough = true` in site proxy config.

### Cert Distribution (Origin → Edge)

`src/mesh/cert_dist.rs` handles origin→edge TLS certificate distribution via 3 mesh messages (`SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse`). Private keys encrypted with AES-256-GCM using per-site keys derived via HKDF from the mesh session key.

### IPC Session Key

The IPC session key is passed via a temp file (`MALUWAF_IPC_KEY_FILE`) instead of an env var. The temp file uses `0600` permissions (Unix only) and is deleted by the worker after reading. Falls back to `MALUWAF_IPC_KEY` env var only if `allow_insecure_ipc_key = true` (default: fail-hard).

### Peer Role Validation

Use `crate::mesh::peer_auth::validate_peer_role()` for centralized global node authentication. This function validates that peers claiming a global role provide the correct `global_node_key`. Used by both Discovery and WireGuard transports.

### TOFU Certificate Pinning

Seed node certificate fingerprints are managed by `MeshCertManager` in `src/mesh/cert.rs`. On first connection, fingerprints are pinned automatically (Trust On First Use). On subsequent connections, fingerprints are verified in `connect_to_peer()` via `verify_seed_fingerprint()`. Pre-configured fingerprints can be set in TOML config via `pinned_cert_fingerprint` on seed nodes.

### Auth Store Merge Pattern

When multiple pending stores need persisting, merge them rather than saving only the last one:

```rust
fn merge_stores(stores: &[AuthStore]) -> AuthStore {
    let mut merged = stores.last().unwrap().clone();
    for store in stores.iter().take(stores.len() - 1) {
        merged.login_logs.extend(store.login_logs.iter().cloned());
    }
    merged
}
```

### Global Nodes as Trust Anchors

Global nodes are the single source of truth and Certificate Authority (CA) for the entire network. This is a fundamental security design decision:

- **Global nodes are NOT elected** — they are explicitly configured and bootstrapped
- Global nodes function analogously to Tor's directory authorities (but with opposite purpose: exposing services rather than providing anonymity)
- All node certificates are signed by global nodes — they serve as the root CA
- Global nodes maintain complete network topology and act as directory servers

Any system that claims to "elect" or "vote" for global nodes violates this security model.

### Module Split Pattern

When splitting large modules:
1. Struct definitions stay in parent file; submodules add `impl StructName { ... }` blocks
2. Each submodule is a sibling file (`foo_bar.rs`), NOT a subdirectory
3. Submodules use `use super::*` or `use crate::module::*` for imports
4. Fields accessed from submodules must be `pub(crate)`, not private
5. Module declarations go in parent module file, not in the struct's file

### ShardedZoneStore

The DNS zone store (`src/dns/server/sharded_store.rs`) uses 64 shards to reduce lock contention. Each shard is an independent `parking_lot::RwLock<HashMap<String, Zone>>`. Zones are distributed by hashing the origin string (djb2 variant).

Key API:
- `get(&str) -> Option<Zone>` — single-shard read, clones zone
- `insert(String, Zone)` — single-shard write
- `for_each(FnMut(&String, &Zone))` — iterates all shards (read locks)
- `for_each_mut(FnMut(&mut Zone))` — iterates all shards (write locks)
- `find(Fn(&str, &Zone) -> bool) -> Option<Zone>` — search all shards
- `get_or_create_and_update(&str, FnOnce(&mut Zone))` — entry-or-insert on one shard
- `keys() -> Vec<String>` — collect all zone names (all shards)

When modifying zone access code, prefer single-shard operations (`get`, `insert`, `update_zone`) over full-shard iteration (`for_each`, `keys`). The `Arc<ShardedZoneStore>` replaces the former `Arc<RwLock<HashMap<String, Zone>>>` pattern.

## Moka Cache Migration

When migrating from `LruCache` to `moka::sync::Cache`:
1. `moka::Cache` is already thread-safe — do NOT wrap in `Mutex` or `RwLock`
2. Remove all `.lock()` calls on the cache
3. Use `.get()`, `.insert()` directly (these methods are thread-safe)
4. For TTL: use `.time_to_live()` not `.expire_after()` (latter requires custom `Expiry` trait implementation)
5. For byte-size eviction: use `.max_capacity()` + `.weigher()` where the weigher returns `u32`
6. `max_capacity` expects `u64`, not `usize`

## Role Comparison Best Practices

Always use `role.is_global()` instead of `role == MeshNodeRole::Global` because:
- `MeshNodeRole` is a bitmask (Global=0b010, Edge=0b001, Origin=0b100)
- Composite roles like `GLOBAL_EDGE` (0b011) have the Global bit set
- Direct equality only matches pure roles, missing composite role cases

## RRSIG Timestamp Encoding

RFC 4034 requires 32-bit (u32) timestamps in RRSIG records. When writing:
```rust
// CORRECT:
rrsig.extend_from_slice(&(timestamp as u32).to_be_bytes());

// WRONG (writes 64-bit):
rrsig.extend_from_slice(&timestamp.to_be_bytes());
```

## Mesh Upstream Routing Architecture

**Nginx-like Domain Routing Model**:

| Component | Format | Example |
|-----------|--------|---------|
| Upstream ID | `http://host:port` | `http://example.com:80` |
| mesh.local_upstreams key | Domain-based | `"http://example.com:80"` |
| Local backend | Private URL | `http://127.0.0.1:5001` |

**Key files**:
- `src/mesh/proxy.rs:extract_upstream_id()` — produces `http://host:port`
- `src/mesh/topology.rs` — stores local_upstreams with domain-based keys
- `src/mesh/transport.rs:announce_upstream()` — announces using domain-based ID
- `src/mesh/dht/keys.rs` — DHT key types including `VerifiedUpstream`

**Routing flow**:
1. Edge receives request → `extract_upstream_id()` → `http://example.com:80`
2. Query DHT for `verified_upstream:http://example.com:80`
3. Get origins that registered this domain+port
4. Weighted random selection → route to selected origin

**Config format**:
```toml
[mesh.local_upstreams]
"http://example.com:80" = {
    upstream_url = "http://127.0.0.1:5001",
    supported_ports = [80, 443],
}
```

**Fixed**: Origin local backend selection is now implemented. Origin nodes accept incoming QUIC streams and route HTTP requests to local backends based on Host header. See `src/mesh/transport.rs:mesh_accept_loop` and `src/mesh/transport_peer.rs:handle_http_proxy_stream`.

## Implementation Plan

The consolidated implementation plan is located at `plans/plan.md`. This single file contains:

| Wave | Focus | Items | Status |
|------|-------|-------|--------|
| 4 | Performance & Code Quality | ~70 | ❌ Open |
| 5 | Future Work | ~25 | ⏸️ Deferred |

**Subagent Execution Model**: Items within Wave 4 can be executed in parallel by separate subagents.
Dependencies between items are documented in `plans/plan.md`.

When reviewing the plan against the codebase, always verify claims directly. Plans may reference items already fixed, use outdated line numbers, or describe bugs incorrectly. Run `grep`/search for the specific patterns described to confirm they still exist before implementing fixes.

**Plan Consolidation Note**: All previous plan files (plan2.md through plan24.md) have been merged into `plans/plan.md`. The original files have been removed.

## Admin Panel Architecture Notes

### Config Propagation

Config changes via the admin API now propagate to workers. `MasterConfigReload` handlers implement real reload in `src/worker/mod.rs` and `src/worker/unified_server.rs`. `PUT /config/main` updates in-memory config and broadcasts via `ProcessManager::broadcast_config_reload()`. `POST /config/reload` also broadcasts. Section-specific handlers (HTTP, TLS, security, etc.) call broadcast after persisting.

Worker `common.rs` handler still logs only (full restart required for that worker type). Hot-reloadable vs restart-required field distinction is tracked for future implementation.

### Frontend Orphaned Files

These admin UI files were previously orphaned but are now reachable:

- `admin-ui/src/pages/system_status.rs` — now at Route `/system-status` ✅
- `admin-ui/src/pages/threat_level.rs` — now at Route `/threat-level` ✅

Still orphaned (not declared as module):
- `admin-ui/src/config_docs.rs` (538 lines — field documentation)

### Genesis Key Handling

The Admin UI System Status page now includes mesh status and genesis key management:

**Backend API**:
- `GET /mesh/status` - Returns `MeshAdminStatusResponse` with:
  - `is_global_node`, `node_id`, `connected_peers`, `global_nodes`, `edge_nodes`
  - `genesis_key_configured`, `genesis_public_key_fingerprint`
  - `signing_key_derived`, `signing_public_key`
- `POST /mesh/derive-signing-key` - Accepts `DeriveSigningKeyRequest { genesis_key_base64 }`, derives signing key

**Frontend API** (`admin-ui/src/services/api.rs`):
- `get_mesh_status()` - fetches mesh status
- `derive_signing_key(genesis_key_base64)` - derives signing key

**Multi-Genesis Key Support**: The system supports multiple authorized genesis keys for key rotation and disaster recovery. Empty `authorized_genesis_keys` means any key is allowed (backward compatible). Non-empty list requires the genesis key's public key to be in the list.

### Capability Attestation System

Global nodes can attest to other nodes' capabilities after verification. DHT key type `CapabilityAttestation` stores:
- `node_id`, `capability` (dns_server, waf, edge_proxy, origin)
- `attested_by_global_node`, `signer_public_key`, `signature`, `timestamp`

## DNS & DNSSEC Architecture

**DNSSEC validation is by design limited to the `Recursive` provider.**

The following providers do NOT perform DNSSEC validation (they are stub/forwarding resolvers):
- `Google` - forwards to Google's DNS, we don't re-validate
- `Cloudflare` - forwards to Cloudflare's DNS, we don't re-validate
- `System` - uses system resolver, no validation
- `Custom` - uses custom upstream IPs, no validation

**To enable DNSSEC validation**, use the `Recursive` provider:

```toml
[dns.recursive]
upstream_provider = "Recursive"
dnssec_validation = true
trust_anchors.enabled = true
trust_anchor_path = "trusted-key.key"
```

## YARA & ThreatIntel Rule Distribution

**Architecture**: Both YARA rules and ThreatIntel use DHT as the primary propagation mechanism. Mesh broadcast is retained as fallback only (to be removed in future).

### Propagation Flow

```
GLOBAL NODE updates rules
         │
         ├──▶ publish_rules_to_dht() ──▶ store rule content + manifest
         │
         └──▶ broadcast_pending_records() ──▶ DhtRecordAnnounce to k closest peers
                           │
                           ▼
              PEERS receive and store in local DHT cache
                           │
                           ▼
    NON-GLOBAL: sync_from_dht() iterates local cache, applies newest version
```

### Key Characteristics

| Aspect | Finding |
|--------|---------|
| DHT announce | One-hop broadcast to k closest peers (NOT recursive Kademlia) |
| Who announces | Global nodes only |
| Who receives | All node types (global, edge, origin) |
| Re-announce | YARA uses `re_announce_interval_secs`; ThreatIntel uses `re_announce_interval_secs` |

### YARA DHT Keys

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `yara_rule:{content_hash}` | Actual rule content (content-addressed) | 24 hours |
| `yara_rules_manifest:{node_id}` | Global node's current ruleset metadata | 24 hours |

### YARA Signature Verification

YARA rules published to DHT are signed using Ed25519:
- **Manifest signature**: `version:content_hash:node_id:timestamp`
- **Rule content signature**: `version:rules:content_hash:node_id:timestamp`

During DHT sync (`sync_from_dht()`), both manifest and rule content signatures are verified before accepting rules. The manifest's `content_hash` is verified against the actual rule content hash. Records without signatures are accepted for backward compatibility with legacy data.

### ThreatIntel DHT Keys

| Key Pattern | Purpose |
|-------------|---------|
| `threat_indicator:{ip}:{threat_type}` | Per-type indicator (composite key, e.g., `threat_indicator:1.2.3.4:IpBlock`) |

**Important**: ThreatIntel uses composite keys with threat_type suffix to prevent collision between different threat types for the same IP. A key without threat_type (e.g., `threat_indicator:1.2.3.4`) will NOT match.

### ThreatIntel Signature Verification

ThreatIntel indicators published to DHT are signed using Ed25519:
- **Indicator signature**: `indicator_value:threat_type:severity:timestamp:source_node_id`

During DHT sync (`sync_from_dht()`), signatures are verified before accepting indicators. The `signer_public_key` is extracted from the DHT record and used to verify the signature. Records without valid signatures are skipped but allow backward compatibility with unsigned legacy records.

### ThreatIntel Re-announcement

Global nodes periodically re-announce local ThreatIntel indicators via `re_announce_local_indicators()`. The interval is controlled by `re_announce_interval_secs` (default: 300s). Only non-expired local-origin indicators are re-announced. Respects `hub_only_mode` (non-global nodes do not re-announce).

## Honeypot Architecture Summary

| Subsystem | Location | Publishing |
|-----------|----------|------------|
| HTTP Honeypot | `src/challenge/honeypot.rs` | Via `block_ip_with_threat_intel()` |
| Port Honeypot | `src/honeypot_port/` | Via `start_mesh_threat_publishing()` |

## Web App Stack Backend Types

| Backend | Config | Implementation |
|---------|--------|----------------|
| Static Files | `[site.static]` | `src/static_files/mod.rs` |
| PHP-FPM | `[site.php]` | `src/php/mod.rs` |
| FastCGI | `[site.fastcgi]` | `src/fastcgi/mod.rs` |
| WASM/Serverless | `[site.serverless]` | `src/serverless/manager.rs` |
| Python (Granian) | `[site.app_server]` | `src/app_server/granian.rs` |
| HTTP Upstream | `[site.upstream]` | `src/proxy.rs` |
| Mesh Origin | DHT + `[site.upstream]` | `src/mesh/topology.rs` |

## FastCGI Pool Management

The FastCGI module (`src/fastcgi/`) provides connection pooling via `FastCgiPoolManager`:

```rust
// Get a pool for a given host:port
let pool = fastcgi::get_pool(host, port);

// Remove a pool (e.g., on config change)
fastcgi::remove_pool(host, port);

// Close all pools (e.g., on shutdown)
fastcgi::close_all_pools();
```

Pools are stored as module-level statics via `LazyLock`, keyed by `host:port`. Each pool manages reusable FastCGI connections.

## PHP Security Settings

`PhpConfig` security fields are enforced via PHP-FPM:

```toml
[site.php]
disable_functions = "exec,passthru,shell_exec,system"
open_basedir = "/var/www/html"
allow_url_fopen = false
max_execution_time = 30
memory_limit = "128M"
upload_max_filesize = "10M"
post_max_size = "50M"
```

These are passed to PHP-FPM as:
- `PHP_ADMIN_VALUE:disable_functions` (admin-only, cannot be overridden)
- `PHP_ADMIN_VALUE:open_basedir` (admin-only, cannot be overridden)
- `PHP_VALUE` for other settings

## PHP Per-Location Security

Security settings can be configured per-location via `PhpLocationConfig`:

```toml
[site.proxy.php.locations]
path = "/api"
disable_functions = "exec,passthru,shell_exec"
open_basedir = "/var/www/api"
max_execution_time = 60
```

Location-level settings override site-level settings for that specific path prefix.

## Static File Directory Templates

Custom templates for directory listing are supported via `SiteStaticThemeConfig`:

```toml
[site.static.theme]
directory_template_path = "/etc/maluwaf/templates/directory.html"
preset = "dark"
```

Supported placeholders:
- `{{url_path}}` - current URL path
- `{{parent_link}}` - parent directory link
- `{{rows}}` - file/folder entries
- `{{site_name}}` - site name (RustWAF)
- `{{title}}` - page title ("Index of {url_path}")

## Skills and Knowledge Base

For complex subsystems, specialized skill files provide detailed architecture guidance:

### Mesh & DHT Architecture

**Location**: `skills/malu_mesh.md` (in-repository copy)

This skill file documents the mesh networking and DHT system, which is complex and has many interdependent components. The skill file contains:
1. **Architecture diagrams** (via text descriptions)
2. **Key derivation chains** (genesis → signing_key → tier_key_master)
3. **Phase status tracking** - what's completed vs deferred
4. **Common issues** - known gaps and debug patterns
5. **File reference table** - purpose of each mesh-related file

The skill file was originally maintained at `~/.config/opencode/skills/malu_mesh/SKILL.md` but a copy is kept in-repository for reliability.

### DNS & DNSSEC

**Location**: `skills/dns_dnssec.md`

Detailed architecture documentation for the DNS and DNSSEC subsystems.