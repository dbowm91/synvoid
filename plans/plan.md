# MaluWAF Consolidated Remediation Plan

> Created: 2026-03-30
> Source: Consolidation of 11 individual plan files (plan2-5, plan_dns1-3, plan_ui1-3, plan_ui5)
> Codebase: ~135k lines of Rust

---

## Overview

This plan consolidates all remediation items from individual plan files into a single actionable document. Items are organized into 11 phases ordered by dependency and risk, with clear parallelization paths for sub-agents.

---

## Phase 1: Quick Cleanup (Low Risk)

> All independent, zero-risk removals. Can run in parallel.

### 1.1 Remove Dead `error.rs` Module

`src/error.rs` (171 lines) defines `WafError`, `WafResult`, `WafErrorExt` — **100% dead code**. Zero imports across codebase.

| # | Task | File |
|---|------|------|
| 1 | Delete file | `src/error.rs` |
| 2 | Remove module declaration | `src/lib.rs:43` — delete `pub mod error;` |
| 3 | Verify no re-exports leak | `pub use utils::errors` at `src/lib.rs:96` is the separate inline module — no change needed |

### 1.2 Deduplicate `current_timestamp()`

6 identical definitions. Canonical: `pub` in `src/utils.rs:423`. Re-exported via `src/process/mod.rs:28`.

| # | Task | File:Line |
|---|------|-----------|
| 1 | Remove local fn, add `use crate::utils::current_timestamp;` | `src/waf/probe_tracker.rs:455` |
| 2 | Same | `src/mesh/dht/stake.rs:531` |
| 3 | Remove `pub fn` method + update `Self::` callers | `src/overseer/state.rs:146` |
| 4 | Same as #1 | `src/mesh/transports/manager.rs:32` |
| 5 | Same as #1 | `src/captcha/mod.rs:192` |
| 6 | Verify: `rg 'fn current_timestamp' src/` returns 1 match | — |

### 1.3 Clean Build Artifacts from Git

| # | Task | File |
|---|------|------|
| 1 | Add to `.gitignore` | `Cargo.bak.*`, `Cargo.lock.new` |
| 2 | Remove from git tracking | `git rm --cached Cargo.bak.lock Cargo.bak.toml Cargo.lock.new Archive.zip` |

### 1.4 Remove Dead DhtKey Variants

5 of 23 `DhtKey` variants in `src/mesh/dht/keys.rs` are never instantiated: `TierClaim`, `NetworkPolicy`, `GlobalNodeBlocklist`, `YaraRuleSubmission`, `GlobalAiBotList`.

| # | Task | File |
|---|------|------|
| 1 | Remove 5 dead variants + all associated code | `src/mesh/dht/keys.rs` |
| 2 | Remove from `is_privileged()` and `is_public()` match arms | `src/mesh/dht/keys.rs` |

**Verification** (after Phase 1):
```bash
cargo check
cargo test --test integration_test
rg 'WafError|WafResult|WafErrorExt' src/ -g '*.rs'  # zero matches
rg 'fn current_timestamp' src/ -g '*.rs'  # 1 match
```

---

## Phase 2: Security Fixes

> High priority. Independent tasks.

### 2.1 X-Forwarded-For Spoofing

`src/admin/middleware.rs:22` — uses `.next()` to take FIRST IP. Should take last trusted IP or validate against trusted proxy list.

### 2.2 Default Admin Token Rejection

`src/config/admin.rs:140` — warns but doesn't reject "changeme". Make it a hard error in release builds.

### 2.3 Plaintext Token Handling

`src/admin/auth.rs:25-31` — returns `false` for plaintext tokens instead of migrating. Either implement migration or return a clear error.

### 2.4 Upgrade RSA Dependency

`rsa = "0.9"` is vulnerable to Marvin Attack (RUSTSEC-2023-0071). Check for patched version or replace with `ring`/`aws-lc-rs`.

### 2.5 Audit Unsafe Code Blocks

82 unsafe blocks need safety review. Key areas: plugin loading (`src/plugin/axum_loader.rs:106`), TLS verification bypass, daemonization (`src/main.rs:666`), zero-copy sendfile (`src/zero_copy.rs:61`).

### 2.6 Upgrade LightningCSS

Using alpha `lightningcss` 1.0.0-alpha.71. Update to stable if available.

**Verification**: `cargo audit`, `cargo test --test integration_test`

---

## Phase 3: Critical Correctness

> High priority. Atomic counter safety.

### 3.1 Fix Atomic Counter Underflow

Replace `fetch_sub` with `fetch_update` + `checked_sub` at:

| File | Occurrences |
|------|-------------|
| `src/metrics/mod.rs` | 2 |
| `src/worker/drain_state.rs` | 6 |
| `src/block_store.rs` | 4 |
| `src/udp/listener.rs` | 2 |

Pattern:
```rust
// BEFORE
self.current_connections.fetch_sub(1, Ordering::Relaxed);
// AFTER
let _ = self.current_connections
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
```

### 3.2 DNS Store Concurrency Bug

`src/dns/store.rs:65` — `Arc<RwLock<Connection>>` not Send+Sync. Replace `RwLock` with `Mutex` or use `parking_lot::RwLock`.

**Verification**: `cargo test --test integration_test`

---

## Phase 4: Performance Optimization

> Medium priority. Independent hot-path improvements.

### 4.1 SSRF Detection — Cache Lowercase

`src/waf/attack_detection/ssrf.rs` — multiple `.to_lowercase()` calls on same input. Cache once.

### 4.2 Rate Limiter — Combine Retain Operations

`src/waf/ratelimit.rs:245-263` — 6 sequential `retain()` calls, each O(n). Consider single-pass approach. Cleanup runs every 30s so impact is bounded.

### 4.3 Path Sanitization

`src/proxy.rs:101` — allocates `Vec<u8>` and `String` per request. Consider `Cow<str>` or reusable buffer.

### 4.4 Response Header Filtering

`src/proxy.rs:147-159` — allocates `Vec` per proxied response. Consider in-place filtering via `HeaderMap`.

### 4.5 Async Lock Contention

Review locks held across await points in `src/admin/mod.rs:135`, `src/auth/mod.rs:300`. Drop locks before await when possible.

**Verification**: `cargo bench` (if benchmarks exist), profiling

---

## Phase 5: Code Quality — Clippy & File Splits

> Medium priority.

### 5.1 Fix Clippy Warnings

| Category | Count | Key Locations |
|----------|-------|---------------|
| Empty line after doc comment | 3 | `src/mesh/transport.rs:693,862,1667` |
| Redundant field name | 1 | `src/mesh/transport_peer.rs:1029` — `role: role` → `role` |
| Type complexity | 6 | Multiple — factor into `type` definitions |
| Redundant closures | 6 | Multiple — simplify |
| `from_str` method confusion | 5 | Multiple — rename or impl `FromStr` |
| `Result<_, ()>` | 4 | Use `Result<_, Infallible>` or custom error |
| Other style | ~20 | See plan2.md Phase 1.6 for full list |

### 5.2 Split Oversized Files (target: <1,500 lines each)

| File | Current Lines | Split Strategy |
|------|---------------|----------------|
| `src/dns/dnssec.rs` | 2,208 | → `dnssec_key_mgmt.rs`, `dnssec_signing.rs`, `dnssec_validation.rs` |
| `src/admin/handlers/config.rs` | 2,136 | → `config_site.rs`, `config_dns.rs`, `config_global.rs` |
| `src/http/server.rs` | 2,109 | → `server_connection.rs`, `server_routing.rs`, `server_error.rs` |
| `src/process/manager.rs` | 2,018 | → `manager_spawn.rs`, `manager_lifecycle.rs`, `manager_ipc.rs` |

**Deferred** (splitting fights the codegen/structure):
- `src/mesh/protocol_proto_encode.rs` (2,024) — generated protobuf pattern
- `src/mesh/transport.rs` (2,086) — already split into 11 submodules

### 5.3 Extract `main.rs` Logic

`src/main.rs` (1,371 lines) → slim to ~200 lines:
- `src/startup/bootstrap.rs` — config loading, validation, logging
- `src/startup/daemon.rs` — PID file, daemon mode, signal handlers
- `src/startup/worker.rs` — worker argument construction, entry point

### 5.4 Standardize Error Handling Pattern

Inconsistent error types: mix of `anyhow` (14 files), `Box<dyn Error + Send + Sync>` (3 files: `config/site.rs`, `http_client/mod.rs`, `tunnel/quic/framing.rs`), and custom types. Standardize per-module: `anyhow` for application code, `thiserror` for library modules.

### 5.5 Clean Up `#[allow(dead_code)]`

137 annotations across 75 files. Audit each: remove if genuinely unused, add explanatory comment if reserved for future use. Priority: `src/mesh/` (~29), `src/dns/server/` (~10).

**Verification**: `cargo clippy -- -D warnings`, `cargo fmt --check`

---

## Phase 6: Eliminate Production `unwrap()` in Hot Paths

> Medium-high risk. Target request-handling code first.

### Wave 1 — Request-Handling Hot Path (~23 unwraps)

| File | Unwraps | Fix |
|------|---------|-----|
| `src/dns/doh.rs` | 11 | `?` propagation or `unwrap_or_else` with error response |
| `src/http/server.rs` | 5 | `.parse().unwrap()` → `.parse().unwrap_or_else(\|_\| HeaderValue::from_static(""))` |
| `src/waf/ip_feed.rs` | ~3 | `.split('#').next().unwrap()` → `.unwrap_or("")` |
| `src/dns/update.rs` | 4 | `?` propagation |
| `src/buffer/pool.rs` | 3 | `unwrap_or_else` with fresh allocation fallback |

### Wave 2 — Deferred (~70 unwraps)

Config parsing, initialization, metrics, `worker_pool/worker.rs:7`, `process/socket_fd.rs:9`, `dns/hsm.rs:9`, `dns/dnssec.rs:6`. Lower risk — values validated at startup.

**Verification**: `rg 'unwrap\(\)' src/dns/doh.rs src/http/server.rs src/waf/ip_feed.rs` — zero matches

---

## Phase 7: DNS — DNSSEC & Resolver

> DNS feature-gated work. Phases 7.1–7.2 are independent of each other.

### 7.1 DNSSEC Validation in Forwarding Mode

`HickoryResolver` (System/Google/Cloudflare/Custom) never validates DNSSEC. `is_dnssec_validated` hardcoded to `false` at `src/dns/resolver.rs:401`.

| # | Task | File |
|---|------|------|
| 1 | Enable `dnssec-ring` feature on hickory-resolver | `Cargo.toml:104` — add `"dnssec-ring"` to features |
| 2 | Add `is_dnssec_validated: bool` to all `DnsResolver` return types | `src/dns/resolver.rs` — `TxtRecord`, `NsRecord`, `MxRecord`, `SoaRecord`, `PtrRecord`, `SrvRecord`, `CNameRecord` |
| 3 | Set `opts.validate = true` in all HickoryResolver constructors | `src/dns/resolver.rs` |
| 4 | Extract validation via `Lookup::dnssec_record_iter()` | `src/dns/resolver.rs` — check `proof().is_secure()` per record |
| 5 | Propagate AD flag in recursive server responses | `src/dns/recursive.rs` |
| 6 | Respect `dnssec_validation` config | `src/dns/recursive.rs`, `src/config/dns.rs` |

### 7.2 NSEC3 SHA-256 Support

`src/dns/dnssec.rs:1385-1404` hardcodes SHA-1. RFC 5155 defines algorithm 2 (SHA-256).

| # | Task | File |
|---|------|------|
| 1 | Add SHA-256 branch to `hash_name_nsec3()` | `src/dns/dnssec.rs:1385-1404` |
| 2 | Add `algorithm: u8` param to `Nsec3Config::new()` | `src/dns/dnssec.rs:1375` |
| 3 | Add `nsec3_algorithm` config option | `src/config/dns.rs` |
| 4 | Verify `base32_encode()` handles 32-byte hashes (52 chars base32, within 63-char DNS label limit) | — |

### 7.3 Forwarder DNSSEC AD Bit Propagation

Parse AD bit from upstream responses in forwarding mode. Set `authentic_data` when upstream AD=1. Add startup warning when using forwarding + DNSSEC requirements.

**Verification**: `cargo test --test integration_test dnssec`, `cargo test --lib resolver`

---

## Phase 8: DNS — Mesh Integration

> DNS feature-gated. Dependencies noted per sub-phase.

### 8.1 Mesh DNS Signing (independent)

Derive DNS signing keys from mesh identity (HKDF-SHA256 from session key + "dns-signing" label). Authoritative server signs mesh-resolved records with derived Ed25519 key.

| # | Task | File |
|---|------|------|
| 1 | Add `derive_dns_signing_key()` | `src/dns/mesh_sync/mod.rs` |
| 2 | Create `MeshSigningKey` struct | `src/dns/mesh_sync/mod.rs` |
| 3 | Update `resolve_from_mesh` to accept signing context | `src/dns/server/query.rs:500-551` |
| 4 | Modify `build_response` to use mesh signing key | `src/dns/server/query.rs:817-834` |

### 8.2 Mesh Certificate Chain Verification (independent)

After TXT/NS domain verification, additionally verify node cert chains back to global node CA.

| # | Task | File |
|---|------|------|
| 1 | Add `certificate_chain` to registration requests | `src/dns/mesh_sync/mod.rs` |
| 2 | Create `verify_certificate_chain` method | `src/dns/mesh_sync/verification.rs` |
| 3 | Store result in `RegisteredOriginNode` | `src/dns/mesh_sync/mod.rs:39-51` |
| 4 | Add config `require_cert_chain_verification` | `src/config/dns.rs` |

### 8.3 DHT Registration Refresh (independent)

`sync_from_dht()` only adds new entries, doesn't update existing ones.

| # | Task | File |
|---|------|------|
| 1 | Add `update_origin_node` method | `src/dns/mesh_sync/mod.rs` |
| 2 | Modify `sync_from_dht` to update existing | `src/dns/mesh_sync/dht.rs:48-139` |
| 3 | Add `last_seen: u64` timestamp | `src/dns/mesh_sync/mod.rs` |
| 4 | Add periodic re-sync (default 30s) | `src/dns/mesh_sync/registry.rs` |

### 8.4 Anycast Node Authentication (depends on 8.2)

Verify DHT record signatures from publishing global node for anycast entries.

### 8.5 Global Node DNS Requirements (independent)

Document DNS serving requirements. Add `dns_serving_healthy` to node announcements. Startup warning if global node has `dns.enabled = false`.

### 8.6 Global Node-Based Recursive Resolution (independent)

Add `GlobalNodes` upstream provider to recursive resolver. New file: `src/dns/resolver_global.rs`. Fallback to traditional DNS if global nodes unavailable.

### 8.7 Unified DNSSEC Architecture (depends on 8.6)

Create `DnsSecValidator` trait supporting both standard RFC 5011 and mesh Ed25519 trust anchors. `MeshTrustAnchorAdapter` imports mesh keys as RFC 5011 anchors.

### 8.8 Formalize Global Node CA (independent)

Document CA architecture. Add CA mode flag. Export root CA certificate. Add CRL generation.

### 8.9 Domain Verification Resilience (depends on 8.6)

Support mesh-internal verification as alternative to external DNS for domain ownership challenges.

### 8.10 QNAME Minimization (deferred)

External dependency on hickory-resolver RFC 7816 support. Document current privacy limitations.

**Verification**: `cargo test --test integration_test -- dns`, `cargo test --test dht_integration_test`

---

## Phase 9: Admin Panel — Backend Wiring

> Frontend work in Rust/wasm (Yew framework). Phase 9.1 is prerequisite for 9.2–9.4.

### 9.1 Add Missing Frontend API Methods

Add ~28 methods to `admin-ui/src/services/api.rs` following existing pattern at `api.rs:461-490`:

```
get_http_config / update_http_config → /config/http
get_logging_config / update_logging_config → /config/logging
get_security_config / update_security_config → /config/security
get_tls_config / update_tls_config → /config/tls
get_tunnel_config / update_tunnel_config → /config/tunnel
get_plugins_config / update_plugins_config → /config/plugins
get_traffic_shaping_config / update_traffic_shaping_config → /config/traffic-shaping
get_ip_feeds_config / update_ip_feeds_config → /config/ip-feeds
get_rate_limits_config / update_rate_limits_config → /config/rate-limits
get_bot_detection_config / update_bot_detection_config → /config/bot-detection
get_mesh_config / update_mesh_config → /config/mesh
get_dns_config / update_dns_config → /config/dns
reload_config → POST /config/reload
validate_config → POST /config/validate
export_config → GET /config/export
import_config → POST /config/import
get_honeypot_status / control_honeypot → /honeypot/*
get_icmp_status / config / enable / disable → /icmp/*
```

### 9.2 Add Frontend Config Type Structs

Add typed structs in `admin-ui/src/types/mod.rs` using `Option<T>` for all fields (forward compatibility):

`HttpConfig`, `LoggingConfig`, `SecurityConfig`, `TrafficShapingConfig`, `RateLimitsConfig`, `BotDetectionConfig`, `IpFeedsConfig`, `TlsConfig`, `DnsConfig`, `MeshConfig`

### 9.3 Fix Config Propagation (Critical Backend Fix)

**Most critical architectural issue**: config changes are persisted to disk but workers never learn about them.

| # | Task | File |
|---|------|------|
| 1 | Fix `MasterConfigReload` handlers — currently no-op | `src/worker/mod.rs:248`, `src/worker/common.rs:197`, `src/worker/unified_server.rs:790` |
| 2 | Fix `PUT /config/main` staleness — update in-memory config after write | `src/admin/handlers/config.rs` |
| 3 | Add `broadcast_config_reload()` to `ProcessManager` | `src/process/manager.rs` — follow pattern of `broadcast_rule_patterns_update` at line 1179 |
| 4 | Call broadcast in all section-specific handlers | `src/admin/handlers/config.rs` |
| 5 | Fix `POST /config/reload` — also reload `main.toml` and signal workers | `src/admin/handlers/config.rs:1030` |
| 6 | Define hot-reloadable vs restart-required fields | Return in `/config/schema` endpoint |

### 9.4 Wire Settings Page Sections

Replace 8 static mockup sections with API-driven components in `admin-ui/src/pages/settings.rs`. Each section: load from API on mount → store in state → section-local Save button → toast on success/error.

Pattern (follow ThemeSection at `settings.rs:468-731` and ProcessManagement page):

| Section | API Endpoint | Fields |
|---------|-------------|--------|
| Server | `GET/PUT /config/main` (extract `server`) | host, port, host_v6, trusted_proxies |
| HTTP | `GET/PUT /config/http` | timeouts, max sizes, keep-alive, compression |
| Logging | `GET/PUT /config/logging` | level, format, file, rotation |
| Metrics | `GET/PUT /config/main` (extract `metrics`) | enabled, port |
| Rate Limits | `GET/PUT /config/rate-limits` | mode, per-IP limits, global limits |
| Bandwidth | `GET/PUT /config/traffic-shaping` | enabled, per-site limits |
| Bot Defaults | `GET/PUT /config/bot-detection` | enabled, difficulty, challenge toggles |
| Upload | `GET/PUT /config/main` (extract `upload`) | enabled, max size, MIME types |

Remove inert global Save/Reset buttons (lines 72-78). Each section has its own.

Wire `config_docs.rs` (538 lines, currently orphaned — not declared as module). Add `mod config_docs;` to `admin-ui/src/main.rs`. Render tooltips from `get_field_doc(section, field_name)`.

**Staleness caveat**: `PUT /config/main` writes to disk but doesn't update in-memory config (fixed in Phase 9.3). Until then, show toast: "Saved to disk. Restart required to apply."

### 9.5 Wire SiteEditor Tabs

Make 6 static tabs load/save per-site config via `GET/PUT /sites/{id}`.

| Tab | Config Section |
|-----|---------------|
| Basic (verify) | domains, upstream, routes |
| Rate Limits | mode, per-IP limits |
| Blocking | blocked paths, response code, pattern mode |
| Attacks | paranoia level, action, per-attack toggles |
| Bot Protection | toggles and inputs |
| Upload | toggles and inputs |

Add missing tabs: Proxy, Security Headers, Static, Auth, WebSocket, gRPC, Tunnel.

Fix Save/Cancel buttons (currently no `onclick` handlers at lines 77-84).

---

## Phase 10: Admin Panel — Missing Pages & UX

### 10.1 Enable Orphaned Pages

| Page | File | Action |
|------|------|--------|
| SystemStatus | `admin-ui/src/pages/system_status.rs` (217 lines) | Add `Route::SystemStatus` to `app.rs`, export in `pages/mod.rs`, add sidebar nav item |
| ThreatLevel | `admin-ui/src/pages/threat_level.rs` (615 lines) | Add `Route::ThreatLevel` to `app.rs`, export in `pages/mod.rs`, add sidebar nav item |

### 10.2 Fix Broken UI

| Issue | File | Fix |
|-------|------|-----|
| TierKeys modal never renders | `admin-ui/src/pages/tier_keys.rs` | Add modal div gated on `show_issue_modal` |
| Sidebar missing bell icon | `admin-ui/src/components/layout/sidebar.rs:121-175` | Add `"bell"` match arm with SVG |
| Upstreams page is mock data | `admin-ui/src/pages/upstreams.rs` | Wire to `GET /upstreams` API, remove `mock_upstreams` |

### 10.3 Add Honeypot & ICMP Pages

Backend APIs exist. Create:
- `admin-ui/src/pages/honeypot.rs` — status, connections, enable/disable
- `admin-ui/src/pages/icmp.rs` — status, config, backends, enable/disable

### 10.4 Usability Improvements

| # | Task | Files |
|---|------|-------|
| 1 | Loading spinners on all API-driven pages | All pages |
| 2 | Shared `toast_error`/`toast_success` helpers | All pages |
| 3 | Change indicators (dirty state on Save buttons) | `settings.rs` |
| 4 | "Requires restart" badges on relevant fields | `settings.rs` |
| 5 | Config export/import buttons | `settings.rs` — `GET /config/export`, `POST /config/import` |
| 6 | Config validation before save | `settings.rs` — `POST /config/validate` |
| 7 | Search/filter on Sites, Logs, Upstreams | Respective pages |
| 8 | Keyboard shortcuts (Ctrl+S, Ctrl+R, Esc) | `app.rs` |

### 10.5 Logs Page

Backend: implement log buffer in `AdminState` (ring buffer, max 10,000) or read from log file. Frontend: wire to `GET /logs` and WebSocket `GET /api/ws/logs` for real-time streaming.

### 10.6 Dynamic Form Generator (Long-term)

Build `DynamicForm` component that fetches `/api/config/schema` and renders forms automatically. Maps `field_type` to form components. Supports nested objects, validation, and `reload_behavior` warnings.

### 10.7 Accessibility & i18n (Long-term)

ARIA labels, keyboard navigation, screen-reader text, i18n framework, RTL support, WCAG AA contrast.

**Verification**: `cargo check` in `admin-ui/`, manual testing of all pages

---

## Phase 11: Testing & Documentation

### 11.1 Add Tests

| # | Task | File |
|---|------|------|
| 1 | Unit tests for `src/proxy.rs` | `src/proxy.rs` — path sanitization, header filtering, response processing |
| 2 | Unit tests for `src/http/server.rs` | `src/http/server.rs` — HTTP parsing, TLS, connection pool |
| 3 | Integration tests for admin API | New: `tests/admin_api_test.rs` |
| 4 | Rate limiting under concurrent load | `tests/integration_test.rs` |
| 5 | IPC message deserialization with malformed data | `tests/integration_test.rs` |

### 11.2 Documentation

| # | Task | File |
|---|------|------|
| 1 | Update Raft reference | `docs/ARCHITECTURE.md:22` — mark as "Planned" |
| 2 | Update CHANGELOG Raft entry | `CHANGELOG.md:27` — move to "Planned" |
| 3 | Document DNS + mesh integration | New: `docs/dns-mesh-integration.md` |
| 4 | Document DNSSEC architecture | New: `docs/dns-dnssec-architecture.md` |
| 5 | Document global node CA | New: `docs/global-node-ca.md` |
| 6 | Add NSEC3 inline comment | `src/dns/dnssec.rs:1367` — explain limitation |

---

## Verification Commands

```bash
# After each phase:
cargo check
cargo check --features dns
cargo test --test integration_test

# Clippy (target: zero warnings)
cargo clippy -- -D warnings

# Formatting
cargo fmt --check

# Full test suite
cargo test

# Security audit
cargo audit
```

---

## Parallelization Strategy

### Sub-Agent Group A — Cleanup (all independent, zero risk)
Phase 1.1 (error.rs) + 1.2 (timestamps) + 1.3 (artifacts) + 1.4 (DhtKeys)
**Effort**: ~30 min

### Sub-Agent Group B — Security & Correctness
Phase 2 (security) + Phase 3 (correctness)
**Effort**: ~1-2 days

### Sub-Agent Group C — Performance
Phase 4 (all sub-tasks independent)
**Effort**: ~0.5-1 day

### Sub-Agent Group D — Clippy & File Splits
Phase 5.1 (clippy) + 5.2 (file splits) + 5.3 (main.rs extraction)
Note: 5.2 depends on 5.1 (clippy fixes reduce noise during split review)
**Effort**: ~2-3 days

### Sub-Agent Group E — unwrap() Elimination
Phase 6 (Wave 1 independent of Group D)
**Effort**: ~1-2 hours

### Sub-Agent Group F — DNS Resolver
Phase 7.1 (DNSSEC forwarding) + 7.2 (NSEC3 SHA-256) — independent of each other
**Effort**: ~1-2 days

### Sub-Agent Group G — DNS Mesh
Phase 8.1 (signing) + 8.3 (DHT refresh) + 8.5 (global node DNS) + 8.8 (CA formalize) — all independent
Then: 8.2 (cert verification) → 8.4 (anycast auth)
Then: 8.6 (global node recursive) → 8.7 (unified DNSSEC) + 8.9 (verification resilience)
**Effort**: ~3-5 days

### Sub-Agent Group H — Admin Backend
Phase 9.1 (API methods) + 9.2 (type structs) + 9.3 (config propagation)
Then: 9.4 (settings wiring) + 9.5 (site editor)
**Effort**: ~3-5 days

### Sub-Agent Group I — Admin Frontend UX
Phase 10.1 (orphaned pages) + 10.2 (broken UI) + 10.3 (honeypot/ICMP)
Then: 10.4 (usability) + 10.5 (logs)
Phase 10.6 (dynamic forms) + 10.7 (a11y/i18n) — long-term, defer
**Effort**: ~3-5 days

### Sub-Agent Group J — Tests & Docs
Phase 11 (all tasks independent)
**Effort**: ~1-2 days

### Maximum Parallelization

```
Week 1:  A (cleanup) + B (security) + C (perf) + E (unwrap) + F (DNS resolver)
Week 2:  D (clippy/splits) + G (DNS mesh, start) + H (admin backend, start)
Week 3:  G (DNS mesh, cont) + H (admin backend, cont) + I (admin UX, start)
Week 4:  I (admin UX, cont) + J (tests/docs)
```

---

## Execution Order (Sequential Fallback)

If running single-threaded, recommended order:

1. **Phase 1** — Quick cleanup (low risk, immediate value)
2. **Phase 3** — Atomic counter safety (critical correctness)
3. **Phase 2** — Security fixes (high priority)
4. **Phase 6** — unwrap() hot path (crash prevention)
5. **Phase 4** — Performance (measurable improvement)
6. **Phase 5.1** — Clippy fixes (CI stability)
7. **Phase 9.3** — Config propagation fix (prerequisite for admin UI)
8. **Phase 5.2-5.3** — File splits + main.rs extraction
9. **Phase 7** — DNS resolver DNSSEC
10. **Phase 9** — Admin panel wiring
11. **Phase 8** — DNS mesh integration
12. **Phase 10** — Admin UX improvements
13. **Phase 11** — Testing & documentation

---

## Risk Assessment

| Risk | Phase | Impact | Mitigation |
|------|-------|--------|------------|
| Atomic counter fix breaks metrics | 3 | Low | `fetch_update` no-ops at zero |
| DNSSEC forwarding adds crypto dep | 7.1 | Medium | Feature-gated, document as "trust-anchor verification" vs "full recursive" |
| File splits cause merge conflicts | 5.2 | High | Do on clean branch, one file at a time |
| Config propagation breaks workers | 9.3 | High | Test with integration tests, gradual rollout |
| Dynamic form schema drift | 10.6 | Medium | Use `Option<T>` for all fields |

---

## Files Summary (Top Modified)

| File | Phases | Change Type |
|------|--------|-------------|
| `src/error.rs` | 1.1 | Delete |
| `src/lib.rs` | 1.1, 5.3 | Remove `pub mod error`, add `pub mod startup` |
| `src/dns/resolver.rs` | 7.1 | Add DNSSEC validation to all record types |
| `src/dns/recursive.rs` | 7.1, 7.3 | AD bit propagation |
| `src/dns/dnssec.rs` | 5.2, 7.2, 11.2 | Split, NSEC3 SHA-256, inline comment |
| `src/dns/mesh_sync/mod.rs` | 8.1-8.4 | Signing key, cert verification, DHT refresh |
| `src/admin/handlers/config.rs` | 5.2, 9.3, 9.4 | Split, config propagation, section handlers |
| `src/process/manager.rs` | 5.2, 9.3 | Split, `broadcast_config_reload()` |
| `src/worker/mod.rs` | 9.3 | Fix `MasterConfigReload` handler |
| `src/worker/common.rs` | 9.3 | Fix `MasterConfigReload` handler |
| `src/worker/unified_server.rs` | 9.3 | Fix `MasterConfigReload` handler |
| `admin-ui/src/services/api.rs` | 9.1, 10.3 | +28 API methods |
| `admin-ui/src/types/mod.rs` | 9.2 | +10 typed config structs |
| `admin-ui/src/pages/settings.rs` | 9.4, 10.4 | Wire 8 sections, usability |
| `admin-ui/src/pages/site_editor.rs` | 9.5 | Wire 6+ tabs |
| `Cargo.toml` | 2.4, 7.1 | RSA upgrade, `dnssec-ring` feature |
