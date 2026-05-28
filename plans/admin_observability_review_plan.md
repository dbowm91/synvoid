# Admin & Observability Review Plan

**Reviewed:** 2026-05-28
**Documents:**
- `architecture/admin_deep_dive.md`
- `architecture/metrics.md`
- `architecture/logging.md`
- `architecture/log_controller.md`
- `architecture/protocol.md`

## Verified Correct Items

| Claim | Document | Source | Status |
|-------|----------|--------|--------|
| `hash_admin_token()` / `verify_admin_token()` location | admin_deep_dive.md | `src/admin/auth.rs:20-26` | Correct |
| MAX_AUTH_ATTEMPTS = 5, AUTH_LOCKOUT_DURATION = 300s, AUTH_WINDOW_DURATION = 60s | admin_deep_dive.md | `src/admin/auth.rs:6-8` | Correct |
| AdminState struct fields and location | admin_deep_dive.md | `src/admin/state.rs:257-267` | Correct |
| SecurityState struct fields | admin_deep_dive.md | `src/admin/state.rs:211-217` | Correct |
| CSRF validation at `state.rs:728-749` uses `ct_eq()` | admin_deep_dive.md | `src/admin/state.rs:728-749` | Correct — `ConstantTimeEq` verified |
| CSRF token generation at `state.rs:751-779` | admin_deep_dive.md | `src/admin/state.rs:751-779` | Correct |
| MAX_CSRF_TOKENS_PER_SESSION = 10 | admin_deep_dive.md | `src/admin/state.rs:314` | Correct |
| create_session at `state.rs:796-828` | admin_deep_dive.md | `src/admin/state.rs:796` | Correct |
| validate_session at `state.rs:830-845` | admin_deep_dive.md | `src/admin/state.rs:830` (ends line 852) | Correct (line end slightly off) |
| YaraRateLimiter location `state.rs:86-143` | admin_deep_dive.md | `src/admin/state.rs:86-143` | Correct |
| Yara rate limit defaults: submit=10, broadcast_apply=5, approve_reject=10, status_list=30 | admin_deep_dive.md | `src/admin/state.rs:118-119` | Correct |
| Session cookie: HttpOnly, Secure (release), SameSite=Strict, Max-Age=3600 | admin_deep_dive.md | `src/admin/handlers/auth.rs:48-55` | Correct |
| CSRF middleware at `middleware.rs:185-266` | admin_deep_dive.md | `src/admin/middleware.rs:185-266` | Correct |
| Auth middleware public routes (/health, /ws/*, /api/openapi.json, /api/docs/*) | admin_deep_dive.md | `src/admin/middleware.rs:110-116` | Correct |
| AuthenticatedUser always has username="admin", role=Admin | admin_deep_dive.md | `src/admin/middleware.rs:158-161` | Correct |
| AuthRateLimiter as static LazyLock | admin_deep_dive.md | `src/admin/auth.rs:139-140` | Correct |
| verify_dummy_admin_token() ensures 200ms minimum | admin_deep_dive.md | `src/admin/handlers/auth.rs:14-22` | Correct |
| Alert supported metrics list (8 metrics) | admin_deep_dive.md | `src/admin/alerting/mod.rs:5-14` | Correct |
| AlertCondition variants: GreaterThan, LessThan, Equals | admin_deep_dive.md | `src/admin/alerting/mod.rs:80-85` | Correct |
| SSRF protection blocks localhost, 127.x, 10.x, 192.168.x, 172.x | admin_deep_dive.md | `src/admin/alerting/mod.rs:146-153` | Correct |
| Audit log file permissions 0o600 | admin_deep_dive.md | `src/admin/audit.rs:73-81` | Correct (set in `with_audit_dir` and `log()`) |
| MAX_CONFIG_VERSIONS = 100 | admin_deep_dive.md | `src/admin/audit.rs:11` | Correct |
| AuthManager struct location `src/auth/mod.rs:91-103` | admin_deep_dive.md | `src/auth/mod.rs:91-103` | Correct |
| create_user location `src/auth/mod.rs:294-333` | admin_deep_dive.md | `src/auth/mod.rs:294` | Correct |
| verify_login location `src/auth/mod.rs:393-533` | admin_deep_dive.md | `src/auth/mod.rs:404` | Correct (offset ~10 lines) |
| validate_session location `src/auth/mod.rs:561-629` | admin_deep_dive.md | `src/auth/mod.rs:572` | Correct (offset ~10 lines) |
| Constant-time CSRF in auth module via `subtle::ConstantTimeEq` | admin_deep_dive.md | `src/auth/mod.rs:15` | Correct |
| MAX_SESSIONS_PER_USER = 5 | admin_deep_dive.md | `src/auth/mod.rs:37` | Correct |
| Username validation (min 1, max 64, no control chars) | admin_deep_dive.md | `src/auth/mod.rs:305-318` | Correct |
| BasicAuthResult enum: Authenticated, CredentialsRequired, Unauthorized | admin_deep_dive.md | `src/auth/basic.rs` | Correct |
| SyslogLogger struct and SyslogFacility variants | logging.md | `src/logging/syslog.rs:3-65` | Correct |
| SyslogConfig fields: facility, app_name, pid | logging.md | `src/logging/syslog.rs:21-25` | Correct |
| Public API methods (emergency, alert, critical, etc.) | logging.md | `src/logging/syslog.rs:143-177` | Correct |
| init_syslog / init_syslog_with_config | logging.md | `src/logging/syslog.rs:195-205` | Correct |
| Platform-specific: Unix syslog, non-Unix tracing fallback | logging.md | `src/logging/syslog.rs:68-125` | Correct |
| LOG_LEVEL static with LazyLock | log_controller.md | `src/log_controller.rs:5` | Correct |
| init_logging_with_dynamic_level, get_log_level, set_log_level | log_controller.md | `src/log_controller.rs:7-36` | Correct |
| set_log_level validates trace/debug/info/warn/error | log_controller.md | `src/log_controller.rs:23-26` | Correct |
| record_proxy_cache_hit/miss, get_proxy_cache_hits/misses | metrics.md | `src/metrics/collection.rs:133-147` | Correct |
| record_static_cache_hit/miss | metrics.md | `src/metrics/collection.rs:174-188` | Correct |
| record_dropped_tls_reload_event | metrics.md | `src/metrics/collection.rs:190-196` | Correct |
| get_global_bandwidth_tracker | metrics.md | `src/metrics/bandwidth.rs:33-38` | Correct |
| SiteMetrics::record_request_start, record_request_end, record_blocked | metrics.md | `src/metrics/types.rs:77-112` | Correct |
| ProtocolType enum variants | protocol.md | `src/protocol/types.rs:6-17` | Correct |
| WafAction enum variants | protocol.md | `src/protocol/trait_def.rs:34-43` | Correct |
| looks_like_dns function | protocol.md | `src/protocol/detect_common.rs:9-22` | Correct |
| extract_first_line function | protocol.md | `src/protocol/detect_common.rs:25-43` | Correct |
| register_protocol_types function | protocol.md | `src/protocol/mod.rs:11-13` | Correct |
| Submodules: grpc.rs, websocket.rs, detect_common.rs | protocol.md | `src/protocol/` | Correct |

## Discrepancies Found

### 1. Handler Count Mismatch (admin_deep_dive.md)

**Document claims:** "26 handlers + 1 feature-gated" and "3 handlers are mesh-gated = 26 total, 23 always available"

**Actual:** `src/admin/handlers/mod.rs` declares 28 handler modules total:
- 4 mesh-gated: `behavioral_intel`, `mesh_admin`, `mesh_topology`, `yara_rules`
- 24 always available

**Impact:** Documentation undercounts by 2 handlers (serverless, spin are real modules not listed in table).

### 2. Middleware Order Inverted (admin_deep_dive.md)

**Document claims (line 154-159):**
```
Request → Client IP → Auth → CSRF → Rate Limit
```

**Actual** (`src/admin/mod.rs:807-819`):
```
Request → Rate Limit (outer) → YARA Rate Limit → CSRF → Auth → Client IP (inner)
```

CSRF is applied *before* Auth in the actual code. The doc inverts the order and omits the YARA rate limit layer entirely.

**Impact:** Medium — misleading for developers extending the middleware stack.

### 3. CORS Line Reference Wrong (admin_deep_dive.md)

**Document claims:** `build_router_from_state()` at line 806.

**Actual:** `build_router_from_state()` is defined at line 173 in `src/admin/mod.rs`. Line 806 is `.layer(create_cors_layer(...))` — the CORS application point, not the function definition.

### 4. SiteMetrics Struct Heavily Simplified (metrics.md)

**Document shows 6 fields:** `total_requests, request_count, blocked, errors, latency_sum, latency_count`

**Actual** (`src/metrics/types.rs:13-27`) has 13 fields including: `challenged`, `proxied`, `current_concurrent`, `peak_concurrent`, `total_latency_ms`, `upstream_successes`, `upstream_failures`, `latency_samples`, `blocked_by_type`

Document references `latency_sum` and `latency_count` which do not exist — actual fields are `total_latency_ms` and `request_count`.

### 5. BandwidthTracker Struct Wrong (metrics.md)

**Document shows:** `inbound: AtomicU64, outbound: AtomicU64`

**Actual** (`src/metrics/bandwidth.rs:108-119`): 11+ atomic fields including `total_bytes_received`, `total_bytes_sent`, `proxied_bytes_received`, `proxied_bytes_sent`, `blocked_bytes_sent`, `challenged_bytes_sent`, `error_bytes_sent`, `http_bytes_received`, `http_bytes_sent`, `https_bytes_received`, plus additional fields.

### 6. WorkerMetrics Struct Missing Fields (metrics.md)

**Document shows:** `requests_processed, bytes_processed, active_connections`

**Actual** (`src/metrics/types.rs:198-213`): `total_requests, blocked, challenged, proxied, errors, current_concurrent, peak_concurrent, total_latency_ms, request_count, latency_samples, blocked_by_type, per_site, bandwidth, per_serverless`

### 7. Global Atomic Counters Outdated (metrics.md)

**Document shows 4 counters as plain statics:** `PROXY_CACHE_HITS, PROXY_CACHE_MISSES, STATIC_CACHE_HITS, DROPPED_EVENTS`

**Actual** (`src/metrics/collection.rs`): Uses `LazyLock<AtomicU64>` pattern. 50+ counters exist covering DHT, honeypot, threat intel, behavioral fingerprint, serverless, stall, and TLS passthrough metrics. Document lists only 4 of these.

### 8. ProtocolHandler Trait Significantly Different (protocol.md)

**Document shows simplified trait** with `Option` return types and no `metrics()`, `set_waf()`, `set_upstream_pool()` methods.

**Actual** (`src/protocol/trait_def.rs:6-32`):
- `detect()` returns `bool` (not `Option<ProtocolDetectionResult>`)
- `parse_request()` returns `Result<ProtocolRequest, ProtocolError>` (not `Option`)
- `parse_response()` returns `Result<ProtocolResponse, ProtocolError>`
- `apply_waf()` takes `&mut ProtocolRequest` and `&Arc<WafCore>` (not `&ProtocolRequest, &WafCore`)
- `select_upstream()` takes `&UpstreamPool` and returns `Option<Backend>` (not `Option<String>`)
- Extra methods: `metrics()`, `set_waf()`, `set_upstream_pool()` not documented

### 9. ProtocolDetectionResult Wrong Types (protocol.md)

**Document shows:** `confidence: f64, matched_pattern: Option<String>`

**Actual** (`src/protocol/detect_common.rs:2-6`): `confidence: f32, matched_pattern: String`

### 10. SyslogLogger Struct Incomplete (logging.md)

**Document shows:** `min_level: Level, syslog: syslog::Logger<UnixTransport>`

**Actual** (`src/logging/syslog.rs:56-65`): Uses `_backend: ()` on Unix, `app_name: String` and `_phantom: ()` on non-Unix. No `syslog` field — the syslog logger is initialized via `syslog::init_unix()` which sets up global state, not a field.

## Bugs Identified

### 1. AdminState::validate_session Race Window (Low Severity)

**Location:** `src/admin/state.rs:830-852`

The method acquires a read lock, releases it, then acquires a write lock to update `last_used`. Between the two locks, another thread could invalidate the session. This is a minor race — the session still gets validated, but the `last_used` update could be lost.

### 2. SSRF Bypass via HTTPS (Medium Severity)

**Location:** `src/admin/alerting/mod.rs:143-154`

The SSRF check only blocks private IP ranges for `http://` URLs. An `https://` URL pointing to `https://127.0.0.1:8443/webhook` would pass validation. This could be exploited if the alerting webhook sends to an internal HTTPS endpoint.

### 3. Audit Log Permissions Set Per-Write (Performance)

**Location:** `src/admin/audit.rs:131-139`

File permissions are re-applied on every audit log write via `std::fs::set_permissions()`. This is redundant — permissions should be set once in `with_audit_dir()` (which already does this at line 73-81). The per-write call adds unnecessary I/O overhead.

### 4. Email Alerting is Stub Implementation (Functional Gap)

**Location:** `src/admin/alerting/mod.rs:349-373`

`send_email_internal()` extracts SMTP config, logs a message, then returns `Ok(())` without actually sending email. The function is a stub — email alerts will silently do nothing.

## Suggested Improvements

### 1. Correct Middleware Order Documentation

Update `admin_deep_dive.md` lines 154-159 to reflect actual middleware order:
```
Request → Rate Limit → YARA Rate Limit → CSRF → Auth → Client IP Extraction
```
Add YARA rate limit layer to the documented stack.

### 2. Update Handler Count

Change "26 handlers + 1 feature-gated" to "28 handler modules (24 always available, 4 mesh-gated)" and update the handler table to include `serverless` and `spin` (if not already listed — `spin` is listed but `serverless` is not in the table).

### 3. Expand SiteMetrics Documentation

Document all 13 fields of `SiteMetrics` with their purpose, not just 6.

### 4. Correct BandwidthTracker Documentation

Replace the simplified 2-field struct with the actual 11+ field struct or at minimum describe the key fields.

### 5. Correct WorkerMetrics Documentation

Replace the 3-field simplified struct with the actual struct or describe the important fields.

### 6. Expand Global Counters Section

Document the full set of 50+ global atomic counters, or at minimum document the categories (cache, dropped events, DHT, honeypot, threat intel, serverless, stall, TLS passthrough).

### 7. Update ProtocolHandler Trait

Replace the simplified trait with the actual trait definition, including correct return types and all methods.

### 8. Fix ProtocolDetectionResult Types

Change `f64` to `f32` and `Option<String>` to `String`.

### 9. Fix SyslogLogger Documentation

Update the struct to reflect the actual platform-conditional fields.

### 10. Fix CORS Line Reference

Change "line 806" to "line 173" for `build_router_from_state()` definition, or clarify that 806 is where the CORS layer is applied.

### 11. Consider SSRF Fix for HTTPS URLs

Extend the SSRF check to also validate HTTPS URLs against private IP ranges. The current `if url_lower.starts_with("http://")` guard excludes HTTPS URLs from SSRF checks entirely.

## Stale Content

### 1. Protocol.md Trait Definition

The documented `ProtocolHandler` trait appears to be from an earlier design iteration. The actual implementation has diverged significantly with `Result` return types, additional lifecycle methods (`set_waf`, `set_upstream_pool`), and a `metrics()` method.

### 2. Metrics.md Static Counter Declarations

The document uses `static PROXY_CACHE_HITS: AtomicU64 = AtomicU64::new(0);` syntax. The actual code uses `LazyLock<AtomicU64>` which is necessary because `AtomicU64::new()` is `const` but the `LazyLock` pattern is used for consistency with other counters that need initialization.

### 3. Metrics.md Struct Definitions

All three documented structs (SiteMetrics, BandwidthTracker, WorkerMetrics) appear to be from an early design phase and do not reflect the current implementation with concurrent tracking, upstream health, per-site breakdowns, and protocol-aware bandwidth.

## Cross-Reference Status

| AGENTS.md Item | Document | Status |
|----------------|----------|--------|
| BUG-CORS-1: CORS config dropped (underscore prefix) | admin_deep_dive.md:161 | **Acknowledged** — doc correctly notes CORS gap on nested `/api` routes and references BUG-CORS-1 |
| CSRF validation constant-time comparison (verified fixed) | admin_deep_dive.md:61, 334 | **Verified** — `ct_eq()` at `state.rs:737-742` confirmed |
| Audit log file permissions (verified fixed) | admin_deep_dive.md:397, 412 | **Verified** — 0o600 permissions set at `audit.rs:73-81` and `audit.rs:131-139` |
| gRPC uptime calculation (verified fixed) | Not directly covered | N/A — gRPC uptime is in supervisor, not admin module |
| SUP-1 gRPC Control Plane TLS | Not directly covered | N/A — separate module |
| BUG-DNS-1: DNS recursor DNSSEC policy | Not covered | N/A — DNS module |
| Admin token bcrypt cost default 12 | admin_deep_dive.md:31 | **Verified** — `BCRYPT_COST: u32 = 12` at `auth.rs:9` |
| Rate limiter requests_per_minute/second windows | admin_deep_dive.md:302-305 | **Verified** — `AdminRateLimitConfig` in `rate_limit.rs:10-13` |
| Session cookie security flags | admin_deep_dive.md:410 | **Verified** — HttpOnly, Secure (release), SameSite=Strict |
| Auth store file permissions 0o700 dir, 0o600 files | admin_deep_dive.md:412 | **Needs verification** — `auth/store.json` permissions not checked in this review |
