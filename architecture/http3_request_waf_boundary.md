# HTTP/3 Request/WAF Composition Boundary

## 1. Ownership Rules

| Owner | Scope |
|-------|-------|
| `crates/synvoid-http3` | HTTP/3 QUIC protocol handling only |
| `crates/synvoid-waf` | WAF engine traits (`WafProcessor`, `WafAccess`, `BlockListStore`, etc.) and primitives (`WafDecision`) |
| `crates/synvoid-http` | Protocol-neutral request dispatch, WAF decision mapping, body collection |
| `src/waf/` | Concrete WAF implementation (`WafCore`) and infrastructure adapters |
| `src/worker/unified_server/` | Data-plane composition, service injection, worker lifecycle |

### Required Invariants

1. **`crates/synvoid-http3` owns HTTP/3 protocol handling only.** It accepts WAF as `Arc<dyn Http3WafBackend>` and must never import concrete root-owned types.
2. **`crates/synvoid-http3` depends only on narrow traits.** It may use `Http3RequestWaf`, `WafAccess`, and shared DTOs (`WafDecision`, `ConnectionLimiter`, `FloodProtector`). It must not import `BlockStore`, `ThreatIntelligenceManager`, `GeoIpManager`, `ChallengeManager`, or violation persistence.
3. **`crates/synvoid-waf` owns WAF semantics and service traits.** Infrastructure traits (`BlockListStore`, `GeoIpLookup`, `ChallengeService`, `WafPersistence`) are defined here.
4. **`src/waf/adapters.rs` bridges root services to WAF crate traits.** `BlockStoreAdapter`, `GeoIpAdapter`, `ChallengeServiceAdapter`, `ViolationPersistenceAdapter` live here.
5. **`src/worker/unified_server/` owns composition.** Concrete services are constructed and injected into the WAF and HTTP layers here.
6. **HTTP/3 must not construct or fetch `BlockStore`, `ThreatIntelligenceManager`, `GeoIpManager`, `ChallengeManager`, or violation persistence directly.**
7. **Request/WAF hot paths must not perform DHT/network lookups** for policy decisions.
8. **Body streaming WAF must preserve backpressure** and not buffer unbounded bodies.

---

## 2. Integration Surface Inventory

### HTTP/3 Crate (`crates/synvoid-http3`)

| Surface | File | Classification |
|---------|------|----------------|
| `Http3WafBackend` trait | `lib.rs:21` | Protocol adapter (composite trait boundary) |
| `Http3Server` struct | `server.rs:20` | Protocol adapter |
| `Http3Server::handle_request()` | `server.rs:205` | Protocol adapter — calls `prepare_http3_request_dispatch` + `handle_http3_request_dispatch` |
| WAF connection limiter access | `server.rs:218,264` | Protocol adapter — delegates to `WafAccess` trait |
| WAF streaming scanner access | `server.rs:261-262` | Protocol adapter — delegates to `WafAccess` trait |
| WAF bandwidth check | `server.rs:219` | Protocol adapter — delegates to `WafAccess` trait |

### HTTP Dispatch (`crates/synvoid-http`)

| Surface | File | Classification |
|---------|------|----------------|
| `Http3RequestWaf` trait | `http3_request_dispatch.rs:28` | WAF service adapter (narrow trait for HTTP/3) |
| `handle_http3_request_dispatch()` | `http3_request_dispatch.rs:79` | Worker/data-plane composition (delegates to WAF) |
| `maybe_handle_http3_waf_decision()` | `http3_waf_dispatch.rs:47` | WAF decision mapping (HTTP/3-specific) |
| `collect_http3_request_body()` | `http3_body.rs` | Body streaming adapter |
| `stream_body_with_waf()` | `shared_handler.rs:304` | Body streaming adapter |
| `collect_body_with_chunk_waf()` | `shared_handler.rs:319` | Body streaming adapter |

### WAF Crate (`crates/synvoid-waf`)

| Surface | File | Classification |
|---------|------|----------------|
| `WafDecision` enum | `primitives.rs:4` | WAF core (shared DTO) |
| `WafAccess` trait | `access.rs:19` | WAF service adapter (narrow infrastructure trait) |
| `WafProcessor` trait | `traits.rs:147` | WAF core (engine trait) |
| `BlockListStore` trait | `traits.rs:15` | WAF core (infrastructure trait) |
| `ErasedBlockStore` | `traits.rs:69` | WAF core (type-erased wrapper) |
| `ConnectionLimiter` | `flood/connection_limiter.rs` | WAF core (shared DTO) |
| `StreamingWafScanner` | `synvoid-core/streaming_waf.rs` | Body streaming adapter (core trait) |

### Root WAF (`src/waf/`)

| Surface | File | Classification |
|---------|------|----------------|
| `WafCore` struct | `mod.rs:98` | WAF core (concrete implementation) |
| `impl Http3RequestWaf for WafCore` | `mod.rs:132` | WAF service adapter |
| `impl WafAccess for WafCore` | `mod.rs:1085` | WAF service adapter |
| `BlockStoreAdapter` | `adapters.rs` | WAF service adapter (bridge) |
| `GeoIpAdapter` | `adapters.rs` | WAF service adapter (bridge) |
| `ChallengeServiceAdapter` | `adapters.rs` | WAF service adapter (bridge) |
| `ViolationPersistenceAdapter` | `adapters.rs` | WAF service adapter (bridge) |

### Worker Composition (`src/worker/unified_server/`)

| Surface | File | Classification |
|---------|------|----------------|
| `DataPlaneServices` | `services.rs:26` | Worker/data-plane composition |
| `UnifiedServer` HTTP/3 spawn | `src/server/mod.rs:984` | Worker/data-plane composition |
| `state.waf` injection | `src/server/mod.rs:1295` | Worker/data-plane composition |

---

## 3. Dependency Direction

```
crates/synvoid-http3
  ├── synvoid-http      (Http3RequestWaf, dispatch functions)
  ├── synvoid-waf       (WafAccess, WafDecision, ConnectionLimiter)
  ├── synvoid-core      (StreamingWafScanner — test only)
  ├── synvoid-config    (Http3Config, MainConfig, SiteBotConfig)
  ├── synvoid-proxy     (Router, UpstreamClientRegistry)
  ├── synvoid-http-client (HttpClient)
  ├── synvoid-metrics   (WorkerMetrics, bandwidth)
  └── synvoid-platform  (bind_udp_reuse)

  ✗ NO root crate imports (no `use synvoid::`)
  ✗ NO concrete WafCore, BlockStore, ThreatIntelligenceManager
```

Expected flow:
- HTTP/3 → narrow traits (via intermediate crates)
- Root/worker → HTTP/3 (provides concrete adapter implementing `Http3WafBackend`)

---

## 4. Request Context Construction

Both HTTP/1/2 and HTTP/3 pass **individual fields** to WAF check functions rather than building a `RequestContext` struct. The `RequestContext` type (defined in `synvoid-core`) is only used in the proxy/gateway path (`crates/synvoid-proxy/src/server.rs`).

### HTTP/3 WAF Check Parameters

```rust
// crates/synvoid-http/src/http3_request_dispatch.rs:163-176
waf.check_request_full(
    waf_site_id,        // Option<&str> — from route or host
    client_ip,          // IpAddr
    method.as_str(),    // &str
    path,               // &str
    query_string,       // Option<&str>
    headers,            // &HeaderMap
    waf_body_slice,     // Option<&[u8]> — None if stream-scanned
    user_agent,         // Option<&str>
    None,               // ja4_hash — not available in QUIC
    waf_bot_config,     // Option<&SiteBotConfig>
)
```

### HTTP/1/2 Buffered WAF Check Parameters

```rust
// crates/synvoid-http/src/http_request_postlude.rs:265-277
waf.check_request_full_owned(
    Some(site_id),
    client_ip,
    method_str,
    path,
    query_string,
    headers,
    None,               // body — already scanned in streaming path
    user_agent,
    None,               // ja4_hash
    Some(site_bot_config),
)
```

### Parity Assessment

| Field | HTTP/1/2 | HTTP/3 | Parity |
|-------|----------|--------|--------|
| client_ip | ✅ | ✅ | ✅ |
| method | ✅ | ✅ | ✅ |
| path | ✅ | ✅ | ✅ |
| query | ✅ | ✅ | ✅ |
| host/site_id | ✅ | ✅ | ✅ |
| headers | ✅ | ✅ | ✅ |
| body | ✅ (deferred) | ✅ (deferred) | ✅ |
| user_agent | ✅ | ✅ | ✅ |
| ja4_hash | None | None | ✅ |
| site_bot_config | ✅ | ✅ | ✅ |
| Early WAF check | ✅ (`early_waf_decision`) | ❌ | Gap |
| Challenge path routes | ✅ (`maybe_handle_challenge_paths`) | ❌ | Gap |

**Gaps documented but intentionally accepted:**
- HTTP/3 has no pre-routing early WAF check — all checks happen post-routing.
- HTTP/3 has no challenge path route interception (CSS honeypot, asset tracking).
- These are HTTP/1/2-specific UX features that rely on browser-rendered challenge pages, which are not applicable to API-only HTTP/3 clients.

---

## 5. WAF Decision Mapping

| Decision | HTTP/1/2 Response | HTTP/3 Response | Parity |
|----------|-------------------|-----------------|--------|
| `Pass` | Continue | Continue | ✅ |
| `Block(status, msg)` | HTML via `error_page_manager` | JSON `{"error":"..."}` | ⚠️ Format differs |
| `Drop` | 404 empty body, blackhole counter | Silent drop, no response | ⚠️ Semantically equivalent |
| `Challenge(_, html)` | 200 HTML body, Alt-Svc header | 200 HTML body | ⚠️ Alt-Svc missing in HTTP/3 |
| `ChallengeWithCookie` | 200 HTML + Set-Cookie (SameSite=Strict) | 200 HTML + Set-Cookie (SameSite=Strict; HttpOnly) | ⚠️ HttpOnly differs |
| `Tarpit(path)` | 200 tarpit HTML body | 200 tarpit HTML body | ✅ |
| `Stall` | Concurrency-capped (429 on cap) | Concurrency-capped (429 on cap) | ✅ |

**Stall concurrency** is guarded by strict RAII permits (`StallPermit` in `synvoid-metrics`). Acquisition uses `fetch_update` for atomic cap enforcement. Drop always releases the active slot. Streaming WAF stall paths also enforce the cap and return 429 when no permit is available.

### Known Parity Gaps (Accepted)

1. **Block response format**: HTTP/1/2 returns themed HTML; HTTP/3 returns JSON. HTTP/3 clients typically don't render HTML error pages.
2. **Challenge cookie**: HTTP/3 adds `HttpOnly` flag; HTTP/1/2 does not. Intentional — HTTP/3 API clients don't need JS access to the cookie.
3. **Alt-Svc header**: Only meaningful in HTTP/1/2 responses to advertise HTTP/3. Not applicable to HTTP/3 responses.

---

## 6. Streaming Body WAF Behavior

### HTTP/3 Body Collection Flow

1. `collect_http3_request_body()` in `crates/synvoid-http/src/http3_body.rs` reads the QUIC stream.
2. If `stream_scanned_upstream_mode` is true, body bytes are passed to `StreamingWafScanner::scan_chunk()` during collection.
3. Terminal WAF decisions during streaming cause early termination (response sent via QUIC stream).
4. Backpressure is preserved via QUIC flow control.
5. Body size is bounded by `config.max_request_size`.

### HTTP/1/2 Body Collection Flow

1. `stream_body_with_waf()` in `crates/synvoid-http/src/shared_handler.rs:304` wraps the body with a streaming WAF scanner.
2. `collect_body_with_chunk_waf()` collects the full body via the scanner.
3. `collect_and_scan_request_body()` in `crates/synvoid-http/src/body_policy.rs:23` orchestrates the flow.
4. Backpressure is preserved via hyper body framing.

### Comparison

| Aspect | HTTP/1/2 | HTTP/3 |
|--------|----------|--------|
| Header scan before body | ✅ (early WAF) | ✅ (full WAF post-routing) |
| Chunk/stream scanning | ✅ `StreamingWafScanner` | ✅ `StreamingWafScanner` |
| Backpressure | ✅ hyper body framing | ✅ QUIC flow control |
| Terminal decision stops reading | ✅ | ✅ |
| Unbounded buffering | No (bounded by config) | No (bounded by config) |
| Body limits | Same config (`max_request_size`) | Same config (`max_request_size`) |

**Status**: Streaming body WAF behavior is consistent across protocols. HTTP/3 uses the same `StreamingWafScanner` trait and bounded body collection.

---

## 7. Mechanical Guardrails

A source-scan guard test exists at `tests/http3_waf_boundary_guard.rs` that scans `crates/synvoid-http3/` for forbidden concrete imports. See that file for details.

The existing `tests/threat_intel_boundary_guard.rs` also covers `crates/synvoid-http3/` in its denylist directories.

---

## 8. Non-Goals and Future Work

### Non-Goals
- Do not redesign the WAF engine.
- Do not add new WAF detection features.
- Do not change threat-intel policy semantics.
- Do not perform a large protocol rewrite.
- Do not enforce mesh-ID blocks at the request path. Mesh-ID blocks are control-plane/admin scoped only (Iteration 51, Outcome A). `RequestContext` and all WAF trait signatures lack a mesh identity field. External HTTP clients do not present mesh credentials. A guardrail test (`tests/mesh_id_boundary_guard.rs`) prevents `is_mesh_id_blocked()` from being called in request-path code.

### Future Work
- **Early WAF check for HTTP/3**: Consider a lightweight pre-routing check if HTTP/3 adoption grows for browser clients.
- **Challenge path routes for HTTP/3**: If CSS challenge pages become relevant for HTTP/3 clients.
- **Block response format parity**: Consider serving themed HTML blocks to HTTP/3 if browser clients become common.

---

## 9. Verification

```bash
cargo test --test http3_waf_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test -p synvoid-http3
cargo test -p synvoid-waf
cargo test -p synvoid-http
cargo test --lib --no-run
```
