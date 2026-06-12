# HTTP/3 Server Module - AGENTS.override.md

Specialized guidance for HTTP/3 QUIC request handling and proxying.

## Hot Path

`crates/synvoid-http3/src/server.rs` — HTTP/3 QUIC request handling and proxying executes on every request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### QUIC Connection Handling

- Connection state management is per-connection
- Stream multiplexing requires careful buffer management

### Architecture Boundary

- `Http3WafBackend` trait is defined in `crates/synvoid-http3/src/lib.rs`
- Server accepts WAF as `Arc<dyn Http3WafBackend>` (trait object)
- Concrete `WafCore` stays in root; only trait objects flow into HTTP/3
- `bind_udp_reuse` comes from `synvoid-platform` crate
- Root re-exports `Http3Server` and `Http3WafBackend` via `src/http3/mod.rs`
- **No root-crate imports** — HTTP/3 depends only on intermediate library crates

### WAF Ownership Rules

| Owner | Scope |
|-------|-------|
| `crates/synvoid-http3` | HTTP/3 protocol handling only |
| `crates/synvoid-waf` | WAF traits (`WafAccess`, `WafProcessor`) and primitives (`WafDecision`) |
| `crates/synvoid-http` | `Http3RequestWaf` trait, dispatch functions, WAF decision mapping |
| `src/waf/` | Concrete `WafCore` and infrastructure adapters |
| `src/worker/unified_server/` | Composition, service injection |

### Forbidden in HTTP/3

The HTTP/3 crate must NOT import:
- `BlockStore`, `BlockListStore` (concrete type)
- `ThreatIntelligenceManager`
- `ChallengeManager`
- `GeoIpManager`
- `ViolationTracker`
- `WafCore`, `WafProcessor` (concrete type)
- Any `crate::waf`, `crate::block_store`, `crate::challenge`, `crate::geoip`, `crate::mesh` paths

### Boundary Guard Test

`tests/http3_waf_boundary_guard.rs` scans `crates/synvoid-http3/` for forbidden concrete imports. Run with:
```bash
cargo test --test http3_waf_boundary_guard
```

### WAF Decision Mapping (HTTP/3 vs HTTP/1/2)

| Decision | HTTP/1/2 | HTTP/3 | Parity |
|----------|----------|--------|--------|
| `Pass` | Continue | Continue | ✅ |
| `Block(status, msg)` | HTML via error_page_manager | JSON `{"error":"..."}` | ⚠️ Format differs |
| `Drop` | 404 empty body | Silent drop | ⚠️ Semantically equivalent |
| `Challenge` | 200 HTML + Alt-Svc | 200 HTML | ⚠️ Alt-Svc missing |
| `ChallengeWithCookie` | Set-Cookie (SameSite=Strict) | Set-Cookie (SameSite=Strict; HttpOnly) | ⚠️ HttpOnly differs |
| `Tarpit` | 200 tarpit HTML | 200 tarpit HTML | ✅ |
| `Stall` | Concurrency-capped (429 on cap) | Concurrency-capped (429 on cap) | ✅ |

All stall paths (full request, HTTP/3, streaming WAF, TLS) enforce the concurrency cap via `StallPermit::try_new()`. When the cap is reached, a 429 response is returned immediately without sleeping.

### Streaming Body WAF

HTTP/3 uses the same `StreamingWafScanner` trait as HTTP/1/2. Body collection flows through `collect_http3_request_body()` with QUIC flow control providing backpressure. Body size bounded by `config.max_request_size`.

### Request Context Construction

Both HTTP/1/2 and HTTP/3 pass individual fields to WAF check functions (not a `RequestContext` struct). The `RequestContext` type is only used in the proxy/gateway path.

## Skills Reference

- `skills/h3_proxy.md` — H3 proxy patterns
- `architecture/http3_request_waf_boundary.md` — Full boundary documentation
