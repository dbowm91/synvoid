# ProxyServer API Parity

Generated: 2026-06-07

The root `src/proxy/mod.rs` is now a compatibility shim re-exporting
`synvoid_proxy::ProxyServer<RootWafProcessor>`. All logic lives in
`crates/synvoid-proxy/src/server.rs`.

## Public API Surface

| Method | Present | Description |
|--------|---------|-------------|
| `new` | Yes | Constructor, delegates to `new_with_pool_config` |
| `new_with_tls` | Yes | Constructor with TLS config |
| `new_with_pool_config` | Yes | Full constructor with pool params |
| `with_upstream_pool` | Yes | Builder: attach upstream pool + retry/buffering config |
| `with_cache` | Yes | Builder: attach proxy cache |
| `with_http2` | Yes | Builder: enable HTTP/2 upstream |
| `with_proxy_headers_config` | Yes | Builder: set proxy headers config |
| `with_quic_tunnel_sender` | Yes | Builder: set QUIC tunnel sender |
| `handle_request` | Yes | Main entry point: WAF check → forward |
| `forward_request_via_tunnel` | Yes | Forward to tunnel URL |
| `handle_request_with_cache` | Yes | Cache-aware request handling (PURGE, SWR, tee) |
| `invalidate_cache` | Yes | Invalidate cache entries by path pattern |
| `invalidate_cache_by_host` | Yes | Invalidate all cache entries for a host |

## Private / Internal Methods

| Method | Description |
|--------|-------------|
| `forward_request` | Dispatch to pool or single upstream |
| `forward_with_pool` | Retry loop across pool backends |
| `send_single_request` | Send via erased client (HTTP or QUIC) |
| `handle_cache_purge` | Auth + purge logic (token or IP allowlist) |
| `process_cache_invalidate_header` | Honor `X-Cache-Invalidate` on response |
| `is_cacheable_method` | Check method against cache settings |
| `should_bypass_cache` | Check Cache-Control for bypass |
| `get_cache_max_age` | Parse max-age from response headers |
| `build_cached_response` | Reconstruct response from cache entry |
| `is_response_cacheable_headers` | Validate status + headers for caching |
| `revalidate_cache_entry` | Background SWR revalidation |

## Items Checked

| Item | Exists? | Notes |
|------|---------|-------|
| `with_cache_purge` | **No** | Cache purge is handled internally via `handle_cache_purge` (called from `handle_request_with_cache` when method is `PURGE`). No builder method for setting purge token/IP allowlist — these are set on the struct fields directly (not exposed as a public builder). |
| `with_quic_tunnel_sender` | **Yes** | `server.rs:263` |
| `handle_request` | **Yes** | Main entry point at `server.rs:268` |

## Behavioral Notes

- `handle_request` performs connection limiting, WAF inspection (full body ≤ 1MB), then calls `forward_request`.
- `forward_request` is private — callers should use `handle_request` or `handle_request_with_cache`.
- `handle_request_with_cache` handles `PURGE` method inline, delegates to private `handle_cache_purge`.
- Cache purge auth uses constant-time comparison (`ct_eq`) for tokens.
- `send_single_request` routes to QUIC tunnel if URL matches `is_quictunnel_url`, otherwise uses `ErasedHttpClient`.

## Compilation

`cargo check -p synvoid-proxy` passes (2 warnings: unused imports).
