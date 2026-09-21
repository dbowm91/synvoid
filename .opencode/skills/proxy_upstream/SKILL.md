---
name: proxy_upstream
description: Reverse proxy engine and upstream pool — dispatch, load balancing, retry/backoff, header filtering, proxy caching. Canonical code lives in crates/synvoid-proxy.
---

# Skill: Proxy & Upstream Engine

## Context

The reverse proxy is the core data-plane forwarding path. Implementation lives in
`crates/synvoid-proxy/src/`; `src/proxy/*.rs` files are **compat re-export shims only**
(do not add new code there).

Full reference: `architecture/proxy.md`, `architecture/upstream.md`, `architecture/proxy_cache.md`.
Subsystem rules: `src/proxy/AGENTS.override.md`.

## When to Use

Use this skill when:
- Changing upstream dispatch, load balancing, or backend selection
- Modifying retry/backoff or upstream failure tracking
- Touching hop-by-hop header filtering or XFF handling
- Working on proxy caching (`crates/synvoid-proxy-cache/`)
- Adding a new `BackendType` routing mode

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-proxy/src/server.rs` | `ProxyServer`: construction, `handle_request*`, cache hooks |
| `crates/synvoid-proxy/src/dispatch.rs` | Upstream dispatch entry |
| `crates/synvoid-proxy/src/executor.rs` | Request building + response handling |
| `crates/synvoid-proxy/src/router.rs` | Routing + `BackendType` enum (Upstream, FastCgi, Static, QuicTunnel, Serverless, Mesh, Spin, ...) |
| `crates/synvoid-proxy/src/headers.rs` | Header filtering, XFF validation/truncation |
| `crates/synvoid-proxy/src/retry.rs` | Retry conditions + `calculate_backoff` (exp cap 2^5, 30s max) |
| `crates/synvoid-upstream/src/` | Backend pool, health checking, load-balance algorithms |
| `crates/synvoid-proxy-cache/src/key.rs` | Cache keys: `uri` field is `"<ahash_hex>:<path_and_query>"`, not raw URI |

## Non-Negotiables

1. **Composition boundary**: request-path code consumes narrow traits; concrete infra
   (BlockStore, ThreatIntelligenceManager) is wired only in composition roots.
   See `architecture/request_path_capability_boundary.md`.
2. **Retries are bodyless-only**: proxied request bodies are one-shot streams; retries
   never replay bodies. Idempotent methods only unless `retry_non_idempotent`.
3. **Cache bypass**: requests carrying `Authorization`, `Proxy-Authorization`, or `Cookie`
   skip shared-cache lookup; responses with `Set-Cookie` / private / no-store are not stored.
4. **Known limitation**: `ErasedHttpClient::new(100)` hardcodes pool size in
   `ProxyServer` regardless of config.
5. **Allocation-free selection** (Phase 51): `UpstreamPool` algorithms select
    over the backend slice through predicates — no per-request candidate
    vectors, no cloned weighted vector. Preserve exact
    ordering/failover/weight/hash semantics; parity is pinned by
    `crates/synvoid-upstream/tests/selection_parity.rs`. Do not change the
    load-balancing policy while touching selection mechanics.
6. **Strict tee reservation** (Phase 56): `TeeBody` never buffers beyond
    `min(reserved_bytes, max_size)` (checked arithmetic); overshoot abandons
    caching only via `abandon_cache_buffering()` with immediate exact-once
    governor release — never truncate/stall/reject the response. Pinned by
    `crates/synvoid-proxy/src/streaming.rs` `streaming_tests`.

## Verification

```bash
cargo nextest run -p synvoid-proxy --cargo-profile ci --profile ci
cargo nextest run -p synvoid-proxy-cache --cargo-profile ci --profile ci
cargo nextest run -p synvoid-upstream --cargo-profile ci --profile ci
```
