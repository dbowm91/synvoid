---
name: http_client
description: Generic upstream HTTP transport — pooling, TLS, Unix sockets, type-erased bodies. Use when touching upstream connections; policy adapters live one layer up.
---

# HTTP Client (Generic Transport)

## Overview

`crates/synvoid-http-client/` is the **policy-free generic transport core**
(Phase 34 decision: `architecture/egress_client_decision_phase34.md`). It owns
connection pooling, TLS clients, Unix-socket transport, and type-erased bodies.
It must NOT gain `synvoid-config`, `synvoid-core`, metrics, or WAF edges.

## Key Files

- `crates/synvoid-http-client/src/client.rs` - `HttpClient` /
  `StreamingHttpClient`, `create_http_client*` / `create_upstream_*` entry
  points, `EmptyBody`
- `crates/synvoid-http-client/src/pool.rs` - Connection pooling
- `crates/synvoid-http-client/src/erased_pool.rs` - `ErasedBody`,
  `ErasedBodyImpl`, `ErasedConnectionPool`, `ErasedHttpClient`, `PoolKey`,
  `BoxErasedBody` (type-erased bodies incl. `StreamingWafBody` wrapping)
- `crates/synvoid-http-client/src/request.rs` - `send_request_streaming`,
  `send_request_streaming_generic<B>` (generic over body type)
- `crates/synvoid-http-client/src/response.rs` - Response handling
- `crates/synvoid-http-client/src/tls.rs` - TLS client construction
- `crates/synvoid-http-client/src/unix.rs` - Unix-socket transport (cfg unix)

## Phase 34 Boundary (binding)

Policy adapters live one layer up — import from there, never reimplement here:

| Capability | Canonical home |
|---|---|
| Site config → TLS | `synvoid_upstream::tls_adapter` (`upstream` skill) |
| WAF-scanning bodies | `synvoid_http::streaming_waf_body` (`streaming_waf` skill) |
| QUIC/tunnel dispatch | root `src/http_client/quic_tunnel_dispatch.rs` |
| H3 upstream dispatch | `synvoid_http::{http3_buffered_upstream_dispatch, http3_streaming_upstream_dispatch}` |

`is_quictunnel_url` stays here only as a dependency-free scheme predicate
(no I/O, no tunnel state) so existing dispatch call sites keep compiling.

## Verification

```bash
cargo nextest run -p synvoid-http-client --cargo-profile ci --profile ci
```
