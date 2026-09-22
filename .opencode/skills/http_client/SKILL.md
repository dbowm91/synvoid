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

## Phase 60/61: eggfetch lane is canonical (binding)

Production egress runs on the eggfetch lane, not the legacy hyper pool:

- Lane owner: `crates/synvoid-http-client/src/eggfetch_transport.rs`
  (`EggfetchUpstreamClient`: `build`/`cached`/`build_uds`/`execute`/
  `send_buffered`/`send_uds_buffered`; `SyncBody`; `native_to_httpresponse`).
- Policy translation: `eggfetch_policy.rs` (`UpstreamTlsConfig` stays
  canonical; `allow_plaintext` is a routing gate, never a TLS toggle).
- Site selection: `UpstreamClientRegistry::get_or_create_lane` (single
  site-keyed map; policy-keyed pool sharing underneath).
- Root operator plane (`src/admin`, `src/waf`) uses the entitled facade
  `crate::http_client::operator_lane_client()` — never `synvoid_http_client`
  directly (root dependency ledger).
- The legacy surface (`HttpClient`, `create_*`, `send_*`, erased pool/body
  types) is FROZEN compatibility-only: keep compiling + tested, never use
  in new production code. Enforced by
  `tools/synvoid-repo-guards/tests/eggfetch_lane_freeze.rs`.
- Buffered parity rule: pass `max=None` to `send_buffered` and enforce size
  limits post-hoc (→502); the lane-internal limit maps oversize to
  200-empty, which changes legacy behavior.
- Full record: `architecture/eggfetch_0_2_transport_closeout.md`.
