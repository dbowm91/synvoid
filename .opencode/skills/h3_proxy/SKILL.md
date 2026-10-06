---
name: h3_proxy
description: HTTP/3 QUIC proxy architecture, streaming implementation, and WAF integration.
---

# HTTP/3 and QUIC Proxy Implementation

This skill documents the HTTP/3 (QUIC) proxy architecture, integration with the WAF, and the streaming implementation.

## Overview

SynVoid provides full HTTP/3 support via the `quinn` and `h3` crates. The implementation acts as a reverse proxy, terminating QUIC/TLS connections and forwarding requests to upstreams.

## Key Components

### HTTP/3 Server (`crates/synvoid-http3/src/server.rs`)

The `Http3Server` manages the QUIC endpoint and H3 connection lifecycle.

- **QUIC Stack**: Powered by `quinn` 0.11.
- **H3 Protocol**: Powered by `h3` 0.0.8 and `h3-quinn` 0.0.10.
- **TLS Configuration**: Integrated with `rustls` via `quinn::crypto::rustls::QuicServerConfig`.

### Request Handling Flow

1. **QUIC Accept**: New connections are accepted and passed to `handle_quic_connection`.
2. **Flood Protection**: Early IP-based filtering via `FloodProtector`.
3. **H3 Handshake**: Establishing the H3 connection over QUIC.
4. **WAF Scanning**: full request body collection (up to `max_request_size`) and scanning via `WafCore::check_request_full`. Dispatch of the resulting `WafDecision` is exhaustive per the enforcement decision contract (`architecture/enforcement_decision_contract.md`); HTTP/3 renders via `maybe_handle_http3_waf_decision` in `crates/synvoid-http3/src/http3_waf_dispatch.rs`.
5. **Routing**: Host and path-based routing via `Router`.
6. **Connection Limiting**: Per-site and per-IP connection limits enforced.
7. **Proxying**: upstream forwarding runs on the **eggfetch lane** via
   `UpstreamClientRegistry::get_or_create_lane(site_id, policy)` +
   `execute(...)` — `crates/synvoid-http3/src/http3_buffered_upstream_dispatch.rs`
   and `http3_streaming_upstream_dispatch.rs`. The frozen legacy
   `send_request_streaming` / `send_request_streaming_generic` helpers in
   `synvoid-http-client` are NOT the HTTP/3 path.
8. **Body Streaming**: Asynchronous piping of upstream response body back to the H3 stream.

## Implementation Details

### QUIC Server Configuration

```rust
let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
```

### Upstream Proxying

HTTP/3 proxying leverages the common `HttpClient` but requires special handling for the response stream to ensure efficient piping of frames:

```rust
while let Some(chunk) = upstream_body.frame().await {
    match chunk {
        Ok(frame) => {
            if let Some(data) = frame.data_ref() {
                request_stream.send_data(data.clone()).await?;
                // Bandwidth tracking...
            }
        }
        Err(e) => break,
    }
}
```

## Configuration

| Option | Location | Default |
|--------|----------|---------|
| `http3.enabled` | `[http3]` in `main.toml` | `false` |
| `http3.port` | `[http3]` in `main.toml` | `443` |
| `max_request_size` | `[http3]` in `main.toml` | `10MB` (distinct from `[http].max_request_size`, default `1MB`) |
| `alt_svc_max_age` | `[http3]` in `main.toml` | `86400` |

(Schema: `crates/synvoid-config/src/http.rs::Http3Config`.)

## Performance Considerations

- **Body Collection**: Current implementation collects the full request body for WAF scanning before proxying. This ensures high security but adds latency for large POST requests.
- **Buffer Reuse**: Leveraging `Bytes` and `BytesMut` for zero-copy data handling where possible.
- **Connection Pooling**: QUIC connections are multiplexed, but upstream connections use the standard HTTP/1.1 or H2 pool.

## Observability

Metrics are emitted through `metrics::` macros across
`crates/synvoid-http3/src/` (`server.rs`, `http3_request_flow.rs`,
`http3_route_dispatch.rs`, `http3_request_dispatch.rs`, `http3_body.rs`,
`http3_waf_dispatch.rs`, `http3_terminal.rs`). There is no single registry
struct; representative names:
- `synvoid.http3.connections` (gauge) / `synvoid.http3.connections.total` (counter)
- `synvoid.http3.responses` (counter)
- `synvoid.http3.requests.blocked`, `.challenged`, `.tarpitted`, `.not_found`,
  `.stalled`, `.stall_capped` (counters)
- `synvoid.http3.request.duration` (histogram), `synvoid.http3.request.errors` (counter)
- `synvoid.http3.enforcement_class_total` (counter, labelled by enforcement class)

There is **no `synvoid.http3.requests.total`** metric — do not reference it.

---

## Request Pipeline Normalization (Iteration 99)

The HTTP/3 dispatch function `handle_http3_request_dispatch` now takes `Http3RequestMetadata` (grouped request fields)
and `Http3DispatchDeps` (grouped service handles) instead of 21 discrete parameters. The pipeline stages are:
metadata normalization → route resolution → body policy → WAF evaluation → terminal response → upstream dispatch → accounting.
See `architecture/http_request_pipeline.md` for the full stage map.

Last updated: 2026-10-06
