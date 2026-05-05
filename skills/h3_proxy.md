# HTTP/3 and QUIC Proxy Implementation

This skill documents the HTTP/3 (QUIC) proxy architecture, integration with the WAF, and the streaming implementation.

## Overview

SynVoid provides full HTTP/3 support via the `quinn` and `h3` crates. The implementation acts as a reverse proxy, terminating QUIC/TLS connections and forwarding requests to upstreams.

## Key Components

### HTTP/3 Server (`src/http3/server.rs`)

The `Http3Server` manages the QUIC endpoint and H3 connection lifecycle.

- **QUIC Stack**: Powered by `quinn` 0.11.
- **H3 Protocol**: Powered by `h3` 0.0.8 and `h3-quinn` 0.0.10.
- **TLS Configuration**: Integrated with `rustls` via `quinn::crypto::rustls::QuicServerConfig`.

### Request Handling Flow

1. **QUIC Accept**: New connections are accepted and passed to `handle_quic_connection`.
2. **Flood Protection**: Early IP-based filtering via `FloodProtector`.
3. **H3 Handshake**: Establishing the H3 connection over QUIC.
4. **WAF Scanning**: full request body collection (up to `max_request_size`) and scanning via `WafCore::check_request_full`.
5. **Routing**: Host and path-based routing via `Router`.
6. **Connection Limiting**: Per-site and per-IP connection limits enforced.
7. **Proxying**: Actual forwarding using `crate::http_client::send_request_streaming`.
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
| `http3.enabled` | `main.toml` | `false` |
| `http3.port` | `main.toml` | `443` |
| `max_request_size` | `main.toml` | `10MB` |
| `alt_svc_max_age` | `main.toml` | `86400` |

## Performance Considerations

- **Body Collection**: Current implementation collects the full request body for WAF scanning before proxying. This ensures high security but adds latency for large POST requests.
- **Buffer Reuse**: Leveraging `Bytes` and `BytesMut` for zero-copy data handling where possible.
- **Connection Pooling**: QUIC connections are multiplexed, but upstream connections use the standard HTTP/1.1 or H2 pool.

## Observability

Metrics are exposed via the global registry:
- `synvoid.http3.connections` (gauge)
- `synvoid.http3.requests.total` (counter)
- `synvoid.http3.requests.blocked` (counter)
- `synvoid.http3.request.duration` (histogram)

---

Last updated: 2026-04-26
