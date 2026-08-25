# HTTP/3 Deep Dive

SynVoid's HTTP/3 server implements QUIC-based HTTP/3 using `quinn` + `h3` crates, architecturally decoupled from concrete WAF types via trait objects.

## Architecture

### Core Struct

```rust
pub struct Http3Server {
    addr: SocketAddr,
    config: Http3Config,
    router: Arc<Router>,
    waf: Arc<dyn Http3WafBackend>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    metrics: Option<Arc<WorkerMetrics>>,
    shutdown_rx: broadcast::Receiver<()>,
    trusted_proxies: Vec<String>,
    main_config: Arc<MainConfig>,
}
```

### Key Trait

```rust
pub trait Http3WafBackend: Http3RequestWaf + WafAccess {
    // Composite trait ensuring HTTP/3 server never depends on concrete WafCore
}
```

This trait boundary is regression-tested to prevent coupling.

## Request Flow

```
QUIC Connection
    │
    ▼
Http3Server::accept()
    │
    ├── Connection limiting
    │
    ▼
prepare_http3_request_prelude()
    │
    ├── Route resolution
    ├── Client IP extraction
    └── Bandwidth limit checks
    │
    ▼
prepare_http3_request_dispatch()
    │
    ├── Full WAF evaluation
    ├── Streaming fast path
    └── Backend dispatch
    │
    ▼
Response via QUIC stream
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Http3Server` | `crates/synvoid-http3/src/server.rs` | Main server |
| `Http3WafBackend` | `crates/synvoid-http3/src/lib.rs` | WAF trait boundary |
| `Http3RequestStream` | `crates/synvoid-http/src/http3_body.rs` | QUIC stream abstraction (trait) |
| `Http3RequestResolver` | `crates/synvoid-http/src/http3_request_flow.rs` | Request resolution trait |

## Integration Points

- Uses `synvoid-proxy::Router` for routing
- Uses `synvoid-http-client` for upstream connections
- Uses `synvoid-metrics::bandwidth` for bandwidth tracking
- Consumed by the root crate's worker composition
