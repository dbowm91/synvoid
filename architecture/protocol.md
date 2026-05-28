# Protocol Detection Architecture

## 1. Purpose and Responsibility

The Protocol module (`src/protocol/`) provides a **pluggable protocol detection and handling framework** supporting HTTP, HTTPS, WebSocket, gRPC, TCP, and UDP with WAF integration.

**Core Responsibilities:**
- Protocol detection from initial bytes
- Pluggable protocol handler registration
- WAF integration for protocol-aware filtering
- Request/response parsing abstraction
- Metrics per protocol type

---

## 2. Key Data Structures

```rust
pub trait ProtocolHandler: Send + Sync {
    fn protocol_type(&self) -> ProtocolType;
    fn name(&self) -> &'static str;
    fn detect(&self, data: &[u8]) -> bool;
    fn parse_request(&self, data: &[u8]) -> Result<ProtocolRequest, ProtocolError>;
    fn build_request_for_upstream(&self, request: &ProtocolRequest) -> Vec<u8>;
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse, ProtocolError>;
    fn apply_waf(&self, request: &mut ProtocolRequest, waf: &Arc<WafCore>) -> WafAction;
    fn select_upstream(&self, request: &ProtocolRequest, pool: &UpstreamPool) -> Option<Backend>;
    fn metrics(&self) -> ProtocolMetrics;
    fn set_waf(&mut self, waf: Arc<WafCore>);
    fn set_upstream_pool(&mut self, pool: Arc<UpstreamPool>);
}

pub enum ProtocolType {
    Http, Https, WebSocket, Wss, Grpc, GrpcTls, Tcp, Udp, Unknown,
}

pub enum ProtocolFamily {
    Http, WebSocket, Grpc, Tcp, Udp,
}

pub enum WafAction {
    Allow, Block, Challenge, Stall, TarPit, LogOnly,
}

pub struct ProtocolDetectionResult<P> {
    pub protocol: P,
    pub confidence: f32,
    pub matched_pattern: String,
}

pub enum ProtocolError {
    Parse(String),
    Framing(String),
    ConnectionClosed,
    Upstream(String),
    WafBlocked(String),
    NotImplemented(String),
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ProtocolHandler::protocol_type()` | Get handler's protocol |
| `ProtocolHandler::name()` | Handler name |
| `ProtocolHandler::detect(data)` | Detect protocol from bytes |
| `ProtocolHandler::parse_request(data)` | Parse into request |
| `ProtocolHandler::apply_waf(request, waf)` | WAF decision |
| `looks_like_dns(data) -> bool` | Quick DNS detection |
| `extract_first_line(data) -> String` | Extract request line |
| `register_protocol_types()` | Debug logging |

---

## 4. Submodules

### `grpc.rs` — gRPC Handler
- HTTP/2 framing detection
- Protobuf content-type matching

### `websocket.rs` — WebSocket Handler
- Upgrade header detection
- WebSocket frame parsing

### `detect_common.rs` — Common Detection
- DNS packet detection
- First-line extraction
- Protocol fingerprinting

---

## 5. Integration Points

- **HTTP Server**: Protocol-level request handling
- **WAF**: Protocol-aware attack detection
- **Listener**: Protocol expectation enforcement
- **Metrics**: Per-protocol request counting

---

## 6. Key Implementation Details

- **Pluggable**: New protocols added via trait implementation
- **Confidence Scoring**: Detection results include confidence level
- **Pattern Matching**: Regex-based protocol fingerprinting
- **WAF Integration**: Each handler implements WAF decision logic
