# Reverse Proxy and WAF Improvement Plan

**Status**: Ready for implementation handoff
**Last updated**: 2026-05-04
**Scope**: True streaming via type-erased connection pool, HTTP/TLS/HTTP3 unification, routing benchmarks, and remaining deferred items.

This file contains all open, partially complete, and deferred work. The next agent should treat every item below as open unless a commit clearly proves otherwise.

## Primary Goal

All untrusted client request handling for WAF/proxy traffic must happen in `UnifiedServerWorker` processes, separate from Overseer and Master. The worker path must scale across:

- Many proxied sites and domains.
- High-traffic non-mesh reverse proxy deployments.
- Mesh-enabled deployments using DHT/topology/mesh transport for routing.
- HTTP, HTTPS, HTTP/3, WebSocket, and supported backend types.

## Verified Baseline

- `src/startup/master.rs` documents that Master must not run `UnifiedServer` inline.
- Master spawns `UnifiedServerWorker` via `process_manager.spawn_unified_server_workers(...)`.
- `src/worker/unified_server.rs` creates `UnifiedServer` in the worker and initializes WAF/mesh-related worker services there.
- `cargo check --no-default-features --features mesh` compiles successfully.

---

## Completed Items (Do Not Modify)

The following items have been completed and verified:

- **P0: Preserve the Worker-Only Request Boundary** ✅ (2026-05-04)
- **P0: Fix Mesh Backend Proxy Wiring** ✅ (2026-05-04)
- **P0: Correct Forwarded Header Semantics** ✅ (2026-05-04)
- **P0: Fix Listener/IP-Based Routing** ✅ (2026-05-04)
- **P1: Make WAF Stall/Tarpit Safe Under Load** ✅ (2026-05-04) - `max_stalled_requests` config + metrics
- **P1: Harden Proxy Security Defaults** ✅ (2026-05-04) - Security regression tests in `tests/security_regression.rs`
- **P1: Scale Routing - Create routing benchmarks** ✅ (2026-05-04) - `benches/bench_routing.rs` with domain/location matching benchmarks
- **P0/P1: Streaming Infrastructure** ✅ (2026-05-04) - `BodyBufferingPolicy` config, `send_request_streaming` updated to accept `Full<Bytes>`

---

## P0/P1: True Streaming via Type-Erased Connection Pool

**Status**: 🚧 IN PROGRESS - Phase 1 Complete, Phases 2-5 Deferred (2026-05-04)

**Completed** (2026-05-04):
- Phase 1: Core trait definitions (ErasedBody, ErasedBodyImpl, PoolKey, BoxErasedBody)
- Phase 6: StreamingWafBody can be wrapped by ErasedBodyImpl

**Deferred**:
- Phase 2-5: Connection pooling infrastructure (deferred due to hyper type complexity)

**Files modified in this wave**:
- `src/http_client/erased_pool.rs` (NEW) - Type-erased body infrastructure
- `src/http_client/mod.rs` - Exports new types

### Problem

The current `HttpClient` is bound to `Full<Bytes>` body type at construction time:

```rust
pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
```

The `Client<C, B>` is parametric over body type `B`. The `PoolClient<B>` and `SendRequest<B>` are typed on `B`, meaning:
- You cannot pass `StreamingWafBody<...>` to a client typed for `Full<Bytes>`
- True streaming would require boxing at per-request level (1M+ allocations/second)
- This is unacceptable for 1M RPS target

### Solution: Option D - Type-Erased Connection Pool

**Reference**: Detailed implementation plan at `../../.local/share/opencode/plans/PLAN-OPTION-D-STREAMING.md`

**Key insight**: Box at connection checkout level, not per-request. Connection checkout happens ~10K-100K times/second (amortized over many requests), vs 1M times/second for per-request boxing.

**Target Architecture:**
```
ErasedClientPool
├── trait PooledConnection: Send + Sync
│   ├── send_request(Request<BoxErasedBody>) -> Future
│   ├── protocol() -> HttpProtocol
│   └── is_available() -> bool
├── HashMap<ClientKey, Vec<Box<dyn PooledConnection>>>
├── Connection checkout returns Box<dyn PooledConnection>
```

### Implementation Phases

#### Phase 1: Core Trait Definitions

**Location**: `src/http_client/erased_pool.rs` (NEW FILE)

Create the type-erased connection traits:

```rust
/// HTTP protocol version
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpProtocol {
    Http1,
    Http2,
}

/// Type-erased HTTP body
pub trait ErasedBody: Send + Sync {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>>;
    fn size_hint(&self) -> hyper::body::SizeHint;
}

/// Boxed erased body type
pub type BoxErasedBody = Box<dyn ErasedBody>;

/// Type-erased pooled connection
pub trait PooledConnection: Send + Sync {
    fn protocol(&self) -> HttpProtocol;
    fn send_request(
        self: Box<Self>,
        request: Request<BoxErasedBody>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<BoxErasedBody>, Box<dyn std::error::Error + Send + Sync>>> + Send>>;
    fn is_available(&self) -> bool;
    fn box_body<B>(body: B) -> BoxErasedBody
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Debug + Send;
}
```

**Wrapper for any Body type:**
```rust
pub struct ErasedBodyImpl<B> {
    inner: B,
}

impl<B> ErasedBody for ErasedBodyImpl<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug + Send,
{
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
```

**Acceptance Criteria:**
- [x] `PooledConnection` trait compiles ✅ (2026-05-04)
- [x] `ErasedBody` trait compiles ✅ (2026-05-04)
- [x] `ErasedBodyImpl` wrapper compiles ✅ (2026-05-04)
- [x] Test that creates a boxed trait object ✅ (2026-05-04)

**Note**: Phases 2-5 (HTTP/1 adapter, HTTP/2 stub, Connection Pool, ErasedHttpClient) were not completed due to hyper's complex type system. The type-erased body infrastructure is in place but full connection pooling requires additional work.

---

#### Phase 2: HTTP/1 Connection Adapter

**Location**: `src/http_client/erased_pool.rs`

```rust
use hyper_util::client::legacy::connect::Connection;

/// HTTP/1.1 pooled connection adapter
pub struct Http1PooledConnection {
    io: Connection,
    authority: http::uri::Authority,
}

impl PooledConnection for Http1PooledConnection {
    fn protocol(&self) -> HttpProtocol { HttpProtocol::Http1 }

    fn send_request(
        self: Box<Self>,
        request: Request<BoxErasedBody>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<BoxErasedBody>, Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        Box::pin(async move {
            let mut conn = http1::Conn::new(self.io);
            let (mut sender, conn) = conn.ready().await?.split();
            let response = sender.send_request(request).await?;
            Ok(response.map(|body| Self::box_body(body)))
        })
    }

    fn is_available(&self) -> bool { true }

    fn box_body<B>(body: B) -> BoxErasedBody
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Debug + Send,
    {
        Box::new(ErasedBodyImpl { inner: body })
    }
}
```

**Acceptance Criteria:**
- [ ] `Http1PooledConnection` implements `PooledConnection`
- [ ] Test that HTTP/1 connection can be pooled and checked out
- [ ] Verify body boxing/unboxing works correctly

---

#### Phase 3: HTTP/2 Connection Adapter (HTTP/1 Only for Now)

**Location**: `src/http_client/erased_pool.rs`

**Decision**: Implement HTTP/1 only initially. HTTP/2 adds multiplexing complexity. The pool key includes `is_http2: bool` so HTTP/2 support can be added later.

```rust
/// HTTP/2 pooled connection adapter (deferred for now)
pub struct Http2PooledConnection {
    connection: Arc<h2::Connection<Bytes>>,
    authority: http::uri::Authority,
}

impl PooledConnection for Http2PooledConnection {
    fn protocol(&self) -> HttpProtocol { HttpProtocol::Http2 }
    fn is_available(&self) -> bool { self.connection.is_open() }
    // ... full implementation when Phase 3B (HTTP/2) is activated
}
```

**Acceptance Criteria:**
- [ ] `Http2PooledConnection` stub compiles (can be no-op for now)
- [ ] Pool key supports `is_http2` flag

---

#### Phase 4: Erased Connection Pool

**Location**: `src/http_client/erased_pool.rs`

```rust
use moka::sync::Cache;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PoolKey {
    pub authority: String,
    pub is_http2: bool,
}

pub struct ErasedConnectionPool {
    idle: Arc<Cache<PoolKey, Vec<Box<dyn PooledConnection>>>>,
    connecting: Arc<Mutex<HashMap<PoolKey, Vec<tokio::sync::oneshot::Sender<Result<Box<dyn PooledConnection>, Box<dyn std::error::Error + Send + Sync>>>>>,
    max_idle_per_host: usize,
}

impl ErasedConnectionPool {
    pub fn new(max_idle_per_host: usize) -> Self { ... }

    pub async fn checkout(
        &self,
        key: PoolKey,
        connector: &dyn Connect,
    ) -> Result<Box<dyn PooledConnection>, Box<dyn std::error::Error + Send + Sync>> { ... }

    pub async fn checkin(&self, key: PoolKey, conn: Box<dyn PooledConnection>) { ... }

    async fn connect(
        &self,
        key: PoolKey,
        connector: &dyn Connect,
    ) -> Result<Box<dyn PooledConnection>, Box<dyn std::error::Error + Send + Sync>> { ... }
}

pub trait Connect: Send + Sync {
    async fn connect(&self, authority: String) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>>;
}
```

**Acceptance Criteria:**
- [ ] `ErasedConnectionPool` compiles
- [ ] Test checkout/checkin cycle
- [ ] Verify connection limiting works

---

#### Phase 5: ErasedHttpClient Integration

**Location**: `src/http_client/mod.rs`

```rust
/// HTTP client with type-erased body support
pub struct ErasedHttpClient {
    pool: Arc<ErasedConnectionPool>,
    connector: Arc<dyn Connect>,
}

impl ErasedHttpClient {
    pub fn new(connector: Arc<dyn Connect>, max_idle_per_host: usize) -> Self { ... }

    pub async fn send_request<B>(
        &self,
        request: Request<B>,
        key: PoolKey,
        timeout: Option<Duration>,
    ) -> Result<Response<Incoming>, Box<dyn std::error::Error + Send + Sync>>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Debug + Send,
    { ... }
}
```

**Acceptance Criteria:**
- [ ] `ErasedHttpClient` compiles
- [ ] Test full request/response cycle
- [ ] Verify timeout handling works

---

#### Phase 6: StreamingWafBody Integration

**Location**: `src/http_client/mod.rs`

```rust
impl<B> From<StreamingWafBody<B>> for Box<dyn ErasedBody>
where
    B: hyper::body::Body<Data = Bytes> + Unpin + 'static,
    B::Error: std::fmt::Debug + Send,
{
    fn from(body: StreamingWafBody<B>) -> Self {
        Box::new(ErasedStreamingBody { inner: body })
    }
}
```

**Status**: ✅ PARTIALLY COMPLETED (2026-05-04)

**Acceptance Criteria:**
- [x] `StreamingWafBody` can be wrapped by `ErasedBodyImpl` ✅ (2026-05-04)
- [ ] Full integration test with WAF scanning during streaming - deferred
- [ ] Verify blocked requests are properly rejected - deferred

**Note**: `ErasedBodyImpl::new()` can wrap `StreamingWafBody<B>` since `StreamingWafBody` implements `HttpBody<Data = Bytes>` when its inner body does. Full integration requires Phases 2-5 to be completed first.

---

#### Phase 7: Feature Flag and Backward Compatibility

**Location**: `Cargo.toml`, `src/http_client/mod.rs`

```toml
[features]
default = ["mesh", "erased_pool"]
erased_pool = []
```

**Strategy**: Both implementations coexist. Feature flag enables new implementation. Existing `HttpClient` remains functional.

```rust
#[cfg(feature = "erased_pool")]
pub mod erased_pool { ... }

#[cfg(feature = "erased_pool")]
pub use erased_pool::ErasedHttpClient;
```

**Acceptance Criteria:**
- [ ] Feature flag `erased_pool` compiles without existing code changes
- [ ] All existing tests pass with and without feature
- [ ] Both `HttpClient` and `ErasedHttpClient` available

---

#### Phase 8: Performance Benchmarking

**Location**: `benches/bench_erased_pool.rs` (NEW FILE)

Create benchmarks comparing:
- Existing `HttpClient` with `Full<Bytes>`
- New `ErasedHttpClient` with streaming bodies
- Memory usage under sustained load

```rust
fn bench_request_overhead(c: &mut Criterion) { ... }
fn bench_connection_checkout(c: &mut Criterion) { ... }
fn bench_memory_usage(c: &mut Criterion) { ... }
```

**Acceptance Criteria:**
- [ ] Benchmarks exist and run
- [ ] Memory allocation rate < 10M bytes/second at 1M RPS
- [ ] Connection checkout latency < 1ms p99

---

#### Phase 9: Full Integration

**Location**: All server files (`src/http/server.rs`, `src/tls/server.rs`, `src/http3/server.rs`)

Once Phase 8 benchmarks confirm performance:

```rust
// Route to appropriate client based on body type and policy
pub async fn proxy_to_upstream<B>(
    client: &HttpClient,
    erased_client: &ErasedHttpClient,
    request: Request<B>,
    policy: BodyBufferingPolicy,
    timeout: Option<Duration>,
) -> Result<Response<Incoming>, Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::fmt::Debug + Send,
{
    match policy {
        BodyBufferingPolicy::Streaming | BodyBufferingPolicy::StreamingRequired => {
            // Use ErasedHttpClient for true streaming
            erased_client.send_request(request, key, timeout).await
        }
        _ => {
            // Default to existing client
            send_request_streaming(client, request, timeout).await
        }
    }
}
```

**Acceptance Criteria:**
- [ ] All call sites migrated or have fallback
- [ ] Performance benchmarks maintained or improved
- [ ] No regression in existing functionality

---

### Files to Create/Modify

| File | Changes | Phase |
|------|---------|-------|
| `src/http_client/erased_pool.rs` | **NEW** - Core traits, HTTP/1 adapter, pool | 1-4 |
| `src/http_client/mod.rs` | Add `ErasedHttpClient`, feature flag, integration | 5-7 |
| `src/http/server.rs` | Add `ErasedHttpClient` usage | 9 |
| `src/tls/server.rs` | Add `ErasedHttpClient` usage | 9 |
| `src/http3/server.rs` | Add `ErasedHttpClient` usage | 9 |
| `benches/bench_erased_pool.rs` | **NEW** - Performance benchmarks | 8 |
| `Cargo.toml` | Add `erased_pool` feature flag (default enabled) | 7 |

---

### Risk Mitigation

| Risk | Mitigation |
|------|------------|
| hyper types don't impl external traits | Use wrapper types (`ErasedBodyImpl<B>`) we control |
| Performance regression | Benchmarks before migration, fallback to existing client |
| HTTP/2 complexity | Implement HTTP/1 only initially, defer HTTP/2 |

---

## P1: Unify HTTP, HTTPS, and HTTP/3 Behavior

### Status: 🚧 IN PROGRESS - Phase 1 Complete (2026-05-05)

**Completed** (2026-05-05):
- Phase 1: `WafResponseIntent` enum and `interpret_waf_decision()` in `src/server/waf_handler.rs`
- Phase 2: `WafContext` struct for shared request data

**In Progress**:
- Phase 3: Extract `dispatch_to_backend()` function
- Phase 4: Protocol adapter traits

**Files modified**:
- `src/server/waf_handler.rs` (NEW) - WafResponseIntent, WafContext, interpret_waf_decision
- `src/server/mod.rs` - Added `pub mod waf_handler`

### Problem

HTTP, TLS, and HTTP/3 paths contain nearly identical request handling/proxy logic. This risks drift in WAF checks, body handling, header forwarding, response filtering, metrics, and drain behavior.

### Code Duplication Analysis

| Category | HTTP | TLS | HTTP/3 |
|----------|------|-----|--------|
| Flood protection | Lines 509-521 | Lines 327-343 | Lines 167-179 |
| Bandwidth limiting | Lines 843-854 | Lines 638-646 | Lines 259-263 |
| WAF decision handling | Lines 1494-1713 | Lines 852-951 | Lines 376-513 |
| Backend dispatch | 95% identical | 95% identical | 95% identical |

### Files to Modify

| File | Purpose |
|------|---------|
| `src/http/server.rs` | HTTP adapter (small after extraction) |
| `src/tls/server.rs` | TLS adapter (small after extraction) |
| `src/http3/server.rs` | HTTP/3 adapter (small after extraction) |
| `src/http/shared_handler.rs` | Extract shared request pipeline |
| `src/server/request_handler.rs` | Extend `ConnectionMeta` trait |

### Implementation Steps

#### Phase 1: Extract `WafResponseIntent` Enum

**Location**: `src/server/waf_handler.rs` (NEW FILE)

```rust
pub enum WafResponseIntent {
    Drop,
    Stall { duration: Duration },
    Block { status: u16, body: String, content_type: &'static str },
    Challenge { html: String },
    ChallengeWithCookie { html, cookie_name, cookie_value, max_age },
    TarPit { delay: Duration, path: String },
    Pass,
}

pub fn interpret_waf_decision(decision: WafDecision, ctx: &WafDecisionContext) -> WafResponseIntent {
    // Match WafDecision variant to WafResponseIntent
}
```

#### Phase 2: Extract `RequestContext` Struct

```rust
pub struct RequestContext {
    pub client_ip: IpAddr,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub host: String,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub is_tls: bool,
    pub ja4_hash: Option<String>,
    pub protocol: &'static str,
}
```

#### Phase 3: Extract `dispatch_to_backend()`

Extract backend dispatch logic into a single function used by all protocols.

#### Phase 4: Protocol Adapter Traits

```rust
pub trait ProtocolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_tls(&self) -> bool;
    fn supports_websocket(&self) -> bool;
    fn forwarded_protocol(&self) -> ForwardedProtocol;
    async fn write_response(&self, intent: WafResponseIntent) -> Result<(), Error>;
}
```

Implement adapters for HTTP, HTTPS, and HTTP/3.

### Acceptance Criteria

1. WafDecision handling code exists in exactly one place
2. Backend dispatch logic exists in exactly one place
3. Protocol-specific files are adapters (< 500 lines each)
4. Parity tests verify same WAF decisions across protocols

---

## Verification Commands

```bash
# Format and check
cargo fmt
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,erased_pool
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns,erased_pool

# Run tests
cargo test --lib
cargo test --lib --features erased_pool
cargo test --test security_regression

# Run benchmarks
cargo bench --bench bench_routing
cargo bench --bench bench_erased_pool  # After Phase 8
```

---

## Deferred Items (Lower Priority)

These items are deferred but documented for future agents:

### P1: Reduce Proxy Hot-Path Allocations

**Problem**: Header forwarding, response filtering, cache keys, URL joining, and body cloning allocate per request.

**Next step**: Benchmark `build_forward_headers` and other hot paths before optimizing.

### P1: Replace Deprecated Global Service Access

**Problem**: `get_threat_intel`, `get_yara_rules`, `get_upload_validator` globals still used in request paths.

**Next step**: Thread `RequestServices` through protocol-agnostic pipeline after unification.

### P2: Cache and Revalidation Scalability

**Problem**: Stale-while-revalidate and invalidation can create unbounded background task bursts.

**Next step**: Requires bounded queue implementation.

### P2: Mesh Proxy Provider Selection

**Problem**: Mesh provider lookup may be unbounded DHT/topology operation.

**Next step**: Requires mesh internals review after P0 mesh wiring completion.

### P2: Performance Verification Gates

**Problem**: 1M RPS aspiration needs measurable hot-path budgets.

**Next step**: Create benchmark infrastructure and define performance budgets.

---

## Reference Documents

- [`docs/adr/ADR-003-unified-worker-process.md`](../docs/adr/ADR-003-unified-worker-process.md) — Unified worker architecture ADR
- [`skills/streaming_waf.md`](../skills/streaming_waf.md) — StreamingWafBody implementation details
- [`skills/performance_patterns.md`](../skills/performance_patterns.md) — Performance patterns and stall metrics
- [`skills/security_patterns.md`](../skills/security_patterns.md) — Security patterns including header forwarding
- [`../../.local/share/opencode/plans/PLAN-OPTION-D-STREAMING.md`](../../.local/share/opencode/plans/PLAN-OPTION-D-STREAMING.md) — Detailed Option D implementation plan
