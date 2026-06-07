//! SynVoid HTTP/3 (QUIC) server.
//!
//! **STATUS**: `src/http3/server.rs` stays in root (`KEEP_ROOT_UNTIL_WAFACCESS_USED`).
//!
//! Dependency inventory (HTC-Q01) found 10 concrete root dependencies.
//! 9 of 12 are already in extracted crates:
//!   `Router` (synvoid-proxy), `FloodProtector`/`FloodDecision` (synvoid-waf),
//!   `HttpClient` (synvoid-http-client), `UpstreamClientRegistry` (synvoid-proxy),
//!   `WorkerMetrics` (synvoid-metrics), `Http3Config`/`MainConfig` (synvoid-config),
//!   `ConnectionLimiter` (synvoid-waf).
//!
//! Root-owned blockers that prevent moving the server:
//!   - `WafCore` — `WafAccess` trait (synvoid-waf) now covers `connection_limiter`,
//!     `is_over_bandwidth_limit`, and `streaming()` accessors. Remaining blocker:
//!     `self.waf.as_ref()` cast for `Http3RequestWaf` dispatch requires concrete
//!     `WafCore` type, and the struct stores `Arc<WafCore>` directly.
//!   - `WorkerDrainState` — `DrainState` trait exists in synvoid-core but the struct
//!     is stored and unused in server.rs methods (low effort, just pass trait object).
//!
//! Platform utility `bind_udp_reuse` (root `src/platform/socket.rs`) stays in root.
