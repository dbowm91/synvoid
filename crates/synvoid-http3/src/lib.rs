//! SynVoid HTTP/3 (QUIC) server.
//!
//! **STATUS**: `src/http3/server.rs` stays in root (`KEEP_ROOT_UNTIL_WAFCORE_TRAIT_EXTENSION`).
//!
//! Dependency inventory (HTC-Q01) found 10 concrete root dependencies.
//! 9 of 12 are already in extracted crates:
//!   `Router` (synvoid-proxy), `FloodProtector`/`FloodDecision` (synvoid-waf),
//!   `HttpClient` (synvoid-http-client), `UpstreamClientRegistry` (synvoid-proxy),
//!   `WorkerMetrics` (synvoid-metrics), `Http3Config`/`MainConfig` (synvoid-config),
//!   `ConnectionLimiter` (synvoid-waf).
//!
//! Root-owned blockers that prevent moving the server:
//!   - `WafCore` — `WafProcessor` trait covers request/body checks but not
//!     `connection_limiter`, `is_over_bandwidth_limit`, or `streaming()` accessors.
//!     Needs `WafProcessor` extension or a new `WafAccess` trait.
//!   - `WorkerDrainState` — `DrainState` trait exists in synvoid-core but the struct
//!     is stored and unused in server.rs methods (low effort, just pass trait object).
//!
//! Platform utility `bind_udp_reuse` (root `src/platform/socket.rs`) stays in root.
