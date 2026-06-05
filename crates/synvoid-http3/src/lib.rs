//! SynVoid HTTP/3 (QUIC) server.
//!
//! **BLOCKER**: Cannot move `src/http3/server.rs` yet because it depends on
//! root-only types: `WafCore`, `Router`, `WorkerMetrics`, `WorkerDrainState`,
//! `UpstreamClientRegistry`, `StreamingWafDecision`, etc.
//!
//! To complete extraction, the following traits are needed in synvoid-waf or
//! synvoid-core:
//! - `WafProcessor` trait abstracting WafCore::check_request / check_request_body
//! - `Router` trait for route resolution
//! - `WorkerMetrics` trait for metrics emission
//! - `DrainState` trait for graceful shutdown
//!
//! Once these traits exist, http3/server.rs can depend on trait objects
//! instead of concrete root types.
