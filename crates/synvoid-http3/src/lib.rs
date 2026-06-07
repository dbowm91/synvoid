//! SynVoid HTTP/3 (QUIC) server.
//!
//! **BLOCKER**: `src/http3/server.rs` still owns the QUIC transport glue and
//! imports concrete root types: `WafCore`, `Router`, `WorkerMetrics`,
//! `WorkerDrainState`, `UpstreamClientRegistry`, `HttpClient`,
//! `FloodProtector`, and `FloodDecision`.
//!
//! Resolved prerequisites already exist in extracted crates:
//! - `synvoid_waf::WafProcessor` (trait for WafCore)
//! - `synvoid_proxy::routing::RouteResolver` (trait for Router)
//! - `synvoid_core::metrics::MetricsSink` (trait for WorkerMetrics)
//! - `synvoid_core::drain::DrainState` (trait for WorkerDrainState)
//!
//! Remaining blockers are the root-owned fields and call sites in
//! `src/http3/server.rs`, plus request-flow glue that still depends on the
//! concrete `UpstreamClientRegistry` (struct in synvoid-proxy, no trait yet),
//! `HttpClient`, `FloodProtector`, and `FloodDecision`.
