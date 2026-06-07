//! SynVoid HTTP/3 (QUIC) server.
//!
//! **BLOCKER**: `src/http3/server.rs` still owns the QUIC transport glue and
//! imports concrete root types: `WafCore`, `Router`, `WorkerMetrics`,
//! `WorkerDrainState`, and `UpstreamClientRegistry`.
//!
//! Resolved prerequisites already exist in extracted crates:
//! - `synvoid_waf::WafProcessor`
//! - `synvoid_proxy::routing::RouteResolver`
//! - `synvoid_core::metrics::MetricsSink`
//! - `synvoid_core::drain::DrainState`
//!
//! Remaining blockers are the root-owned fields and call sites in
//! `src/http3/server.rs`, plus any request-flow glue that still depends on the
//! concrete `UpstreamClientRegistry` or `StreamingWafDecision` path.
