//! SynVoid WAF engine - attack detection, normalization, and pattern matching.
//!
//! This crate provides the core WAF attack detection logic independent of
//! HTTP server, supervisor, worker, mesh, DNS, and admin subsystems.

pub mod attack_detection;
pub mod bot;
pub mod endpoints;
pub mod flood;
pub mod mitigation;
pub mod primitives;
pub mod probe_tracker;
pub mod ratelimit;
pub mod request_sanitization;
pub mod threat;
pub mod traffic_shaper;
pub mod traits;
pub mod violation_tracker;

pub use flood::{FloodConfig, FloodDecision, FloodProtector, FloodStats};
pub use primitives::{TestModeConfig, WafConfig, WafDecision};
pub use probe_tracker::{UpstreamErrorResult, UpstreamErrorTracker};
pub use traffic_shaper::{
    AsyncTokenBucket, ConnectionLimitError, ConnectionLimiter, ConnectionToken, TokenBucket,
};
