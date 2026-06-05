//! SynVoid WAF engine - attack detection, normalization, and pattern matching.
//!
//! This crate provides the core WAF attack detection logic independent of
//! HTTP server, supervisor, worker, mesh, DNS, and admin subsystems.

pub mod attack_detection;
pub mod bot;
pub mod endpoints;
pub mod flood;
pub mod primitives;
pub mod request_sanitization;
pub mod traffic_shaper;
pub mod traits;

pub use flood::{FloodConfig, FloodDecision, FloodProtector, FloodStats};
pub use primitives::{TestModeConfig, WafConfig, WafDecision};
pub use traffic_shaper::{AsyncTokenBucket, ConnectionLimiter, ConnectionLimitError, ConnectionToken, TokenBucket};
