//! Compatibility re-export over the canonical [`synvoid_rate_limit`] crate.
//!
//! Phase 33 moved the neutral admission vocabulary (`RateLimitResult`,
//! `IpRateLimiter`, `KeyedRateLimiter`, `RateLimitStats`,
//! `RateLimitStatsProvider`) into `synvoid-rate-limit` so WAF and mesh share
//! one definition. This module stays only so existing `crate::utils::ratelimit`
//! paths keep compiling; new domain code must import `synvoid_rate_limit`
//! directly.

pub use synvoid_rate_limit::{
    IpRateLimiter, KeyedRateLimiter, RateLimitResult, RateLimitStats, RateLimitStatsProvider,
};
