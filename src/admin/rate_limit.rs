// Re-export admin rate limiting from synvoid-admin crate.
#[allow(unused_imports)]
pub use synvoid_admin::rate_limit::{
    AdminRateLimitConfig, AdminRateLimitLayer, AdminRateLimitMiddleware, AdminRateLimiter, ClientIp,
};
