// Re-export admin token auth primitives from synvoid-admin crate.
#[allow(unused_imports)]
pub use synvoid_admin::auth::{
    hash_admin_token, hash_admin_token_with_cost, verify_admin_token, AuthRateLimiter,
    AUTH_RATE_LIMITER, AUTH_LOCKOUT_DURATION, MAX_AUTH_ATTEMPTS,
};
