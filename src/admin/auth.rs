// Re-export admin token auth primitives from synvoid-admin crate.
#[allow(unused_imports)]
pub use synvoid_admin::auth::{
    hash_admin_token, hash_admin_token_with_cost, verify_admin_token, verify_admin_token_async,
    verify_dummy_admin_token_async, AuthRateLimiter, AUTH_LOCKOUT_DURATION, AUTH_RATE_LIMITER,
    MAX_AUTH_ATTEMPTS,
};
