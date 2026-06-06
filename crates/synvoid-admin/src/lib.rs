//! SynVoid admin API primitives.
//!
//! Provides admin token authentication, schema helpers, and types
//! shared between the admin API handlers and other subsystems.

pub mod auth;
pub mod handlers;
pub mod rate_limit;
pub mod schema;
