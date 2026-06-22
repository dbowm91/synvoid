//! Compatibility facade for `synvoid_http::listener`.
//!
//! New code should import `synvoid_http` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_http::listener::common::ConnectionContext;
