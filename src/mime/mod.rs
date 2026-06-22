//! Compatibility facade for `synvoid_app_handlers::mime`.
//!
//! New code should import `synvoid_app_handlers` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_app_handlers::mime::*;
