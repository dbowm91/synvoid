//! Compatibility facade for `synvoid_app_server`.
//!
//! New code should import `synvoid_app_server` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_app_server::*;
