//! Compatibility facade for `synvoid_honeypot`.
//!
//! New code should import `synvoid_honeypot` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_honeypot::*;
