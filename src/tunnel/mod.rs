//! Compatibility facade for `synvoid_tunnel`.
//!
//! New code should import `synvoid_tunnel` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_tunnel::*;
