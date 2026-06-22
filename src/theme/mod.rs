//! Compatibility facade for `synvoid_theme`.
//!
//! New code should import `synvoid_theme` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_theme::*;
