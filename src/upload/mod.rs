//! Compatibility facade for `synvoid_upload`.
//!
//! New code should import `synvoid_upload` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_upload::*;
