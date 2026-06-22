//! Compatibility facade for `synvoid_mesh`.
//!
//! New code should import `synvoid_mesh` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_mesh::mesh::*;
