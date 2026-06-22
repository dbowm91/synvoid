//! Compatibility facade for `synvoid_ipc`.
//!
//! New code should import `synvoid_ipc` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_ipc::*;
