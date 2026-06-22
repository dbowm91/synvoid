//! Compatibility facade for `synvoid_serverless`.
//!
//! New code should import `synvoid_serverless` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_serverless::*;
