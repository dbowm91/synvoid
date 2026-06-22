//! Compatibility facade for `synvoid_block_store`.
//!
//! New code should import `synvoid_block_store` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_block_store::*;
