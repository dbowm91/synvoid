//! Compatibility facade for `synvoid_proxy::bidirectional`.
//!
//! New code should import `synvoid_proxy` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_proxy::bidirectional::*;
