//! Compatibility facade for `synvoid_plugin_runtime::spin`.
//!
//! New code should import `synvoid_plugin_runtime` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_plugin_runtime::spin::*;
