//! Re-export the canonical unsafe native loader from the plugin-runtime crate.
//!
//! The root crate delegates to `synvoid_plugin_runtime::unsafe_native_loader`
//! for all loading logic. This module exists only so that `src/plugin/mod.rs`
//! can refer to `unsafe_native_loader::load_plugin_full` without adding a
//! direct dependency on the runtime crate at every call site.

pub use synvoid_plugin_runtime::unsafe_native_loader::UnsafeNativeExtension;
pub use synvoid_plugin_runtime::unsafe_native_loader::UnsafeNativeExtensionStatus;

/// Load an unsafe native extension, delegating entirely to the runtime crate.
pub fn load_plugin_full(
    path: &std::path::Path,
    allowed_dirs: &[String],
    expected_hash: Option<&str>,
) -> Result<UnsafeNativeExtension, super::UnsafeNativePluginError> {
    synvoid_plugin_runtime::unsafe_native_loader::load_plugin(path, allowed_dirs, expected_hash)
}
