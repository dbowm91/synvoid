//! Pure-facade re-export of the canonical unsafe native loader.
//!
//! Phase 28: loading authority lives in `synvoid-native-extension` and is
//! re-exported through `synvoid_plugin_runtime::unsafe_native_loader`. This
//! module contains no loading logic: it only re-exports the extension status
//! types and delegates `load_plugin_full` to the runtime facade (which, in
//! builds without the `unsafe-native-extensions` feature, always reports
//! `Unsupported` instead of loading).

pub use synvoid_plugin_runtime::unsafe_native_loader::UnsafeNativeExtension;
pub use synvoid_plugin_runtime::unsafe_native_loader::UnsafeNativeExtensionStatus;

/// Load an unsafe native extension, delegating entirely to the runtime facade.
pub fn load_plugin_full(
    path: &std::path::Path,
    allowed_dirs: &[String],
    expected_hash: Option<&str>,
) -> Result<UnsafeNativeExtension, super::UnsafeNativePluginError> {
    synvoid_plugin_runtime::unsafe_native_loader::load_plugin(path, allowed_dirs, expected_hash)
}
