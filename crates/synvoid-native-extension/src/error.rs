//! Canonical error types for unsafe native extensions.
//!
//! Phase 28: canonical owner is `synvoid-native-extension`. The
//! `synvoid-plugin-runtime` crate re-exports these when its
//! `unsafe-native-extensions` feature is enabled and provides a compatible
//! stub (including [`UnsafeNativePluginError::Unsupported`]) when disabled.

/// Errors from unsafe native extension loading and validation.
///
/// [`UnsafeNativePluginError::Unsupported`] is returned by builds that lack
/// compiled native support instead of silently pretending a load succeeded.
#[derive(Debug, thiserror::Error)]
pub enum UnsafeNativePluginError {
    #[error("Failed to load unsafe native extension: {0}")]
    LoadFailed(String),
    #[error(
        "Unsafe native extension ABI version {plugin} does not match expected version {expected}"
    )]
    AbiMismatch { plugin: String, expected: String },
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("Unsafe native extension not allowed in production mode")]
    ProductionDenied,
    #[error("Risk acknowledgement missing or incorrect")]
    RiskAcknowledgementRequired,
    #[error("No allowed directories configured for unsafe native extensions")]
    NoAllowedDirs,
    #[error(
        "Unsafe native extensions are not compiled into this binary \
         (enable the `unsafe-native-extensions` feature and set \
         [plugins.unsafe_native] at runtime)"
    )]
    Unsupported,
}

/// Backward-compatible alias (Phase 8 rename from "Axum plugins").
pub type AxumPluginError = UnsafeNativePluginError;
