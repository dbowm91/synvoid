//! Compatibility facade over `synvoid_static_files`.
//!
//! Canonical static-file implementation (including `file_manager`) lives in
//! `synvoid_static_files`. This root module only re-exports crate modules.
//! See `architecture/root_module_ledger.md` before adding code here.

pub use synvoid_static_files::client;
pub use synvoid_static_files::directory;
pub use synvoid_static_files::file_manager;
pub use synvoid_static_files::minifier;

pub use synvoid_config::mesh::{
    MeshCompressionConfig, MeshImageProtectionConfig, MeshMinificationConfig,
};
pub use synvoid_static_files::{
    NormalizedLocation, StaticError, StaticFileHandler, StaticResponse, StaticResponseBody,
};
