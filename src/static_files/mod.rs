//! Transitional compatibility surface for `synvoid_static_files`.
//!
//! Most static-file implementation belongs in `synvoid_static_files`. This root
//! module still exposes compatibility shims and a local `file_manager` adapter
//! during the modularization transition. See `architecture/root_module_ledger.md`
//! before adding new implementation here.

pub use synvoid_static_files::client;
pub use synvoid_static_files::directory;
pub mod file_manager;
pub use synvoid_static_files::minifier;

pub use synvoid_config::mesh::{
    MeshCompressionConfig, MeshImageProtectionConfig, MeshMinificationConfig,
};
pub use synvoid_static_files::{
    NormalizedLocation, StaticError, StaticFileHandler, StaticResponse, StaticResponseBody,
};
