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
