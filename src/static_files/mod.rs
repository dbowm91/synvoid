pub use synvoid_static_files::client;
pub use synvoid_static_files::directory;
pub mod file_manager;
pub use synvoid_static_files::minifier;

pub use synvoid_static_files::{
    MeshCompressionConfig, MeshImageProtectionConfig, MeshMinificationConfig, NormalizedLocation,
    StaticError, StaticFileHandler, StaticResponse, StaticResponseBody,
};
