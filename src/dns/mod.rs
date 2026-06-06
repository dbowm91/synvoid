//! DNS Server module for SynVoid
//!
//! Re-exports from the extracted synvoid-dns crate.
//! Mesh-specific DNS modules (mesh_dnssec, mesh_sync, anycast_sync) are now
//! in the synvoid-dns crate, feature-gated behind `mesh`.

#[cfg(feature = "dns")]
pub use synvoid_dns::*;

#[cfg(feature = "mesh")]
pub use synvoid_dns::mesh_dnssec;
#[cfg(feature = "mesh")]
pub use synvoid_dns::mesh_sync;
#[cfg(feature = "mesh")]
pub use synvoid_dns::anycast_sync;
