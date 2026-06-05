//! DNS Server module for SynVoid
//!
//! Re-exports from the extracted synvoid-dns crate.
//! Mesh-specific DNS modules (mesh_dnssec, mesh_sync, anycast_sync) remain here
//! because they depend on root mesh types.

#[cfg(feature = "dns")]
pub use synvoid_dns::*;

#[cfg(feature = "mesh")]
pub mod anycast_sync;
#[cfg(feature = "dns")]
pub mod mesh_dnssec;
#[cfg(feature = "mesh")]
pub mod mesh_sync;
