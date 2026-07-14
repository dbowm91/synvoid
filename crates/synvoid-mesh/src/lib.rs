//! Mesh networking subsystem for SynVoid.
//!
//! Provides peer-to-peer connectivity, DHT-based service discovery,
//! encrypted transport (QUIC, WireGuard), multi-tenant organization
//! management, and distributed DNS with DNSSEC support.
//!
//! See `architecture/mesh_transport_lifecycle.md` for transport state machine details.

pub mod mesh;
pub mod stubs;

pub use mesh::*;
