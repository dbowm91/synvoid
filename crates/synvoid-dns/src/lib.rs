//! DNS Server module for SynVoid
//!
//! This crate provides an authoritative DNS server with support for:
//! - Standalone operation (manual zone configuration)
//! - Mesh mode (dynamic registration from edge nodes)
//! - DNSSEC signing
//! - Geo-steering based on client location and node health
//! - DNS-over-TLS (DoT)
//! - DNS-over-HTTPS (DoH)
//! - DNS-over-Quic (DoQ)
//! - Dynamic Updates (RFC 2136)

#[path = "mod.rs"]
mod dns;

pub use dns::*;

pub mod health;

#[cfg(feature = "mesh")]
pub mod anycast_sync;
#[cfg(feature = "mesh")]
pub mod mesh_dnssec;
#[cfg(feature = "mesh")]
pub mod mesh_sync;
