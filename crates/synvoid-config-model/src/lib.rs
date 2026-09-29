//! Low-capability, serializable configuration models.
//!
//! This crate owns DTOs that do not require configuration loading, filesystem
//! discovery, or runtime service authority.

pub mod honeypot_port;

pub use honeypot_port::HoneypotPortConfig;
