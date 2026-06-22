//! Compatibility facade for `synvoid_vpn_client`.
//!
//! New code should import `synvoid_vpn_client` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_vpn_client::*;
