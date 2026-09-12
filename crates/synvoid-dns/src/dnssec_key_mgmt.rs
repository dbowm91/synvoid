//! DNSSEC key-management facade (Phase 30).
//!
//! Canonical implementation lives in `synvoid-dnssec-keystore::keystore`.
//! This module re-exports the custody API so existing `crate::dnssec::`
//! and `crate::dnssec_key_mgmt::` paths keep compiling while new code
//! targets `synvoid_dnssec_keystore` directly.
//!
//! Boundary note: [`DnsSecKeyManager`] handles are opaque with respect to
//! private bytes. The query path signs via [`SealedSigningKey::sign`] or
//! [`DnssecKeystore::sign_canonical`]; public data flows via [`KeyMetadata`].

pub use synvoid_dnssec_keystore::{
    DnsSecKeyManager, DnsSecKeyStatus, DnssecKeystore, KeyInfo, KeyMetadata, KeyRotationConfig,
    KeyRotationResult, RolloverState, SealedSigningKey, ZoneSigningKey,
};
