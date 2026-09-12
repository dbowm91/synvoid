//! HSM facade (Phase 30).
//!
//! Canonical implementation lives in `synvoid-dnssec-keystore::hsm`.
//! This module re-exports the narrow signer contract and converts
//! `synvoid_config::dns::HsmConfig` into the keystore-local config so the
//! keystore crate stays free of config-crate dependencies (one-way boundary).
//!
//! Fail-closed rule: PKCS#11 establishment failures never fall back to
//! software keys. See the keystore crate for the authoritative semantics.

pub use synvoid_dnssec_keystore::hsm::{
    HsmAlgorithm as HsmKeyAlgorithm, HsmConfig as KeystoreHsmConfig, HsmError, HsmManager,
    HsmProvider as KeystoreHsmProvider, HsmSigner, SoftHsm,
};
#[cfg(feature = "hsm")]
pub use synvoid_dnssec_keystore::Pkcs11Hsm;

// Back-compat alias for the pre-extraction algorithm path.
pub use synvoid_dnssec_keystore::hsm::HsmAlgorithm as Algorithm;

/// Convert the DNS config HSM section into the keystore-local config.
/// PIN material is wrapped in a zeroizing container inside the keystore
/// constructor and is never logged.
pub fn keystore_config_from_dns(config: &synvoid_config::dns::HsmConfig) -> KeystoreHsmConfig {
    let provider = match config.provider {
        synvoid_config::dns::HsmProvider::Pkcs11 => KeystoreHsmProvider::Pkcs11,
        synvoid_config::dns::HsmProvider::Soft => KeystoreHsmProvider::Soft,
    };
    // DNS zones that explicitly select the PKCS#11 provider require HSM
    // backing: establishment failures fail closed (no silent fallback).
    let require_hsm =
        matches!(config.provider, synvoid_config::dns::HsmProvider::Pkcs11) && config.enabled;
    KeystoreHsmConfig::from_string_parts(
        config.enabled,
        provider,
        config.module_path.clone(),
        config.slot_id,
        config.pin.clone(),
        config.key_label.clone(),
        config.key_id.as_ref().map(|s| s.as_bytes().to_vec()),
        require_hsm,
    )
}

/// Back-compat backend enum: PKCS#11 variant only exists with the `hsm`
/// feature; software is always available.
pub enum HsmBackend {
    #[cfg(feature = "hsm")]
    Pkcs11(Pkcs11Hsm),
    Soft(SoftHsm),
}
