//! HSM facade (Phase 30).
//!
//! Canonical implementation lives in `synvoid-dnssec-keystore::hsm`.
//! This module re-exports the narrow signer contract and converts the
//! DNS-owned [`crate::runtime_config::HsmRuntimeConfig`] into the
//! keystore-local config so the keystore crate stays free of application
//! dependencies (one-way boundary).
//!
//! Phase 128 removed `keystore_config_from_dns`: the persisted HSM schema no
//! longer reaches this crate, so the only input is DNS-owned runtime values.
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

/// Convert the DNS-owned HSM runtime values into the keystore-local config.
/// PIN material is wrapped in a zeroizing container inside the keystore
/// constructor and is never logged.
pub fn keystore_config_from_runtime(
    config: &crate::runtime_config::HsmRuntimeConfig,
) -> KeystoreHsmConfig {
    let provider = match config.provider {
        crate::runtime_config::HsmProviderRuntime::Pkcs11 => KeystoreHsmProvider::Pkcs11,
        crate::runtime_config::HsmProviderRuntime::Soft => KeystoreHsmProvider::Soft,
    };
    // DNS zones that explicitly select the PKCS#11 provider require HSM
    // backing: establishment failures fail closed (no silent fallback). The
    // application adapter already computed this flag; it is carried verbatim
    // so the two layers cannot disagree about fail-closed behavior.
    KeystoreHsmConfig::from_string_parts(
        config.enabled,
        provider,
        config.module_path.clone(),
        config.slot_id,
        config.pin.clone(),
        config.key_label.clone(),
        config.key_id.clone(),
        config.require_hsm,
    )
}

/// Back-compat backend enum: PKCS#11 variant only exists with the `hsm`
/// feature; software is always available.
pub enum HsmBackend {
    #[cfg(feature = "hsm")]
    Pkcs11(Pkcs11Hsm),
    Soft(SoftHsm),
}
