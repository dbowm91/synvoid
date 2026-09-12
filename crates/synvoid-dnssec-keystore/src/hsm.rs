//! HSM-backed signing isolation (Phase 30 Part C).
//!
//! # Boundary rules
//!
//! - `cryptoki` (PKCS#11) is an **optional** dependency behind the crate
//!   `pkcs11`/`hsm` features. Software-key builds link no PKCS#11 provider
//!   and perform no dynamic library loading.
//! - HSM handles never leave this module as raw session/object values; the
//!   query path sees only the narrow [`HsmSigner`] trait (`sign`,
//!   `get_public_key`, `key_id`).
//! - Fail-closed: a zone configured to require HSM keys never silently falls
//!   back to software keys. [`HsmManager::initialize`] returns a typed
//!   [`HsmError`] when the PKCS#11 backend cannot be established and the
//!   configuration requires it.
//! - PINs/secrets are held in [`Zeroizing`] wrappers and never logged.

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
#[cfg(feature = "pkcs11")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Typed HSM failures. Callers fail closed on `InitializationFailed`,
/// `SessionError`, and `SigningFailed` for HSM-required zones.
#[derive(Debug, Clone, Error)]
pub enum HsmError {
    #[error("HSM provider: {0}")]
    Provider(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("initialization failed: {0}")]
    InitializationFailed(String),
    #[error("session error: {0}")]
    SessionError(String),
    #[error("object not found")]
    ObjectNotFound,
    #[error("HSM support not compiled (enable the `pkcs11` feature)")]
    NotCompiled,
}

impl From<HsmError> for crate::error::KeystoreError {
    fn from(e: HsmError) -> Self {
        crate::error::KeystoreError::Hsm(e.to_string())
    }
}

/// Narrow HSM signer contract: opaque handles only.
pub trait HsmSigner: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError>;
    fn get_public_key(&self) -> Result<Vec<u8>, HsmError>;
    fn key_id(&self) -> &str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HsmAlgorithm {
    #[default]
    Ed25519,
    RsaSha256,
}

impl From<crate::algorithm::Algorithm> for HsmAlgorithm {
    fn from(algo: crate::algorithm::Algorithm) -> Self {
        match algo {
            crate::algorithm::Algorithm::Ed25519 => HsmAlgorithm::Ed25519,
            crate::algorithm::Algorithm::RSA => HsmAlgorithm::RsaSha256,
        }
    }
}

#[cfg(feature = "pkcs11")]
impl HsmAlgorithm {
    pub fn to_cryptoki_mechanism(&self) -> cryptoki::mechanism::Mechanism<'_> {
        use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
        use cryptoki::mechanism::Mechanism;
        match self {
            HsmAlgorithm::Ed25519 => {
                Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519))
            }
            HsmAlgorithm::RsaSha256 => Mechanism::Sha256RsaPkcs,
        }
    }
}

/// Which backend to establish. `Pkcs11` requires the `pkcs11` feature;
/// without it, initialization fails closed with [`HsmError::NotCompiled`]
/// instead of silently using software keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HsmProvider {
    #[default]
    Pkcs11,
    Soft,
}

/// Local HSM configuration. `synvoid-dns` converts from
/// `synvoid_config::dns::HsmConfig` at its facade so this crate does not
/// depend on the config crate (one-way boundary).
#[derive(Debug, Clone, Default)]
pub struct HsmConfig {
    pub enabled: bool,
    pub provider: HsmProvider,
    pub module_path: String,
    pub slot_id: Option<usize>,
    pub pin: Option<Zeroizing<String>>,
    pub key_label: Option<String>,
    pub key_id: Option<Vec<u8>>,
    /// When true, any PKCS#11 establishment failure is returned to the
    /// caller and the zone must refuse to serve signed answers. When false,
    /// the manager still never *silently* falls back: it reports
    /// unavailability and leaves signing disabled.
    pub require_hsm: bool,
}

impl HsmConfig {
    /// Build from plain string parts without requiring callers to depend on
    /// `zeroize`: the PIN is wrapped in a zeroizing container here, at the
    /// custody boundary.
    #[allow(clippy::too_many_arguments)] // mirrors HsmConfig fields one-to-one
    pub fn from_string_parts(
        enabled: bool,
        provider: HsmProvider,
        module_path: String,
        slot_id: Option<usize>,
        pin: Option<String>,
        key_label: Option<String>,
        key_id: Option<Vec<u8>>,
        require_hsm: bool,
    ) -> Self {
        Self {
            enabled,
            provider,
            module_path,
            slot_id,
            pin: pin.map(Zeroizing::new),
            key_label,
            key_id,
            require_hsm,
        }
    }

    /// Redacted debug: never render PIN material.
    pub fn redacted(&self) -> String {
        format!(
            "HsmConfig {{ enabled: {}, provider: {:?}, module_path_set: {}, slot_id: {:?}, pin_set: {}, key_label_set: {}, key_id_set: {}, require_hsm: {} }}",
            self.enabled,
            self.provider,
            !self.module_path.is_empty(),
            self.slot_id,
            self.pin.as_ref().map(|p| !p.is_empty()).unwrap_or(false),
            self.key_label.is_some(),
            self.key_id.is_some(),
            self.require_hsm,
        )
    }
}

/// PKCS#11 backend. Only compiled with `pkcs11`.
#[cfg(feature = "pkcs11")]
pub struct Pkcs11Hsm {
    context: cryptoki::context::Pkcs11,
    slot: cryptoki::slot::Slot,
    pin: Zeroizing<String>,
    key_label: Option<String>,
    key_id: Option<Vec<u8>>,
    algorithm: HsmAlgorithm,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Hsm {
    pub fn new(
        module_path: &str,
        slot_id: usize,
        pin: &str,
        key_label: Option<&str>,
        key_id: Option<&[u8]>,
        algorithm: crate::algorithm::Algorithm,
    ) -> Result<Self, HsmError> {
        use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
        use cryptoki::slot::Slot;

        if module_path.is_empty() {
            return Err(HsmError::InitializationFailed(
                "PKCS#11 module path is empty; refusing to guess a provider (fail-closed)"
                    .to_string(),
            ));
        }

        let context =
            Pkcs11::new(module_path).map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        // Already-initialized is benign (shared process); any other
        // initialization failure is returned fail-closed.
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {}
            Err(e) if e.to_string().contains("CRYPTOKI_ALREADY_INITIALIZED") => {}
            Err(e) => {
                return Err(HsmError::InitializationFailed(e.to_string()));
            }
        }

        let slots: Vec<Slot> = context
            .get_all_slots()
            .map_err(|e| HsmError::Provider(e.to_string()))?;
        let slot = *slots
            .get(slot_id)
            .ok_or_else(|| HsmError::Provider(format!("slot {slot_id} not found")))?;

        Ok(Self {
            context,
            slot,
            pin: Zeroizing::new(pin.to_string()),
            key_label: key_label.map(|s| s.to_string()),
            key_id: key_id.map(|b| b.to_vec()),
            algorithm: HsmAlgorithm::from(algorithm),
        })
    }

    fn open_session(&self) -> Result<cryptoki::session::Session, HsmError> {
        let session = self
            .context
            .open_rw_session(self.slot)
            .map_err(|e| HsmError::SessionError(e.to_string()))?;
        if !self.pin.is_empty() {
            session
                .login(
                    cryptoki::session::UserType::User,
                    Some(&cryptoki::types::AuthPin::new(
                        (*self.pin).clone().into_boxed_str(),
                    )),
                )
                .map_err(|e| HsmError::SessionError(e.to_string()))?;
        }
        Ok(session)
    }

    fn close_session(&self, session: &cryptoki::session::Session) {
        if !self.pin.is_empty() {
            let _ = session.logout();
        }
    }

    pub fn find_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        use cryptoki::object::{Attribute, ObjectClass};
        let session = self.open_session()?;
        let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        if let Some(ref label) = self.key_label {
            template.push(Attribute::Label(label.clone().into()));
        }
        if let Some(ref id) = self.key_id {
            template.push(Attribute::Id(id.clone()));
        }
        if template.len() == 1 {
            template.push(Attribute::Label("dnssec-key".into()));
        }
        let objects = session
            .find_objects(&template)
            .map_err(|e| HsmError::SessionError(e.to_string()))?;
        let handle = objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound("key not found for configured label/id".to_string())
        })?;
        self.close_session(&session);
        Ok(handle)
    }

    pub fn find_public_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        use cryptoki::object::{Attribute, ObjectClass};
        let session = self.open_session()?;
        let mut template = vec![Attribute::Class(ObjectClass::PUBLIC_KEY)];
        if let Some(ref label) = self.key_label {
            template.push(Attribute::Label(label.clone().into()));
        }
        if let Some(ref id) = self.key_id {
            template.push(Attribute::Id(id.clone()));
        }
        if template.len() == 1 {
            template.push(Attribute::Label("dnssec-key".into()));
        }
        let objects = session
            .find_objects(&template)
            .map_err(|e| HsmError::SessionError(e.to_string()))?;
        let handle = objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound("public key not found for configured label/id".to_string())
        })?;
        self.close_session(&session);
        Ok(handle)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_handle = self.find_key()?;
        let session = self.open_session()?;
        let mechanism = self.algorithm.to_cryptoki_mechanism();
        let signature = session
            .sign(&mechanism, key_handle, data)
            .map_err(|e| HsmError::SigningFailed(e.to_string()))?;
        self.close_session(&session);
        Ok(signature)
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        use cryptoki::object::{Attribute, AttributeType};
        let key_handle = self.find_public_key()?;
        let session = self.open_session()?;
        let attributes = session
            .get_attributes(
                key_handle,
                &[AttributeType::EcPoint, AttributeType::Modulus],
            )
            .map_err(|e| HsmError::SessionError(e.to_string()))?;
        self.close_session(&session);
        for attr in attributes {
            match attr {
                Attribute::EcPoint(point) => return Ok(point),
                Attribute::Modulus(modulus) => return Ok(modulus),
                _ => {}
            }
        }
        Err(HsmError::ObjectNotFound)
    }
}

#[cfg(feature = "pkcs11")]
impl Drop for Pkcs11Hsm {
    fn drop(&mut self) {
        self.pin.zeroize();
    }
}

#[cfg(feature = "pkcs11")]
impl HsmSigner for Pkcs11Hsm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Pkcs11Hsm::sign(self, data)
    }
    fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        Pkcs11Hsm::get_public_key(self)
    }
    fn key_id(&self) -> &str {
        self.key_label.as_deref().unwrap_or("unnamed")
    }
}

/// Software signer used for tests, development, and explicit `Soft`
/// provider selection. Never used as a silent fallback for a failed
/// PKCS#11 establishment: [`HsmManager::initialize`] only installs it when
/// the configuration explicitly requests `Soft` (or when HSM is disabled
/// and the caller explicitly asks for a software handle).
pub struct SoftHsm {
    key: ed25519_dalek::SigningKey,
    key_id: String,
}

impl SoftHsm {
    pub fn try_new(key_id: String) -> Result<Self, crate::error::KeystoreError> {
        let seed = crate::rng::random_bytes(32)?;
        let arr: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::KeystoreError::Entropy("short read".to_string()))?;
        Ok(Self {
            key: ed25519_dalek::SigningKey::from_bytes(&arr),
            key_id,
        })
    }

    pub fn new(key_id: String) -> Self {
        Self::try_new(key_id).expect("entropy failure at SoftHsm construction")
    }

    pub fn from_bytes(key_id: String, seed: &[u8]) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(
            seed.try_into()
                .expect("Ed25519 seed must be exactly 32 bytes"),
        );
        Self { key, key_id }
    }
}

impl HsmSigner for SoftHsm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        use ed25519_dalek::Signer;
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
    fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        Ok(self.key.verifying_key().to_bytes().to_vec())
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
}

pub enum HsmBackendKind {
    #[cfg(feature = "pkcs11")]
    Pkcs11,
    Soft,
}

/// Fail-closed HSM manager. Holds at most one opaque backend behind a
/// lock; the query path calls [`HsmManager::sign`] without ever seeing raw
/// handles or PINs.
pub struct HsmManager {
    backend: Arc<RwLock<Option<Box<dyn HsmSigner>>>>,
    require_hsm: Arc<RwLock<bool>>,
}

impl HsmManager {
    pub fn new() -> Self {
        Self {
            backend: Arc::new(RwLock::new(None)),
            require_hsm: Arc::new(RwLock::new(false)),
        }
    }

    /// Establish the configured backend. Fail-closed semantics:
    /// - disabled config → Ok, unavailable (no backend installed);
    /// - `Soft` provider → install software signer;
    /// - `Pkcs11` provider with the `pkcs11` feature → install PKCS#11
    ///   signer or return Err (never fall back to software);
    /// - `Pkcs11` provider without the feature → Err(`NotCompiled`) when
    ///   `require_hsm` is set, otherwise Ok-but-unavailable so normal
    ///   software-key builds keep serving unsigned/software-signed answers
    ///   per zone policy decided by the caller.
    pub fn initialize(&self, config: &HsmConfig) -> Result<(), HsmError> {
        *self.require_hsm.write() = config.require_hsm;
        if !config.enabled {
            tracing::info!("HSM disabled, using software keys");
            return Ok(());
        }
        match config.provider {
            HsmProvider::Soft => {
                let hsm = SoftHsm::try_new("soft-hsm-key".to_string())
                    .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;
                *self.backend.write() = Some(Box::new(hsm));
                tracing::info!("HSM initialized (SoftHSM)");
                Ok(())
            }
            HsmProvider::Pkcs11 => self.initialize_pkcs11(config),
        }
    }

    #[cfg(feature = "pkcs11")]
    fn initialize_pkcs11(&self, config: &HsmConfig) -> Result<(), HsmError> {
        let pin = config.pin.as_ref().map(|p| p.as_str()).unwrap_or("");
        let key_id_bytes = config.key_id.as_deref();
        let hsm = Pkcs11Hsm::new(
            &config.module_path,
            config.slot_id.unwrap_or(0),
            pin,
            config.key_label.as_deref().or(Some("dnssec-key")),
            key_id_bytes,
            crate::algorithm::Algorithm::Ed25519,
        )?;
        *self.backend.write() = Some(Box::new(hsm));
        tracing::info!("HSM initialized (PKCS#11)");
        Ok(())
    }

    #[cfg(not(feature = "pkcs11"))]
    fn initialize_pkcs11(&self, config: &HsmConfig) -> Result<(), HsmError> {
        // Fail closed when the operator requires HSM; otherwise report
        // unavailability without installing a silent software substitute.
        if config.require_hsm || !config.module_path.is_empty() {
            return Err(HsmError::NotCompiled);
        }
        tracing::warn!(
            "PKCS#11 requested but the `pkcs11` feature is not compiled; HSM unavailable (no fallback installed)"
        );
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.backend.read().is_some()
    }

    /// Whether the manager was configured to require HSM backing.
    pub fn requires_hsm(&self) -> bool {
        *self.require_hsm.read()
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        match self.backend.read().as_ref() {
            Some(signer) => signer.sign(data),
            None => Err(HsmError::Provider("HSM not initialized".to_string())),
        }
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        match self.backend.read().as_ref() {
            Some(signer) => signer.get_public_key(),
            None => Err(HsmError::Provider("HSM not initialized".to_string())),
        }
    }
}

impl Default for HsmManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soft_config() -> HsmConfig {
        HsmConfig {
            enabled: true,
            provider: HsmProvider::Soft,
            ..HsmConfig::default()
        }
    }

    #[test]
    fn soft_hsm_sign_verify_roundtrip() {
        let hsm = SoftHsm::new("test-key".to_string());
        let sig = hsm.sign(b"canonical").unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(hsm.get_public_key().unwrap().len(), 32);
        assert_eq!(hsm.key_id(), "test-key");
    }

    #[test]
    fn soft_hsm_deterministic_for_same_seed() {
        let a = SoftHsm::from_bytes("a".to_string(), &[1u8; 32]);
        let b = SoftHsm::from_bytes("b".to_string(), &[1u8; 32]);
        assert_eq!(a.sign(b"m").unwrap(), b.sign(b"m").unwrap());
    }

    #[test]
    fn manager_disabled_is_unavailable() {
        let m = HsmManager::new();
        m.initialize(&HsmConfig::default()).unwrap();
        assert!(!m.is_available());
        assert!(m.sign(b"x").is_err());
    }

    #[test]
    fn manager_soft_initializes() {
        let m = HsmManager::new();
        m.initialize(&soft_config()).unwrap();
        assert!(m.is_available());
        assert_eq!(m.sign(b"x").unwrap().len(), 64);
    }

    #[test]
    fn pkcs11_without_module_fails_closed() {
        let m = HsmManager::new();
        let config = HsmConfig {
            enabled: true,
            provider: HsmProvider::Pkcs11,
            module_path: String::new(),
            require_hsm: true,
            ..HsmConfig::default()
        };
        let err = m.initialize(&config).unwrap_err();
        // Either NotCompiled (feature off) or InitializationFailed (feature on,
        // empty path refused). Both are fail-closed; neither installs fallback.
        let msg = err.to_string();
        assert!(
            msg.contains("not compiled") || msg.contains("empty"),
            "unexpected: {msg}"
        );
        assert!(!m.is_available(), "no silent software fallback allowed");
    }

    #[test]
    fn hsm_config_redaction_never_contains_pin() {
        let config = HsmConfig {
            enabled: true,
            provider: HsmProvider::Pkcs11,
            module_path: "/lib/softhsm.so".to_string(),
            pin: Some(Zeroizing::new("super-secret-pin".to_string())),
            ..HsmConfig::default()
        };
        let rendered = config.redacted();
        assert!(!rendered.contains("super-secret-pin"));
    }

    #[test]
    fn no_silent_fallback_marker_absent() {
        // Static self-check: production code above the test module must not
        // contain the historical silent-fallback path. (The repo-guard test
        // enforces this workspace-wide; we split the marker to avoid
        // self-matching this assertion.)
        let src = include_str!("hsm.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        let marker = ["falling", "back", "to", "SoftHSM"].join(" ");
        assert!(!prod.contains(&marker));
    }
}
