use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum HsmError {
    #[error("HSM Provider: {0}")]
    Provider(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Initialization failed: {0}")]
    InitializationFailed(String),
    #[error("Session error: {0}")]
    SessionError(String),
    #[error("Object not found")]
    ObjectNotFound,
}

pub trait HsmSigner: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError>;
    fn get_public_key(&self) -> Result<Vec<u8>, HsmError>;
    fn key_id(&self) -> &str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Ed25519,
    RsaSha256,
}

impl Algorithm {
    pub fn to_cryptoki_mechanism(&self) -> cryptoki::mechanism::Mechanism {
        use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
        use cryptoki::mechanism::Mechanism;
        match self {
            Algorithm::Ed25519 => Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
            Algorithm::RsaSha256 => Mechanism::Sha256RsaPkcs,
        }
    }
}

impl From<super::dnssec::Algorithm> for Algorithm {
    fn from(algo: super::dnssec::Algorithm) -> Self {
        match algo {
            super::dnssec::Algorithm::Ed25519 => Algorithm::Ed25519,
            super::dnssec::Algorithm::RSA => Algorithm::RsaSha256,
        }
    }
}

pub enum HsmBackend {
    Pkcs11(Pkcs11Hsm),
    Soft(SoftHsm),
}

pub struct Pkcs11Hsm {
    context: cryptoki::context::Pkcs11,
    slot: cryptoki::slot::Slot,
    pin: cryptoki::types::AuthPin,
    key_label: String,
    algorithm: Algorithm,
    key_id: Vec<u8>,
}

impl Pkcs11Hsm {
    pub fn new(
        module_path: &str,
        slot_id: usize,
        pin: &str,
        key_label: &str,
        algorithm: super::dnssec::Algorithm,
    ) -> Result<Self, HsmError> {
        use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
        use cryptoki::slot::Slot;

        let context =
            Pkcs11::new(module_path).map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        let slots: Vec<Slot> = context
            .get_all_slots()
            .map_err(|e| HsmError::Provider(e.to_string()))?;

        let slot = slots
            .get(slot_id)
            .ok_or_else(|| HsmError::Provider(format!("Slot {} not found", slot_id)))?
            .clone();

        let key_id = key_label.as_bytes().to_vec();

        Ok(Self {
            context,
            slot,
            pin: cryptoki::types::AuthPin::new(pin.into()),
            key_label: key_label.to_string(),
            algorithm: Algorithm::from(algorithm),
            key_id,
        })
    }

    pub fn find_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        use cryptoki::object::{Attribute, ObjectClass};

        let session = self
            .context
            .open_rw_session(self.slot.clone())
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        session
            .login(cryptoki::session::UserType::User, Some(&self.pin))
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        let template = vec![
            Attribute::Label(self.key_label.clone().into()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sign(true),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        session
            .logout()
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound(format!("Key with label '{}' not found", self.key_label))
        })
    }

    pub fn find_public_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        use cryptoki::object::{Attribute, ObjectClass};

        let session = self
            .context
            .open_rw_session(self.slot.clone())
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        session
            .login(cryptoki::session::UserType::User, Some(&self.pin))
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        let template = vec![
            Attribute::Label(self.key_label.clone().into()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        session
            .logout()
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound(format!(
                "Public key with label '{}' not found",
                self.key_label
            ))
        })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_handle = self.find_key()?;

        let session = self
            .context
            .open_rw_session(self.slot.clone())
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        session
            .login(cryptoki::session::UserType::User, Some(&self.pin))
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        let mechanism = self.algorithm.to_cryptoki_mechanism();

        let signature = session
            .sign(&mechanism, key_handle, data)
            .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

        session
            .logout()
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        Ok(signature)
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        use cryptoki::object::{Attribute, AttributeType};

        let key_handle = self.find_public_key()?;

        let session = self
            .context
            .open_rw_session(self.slot.clone())
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        session
            .login(cryptoki::session::UserType::User, Some(&self.pin))
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        let attributes = session
            .get_attributes(
                key_handle,
                &[AttributeType::EcPoint, AttributeType::Modulus],
            )
            .map_err(|e| HsmError::SessionError(e.to_string()))?;

        let _ = session.logout();

        if let Some(Attribute::EcPoint(params)) = attributes.get(0) {
            Ok(params.clone())
        } else if let Some(Attribute::Modulus(modulus)) = attributes.get(0) {
            Ok(modulus.clone())
        } else {
            Err(HsmError::ObjectNotFound)
        }
    }
}

impl HsmSigner for Pkcs11Hsm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Pkcs11Hsm::sign(self, data)
    }

    fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        Pkcs11Hsm::get_public_key(self)
    }

    fn key_id(&self) -> &str {
        &self.key_label
    }
}

pub struct SoftHsm {
    key: ed25519_dalek::SigningKey,
    key_id: String,
}

impl SoftHsm {
    pub fn new(key_id: String) -> Self {
        let bytes = super::crypto_rng::random_bytes(32);
        let key = ed25519_dalek::SigningKey::from_bytes(bytes.as_slice().try_into().unwrap());
        Self { key, key_id }
    }

    pub fn from_bytes(key_id: String, seed: &[u8]) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(seed.try_into().unwrap());
        Self { key, key_id }
    }
}

impl HsmSigner for SoftHsm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        use ed25519_dalek::Signer;
        let sig = self.key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        use ed25519_dalek::VerifyingKey;
        Ok(self.key.verifying_key().to_bytes().to_vec())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }
}

pub struct HsmManager {
    backend: Arc<RwLock<Option<Box<dyn HsmSigner>>>>,
}

impl HsmManager {
    pub fn new() -> Self {
        Self {
            backend: Arc::new(RwLock::new(None)),
        }
    }

    pub fn initialize(&self, config: &crate::config::dns::HsmConfig) -> Result<(), HsmError> {
        if !config.enabled {
            tracing::info!("HSM disabled, using in-memory keys");
            return Ok(());
        }

        match config.provider {
            crate::config::dns::HsmProvider::Pkcs11 => {
                if config.module_path.is_empty() {
                    tracing::warn!("PKCS#11 module path not specified, falling back to SoftHSM");
                    let key_id = "soft-hsm-key".to_string();
                    let hsm = SoftHsm::new(key_id);
                    *self.backend.write() = Some(Box::new(hsm));
                    tracing::info!("HSM initialized (SoftHSM fallback)");
                    return Ok(());
                }

                match Pkcs11Hsm::new(
                    &config.module_path,
                    config.slot_id.unwrap_or(0),
                    config.pin.as_deref().unwrap_or(""),
                    "dnssec-key",
                    super::dnssec::Algorithm::Ed25519,
                ) {
                    Ok(hsm) => {
                        *self.backend.write() = Some(Box::new(hsm));
                        tracing::info!("HSM initialized (PKCS#11)");
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to initialize PKCS#11 HSM: {}, falling back to SoftHSM",
                            e
                        );
                        let key_id = "soft-hsm-key".to_string();
                        let hsm = SoftHsm::new(key_id);
                        *self.backend.write() = Some(Box::new(hsm));
                    }
                }
            }
            crate::config::dns::HsmProvider::Soft => {
                let key_id = "soft-hsm-key".to_string();
                let hsm = SoftHsm::new(key_id);
                *self.backend.write() = Some(Box::new(hsm));
                tracing::info!("HSM initialized (SoftHSM)");
            }
        }

        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.backend.read().is_some()
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let backend = self.backend.read();
        match backend.as_ref() {
            Some(signer) => signer.sign(data),
            None => Err(HsmError::Provider("HSM not initialized".to_string())),
        }
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        let backend = self.backend.read();
        match backend.as_ref() {
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

    #[test]
    fn test_soft_hsm_sign_verify() {
        let hsm = SoftHsm::new("test-key".to_string());

        let data = b"test data to sign";
        let signature = hsm.sign(data).expect("signing should succeed");

        assert_eq!(signature.len(), 64, "Ed25519 signatures are 64 bytes");

        let public_key = hsm.get_public_key().expect("get_public_key should succeed");
        assert_eq!(public_key.len(), 32, "Ed25519 public keys are 32 bytes");
    }

    #[test]
    fn test_soft_hsm_key_id() {
        let key_id = "my-custom-key-id";
        let hsm = SoftHsm::new(key_id.to_string());
        assert_eq!(hsm.key_id(), key_id);
    }

    #[test]
    fn test_soft_hsm_from_bytes() {
        let seed = [0u8; 32];
        let hsm = SoftHsm::from_bytes("test".to_string(), &seed);

        let data = b"sign me";
        let sig1 = hsm.sign(data).expect("signing should succeed");

        let sig2 = hsm.sign(data).expect("signing should succeed");
        assert_eq!(
            sig1, sig2,
            "same key should produce same signature for same input"
        );
    }

    #[test]
    fn test_soft_hsm_deterministic_signatures() {
        let seed = [1u8; 32];
        let hsm1 = SoftHsm::from_bytes("key1".to_string(), &seed);
        let hsm2 = SoftHsm::from_bytes("key2".to_string(), &seed);

        let data = b"test data";

        let sig1 = hsm1.sign(data).expect("signing should succeed");
        let sig2 = hsm2.sign(data).expect("signing should succeed");

        assert_eq!(
            sig1, sig2,
            "identical seeds should produce identical signatures"
        );
    }

    #[test]
    fn test_hsm_manager_default_uninitialized() {
        let manager = HsmManager::new();
        assert!(
            !manager.is_available(),
            "manager should not be available by default"
        );
    }

    #[test]
    fn test_hsm_manager_init_soft() {
        let manager = HsmManager::new();
        let config = crate::config::dns::HsmConfig {
            enabled: true,
            provider: crate::config::dns::HsmProvider::Soft,
            module_path: String::new(),
            slot_id: None,
            pin: None,
        };

        manager
            .initialize(&config)
            .expect("initialization should succeed");
        assert!(
            manager.is_available(),
            "manager should be available after init"
        );

        let signature = manager.sign(b"test").expect("signing should succeed");
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_hsm_manager_disabled() {
        let manager = HsmManager::new();
        let config = crate::config::dns::HsmConfig {
            enabled: false,
            provider: crate::config::dns::HsmProvider::Soft,
            module_path: String::new(),
            slot_id: None,
            pin: None,
        };

        manager
            .initialize(&config)
            .expect("initialization should succeed");
        assert!(
            manager.is_available(),
            "manager should be available (soft fallback)"
        );
    }

    #[test]
    fn test_algorithm_from_dnssec() {
        assert_eq!(
            Algorithm::from(super::super::dnssec::Algorithm::Ed25519),
            Algorithm::Ed25519
        );
        assert_eq!(
            Algorithm::from(super::super::dnssec::Algorithm::RSA),
            Algorithm::RsaSha256
        );
    }
}
