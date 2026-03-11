use parking_lot::RwLock;
use std::sync::Arc;

pub trait HsmSigner: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HsmError>;
    fn get_public_key(&self) -> Result<Vec<u8>, HsmError>;
    fn key_id(&self) -> &str;
}

#[derive(Debug, Clone)]
pub enum HsmError {
    Provider(String),
    KeyNotFound(String),
    SigningFailed(String),
    InitializationFailed(String),
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmError::Provider(msg) => write!(f, "HSM Provider: {}", msg),
            HsmError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            HsmError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            HsmError::InitializationFailed(msg) => write!(f, "Initialization failed: {}", msg),
        }
    }
}

impl std::error::Error for HsmError {}

pub enum HsmBackend {
    Pkcs11(Pkcs11Hsm),
    Soft(SoftHsm),
}

pub struct Pkcs11Hsm {
    #[allow(dead_code)]
    context: cryptoki::context::Pkcs11,
    key_id: Vec<u8>,
    algorithm: super::dnssec::Algorithm,
}

impl Pkcs11Hsm {
    #[allow(dead_code)]
    pub fn new(
        module_path: &str,
        slot_id: usize,
        pin: &str,
        key_label: &str,
        algorithm: super::dnssec::Algorithm,
    ) -> Result<Self, HsmError> {
        use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
        use cryptoki::mechanism::Mechanism;
        use cryptoki::slot::Slot;

        let context =
            Pkcs11::new(module_path).map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        let slots: Vec<Slot> = context
            .get_all_slots()
            .map_err(|e| HsmError::Provider(e.to_string()))?;

        let _slot = slots
            .get(slot_id)
            .ok_or_else(|| HsmError::Provider(format!("Slot {} not found", slot_id)))?;

        // Note: Session handling has changed in cryptoki 0.12
        // For now, we skip session creation as this is a stub implementation
        tracing::warn!("PKCS#11 session creation is a stub - using SoftHSM recommended");

        let key_id = key_label.as_bytes().to_vec();

        Ok(Self {
            context,
            key_id,
            algorithm,
        })
    }

    #[allow(dead_code)]
    pub fn find_key(
        &self,
        _session: &cryptoki::session::Session,
        key_label: &str,
    ) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        use cryptoki::object::Attribute;

        tracing::warn!("PKCS#11 find_key is a stub - key lookup not implemented");
        let _ = key_label;
        Err(HsmError::KeyNotFound(
            "Key lookup not implemented".to_string(),
        ))
    }
}

impl HsmSigner for Pkcs11Hsm {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        tracing::warn!("PKCS#11 signing requires full session context - using stub");
        Err(HsmError::SigningFailed(
            "PKCS#11 signing not fully implemented - use SoftHSM for now".to_string(),
        ))
    }

    fn get_public_key(&self) -> Result<Vec<u8>, HsmError> {
        tracing::warn!("PKCS#11 get_public_key requires full session context - using stub");
        Err(HsmError::Provider(
            "PKCS#11 not fully implemented - use SoftHSM for now".to_string(),
        ))
    }

    fn key_id(&self) -> &str {
        "pkcs11-key"
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
