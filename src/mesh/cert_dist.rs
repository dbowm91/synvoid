use std::collections::HashMap;
use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use parking_lot::RwLock;
use sha2::Sha256;

const NONCE_SIZE: usize = 12;
const DERIVED_KEY_SIZE: usize = 32;
const HKDF_INFO: &[u8] = b"synvoid-cert-dist";

#[derive(Debug, Clone)]
pub struct EncryptedCertData {
    pub site_id: String,
    pub cert_data: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecryptedCert {
    pub cert_data: Vec<u8>,
    pub key_pem: Vec<u8>,
}

pub struct CertDistManager {
    mesh_session_key: Vec<u8>,
    certs: Arc<RwLock<HashMap<String, DecryptedCert>>>,
}

impl CertDistManager {
    pub fn new(mesh_session_key: Vec<u8>) -> Self {
        Self {
            mesh_session_key,
            certs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn distribute_cert(
        &self,
        site_id: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<EncryptedCertData, CertDistError> {
        let per_site_key = self.derive_site_key(site_id)?;

        let cipher = Aes256Gcm::new_from_slice(&per_site_key)
            .map_err(|e| CertDistError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::clone_from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, key_pem)
            .map_err(|e| CertDistError::Encryption(e.to_string()))?;

        let encrypted_key = ciphertext;

        let mut certs = self.certs.write();
        certs.insert(
            site_id.to_string(),
            DecryptedCert {
                cert_data: cert_pem.to_vec(),
                key_pem: key_pem.to_vec(),
            },
        );

        Ok(EncryptedCertData {
            site_id: site_id.to_string(),
            cert_data: cert_pem.to_vec(),
            encrypted_key,
            nonce: nonce_bytes.to_vec(),
        })
    }

    pub fn receive_cert(
        &self,
        encrypted: &EncryptedCertData,
    ) -> Result<DecryptedCert, CertDistError> {
        let per_site_key = self.derive_site_key(&encrypted.site_id)?;

        let cipher = Aes256Gcm::new_from_slice(&per_site_key)
            .map_err(|e| CertDistError::Decryption(e.to_string()))?;

        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(CertDistError::Decryption(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_SIZE,
                encrypted.nonce.len()
            )));
        }

        let nonce = Nonce::clone_from_slice(&encrypted.nonce);

        let key_pem = cipher
            .decrypt(&nonce, encrypted.encrypted_key.as_ref())
            .map_err(|e| CertDistError::Decryption(e.to_string()))?;

        let cert = DecryptedCert {
            cert_data: encrypted.cert_data.clone(),
            key_pem,
        };

        let mut certs = self.certs.write();
        certs.insert(encrypted.site_id.clone(), cert.clone());

        Ok(cert)
    }

    pub fn get_cert(&self, site_id: &str) -> Option<DecryptedCert> {
        self.certs.read().get(site_id).cloned()
    }

    pub fn remove_cert(&self, site_id: &str) -> bool {
        self.certs.write().remove(site_id).is_some()
    }

    pub fn has_cert(&self, site_id: &str) -> bool {
        self.certs.read().contains_key(site_id)
    }

    pub fn list_sites(&self) -> Vec<String> {
        self.certs.read().keys().cloned().collect()
    }

    pub fn rotate_session_key(
        &mut self,
        new_mesh_session_key: Vec<u8>,
    ) -> Result<Vec<(String, EncryptedCertData)>, CertDistError> {
        let old_certs: Vec<(String, DecryptedCert)> = self
            .certs
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut re_encrypted = Vec::new();
        for (site_id, cert) in old_certs {
            let encrypted = self.distribute_cert_with_key(
                &site_id,
                &cert.cert_data,
                &cert.key_pem,
                &new_mesh_session_key,
            )?;
            re_encrypted.push((site_id, encrypted));
        }

        self.mesh_session_key = new_mesh_session_key;

        Ok(re_encrypted)
    }

    fn distribute_cert_with_key(
        &self,
        site_id: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        mesh_session_key: &[u8],
    ) -> Result<EncryptedCertData, CertDistError> {
        let per_site_key = self.derive_site_key_with_key(site_id, mesh_session_key)?;

        let cipher = Aes256Gcm::new_from_slice(&per_site_key)
            .map_err(|e| CertDistError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::clone_from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, key_pem)
            .map_err(|e| CertDistError::Encryption(e.to_string()))?;

        Ok(EncryptedCertData {
            site_id: site_id.to_string(),
            cert_data: cert_pem.to_vec(),
            encrypted_key: ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    fn derive_site_key_with_key(
        &self,
        site_id: &str,
        mesh_session_key: &[u8],
    ) -> Result<[u8; DERIVED_KEY_SIZE], CertDistError> {
        let hk = Hkdf::<Sha256>::new(None, mesh_session_key);

        let mut okm = [0u8; DERIVED_KEY_SIZE];
        let info = self.build_hkdf_info(site_id);
        hk.expand(&info, &mut okm)
            .map_err(|e| CertDistError::KeyDerivation(e.to_string()))?;

        Ok(okm)
    }

    fn derive_site_key(&self, site_id: &str) -> Result<[u8; DERIVED_KEY_SIZE], CertDistError> {
        let hk = Hkdf::<Sha256>::new(None, &self.mesh_session_key);

        let mut okm = [0u8; DERIVED_KEY_SIZE];
        let info = self.build_hkdf_info(site_id);
        hk.expand(&info, &mut okm)
            .map_err(|e| CertDistError::KeyDerivation(e.to_string()))?;

        Ok(okm)
    }

    fn build_hkdf_info(&self, site_id: &str) -> Vec<u8> {
        let mut info = Vec::with_capacity(HKDF_INFO.len() + site_id.len() + 1);
        info.extend_from_slice(HKDF_INFO);
        info.push(0);
        info.extend_from_slice(site_id.as_bytes());
        info
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CertDistError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
    #[error("Certificate not found: {0}")]
    NotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> CertDistManager {
        let mut key = [0u8; 32];
        rand::fill(&mut key);
        CertDistManager::new(key.to_vec())
    }

    #[test]
    fn test_distribute_and_receive() {
        let manager = make_manager();
        let cert_pem = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let key_pem = b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";

        let encrypted = manager.distribute_cert("site1", cert_pem, key_pem).unwrap();

        assert_eq!(encrypted.site_id, "site1");
        assert_eq!(encrypted.cert_data, cert_pem);
        assert_eq!(encrypted.nonce.len(), NONCE_SIZE);
        assert_ne!(encrypted.encrypted_key, key_pem);

        let decrypted = manager.receive_cert(&encrypted).unwrap();
        assert_eq!(decrypted.cert_data, cert_pem);
        assert_eq!(decrypted.key_pem, key_pem);
    }

    #[test]
    fn test_different_sites_different_keys() {
        let manager = make_manager();
        let cert_pem = b"cert";
        let key_pem = b"key";

        let enc1 = manager.distribute_cert("site1", cert_pem, key_pem).unwrap();
        let enc2 = manager.distribute_cert("site2", cert_pem, key_pem).unwrap();

        assert_ne!(enc1.encrypted_key, enc2.encrypted_key);
    }

    #[test]
    fn test_wrong_site_cannot_decrypt() {
        let manager1 = make_manager();
        let manager2 = make_manager();
        let cert_pem = b"cert";
        let key_pem = b"key";

        let encrypted = manager1
            .distribute_cert("site1", cert_pem, key_pem)
            .unwrap();

        assert!(manager2.receive_cert(&encrypted).is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let manager = make_manager();
        let cert_pem = b"cert";
        let key_pem = b"key";

        let mut encrypted = manager.distribute_cert("site1", cert_pem, key_pem).unwrap();
        encrypted.nonce = vec![0u8; 4];

        assert!(manager.receive_cert(&encrypted).is_err());
    }

    #[test]
    fn test_get_and_list() {
        let manager = make_manager();
        let cert_pem = b"cert";
        let key_pem = b"key";

        manager.distribute_cert("site1", cert_pem, key_pem).unwrap();
        manager.distribute_cert("site2", cert_pem, key_pem).unwrap();

        assert!(manager.has_cert("site1"));
        assert!(manager.has_cert("site2"));
        assert!(!manager.has_cert("site3"));

        let mut sites = manager.list_sites();
        sites.sort();
        assert_eq!(sites, vec!["site1", "site2"]);
    }

    #[test]
    fn test_remove_cert() {
        let manager = make_manager();
        let cert_pem = b"cert";
        let key_pem = b"key";

        manager.distribute_cert("site1", cert_pem, key_pem).unwrap();
        assert!(manager.has_cert("site1"));

        assert!(manager.remove_cert("site1"));
        assert!(!manager.has_cert("site1"));
        assert!(!manager.remove_cert("site1"));
    }

    #[test]
    fn test_rotate_session_key() {
        let mut old_key = [0u8; 32];
        let mut new_key = [1u8; 32];
        rand::fill(&mut old_key);
        rand::fill(&mut new_key);

        let mut manager = CertDistManager::new(old_key.to_vec());
        let cert_pem = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let key_pem = b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";

        manager.distribute_cert("site1", cert_pem, key_pem).unwrap();
        manager.distribute_cert("site2", cert_pem, key_pem).unwrap();

        let re_encrypted = manager.rotate_session_key(new_key.to_vec()).unwrap();

        assert_eq!(re_encrypted.len(), 2);

        let re_encrypted_site1 = re_encrypted
            .iter()
            .find(|(id, _)| id == "site1")
            .map(|(_, e)| e)
            .unwrap();
        assert_eq!(re_encrypted_site1.site_id, "site1");
        assert_eq!(re_encrypted_site1.cert_data, cert_pem);
    }
}
