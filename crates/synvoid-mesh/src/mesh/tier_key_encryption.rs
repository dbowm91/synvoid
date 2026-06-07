use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

const NONCE_SIZE: usize = 12;
const DERIVED_KEY_SIZE: usize = 32;
const HKDF_INFO: &[u8] = b"synvoid-tier-key-encrypt";
const TRANSMISSION_HKDF_INFO: &[u8] = b"synvoid-tier-key-transmit";

const HKDF_INFO_ORG: &[u8] = b"synvoid-privileged-org";
const HKDF_INFO_MEMBER_CERT: &[u8] = b"synvoid-privileged-member-cert";
const HKDF_INFO_GLOBAL_NODE_LIST: &[u8] = b"synvoid-privileged-global-node-list";
const HKDF_INFO_ORG_NAME_RESERVATION: &[u8] = b"synvoid-privileged-org-name-reservation";
const HKDF_INFO_DNS_ZONE: &[u8] = b"synvoid-privileged-dns-zone";
const HKDF_INFO_DNS_DOMAIN_REG: &[u8] = b"synvoid-privileged-dns-domain-reg";
const HKDF_INFO_ANYCAST_NODE: &[u8] = b"synvoid-privileged-anycast-node";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegedRecordType {
    Organization,
    TierKey,
    MemberCertificate,
    GlobalNodeList,
    OrgNameReservation,
    DnsZone,
    DnsDomainRegistration,
    AnycastNode,
}

impl PrivilegedRecordType {
    fn hkdf_info(&self) -> &[u8] {
        match self {
            PrivilegedRecordType::Organization => HKDF_INFO_ORG,
            PrivilegedRecordType::TierKey => HKDF_INFO,
            PrivilegedRecordType::MemberCertificate => HKDF_INFO_MEMBER_CERT,
            PrivilegedRecordType::GlobalNodeList => HKDF_INFO_GLOBAL_NODE_LIST,
            PrivilegedRecordType::OrgNameReservation => HKDF_INFO_ORG_NAME_RESERVATION,
            PrivilegedRecordType::DnsZone => HKDF_INFO_DNS_ZONE,
            PrivilegedRecordType::DnsDomainRegistration => HKDF_INFO_DNS_DOMAIN_REG,
            PrivilegedRecordType::AnycastNode => HKDF_INFO_ANYCAST_NODE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedPrivilegedData {
    pub record_type: PrivilegedRecordType,
    pub context: String,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl EncryptedPrivilegedData {
    pub fn record_type(&self) -> &PrivilegedRecordType {
        &self.record_type
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedTierKeyData {
    pub org_id: String,
    pub tier: u32,
    pub key_id: String,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl EncryptedTierKeyData {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TierKeyEncryptionError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
}

pub struct TierKeyEncryption {
    master_key: Vec<u8>,
}

impl TierKeyEncryption {
    pub fn new(master_key: Vec<u8>) -> Self {
        Self { master_key }
    }

    #[allow(deprecated)]
    pub fn encrypt_for_transmission(
        &self,
        tier_key_bytes: &[u8],
        transmission_key: &[u8; 32],
    ) -> Vec<u8> {
        let cipher = match Aes256Gcm::new_from_slice(transmission_key) {
            Ok(c) => c,
            Err(_) => return tier_key_bytes.to_vec(),
        };

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(nonce, tier_key_bytes) {
            Ok(ciphertext) => {
                let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&ciphertext);
                result
            }
            Err(_) => tier_key_bytes.to_vec(),
        }
    }

    #[allow(deprecated)]
    pub fn decrypt_for_transmission(
        &self,
        encrypted_data: &[u8],
        transmission_key: &[u8; 32],
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted_data.len() < NONCE_SIZE {
            return Err(TierKeyEncryptionError::Decryption(
                "Data too short for nonce".to_string(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(transmission_key)
            .map_err(|e| TierKeyEncryptionError::Decryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted_data[..NONCE_SIZE]);
        let ciphertext = &encrypted_data[NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| TierKeyEncryptionError::Decryption(e.to_string()))
    }

    #[allow(deprecated)]
    pub fn encrypt_tier_key_data(
        &self,
        org_id: &str,
        tier: u32,
        key_id: &str,
        tier_key_bytes: &[u8],
    ) -> Result<EncryptedTierKeyData, TierKeyEncryptionError> {
        let context = format!("{}:{}:{}", org_id, tier, key_id);
        let per_key = self.derive_encryption_key(&context)?;

        let cipher = Aes256Gcm::new_from_slice(&per_key)
            .map_err(|e| TierKeyEncryptionError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, tier_key_bytes)
            .map_err(|e| TierKeyEncryptionError::Encryption(e.to_string()))?;

        Ok(EncryptedTierKeyData {
            org_id: org_id.to_string(),
            tier,
            key_id: key_id.to_string(),
            encrypted_key: ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    #[allow(deprecated)]
    pub fn decrypt_tier_key_data(
        &self,
        encrypted: &EncryptedTierKeyData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        let context = format!(
            "{}:{}:{}",
            encrypted.org_id, encrypted.tier, encrypted.key_id
        );
        let per_key = self.derive_encryption_key(&context)?;

        let cipher = Aes256Gcm::new_from_slice(&per_key)
            .map_err(|e| TierKeyEncryptionError::Decryption(e.to_string()))?;

        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(TierKeyEncryptionError::Decryption(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_SIZE,
                encrypted.nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.encrypted_key.as_ref())
            .map_err(|e| TierKeyEncryptionError::Decryption(e.to_string()))
    }

    fn derive_encryption_key(
        &self,
        context: &str,
    ) -> Result<[u8; DERIVED_KEY_SIZE], TierKeyEncryptionError> {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);

        let mut okm = [0u8; DERIVED_KEY_SIZE];
        let info = Self::build_hkdf_info(context);
        hk.expand(&info, &mut okm)
            .map_err(|e| TierKeyEncryptionError::KeyDerivation(e.to_string()))?;

        Ok(okm)
    }

    fn derive_privileged_key(
        &self,
        record_type: &PrivilegedRecordType,
        context: &str,
    ) -> Result<[u8; DERIVED_KEY_SIZE], TierKeyEncryptionError> {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);

        let hkdf_info = record_type.hkdf_info();
        let ctx_bytes = context.as_bytes();
        let mut info = Vec::with_capacity(hkdf_info.len() + ctx_bytes.len() + 1);
        info.extend_from_slice(hkdf_info);
        info.push(0);
        info.extend_from_slice(ctx_bytes);

        let mut okm = [0u8; DERIVED_KEY_SIZE];
        hk.expand(&info, &mut okm)
            .map_err(|e| TierKeyEncryptionError::KeyDerivation(e.to_string()))?;

        Ok(okm)
    }

    #[allow(deprecated)]
    fn encrypt_privileged_internal(
        &self,
        record_type: PrivilegedRecordType,
        context: &str,
        data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        let per_key = self.derive_privileged_key(&record_type, context)?;

        let cipher = Aes256Gcm::new_from_slice(&per_key)
            .map_err(|e| TierKeyEncryptionError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| TierKeyEncryptionError::Encryption(e.to_string()))?;

        Ok(EncryptedPrivilegedData {
            record_type,
            context: context.to_string(),
            encrypted_data: ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    #[allow(deprecated)]
    fn decrypt_privileged_internal(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        let per_key = self.derive_privileged_key(&encrypted.record_type, &encrypted.context)?;

        let cipher = Aes256Gcm::new_from_slice(&per_key)
            .map_err(|e| TierKeyEncryptionError::Decryption(e.to_string()))?;

        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(TierKeyEncryptionError::Decryption(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_SIZE,
                encrypted.nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.encrypted_data.as_ref())
            .map_err(|e| TierKeyEncryptionError::Decryption(e.to_string()))
    }

    pub fn encrypt_organization_data(
        &self,
        org_id: &str,
        org_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        self.encrypt_privileged_internal(PrivilegedRecordType::Organization, org_id, org_data)
    }

    pub fn decrypt_organization_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::Organization {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for organization decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn encrypt_member_certificate_data(
        &self,
        org_id: &str,
        cert_id: &str,
        cert_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        let context = format!("{}:{}", org_id, cert_id);
        self.encrypt_privileged_internal(
            PrivilegedRecordType::MemberCertificate,
            &context,
            cert_data,
        )
    }

    pub fn decrypt_member_certificate_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::MemberCertificate {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for member certificate decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn encrypt_global_node_list_data(
        &self,
        list_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        self.encrypt_privileged_internal(PrivilegedRecordType::GlobalNodeList, "", list_data)
    }

    pub fn decrypt_global_node_list_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::GlobalNodeList {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for global node list decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn encrypt_org_name_reservation_data(
        &self,
        org_name: &str,
        reservation_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        self.encrypt_privileged_internal(
            PrivilegedRecordType::OrgNameReservation,
            org_name,
            reservation_data,
        )
    }

    pub fn decrypt_org_name_reservation_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::OrgNameReservation {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for org name reservation decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn encrypt_dns_zone_data(
        &self,
        zone: &str,
        zone_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        self.encrypt_privileged_internal(PrivilegedRecordType::DnsZone, zone, zone_data)
    }

    pub fn decrypt_dns_zone_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::DnsZone {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for DNS zone decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn encrypt_dns_domain_registration_data(
        &self,
        domain: &str,
        registration_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        self.encrypt_privileged_internal(
            PrivilegedRecordType::DnsDomainRegistration,
            domain,
            registration_data,
        )
    }

    pub fn decrypt_dns_domain_registration_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::DnsDomainRegistration {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for DNS domain registration decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn encrypt_anycast_node_data(
        &self,
        node_id: &str,
        anycast_data: &[u8],
    ) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
        self.encrypt_privileged_internal(PrivilegedRecordType::AnycastNode, node_id, anycast_data)
    }

    pub fn decrypt_anycast_node_data(
        &self,
        encrypted: &EncryptedPrivilegedData,
    ) -> Result<Vec<u8>, TierKeyEncryptionError> {
        if encrypted.record_type != PrivilegedRecordType::AnycastNode {
            return Err(TierKeyEncryptionError::Decryption(
                "Wrong record type for anycast node decryption".to_string(),
            ));
        }
        self.decrypt_privileged_internal(encrypted)
    }

    pub fn build_hkdf_info(context: &str) -> Vec<u8> {
        let ctx_bytes = context.as_bytes();
        let mut info = Vec::with_capacity(HKDF_INFO.len() + ctx_bytes.len() + 1);
        info.extend_from_slice(HKDF_INFO);
        info.push(0);
        info.extend_from_slice(ctx_bytes);
        info
    }

    pub fn build_transmission_hkdf_info() -> Vec<u8> {
        TRANSMISSION_HKDF_INFO.to_vec()
    }
}

pub fn derive_transmission_key(session_key: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut okm = [0u8; DERIVED_KEY_SIZE];
    let info = TierKeyEncryption::build_transmission_hkdf_info();
    let _ = hk.expand(&info, &mut okm);
    okm
}

pub fn serialize_encrypted_tier_key(encrypted: &EncryptedTierKeyData) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&[0u8; 4]); // placeholder for total length
    result.extend_from_slice(&(encrypted.org_id.len() as u32).to_be_bytes());
    result.extend_from_slice(encrypted.org_id.as_bytes());
    result.extend_from_slice(&encrypted.tier.to_be_bytes());
    result.extend_from_slice(&(encrypted.key_id.len() as u32).to_be_bytes());
    result.extend_from_slice(encrypted.key_id.as_bytes());
    result.extend_from_slice(&(encrypted.nonce.len() as u32).to_be_bytes());
    result.extend_from_slice(&encrypted.nonce);
    result.extend_from_slice(&(encrypted.encrypted_key.len() as u32).to_be_bytes());
    result.extend_from_slice(&encrypted.encrypted_key);

    let total_len = (result.len() - 4) as u32;
    result[..4].copy_from_slice(&total_len.to_be_bytes());
    result
}

pub fn deserialize_encrypted_tier_key(
    data: &[u8],
) -> Result<EncryptedTierKeyData, TierKeyEncryptionError> {
    let mut offset = 4; // Skip total length prefix

    if data.len() < offset + 4 {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short".to_string(),
        ));
    }

    let org_id_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;
    let org_id = String::from_utf8_lossy(&data[offset..offset + org_id_len]).to_string();
    offset += org_id_len;

    let tier = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    let key_id_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;
    let key_id = String::from_utf8_lossy(&data[offset..offset + key_id_len]).to_string();
    offset += key_id_len;

    let nonce_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;
    let nonce = data[offset..offset + nonce_len].to_vec();
    offset += nonce_len;

    let encrypted_key_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;
    let encrypted_key = data[offset..offset + encrypted_key_len].to_vec();

    Ok(EncryptedTierKeyData {
        org_id,
        tier,
        key_id,
        encrypted_key,
        nonce,
    })
}

pub fn serialize_encrypted_privileged(encrypted: &EncryptedPrivilegedData) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&[0u8; 4]);
    let record_type_byte: u8 = match encrypted.record_type {
        PrivilegedRecordType::Organization => 0,
        PrivilegedRecordType::TierKey => 1,
        PrivilegedRecordType::MemberCertificate => 2,
        PrivilegedRecordType::GlobalNodeList => 3,
        PrivilegedRecordType::OrgNameReservation => 4,
        PrivilegedRecordType::DnsZone => 5,
        PrivilegedRecordType::DnsDomainRegistration => 6,
        PrivilegedRecordType::AnycastNode => 7,
    };
    result.push(record_type_byte);
    result.extend_from_slice(&(encrypted.context.len() as u32).to_be_bytes());
    result.extend_from_slice(encrypted.context.as_bytes());
    result.extend_from_slice(&(encrypted.nonce.len() as u32).to_be_bytes());
    result.extend_from_slice(&encrypted.nonce);
    result.extend_from_slice(&(encrypted.encrypted_data.len() as u32).to_be_bytes());
    result.extend_from_slice(&encrypted.encrypted_data);

    let total_len = (result.len() - 4) as u32;
    result[..4].copy_from_slice(&total_len.to_be_bytes());
    result
}

pub fn deserialize_encrypted_privileged(
    data: &[u8],
) -> Result<EncryptedPrivilegedData, TierKeyEncryptionError> {
    let mut offset = 4;

    if data.len() < offset + 1 {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for record type".to_string(),
        ));
    }

    let record_type_byte = data[offset];
    offset += 1;

    let record_type = match record_type_byte {
        0 => PrivilegedRecordType::Organization,
        1 => PrivilegedRecordType::TierKey,
        2 => PrivilegedRecordType::MemberCertificate,
        3 => PrivilegedRecordType::GlobalNodeList,
        4 => PrivilegedRecordType::OrgNameReservation,
        5 => PrivilegedRecordType::DnsZone,
        6 => PrivilegedRecordType::DnsDomainRegistration,
        7 => PrivilegedRecordType::AnycastNode,
        _ => {
            return Err(TierKeyEncryptionError::Decryption(format!(
                "Unknown record type byte: {}",
                record_type_byte
            )));
        }
    };

    if data.len() < offset + 4 {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for context length".to_string(),
        ));
    }

    let context_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + context_len {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for context".to_string(),
        ));
    }
    let context = String::from_utf8_lossy(&data[offset..offset + context_len]).to_string();
    offset += context_len;

    if data.len() < offset + 4 {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for nonce length".to_string(),
        ));
    }

    let nonce_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + nonce_len {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for nonce".to_string(),
        ));
    }
    let nonce = data[offset..offset + nonce_len].to_vec();
    offset += nonce_len;

    if data.len() < offset + 4 {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for encrypted data length".to_string(),
        ));
    }

    let encrypted_data_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + encrypted_data_len {
        return Err(TierKeyEncryptionError::Decryption(
            "Data too short for encrypted data".to_string(),
        ));
    }
    let encrypted_data = data[offset..offset + encrypted_data_len].to_vec();

    Ok(EncryptedPrivilegedData {
        record_type,
        context,
        encrypted_data,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_encrypter() -> TierKeyEncryption {
        let mut key = [0u8; 32];
        rand::fill(&mut key);
        TierKeyEncryption::new(key.to_vec())
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encrypter = make_encrypter();
        let tier_key = b"my_super_secret_tier_key_data_32bytes!";

        let encrypted = encrypter
            .encrypt_tier_key_data("org-123", 1, "key-abc", tier_key)
            .unwrap();

        assert_eq!(encrypted.org_id, "org-123");
        assert_eq!(encrypted.tier, 1);
        assert_eq!(encrypted.key_id, "key-abc");
        assert_ne!(encrypted.encrypted_key, tier_key.to_vec());

        let decrypted = encrypter.decrypt_tier_key_data(&encrypted).unwrap();
        assert_eq!(decrypted, tier_key.to_vec());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let encrypter = make_encrypter();
        let tier_key = b"test_key_16_bytes!";

        let encrypted = encrypter
            .encrypt_tier_key_data("org-1", 2, "key-xyz", tier_key)
            .unwrap();

        let serialized = serialize_encrypted_tier_key(&encrypted);
        let deserialized = deserialize_encrypted_tier_key(&serialized).unwrap();

        assert_eq!(deserialized.org_id, encrypted.org_id);
        assert_eq!(deserialized.tier, encrypted.tier);
        assert_eq!(deserialized.key_id, encrypted.key_id);

        let decrypted = encrypter.decrypt_tier_key_data(&deserialized).unwrap();
        assert_eq!(decrypted, tier_key.to_vec());
    }

    #[test]
    fn test_different_contexts_different_keys() {
        let encrypter = make_encrypter();
        let tier_key = b"test_key";

        let enc1 = encrypter
            .encrypt_tier_key_data("org-1", 1, "key-1", tier_key)
            .unwrap();
        let enc2 = encrypter
            .encrypt_tier_key_data("org-2", 1, "key-1", tier_key)
            .unwrap();

        assert_ne!(enc1.encrypted_key, enc2.encrypted_key);
    }

    #[test]
    fn test_wrong_key_cannot_decrypt() {
        let encrypter1 = make_encrypter();
        let encrypter2 = make_encrypter();
        let tier_key = b"test_key";

        let encrypted = encrypter1
            .encrypt_tier_key_data("org-1", 1, "key-1", tier_key)
            .unwrap();

        assert!(encrypter2.decrypt_tier_key_data(&encrypted).is_err());
    }

    #[test]
    fn test_organization_encrypt_decrypt_roundtrip() {
        let encrypter = make_encrypter();
        let org_data = b"organization sensitive data";

        let encrypted = encrypter
            .encrypt_organization_data("org-123", org_data)
            .unwrap();

        assert_eq!(encrypted.record_type, PrivilegedRecordType::Organization);
        assert_eq!(encrypted.context, "org-123");
        assert_ne!(encrypted.encrypted_data, org_data.to_vec());

        let decrypted = encrypter.decrypt_organization_data(&encrypted).unwrap();
        assert_eq!(decrypted, org_data.to_vec());
    }

    #[test]
    fn test_member_certificate_encrypt_decrypt_roundtrip() {
        let encrypter = make_encrypter();
        let cert_data = b"member certificate sensitive data";

        let encrypted = encrypter
            .encrypt_member_certificate_data("org-123", "cert-456", cert_data)
            .unwrap();

        assert_eq!(
            encrypted.record_type,
            PrivilegedRecordType::MemberCertificate
        );
        assert_eq!(encrypted.context, "org-123:cert-456");

        let decrypted = encrypter
            .decrypt_member_certificate_data(&encrypted)
            .unwrap();
        assert_eq!(decrypted, cert_data.to_vec());
    }

    #[test]
    fn test_global_node_list_encrypt_decrypt_roundtrip() {
        let encrypter = make_encrypter();
        let list_data = b"global node list sensitive data";

        let encrypted = encrypter.encrypt_global_node_list_data(list_data).unwrap();

        assert_eq!(encrypted.record_type, PrivilegedRecordType::GlobalNodeList);
        assert_eq!(encrypted.context, "");

        let decrypted = encrypter.decrypt_global_node_list_data(&encrypted).unwrap();
        assert_eq!(decrypted, list_data.to_vec());
    }

    #[test]
    fn test_different_privileged_types_different_keys() {
        let encrypter = make_encrypter();
        let data = b"same data";

        let enc_org = encrypter.encrypt_organization_data("org-1", data).unwrap();
        let enc_cert = encrypter
            .encrypt_member_certificate_data("org-1", "cert-1", data)
            .unwrap();
        let enc_list = encrypter.encrypt_global_node_list_data(data).unwrap();

        assert_ne!(enc_org.encrypted_data, enc_cert.encrypted_data);
        assert_ne!(enc_org.encrypted_data, enc_list.encrypted_data);
        assert_ne!(enc_cert.encrypted_data, enc_list.encrypted_data);
    }

    #[test]
    fn test_wrong_type_cannot_decrypt() {
        let encrypter = make_encrypter();
        let org_data = b"org data";

        let encrypted = encrypter
            .encrypt_organization_data("org-123", org_data)
            .unwrap();

        assert!(encrypter
            .decrypt_member_certificate_data(&encrypted)
            .is_err());
        assert!(encrypter.decrypt_global_node_list_data(&encrypted).is_err());
    }

    #[test]
    fn test_privileged_serialize_deserialize_roundtrip() {
        let encrypter = make_encrypter();
        let cert_data = b"certificate data to serialize";

        let encrypted = encrypter
            .encrypt_member_certificate_data("org-serialize", "cert-test", cert_data)
            .unwrap();

        let serialized = serialize_encrypted_privileged(&encrypted);
        let deserialized = deserialize_encrypted_privileged(&serialized).unwrap();

        assert_eq!(deserialized.record_type, encrypted.record_type);
        assert_eq!(deserialized.context, encrypted.context);

        let decrypted = encrypter
            .decrypt_member_certificate_data(&deserialized)
            .unwrap();
        assert_eq!(decrypted, cert_data.to_vec());
    }

    #[test]
    fn test_dns_zone_encrypt_decrypt_roundtrip() {
        let encrypter = make_encrypter();
        let zone_data = b"dns zone sensitive data";

        let encrypted = encrypter
            .encrypt_dns_zone_data("example.com.", zone_data)
            .unwrap();

        assert_eq!(encrypted.record_type, PrivilegedRecordType::DnsZone);
        assert_eq!(encrypted.context, "example.com.");

        let decrypted = encrypter.decrypt_dns_zone_data(&encrypted).unwrap();
        assert_eq!(decrypted, zone_data.to_vec());
    }

    #[test]
    fn test_anycast_node_encrypt_decrypt_roundtrip() {
        let encrypter = make_encrypter();
        let anycast_data = b"anycast node sensitive data";

        let encrypted = encrypter
            .encrypt_anycast_node_data("node-123", anycast_data)
            .unwrap();

        assert_eq!(encrypted.record_type, PrivilegedRecordType::AnycastNode);
        assert_eq!(encrypted.context, "node-123");

        let decrypted = encrypter.decrypt_anycast_node_data(&encrypted).unwrap();
        assert_eq!(decrypted, anycast_data.to_vec());
    }
}
