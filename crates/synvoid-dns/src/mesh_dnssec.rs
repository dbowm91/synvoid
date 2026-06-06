use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::Verifier;
use parking_lot::RwLock;

use crate::dnssec::{Algorithm, ZoneSigningKey};

#[derive(Clone)]
pub struct MeshTrustAnchor {
    pub zone_name: String,
    pub dnskeys: Vec<ZoneSigningKey>,
    pub ds_records: Vec<DsRecord>,
    pub validated_at: u64,
}

#[derive(Clone)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

pub struct MeshDnsSecValidator {
    trust_anchors: Arc<RwLock<HashMap<String, MeshTrustAnchor>>>,
    trusted_certificates: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MeshDnsSecValidator {
    pub fn new() -> Self {
        Self {
            trust_anchors: Arc::new(RwLock::new(HashMap::new())),
            trusted_certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_trust_anchor(&self, anchor: MeshTrustAnchor) {
        let zone_name = anchor.zone_name.clone();
        let mut anchors = self.trust_anchors.write();
        anchors.insert(anchor.zone_name.clone(), anchor);
        tracing::info!("Added trust anchor for zone: {}", zone_name);
    }

    pub fn remove_trust_anchor(&self, zone_name: &str) {
        let mut anchors = self.trust_anchors.write();
        anchors.remove(zone_name);
        tracing::info!("Removed trust anchor for zone: {}", zone_name);
    }

    pub fn get_trust_anchor(&self, zone_name: &str) -> Option<MeshTrustAnchor> {
        let anchors = self.trust_anchors.read();
        anchors.get(zone_name).cloned()
    }

    pub fn add_trusted_certificate(&self, node_id: String, certificate_der: Vec<u8>) {
        let mut certs = self.trusted_certificates.write();
        certs.insert(node_id, certificate_der);
    }

    pub fn validate_rrsig(
        &self,
        rrsig: &[u8],
        signed_data: &[u8],
        zone_name: &str,
    ) -> Result<bool, String> {
        let anchors = self.trust_anchors.read();

        let anchor = anchors.get(zone_name).ok_or("No trust anchor for zone")?;

        if rrsig.len() < 18 {
            return Err("RRSIG too short".to_string());
        }

        let algorithm = rrsig[2];
        let key_tag = u16::from_be_bytes([rrsig[12], rrsig[13]]);

        let matching_key = anchor
            .dnskeys
            .iter()
            .find(|k| k.key_tag == key_tag && k.algorithm.to_u8() == algorithm)
            .ok_or("No matching DNSKEY found")?;

        match matching_key.algorithm {
            Algorithm::Ed25519 => {
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                    matching_key.public_key[..32]
                        .try_into()
                        .map_err(|_| "Invalid key length")?,
                )
                .map_err(|e| format!("Invalid Ed25519 key: {:?}", e))?;

                let signature_bytes: [u8; 64] = rrsig[18..]
                    .try_into()
                    .map_err(|_| "Invalid signature length")?;

                let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

                match verifying_key.verify(signed_data, &signature) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            Algorithm::RSA => {
                use rsa::pkcs1v15::VerifyingKey;
                use rsa::signature::Verifier;
                use sha2::Sha256;

                let public_key_bytes = &matching_key.public_key;
                if public_key_bytes.len() < 3 {
                    return Err("RSA public key too short".to_string());
                }

                let exponent_len = public_key_bytes[0] as usize;
                if public_key_bytes.len() < 1 + exponent_len {
                    return Err("RSA public key truncated".to_string());
                }

                let exponent = rsa::BigUint::from_bytes_be(&public_key_bytes[1..1 + exponent_len]);
                let modulus = rsa::BigUint::from_bytes_be(&public_key_bytes[1 + exponent_len..]);

                let rsa_public_key = rsa::RsaPublicKey::new(modulus, exponent)
                    .map_err(|e| format!("Invalid RSA public key: {}", e))?;

                let verifying_key = VerifyingKey::<Sha256>::new(rsa_public_key);

                let signature_bytes = &rrsig[18..];

                match verifying_key.verify(
                    signed_data,
                    &rsa::pkcs1v15::Signature::try_from(signature_bytes)
                        .map_err(|e| format!("Invalid RSA signature: {}", e))?,
                ) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    pub fn validate_dnskey_chain(
        &self,
        _dnskey_record: &[u8],
        ds_record: &[u8],
        zone_name: &str,
    ) -> Result<bool, String> {
        if ds_record.len() < 4 {
            return Err("DS record too short".to_string());
        }

        let key_tag = u16::from_be_bytes([ds_record[0], ds_record[1]]);
        let algorithm = ds_record[2];
        let digest_type = ds_record[3];
        let digest = &ds_record[4..];

        let anchors = self.trust_anchors.read();
        let anchor = anchors.get(zone_name).ok_or("No trust anchor for zone")?;

        let matching_ds = anchor
            .ds_records
            .iter()
            .find(|ds| {
                ds.key_tag == key_tag && ds.algorithm == algorithm && ds.digest_type == digest_type
            })
            .ok_or("No matching DS record")?;

        if matching_ds.digest != digest {
            return Err("DS digest mismatch".to_string());
        }

        Ok(true)
    }

    pub fn create_trust_anchor_from_dnskeys(
        &self,
        zone_name: String,
        dnskeys: Vec<ZoneSigningKey>,
    ) -> MeshTrustAnchor {
        use sha2::{Digest, Sha256};

        let mut ds_records = Vec::new();

        for key in &dnskeys {
            if key.key_type != crate::dnssec::KeyType::KSK {
                continue;
            }

            let mut ds_data = Vec::new();
            ds_data.extend_from_slice(&key.key_tag.to_be_bytes());
            ds_data.push(key.algorithm.to_u8());
            ds_data.push(2);

            let canonical_dnskey = crate::dnssec::compute_dnskey_canonical(
                key.flags,
                3, // protocol
                key.algorithm.to_u8(),
                &key.public_key,
            );

            let mut hasher = Sha256::new();
            hasher.update(&canonical_dnskey);
            let digest = hasher.finalize();

            ds_data.extend_from_slice(&digest);

            ds_records.push(DsRecord {
                key_tag: key.key_tag,
                algorithm: key.algorithm.to_u8(),
                digest_type: 2,
                digest: digest.to_vec(),
            });
        }

        let now = synvoid_utils::safe_unix_timestamp();

        MeshTrustAnchor {
            zone_name,
            dnskeys,
            ds_records,
            validated_at: now,
        }
    }

    pub fn get_all_trust_anchors(&self) -> HashMap<String, MeshTrustAnchor> {
        self.trust_anchors.read().clone()
    }
}

impl Default for MeshDnsSecValidator {
    fn default() -> Self {
        Self::new()
    }
}
