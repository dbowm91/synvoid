use base64::Engine;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct EdgeAttestation {
    pub node_id: String,
    pub global_node_id: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub attested_at: u64,
    pub expires_at: u64,
}

impl EdgeAttestation {
    pub fn new(
        node_id: String,
        global_node_id: String,
        signer_public_key: String,
        signature: Vec<u8>,
        attested_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            node_id,
            global_node_id,
            signer_public_key,
            signature,
            attested_at,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = crate::mesh::safe_unix_timestamp();
        now > self.expires_at
    }

    pub fn signable_content(&self) -> String {
        format!(
            "edge:{}:{}:{}",
            self.node_id, self.global_node_id, self.attested_at
        )
    }

    pub fn verify_signature(&self) -> bool {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let pk_bytes = match URL_SAFE_NO_PAD.decode(&self.signer_public_key) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        crate::mesh::cert::verify_ed25519(&self.signable_content(), &self.signature, &pk_bytes)
    }

    pub fn serialize(&self) -> Vec<u8> {
        crate::serialization::serialize(self).unwrap_or_default()
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        crate::serialization::deserialize(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_signable_content() {
        let attestation = EdgeAttestation::new(
            "edge-node-123".to_string(),
            "global-456".to_string(),
            "Pk".to_string(),
            vec![],
            1234567890,
            1234567890 + 86400,
        );
        assert_eq!(
            attestation.signable_content(),
            "edge:edge-node-123:global-456:1234567890"
        );
    }

    #[test]
    fn test_attestation_is_expired() {
        let attestation = EdgeAttestation::new(
            "edge-node-123".to_string(),
            "global-456".to_string(),
            "Pk".to_string(),
            vec![],
            1234567890,
            1234567890 + 86400,
        );
        assert!(!attestation.is_expired());

        let expired_attestation = EdgeAttestation::new(
            "edge-node-123".to_string(),
            "global-456".to_string(),
            "Pk".to_string(),
            vec![],
            100,
            200,
        );
        assert!(expired_attestation.is_expired());
    }
}
