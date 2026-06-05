use base64::Engine;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct CapabilityAttestation {
    pub node_id: String,
    pub capability: String,
    pub attested_by_global_node: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl CapabilityAttestation {
    pub fn new(
        node_id: String,
        capability: String,
        attested_by_global_node: String,
        signer_public_key: String,
        signature: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            node_id,
            capability,
            attested_by_global_node,
            signer_public_key,
            signature,
            timestamp,
        }
    }

    pub fn signable_content(&self) -> String {
        format!(
            "{},{},{},{}",
            self.node_id, self.capability, self.attested_by_global_node, self.timestamp
        )
    }

    pub fn verify_signature(&self) -> bool {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let pk_bytes = match URL_SAFE_NO_PAD.decode(&self.signer_public_key) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        crate::cert::verify_ed25519(&self.signable_content(), &self.signature, &pk_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_signable_content() {
        let attestation = CapabilityAttestation::new(
            "node-123".to_string(),
            "dns_server".to_string(),
            "global-456".to_string(),
            "Pk".to_string(),
            vec![],
            1234567890,
        );
        assert_eq!(
            attestation.signable_content(),
            "node-123,dns_server,global-456,1234567890"
        );
    }
}
