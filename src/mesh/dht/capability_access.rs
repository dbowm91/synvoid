use crate::mesh::dht::capability_attestation::CapabilityAttestation;
use crate::mesh::dht::keys::DhtKey;
use std::sync::Arc;

type AttestationFn = dyn Fn(&str, &str) -> Option<CapabilityAttestation> + Send + Sync;

pub struct CapabilityAccessVerifier {
    verify_fn: Arc<AttestationFn>,
}

impl std::fmt::Debug for CapabilityAccessVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityAccessVerifier").finish()
    }
}

impl Clone for CapabilityAccessVerifier {
    fn clone(&self) -> Self {
        Self {
            verify_fn: self.verify_fn.clone(),
        }
    }
}

impl CapabilityAccessVerifier {
    pub fn new(
        verify_fn: impl Fn(&str, &str) -> Option<CapabilityAttestation> + 'static + Send + Sync,
    ) -> Self {
        Self {
            verify_fn: Arc::new(verify_fn),
        }
    }

    pub fn key_requires_capability(key: &str) -> Option<(&'static str, &'static str)> {
        let dht_key = DhtKey::from_str(key);
        match dht_key {
            DhtKey::YaraRulesManifest { .. } => Some(("waf", "YaraRulesManifest")),
            DhtKey::YaraRuleContent { .. } => Some(("waf", "YaraRuleContent")),
            DhtKey::ThreatIndicator(_, _) => Some(("threat_intel", "ThreatIndicator")),
            _ => None,
        }
    }

    pub fn verify_capability_for_key(
        &self,
        node_id: &str,
        key: &str,
    ) -> bool {
        let Some((required_capability, _)) = Self::key_requires_capability(key) else {
            return true;
        };

        let attestation = (self.verify_fn)(node_id, required_capability);

        match attestation {
            Some(att) => {
                if att.node_id != node_id {
                    tracing::warn!(
                        "Capability attestation node_id mismatch: expected {}, got {}",
                        node_id,
                        att.node_id
                    );
                    return false;
                }
                if att.capability != required_capability {
                    tracing::warn!(
                        "Capability attestation capability mismatch: expected {}, got {}",
                        required_capability,
                        att.capability
                    );
                    return false;
                }
                att.verify_signature()
            }
            None => {
                tracing::warn!(
                    "No capability attestation found for node {} with capability {}",
                    node_id,
                    required_capability
                );
                false
            }
        }
    }

    pub fn verify_node_has_capability(
        &self,
        node_id: &str,
        capability: &str,
    ) -> bool {
        let attestation = (self.verify_fn)(node_id, capability);

        match attestation {
            Some(att) => {
                if att.node_id != node_id {
                    return false;
                }
                if att.capability != capability {
                    return false;
                }
                att.verify_signature()
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_requires_capability_yara() {
        let (cap, name) = CapabilityAccessVerifier::key_requires_capability("yara_rules_manifest:node123").unwrap();
        assert_eq!(cap, "waf");
        assert_eq!(name, "YaraRulesManifest");

        let (cap, name) = CapabilityAccessVerifier::key_requires_capability("yara_rule:abc123").unwrap();
        assert_eq!(cap, "waf");
        assert_eq!(name, "YaraRuleContent");
    }

    #[test]
    fn test_key_requires_capability_threat() {
        let (cap, name) = CapabilityAccessVerifier::key_requires_capability("threat_indicator:1.2.3.4:IpBlock").unwrap();
        assert_eq!(cap, "threat_intel");
        assert_eq!(name, "ThreatIndicator");
    }

    #[test]
    fn test_key_no_capability_required() {
        let result = CapabilityAccessVerifier::key_requires_capability("upstream:test");
        assert!(result.is_none());

        let result = CapabilityAccessVerifier::key_requires_capability("node_info:test");
        assert!(result.is_none());
    }
}