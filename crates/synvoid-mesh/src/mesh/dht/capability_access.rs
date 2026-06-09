use crate::dht::capability_attestation::CapabilityAttestation;
use crate::dht::key_policy::{DhtKeyPolicyTable, DhtRecordAuthorityClass};
use crate::dht::keys::DhtKey;
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
        let policy = DhtKeyPolicyTable::policy_for_key(&dht_key);
        match policy.authority_class {
            DhtRecordAuthorityClass::CapabilityAttested => policy
                .required_capability
                .map(|cap| (cap, key_type_name(&dht_key))),
            _ => None,
        }
    }

    pub fn verify_capability_for_key(&self, node_id: &str, key: &str) -> bool {
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

    pub fn verify_node_has_capability(&self, node_id: &str, capability: &str) -> bool {
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

fn key_type_name(key: &DhtKey) -> &'static str {
    match key {
        DhtKey::YaraRulesManifest { .. } => "YaraRulesManifest",
        DhtKey::YaraRuleContent { .. } => "YaraRuleContent",
        DhtKey::YaraCompiledRuleContent { .. } => "YaraCompiledRuleContent",
        DhtKey::YaraChunk { .. } => "YaraChunk",
        DhtKey::YaraCompiledChunk { .. } => "YaraCompiledChunk",
        DhtKey::ThreatIndicator(_, _) => "ThreatIndicator",
        DhtKey::DnsZone(_) => "DnsZone",
        DhtKey::DnsRecord(_, _) => "DnsRecord",
        DhtKey::DnsDomainRegistration(_) => "DnsDomainReg",
        DhtKey::Organization(_) => "Organization",
        DhtKey::OrgPublicKey(_) => "OrgPublicKey",
        DhtKey::TierKey(_, _) => "TierKey",
        DhtKey::MemberCertificate(_, _) => "MemberCertificate",
        DhtKey::GlobalNodeList => "GlobalNodeList",
        DhtKey::OrgNameReservation(_) => "OrgNameReservation",
        DhtKey::VerifiedUpstream(_) => "VerifiedUpstream",
        DhtKey::TierClaim(_) => "TierClaim",
        DhtKey::GlobalNodeProof { .. } => "GlobalNodeProof",
        DhtKey::NodeCertBinding { .. } => "NodeCertBinding",
        DhtKey::GenesisKeyTransition { .. } => "GenesisKeyTransition",
        DhtKey::RevokedGlobalNode { .. } => "RevokedGlobalNode",
        DhtKey::NodeInfo(_) => "NodeInfo",
        DhtKey::NodeHealth(_) => "NodeHealth",
        DhtKey::NodeLoad(_) => "NodeLoad",
        DhtKey::GlobalNodeHeartbeat(_) => "GlobalNodeHeartbeat",
        DhtKey::NodeCapability { .. } => "NodeCapability",
        DhtKey::EdgeAttestation { .. } => "EdgeAttestation",
        DhtKey::CapabilityAttestation { .. } => "CapabilityAttestation",
        DhtKey::GlobalNodePublicKey(_) => "GlobalNodePublicKey",
        DhtKey::OriginReachability { .. } => "OriginReachability",
        DhtKey::VerificationTask { .. } => "VerificationTask",
        DhtKey::OriginPenalty { .. } => "OriginPenalty",
        DhtKey::Upstream(_) => "Upstream",
        DhtKey::AnycastNode(_) => "AnycastNode",
        DhtKey::UpstreamImageProtection(_) => "UpstreamImageProtection",
        DhtKey::UpstreamMinification(_) => "UpstreamMinification",
        DhtKey::UpstreamCompression(_) => "UpstreamCompression",
        DhtKey::UpstreamProxyCachePreferences(_) => "UpstreamProxyCachePreferences",
        DhtKey::SiteImagePoisonConfig(_) => "SiteImagePoisonConfig",
        DhtKey::SiteContentVersion { .. } => "SiteContentVersion",
        DhtKey::UpstreamOwnershipChallenge(_) => "UpstreamOwnershipChallenge",
        DhtKey::ServerlessFunction { .. } => "ServerlessFunction",
        DhtKey::BehavioralFingerprint { .. } => "BehavioralFingerprint",
        DhtKey::TransformedContent { .. } => "TransformedContent",
        DhtKey::PoisonedImage { .. } => "PoisonedImage",
        DhtKey::SiteScoped { .. } => "SiteScoped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_requires_capability_yara() {
        let (cap, name) =
            CapabilityAccessVerifier::key_requires_capability("yara_rules_manifest:node123")
                .unwrap();
        assert_eq!(cap, "waf");
        assert_eq!(name, "YaraRulesManifest");

        let (cap, name) =
            CapabilityAccessVerifier::key_requires_capability("yara_rule:abc123").unwrap();
        assert_eq!(cap, "waf");
        assert_eq!(name, "YaraRuleContent");
    }

    #[test]
    fn test_key_requires_capability_threat() {
        let (cap, name) =
            CapabilityAccessVerifier::key_requires_capability("threat_indicator:1.2.3.4:IpBlock")
                .unwrap();
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
